# bouncer/src/bouncer/engine.py
"""The contract engine: a deterministic gate over every tool call.

evaluate() runs, in order: schema pinning (unknown/changed tool -> ask), call
budgets, per-argument constraints, then the deny-unless-trusted sink gate
(Task 9). Every call is audited. No LLM, no network, no I/O beyond the audit
append — this module is the load-bearing safety boundary.
"""

from __future__ import annotations

import os
import re
from pathlib import PurePosixPath

from .approvals import ApprovalStore, approval_key
from .audit import AuditLog
from .policy import PolicyResolver
from .taint import TaintTracker, normalize
from .types import AuditEntry, Decision, ToolCall, ToolPolicy, TrustLevel, Verdict


def _normeq(s: str) -> str:
    return os.path.normpath(str(s))


def _scalar_dests(value: object) -> list[str]:
    # Flatten a sink arg into its scalar destination strings. A list/tuple (the
    # normal multi-recipient shape) is all destinations; nested lists flatten too.
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            out.extend(_scalar_dests(item))
        return out
    return [str(value)]


def _within_prefix(value: str, prefix: str) -> bool:
    # Normalize both as POSIX paths (MCP tool args are posix-style); a value is
    # contained iff, after collapsing '.'/'..', prefix is an ancestor-or-equal.
    v = PurePosixPath(_normeq(value))
    p = PurePosixPath(_normeq(prefix))
    return v == p or p in v.parents


class ContractEngine:
    def __init__(
        self,
        resolver: PolicyResolver,
        taint: TaintTracker,
        approvals: ApprovalStore,
        audit: AuditLog,
        schemas: dict[str, dict[str, object]],
    ) -> None:
        self._resolver = resolver
        self._taint = taint
        self._approvals = approvals
        self._audit = audit
        self._schemas = schemas
        self._counts: dict[str, int] = {}

    def register_output(self, text: str) -> None:
        self._taint.record_output(text)

    def on_approved(self, key: str) -> None:
        self._approvals.approve(key)

    def evaluate(self, call: ToolCall, *, count_budget: bool = True) -> Decision:
        decision = self._decide(call, count_budget)
        self._audit.write(AuditEntry(
            tool=call.tool, args=call.args, verdict=decision.verdict.value,
            reason=decision.reason, contract=decision.contract,
        ))
        return decision

    def _decide(self, call: ToolCall, count_budget: bool = True) -> Decision:
        schema = self._schemas.get(call.tool)
        if schema is None:
            return Decision(Verdict.ASK, "unknown tool (not pinned at startup)", "pinning")

        policy = self._resolver.policy_for(call.tool, schema)

        budget = self._check_budget(call.tool, policy, count_budget)
        if budget is not None:
            return budget

        constraint = self._check_constraints(call, policy)
        if constraint is not None:
            return constraint

        sink = self._check_sink_gate(call, policy)  # implemented in Task 9
        if sink is not None:
            return sink

        return Decision(Verdict.ALLOW, "", "default")

    def _check_budget(
        self, tool: str, policy: ToolPolicy, count_budget: bool = True
    ) -> Decision | None:
        if policy.max_calls is None:
            return None
        # A re-evaluation within one client call's ASK approval loop must not
        # re-consume a slot; the first evaluate of the call already counted it.
        if not count_budget:
            return None
        self._counts[tool] = self._counts.get(tool, 0) + 1
        if self._counts[tool] > policy.max_calls:
            return Decision(
                Verdict.DENY,
                f"call budget {policy.max_calls} for {tool!r} exceeded",
                "budget",
            )
        return None

    def _check_constraints(self, call: ToolCall, policy: ToolPolicy) -> Decision | None:
        for param in policy.write_params:
            if param in call.args and policy.allowed_path_prefixes:
                value = str(call.args[param])
                if not any(
                    _within_prefix(value, pre) for pre in policy.allowed_path_prefixes
                ):
                    return Decision(
                        Verdict.DENY,
                        f"{param}={value!r} outside allowed prefixes "
                        f"{list(policy.allowed_path_prefixes)}",
                        "constraint",
                    )
        for arg, pattern in policy.arg_patterns:
            if arg in call.args and not re.fullmatch(pattern, str(call.args[arg])):
                return Decision(
                    Verdict.DENY,
                    f"{arg}={call.args[arg]!r} does not match /{pattern}/",
                    "constraint",
                )
        return None

    def _check_sink_gate(self, call: ToolCall, policy: ToolPolicy) -> Decision | None:
        if not policy.exfiltrating:
            return None
        # Fail-closed: an exfiltrating tool with no declared sinks treats every
        # arg as a destination, so a forgotten declaration can never leave a sink
        # unguarded.
        sinks = policy.sink_params or tuple(call.args.keys())
        # Fail-closed again: declared sinks that are ALL absent from this call
        # mean the policy was written for a different schema (e.g. `to=` vs
        # `recipients=`) and the real destination is invisible — treat every
        # arg as a sink rather than silently allowing an unseen destination.
        if not any(param in call.args for param in sinks):
            sinks = tuple(call.args.keys())

        pending_ask: Decision | None = None
        for param in sinks:
            if param not in call.args:
                continue
            # A list/tuple sink is a set of destinations; classify each element so
            # a tainted address hidden in a multi-recipient list still DENYs.
            for value in _scalar_dests(call.args[param]):
                trust = self._trust_of(call.tool, param, value, policy)
                if trust is TrustLevel.TAINTED:
                    return Decision(
                        Verdict.DENY,
                        f"destination {param}={value!r} came from untrusted data",
                        "sink_gate",
                    )
                if trust is TrustLevel.UNPROVEN and pending_ask is None:
                    pending_ask = Decision(
                        Verdict.ASK,
                        f"destination {param}={value!r} is not a vouched recipient",
                        "sink_gate",
                        ask_key=approval_key(call.tool, param, value),
                    )
        return pending_ask

    def _trust_of(self, tool: str, param: str, value: str, policy: ToolPolicy) -> TrustLevel:
        norm_allow = {normalize(d) for d in policy.trusted_destinations}
        if normalize(value) in norm_allow:
            return TrustLevel.TRUSTED
        if self._approvals.is_approved(approval_key(tool, param, str(value))):
            return TrustLevel.TRUSTED
        if self._taint.classify(str(value)):
            return TrustLevel.TAINTED
        return TrustLevel.UNPROVEN
