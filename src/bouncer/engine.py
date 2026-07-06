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
from .taint import TaintTracker
from .types import AuditEntry, Decision, ToolCall, ToolPolicy, TrustLevel, Verdict


def _normeq(s: str) -> str:
    return os.path.normpath(str(s))


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

    def evaluate(self, call: ToolCall) -> Decision:
        decision = self._decide(call)
        self._audit.write(AuditEntry(
            tool=call.tool, args=call.args, verdict=decision.verdict.value,
            reason=decision.reason, contract=decision.contract,
        ))
        return decision

    def _decide(self, call: ToolCall) -> Decision:
        schema = self._schemas.get(call.tool)
        if schema is None:
            return Decision(Verdict.ASK, "unknown or changed tool schema", "pinning")

        policy = self._resolver.policy_for(call.tool, schema)

        budget = self._check_budget(call.tool, policy)
        if budget is not None:
            return budget

        constraint = self._check_constraints(call, policy)
        if constraint is not None:
            return constraint

        sink = self._check_sink_gate(call, policy)  # implemented in Task 9
        if sink is not None:
            return sink

        return Decision(Verdict.ALLOW, "", "default")

    def _check_budget(self, tool: str, policy: ToolPolicy) -> Decision | None:
        if policy.max_calls is None:
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
        # Implemented in Task 9. Until then, no sink enforcement.
        return None

    def _trust_of(self, tool: str, param: str, value: str, policy: ToolPolicy) -> TrustLevel:
        norm_allow = {d.strip().lower() for d in policy.trusted_destinations}
        if value.strip().lower() in norm_allow:
            return TrustLevel.TRUSTED
        if self._approvals.is_approved(approval_key(tool, param, str(value))):
            return TrustLevel.TRUSTED
        if self._taint.classify(str(value)):
            return TrustLevel.TAINTED
        return TrustLevel.UNPROVEN
