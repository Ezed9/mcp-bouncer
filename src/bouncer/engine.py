# bouncer/src/bouncer/engine.py
"""The contract engine: a deterministic gate over every tool call.

evaluate() runs, in order: schema pinning (unknown/changed tool -> ask), call
budgets, per-argument constraints, then the deny-unless-trusted sink gate
(Task 9). Every call is audited. No LLM, no network, no I/O beyond the audit
append — this module is the load-bearing safety boundary.

ContractEngine is STATEFUL and NOT SYNCHRONIZED: call counts, the taint
tracker's recorded outputs and the approval store all mutate on every call.
Concurrent `evaluate()` would race the budget. Drive it from one task.
"""

from __future__ import annotations

import os
import re
from email.utils import getaddresses
from pathlib import PurePosixPath

from .approvals import ApprovalStore, approval_key
from .audit import AuditLog
from .policy import PolicyResolver
from .taint import TaintTracker, normalize
from .types import AuditEntry, Decision, ToolCall, ToolPolicy, TrustLevel, Verdict


def _normeq(s: str) -> str:
    return os.path.normpath(str(s))


# The lookbehind starts a match only at the start of a run of address
# characters: the same matches, but linear instead of quadratic on long runs.
_ADDRESS_TOKEN = re.compile(r"(?<![\w.%+\-])[\w.%+\-]+@[\w\-]+(?:\.[\w\-]+)*")
# Keys of a structured recipient ({"email": ..., "name": ...}) that name a
# field rather than being a destination. Any other dict key is gated as a
# destination, since a recipient map can be keyed by address.
_FIELD_NAMES = frozenset({
    "email", "emailaddress", "email_address", "address", "name", "displayname",
    "display_name", "type", "role", "id", "user", "channel", "url",
})


def _addresses(value: str) -> list[str]:
    # Gate on addresses, not display names or list syntax, so the allowlist,
    # approvals and taint see "Dana <dana@x.com>" and "dana@x.com" as one
    # recipient, and "a@x.com, b@y.com" as two. URLs are left whole: the
    # header parser would mangle them. Unparseable input stays as it is.
    if "@" not in value or "://" in value:
        return [value]
    parsed = getaddresses([value.replace(";", ",").strip().strip(",")], strict=True)
    found = [addr for _, addr in parsed if addr] or [value]
    # The parser drops comments and display names, but the downstream tool may
    # not, so every address-shaped token in the raw value is gated too.
    seen = {normalize(a) for a in found}
    return found + [t for t in _ADDRESS_TOKEN.findall(value) if normalize(t) not in seen]


def _taint_variants(value: str) -> list[str]:
    # Extra forms checked for taint only (DENY), never for trust: an address
    # inside a URL (which `_addresses` leaves whole), and an address without
    # its "+tag", which reaches the same mailbox on most providers.
    out: list[str] = []
    tokens = _ADDRESS_TOKEN.findall(value) if "://" in value else [value]
    for token in tokens:
        if token != value:
            out.append(token)
        local, at, domain = token.partition("@")
        if at and "+" in local:
            out.append(local.split("+", 1)[0] + "@" + domain)
    return out


def _scalar_dests(value: object) -> list[str]:
    # Flatten a sink arg into its destination strings. A list/tuple/set
    # (multi-recipient shapes) is all destinations; a dict (a structured
    # recipient like {"email": ...}, or a map keyed by address) contributes its
    # values and every key that is not a known field name; nested containers
    # flatten recursively; a string is split into its addresses. Flattening —
    # rather than str()-ing the container — keeps each address exposed to taint
    # so a tainted address nested in a structure still DENYs instead of
    # downgrading to ASK.
    if isinstance(value, (list, tuple, set, frozenset)):
        out: list[str] = []
        for item in value:
            out.extend(_scalar_dests(item))
        return out
    if isinstance(value, dict):
        out = []
        for key, item in value.items():
            if not (isinstance(key, str) and key.lower() in _FIELD_NAMES):
                out.extend(_addresses(str(key)))
            out.extend(_scalar_dests(item))
        return out
    return _addresses(str(value))


def destination_count(args: dict[str, object]) -> int:
    """How many destinations the sink gate can ask about for these args (>= 1).

    The proxy's ASK loop uses it as its round bound: each approval proves one.
    """
    return max(sum(len(_scalar_dests(v)) for v in args.values()), 1)


def _show(value: str) -> str:
    # The reason string is what a human approves. A homoglyph ("а", Cyrillic)
    # looks exactly like ASCII, so non-ASCII also gets an escaped form.
    return repr(value) if value.isascii() else f"{value!r} (as ASCII: {ascii(value)})"


def _show_param(param: str) -> str:
    # Arg names can be agent-chosen (the all-args fallback): quote odd ones so
    # a newline in a name cannot lay out a fake prompt.
    return param if param.isascii() and param.isidentifier() else repr(param)


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

    def register_schema(self, tool: str, schema: dict[str, object]) -> None:
        """Pin a tool the caller learns about after construction.

        `schemas` is retained BY REFERENCE, so mutating the dict you passed in
        also works -- but that is an implementation detail, and this is the
        supported way. A tool that is not pinned gets ASK, never ALLOW.

        Re-registering an identical schema is idempotent. Re-registering a
        DIFFERENT one raises: a pin that can be silently overwritten is not a
        pin, and a schema that changes under an already-approved tool is the
        shape this engine exists to refuse.
        """
        existing = self._schemas.get(tool)
        if existing is not None and existing != schema:
            raise ValueError(
                f"{tool!r} is already pinned to a different schema; "
                "re-pinning would silently change what was approved"
            )
        self._schemas[tool] = schema

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
        dests = [(p, v) for p in sinks if p in call.args for v in _scalar_dests(call.args[p])]
        # Fail-closed again: declared sinks that are all absent (or all empty,
        # like `to: []`) mean the real destination is somewhere the policy does
        # not name — e.g. `recipients=` vs `to=` — so treat every arg as a sink
        # rather than silently allowing an unseen destination.
        if not dests:
            dests = [(p, v) for p in call.args for v in _scalar_dests(call.args[p])]
        # Nothing at all to vouch for: an exfiltrating call with an implicit
        # destination (a reply to the sender, say). Never a silent ALLOW.
        if not dests:
            key = approval_key(call.tool, "", "")
            if self._approvals.is_approved(key):
                return None
            return Decision(
                Verdict.ASK, "no destination is visible in this call", "sink_gate",
                ask_key=key,
            )

        pending_ask: Decision | None = None
        # A list/tuple sink is a set of destinations; classify each element so
        # a tainted address hidden in a multi-recipient list still DENYs.
        for param, value in dests:
            trust = self._trust_of(call.tool, param, value, policy)
            if trust is TrustLevel.TAINTED:
                return Decision(
                    Verdict.DENY,
                    f"destination {_show_param(param)}={_show(value)} "
                    "came from untrusted data",
                    "sink_gate",
                )
            if trust is TrustLevel.UNPROVEN and pending_ask is None:
                pending_ask = Decision(
                    Verdict.ASK,
                    f"destination {_show_param(param)}={_show(value)} "
                    "is not a vouched recipient",
                    "sink_gate",
                    ask_key=approval_key(call.tool, param, value),
                )
        return pending_ask

    def _is_trusted(self, tool: str, param: str, value: str, policy: ToolPolicy) -> bool:
        norm_allow = {normalize(a) for d in policy.trusted_destinations for a in _addresses(d)}
        if normalize(value) in norm_allow:
            return True
        return self._approvals.is_approved(approval_key(tool, param, value))

    def _trust_of(self, tool: str, param: str, value: str, policy: ToolPolicy) -> TrustLevel:
        if self._is_trusted(tool, param, value, policy):
            return TrustLevel.TRUSTED
        if self._taint.classify(value):
            return TrustLevel.TAINTED
        # Taint-only forms (an address in a URL query, one without its +tag).
        # Forms that are themselves trusted are skipped.
        for variant in _taint_variants(value):
            if not self._is_trusted(tool, param, variant, policy) \
                    and self._taint.classify(variant):
                return TrustLevel.TAINTED
        return TrustLevel.UNPROVEN
