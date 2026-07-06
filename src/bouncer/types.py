# bouncer/src/bouncer/types.py
"""Core value types for the contract engine. Frozen dataclasses + string enums.

Nothing here performs I/O or holds mutable engine state; these are the vocabulary
the engine, policy resolver, and audit log speak.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


class TrustLevel(str, Enum):
    TRUSTED = "trusted"    # allowlisted destination or a remembered approval
    TAINTED = "tainted"    # matches a recorded untrusted tool output
    UNPROVEN = "unproven"  # neither vouched-for nor provably untrusted


@dataclass(frozen=True)
class ToolCall:
    tool: str
    args: dict[str, object]


@dataclass(frozen=True)
class ToolPolicy:
    name: str
    exfiltrating: bool = False
    sink_params: tuple[str, ...] = ()
    trusted_destinations: tuple[str, ...] = ()
    write_params: tuple[str, ...] = ()
    allowed_path_prefixes: tuple[str, ...] = ()
    arg_patterns: tuple[tuple[str, str], ...] = ()  # (arg_name, regex)
    max_calls: int | None = None


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    contract: str  # "sink_gate" | "constraint" | "budget" | "pinning" | "default"
    ask_key: str | None = None


@dataclass(frozen=True)
class AuditEntry:
    tool: str
    args: dict[str, object] = field(default_factory=dict)
    verdict: str = ""
    reason: str = ""
    contract: str = ""
