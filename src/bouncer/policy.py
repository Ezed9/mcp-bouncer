# bouncer/src/bouncer/policy.py
"""Policy resolution: user/pack overrides first, heuristics as the fallback.

Layer order (first hit wins): explicit override (user YAML or curated pack) >
heuristic derivation from the tool schema. MCP annotations, when present, are
folded into pack authoring rather than trusted at runtime, per the design's
'annotations are not a security boundary' stance.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .heuristics import derive_policy
from .types import ToolPolicy


class PolicyError(ValueError):
    """Raised when a policy file is structurally invalid."""


def _policy_from_dict(name: str, raw: dict[str, object]) -> ToolPolicy:
    def _tuple(key: str) -> tuple[str, ...]:
        val = raw.get(key, [])
        return tuple(str(x) for x in val) if isinstance(val, list) else ()

    patterns = raw.get("arg_patterns", {})
    arg_patterns = (
        tuple((str(k), str(v)) for k, v in patterns.items())
        if isinstance(patterns, dict) else ()
    )
    max_calls = raw.get("max_calls")
    return ToolPolicy(
        name=name,
        exfiltrating=bool(raw.get("exfiltrating", False)),
        sink_params=_tuple("sink_params"),
        trusted_destinations=_tuple("trusted_destinations"),
        write_params=_tuple("write_params"),
        allowed_path_prefixes=_tuple("allowed_path_prefixes"),
        arg_patterns=arg_patterns,
        max_calls=(
            int(max_calls)
            if isinstance(max_calls, int) and not isinstance(max_calls, bool)
            else None
        ),
    )


def load_policies(paths: list[Path]) -> dict[str, ToolPolicy]:
    out: dict[str, ToolPolicy] = {}
    for path in paths:
        data = yaml.safe_load(path.read_text()) or {}
        if not isinstance(data, dict):
            raise PolicyError(
                f"malformed policy file {path}: top-level YAML must be a mapping of "
                f"tool-name to policy, got {type(data).__name__}"
            )
        for name, raw in data.items():
            out[name] = _policy_from_dict(name, raw if isinstance(raw, dict) else {})
    return out


class PolicyResolver:
    def __init__(
        self,
        overrides: dict[str, ToolPolicy],
        use_heuristics: bool = True,
    ) -> None:
        self._overrides = overrides
        self._use_heuristics = use_heuristics

    def policy_for(self, name: str, input_schema: dict[str, object]) -> ToolPolicy:
        if name in self._overrides:
            return self._overrides[name]
        if self._use_heuristics:
            return derive_policy(name, input_schema)
        return ToolPolicy(name=name)
