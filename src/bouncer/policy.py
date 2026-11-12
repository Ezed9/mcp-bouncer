# bouncer/src/bouncer/policy.py
"""Policy resolution: user/pack overrides first, heuristics as the fallback.

Layer order (first hit wins): explicit override (user YAML or curated pack) >
heuristic derivation from the tool schema. MCP annotations, when present, are
folded into pack authoring rather than trusted at runtime, per the design's
'annotations are not a security boundary' stance.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .heuristics import derive_policy
from .types import ToolPolicy


class PolicyError(ValueError):
    """Raised when a policy file is structurally invalid."""


_KEYS = frozenset({
    "exfiltrating", "sink_params", "trusted_destinations", "write_params",
    "allowed_path_prefixes", "arg_patterns", "max_calls",
})


def _policy_from_dict(name: str, raw: object) -> ToolPolicy:
    # A misspelled key or a value of the wrong type is an error, never ignored:
    # ignoring one silently turns off the control it was meant to set.
    if not isinstance(raw, dict):
        raise PolicyError(
            f"policy for tool {name!r} must be a mapping (use {{}} for no rules), "
            f"got {type(raw).__name__}"
        )
    unknown = sorted(str(k) for k in raw if k not in _KEYS)
    if unknown:
        raise PolicyError(
            f"unknown key(s) {unknown} for tool {name!r}; known keys: {sorted(_KEYS)}"
        )

    def _tuple(key: str) -> tuple[str, ...]:
        val = raw.get(key)
        if val is None:
            return ()
        if not isinstance(val, list) or any(isinstance(x, (list, dict)) for x in val):
            raise PolicyError(
                f"{key} for tool {name!r} must be a list of strings, got {val!r}"
            )
        return tuple(str(x) for x in val)

    exfiltrating = raw.get("exfiltrating", False)
    if not isinstance(exfiltrating, bool):
        raise PolicyError(
            f"exfiltrating for tool {name!r} must be true or false, got {exfiltrating!r}"
        )
    sink_params = _tuple("sink_params")
    trusted_destinations = _tuple("trusted_destinations")
    if (sink_params or trusted_destinations) and not exfiltrating:
        raise PolicyError(
            f"tool {name!r} sets sink_params or trusted_destinations without "
            "`exfiltrating: true`, so the destination check would be off for it"
        )

    patterns = raw.get("arg_patterns")
    if patterns is not None and not isinstance(patterns, dict):
        raise PolicyError(
            f"arg_patterns for tool {name!r} must be a mapping of arg to regex, "
            f"got {patterns!r}"
        )
    arg_patterns = tuple((str(k), str(v)) for k, v in (patterns or {}).items())
    for arg, pattern in arg_patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise PolicyError(
                f"invalid arg_patterns regex for tool {name!r}, "
                f"arg {arg!r}: {pattern!r} ({exc})"
            ) from exc
    max_calls = raw.get("max_calls")
    if max_calls is not None and (
        not isinstance(max_calls, int) or isinstance(max_calls, bool) or max_calls < 0
    ):
        raise PolicyError(
            f"max_calls for tool {name!r} must be a whole number of 0 or more, "
            f"got {max_calls!r}"
        )
    return ToolPolicy(
        name=name,
        exfiltrating=exfiltrating,
        sink_params=sink_params,
        trusted_destinations=trusted_destinations,
        write_params=_tuple("write_params"),
        allowed_path_prefixes=_tuple("allowed_path_prefixes"),
        arg_patterns=arg_patterns,
        max_calls=max_calls,
    )


def builtin_pack_paths() -> list[Path]:
    packs_dir = Path(__file__).parent / "packs"
    return sorted(packs_dir.glob("*.yaml"))


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
            out[name] = _policy_from_dict(name, raw)
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
        """Resolve a policy: explicit override, then heuristics, then nothing.

        With `use_heuristics=False` an unknown tool falls through to a fully
        permissive `ToolPolicy(name=name)`. That is safe ONLY because
        `ContractEngine` checks pinning first and ASKs for any tool it was not
        given a schema for, so this branch is never reached for an unknown
        tool. **That ordering is load-bearing.** A caller using PolicyResolver
        outside the engine must do its own catalog check first.
        """
        if name in self._overrides:
            return self._overrides[name]
        if self._use_heuristics:
            return derive_policy(name, input_schema)
        return ToolPolicy(name=name)
