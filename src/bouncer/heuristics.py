# bouncer/src/bouncer/heuristics.py
"""Last-resort policy derivation from a tool's name and JSON schema.

Used only when no pack or user YAML covers a tool. Deliberately conservative on
what it treats as a write (needs a write-ish verb AND a path-ish param) but
liberal on what it treats as a sink (any destination-shaped param), because
missing a sink is a safety gap while a false sink only costs an extra ASK.
"""

from __future__ import annotations

from .types import ToolPolicy

_SINK_NAMES = frozenset({
    "to", "recipient", "recipients", "cc", "bcc",
    "url", "email", "address", "channel", "share_with",
})
_WRITE_PARAM_NAMES = frozenset({"path", "file_path", "filename", "dest", "destination"})
_WRITE_VERBS = ("write", "create", "save", "put", "upload", "edit")
_DELETE_VERBS = ("delete", "remove", "rm", "drop")


def _properties(input_schema: dict[str, object]) -> list[str]:
    props = input_schema.get("properties", {})
    return list(props.keys()) if isinstance(props, dict) else []


def derive_policy(name: str, input_schema: dict[str, object]) -> ToolPolicy:
    lname = name.lower()
    props = _properties(input_schema)

    sink_params = tuple(p for p in props if p.lower() in _SINK_NAMES)

    write_params: tuple[str, ...] = ()
    if any(v in lname for v in _WRITE_VERBS):
        write_params = tuple(p for p in props if p.lower() in _WRITE_PARAM_NAMES)

    max_calls = 2 if any(v in lname for v in _DELETE_VERBS) else None

    return ToolPolicy(
        name=name,
        exfiltrating=bool(sink_params),
        sink_params=sink_params,
        write_params=write_params,
        max_calls=max_calls,
    )
