# bouncer/src/bouncer/heuristics.py
"""Last-resort policy derivation from a tool's name and JSON schema.

Used only when no pack or user YAML covers a tool. Deliberately conservative on
what it treats as a write (needs a write-ish verb AND a path-ish param) but
liberal on what it treats as a sink (any destination-shaped param), because
missing a sink is a safety gap while a false sink only costs an extra ASK.
"""

from __future__ import annotations

import re

from .types import ToolPolicy

_SINK_NAMES = frozenset({
    "to", "recipient", "recipients", "cc", "bcc",
    "url", "email", "address", "channel", "share_with",
})
_WRITE_PARAM_NAMES = frozenset({"path", "file_path", "filename", "dest", "destination"})
_WRITE_VERBS = ("write", "create", "save", "put", "upload", "edit")
_DELETE_VERBS = ("delete", "remove")
# Short verbs must be a whole word of the name: as substrings they also match
# "fill_form", "permissions", "transform" and "dropbox".
_DELETE_WORDS = frozenset({"rm", "rmdir", "drop"})
_WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")


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

    words = {w.lower() for w in _WORD.findall(name)}
    deletes = any(v in lname for v in _DELETE_VERBS) or bool(words & _DELETE_WORDS)
    max_calls = 2 if deletes else None

    return ToolPolicy(
        name=name,
        exfiltrating=bool(sink_params),
        sink_params=sink_params,
        write_params=write_params,
        max_calls=max_calls,
    )
