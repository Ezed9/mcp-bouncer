# bouncer/src/bouncer/approvals.py
"""Session approval memory keyed on (tool, sink_param, destination).

The whole point of ask-with-memory: a benign 'reply to this sender' asks once,
then is remembered so a normal session is not a wall of prompts. Optional file
persistence makes an approval survive across sessions per project.
"""

from __future__ import annotations

from pathlib import Path

from .taint import normalize


def approval_key(tool: str, sink_param: str, destination: str) -> str:
    return f"{tool}\x1f{sink_param}\x1f{normalize(destination)}"


class ApprovalStore:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path
        self._keys: set[str] = set()
        if path is not None and path.exists():
            self._keys = {line.strip() for line in path.read_text().splitlines() if line.strip()}

    def is_approved(self, key: str) -> bool:
        return key in self._keys

    def approve(self, key: str) -> None:
        if key in self._keys:
            return
        self._keys.add(key)
        if self._path is not None:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(key + "\n")
