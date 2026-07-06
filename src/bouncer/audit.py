# bouncer/src/bouncer/audit.py
"""Append-only JSONL audit log — one verdict per line.

Deterministic, machine-readable evidence of every decision. This is the artifact
a classifier-based tool cannot produce and the seed of a future compliance
feature; in v1 it is simply always on.
"""

from __future__ import annotations

import json
from pathlib import Path

from .types import AuditEntry


class AuditLog:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, entry: AuditEntry) -> None:
        record = {
            "tool": entry.tool,
            "args": entry.args,
            "verdict": entry.verdict,
            "reason": entry.reason,
            "contract": entry.contract,
        }
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
