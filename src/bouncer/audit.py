# bouncer/src/bouncer/audit.py
"""Append-only JSONL audit log — one verdict per line.

Deterministic, machine-readable evidence of every decision. This is the artifact
a classifier-based tool cannot produce and the seed of a future compliance
feature; in v1 it is simply always on.
"""

from __future__ import annotations

import contextlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from .types import AuditEntry


class AuditLog:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # The log holds argument values (message bodies, file contents), so it
        # is private to the user. This also tightens a log an older version
        # created with the default mode.
        with contextlib.suppress(OSError):
            self._path.chmod(0o600)

    def write(self, entry: AuditEntry) -> None:
        record = {
            "ts": datetime.now(UTC).isoformat(timespec="seconds"),
            "tool": entry.tool,
            "args": entry.args,
            "verdict": entry.verdict,
            "reason": entry.reason,
            "contract": entry.contract,
        }
        line = json.dumps(record, default=str) + "\n"
        # One write call per line: several proxies append to the same file.
        fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
