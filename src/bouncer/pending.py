# bouncer/src/bouncer/pending.py
"""One-time approvals for clients that cannot elicit.

When the client has no elicitation, the proxy cannot ask the human during the
call. Instead it denies the call and records a pending approval here, under a
short code. The human runs `bouncer approve <code>` in their own terminal, and
the next attempt of a call to the same destination passes, once.

What binds an approval, and why a code cannot approve anything else:

- An entry holds the wrapped server's name and the engine's approval key
  (tool, sink param, normalized destination). The proxy looks an approval up
  by (server, key), never by code: the agent never sends a code back, so a code
  quoted by the agent or the human cannot be pointed at a different
  destination, tool or server.
- A pending code expires `TTL_SECONDS` after it was issued. Approving it gives
  the retry `TTL_SECONDS` from the moment of approval. An approval is removed
  when a call uses it, so it allows one call.
- The file is `~/.bouncer/pending.json`, created 0600 in a 0700 directory and
  replaced atomically under a lock. It is never exposed over MCP, and there is
  no MCP tool that approves. A file readable or writable by group or others is
  ignored on POSIX, which fails closed (every code is unknown).

No LLM, no network. Stdlib only, so `bouncer-core` keeps its one dependency.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import stat
import tempfile
import time
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, replace
from pathlib import Path

try:  # POSIX. On Windows there is no lock; os.replace is still atomic.
    import fcntl
except ImportError:  # pragma: no cover - platform branch
    fcntl = None  # type: ignore[assignment]

TTL_SECONDS = 300
# An agent looping over new recipients must not grow the file without bound.
MAX_PENDING = 20
# No 0/O, 1/I/L: the human reads the code off one screen and types it.
_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_CODE_LEN = 6


def default_path() -> Path:
    return Path.home() / ".bouncer" / "pending.json"


def normalize_code(code: str) -> str:
    return "".join(c for c in code.upper() if c.isalnum())


def show_code(code: str) -> str:
    return f"{code[:3]}-{code[3:]}"


@dataclass(frozen=True)
class Pending:
    code: str
    server: str
    key: str
    tool: str
    reason: str
    created: float
    expires: float
    approved: bool = False


class PendingApprovals:
    """File-backed pending and approved one-time codes. Safe across processes.

    Each `bouncer run` (one per wrapped server) and the `bouncer approve` CLI
    open the same file; every read-modify-write holds an exclusive lock.
    """

    def __init__(
        self, path: Path | None = None, clock: Callable[[], float] = time.time
    ) -> None:
        self._path = path if path is not None else default_path()
        self._clock = clock

    @property
    def path(self) -> Path:
        return self._path

    # -- proxy side ---------------------------------------------------------

    def is_approved(self, server: str, key: str) -> bool:
        """Is there an approved, unexpired code for this exact (server, key)?"""
        now = self._clock()
        return any(
            e.approved and e.server == server and e.key == key and e.expires > now
            for e in self._read()
        )

    def request(
        self, server: str, tool: str, asks: list[tuple[str, str]]
    ) -> list[str] | None:
        """Record a pending code per (key, reason); return the codes in order.

        A key that already has an unexpired code keeps it, so an agent retrying
        before the human answers doesn't hand them a new code each time.
        Returns None, issuing nothing, if that would pass `MAX_PENDING`.
        """
        with self._locked() as entries:
            now = self._clock()
            codes: list[str] = []
            for key, reason in asks:
                found = next(
                    (e for e in entries
                     if e.server == server and e.key == key and e.expires > now),
                    None,
                )
                if found is not None:
                    codes.append(found.code)
                    continue
                if sum(not e.approved for e in entries) >= MAX_PENDING:
                    return None
                code = self._new_code({e.code for e in entries})
                entries.append(Pending(
                    code=code, server=server, key=key, tool=tool, reason=reason,
                    created=now, expires=now + TTL_SECONDS,
                ))
                codes.append(code)
            return codes

    def consume(self, server: str, keys: set[str]) -> bool:
        """Use one approval per key, all or nothing. False if any is missing.

        Checked again under the lock: an approval that expired, or that another
        call used, since `is_approved` returned True fails the whole call.
        """
        with self._locked() as entries:
            now = self._clock()
            hits = [
                e for e in entries
                if e.approved and e.server == server and e.key in keys and e.expires > now
            ]
            if {e.key for e in hits} != keys:
                return False
            for e in hits:
                entries.remove(e)
            return True

    # -- human side (the CLI) -----------------------------------------------

    def get(self, code: str) -> Pending | None:
        code = normalize_code(code)
        now = self._clock()
        return next(
            (e for e in self._read() if e.code == code and e.expires > now), None
        )

    def approve(self, code: str) -> Pending | None:
        """Mark a pending code approved. None if unknown, expired or used."""
        code = normalize_code(code)
        with self._locked() as entries:
            now = self._clock()
            for i, e in enumerate(entries):
                if e.code == code and not e.approved and e.expires > now:
                    entries[i] = replace(e, approved=True, expires=now + TTL_SECONDS)
                    return entries[i]
            return None

    def active(self) -> list[Pending]:
        now = self._clock()
        return sorted(
            (e for e in self._read() if e.expires > now), key=lambda e: e.created
        )

    # -- storage --------------------------------------------------------------

    def _new_code(self, taken: set[str]) -> str:
        while True:
            code = "".join(secrets.choice(_ALPHABET) for _ in range(_CODE_LEN))
            if code not in taken:
                return code

    def _read(self) -> list[Pending]:
        try:
            fd = os.open(self._path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return []
        except OSError:
            return []  # a symlink (O_NOFOLLOW) or unreadable: fail closed
        with os.fdopen(fd, encoding="utf-8") as fh:
            if not _private(os.fstat(fh.fileno())):
                return []
            try:
                raw = json.load(fh)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return []
        out: list[Pending] = []
        for item in raw.get("entries", []) if isinstance(raw, dict) else []:
            try:
                out.append(Pending(**item))
            except TypeError:
                continue
        return out

    @contextlib.contextmanager
    def _locked(self) -> Iterator[list[Pending]]:
        """Read, let the caller edit the list, prune expired entries, write back."""
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_path = self._path.with_name(self._path.name + ".lock")
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            entries = self._read()
            yield entries
            now = self._clock()
            self._write([e for e in entries if e.expires > now])
        finally:
            os.close(lock_fd)  # closing releases the flock

    def _write(self, entries: list[Pending]) -> None:
        # mkstemp creates the file 0600; os.replace swaps it in atomically, so a
        # reader never sees a half-written file or a wider mode.
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=".pending-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "entries": [asdict(e) for e in entries]}, fh)
            os.replace(tmp, self._path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise


def _private(st: os.stat_result) -> bool:
    if os.name != "posix":  # pragma: no cover - platform branch
        return True
    return (
        stat.S_ISREG(st.st_mode)
        and not st.st_mode & 0o077
        and st.st_uid == os.getuid()
    )
