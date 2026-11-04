"""The one-time approval store: binding, TTL, single use, and the file's mode."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from bouncer.approvals import approval_key
from bouncer.pending import (
    MAX_PENDING,
    TTL_SECONDS,
    PendingApprovals,
    normalize_code,
    show_code,
)

BOB = approval_key("send_email", "to", "bob@partner.com")
CAROL = approval_key("send_email", "to", "carol@partner.com")


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def _store(tmp_path: Path) -> tuple[PendingApprovals, Clock]:
    clock = Clock()
    return PendingApprovals(tmp_path / "b" / "pending.json", clock=clock), clock


def test_request_approve_consume_once(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    [code] = store.request("mail", "send_email", [(BOB, "bob?")]) or []
    assert not store.is_approved("mail", BOB)
    assert store.approve(code) is not None
    assert store.is_approved("mail", BOB)
    assert store.consume("mail", {BOB}) is True
    assert store.consume("mail", {BOB}) is False  # single use
    assert not store.is_approved("mail", BOB)
    assert store.approve(code) is None  # a used code is gone


def test_file_is_private_and_dir_is_0700(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    store.request("mail", "send_email", [(BOB, "bob?")])
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700


def test_group_writable_file_is_ignored(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    [code] = store.request("mail", "send_email", [(BOB, "bob?")]) or []
    store.approve(code)
    os.chmod(store.path, 0o620)
    assert not store.is_approved("mail", BOB)
    assert store.get(code) is None


def test_symlinked_file_is_ignored(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    [code] = store.request("mail", "send_email", [(BOB, "bob?")]) or []
    store.approve(code)
    real = tmp_path / "elsewhere.json"
    store.path.rename(real)
    store.path.symlink_to(real)
    assert not store.is_approved("mail", BOB)


def test_pending_code_expires(tmp_path: Path) -> None:
    store, clock = _store(tmp_path)
    [code] = store.request("mail", "send_email", [(BOB, "bob?")]) or []
    clock.now += TTL_SECONDS + 1
    assert store.approve(code) is None
    assert store.active() == []


def test_approved_code_expires_before_retry(tmp_path: Path) -> None:
    store, clock = _store(tmp_path)
    [code] = store.request("mail", "send_email", [(BOB, "bob?")]) or []
    clock.now += TTL_SECONDS - 10
    assert store.approve(code) is not None  # the retry window restarts here
    clock.now += TTL_SECONDS - 1
    assert store.is_approved("mail", BOB)
    clock.now += 2
    assert not store.is_approved("mail", BOB)
    assert store.consume("mail", {BOB}) is False


def test_approval_is_bound_to_server_and_key(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    [code] = store.request("mail", "send_email", [(BOB, "bob?")]) or []
    store.approve(code)
    assert not store.is_approved("mail", CAROL)
    assert not store.is_approved("other-server", BOB)
    assert store.consume("mail", {CAROL}) is False
    assert store.consume("other-server", {BOB}) is False
    assert store.is_approved("mail", BOB)  # failed consumes used nothing


def test_consume_is_all_or_nothing(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    [bob] = store.request("mail", "send_email", [(BOB, "bob?")]) or []
    store.approve(bob)
    store.request("mail", "send_email", [(CAROL, "carol?")])  # not approved
    assert store.consume("mail", {BOB, CAROL}) is False
    assert store.is_approved("mail", BOB)


def test_same_key_keeps_its_code(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    first = store.request("mail", "send_email", [(BOB, "bob?")])
    again = store.request("mail", "send_email", [(BOB, "bob?")])
    assert first == again
    assert len(store.active()) == 1


def test_pending_codes_are_capped(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    for i in range(MAX_PENDING):
        key = approval_key("send_email", "to", f"u{i}@x.com")
        assert store.request("mail", "send_email", [(key, "?")]) is not None
    assert store.request("mail", "send_email", [(BOB, "bob?")]) is None
    assert len(store.active()) == MAX_PENDING


def test_code_format_and_normalizing(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    [code] = store.request("mail", "send_email", [(BOB, "bob?")]) or []
    assert len(code) == 6 and code.isalnum() and code.isupper()
    assert not set(code) & set("01OIL")
    shown = show_code(code)
    assert store.get(shown.lower()) is not None
    assert normalize_code(f" {shown.lower()} ") == code


@pytest.mark.parametrize("content", ["not json", "[]", '{"entries": [{"code": 1}]}'])
def test_corrupt_file_reads_as_empty(tmp_path: Path, content: str) -> None:
    store, _ = _store(tmp_path)
    store.request("mail", "send_email", [(BOB, "bob?")])
    store.path.write_text(content)
    assert store.active() == []
    # and the next write replaces it with a valid file
    store.request("mail", "send_email", [(BOB, "bob?")])
    assert len(json.loads(store.path.read_text())["entries"]) == 1
