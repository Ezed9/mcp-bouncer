# bouncer/tests/test_approvals.py
from pathlib import Path

from bouncer.approvals import ApprovalStore, approval_key


def test_key_is_stable_and_destination_normalized() -> None:
    a = approval_key("send_email", "to", "Alice@Corp.com")
    b = approval_key("send_email", "to", "  alice@corp.com ")
    assert a == b


def test_unknown_key_not_approved() -> None:
    store = ApprovalStore()
    assert store.is_approved(approval_key("send_email", "to", "x@y.com")) is False


def test_approve_then_is_approved() -> None:
    store = ApprovalStore()
    k = approval_key("send_email", "to", "x@y.com")
    store.approve(k)
    assert store.is_approved(k) is True


def test_persistence_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "approvals.txt"
    k = approval_key("send_email", "to", "x@y.com")
    ApprovalStore(path=path).approve(k)
    assert ApprovalStore(path=path).is_approved(k) is True
