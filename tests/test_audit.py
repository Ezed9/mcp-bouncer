# bouncer/tests/test_audit.py
import json
from pathlib import Path

from bouncer.audit import AuditLog
from bouncer.types import AuditEntry


def test_write_appends_one_json_line_per_entry(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.write(AuditEntry(tool="send_email", args={"to": "x@y.com"},
                         verdict="deny", reason="tainted destination", contract="sink_gate"))
    log.write(AuditEntry(tool="read_file", args={"path": "./a"},
                         verdict="allow", reason="", contract="default"))

    lines = path.read_text().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["tool"] == "send_email"
    assert first["verdict"] == "deny"
    assert first["contract"] == "sink_gate"
    assert first["ts"].endswith("+00:00")


def test_log_is_private_to_the_user(tmp_path: Path) -> None:
    # It records argument values, so only the owner may read it. A log an
    # older version created with the default mode is tightened too.
    old = tmp_path / "old.jsonl"
    old.write_text("")
    old.chmod(0o644)
    new = tmp_path / "new" / "audit.jsonl"
    for path in (old, new):
        AuditLog(path).write(AuditEntry(tool="read_file"))
        assert path.stat().st_mode & 0o777 == 0o600
        assert len(path.read_text().splitlines()) == 1
