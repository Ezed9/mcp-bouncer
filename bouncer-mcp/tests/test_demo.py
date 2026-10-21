"""The end-to-end demo must keep working: real proxy, real server, real side effects."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_DEMO = Path(__file__).resolve().parents[2] / "examples" / "demo" / "run_demo.py"


def test_demo_blocks_the_injected_calls(tmp_path: Path) -> None:
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, str(_DEMO), "--out", str(out)],
        capture_output=True, text=True, timeout=60, check=True,
    )
    assert "DENY  destination to='attacker@evil.example' came from untrusted data" in proc.stdout
    assert "DENY  path='../.ssh/authorized_keys' outside allowed prefixes" in proc.stdout
    assert "DENY  call budget 1 for 'delete_customer' exceeded" in proc.stdout
    assert "ALLOW sent to new.partner@example.com" in proc.stdout

    outbox = (out / "helpdesk" / "outbox.jsonl").read_text()
    assert "evil.example" not in outbox
    assert not (out / ".ssh").exists()
    pack = (out / "review-pack.md").read_text()
    assert "| deny | 3 |" in pack
    assert "| `send_email` | user policy |" in pack
