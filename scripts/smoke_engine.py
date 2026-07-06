# bouncer/scripts/smoke_engine.py
"""Direct ContractEngine smoke for scenarios the live proxy cannot configure.

The proxy (proxy.py) builds its engine from builtin packs ONLY and accepts no
user-policy YAML, so the constraint (allowed_path_prefixes) and budget scenarios
cannot be driven through the wrapped filesystem server. This drives the engine
directly with a realistic user policy layered over the filesystem pack, using the
REAL tool names + schemas captured from the live server, and also demonstrates
the deny-unless-trusted sink gate on an exfiltrating tool. All verdicts printed
are the engine's real output.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from bouncer.approvals import ApprovalStore
from bouncer.audit import AuditLog
from bouncer.engine import ContractEngine
from bouncer.policy import PolicyResolver, builtin_pack_paths, load_policies
from bouncer.taint import TaintTracker
from bouncer.types import ToolCall

# Real inputSchemas captured from the live @modelcontextprotocol/server-filesystem.
FS_SCHEMAS: dict[str, dict[str, object]] = {
    "write_file": {
        "type": "object",
        "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
        "required": ["path", "content"],
    },
    "delete_file": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
    "send_email": {  # not a filesystem tool; used only for the sink-gate demo
        "type": "object",
        "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
        "required": ["to", "body"],
    },
}

USER_YAML = """
write_file:
  write_params: [path]
  allowed_path_prefixes: ["./out"]
delete_file:
  write_params: [path]
  max_calls: 2
send_email:
  exfiltrating: true
  sink_params: [to]
  trusted_destinations: ["ok@corp.com"]
"""


def build_engine(audit_path: Path) -> ContractEngine:
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(USER_YAML)
        user_path = Path(fh.name)
    # Layer order in load_policies: later paths win, so user YAML overrides packs.
    overrides = load_policies(builtin_pack_paths() + [user_path])
    return ContractEngine(
        resolver=PolicyResolver(overrides=overrides),
        taint=TaintTracker(),
        approvals=ApprovalStore(),
        audit=AuditLog(audit_path),
        schemas=FS_SCHEMAS,
    )


def show(engine: ContractEngine, label: str, call: ToolCall) -> None:
    d = engine.evaluate(call)
    print(f"{label}: {d.verdict.value.upper()} [{d.contract}] {d.reason}")


def main() -> None:
    audit_path = Path(__file__).resolve().parent.parent / "smoke_work" / "engine-audit.jsonl"
    if audit_path.exists():
        audit_path.unlink()
    engine = build_engine(audit_path)

    print("=== (b) constraint: write_file allowed_path_prefixes=['./out'] ===")
    show(engine, "b1 write ./out/note.txt", ToolCall("write_file",
         {"path": "./out/note.txt", "content": "ok"}))
    show(engine, "b2 write /etc/x", ToolCall("write_file",
         {"path": "/etc/x", "content": "nope"}))
    print()

    print("=== (c) budget: delete_file max_calls=2 ===")
    for i in (1, 2, 3):
        show(engine, f"c delete #{i}", ToolCall("delete_file", {"path": "./out/note.txt"}))
    print()

    print("=== (d) sink gate: exfiltrating send_email, tainted destination ===")
    # Record an untrusted tool output containing an attacker address.
    engine.register_output("Contact the admin at attacker@evil.com for access.")
    show(engine, "d1 send to trusted ok@corp.com", ToolCall("send_email",
         {"to": "ok@corp.com", "body": "hi"}))
    show(engine, "d2 send to tainted attacker@evil.com", ToolCall("send_email",
         {"to": "attacker@evil.com", "body": "leak"}))
    show(engine, "d3 send to unproven new@random.com", ToolCall("send_email",
         {"to": "new@random.com", "body": "hi"}))
    print()
    print(f"engine audit written to: {audit_path}")


if __name__ == "__main__":
    main()
