# bouncer/tests/test_heuristics.py
from bouncer.heuristics import derive_policy


def _schema(*props: str) -> dict[str, object]:
    return {"type": "object", "properties": {p: {"type": "string"} for p in props}}


def test_email_tool_is_exfiltrating_with_sink_params() -> None:
    p = derive_policy("send_email", _schema("to", "cc", "subject", "body"))
    assert p.exfiltrating is True
    assert "to" in p.sink_params
    assert "cc" in p.sink_params
    assert "body" not in p.sink_params


def test_write_tool_gets_write_params() -> None:
    p = derive_policy("write_file", _schema("path", "contents"))
    assert "path" in p.write_params
    assert p.exfiltrating is False


def test_delete_tool_gets_budget() -> None:
    p = derive_policy("delete_file", _schema("path"))
    assert p.max_calls == 2


def test_plain_read_tool_has_no_constraints() -> None:
    p = derive_policy("read_file", _schema("path"))
    assert p.exfiltrating is False
    assert p.write_params == ()
    assert p.max_calls is None
