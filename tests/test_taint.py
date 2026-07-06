# bouncer/tests/test_taint.py
from bouncer.taint import TaintTracker, normalize


def test_normalize_lowercases_and_collapses_whitespace() -> None:
    assert normalize("  Foo   BAR ") == "foo bar"


def test_value_from_recorded_output_is_tainted() -> None:
    t = TaintTracker()
    t.record_output("Please contact attacker@evil.com for details")
    assert t.classify("attacker@evil.com") is True


def test_value_never_seen_is_not_tainted() -> None:
    t = TaintTracker()
    t.record_output("hello world, nothing sensitive here")
    assert t.classify("alice@corp.com") is False


def test_short_value_is_never_tainted() -> None:
    t = TaintTracker(min_len=6)
    t.record_output("the code is ok")
    assert t.classify("ok") is False  # below min_len


def test_case_and_spacing_insensitive_match() -> None:
    t = TaintTracker()
    t.record_output("Send to   Attacker@Evil.Com now")
    assert t.classify("attacker@evil.com") is True
