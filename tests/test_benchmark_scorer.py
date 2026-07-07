# bouncer/tests/test_benchmark_scorer.py
"""Deterministic unit tests for the benchmark scorer. No LLM, no network."""

from __future__ import annotations

from bouncer.benchmark_scoring import block_rate


def test_block_rate_counts_deny_and_ask_as_blocked() -> None:
    verdicts = ["deny", "ask", "allow", "deny"]
    assert block_rate(verdicts) == 0.75


def test_block_rate_all_allow_is_zero() -> None:
    assert block_rate(["allow", "allow", "allow"]) == 0.0


def test_block_rate_empty_list_is_zero() -> None:
    assert block_rate([]) == 0.0
