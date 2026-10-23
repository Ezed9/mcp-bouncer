"""Offline tests for benchmark/make_charts.py: data -> states -> geometry -> SVG."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest

from benchmark import make_charts as mc
from benchmark.run_agentdojo import _clopper_pearson, _summarize

FINAL = Path(__file__).resolve().parent.parent / "benchmark" / "results" / "final.jsonl"
SVG_NS = "{http://www.w3.org/2000/svg}"


def _row(condition: str, user: str, inj: str | None, *, security: bool | None = None,
         contacted: bool | None = None, utility: bool = False, sending: bool = False,
         verdicts: dict[str, int] | None = None, error: str | None = None) -> dict[str, Any]:
    return {
        "condition": condition, "user_task": user, "injection_task": inj,
        "in_scope": inj is not None, "security": security, "attacker_contacted": contacted,
        "utility": utility, "sending_task": sending, "verdict_counts": verdicts,
        "error": error, "model": "m", "suite": "workspace/v1", "attack": "a" if inj else None,
    }


def test_case_state_precedence() -> None:
    assert mc.case_state(None) == mc.MISSING
    assert mc.case_state(_row("baseline", "u", "i", error="boom")) == mc.MISSING
    assert mc.case_state(_row("baseline", "u", "i", security=True, contacted=True)) == mc.SUCCEEDED
    assert mc.case_state(_row("baseline", "u", "i", security=False, contacted=True)) == mc.RECEIVED
    assert mc.case_state(_row("bouncer", "u", "i", security=False, contacted=False,
                              verdicts={"allow": 0, "ask": 1, "deny": 0})) == mc.DENIED
    assert mc.case_state(_row("bouncer", "u", "i", security=False, contacted=False,
                              verdicts={"allow": 2, "ask": 0, "deny": 0})) == mc.NONE


def test_latest_row_wins_and_aborted_case_is_dropped() -> None:
    rows = [
        _row("baseline", "user_task_1", "injection_task_0", error="JSONDecodeError"),
        _row("baseline", "user_task_1", "injection_task_0", security=True, contacted=True),
        _row("baseline", "user_task_2", "injection_task_0", error="aborted: spend cap"),
        _row("bouncer", "user_task_2", "injection_task_0", security=False, contacted=False),
    ]
    m = mc.build_matrix(mc.latest_rows(rows))
    assert m.cells["baseline"][("user_task_1", "injection_task_0")] == mc.SUCCEEDED
    # Planned because the bouncer side ran it; the aborted baseline shows as no result.
    assert m.cells["baseline"][("user_task_2", "injection_task_0")] == mc.MISSING
    assert m.cells["bouncer"][("user_task_1", "injection_task_0")] == mc.MISSING


def test_matrix_orders_tasks_numerically() -> None:
    rows = [_row("baseline", f"user_task_{u}", f"injection_task_{i}", security=False,
                 contacted=False) for u in (10, 2, 1) for i in (10, 3)]
    m = mc.build_matrix(mc.latest_rows(rows))
    assert m.user_tasks == ["user_task_1", "user_task_2", "user_task_10"]
    assert m.injections == ["injection_task_3", "injection_task_10"]


def test_partition_fills_width_with_gaps_and_skips_zeros() -> None:
    segs = mc.partition([("a", 48), ("b", 0), ("c", 58), ("d", 58)], 10, 760, gap=2)
    assert [s for s, _, _ in segs] == ["a", "c", "d"]
    assert segs[0][1] == 10
    end = segs[-1][1] + segs[-1][2]
    assert end == pytest.approx(770)
    assert sum(w for _, _, w in segs) + 2 * (len(segs) - 1) == pytest.approx(760)
    assert segs[0][2] + 2 == pytest.approx(760 * 48 / 164)


def test_linear_and_cell_geometry() -> None:
    assert mc.linear(0.5, 0, 1, 100, 300) == 200
    assert mc.cell_xy(3, 2, 10, 20, 16) == (58, 52)
    assert mc.hero_pitch(40, 760, 56, 44) == 16


def test_clopper_pearson_matches_driver() -> None:
    for k, n in ((0, 163), (48, 164), (4, 6), (0, 6), (30, 40)):
        lo, hi = mc.clopper_pearson(k, n)
        dlo, dhi = _clopper_pearson(k, n)
        assert lo == pytest.approx(dlo, abs=1e-9)
        assert hi == pytest.approx(dhi, abs=1e-9)
    assert mc.ci_text(mc.Prop(0, 163)) == "95% CI 0%–2.2%"


@pytest.fixture(scope="module")
def final_rows() -> list[dict[str, Any]]:
    if not FINAL.exists():
        pytest.skip("benchmark/results/final.jsonl not present")
    return mc.load_rows(FINAL)


def test_facts_agree_with_driver_summary(final_rows: list[dict[str, Any]]) -> None:
    f = mc.facts(final_rows)
    s = _summarize(final_rows)["conditions"]
    for cond in ("baseline", "bouncer"):
        assert (f.succeeded[cond].k, f.succeeded[cond].n) == (
            s[cond]["attack_success"]["k"], s[cond]["attack_success"]["n"])
        assert (f.received[cond].k, f.received[cond].n) == (
            s[cond]["attacker_contacted"]["k"], s[cond]["attacker_contacted"]["n"])
    for cond in ("baseline", "bouncer", "benign-baseline", "benign-bouncer"):
        for part, key in (("all", "utility"), ("sending", "utility_sending"),
                          ("other", "utility_non_sending")):
            assert (f.util[(cond, part)].k, f.util[(cond, part)].n) == (
                s[cond][key]["k"], s[cond][key]["n"])
    assert sum(f.sink_verdicts.values()) == sum(s["bouncer"]["sink_verdicts"].values())


def _texts(svg: str) -> str:
    root = ET.fromstring(svg)
    return " ".join("".join(t.itertext()) for t in root.iter(f"{SVG_NS}text"))


def test_svgs_are_well_formed_and_labelled(final_rows: list[dict[str, Any]]) -> None:
    out = mc.render_all(final_rows)
    assert set(out) == {"agentdojo-cases.svg", "agentdojo-outcomes.svg", "agentdojo-cost.svg",
                        "agentdojo-card-1200x675.svg", "agentdojo-card-1080x1080.svg"}
    for name, svg in out.items():
        root = ET.fromstring(svg)
        assert root.get("role") == "img" and root.get("aria-label"), name
        assert root.find(f"{SVG_NS}title") is not None, name
        assert root.find(f"{SVG_NS}desc") is not None, name
        assert "prefers-color-scheme: dark" in svg, name
        assert "<script" not in svg and "@import" not in svg and "href=" not in svg, name
    expected = {
        "agentdojo-cases.svg": ["48/164", "106/164", "0/163", "124/163", "2.2%"],
        "agentdojo-outcomes.svg": ["106/164", "0/163", "2.2%"],
        "agentdojo-cost.svg": ["4/6 → 0/6", "29/34 → 30/34", "33/40 → 30/40",
                               "8/24 → 0/24", "44/164 → 86/163"],
        "agentdojo-card-1200x675.svg": ["48/164", "0/163", "4/6", "0/6", "gpt-4o-mini"],
        "agentdojo-card-1080x1080.svg": ["48/164", "0/163", "4/6 → 0/6", "29/34 → 30/34"],
    }
    for name, labels in expected.items():
        body = _texts(out[name])
        for label in labels:
            assert label in body, (name, label)


def test_cells_drawn_match_counts(final_rows: list[dict[str, Any]]) -> None:
    svg = mc.render_all(final_rows)["agentdojo-cases.svg"]
    def cells(state: str) -> int:
        return len(re.findall(rf'</title><rect [^>]*class="s-{state}"', svg))

    assert cells("succeeded") == 48  # all in the without-Bouncer panel
    assert cells("received") == 106 - 48
    assert cells("denied") == 124
    # Without: one error, one budget stop. With: two errors, one case never run.
    assert cells("missing") == 2 + 3


def test_readme_text_is_at_least_12px_at_800px(final_rows: list[dict[str, Any]]) -> None:
    out = mc.render_all(final_rows)
    for name in ("agentdojo-cases.svg", "agentdojo-outcomes.svg", "agentdojo-cost.svg",
                 "agentdojo-card-1200x675.svg", "agentdojo-card-1080x1080.svg"):
        w, _ = mc.svg_size(out[name])
        sizes = [float(s) for s in re.findall(r'font-size="([\d.]+)"', out[name])]
        assert min(sizes) * 800 / w >= 12 - 1e-9, name


def test_output_is_deterministic(final_rows: list[dict[str, Any]]) -> None:
    assert mc.render_all(final_rows) == mc.render_all(final_rows)
