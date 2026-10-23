"""Render the AgentDojo benchmark figures for the README and launch posts.

Reads one results JSONL (default benchmark/results/final.jsonl) and writes
hand-written SVGs to docs/assets. Standard library only and deterministic: the
same JSONL always gives byte-identical SVGs.

    python3 benchmark/make_charts.py          # SVGs
    python3 benchmark/make_charts.py --png    # also PNGs, via macOS qlmanage + sips

Figures:
  agentdojo-cases.svg            hero, README: every attack case, without vs with
  agentdojo-outcomes.svg         README / thread: what happened in each case, as counts
  agentdojo-cost.svg             README / thread: task completion, the price paid
  agentdojo-card-1200x675.svg    X / Reddit link card: headline + hero
  agentdojo-card-1080x1080.svg   square post: headline + hero + cost

Design notes (why these forms):
- Hero is a case matrix, not a bar chart. A bar for "attack success with
  Bouncer" is zero, so it draws nothing and the result looks like missing data.
  In the matrix every case is drawn in both panels, so the with-Bouncer panel is
  full of marks: blue where Bouncer refused a send, gray where the agent never
  tried. Columns are user tasks and rows are injections (transposed from 40x4 so
  it fits a 16:9 card and README width); the two panels share columns, so the
  eye drops straight from a red cell to the same case with Bouncer. Tasks stay in
  numeric order: nothing is sorted to make the picture look cleaner.
- Outcomes figure is a partition bar per condition, not a funnel of shrinking
  bars: both bars run the full n, so neither side is empty, and the nesting
  (succeeded is a subset of "send to attacker ran") is a bracket above it.
- Cost figure is a dumbbell with 95% intervals, sending tasks first, so the
  4/6 -> 0/6 drop is as visible as the win. Under-attack rows sit beside the
  no-attack rows because their direction differs and both are true.
- A per-injection small-multiples figure was left out: the matrix rows already
  are per-injection, with the per-row count printed at the right.
Colors: status red for "attack succeeded", amber for "send to attacker ran",
categorical blue for Bouncer's action, warm gray for "nothing sent". Checked with
the dataviz validator (all pairs, light and dark surfaces); amber is under 3:1 on
the light surface, so every color is also named by a legend and the counts are
printed as text.
"""

from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RESULTS = ROOT / "benchmark" / "results" / "final.jsonl"
DEFAULT_OUT = ROOT / "docs" / "assets"
REPO_LABEL = "github.com/Ezed9/mcp-bouncer"
ABORTED = "aborted: "  # same marker as run_agentdojo: a case cut short by a stop

SUCCEEDED, RECEIVED, DENIED, NONE, MISSING = (
    "succeeded", "received", "denied", "none", "missing")
STATES = (SUCCEEDED, RECEIVED, DENIED, NONE, MISSING)
STATE_LABEL = {
    SUCCEEDED: "attack succeeded (AgentDojo check)",
    RECEIVED: "send to attacker ran, not scored a success",
    DENIED: "Bouncer refused a send/share",
    NONE: "no send to the attacker attempted",
    MISSING: "no result (error or budget stop)",
}

FONT = "system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"

# Light/dark tokens. Steps come from the dataviz reference palette: chart
# surfaces, ink, status critical (red), categorical yellow (amber) and blue.
LIGHT = {
    "surface": "#fcfcfb", "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#6b6a66",
    "grid": "#e1e0d9", "axis": "#c3c2b7", "band": "#f3f2ee",
    "succeeded": "#d03b3b", "received": "#eda100", "denied": "#2a78d6", "none": "#c3c2b7",
    "without": "#6b6a66",
}
DARK = {
    "surface": "#1a1a19", "ink": "#f0efec", "ink2": "#c3c2b7", "muted": "#a3a29c",
    "grid": "#2c2c2a", "axis": "#4a4a46", "band": "#232321",
    "succeeded": "#d03b3b", "received": "#c98500", "denied": "#3987e5", "none": "#4a4a46",
    "without": "#a3a29c",
}


# ---------------------------------------------------------------- data


def load_rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def latest_rows(rows: list[dict[str, Any]]) -> dict[tuple[str, str, str | None], dict[str, Any]]:
    """One row per case, the same rule as run_agentdojo: a later row for a case
    supersedes an earlier one, and a case cut short by a stop counts as not run."""
    latest: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    for r in rows:
        latest[(r["condition"], r["user_task"], r["injection_task"])] = r
    return {k: r for k, r in latest.items() if not (r["error"] or "").startswith(ABORTED)}


def task_number(task_id: str) -> int:
    return int(task_id.rsplit("_", 1)[1])


def case_state(row: dict[str, Any] | None) -> str:
    if row is None or row["error"] is not None:
        return MISSING
    if row["security"]:
        return SUCCEEDED
    if row["attacker_contacted"]:
        return RECEIVED
    verdicts = row.get("verdict_counts") or {}
    if verdicts.get("deny", 0) + verdicts.get("ask", 0) > 0:
        return DENIED
    return NONE


@dataclass(frozen=True)
class Matrix:
    user_tasks: list[str]
    injections: list[str]
    cells: dict[str, dict[tuple[str, str], str]]  # condition -> (user, injection) -> state

    def counts(self, condition: str, injection: str | None = None) -> Counter[str]:
        return Counter(s for (_, inj), s in self.cells[condition].items()
                       if injection is None or inj == injection)


def build_matrix(latest: dict[tuple[str, str, str | None], dict[str, Any]]) -> Matrix:
    attack = {k: r for k, r in latest.items()
              if k[0] in ("baseline", "bouncer") and r["in_scope"] and k[2] is not None}
    planned = {(u, i) for (_, u, i) in attack if i is not None}
    cells = {cond: {(u, i): case_state(attack.get((cond, u, i))) for (u, i) in planned}
             for cond in ("baseline", "bouncer")}
    return Matrix(
        user_tasks=sorted({u for u, _ in planned}, key=task_number),
        injections=sorted({i for _, i in planned}, key=task_number),
        cells=cells,
    )


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact two-sided interval for k/n (same method as run_agentdojo)."""
    if n == 0:
        return (0.0, 1.0)

    def cdf(kk: int, p: float) -> float:
        if kk >= n or p <= 0.0:
            return 1.0
        if kk < 0 or p >= 1.0:
            return 0.0
        lp, lq = math.log(p), math.log1p(-p)
        return min(1.0, sum(math.exp(math.lgamma(n + 1) - math.lgamma(i + 1)
                                     - math.lgamma(n - i + 1) + i * lp + (n - i) * lq)
                            for i in range(kk + 1)))

    def root(f: Any) -> float:
        lo, hi = 0.0, 1.0
        for _ in range(100):
            mid = (lo + hi) / 2
            lo, hi = (mid, hi) if f(mid) > 0 else (lo, mid)
        return (lo + hi) / 2

    lower = 0.0 if k == 0 else root(lambda p: alpha / 2 - (1 - cdf(k - 1, p)))
    upper = 1.0 if k == n else root(lambda p: cdf(k, p) - alpha / 2)
    return (lower, upper)


@dataclass(frozen=True)
class Prop:
    k: int
    n: int

    @property
    def rate(self) -> float:
        return self.k / self.n if self.n else 0.0

    @property
    def ci(self) -> tuple[float, float]:
        return clopper_pearson(self.k, self.n)


def pct(x: float) -> str:
    v = round(x * 100, 1)
    return f"{v:.0f}%" if v == int(v) else f"{v:.1f}%"


def ci_text(p: Prop) -> str:
    lo, hi = p.ci
    return f"95% CI {pct(lo)}–{pct(hi)}"


def utility(latest: dict[tuple[str, str, str | None], dict[str, Any]],
            condition: str, part: str) -> Prop:
    ok = [r for k, r in latest.items() if k[0] == condition and r["error"] is None]
    if part == "sending":
        ok = [r for r in ok if r["sending_task"]]
    elif part == "other":
        ok = [r for r in ok if not r["sending_task"]]
    return Prop(sum(1 for r in ok if r["utility"]), len(ok))


@dataclass(frozen=True)
class Facts:
    model: str
    suite: str
    attack: str
    matrix: Matrix
    succeeded: dict[str, Prop]
    received: dict[str, Prop]
    denied: Prop
    fate_of_landed: Counter[str]  # bouncer state of cases that succeeded without Bouncer
    sink_verdicts: Counter[str]
    denied_on_sending: int
    sending_tasks: list[str]
    util: dict[tuple[str, str], Prop]  # (condition, part)


def facts(rows: list[dict[str, Any]]) -> Facts:
    latest = latest_rows(rows)
    m = build_matrix(latest)
    succeeded, received = {}, {}
    for cond in ("baseline", "bouncer"):
        c = m.counts(cond)
        n = sum(c.values()) - c[MISSING]
        succeeded[cond] = Prop(c[SUCCEEDED], n)
        received[cond] = Prop(c[SUCCEEDED] + c[RECEIVED], n)
        if cond == "bouncer":
            denied = Prop(c[DENIED], n)
    fate = Counter(m.cells["bouncer"][key] for key, s in m.cells["baseline"].items()
                   if s == SUCCEEDED)
    verdicts: Counter[str] = Counter()
    for k, r in latest.items():
        if k[0] == "bouncer" and r["error"] is None:
            verdicts.update(r.get("verdict_counts") or {})
    sending = sorted({k[1] for k, r in latest.items() if r["sending_task"]}, key=task_number)
    denied_on_sending = sum(1 for (u, _), s in m.cells["bouncer"].items()
                            if s == DENIED and u in sending)
    util = {(cond, part): utility(latest, cond, part)
            for cond in ("baseline", "bouncer", "benign-baseline", "benign-bouncer")
            for part in ("all", "sending", "other")}
    first = next(r for r in rows if r["attack"])
    return Facts(
        model=first["model"], suite=first["suite"].replace("/", " "), attack=first["attack"],
        matrix=m, succeeded=succeeded, received=received, denied=denied,
        fate_of_landed=fate, sink_verdicts=verdicts, denied_on_sending=denied_on_sending,
        sending_tasks=sending, util=util,
    )


# ---------------------------------------------------------------- geometry


def partition(counts: list[tuple[str, int]], x: float, width: float,
              gap: float = 2.0) -> list[tuple[str, float, float]]:
    """Split [x, x+width] into segments proportional to the counts, with a
    surface gap between touching segments. Zero counts get no segment."""
    total = sum(k for _, k in counts)
    live = [(s, k) for s, k in counts if k > 0]
    out, acc = [], 0
    for idx, (state, k) in enumerate(live):
        x0 = x + width * acc / total
        acc += k
        x1 = x + width * acc / total
        out.append((state, x0, x1 - x0 - (gap if idx < len(live) - 1 else 0.0)))
    return out


def linear(v: float, d0: float, d1: float, r0: float, r1: float) -> float:
    return r0 + (v - d0) / (d1 - d0) * (r1 - r0)


def cell_xy(col: int, row: int, x0: float, y0: float, pitch: float) -> tuple[float, float]:
    return (x0 + col * pitch, y0 + row * pitch)


_NARROW = set("iljtf.,:;'|!()[] ")
_WIDE = set("mwMW%—–")


def text_width(s: str, size: float, bold: bool = False) -> float:
    """Rough width of system-sans text, deliberately a little generous."""
    em = 0.0
    for ch in s:
        if ch in _NARROW:
            em += 0.3
        elif ch in _WIDE:
            em += 0.85
        elif ch.isupper() or ch.isdigit():
            em += 0.64
        else:
            em += 0.54
    return em * size * (1.06 if bold else 1.0)


# ---------------------------------------------------------------- svg


def _num(v: float) -> str:
    return f"{v:.2f}".rstrip("0").rstrip(".")


def text(x: float, y: float, s: str, cls: str, size: float, *, anchor: str = "start",
         bold: bool = False) -> str:
    weight = ' font-weight="600"' if bold else ""
    a = f' text-anchor="{anchor}"' if anchor != "start" else ""
    return (f'<text x="{_num(x)}" y="{_num(y)}" class="{cls}" font-size="{_num(size)}"'
            f'{weight}{a}>{escape(s)}</text>')


def rect(x: float, y: float, w: float, h: float, cls: str, rx: float = 0.0) -> str:
    r = f' rx="{_num(rx)}"' if rx else ""
    return (f'<rect x="{_num(x)}" y="{_num(y)}" width="{_num(w)}" height="{_num(h)}"'
            f' class="{cls}"{r}/>')


def line(x1: float, y1: float, x2: float, y2: float, cls: str, w: float = 1.0) -> str:
    return (f'<line x1="{_num(x1)}" y1="{_num(y1)}" x2="{_num(x2)}" y2="{_num(y2)}"'
            f' class="{cls}" stroke-width="{_num(w)}"/>')


def _tokens(t: dict[str, str]) -> str:
    return "".join(f"--{k}:{v};" for k, v in t.items())


def style() -> str:
    classes = [
        ".bg{fill:var(--surface)}", ".ink{fill:var(--ink)}", ".ink2{fill:var(--ink2)}",
        ".muted{fill:var(--muted)}", ".grid{stroke:var(--grid)}", ".axis{stroke:var(--axis)}",
        ".band{fill:var(--band)}", ".ring{stroke:var(--surface)}",
        ".ink-stroke{stroke:var(--ink2);fill:none}",
        ".without{fill:var(--without)}", ".without-s{stroke:var(--without)}",
        ".bouncer{fill:var(--denied)}", ".bouncer-s{stroke:var(--denied)}",
        ".on-dark{fill:#ffffff}", ".on-light{fill:#0b0b0b}", ".on-none{fill:var(--ink)}",
        ".marker{fill:var(--ink2)}",
    ]
    classes += [f".s-{s}{{fill:var(--{s})}}" for s in (SUCCEEDED, RECEIVED, DENIED, NONE)]
    classes.append(".s-missing{fill:none;stroke:var(--muted);stroke-width:1}")
    return (
        "<style>"
        f":root{{{_tokens(LIGHT)}}}"
        f"@media (prefers-color-scheme: dark){{:root:not(.light){{{_tokens(DARK)}}}}}"
        f":root.dark{{{_tokens(DARK)}}}"
        + "".join(classes) + "</style>"
    )


def document(width: float, height: float, title: str, desc: str, body: list[str]) -> str:
    return "\n".join([
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {_num(width)} {_num(height)}"'
        f' width="{_num(width)}" height="{_num(height)}" role="img"'
        f' aria-labelledby="t d" aria-label="{escape(title, {chr(34): "&quot;"})}"'
        f' font-family="{FONT}">',
        f'<title id="t">{escape(title)}</title>',
        f'<desc id="d">{escape(desc)}</desc>',
        style(),
        rect(0, 0, width, height, "bg", rx=8),
        *body,
        "</svg>",
        "",
    ])


def wrap(s: str, size: float, width: float, bold: bool = False) -> list[str]:
    lines, cur = [], ""
    for word in s.split(" "):
        trial = f"{cur} {word}".strip()
        if cur and text_width(trial, size, bold) > width:
            lines.append(cur)
            cur = word
        else:
            cur = trial
    return [*lines, cur] if cur else lines


def paragraph(x: float, y: float, s: str, cls: str, size: float, width: float,
              leading: float = 1.4, bold: bool = False) -> tuple[list[str], float]:
    """Wrapped text; returns the fragments and the y of the next line."""
    out = []
    for ln in wrap(s, size, width, bold):
        out.append(text(x, y, ln, cls, size, bold=bold))
        y += size * leading
    return out, y


def legend(x: float, y: float, items: list[tuple[str, str]], size: float, width: float,
           swatch: float) -> tuple[list[str], float]:
    """Flow layout of (state, label) swatches; wraps to the next row when full."""
    out, cx, cy = [], x, y
    for state, label in items:
        w = swatch + 6 + text_width(label, size) + size * 1.4
        if cx > x and cx + w > x + width:
            cx, cy = x, cy + size * 1.8
        out.append(_swatch(cx, cy - swatch + size * 0.1, swatch, state))
        out.append(text(cx + swatch + 6, cy, label, "ink2", size))
        cx += w
    return out, cy + size * 1.8


def _swatch(x: float, y: float, s: float, state: str) -> str:
    if state == "sending":
        return rect(x, y + s - 3, s, 3, "marker")
    if state == MISSING:
        return rect(x + 0.5, y + 0.5, s - 1, s - 1, "s-missing", rx=2)
    return rect(x, y, s, s, f"s-{state}", rx=2)


# ---------------------------------------------------------------- hero


@dataclass(frozen=True)
class HeroSize:
    width: float      # total width available for the hero block
    label_w: float    # row-label column
    count_w: float    # per-row count column
    pitch: float      # cell pitch; the cell is pitch - gap
    f_head: float
    f_text: float
    f_small: float
    gap: float = 2.0


def hero_pitch(n_cols: int, width: float, label_w: float, count_w: float) -> float:
    return math.floor((width - label_w - count_w) / n_cols)


def hero_block(f: Facts, x: float, y: float, hs: HeroSize) -> tuple[list[str], float]:
    m = f.matrix
    out: list[str] = []
    gx = x + hs.label_w
    grid_w = hs.pitch * len(m.user_tasks)
    right = gx + grid_w + hs.count_w
    panels = [
        ("baseline", "Without Bouncer",
         f"{f.succeeded['baseline'].k}/{f.succeeded['baseline'].n} succeeded · "
         f"{f.received['baseline'].k}/{f.received['baseline'].n} sent to attacker"),
        ("bouncer", "With Bouncer",
         f"{f.succeeded['bouncer'].k}/{f.succeeded['bouncer'].n} succeeded "
         f"({ci_text(f.succeeded['bouncer'])}) · "
         f"{f.received['bouncer'].k}/{f.received['bouncer'].n} sent to attacker · "
         f"{f.denied.k}/{f.denied.n} refused"),
    ]
    for p_idx, (cond, name, summary) in enumerate(panels):
        y += hs.f_head
        out.append(text(x, y, name, "ink", hs.f_head, bold=True))
        sx = x + text_width(name, hs.f_head, True) + hs.f_text * 0.8
        col_head = "succeeded"
        room = right - text_width(col_head, hs.f_small) - hs.f_small
        if sx + text_width(summary, hs.f_text) > room:
            y += hs.f_text * 1.45
            sx = x
        out.append(text(sx, y, summary, "ink2", hs.f_text))
        out.append(text(right, y, col_head, "muted", hs.f_small, anchor="end"))
        y += hs.f_small * 0.9
        top = y
        for r_idx, inj in enumerate(m.injections):
            ry = top + r_idx * hs.pitch
            label = f"inj. {task_number(inj)}"
            out.append(text(gx - 8, ry + hs.pitch * 0.5 + hs.f_small * 0.36, label, "ink2",
                            hs.f_small, anchor="end"))
            row = m.counts(cond, inj)
            n = sum(row.values()) - row[MISSING]
            out.append(text(right, ry + hs.pitch * 0.5 + hs.f_small * 0.36,
                            f"{row[SUCCEEDED]}/{n}", "ink2", hs.f_small, anchor="end"))
            for c_idx, user in enumerate(m.user_tasks):
                state = m.cells[cond].get((user, inj))
                if state is None:
                    continue
                cx, cy = cell_xy(c_idx, r_idx, gx, top, hs.pitch)
                size = hs.pitch - hs.gap
                tip = (f"<title>{name}: user task {task_number(user)}, injection "
                       f"{task_number(inj)}: {STATE_LABEL[state]}</title>")
                if state == MISSING:
                    shape = rect(cx + 0.5, cy + 0.5, size - 1, size - 1, "s-missing", rx=2)
                else:
                    shape = rect(cx, cy, size, size, f"s-{state}", rx=2)
                out.append(f"<g>{tip}{shape}</g>")
        y = top + len(m.injections) * hs.pitch + (hs.f_head * 0.9 if p_idx == 0 else 0)

    # Sending-task markers and the user-task axis under the second panel.
    for c_idx, user in enumerate(m.user_tasks):
        cx = gx + c_idx * hs.pitch
        if user in f.sending_tasks:
            out.append(rect(cx, y + 1, hs.pitch - hs.gap, 3, "marker"))
    ty = y + 4 + hs.f_small * 1.25
    out.append(text(gx - 8, ty, "user task", "muted", hs.f_small, anchor="end"))
    last = len(m.user_tasks) - 1
    for c_idx, user in enumerate(m.user_tasks):
        num = task_number(user)
        if num % 10 == 0 or c_idx == last:
            cx = gx + c_idx * hs.pitch + (hs.pitch - hs.gap) / 2
            out.append(text(cx, ty, str(num), "muted", hs.f_small, anchor="middle"))
    return out, ty + hs.f_small * 0.6


def hero_legend(x: float, y: float, size: float, width: float,
                swatch: float) -> tuple[list[str], float]:
    items = [(s, STATE_LABEL[s]) for s in STATES]
    items.append(("sending", "task that sends email or shares a file"))
    return legend(x, y, items, size, width, swatch)


def landed_note(f: Facts) -> str:
    fate = f.fate_of_landed
    total = sum(fate.values())
    parts = [f"{fate[DENIED]} had a send refused"]
    if fate[NONE]:
        parts.append(f"{fate[NONE]} made no send attempt")
    if fate[MISSING]:
        parts.append(f"{fate[MISSING]} have no result")
    if fate[SUCCEEDED] or fate[RECEIVED]:
        parts.append(f"{fate[SUCCEEDED] + fate[RECEIVED]} still reached the attacker")
    return (f"Of the {total} cases where the attack succeeded without Bouncer, with Bouncer "
            + ", ".join(parts[:-1]) + (" and " if len(parts) > 1 else "") + parts[-1] + ".")


def scope_note(f: Facts) -> str:
    return (f"One model ({f.model}), one fixed non-adaptive attack template "
            f"({f.attack}), one trial per case. Refused includes "
            f"{f.sink_verdicts['ask']} calls held for approval with no human present.")


def hero_svg(f: Facts) -> str:
    W, pad = 800, 20
    m = f.matrix
    hs = HeroSize(width=W - 2 * pad, label_w=56, count_w=44,
                  pitch=hero_pitch(len(m.user_tasks), W - 2 * pad, 56, 44),
                  f_head=14, f_text=12, f_small=12)
    b, s = f.succeeded["baseline"], f.succeeded["bouncer"]
    title = (f"Attacks that succeeded: {b.k} of {b.n} without Bouncer, "
             f"{s.k} of {s.n} with it")
    out = [text(pad, 32, title, "ink", 18, bold=True)]
    sub, y = paragraph(
        pad, 54, f"Each square is one attack case: a user task (column) given one injected "
        f"instruction (row). AgentDojo {f.suite}, {f.attack} attack, {f.model}.",
        "ink2", 13, W - 2 * pad)
    out += sub
    blk, y = hero_block(f, pad, y + 4, hs)
    out += blk
    leg, y = hero_legend(pad, y + 16, 12, W - 2 * pad, 11)
    out += leg
    notes, y = paragraph(pad, y + 2, landed_note(f) + " " + scope_note(f), "muted", 12,
                         W - 2 * pad, leading=1.45)
    out += notes
    desc = (f"Two grids of {len(m.user_tasks)} user tasks by {len(m.injections)} injections. "
            f"Without Bouncer {b.k} of {b.n} cases are red (attack succeeded) and "
            f"{f.received['baseline'].k - b.k} more are amber (sent to attacker). "
            f"With Bouncer there are no red or amber cells; {f.denied.k} of {f.denied.n} are "
            f"blue (Bouncer refused a send or share) and the rest gray. " + landed_note(f))
    return document(W, math.ceil(y + 6), title, desc, out)


# ---------------------------------------------------------------- outcomes


def outcomes_svg(f: Facts) -> str:
    W, pad = 800, 20
    bar_h = 24
    x0, bw = pad, W - 2 * pad
    out = [text(pad, 32, "What happened in each attack case", "ink", 18, bold=True)]
    sub, y = paragraph(
        pad, 54, "Every case is counted once; both bars run the full set of cases with a "
        "result. Counts are inside the bars.", "ink2", 13, bw)
    out += sub
    m = f.matrix
    rows = [
        ("baseline", "Without Bouncer", [(SUCCEEDED, "attack succeeded"),
                                         (RECEIVED, "send to attacker ran, not scored a success"),
                                         (NONE, "no send to the attacker")]),
        ("bouncer", "With Bouncer", [(SUCCEEDED, "attack succeeded"),
                                     (RECEIVED, "send to attacker ran"),
                                     (DENIED, "Bouncer refused a send/share"),
                                     (NONE, "no send attempted")]),
    ]
    for cond, name, parts in rows:
        c = m.counts(cond)
        n = sum(c.values()) - c[MISSING]
        y += 22
        out.append(text(x0, y, name, "ink", 14, bold=True))
        out.append(text(x0 + text_width(name, 14, True) + 8, y, f"{n} cases", "muted", 12))
        succ, recv = f.succeeded[cond], f.received[cond]
        y += 24
        bar_y = y + 10
        segs = partition([(s, c[s]) for s, _ in parts], x0, bw)
        if recv.k:
            x_end = next(sx + sw for s, sx, sw in segs if s == RECEIVED) if c[RECEIVED] else \
                next(sx + sw for s, sx, sw in segs if s == SUCCEEDED)
            out.append(f'<path d="M{_num(x0)},{_num(bar_y - 3)} V{_num(bar_y - 8)} '
                       f'H{_num(x_end)} V{_num(bar_y - 3)}" class="ink-stroke" '
                       f'stroke-width="1"/>')
            out.append(text(x0, bar_y - 13,
                            f"Send to the attacker ran: {recv.k}/{recv.n} ({pct(recv.rate)}, "
                            f"{ci_text(recv)}), of which AgentDojo scored {succ.k} a success",
                            "ink2", 12))
        else:
            out.append(text(x0, bar_y - 8,
                            f"Attack succeeded: {succ.k}/{succ.n} ({ci_text(succ)}) · "
                            f"sent to attacker: {recv.k}/{recv.n}", "ink", 13,
                            bold=True))
        for i, (state, sx, sw) in enumerate(segs):
            last = i == len(segs) - 1
            out.append(f"<g><title>{name}: {dict(parts)[state]}: {c[state]}/{n}</title>"
                       + _bar_segment(sx, bar_y, sw, bar_h, f"s-{state}", round_end=last)
                       + "</g>")
            label = str(c[state])
            if text_width(label, 13, True) + 12 < sw:
                cls = {SUCCEEDED: "on-dark", DENIED: "on-dark", RECEIVED: "on-light"}.get(
                    state, "on-none")
                out.append(text(sx + 8, bar_y + bar_h / 2 + 4.5, label, cls, 13, bold=True))
        ly = bar_y + bar_h + 17
        for state, sx, sw in segs:
            lab, _ = paragraph(sx, ly, dict(parts)[state], "ink2", 12, sw - 6, leading=1.3)
            out += lab
        y = ly + 16
    v = f.sink_verdicts
    note = (f"Refused: at least one send_email or share_file call in the case was denied. "
            f"Over all Bouncer cases, {v['deny']} such calls were denied, {v['ask']} held for "
            f"approval (no human, so not run) and {v['allow']} allowed. {f.denied_on_sending} of "
            f"the {f.denied.k} refused cases are sending tasks, where a refused call can be the "
            f"user's own send. One model ({f.model}), one fixed non-adaptive attack.")
    notes, y = paragraph(pad, y + 14, note, "muted", 12, bw, leading=1.45)
    out += notes
    b, s = f.succeeded["baseline"], f.succeeded["bouncer"]
    desc = (f"Two full-length bars. Without Bouncer: {b.k} attack succeeded, "
            f"{f.received['baseline'].k - b.k} sent to attacker but not scored a success, "
            f"the rest no send to the attacker, of {b.n}. With Bouncer: {s.k} succeeded, "
            f"{f.received['bouncer'].k} sent to attacker, {f.denied.k} Bouncer refused a send or "
            f"share, the rest no send attempted, of {s.n}.")
    return document(W, math.ceil(y + 4), "What happened in each attack case", desc, out)


def _bar_segment(x: float, y: float, w: float, h: float, cls: str, round_end: bool) -> str:
    if not round_end or w < 8:
        return rect(x, y, w, h, cls)
    r = 4
    return (f'<path class="{cls}" d="M{_num(x)},{_num(y)} H{_num(x + w - r)} '
            f'Q{_num(x + w)},{_num(y)} {_num(x + w)},{_num(y + r)} V{_num(y + h - r)} '
            f'Q{_num(x + w)},{_num(y + h)} {_num(x + w - r)},{_num(y + h)} H{_num(x)} Z"/>')


# ---------------------------------------------------------------- cost


@dataclass(frozen=True)
class CostGroup:
    title: str
    without: str  # condition without Bouncer
    with_: str    # condition with Bouncer
    rows: list[tuple[str, str, bool]]  # (label, part, highlight)


def cost_block(f: Facts, x: float, y: float, width: float, *, label_w: float, value_w: float,
               groups: list[CostGroup], f_text: float, row_h: float,
               group_titles: bool = True) -> tuple[list[str], float]:
    """Dumbbell rows, one per (label, part, highlight) in each group."""
    out: list[str] = []
    px0, px1 = x + label_w, x + width - value_w
    axis_y = y
    for t in (0, 0.25, 0.5, 0.75, 1.0):
        gxp = linear(t, 0, 1, px0, px1)
        out.append(text(gxp, axis_y, pct(t), "muted", f_text, anchor="middle"))
    out.append(text(x + width, axis_y, "without → with", "muted", f_text, anchor="end"))
    y = axis_y + f_text * 0.8
    grid_top = y
    rows_svg: list[str] = []
    for g in groups:
        if group_titles:
            y += f_text * 1.6
            rows_svg.append(text(x, y, g.title, "ink", f_text + 1, bold=True))
            y += f_text * 0.5
        else:
            y += f_text * 0.6
        for label, part, highlight in g.rows:
            cy = y + row_h / 2
            if highlight:
                rows_svg.append(rect(x - 6, y + 1, width + 12, row_h - 2, "band", rx=4))
            rows_svg.append(text(x, cy + f_text * 0.36, label, "ink2", f_text))
            a, b = f.util[(g.without, part)], f.util[(g.with_, part)]
            xa, xb = linear(a.rate, 0, 1, px0, px1), linear(b.rate, 0, 1, px0, px1)
            rows_svg.append(line(xa, cy, xb, cy, "axis", 2))
            for prop, cls, dy in ((a, "without", -5), (b, "bouncer", 5)):
                lo, hi = prop.ci
                rows_svg.append(line(linear(lo, 0, 1, px0, px1), cy + dy,
                                     linear(hi, 0, 1, px0, px1), cy + dy, f"{cls}-s", 1.5))
            for prop, cls, who in ((a, "without", "without Bouncer"),
                                   (b, "bouncer", "with Bouncer")):
                xp = linear(prop.rate, 0, 1, px0, px1)
                rows_svg.append(
                    f"<g><title>{escape(label)}, {who}: {prop.k}/{prop.n} = {pct(prop.rate)} "
                    f"({ci_text(prop)})</title>"
                    f'<circle cx="{_num(xp)}" cy="{_num(cy)}" r="5" class="{cls} ring" '
                    f'stroke-width="2"/></g>')
            rows_svg.append(text(x + width, cy + f_text * 0.36,
                                 f"{a.k}/{a.n} → {b.k}/{b.n}", "ink", f_text, anchor="end",
                                 bold=highlight))
            y += row_h
    for t in (0, 0.25, 0.5, 0.75, 1.0):
        gxp = linear(t, 0, 1, px0, px1)
        out.append(line(gxp, grid_top, gxp, y, "grid", 1))
    return out + rows_svg, y


def no_attack_group(f: Facts) -> CostGroup:
    nb = f.util[("benign-baseline", "other")].n
    return CostGroup(
        f"No attack ({f.util[('benign-baseline', 'all')].n} user tasks)",
        "benign-baseline", "benign-bouncer",
        [(f"Sending tasks ({len(f.sending_tasks)})", "sending", True),
         (f"Other tasks ({nb})", "other", False),
         ("All tasks", "all", False)])


def cost_legend(x: float, y: float, size: float) -> list[str]:
    out = [f'<circle cx="{_num(x + 5)}" cy="{_num(y - size * 0.35)}" r="5" class="without"/>',
           text(x + 15, y, "without Bouncer", "ink2", size)]
    x2 = x + 15 + text_width("without Bouncer", size) + 18
    out += [f'<circle cx="{_num(x2 + 5)}" cy="{_num(y - size * 0.35)}" r="5" class="bouncer"/>',
            text(x2 + 15, y, "with Bouncer", "ink2", size)]
    x3 = x2 + 15 + text_width("with Bouncer", size) + 18
    out += [line(x3, y - size * 0.35, x3 + 22, y - size * 0.35, "ink-stroke", 1.5),
            text(x3 + 28, y, "95% interval", "ink2", size)]
    return out


def cost_svg(f: Facts) -> str:
    W, pad = 800, 20
    ns = len(f.sending_tasks)
    title = "The cost: task completion with and without Bouncer"
    out = [text(pad, 32, title, "ink", 18, bold=True)]
    sub, y = paragraph(
        pad, 54,
        f"Share of user tasks AgentDojo scored as done. In this run Bouncer allowed no send "
        f"or share at all, so the {ns} tasks that email or share a file fail with it.",
        "ink2", 13, W - 2 * pad)
    out += sub
    out += cost_legend(pad, y + 6, 12)
    groups = [
        no_attack_group(f),
        CostGroup("Under attack (one case per task × injection)", "baseline", "bouncer",
                  [("Sending tasks", "sending", True), ("Other tasks", "other", False),
                   ("All cases", "all", False)]),
    ]
    blk, y = cost_block(f, pad, y + 36, W - 2 * pad, label_w=130, value_w=120, groups=groups,
                        f_text=12, row_h=28)
    out += blk
    a, b = f.util[("baseline", "all")], f.util[("bouncer", "all")]
    note = (f"Under attack, overall completion is higher with Bouncer ({a.k}/{a.n} → "
            f"{b.k}/{b.n}) because AgentDojo fails any task where an unwanted email "
            f"actually went out. Only "
            f"{ns} sending tasks, so their intervals are wide "
            f"({f.util[('benign-bouncer', 'sending')].k}/{f.util[('benign-bouncer', 'sending')].n}"
            f" has a 95% upper bound of {pct(f.util[('benign-bouncer', 'sending')].ci[1])}). "
            f"Asks were treated as denies (no human in the loop).")
    notes, y = paragraph(pad, y + 22, note, "muted", 12, W - 2 * pad, leading=1.45)
    out += notes
    desc = "; ".join(
        f"{label}: {f.util[(w, part)].k}/{f.util[(w, part)].n} without Bouncer, "
        f"{f.util[(wb, part)].k}/{f.util[(wb, part)].n} with"
        for (label, w, wb, part) in (
            ("no attack, sending tasks", "benign-baseline", "benign-bouncer", "sending"),
            ("no attack, other tasks", "benign-baseline", "benign-bouncer", "other"),
            ("no attack, all", "benign-baseline", "benign-bouncer", "all"),
            ("under attack, sending tasks", "baseline", "bouncer", "sending"),
            ("under attack, other tasks", "baseline", "bouncer", "other"),
            ("under attack, all", "baseline", "bouncer", "all"),
        )) + "."
    return document(W, math.ceil(y + 4), title, desc, out)


# ---------------------------------------------------------------- social cards


def headline(f: Facts) -> str:
    b, s = f.succeeded["baseline"], f.succeeded["bouncer"]
    return f"Exfiltration attacks: {b.k}/{b.n} succeeded without Bouncer, {s.k}/{s.n} with it"


def cost_line(f: Facts) -> str:
    a, b = f.util[("benign-baseline", "sending")], f.util[("benign-bouncer", "sending")]
    return (f"The cost: the {a.n} tasks that email or share a file went from "
            f"{a.k}/{a.n} to {b.k}/{b.n} completed.")


def fit_size(s: str, width: float, size: float, bold: bool = True) -> float:
    while size > 12 and text_width(s, size, bold) > width:
        size -= 0.5
    return size


def card_svg(f: Facts, W: int, H: int) -> str:
    pad = 40 if W > H else 44
    m = f.matrix
    square = W == H
    out: list[str] = []
    h = headline(f)
    if square:
        lines_, y = paragraph(pad, pad + 34, h, "ink", 40, W - 2 * pad, leading=1.18, bold=True)
    else:
        size = fit_size(h, W - 2 * pad, 32)
        lines_, y = [text(pad, pad + size, h, "ink", size, bold=True)], pad + size * 2.1
    out += lines_
    cl, y = paragraph(pad, y + (2 if square else -6), cost_line(f), "ink2", 21, W - 2 * pad,
                      leading=1.35)
    out += cl
    label_w, count_w = 74, 58
    pitch = hero_pitch(len(m.user_tasks), W - 2 * pad, label_w, count_w)
    hs = HeroSize(width=W - 2 * pad, label_w=label_w, count_w=count_w, pitch=pitch,
                  f_head=21, f_text=18, f_small=18, gap=3 if pitch >= 22 else 2)
    blk, y = hero_block(f, pad, y + 8, hs)
    out += blk
    leg, y = hero_legend(pad, y + 22, 18, W - 2 * pad, 15)
    out += leg
    if square:
        nb = f.util[("benign-baseline", "all")].n
        y += 14
        out.append(text(pad, y, f"Task completion with no attack ({nb} user tasks)", "ink", 21,
                        bold=True))
        cb, y = cost_block(f, pad, y + 34, W - 2 * pad, label_w=220, value_w=150,
                           groups=[no_attack_group(f)], f_text=18, row_h=42,
                           group_titles=False)
        out += cb
        out += cost_legend(pad, y + 30, 18)
        y += 40
    foot = (f"One model ({f.model}), one fixed non-adaptive attack ({f.attack}), "
            f"AgentDojo {f.suite}, scored by AgentDojo's own check. {REPO_LABEL}")
    fl, y = paragraph(pad, max(y + 8, H - pad - (18 * 1.4 if square else 18 * 2.6)), foot,
                      "muted", 18, W - 2 * pad, leading=1.4)
    out += fl
    desc = (headline(f) + ". " + cost_line(f) + " " + landed_note(f) + " " + scope_note(f))
    if y > H + 1:
        raise ValueError(f"card {W}x{H} overflows: content ends at y={y:.0f}")
    return document(W, H, headline(f), desc, out)


# ---------------------------------------------------------------- output


def render_all(rows: list[dict[str, Any]]) -> dict[str, str]:
    f = facts(rows)
    return {
        "agentdojo-cases.svg": hero_svg(f),
        "agentdojo-outcomes.svg": outcomes_svg(f),
        "agentdojo-cost.svg": cost_svg(f),
        "agentdojo-card-1200x675.svg": card_svg(f, 1200, 675),
        "agentdojo-card-1080x1080.svg": card_svg(f, 1080, 1080),
    }


def svg_size(svg: str) -> tuple[int, int]:
    head = svg.split(">", 1)[0]
    w = float(head.split(' width="', 1)[1].split('"', 1)[0])
    h = float(head.split(' height="', 1)[1].split('"', 1)[0])
    return int(w), int(h)


def render_png(svg_path: Path, png_path: Path, scale: int = 2) -> bool:
    """Light-theme PNG via Quick Look. Returns False, quietly, without qlmanage/sips."""
    if not (shutil.which("qlmanage") and shutil.which("sips")):
        return False
    svg = svg_path.read_text()
    w, h = svg_size(svg)
    side = max(w, h)
    # Quick Look renders into a square; centre the figure in a square viewBox so
    # sips's centred crop cuts exactly the figure back out. Force the light theme.
    head, rest = svg.split(">", 1)
    head = (head.replace("<svg ", '<svg class="light" ', 1)
            .replace(f'viewBox="0 0 {w} {h}"',
                     f'viewBox="{-(side - w) / 2} {-(side - h) / 2} {side} {side}"')
            .replace(f'width="{w}" height="{h}"', f'width="{side}" height="{side}"'))
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / svg_path.name
        src.write_text(f"{head}>{rest}")
        subprocess.run(["qlmanage", "-t", "-s", str(side * scale), "-o", tmp, str(src)],
                       check=True, capture_output=True)
        thumb = Path(tmp) / f"{svg_path.name}.png"
        if not thumb.exists():
            return False
        subprocess.run(["sips", "-c", str(h * scale), str(w * scale), str(thumb),
                        "--out", str(png_path)], check=True, capture_output=True)
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--png", action="store_true", help="also render PNGs (macOS only)")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for name, svg in render_all(load_rows(args.results)).items():
        path = args.out / name
        path.write_text(svg)
        print(path.relative_to(ROOT) if path.is_relative_to(ROOT) else path)
        if args.png:
            png = path.with_suffix(".png")
            if render_png(path, png):
                print(png.relative_to(ROOT) if png.is_relative_to(ROOT) else png)


if __name__ == "__main__":
    main()
