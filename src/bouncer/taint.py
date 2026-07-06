# bouncer/src/bouncer/taint.py
"""Value-level provenance tracking across tool calls.

Every untrusted tool output is recorded (normalized). A later argument value is
`tainted` iff it appears verbatim (modulo case/whitespace) inside some recorded
output. This decides DENY vs ASK in the sink gate — it is NOT the safety
mechanism (deny-unless-trusted is), so approximate matching is acceptable: a
missed match degrades to ASK, never to a silent ALLOW.
"""

from __future__ import annotations

import re

_WS = re.compile(r"\s+")


def normalize(text: str) -> str:
    return _WS.sub(" ", str(text).strip().lower())


class TaintTracker:
    def __init__(self, min_len: int = 6) -> None:
        self._min_len = min_len
        self._outputs: list[str] = []

    def record_output(self, text: str) -> None:
        self._outputs.append(normalize(text))

    def classify(self, value: str) -> bool:
        needle = normalize(value)
        if len(needle) < self._min_len:
            return False
        return any(needle in hay for hay in self._outputs)
