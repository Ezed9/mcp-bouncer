# bouncer/src/bouncer/taint.py
"""Value-level provenance tracking across tool calls.

Every untrusted tool output is recorded (normalized). A later argument value is
`tainted` iff it appears verbatim (modulo case/whitespace) inside some recorded
output as a whole token: `ana@x.com` inside `dana@x.com` does not count. This
decides DENY vs ASK in the sink gate — it is NOT the safety mechanism
(deny-unless-trusted is), so approximate matching is acceptable: a missed match
degrades to ASK, never to a silent ALLOW.
"""

from __future__ import annotations

import re

_WS = re.compile(r"\s+")
# A match must not be glued to more address characters on either side. A
# trailing "." or "-" only continues the token if more word characters follow,
# so "attacker@evil.com." at the end of a sentence still matches.
_BEFORE = r"(?<![\w.%+\-])"
_AFTER = r"(?![\w%+@]|[.\-]\w)"


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
        pattern = re.compile(_BEFORE + re.escape(needle) + _AFTER)
        return any(pattern.search(hay) for hay in self._outputs)
