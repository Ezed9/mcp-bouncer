# bouncer/src/bouncer/taint.py
"""Value-level provenance tracking across tool calls.

Every untrusted tool output is recorded (folded, see `fold`). A later argument
value is `tainted` iff it appears inside some recorded output as a whole token:
`ana@x.com` inside `dana@x.com` does not count. This decides DENY vs ASK in the
sink gate — it is NOT the safety mechanism (deny-unless-trusted is), so
approximate matching is acceptable: a missed match degrades to ASK, never to a
silent ALLOW.
"""

from __future__ import annotations

import html
import re
import string
import unicodedata
from urllib.parse import unquote

_WS = re.compile(r"\s+")
_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
# A match must not be glued to more address characters on either side. A
# trailing "." or "-" only continues the token if more word characters follow,
# so "attacker@evil.com." at the end of a sentence still matches.
_BEFORE = r"(?<![\w.%+\-])"
_AFTER = r"(?![\w%+@]|[.\-]\w)"


def normalize(text: str) -> str:
    """Identity of a destination for the allowlist and approvals.

    Trims, collapses whitespace runs and lowercases ASCII letters only. Full
    Unicode lowercasing would map KELVIN SIGN (U+212A) to "k", so a different
    string would match an allowlisted or approved one.
    """
    return _WS.sub(" ", str(text).strip()).translate(_ASCII_LOWER)


def fold(text: str) -> str:
    """Looser form used only for taint matching, where wider is safer.

    NFKC (full-width "＠" -> "@"), drops invisible format characters
    (zero-width space, soft hyphen, ...), case-folds and collapses whitespace.
    Never used for trust: widening a match here can only turn ASK into DENY.
    """
    t = unicodedata.normalize("NFKC", str(text))
    t = "".join(ch for ch in t if unicodedata.category(ch) != "Cf")
    return _WS.sub(" ", t.strip()).casefold()


_JSON_ESCAPE = re.compile(r'\\(?:u([0-9a-fA-F]{4})|([nrtbf/"\\]))')
_JSON_CHARS = {"n": "\n", "r": "\r", "t": "\t", "b": " ", "f": " "}


def _json_unescape(text: str) -> str:
    def repl(m: re.Match[str]) -> str:
        if m.group(1):
            return chr(int(m.group(1), 16))
        return _JSON_CHARS.get(m.group(2), m.group(2))

    return _JSON_ESCAPE.sub(repl, text)


def _html_percent_decode(text: str) -> str:
    return unquote(html.unescape(text))


class TaintTracker:
    def __init__(self, min_len: int = 6) -> None:
        self._min_len = min_len
        self._outputs: list[str] = []

    def record_output(self, text: str) -> None:
        # Also keep decoded forms, so the plain address the agent reads and
        # sends is tainted. JSON escapes: a server that returns JSON as text
        # writes a newline as "\n", and "...\nattacker@evil.com" would glue an
        # "n" onto the address. HTML entities and percent-encoding:
        # "attacker&#64;evil.com", "mailto:attacker%40evil.com".
        forms = [text]
        for decode in (_json_unescape, _html_percent_decode):
            for form in list(forms):
                decoded = decode(form)
                if decoded not in forms:
                    forms.append(decoded)
        self._outputs.extend(fold(form) for form in forms)

    def classify(self, value: str) -> bool:
        needle = fold(value)
        if len(needle) < self._min_len:
            return False
        pattern = re.compile(_BEFORE + re.escape(needle) + _AFTER)
        return any(pattern.search(hay) for hay in self._outputs)
