"""
Triagle — personal-data masking for Indian identifiers.

Runs on every prompt before it leaves the process for a model API, and is
reversed on the way back so the analyst still sees real values. The model
only ever sees stable placeholders (<AADHAAR_1>, <PAN_1>, ...), so it can
still reason about "the same person" across a prompt.

What it recognises:
  Aadhaar   12 digits, optionally grouped 4-4-4, first digit 2-9, and the
            Verhoeff check digit must be valid (cuts false matches on order
            numbers, phone-like strings and so on)
  PAN       AAAPL1234C shape with a valid holder-type letter in position 4
  UPI ID    name@handle, where the handle has no dot (so not an email)
  Mobile    Indian 10-digit mobile, optional +91 / 0 prefix
  Email     ordinary addresses

Honest limits: this is pattern matching. It does not find names, addresses,
or identifiers written in words, and it is not a substitute for running the
model inside the customer's network when the data is sensitive.
"""
import re

_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
      [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
      [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
      [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
_INV = [0,4,3,2,1,5,6,7,8,9]


def verhoeff_valid(digits):
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(digits):
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


_AADHAAR = re.compile(r"(?<![\d])([2-9]\d{3})[ -]?(\d{4})[ -]?(\d{4})(?![\d])")
_PAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z](?![A-Za-z0-9])")
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![\w-])")
_UPI = re.compile(r"(?<![\w.+-])[A-Za-z0-9][\w.-]{1,255}@[A-Za-z]{2,64}(?![\w.-])")
_MOBILE = re.compile(r"(?<![\d])(?:\+91[ -]?|0)?[6-9]\d{9}(?![\d])")


def _aadhaar_ok(m):
    return verhoeff_valid("".join(m.groups()))


# order matters: longer / stricter shapes first
_RULES = [
    ("AADHAAR", _AADHAAR, _aadhaar_ok),
    ("PAN", _PAN, None),
    ("EMAIL", _EMAIL, None),
    ("UPI", _UPI, None),
    ("MOBILE", _MOBILE, None),
]


def mask(text, mapping=None):
    """Returns (masked_text, mapping). mapping is placeholder -> original.
    Pass the same mapping to several calls to keep placeholders consistent."""
    if mapping is None:
        mapping = {}
    if not text:
        return text, mapping
    reverse = {v: k for k, v in mapping.items()}
    counters = {}
    for k in mapping:
        kind, _, n = k.strip("<>").rpartition("_")
        counters[kind] = max(counters.get(kind, 0), int(n))

    for kind, rx, check in _RULES:
        def repl(m, kind=kind, check=check):
            if check and not check(m):
                return m.group(0)
            original = m.group(0)
            if original in reverse:
                return reverse[original]
            counters[kind] = counters.get(kind, 0) + 1
            token = f"<{kind}_{counters[kind]}>"
            mapping[token] = original
            reverse[original] = token
            return token
        text = rx.sub(repl, text)
    return text, mapping


def unmask(text, mapping):
    if not text or not mapping:
        return text
    for token in sorted(mapping, key=len, reverse=True):
        text = text.replace(token, mapping[token])
    return text


def summary(mapping):
    """{'AADHAAR': 1, 'PAN': 2} — counts only, never values."""
    out = {}
    for token in mapping or {}:
        kind = token.strip("<>").rpartition("_")[0]
        out[kind] = out.get(kind, 0) + 1
    return out
