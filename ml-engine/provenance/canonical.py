"""RFC 8785 JSON Canonicalization Scheme.

Tamper detection is only as good as the serialisation it hashes. An ad-hoc scheme --
joining fields with a separator, or `json.dumps` with default settings -- breaks in ways
that are easy to overlook and fatal in practice:

* **Separator injection.** Joining fields with ``||`` means a prediction of
  ``"STOP||0.99"`` collides with a different record. The digest stops being a function of
  the *structure*.
* **Cross-implementation drift.** Python renders ``0.1 + 0.2`` and large integers
  differently from JavaScript. A record sealed by the Python engine would then fail
  verification in the Node gateway, producing false TAMPERED alerts -- which is how an
  integrity system gets switched off.
* **Key ordering and escaping.** Two semantically identical objects must produce
  identical bytes.

RFC 8785 (JCS) solves all three: keys sorted by UTF-16 code unit, no insignificant
whitespace, minimal string escaping, and numbers rendered by the ECMAScript
``Number::toString`` algorithm. Implementing the same scheme in Python and TypeScript is
what lets either side seal a record and the other verify it.
"""

from __future__ import annotations

import math
import re
from typing import Any

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}

_EXPONENT = re.compile(r"^(-?)(\d)(?:\.(\d+))?e([+-])(\d+)$")


def serialize_number(value: float | int) -> str:
    """Render a number per the ECMAScript ``Number::toString`` algorithm.

    This is the fiddly part of JCS. Python's ``repr`` agrees with JavaScript for most
    doubles because both emit the shortest round-tripping representation, but the
    exponent formatting and the integer/float boundary differ, so those are normalised
    explicitly.
    """
    if isinstance(value, bool):  # bool is a subclass of int; never let it through here
        raise TypeError("bool is not a JSON number")

    if isinstance(value, int):
        return str(value)

    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN and Infinity cannot be canonicalised (RFC 8785 section 3.2.2.3)")

    if value == 0:
        # JavaScript renders -0 as "0".
        return "0"

    # An integral double renders without a fractional part in JavaScript.
    if value.is_integer() and abs(value) < 1e21:
        return str(int(value))

    text = repr(float(value))

    if "e" in text or "E" in text:
        text = text.replace("E", "e")
        match = _EXPONENT.match(text)
        if match:
            sign, lead, fraction, exp_sign, exp_digits = match.groups()
            mantissa = f"{lead}.{fraction}" if fraction else lead
            exponent = int(exp_digits)
            # ECMAScript uses decimal notation for exponents in [-7, 21).
            if exp_sign == "+" and exponent < 21:
                return f"{sign}{float(text):.0f}" if float(text).is_integer() else f"{sign}{float(text)!r}"
            text = f"{sign}{mantissa}e{'+' if exp_sign == '+' else '-'}{exponent}"

    return text


def serialize_string(value: str) -> str:
    """Minimal JSON string escaping per RFC 8785 section 3.2.2.2."""
    out = ['"']
    for char in value:
        escape = _ESCAPES.get(char)
        if escape is not None:
            out.append(escape)
        elif ord(char) < 0x20:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def canonicalize(value: Any) -> str:
    """Produce the canonical JSON text for `value`."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return serialize_string(value)
    if isinstance(value, (int, float)):
        return serialize_number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 sorts by UTF-16 code unit. Python sorts str by code point, which
        # differs only for characters above the BMP; encoding to UTF-16 makes it exact.
        items = sorted(value.items(), key=lambda kv: str(kv[0]).encode("utf-16-be"))
        return "{" + ",".join(f"{serialize_string(str(k))}:{canonicalize(v)}" for k, v in items) + "}"

    raise TypeError(f"{type(value).__name__} is not JSON-serialisable and cannot be canonicalised")


def canonical_bytes(value: Any) -> bytes:
    return canonicalize(value).encode("utf-8")


__all__ = ["canonical_bytes", "canonicalize", "serialize_number", "serialize_string"]
