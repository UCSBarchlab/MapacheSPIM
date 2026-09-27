"""
Operand parsing and expression evaluation shared by the built-in encoders.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Type


class EncodeError(ValueError):
    """Raised when an instruction cannot be encoded."""


_RELOC_RE = re.compile(r"^%(hi|lo|pcrel_hi|pcrel_lo)\((.*)\)$", re.IGNORECASE)
_TERM_RE = re.compile(r"\s*([+-]?)\s*([^+\-\s][^+\-]*)")


def parse_int(text: str) -> Optional[int]:
    """Parse an integer or character literal, or return None."""
    t = text.strip()
    if len(t) >= 3 and t[0] == "'" and t[-1] == "'":
        body = t[1:-1]
        escapes = {"\\n": 10, "\\t": 9, "\\r": 13, "\\0": 0, "\\\\": 92, "\\'": 39}
        if body in escapes:
            return escapes[body]
        if len(body) == 1:
            return ord(body)
        return None
    try:
        return int(t, 0)
    except ValueError:
        pass
    # int(..., 0) rejects leading zeros like "010"; accept them as decimal
    if re.fullmatch(r"[+-]?\d+", t):
        return int(t, 10)
    return None


def sign_extend(value: int, bits: int) -> int:
    """Interpret the low ``bits`` bits of value as a signed integer."""
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


class Context:
    """Address and symbol information needed to encode one instruction."""

    def __init__(
        self,
        address: int,
        labels: Dict[str, int],
        strict: bool = True,
        error: Type[EncodeError] = EncodeError,
        lo_bits: int = 12,
    ):
        self.address = address
        self.labels = labels
        # When not strict (the sizing pass), unknown symbols evaluate to 0
        self.strict = strict
        self.error = error
        # Width of the low part for %hi/%lo: 12 on RISC-V, 16 on MIPS
        self.lo_bits = lo_bits

    def symbol(self, name: str) -> int:
        if name in self.labels:
            return self.labels[name]
        if self.strict:
            raise self.error(f"undefined symbol '{name}'")
        return 0

    def eval(self, text: str) -> int:
        """Evaluate an operand expression such as 'label+8' or '%lo(msg)'."""
        text = text.strip()
        if not text:
            raise self.error("missing operand")

        m = _RELOC_RE.match(text)
        if m:
            kind, inner = m.group(1).lower(), m.group(2)
            value = self.eval(inner)
            lo_bits = self.lo_bits
            hi_mask = (1 << (32 - lo_bits)) - 1
            if kind == "hi":
                # Rounded so that (%hi << lo_bits) + sign-extended %lo == value
                return ((value + (1 << (lo_bits - 1))) >> lo_bits) & hi_mask
            if kind == "lo":
                return sign_extend(value, lo_bits)
            if kind == "pcrel_hi":
                offset = value - self.address
                return ((offset + 0x800) >> 12) & 0xFFFFF
            # %pcrel_lo(label) names the auipc instruction; the low part is
            # relative to that instruction's pc and the auipc's target.
            raise self.error("%pcrel_lo is not supported; use la or lla instead")

        literal = parse_int(text)
        if literal is not None:
            return literal

        total = 0
        pos = 0
        matched = False
        for m2 in _TERM_RE.finditer(text):
            if m2.start() != pos and text[pos : m2.start()].strip():
                break
            sign, term = m2.group(1), m2.group(2).strip()
            v = parse_int(term)
            if v is None:
                if not re.fullmatch(r"[A-Za-z_.$][\w.$]*", term):
                    raise self.error(f"cannot parse expression '{text}'")
                v = self.symbol(term)
            total += -v if sign == "-" else v
            pos = m2.end()
            matched = True
        if not matched or text[pos:].strip():
            raise self.error(f"cannot parse expression '{text}'")
        return total


def split_operands(text: str) -> List[str]:
    """Split operands on commas that are not inside parentheses or quotes."""
    ops: List[str] = []
    depth = 0
    quote = False
    cur = ""
    for ch in text:
        if ch == "'" and depth == 0:
            quote = not quote
        if not quote:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "," and depth == 0:
                ops.append(cur.strip())
                cur = ""
                continue
        cur += ch
    if cur.strip() or ops:
        ops.append(cur.strip())
    return ops
