"""
Operand parsing and expression evaluation shared by the built-in encoders.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Tuple, Type


class EncodeError(ValueError):
    """Raised when an instruction cannot be encoded."""


_RELOC_RE = re.compile(r"^%(hi|lo|pcrel_hi|pcrel_lo)\((.*)\)$", re.IGNORECASE)

_TOKEN_RE = re.compile(
    r"""\s*(?:
      (?P<num>0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)
    | (?P<char>'(?:\\.|[^\\'])'?)
    | (?P<func>%[A-Za-z_]+)
    | (?P<ident>[A-Za-z_.$][\w.$]*)
    | (?P<op><<|>>|[-+*/%&|^~()!])
    )""",
    re.VERBOSE,
)

_ESCAPES = {
    "n": 10,
    "t": 9,
    "r": 13,
    "0": 0,
    "\\": 92,
    "'": 39,
    '"': 34,
    "a": 7,
    "b": 8,
    "f": 12,
    "v": 11,
}


def _number(text: str) -> int:
    """Integer literal with GNU as rules: 0x hex, 0b binary, leading 0 octal."""
    lower = text.lower()
    if lower.startswith("0x"):
        return int(text[2:], 16)
    if lower.startswith("0b"):
        return int(text[2:], 2)
    if len(text) > 1 and text.startswith("0"):
        return int(text, 8)
    return int(text, 10)


def _char(text: str) -> int:
    """Character literal: 'A', 'A (GNU's older form), or an escape like '\\n'."""
    body = text[1:-1] if len(text) > 2 and text.endswith("'") else text[1:]
    if body.startswith("\\") and len(body) == 2:
        if body[1] not in _ESCAPES:
            raise ValueError(f"unknown escape in character literal {text}")
        return _ESCAPES[body[1]]
    if len(body) != 1:
        raise ValueError(f"bad character literal {text}")
    return ord(body)


def parse_int(text: str) -> Optional[int]:
    """Parse a lone integer or character literal, or return None."""
    t = text.strip()
    sign = 1
    if t[:1] in "+-" and len(t) > 1:
        sign = -1 if t[0] == "-" else 1
        t = t[1:].strip()
    try:
        if t.startswith("'"):
            return sign * _char(t)
        if re.fullmatch(r"0[xX][0-9a-fA-F]+|0[bB][01]+|\d+", t):
            return sign * _number(t)
    except ValueError:
        return None
    return None


class ExpressionError(ValueError):
    """An expression could not be parsed or evaluated."""


class UndefinedSymbol(ExpressionError):
    """An expression refers to a symbol that is not (yet) defined."""

    def __init__(self, name: str):
        super().__init__(f"undefined symbol '{name}'")
        self.name = name


def evaluate(
    text: str,
    resolve: Callable[[str], int],
    function: Optional[Callable[[str, int], int]] = None,
) -> int:
    """
    Evaluate an assembler expression with GNU as semantics.

    Supports integer and character literals, symbols (looked up with
    ``resolve``, which raises UndefinedSymbol if unknown), parentheses, unary
    ``- + ~ !``, and the binary operators in GNU as precedence order:

        highest:  *  /  %  <<  >>
                  |  &  ^  !        (a ! b is a | ~b)
        lowest:   +  -

    Functions such as ``%hi(expr)`` are passed to ``function(name, value)``.
    Division truncates toward zero, as in C.

    Raises:
        ExpressionError: For malformed expressions or division by zero.
    """
    tokens: List[Tuple[str, str]] = []
    pos = 0
    text = text.rstrip()
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise ExpressionError(f"cannot parse expression '{text.strip()}'")
        kind = m.lastgroup or ""
        tokens.append((kind, m.group(kind)))
        pos = m.end()
    if not tokens:
        raise ExpressionError("missing expression")

    index = 0

    def peek() -> Tuple[Optional[str], Optional[str]]:
        return tokens[index] if index < len(tokens) else (None, None)

    def take() -> Tuple[Optional[str], Optional[str]]:
        nonlocal index
        tok = peek()
        index += 1
        return tok

    def expect(value: str) -> None:
        kind, tok = take()
        if tok != value:
            raise ExpressionError(f"expected '{value}' in '{text.strip()}'")

    def primary() -> int:
        kind, tok = take()
        if tok is None:
            raise ExpressionError(f"incomplete expression '{text.strip()}'")
        if kind == "num":
            return _number(tok)
        if kind == "char":
            return _char(tok)
        if kind == "ident":
            return resolve(tok)
        if kind == "func":
            if function is None:
                raise ExpressionError(f"{tok}() is not supported here")
            expect("(")
            value = additive()
            expect(")")
            return function(tok[1:].lower(), value)
        if tok == "(":
            value = additive()
            expect(")")
            return value
        if tok == "-":
            return -primary()
        if tok == "+":
            return primary()
        if tok == "~":
            return ~primary()
        if tok == "!":
            return int(primary() == 0)
        raise ExpressionError(f"cannot parse expression '{text.strip()}'")

    def multiplicative() -> int:
        value = primary()
        while peek()[1] in ("*", "/", "%", "<<", ">>"):
            op = take()[1]
            rhs = primary()
            if op == "*":
                value *= rhs
            elif op in ("/", "%"):
                if rhs == 0:
                    raise ExpressionError("division by zero")
                quotient = abs(value) // abs(rhs) * (1 if (value >= 0) == (rhs >= 0) else -1)
                value = quotient if op == "/" else value - quotient * rhs
            elif op == "<<":
                value <<= rhs
            else:
                value >>= rhs
        return value

    def bitwise() -> int:
        value = multiplicative()
        while peek()[1] in ("|", "&", "^", "!"):
            op = take()[1]
            rhs = multiplicative()
            if op == "|":
                value |= rhs
            elif op == "&":
                value &= rhs
            elif op == "^":
                value ^= rhs
            else:
                value |= ~rhs
        return value

    def additive() -> int:
        value = bitwise()
        while peek()[1] in ("+", "-"):
            op = take()[1]
            rhs = bitwise()
            value = value + rhs if op == "+" else value - rhs
        return value

    result = additive()
    if index != len(tokens):
        raise ExpressionError(f"cannot parse expression '{text.strip()}'")
    return result


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
        hi_range: Optional[Tuple[int, int]] = None,
    ):
        self.address = address
        self.labels = labels
        # When not strict (the sizing pass), unknown symbols evaluate to 0
        self.strict = strict
        self.error = error
        # Width of the low part for %hi/%lo: 12 on RISC-V, 16 on MIPS
        self.lo_bits = lo_bits
        # Values %hi accepts (RV64: those lui+addi can build, i.e. signed 32-bit)
        self.hi_range = hi_range

    def symbol(self, name: str) -> int:
        if name == ".":
            return self.address
        if name in self.labels:
            return self.labels[name]
        if self.strict:
            raise UndefinedSymbol(name)
        return 0

    def _function(self, name: str, value: int) -> int:
        lo_bits = self.lo_bits
        hi_mask = (1 << (32 - lo_bits)) - 1
        if name == "hi":
            if self.hi_range is not None and not self.hi_range[0] <= value <= self.hi_range[1]:
                raise ExpressionError(
                    f"%hi: value 0x{value & 0xFFFFFFFFFFFFFFFF:x} is out of range "
                    "(on RV64, lui sign-extends; use la to load an address)"
                )
            # Rounded so that (%hi << lo_bits) + sign-extended %lo == value
            return ((value + (1 << (lo_bits - 1))) >> lo_bits) & hi_mask
        if name == "lo":
            return sign_extend(value, lo_bits)
        if name == "pcrel_hi":
            offset = value - self.address
            return ((offset + 0x800) >> 12) & 0xFFFFF
        if name == "pcrel_lo":
            # %pcrel_lo(label) names the auipc instruction, which this
            # encoder does not track; la/lla/lw symbol do the same job
            raise ExpressionError("%pcrel_lo is not supported; use la or lla instead")
        raise ExpressionError(f"unknown function %{name}")

    def eval(self, text: str) -> int:
        """Evaluate an operand expression such as 'label+8' or '%lo(msg)'."""
        if not text.strip():
            raise self.error("missing operand")
        try:
            return evaluate(text, self.symbol, self._function)
        except ExpressionError as e:
            raise self.error(str(e))


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
