"""Symbol table lookups: by name, and from an address to the nearest symbol."""

from __future__ import annotations

import bisect
from typing import Dict, List, Optional, Tuple

# Addresses further than this past a symbol are not described relative to it
MAX_SYMBOL_DISTANCE = 0x100000


class SymbolTable:
    """Program symbols (name -> address) with fast reverse lookup."""

    def __init__(self, symbols: Optional[Dict[str, int]] = None) -> None:
        self._by_name: Dict[str, int] = dict(symbols or {})
        # One name per address; when several symbols share an address the
        # last one defined is used
        by_addr = {addr: name for name, addr in self._by_name.items()}
        self._addrs: List[int] = sorted(by_addr)
        self._names: List[str] = [by_addr[a] for a in self._addrs]

    def __len__(self) -> int:
        return len(self._by_name)

    def __contains__(self, name: object) -> bool:
        return name in self._by_name

    def as_dict(self) -> Dict[str, int]:
        """A copy of the table as name -> address."""
        return dict(self._by_name)

    def lookup(self, name: str) -> Optional[int]:
        """Address of a symbol, or None."""
        return self._by_name.get(name)

    def nearest(self, addr: int) -> Tuple[Optional[str], Optional[int]]:
        """(symbol, offset) for the closest symbol at or before ``addr``.

        Returns (None, None) when there is none within MAX_SYMBOL_DISTANCE.
        """
        index = bisect.bisect_right(self._addrs, addr) - 1
        if index < 0:
            return (None, None)
        offset = addr - self._addrs[index]
        if offset > MAX_SYMBOL_DISTANCE:
            return (None, None)
        return (self._names[index], offset)

    def describe(self, addr: int) -> str:
        """``<symbol>`` or ``<symbol+offset>`` for an address, or "" if none."""
        name, offset = self.nearest(addr)
        if name is None:
            return ""
        return f"<{name}>" if offset == 0 else f"<{name}+{offset}>"
