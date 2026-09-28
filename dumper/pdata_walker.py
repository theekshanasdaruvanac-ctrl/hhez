""".pdata (PE exception directory) walker: exact function extents.

The exception directory is a RUNTIME_FUNCTION array the OS uses for x64
stack unwinding. Its BeginAddress/EndAddress pairs are the compiler's own
answer to "where does this function live" — strictly better than
prologue heuristics, and present in every FiveM citizen module.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from dumper.pe_parser import Image, IMAGE_DIRECTORY_ENTRY_EXCEPTION


@dataclass(frozen=True, order=True)
class FuncRange:
    begin: int  # RVA, inclusive
    end: int    # RVA, exclusive

    def contains(self, rva: int) -> bool:
        return self.begin <= rva < self.end

    def size(self) -> int:
        return self.end - self.begin


class Inventory:
    def __init__(self, funcs: list[FuncRange]):
        self.funcs = funcs  # sorted by begin

    def __len__(self) -> int:
        return len(self.funcs)

    def find(self, rva: int) -> FuncRange | None:
        lo, hi = 0, len(self.funcs) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            f = self.funcs[mid]
            if rva < f.begin:
                hi = mid - 1
            elif rva >= f.end:
                lo = mid + 1
            else:
                return f
        return None

    def containing(self, rva: int) -> list[FuncRange]:
        # chained unwind info can make extents overlap; return all owners
        return [f for f in self.funcs if f.contains(rva)]


def walk(img: Image) -> Inventory | None:
    d = img.data_dirs.get(IMAGE_DIRECTORY_ENTRY_EXCEPTION)
    if not d:
        return None
    rva, size = d
    blob = img.read(rva, size - size % 12)
    if blob is None:
        return None
    funcs: list[FuncRange] = []
    for i in range(0, len(blob), 12):
        begin, end, _unwind = struct.unpack_from("<III", blob, i)
        if begin and end > begin:
            funcs.append(FuncRange(begin, end))
    if not funcs:
        return None
    funcs.sort()
    return Inventory(funcs)
