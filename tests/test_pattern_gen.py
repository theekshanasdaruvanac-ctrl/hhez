"""Offline unit tests: no FiveM binaries needed (CI runs these pre-fetch)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dumper.pattern_gen import Pattern, PatternError, scan, shared_prologue_length


class FakeSection:
    def __init__(self, rva: int, data: bytes):
        self.rva = rva
        self.vsize = len(data)
        self.raw_size = len(data)
        self._data = data


class FakeImage:
    """Just the surface pattern_gen.scan touches."""

    def __init__(self, data: bytes, rva: int = 0x1000):
        self.sec = FakeSection(rva, data)

    def text(self):
        return self.sec

    def read(self, rva: int, size: int):
        if rva < self.sec.rva:
            return None
        off = rva - self.sec.rva
        return self.sec._data[off:off + size]


def test_pattern_text_roundtrip():
    p = Pattern.from_text("48 8B 05 ?? ?? ?? ?? 48 8B 90")
    assert p.length() == 10
    assert p.mask() == "xxx????xxx"
    assert Pattern.from_text(p.to_text()).toks == p.toks


def test_pattern_rejects_junk():
    with pytest.raises(PatternError):
        Pattern.from_text("48 XY 05")
    with pytest.raises(PatternError):
        Pattern.from_text("")


def test_scan_wildcards_exact():
    code = bytes([0x90, 0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x44,
                  0x48, 0x8B, 0x90, 0x90])
    img = FakeImage(code)
    hits = scan(img, Pattern.from_text("48 8B 05 ?? ?? ?? ?? 48 8B 90"))
    assert hits == [0x1001]          # one hit, at its RVA


def test_scan_no_hit_when_fixed_byte_differs():
    code = bytes([0x48, 0x8B, 0x05, 1, 2, 3, 4, 0x48, 0x99, 0x90])
    img = FakeImage(code)
    assert scan(img, Pattern.from_text("48 8B 05 ?? ?? ?? ?? 48 8B 90")) == []


def test_scan_all_wildcards_is_error():
    img = FakeImage(b"\x90" * 16)
    with pytest.raises(PatternError):
        scan(img, Pattern.from_text("?? ?? ?? ??"))


def test_store_ctx_wildcards_only_the_rel32():
    # call rel32 + store: window must carry regardless of call target
    a = bytes([0xE8, 0x0D, 0x23, 0x00, 0x00, 0x48, 0x89, 0x47, 0x58])
    b = bytes([0xE8, 0xAA, 0xBB, 0xCC, 0xDD, 0x48, 0x89, 0x47, 0x58])
    img_a, img_b = FakeImage(a), FakeImage(b)
    pat = Pattern.from_text("E8 ?? ?? ?? ?? 48 89 47 58")
    assert scan(img_a, pat) == [0x1000]
    assert scan(img_b, pat) == [0x1000]   # same pattern, other rel32


def test_shared_prologue_length():
    bodies = [bytes([0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x01]),
              bytes([0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x02])]
    assert shared_prologue_length(bodies) == 6
