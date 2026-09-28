"""Walk luaL_Reg-lite registration tables out of a PE image.

typedef struct luaL_Reg { const char *name; lua_CFunction func; } luaL_Reg;
FiveM's fork uses the std::string_view-flavored variant; both shapes are
handled (raw chars, or pointer to {ptr,len}).

Discovery is recursive, mirroring how the runtime itself finds its
libraries:
  1. seed tables: exports named *GetLuaLibs* / *GetCitizenLibs* open with
     `lea rax,[rip+table]; ret`
  2. their entries are *loader* functions (luaopen_* shape); a loader's
     body contains `lea reg,[rip+inner_table]` feeding luaL_setfuncs —
     walk those too
  3. repeat for the second layer (bounded)

Validity: name resolves to printable ascii AND func lands inside the
.text section. pdata-entry is recorded per entry as `pdata_verified`
instead of being a hard gate/linker: ICF folds identical bodies and the
folded survivor can be registered from a non-entry address (observed on
real builds), and refusing those drops legitimate members. The
section check plus recursive-from-export provenance is what makes a false
table nearly impossible; a linear .rdata sweep would not be, and this
does not do one.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_REG_RIP

from dumper.pe_parser import Image
from dumper.pdata_walker import Inventory

MAX_ENTRIES = 4096
MAX_TABLES = 64
MAX_DEPTH = 3
MAX_BODY = 0x8000          # decode budget per loader body
LIB_GETTERS = ("GetLuaLibs", "GetCitizenLibs", "GetServerLuaLibs")


@dataclass(frozen=True)
class RegEntry:
    name: str
    fn_rva: int
    name_rva: int
    entry_rva: int
    pdata_verified: bool


@dataclass(frozen=True)
class RegTable:
    table_rva: int
    origin: str                  # export name, or "via <owner fn name>"
    entries: tuple[RegEntry, ...]


def _read_str(img: Image, rva: int, limit: int = 128) -> str | None:
    buf = bytearray()
    for k in range(limit):
        b = img.read(rva + k, 1)
        if b is None:
            return None
        c = b[0]
        if c == 0:
            break
        if c < 0x20 or c > 0x7E:
            return None
        buf.append(c)
    s = buf.decode("ascii", "replace")
    return s or None


def _resolve_name(img: Image, name_v: int) -> tuple[str, int] | None:
    """(name, name_rva) from a luaL_Reg::name qword, both flavors."""
    base = img.preferred_base
    if not (base <= name_v < base + img.size()):
        return None
    name_rva = name_v - base
    name = _read_str(img, name_rva)
    if name is not None:
        return name, name_rva
    inner = img.read(name_rva, 16)
    if inner is not None:
        p, ln = struct.unpack("<QQ", inner)
        if base <= p < base + img.size() and 0 < ln <= 128:
            name_rva = p - base
            name = _read_str(img, name_rva, ln + 1)
            if name is not None:
                return name, name_rva
    return None


def walk_reg_table(img: Image, inv: Inventory, table_rva: int) -> list[RegEntry]:
    """Entries until the terminator (null fn slot); first bad slot stops."""
    base = img.preferred_base
    text = img.text()
    out: list[RegEntry] = []
    for i in range(MAX_ENTRIES):
        e = table_rva + i * 16
        q = img.read(e, 16)
        if q is None:
            break
        name_v, fn_v = struct.unpack("<QQ", q)
        if name_v == 0 or fn_v == 0:
            break                      # null name OR null func = terminator
        got = _resolve_name(img, name_v)
        if got is None:
            break
        name, name_rva = got
        if not (base <= fn_v < base + img.size()):
            break
        fn_rva = fn_v - base
        if not text.contains(fn_rva):
            break
        f = inv.find(fn_rva)
        ok = bool(f and f.contains(fn_rva))
        out.append(RegEntry(name, fn_rva, name_rva, e, ok))
    return out


def _rip_lea_targets(img: Image, fn_rva: int, inv: Inventory) -> list[int]:
    """RVA targets of `lea reg,[rip+d]` inside one function body."""
    f = inv.find(fn_rva)
    span = f.size() if (f and f.contains(fn_rva)) else 0
    start = f.begin if f else fn_rva
    text = img.text()
    span = min(span or 0x400, MAX_BODY, text.rva + text.raw_size - start)
    blob = img.read(start, max(span, 1))
    if not blob:
        return []
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    out: list[int] = []
    for ins in md.disasm(blob, start):
        if ins.mnemonic != "lea" or len(ins.bytes) < 7:
            continue
        for op in ins.operands:
            if op.type == 3 and op.mem.base == X86_REG_RIP and op.mem.index == 0:
                # disp32 = last 4 bytes of the encoding; bytes over details
                disp = struct.unpack_from("<i", ins.bytes, len(ins.bytes) - 4)[0]
                dst = ins.address + ins.size + disp
                s = img.section_of(dst)
                if s and s.name in (".rdata", ".data"):
                    out.append(dst)
    return out


def find_reg_tables(img: Image, inv: Inventory) -> list[RegTable]:
    """All registration tables reachable from the lib-getter exports.

    Returns tables in discovery order. Duplicate tables are deduped; each
    RegTable.origin records how it was reached.
    """
    tables: list[RegTable] = []
    seen_tables: set[int] = set()

    def add(table_rva: int, origin: str) -> RegTable | None:
        if table_rva in seen_tables or len(tables) >= MAX_TABLES:
            return None
        entries = walk_reg_table(img, inv, table_rva)
        if len(entries) < 2:            # a lone entry proves nothing
            return None
        seen_tables.add(table_rva)
        t = RegTable(table_rva, origin, tuple(entries))
        tables.append(t)
        return t

    frontier: list[tuple[int, str]] = []
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for exp in img.exports():
        if not any(g in exp.name for g in LIB_GETTERS):
            continue
        blob = img.read(exp.rva, 16)
        if blob is None:
            continue
        for ins in md.disasm(blob, exp.rva):
            if ins.mnemonic != "lea":
                break
            for op in ins.operands:
                if op.type == 3 and op.mem.base == X86_REG_RIP and op.mem.index == 0:
                    disp = struct.unpack_from("<i", ins.bytes,
                                              len(ins.bytes) - 4)[0]
                    dst = ins.address + ins.size + disp
                    if img.section_of(dst):
                        frontier.append((dst, exp.name))
                    break
            break

    for depth in range(MAX_DEPTH + 1):
        next_frontier: list[tuple[int, str]] = []
        scanned: set[int] = set()
        for table_rva, origin in frontier:
            t = add(table_rva, origin)
            if t is None or depth >= MAX_DEPTH:
                continue
            for e in t.entries:
                if e.entry_rva in scanned or len(scanned) >= 512:
                    continue
                scanned.add(e.entry_rva)
                for cand in _rip_lea_targets(img, e.fn_rva, inv):
                    if cand not in seen_tables:
                        next_frontier.append((cand, f"via {e.name} ({e.fn_rva:#x})"))
        frontier = dedupe(next_frontier)
        if not frontier:
            break
    return tables


def dedupe(pairs: list[tuple[int, str]]) -> list[tuple[int, str]]:
    seen: set[int] = set()
    out: list[tuple[int, str]] = []
    for rva, origin in pairs:
        if rva not in seen:
            seen.add(rva)
            out.append((rva, origin))
    return out
