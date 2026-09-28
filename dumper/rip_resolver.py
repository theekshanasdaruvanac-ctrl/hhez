"""RIP-relative analysis over a PE's code: references, call sites, rcx loads.

Everything here disassembles PER FUNCTION from the .pdata inventory rather
than linearly over .text — MSVC jump tables desync a linear sweep and the
desync silently invents instructions. Function-bounded decoding cannot.

The three primitives Phase 3 (and later, Phase 4) compose:

  rip_ref_sites      every RIP-relative access in code, with the data RVA
  call_sites         every `call rel32` hitting a known function, paired
                    with the RIP-relative register loads just before it
  rip_targets_in_fn  the data globals one function touches

Instruction displacements are parsed from RAW BYTES at the instruction
tail, not from capstone's resolved operand: the emitted anchor patterns
must match the bytes on disk exactly, so bytes are the only acceptable
source of truth.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_REG_RIP

from dumper.pe_parser import Image
from dumper.pdata_walker import Inventory, FuncRange

MEM_OP = 3  # CS_OP / X86_OP_MEM


@dataclass(frozen=True)
class RipRef:
    rva: int          # instruction address
    size: int         # instruction length
    mnemonic: str
    reg: str          # destination register name, '' if none
    data_rva: int     # the global it references
    raw: bytes        # exact instruction bytes


@dataclass(frozen=True)
class CallSite:
    call_rva: int
    target_rva: int
    name: str
    caller: FuncRange
    loads: tuple[RipRef, ...]   # RIP loads feeding registers, nearest first


def _md() -> Cs:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


def rip_target_raw(ins) -> int | None:
    """Data RVA of a RIP-relative operand, parsed from the encoding tail.

    Returns None unless the instruction has exactly a [rip+disp32] memory
    operand form, in which case the disp32 occupies the last 4 bytes.
    """
    has_rip = False
    for op in ins.operands:
        if op.type == MEM_OP and op.mem.base == X86_REG_RIP:
            has_rip = True
            break
    if not has_rip or len(ins.bytes) < 7:
        return None
    disp = struct.unpack_from("<i", ins.bytes, len(ins.bytes) - 4)[0]
    return ins.address + len(ins.bytes) + disp


def iter_functions(img: Image, inv: Inventory):
    """(FuncRange, [instructions]) per pdata function, decoded in-place."""
    md = _md()
    text = img.text()
    seen: set[int] = set()
    for f in inv.funcs:
        if f.begin in seen:
            continue  # chained unwind entries can repeat an entry
        seen.add(f.begin)
        if img.section_of(f.begin) is not text:
            continue  # entry lives outside .text (e.g. stub section)
        span = min(f.size(), (text.rva + min(text.raw_size, text.vsize or text.raw_size)) - f.begin)
        blob = img.read(f.begin, max(span, 1))
        if not blob:
            continue
        insns = list(md.disasm(blob, f.begin))
        if insns:
            yield f, insns


def jmp_stub_map(img: Image, inv: Inventory) -> dict[int, int]:
    """Map `jmp rel32`-only stubs to their real target (LINKER/ICF thunks)."""
    out: dict[int, int] = {}
    done: set[int] = set()
    for f in inv.funcs:
        if f.begin in done:
            continue
        done.add(f.begin)
        b = img.read(f.begin, 5)
        if b and b[0] == 0xE9 and f.size() <= 5:
            dst = f.begin + 5 + struct.unpack_from("<i", b, 1)[0]
            # follow chains (stub -> stub -> body), bounded
            for _ in range(4):
                nb = img.read(dst, 5)
                if nb and nb[0] == 0xE9:
                    nd = dst + 5 + struct.unpack_from("<i", nb, 1)[0]
                    if nd == dst:
                        break
                    dst = nd
                else:
                    break
            out[f.begin] = dst
    return out


def rip_ref_sites(img: Image, inv: Inventory):
    """Yield (func, RipRef) for every RIP-relative access in code."""
    for f, insns in iter_functions(img, inv):
        for ins in insns:
            tgt = rip_target_raw(ins)
            if tgt is None:
                continue
            reg = ""
            if ins.operands and ins.operands[0].type == 1:  # X86_OP_REG
                reg = ins.reg_name(ins.operands[0].reg) or ""
            yield f, RipRef(ins.address, ins.size, ins.mnemonic, reg, tgt,
                             bytes(ins.bytes))


def rip_targets_in_fn(img: Image, inv: Inventory, fn: FuncRange) -> list[RipRef]:
    """RIP references made by one specific function, in order."""
    for f, insns in iter_functions(img, inv):
        if f.begin != fn.begin:
            continue
        out: list[RipRef] = []
        for ins in insns:
            tgt = rip_target_raw(ins)
            if tgt is None:
                continue
            reg = ""
            if ins.operands and ins.operands[0].type == 1:
                reg = ins.reg_name(ins.operands[0].reg) or ""
            out.append(RipRef(ins.address, ins.size, ins.mnemonic, reg, tgt,
                              bytes(ins.bytes)))
        return out
    return []


def _rip_loads(insns, idx: int, window: int,
               want_reg: str | None) -> tuple[RipRef, ...]:
    """RIP loads feeding registers within `window` instructions before idx.

    Nearest-first, so the closest load to the call is first; a load whose
    destination register is later overwritten inside the window would also
    appear — the caller weighs proximity, this does not pretend to be a
    dataflow analysis.
    """
    out: list[RipRef] = []
    lo = max(0, idx - window)
    for j in range(idx - 1, lo - 1, -1):
        ins = insns[j]
        if ins.mnemonic not in ("mov", "lea", "movzx", "cmovne", "cmove"):
            continue
        tgt = rip_target_raw(ins)
        if tgt is None or not ins.operands or ins.operands[0].type != 1:
            continue
        reg = ins.reg_name(ins.operands[0].reg) or ""
        if want_reg is not None and reg != want_reg:
            continue
        out.append(RipRef(ins.address, ins.size, ins.mnemonic, reg, tgt,
                          bytes(ins.bytes)))
    return tuple(out)


def call_sites(img: Image, inv: Inventory, targets: dict[int, str], *,
               arg_reg: str | None = "rcx", window: int = 8,
               follow_stubs: bool = True):
    """Yield CallSite for every direct call into `targets`.

    `targets` maps known function RVA -> symbol name. Stub-following
    resolves calls landing on an ICF `jmp` thunk to the body behind it.
    """
    stubs = jmp_stub_map(img, inv) if follow_stubs else {}
    for f, insns in iter_functions(img, inv):
        for i, ins in enumerate(insns):
            b = ins.bytes
            if len(b) != 5 or b[0] != 0xE8 or ins.mnemonic != "call":
                continue
            dst = ins.address + 5 + struct.unpack_from("<i", b, 1)[0]
            name = targets.get(dst)
            if name is None and follow_stubs:
                real = stubs.get(dst)
                if real is not None:
                    name = targets.get(real)
                    if name is not None:
                        dst = real
            if name is None:
                continue
            yield CallSite(ins.address, dst, name, f,
                           _rip_loads(insns, i, window, arg_reg))
