"""AOB pattern generation and scanning.

A Pattern is a byte sequence with per-position wildcards. Generation works
from a reference-compiled function body (same compiler, same flags, same
source — e.g. stock Lua 5.4 /O2) and finds the shortest window that matches
EXACTLY ONCE in the target module's .text.

Wildcards applied to the reference body — the bytes that legitimately vary
between two builds of the same source:
  * every RIP-relative disp32 (its target moved, so its value means nothing)
  * every [rsp+disp] / [rbp+disp] frame displacement (stack layout shifts)
  * sub/add rsp, imm  frame-size immediates
Everything else (opcodes, ModRM, register operands, small constants) stays
pinned — that is what keeps patterns specific.

The shared prologue (PUSHes + MOV spill + SUB RSP boilerplate many Lua
functions open with identically) is skipped: windows start at or past the
longest common prologue across the reference function set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_REG_RBP, X86_REG_RSP, X86_REG_RIP

from dumper.pe_parser import Image

HEX_BYTE_RE = re.compile(r"^[0-9A-Fa-f?]{2}$")

MIN_PATTERN = 8
MAX_PATTERN = 32


class PatternError(Exception):
    pass


@dataclass(frozen=True)
class Pattern:
    toks: tuple[int | None, ...]

    @staticmethod
    def from_text(text: str) -> "Pattern":
        toks: list[int | None] = []
        for part in text.split():
            if part in ("??", "?"):
                toks.append(None)
            elif HEX_BYTE_RE.match(part):
                toks.append(int(part, 16))
            else:
                raise PatternError(f"bad pattern token: {part!r}")
        if not toks:
            raise PatternError("empty pattern")
        return Pattern(tuple(toks))

    def to_text(self) -> str:
        return " ".join("??" if t is None else f"{t:02X}" for t in self.toks)

    def mask(self) -> str:
        return "".join("x" if t is not None else "?" for t in self.toks)

    def length(self) -> int:
        return len(self.toks)


def wildcard_map(code: bytes, base_rva: int) -> set[int]:
    """Byte offsets inside `code` whose values vary build-to-build.

    Conservative by design: any uncertainty widens the wildcard set, which
    can only make the generator search longer windows — never let a
    build-variable byte stay fixed.
    """
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    wild: set[int] = set()
    consumed = 0
    for ins in md.disasm(code, base_rva):
        off = ins.address - base_rva
        if ins.id == 0:
            break  # decode desync; bytes past here stay fixed and simply fail
        consumed = off + ins.size
        end = off + ins.size
        has_mem = False
        rip_mem = False
        frame_mem_disp = False
        for op in ins.operands:
            if op.type != 3:  # X86_OP_MEM
                continue
            has_mem = True
            if op.mem.base == X86_REG_RIP:
                rip_mem = True
            elif op.mem.base in (X86_REG_RSP, X86_REG_RBP) or op.mem.index in (
                    X86_REG_RSP, X86_REG_RBP):
                if op.mem.disp != 0:
                    frame_mem_disp = True
        if rip_mem or frame_mem_disp:
            # disp32/disp8 lives at or near the tail of the encoding; when an
            # immediate follows the disp, wildcards eat part of the imm —
            # harmless. A rip-relative form ALWAYS carries disp32, so the
            # last 4 bytes always contain variable material.
            wild.update(range(max(off, end - 4), end))
        if ins.mnemonic in ("add", "sub") and ins.operands and \
                ins.reg_name(ins.operands[0].reg) == "rsp" and \
                len(ins.operands) > 1 and ins.operands[1].type == 2:  # X86_OP_IMM
            # frame-size immediate: imm8 form wildcards 1 tail byte,
            # imm32 form wildcards 4 (sub rsp, imm32 with REX keeps imm at tail)
            v = ins.operands[1].imm
            n = 4 if v > 0x7F else 1
            wild.update(range(end - n, end))
        # Branch displacements: call/jmp/jcc rel8 and rel32 encode a distance
        # to a site that moves between builds. Pinning them dooms the pattern.
        mn = ins.mnemonic
        if mn in ("call", "jmp") or (mn and mn[0] == "j" and mn != "jmp" and "ptr" not in ins.op_str):
            if ins.size >= 5:
                wild.update(range(end - 4, end))   # rel32
            elif ins.size == 2:
                wild.update(range(end - 1, end))   # rel8 (short jcc)
    return {w for w in wild if 0 <= w < len(code)}


def _longest_fixed_run(toks: tuple[int | None, ...]) -> tuple[int, bytes] | None:
    best_start, best_len, cur_start, cur_len = -1, 0, -1, 0
    for i, t in enumerate(toks):
        if t is None:
            cur_start, cur_len = -1, 0
        else:
            if cur_len == 0:
                cur_start = i
            cur_len += 1
            if cur_len > best_len:
                best_start, best_len = cur_start, cur_len
    if best_len == 0:
        return None
    return best_start, bytes(toks[best_start:best_start + best_len])


def scan(img: Image, pat: Pattern, only_text: bool = True) -> list[int]:
    """RVAs in executable sections where `pat` matches.

    The longest fixed run is used as a C-level str.find anchor; only its
    candidate offsets pay the full wildcard-checked compare. Two passes over
    a 2 MB .text stay interactive.
    """
    secs = [img.text()] if only_text else img.exec_sections()
    toks = pat.toks
    n = len(toks)
    anchor = _longest_fixed_run(toks)
    if anchor is None:
        raise PatternError("pattern is all wildcards")
    off, needle = anchor
    hits: list[int] = []
    for s in secs:
        blob_len = min(s.raw_size, s.vsize or s.raw_size)
        blob = img.read(s.rva, blob_len)
        if blob is None or len(blob) < n:
            continue
        start = 0
        while True:
            pos = blob.find(needle, start)
            start = pos + 1
            if pos < 0:
                break
            cand = pos - off
            if cand < 0 or cand + n > len(blob):
                continue
            ok = True
            for i, t in enumerate(toks):
                if t is not None and blob[cand + i] != t:
                    ok = False
                    break
            if ok:
                hits.append(s.rva + cand)
    return hits


def shared_prologue_length(bodies: list[bytes], cap: int = 32) -> int:
    """Longest byte prefix common to every function body (capped)."""
    if not bodies:
        return 0
    lcp = 0
    while lcp < cap and all(len(b) > lcp and b[lcp] == bodies[0][lcp] for b in bodies):
        lcp += 1
    return lcp


def generate(body: bytes, base_rva: int, target: Image,
             start_min: int = 0,
             min_len: int = MIN_PATTERN,
             max_len: int = MAX_PATTERN,
             inventory=None) -> tuple[Pattern, int, int] | None:
    """Shortest unique pattern for `body`.

    Returns (pattern, window_start_in_body, target_hit_rva) or None.
    Window hits identify the function entry at hit_rva - window_start.

    When `inventory` (a pdata Inventory) is given, a candidate window is
    only accepted if the implied entry is exactly a pdata function start:
    a unique match in the middle of an unrelated function is a coincidence
    to be rejected, not evidence.
    """
    wild = wildcard_map(body, base_rva)
    n = len(body)

    def accept(start: int, hits: list[int]) -> bool:
        if inventory is None:
            return True
        entry = hits[0] - start
        f = inventory.find(entry)
        return f is not None and f.begin == entry

    for start in range(start_min, max(start_min + 1, n - min_len)):
        for ln in range(min_len, max_len + 1):
            if start + ln > n:
                break
            toks = tuple(None if (start + k) in wild else body[start + k]
                         for k in range(ln))
            pat = Pattern(toks)
            if pat.length() - sum(1 for t in toks if t is None) < 4:
                continue  # a pattern with <4 fixed bytes is noise, not identity
            hits = scan(target, pat)
            if len(hits) == 1 and accept(start, hits):
                return pat, start, hits[0]
    return None


def probe_ref_entry(ref_body: bytes, ref_rva: int, target: Image, inventory,
                    *, min_len: int = 10, max_len: int = 48,
                    entry_slack: int = 16) -> tuple[int, int, Pattern] | None:
    """Semantic probe: find the function in `target` that implements `ref_body`.

    FiveM's Lua is the real source under /GL+LTCG plus their patches, so an
    exported function can differ mid-body from a per-file /O2 compile. The
    opening bytes still match. Grow a wildcarded prefix of the reference
    body until it matches EXACTLY ONCE in the target and that hit lies
    within `entry_slack` of a pdata function start; return
    (function_entry, window_start, pattern).
    """
    wild = wildcard_map(ref_body, ref_rva)
    n = len(ref_body)
    for ln in range(min_len, min(max_len, n) + 1):
        toks = tuple(None if k in wild else ref_body[k] for k in range(ln))
        pat = Pattern(toks)
        fixed = ln - sum(1 for t in toks if t is None)
        if fixed < 8:
            continue
        hits = scan(target, pat)
        if len(hits) != 1:
            continue
        owner = inventory.find(hits[0])
        if owner is None or hits[0] - owner.begin > entry_slack:
            continue
        return owner.begin, ln, pat
    return None


def target_pattern(target: Image, entry: int, fn_size: int,
                   *, min_len: int = 8, max_len: int = 48,
                   min_fixed: int = 8) -> Pattern | None:
    """Shortest unique window over the TARGET's own function bytes.

    The emitted seed pattern is derived from the bytes of a real FiveM
    build (not from a reference compile), with the same build-variable
    bytes wildcarded. Uniqueness is re-verified across .text.
    """
    span = min(fn_size, 0xC0)
    body = target.read(entry, span)
    if body is None or len(body) < min_len:
        return None
    wild = wildcard_map(body, entry)
    for start in range(0, max(1, min(24, len(body) - min_len + 1))):
        for ln in range(min_len, min(max_len, len(body) - start) + 1):
            toks = tuple(None if (start + k) in wild else body[start + k]
                         for k in range(ln))
            pat = Pattern(toks)
            if pat.length() - sum(1 for t in toks if t is None) < min_fixed:
                continue
            if len(scan(target, pat)) == 1:
                return pat
    return None
