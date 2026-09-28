"""Phase 3 — locate the globals that anchor the lua_State, and emit the
resolver's anchor records.

Discovery, not assumption. Two anchor shapes are measured on every build:

  shape A — classic:   mov rcx, [rip+G]; call <lua fn>
                       G IS the lua_State* slot (older / server builds).
  shape B — runtime:   mov rcx, [rip+G]; mov rax, [rcx+D]   (within a few
                       instructions)  -> G holds the LuaScriptRuntime/
                       LuaStateHolder singleton, D is its lua_state field
                       (the modern client shape: states reach callees
                       through the instance, and lib functions are
                       VM-dispatched so direct calls are rare/atypical).

Shape B is found by a census, not a call-graph: every `mov reg,[rip+G]`
loading a WRITABLE-section global is scored, and the follow-load window
counts [reg+disp] hops — the disp histogram IS the lua_state field-offset
evidence (also Phase 4's seed). Call-adjacency (shape A) rides the same
single disassembly pass, weighted by verified symbols from the luaL_Reg
tables (dumper/luaL_reg.py) plus the phase-2 seed.

Ranking rule: shape-A wins if any global has multiple distinct callers
feeding rcx directly before known lua calls; else the highest-scoring
shape-B global wins. Output marks which shape was chosen, with all
evidence, so the resolver's Gate 3 can falsify it cheaply at runtime.

Output: data/anchors/stable_globals.json
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capstone.x86 import X86_REG_RCX, X86_REG_RIP          # noqa: E402

from dumper.pe_parser import Image                          # noqa: E402
from dumper.pdata_walker import walk as pdata_walk          # noqa: E402
from dumper.rip_resolver import (iter_functions, rip_target_raw,   # noqa: E402
                                 jmp_stub_map)
from dumper.luaL_reg import find_reg_tables                 # noqa: E402
from pipeline.fetch_artifact import find_lua_module, client_module  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

MIN_SHAPE_A_CALLERS = 2      # multi-caller rcx-before-known-call = strong
FOLLOW_WINDOW = 16           # instrs after a global load to spot [reg+disp]
FOLLOW_LIMIT = 4096          # cap per-candidate follow-analysis work

# Shape C (preferred on modern builds): the module EXPORTS the state
# allocator (substring match, works mangled or plain — observed:
# ?lua_rpmalloc_state@LuaStateHolder@fx@@CAPEAUlua_State@@AEAPEAX@Z).
# Its single call site is followed by `mov [reg+D], rax` storing the fresh
# lua_State* into the owner object -> D is the lua_state field offset.
# If that same function also publishes an instance to a writable global
# (`mov [rip+G], reg`), G is the runtime singleton and
# `state = *[G] + D` is the full anchor chain, verified end to end.
ALLOCATOR_HINTS = ("lua_rpmalloc_state", "rpmalloc_state")


@dataclass
class Global:
    rva: int
    writable: bool
    section: str
    a_loads: list = field(default_factory=list)     # (call_rva, instr, bytes, sym)
    a_callers: set = field(default_factory=set)
    b_loads: int = 0                                # loads by any reg, any ctx
    b_load_fns: set = field(default_factory=set)
    b_follow: dict = field(default_factory=lambda: defaultdict(int))  # disp->n
    b_store: int = 0
    store_from_ctor: bool = False

    @property
    def score_a(self) -> int:
        return len(self.a_callers)

    @property
    def score_b(self) -> int:
        return self.b_load_fns.__len__() + self.b_store * 2

    def top_follows(self) -> list[tuple[int, int]]:
        return sorted(self.b_follow.items(), key=lambda kv: -kv[1])[:6]


def merge_symbols(img: Image, inv, seed: dict | None) -> tuple[dict[int, str], list]:
    syms: dict[int, str] = {}
    tables = find_reg_tables(img, inv)
    for t in tables:
        for e in t.entries:
            syms.setdefault(e.fn_rva, f"lib:{e.name}")
    if seed:
        for name, info in seed.get("lua_functions", {}).items():
            syms[int(info["rva"], 16)] = name
    return syms, tables


def collect(img: Image, inv, syms: dict[int, str]) -> tuple[dict[int, Global], dict[int, int]]:
    """One disassembly pass; returns writable-global registry + ctor-store map."""
    stubs = jmp_stub_map(img, inv)
    globals_: dict[int, Global] = {}
    ctor_stores: dict[int, int] = defaultdict(int)

    def reg(rva: int) -> Global:
        g = globals_.get(rva)
        if g is None:
            s = img.section_of(rva)
            writable = bool(s and (s.chars & 0x80000000))
            g = globals_[rva] = Global(
                rva, writable,
                f"{s.name}/{('w' if writable else 'r')}" if s else "<outside>")
        return g

    for f, insns in iter_functions(img, inv):
        n = len(insns)
        for i, ins in enumerate(insns):
            ops = ins.operands
            # ---- shape B raw census + follow windows (loads only) ----
            if ins.mnemonic in ("mov", "lea", "movzx") and len(ops) == 2 \
                    and ops[0].type == 1 and ops[1].type == 3 \
                    and ops[1].mem.base == X86_REG_RIP:
                tgt = rip_target_raw(ins)
                if tgt is not None:
                    g = reg(tgt)
                    if len(g.b_load_fns) < FOLLOW_LIMIT:
                        g.b_load_fns.add(f.begin)
                        g.b_loads += 1
                        dst_reg = ins.operands[0].reg
                        for j in range(i + 1, min(i + 1 + FOLLOW_WINDOW, n)):
                            p = insns[j]
                            po = p.operands
                            if len(po) != 2 or po[0].type != 1 or po[1].type != 3:
                                continue
                            m = po[1].mem
                            if m.base == dst_reg and m.base != X86_REG_RIP \
                                    and 0 <= m.disp <= 0x100000:
                                g.b_follow[m.disp] += 1
                    continue
            # ---- rip stores (singleton publish evidence) ----
            if ins.mnemonic in ("mov", "movdqu", "movups") and ops \
                    and ops[0].type == 3 and ops[0].mem.base == X86_REG_RIP:
                tgt = rip_target_raw(ins)
                if tgt is not None:
                    g = reg(tgt)
                    g.b_store += 1
                    ctor_stores[tgt] += 1
                continue
            # ---- shape A: call into known symbol, rcx fed from [rip+G] ----
            b = ins.bytes
            if len(b) != 5 or b[0] != 0xE8 or ins.mnemonic != "call":
                continue
            dst = ins.address + 5 + struct.unpack_from("<i", b, 1)[0]
            name = syms.get(dst) or syms.get(stubs.get(dst, -1))
            if name is None:
                continue
            for j in range(i - 1, max(-1, i - 9), -1):
                prev = insns[j]
                po = prev.operands
                if prev.mnemonic not in ("mov", "lea", "movzx") or len(po) != 2:
                    continue
                if po[0].type != 1 or po[0].reg != X86_REG_RCX \
                        or po[1].type != 3 or po[1].mem.base != X86_REG_RIP:
                    continue
                tgt = rip_target_raw(prev)
                if tgt is None:
                    continue
                g = reg(tgt)
                g.a_callers.add(f.begin)
                g.a_loads.append((ins.address, prev.address,
                                  bytes(prev.bytes), name))
    return globals_, dict(ctor_stores)


def find_singleton_by_field(img: Image, inv, field_disp: int) -> list[dict]:
    """Writable globals G provably dereferenced as [G-load + field_disp].

    Per-function mini def-use: tag a register when it is loaded
    `mov/lea/movzx reg,[rip+G]` from a WRITABLE global; propagate through
    `mov reg,reg`; untag on any def; a `[tagged_reg+field_disp]` access
    marks G. Returns consumer sites sorted by count.
    """
    from collections import defaultdict
    hits: dict[int, list] = defaultdict(list)
    for f, insns in iter_functions(img, inv):
        live: dict[int, tuple[int, int]] = {}
        for ins in insns:
            ops = ins.operands
            if not ops:
                continue
            for op in ops:                       # defs kill tags
                if op.type == 1:
                    live.pop(op.reg, None)
            if ins.mnemonic in ("mov", "lea", "movzx") and len(ops) == 2 \
                    and ops[0].type == 1 and ops[1].type == 3 \
                    and ops[1].mem.base == X86_REG_RIP:
                t = rip_target_raw(ins)
                if t is None:
                    continue
                s = img.section_of(t)
                if s and (s.chars & 0x80000000):
                    live[ops[0].reg] = (t, ins.address)
                continue
            if ins.mnemonic == "mov" and len(ops) == 2 \
                    and ops[0].type == 1 and ops[1].type == 1:
                src = ops[1].reg
                if src in live:
                    live[ops[0].reg] = live[src]
                continue
            for op in ops:
                if op.type == 3 and op.mem.base and op.mem.base != X86_REG_RIP \
                        and op.mem.disp == field_disp:
                    tag = live.get(op.mem.base)
                    if tag is not None:
                        g, load_addr = tag
                        hits[g].append((load_addr, ins.address, f.begin))
    out = [{"global_rva": f"0x{g:X}",
            "consumer_sites": [f"0x{la:X}" for la, _, _ in fs[:6]],
            "deref_sites": [f"0x{da:X}" for _, da, _ in fs[:6]],
            "consumer_funcs": sorted({f"0x{fn:X}" for _, _, fn in fs})}
           for g, fs in sorted(hits.items(), key=lambda kv: -len(kv[1]))]
    return out


def consumer_anchor(img: Image, site: int, global_rva: int) -> dict:
    """Pattern window starting at the `mov reg,[rip+G]` load of a consumer.

    5 load bytes (disp32 wildcarded) + the deref instruction that reads
    the state field (disp bytes wildcarded). Emits the shortest unique
    prefix so the resolver's scanner gets exactly one hit.
    """
    from dumper.pattern_gen import Pattern, scan
    blob = img.read(site, 32)
    # load instr length from bytes: 48 8B 05 = disp32 (7); 48 8B 05 is the
    # common encoding; use capstone for exactness
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    ins_list = list(md.disasm(blob, site))
    if not ins_list:
        return {}
    load = ins_list[0]
    load_len = load.size
    # find the deref of the tagged field inside the next 6 instructions
    dst = load.operands[0].reg if load.operands and load.operands[0].type == 1 else None
    deref = None
    for p in ins_list[1:7]:
        for op in p.operands:
            if op.type == 3 and op.mem.base == dst:
                deref = p
                break
        if deref:
            break
    end = deref.size + deref.address if deref else load.address + load_len
    win = img.read(site, end - site)
    # wildcard rip disp32 of the load (last 4 bytes of load instr) and any
    # disp32/disp8 tail of the deref
    wild = set(range(load_len - 4, load_len))
    if deref is not None:
        dlen = deref.size - deref.address
        # conservative: last byte of deref is disp8-or-tail; last four if disp32
        tail = 4 if dlen >= 7 else 1
        wild |= set(range(load_len + dlen - tail, load_len + dlen))
    toks = tuple(None if i in wild else win[i] for i in range(len(win)))
    pat = Pattern(toks)
    # grow-shrink not needed: whole 2-instr window; check uniqueness
    n = len(scan(img, pat))
    return {"pattern": pat.to_text(), "mask": pat.mask(),
            "pattern_len": len(win), "disp_offset": 3,
            "disp_size": 4, "unique_hits": n,
            "site": f"0x{site:X}", "global_rva": f"0x{global_rva:X}"}


def pattern_for(raw: bytes) -> tuple[str, str]:
    toks = [f"{b:02X}" for b in raw[:-4]] + ["??"] * 4
    return " ".join(toks), "x" * len(raw[:-4]) + "????"


def shape_c(img: Image, inv) -> dict | None:
    """Allocator-chain anchor: exported state allocator -> [this+D] store.

    Returns dict with field_disp, call site, store bytes, and — when the
    containing function also publishes `this` to a writable global
    (`mov [rip+G], <store-reg>`, scanned over the whole function, not just
    the post-call window) — the runtime singleton G. None when no
    exported allocator exists (shape not present; not an error).
    """
    exps = [e for e in img.exports()
            if any(h in e.name for h in ALLOCATOR_HINTS)]
    if not exps:
        return None
    stubs = jmp_stub_map(img, inv)
    for e in exps:
        want = {e.rva} | {k for k, v in stubs.items() if v == e.rva}
        results: list[dict] = []
        for f, insns in iter_functions(img, inv):
            for i, ins in enumerate(insns):
                b = ins.bytes
                if len(b) != 5 or b[0] != 0xE8 or ins.mnemonic != "call":
                    continue
                dst = ins.address + 5 + struct.unpack_from("<i", b, 1)[0]
                if dst not in want and stubs.get(dst) not in want:
                    continue
                field_disp = store_bytes = store_reg = None
                for j in range(i + 1, min(i + 9, len(insns))):
                    p = insns[j]
                    po = p.operands
                    if len(po) != 2 or po[1].type != 1:
                        continue
                    if ins.reg_name(po[1].reg) != "rax":
                        continue
                    if po[0].type == 3 and po[0].mem.base not in (0, X86_REG_RIP) \
                            and 0 < po[0].mem.disp <= 0x100000 \
                            and field_disp is None:
                        field_disp = po[0].mem.disp
                        store_reg = ins.reg_name(po[0].mem.base)
                        store_bytes = bytes(p.bytes)
                if field_disp is None:
                    continue
                # publish scan: `mov [rip+G], <store_reg>` anywhere in the
                # same function (constructors typically publish last)
                publish_g = None
                for p in insns:
                    po = p.operands
                    if len(po) != 2 or po[1].type != 1 or po[0].type != 3:
                        continue
                    if po[0].mem.base != X86_REG_RIP:
                        continue
                    if ins.reg_name(po[1].reg) != store_reg:
                        continue
                    t = rip_target_raw(p)
                    if t is None:
                        continue
                    s = img.section_of(t)
                    if s and (s.chars & 0x80000000):
                        publish_g = t     # last one wins; usually only one
                results.append({
                    "allocator_export": e.name,
                    "allocator_rva": f"0x{e.rva:X}",
                    "call_rva": f"0x{ins.address:X}",
                    "caller_rva": f"0x{f.begin:X}",
                    "field_disp": f"0x{field_disp:X}",
                    "store_reg_base": store_reg,
                    "store_pattern": " ".join(f"{b:02X}" for b in store_bytes),
                    "singleton_publish_global":
                        f"0x{publish_g:X}" if publish_g else None,
                })
        canon: dict[tuple, dict] = {}
        for r in results:
            canon.setdefault((r["caller_rva"], r["field_disp"]), r)
        if canon:
            rs = list(canon.values())
            published = [r for r in rs if r["singleton_publish_global"]]
            return {
                "records": rs,
                "field_disp": published[0]["field_disp"] if published
                            else rs[0]["field_disp"],
                "singleton_publish_global":
                    published[0]["singleton_publish_global"] if published
                    else None,
            }
    return None


def record(g: Global, img: Image) -> dict:
    out = {
        "global_rva": f"0x{g.rva:X}",
        "section": g.section,
        "writable": g.writable,
        "shape_a_direct_state": {
            "rcx_callers": len(g.a_callers),
            "sites": len(g.a_loads),
            "sample_symbol": g.a_loads[0][3] if g.a_loads else None,
            "sample_load_rva": f"0x{g.a_loads[0][1]:X}" if g.a_loads else None,
            "load_pattern": pattern_for(g.a_loads[0][2])[0] if g.a_loads else None,
            "load_mask": pattern_for(g.a_loads[0][2])[1] if g.a_loads else None,
        },
        "shape_b_runtime_singleton": {
            "loader_functions": len(g.b_load_fns),
            "total_loads": g.b_loads,
            "stores": g.b_store,
            "follow_disp_histogram": [{"disp": f"0x{d:X}", "count": c}
                                      for d, c in g.top_follows()],
        },
    }
    return out


def find_anchor(target_dll: Path, build: int, seed_path: Path | None) -> dict:
    img = Image.load(target_dll)
    inv = pdata_walk(img)
    seed = None
    if seed_path and seed_path.exists():
        seed = json.loads(seed_path.read_text(encoding="utf-8"))

    syms, tables = merge_symbols(img, inv, seed)
    n_tbl_entries = sum(len(t.entries) for t in tables)
    print(f"anchor: {len(syms)} verified-symbol targets "
          f"({len(tables)} reg tables / {n_tbl_entries} registrations)")

    globals_, _ctor = collect(img, inv, syms)
    writable = [g for g in globals_.values() if g.writable]
    shape_a = sorted((g for g in writable if g.score_a),
                     key=lambda g: -g.score_a)
    shape_b = sorted((g for g in writable if g.b_load_fns and g.b_store
                      and g.b_follow),
                     key=lambda g: -g.score_b)
    print(f"anchor: {len(writable)} writable globals referenced; "
          f"shape-A {len(shape_a)}, shape-B candidates {len(shape_b)}")
    print("  top shape-B (store + loads + [reg+d] follows):")
    for g in shape_b[:6]:
        print(f"    G {g.rva:#x} loaders={len(g.b_load_fns):3} stores={g.b_store:2} "
              f"follows={[(hex(d), c) for d, c in g.top_follows()[:4]]}")

    c = shape_c(img, inv)
    if c:
        print(f"anchor: shape C allocator chain: field=+{c['field_disp']} "
              f"singleton={c['singleton_publish_global']} "
              f"({len(c['records'])} verified call site(s))")
    else:
        print("anchor: shape C not present (no exported state allocator)")

    # Decision: C beats A beats B.
    singleton = None
    if c is not None:
        shape, winner = "C", None
        field = int(c["field_disp"], 16)
        # cross-check: any writable global whose load is provably followed
        # by [loaded+field] is the runtime singleton holder. This is
        # end-to-end verified (allocator proves `field` = state offset;
        # liveness proves `G` is the object holding it).
        named = find_singleton_by_field(img, inv, field)
        g_rva_s = named[0]["global_rva"] if named \
            else c["singleton_publish_global"]
        singleton = named[0] if named else None
        if named and c["singleton_publish_global"] and \
                int(named[0]["global_rva"], 16) != int(c["singleton_publish_global"], 16):
            print(f"anchor: NOTE publish-global {c['singleton_publish_global']} "
                  f"!= liveness holder {named[0]['global_rva']}")
        winner_rec = (consumer_anchor(img, int(named[0]["consumer_sites"][0], 16),
                                      int(g_rva_s, 16))
                      if named and named[0]["consumer_sites"] else None)
        if winner_rec and len(named[0]["consumer_sites"]) > 1:
            # alternative anchor windows — Phase 5 carries a chain when the
            # primary window's context mutates between builds
            alts = []
            for s in named[0]["consumer_sites"][1:6]:
                r = consumer_anchor(img, int(s, 16), int(g_rva_s, 16))
                if r and r.get("unique_hits") == 1:
                    alts.append(r)
            winner_rec["fallback_patterns"] = alts
        if named:
            c["singleton_publish_global"] = g_rva_s
            c["liveness_verified"] = True
        lua_state_via = (f"state = *[{g_rva_s}].+{c['field_disp']}"
                         if g_rva_s else f"state = *[holder]+{c['field_disp']}")
    elif shape_a and shape_a[0].score_a >= MIN_SHAPE_A_CALLERS:
        winner, shape = shape_a[0], "A"
        g_rva_s, winner_rec = f"0x{shape_a[0].rva:X}", record(shape_a[0], img)
        lua_state_via = f"state = *[{g_rva_s}]"
    elif shape_b:
        winner, shape = shape_b[0], "B"
        d, _ = shape_b[0].top_follows()[0]
        g_rva_s, winner_rec = f"0x{shape_b[0].rva:X}", record(shape_b[0], img)
        lua_state_via = f"state = *[{g_rva_s}] + 0x{d:X} -> load"
    else:
        shape, winner, winner_rec, g_rva_s = "none", None, None, None
        lua_state_via = None

    if winner or shape == "C":
        print(f"anchor: WINNER shape {shape}  ({lua_state_via})")
    else:
        print("anchor: NO ANCHOR FOUND — emitting candidates for inspection")

    out = {
        "build": build,
        "module": str(target_dll),
        "module_name": target_dll.name,
        "module_code_hash": f"0x{img.code_hash():016X}",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generator": "pipeline/find_state_anchor/2.1.0",
        "symbols_used": len(syms),
        "reg_tables": [{"table_rva": f"0x{t.table_rva:X}", "origin": t.origin,
                        "entries": len(t.entries)} for t in tables],
        "chosen": {
            "shape": shape,
            "global_rva": g_rva_s,
            "lua_state_via": lua_state_via,
            "record": winner_rec,
            "shape_c": c,
        },
        "shape_a_candidates": [record(g, img) for g in shape_a[:8]],
        "shape_b_candidates": [record(g, img) for g in shape_b[:8]],
        "verification": {
            "anchor_ok": winner is not None or shape == "C",
            "notes": [
                "offline evidence is structural: exported state allocator "
                "whose result is stored at [holder+D] (shape C), writable "
                "global multi-caller rcx-before-known-lua-call (shape A), or "
                "publish-store + multi-loader singleton (shape B)",
                "shape C field_disp doubles as lua_state field offset input "
                "for Phase 4",
                "the deref itself (load G -> non-null -> +D -> LUA_TTHREAD "
                "tag at L+0xC) is Gate 3, resolver-side, marked not_run in "
                "offline runs",
            ],
        },
    }
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", type=Path, default=None,
                    help="module to analyze; default: installed client, "
                         "newest cached artifact")
    ap.add_argument("--build", type=int, default=0)
    ap.add_argument("--seed", type=Path,
                    default=DATA / "seeds" / "lua_functions.json")
    ap.add_argument("--out", type=Path,
                    default=DATA / "anchors" / "stable_globals.json")
    args = ap.parse_args(argv)

    target = args.target
    if target is None:
        c = client_module(ROOT / "cache")
        if c is None:
            arts = ROOT / "cache" / "artifacts"
            if arts.is_dir():
                newest = max((p for p in arts.iterdir() if p.is_dir()),
                             key=lambda p: int(p.name))
                target = find_lua_module(newest)
        else:
            target = c
        print(f"find_state_anchor: analysis target {target}")
    if target is None:
        print("find_state_anchor: nothing to analyze; pass --target",
              file=sys.stderr)
        return 64

    out = find_anchor(Path(target), args.build, args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0 if out["verification"]["anchor_ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
