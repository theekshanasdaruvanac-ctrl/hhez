"""Layer ladder for the lua_State anchor chain on an ANY build.

Inputs: a target citizen-scripting-lua.dll (+ optionally the previous
build's carried anchor patterns). No RVAs assumed.

  Layer A — carry: replay committed patterns from the previous build's
      seed:
        store_ctx : E8 ?? ?? ?? ?? <store [reg+D],rax bytes>
                    unique -> ctor call-site; D read straight out of the
                    store's ModRM disp bytes. (Observed: the same
                    window is unique in BOTH the 36109 client and the
                    35945 server — field +0x58 travels verbatim.)
        consumer  : 48 8B 05 ?? ?? ?? ?? <deref tail wildcarded>
                    unique -> load site; G = site+len+disp32-from-bytes.
  Layer B — fresh semantics on THIS module (no memory needed):
        exported lua_rpmalloc_state allocator -> caller -> [reg+D] store
        (shape_c), then def-use liveness (find_singleton_by_field) names
        the writable singleton G. Emits a FRESH consumer pattern from the
        located site, self-healing the seed.
  Layer C — last resort: full global census (shape A rcx-before-call,
        shape B publish+follow histogram) via find_state_anchor.

Returns dict: {"shape":"C","field_disp","holder_global","site","pattern",
"layers":[...which fired...],"liveness_verified":bool,"verification"}.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dumper.pe_parser import Image                          # noqa: E402
from dumper.pdata_walker import walk as pdata_walk          # noqa: E402
from dumper.pattern_gen import Pattern, scan                # noqa: E402

from pipeline.find_state_anchor import (                    # noqa: E402
    shape_c, find_singleton_by_field, consumer_anchor, find_anchor)


def _disp_from_store(img: Image, hit: int) -> tuple[int, int] | None:
    """Decode the store right after a 5-byte `E8 rel32` call.

    Returns (field_disp, store_len) for `mov [reg+D], rax`, else None —
    the field offset is READ FROM THE BYTES, never assumed.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_REG_RAX, X86_REG_RIP
    blob = img.read(hit + 5, 16)
    if blob is None:
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for ins in md.disasm(blob, hit + 5):
        ops = ins.operands
        if len(ops) != 2 or ops[0].type != 3 or ops[1].type != 1:
            continue
        if ops[1].reg != X86_REG_RAX:
            continue
        m = ops[0].mem
        if m.base == X86_REG_RIP or m.base == 0:
            continue
        if m.index != 0:
            return None
        return m.disp, ins.size
    return None


def _holder_from_site(img: Image, site: int, pat_len: int) -> int | None:
    """G for a `48 8B 05 disp32` load at site (*((site+7)+disp))."""
    head = img.read(site, 7)
    if head is None or head[:3] != b"\x48\x8b\x05":
        return None
    disp = struct.unpack_from("<i", head, 3)[0]
    return (site + 7 + disp) & 0xFFFFFFFF


def shape_d(img: Image) -> dict | None:
    """Exported-factory anchor (universal contract).

    `static lua_State* LuaStateHolder::lua_rpmalloc_state(void*&)` is an
    EXPORTED, name-decorated entry present in both client and server
    modules of every inspected build. A resolver can GetProcAddress it
    (name, not address) and call it for the live lua_State* + rpmalloc
    slot. Statically verifiable: export exists, and its first caller
    stores the returned state into holder + field (Layer-B store).
    """
    from pipeline.find_state_anchor import ALLOCATOR_HINTS
    for ex in img.exports():
        if not ex.name or not any(h in ex.name for h in ALLOCATOR_HINTS):
            continue
        return {"export": ex.name, "export_rva": f"0x{ex.rva:X}"}
    return None


def identify(img: Image, inv, carried: dict | None) -> dict:
    layers: list[str] = []
    field = ctor = None
    holder = site = None
    pattern = None
    liveness = False
    exported = shape_d(img)               # runtime contract: exported name
    if exported:
        layers.append("E:export_contract")

    # ---------- Layer A: carried patterns -------------------------------
    if carried:
        sc = carried.get("store_ctx")
        if sc:
            hits = scan(img, Pattern.from_text(sc["pattern"]))
            if len(hits) == 1:
                dec = _disp_from_store(img, hits[0])
                if dec:
                    field, _ = dec        # THIS module's bytes decide D
                    ctor = hits[0]
                    layers.append("A:store_ctx")
                    carried_d = sc.get("field_disp")
                    if carried_d and int(carried_d, 16) != field:
                        layers.append(f"A:field-drift {carried_d}->0x{field:X}")
        cp = carried.get("consumer")
        if cp:
            hits = scan(img, Pattern.from_text(cp["pattern"]))
            if len(hits) == 1:
                g = _holder_from_site(img, hits[0], cp.get("pattern_len", 0))
                if g is not None:
                    holder, site = g, hits[0]
                    pattern = cp["pattern"]
                    layers.append("A:consumer")

    # ---------- Layer B: fresh allocator + liveness -----------------------
    if field is None:
        c = shape_c(img, inv)
        if c:
            pub = [r for r in c["records"]]
            published = [r for r in pub if r["singleton_publish_global"]]
            field = int(c["field_disp"], 16)
            ctor = int((published or pub)[0]["call_rva"], 16)
            layers.append("B:allocator_export")
            if not holder:
                rec = (published or pub)[0]
                if rec["singleton_publish_global"]:
                    holder = int(rec["singleton_publish_global"], 16)
    if holder is None and field is not None:
        named = find_singleton_by_field(img, inv, field)
        if named:
            holder = int(named[0]["global_rva"], 16)
            site = int(named[0]["consumer_sites"][0], 16)
            liveness = True
            layers.append("B:liveness")

    # ---------- self-heal: fresh unique pattern for THIS module -----------
    if holder is not None and site is not None and "A:consumer" not in layers:
        rec = consumer_anchor(img, site, holder)
        if rec and rec.get("unique_hits") == 1:
            pattern = rec["pattern"]
        elif rec:
            pattern = rec["pattern"]      # keep with honest unique_hits

    # ---------- Layer C: census fallback -------------------------------------
    if field is None and holder is None and not exported:
        layers.append("C:census")
        return {"shape": "census-fallback",
                "fallback": {"note": "run find_state_anchor full pass and "
                                     "inspect candidates"},
                "layers": layers}

    if pattern is None and holder is not None and site is not None:
        rec = consumer_anchor(img, site, holder)
        pattern = rec.get("pattern") if rec else None

    holder_chain = holder is not None and field is not None and liveness
    ok = field is not None and (holder is not None or exported is not None)
    store_ctx = None
    if ctor is not None:
        sc = _store_ctx_pattern(img, ctor)
        store_ctx = {"pattern": sc} if sc else None
    state_via = None
    if holder is not None and field is not None:
        state_via = f"state = *[0x{holder:X}] + 0x{field:X}"
    elif field is not None and exported:
        state_via = (f"state = {exported['export']}(slot)  "
                     "(GetPtr at runtime, pass &slot)")
    return {
        "shape": "C" if holder is not None else "E",
        "state_via": state_via,
        "export_contract": exported,
        "field_disp": f"0x{field:X}" if field is not None else None,
        "holder_global": f"0x{holder:X}" if holder is not None else None,
        "ctor_call_site": f"0x{ctor:X}" if ctor is not None else None,
        "consumer_site": f"0x{site:X}" if site is not None else None,
        "consumer_pattern": pattern,
        "unique_hits": (len(scan(img, Pattern.from_text(pattern)))
                        if pattern else None),
        "liveness_verified": liveness or ("A:consumer" in layers),
        "lua_state_via": (f"state = *[0x{holder:X}] + 0x{field:X}"
                          if holder is not None and field is not None
                          else None),
        "store_ctx": store_ctx,
        "layers": layers,
        "verification": {"anchor_ok": ok},
    }


def _store_ctx_pattern(img: Image, call_site: int) -> str | None:
    """`E8 ?? ?? ?? ?? <store bytes>` — call+next-instruction window.

    The call's rel32 is wildcarded (moves with every build); the store
    bytes travel verbatim while the field offset is stable. Verified on
    client 36109 and server 35945: the same window is unique in both.
    """
    blob = img.read(call_site, 5)
    if blob is None or blob[0] != 0xE8:
        return None
    tail = img.read(call_site + 5, 8)
    if tail is None:
        return None
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for ins in md.disasm(tail, call_site + 5):
        return "E8 ?? ?? ?? ?? " + " ".join(f"{b:02X}" for b in tail[:ins.size])
    return None


def find_singleton_chain(img: Image, inv, field: int, max_hops: int = 2):
    """Name writable globals G whose value reaches [..+field] through up
    to `max_hops` qword field loads: G -> [G+a] -> (+b) -> (+field).

    Client modules resolve at hop 0-1 (direct holder global). Server
    modules reach the holder through a runtime object (two hops), which
    is why single-hop liveness misses them. Returns one record per G:
    {global_rva, hops:[a,b...], site}. Tags die on call/def as usual;
    only loads from a tagged base extend the chain (never widen).
    """
    import struct
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_REG_RIP
    from dumper.rip_resolver import iter_functions, rip_target_raw

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    best: dict[int, dict] = {}
    for f, insns in iter_functions(img, inv):
        if not insns:
            continue
        chain_tag: dict[int, tuple] = {}    # reg -> (g_rva, (hop, hop...))
        for ins in insns:
            mn, ops = ins.mnemonic, ins.operands
            if mn == "call":
                chain_tag.clear()
                continue
            n = len(ops)
            if not n:
                continue
            # chain_tag[reg] = (g_rva, hops_tuple)
            op0 = ops[0]
            op1 = ops[1] if n > 1 else None
            dreg = op0.reg if op0.type == 1 else None
            src = None
            if op1 is not None and op1.type == 3:
                if op1.mem.base == X86_REG_RIP:
                    src = ("g", rip_target_raw(ins), 0)
                elif op1.mem.base != 0 and op1.mem.base in chain_tag:
                    src = ("m", chain_tag[op1.mem.base], op1.mem.disp)
            elif op1 is not None and op1.type == 1 and op1.reg in chain_tag:
                src = ("r", chain_tag[op1.reg], 0)
            if dreg is not None:
                chain_tag.pop(dreg, None)
            if src is None or mn != "mov" or dreg is None:
                continue
            kind, payload, disp = src
            if kind == "g":
                g = payload
                if g is None:
                    continue
                s = img.section_of(g)
                if s is None or not (s.chars & 0x80000000):
                    continue              # only writable globals start chains
                chain_tag[dreg] = (g, ())
            elif kind == "r":
                chain_tag[dreg] = payload
            else:                         # memory through a tagged base
                g, hops = payload
                if disp == field and len(hops) <= max_hops:
                    rec = best.get(g)
                    if rec is None or len(rec["hops"]) > len(hops):
                        best[g] = {"global_rva": g,
                                   "hops": list(hops),
                                   "site": ins.address}
                    continue
                if len(hops) < max_hops:
                    chain_tag[dreg] = (g, hops + (disp,))
    return sorted(best.values(),
                  key=lambda r: (len(r["hops"]), -r["site"]))


def carried_from_seed(seed: dict) -> dict:
    """Extract Layer-A inputs from ANY committed seed shape.

    schema-2: seed["anchor"]{consumer_pattern, store_ctx{pattern,...}}
    v1:       seed["chosen"]["record"]["pattern"] +
              chosen["shape_c"]["records"][0]["store_pattern"] ->
              reconstructed call+store window `E8 ?? ?? ?? ?? <store>`.
    """
    out: dict = {}
    a = seed.get("anchor")
    if a:
        if a.get("consumer_pattern"):
            out["consumer"] = {"pattern": a["consumer_pattern"]}
        sc = a.get("store_ctx")
        if sc and sc.get("pattern"):
            out["store_ctx"] = sc
        if out:
            return out
    ch = seed.get("chosen") or {}
    rec = ch.get("record") or {}
    if rec.get("pattern"):
        out["consumer"] = {"pattern": rec["pattern"],
                           "pattern_len": rec.get("pattern_len", 0)}
    c = ch.get("shape_c") or {}
    for r in c.get("records", []):
        if r.get("store_pattern"):
            out["store_ctx"] = {
                "pattern": "E8 ?? ?? ?? ?? " + r["store_pattern"],
                "field_disp": r.get("field_disp")}
            break
    return out
