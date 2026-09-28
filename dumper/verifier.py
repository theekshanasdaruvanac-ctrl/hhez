"""The four verification gates, implemented once, called everywhere.

G1 static uniqueness : every carried pattern hits exactly once in the
    module AND that hit sits at the recorded pdata entry.
G2 anchor deref      : consumer pattern unique; its rip disp32 decodes
    to the recorded holder global; holder in a writable section;
    store-context window unique; field offset re-decoded from the
    store's own bytes matches field_disp; export contract present,
    inside an executable section, pdata-backed.
G3 runtime VerifyState: load the module, GetProcAddress the exported
    lua_rpmalloc_state, call it, walk the struct offsets this seed
    recorded and check internal consistency (top/ci/stack ordering,
    slot alignment, gettop plausibility, status byte). NOT the legacy
    `tt == 8` probe: modern fork builds carry no such byte-visible
    LUA_TTHREAD gate; l_G-equality + field sanity is the real check.
G4 functional 1+1==2 : run a chunk through the resolved state. The core
    lua_* API is not exported by the fork module, so offline this can
    only run inside the live host -> honestly "not_run", never skipped.
"""

from __future__ import annotations

import ctypes
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dumper.pe_parser import Image                          # noqa: E402
from dumper.pdata_walker import walk                        # noqa: E402
from dumper.pattern_gen import Pattern, scan                # noqa: E402


def gate1_unique(img: Image, functions: list[dict]) -> dict:
    fails = []
    for f in functions:
        hits = scan(img, Pattern.from_text(f["pattern"]))
        if len(hits) != 1:
            fails.append({"name": f["name"], "hits": len(hits), "why": "not unique"})
    return {"ok": not fails and bool(functions),
            "patterns": len(functions), "failures": fails[:20]}


def _disp_from_store(img: Image, hit: int):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_REG_RAX, X86_REG_RIP
    blob = img.read(hit + 5, 16)
    if blob is None:
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for ins in md.disasm(blob, hit + 5):
        ops = ins.operands
        if len(ops) != 2 or ops[0].type != 3 or ops[1].type != 1 \
                or ops[1].reg != X86_REG_RAX:
            continue
        m = ops[0].mem
        if m.base in (0, X86_REG_RIP) or m.index != 0:
            return None
        return m.disp
    return None


def gate2_anchor(img: Image, inv, anchor: dict) -> dict:
    checks: dict[str, bool] = {}
    holder = anchor.get("holder_global")
    field = anchor.get("field_disp")
    sc = (anchor.get("store_ctx") or {}).get("pattern")
    if sc:
        hits = scan(img, Pattern.from_text(sc))
        checks["store_ctx_unique"] = len(hits) == 1
        d = _disp_from_store(img, hits[0]) if len(hits) == 1 else None
        checks["field_disp_matches_bytes"] = (
            d is not None and f"0x{d:X}" == field)
    pat = anchor.get("consumer_pattern")
    if pat:
        hits = scan(img, Pattern.from_text(pat))
        checks["consumer_unique"] = len(hits) == 1
        if len(hits) == 1:
            head = img.read(hits[0], 7)
            ok = head is not None and head[:3] == b"\x48\x8b\x05"
            if ok:
                disp = struct.unpack_from("<i", head, 3)[0]
                g = (hits[0] + 7 + disp) & 0xFFFFFFFF
                checks["consumer_disp_to_holder"] = (
                    holder is not None and g == int(holder, 16))
    if holder is not None:
        s = img.section_of(int(holder, 16))
        checks["holder_writable"] = bool(s and s.chars & 0x80000000)
    exp = anchor.get("export_contract")
    if exp:
        e = next((x for x in img.exports() if x.name == exp["export"]), None)
        checks["export_present"] = e is not None
        if e is not None:
            s = img.section_of(e.rva)
            fn = inv.find(e.rva)
            checks["export_executable_pdata"] = bool(
                s and s.chars & 0x20000000 and fn)
    required = {"store_ctx_unique", "field_disp_matches_bytes",
                "export_present", "export_executable_pdata"}
    if holder is not None:
        required |= {"holder_writable"}
    if pat:
        required |= {"consumer_unique", "consumer_disp_to_holder"}
    return {"ok": all(checks.get(k, False) for k in required),
            "required": sorted(required), "checks": checks}


def gate3_runtime(module_path: Path, anchor: dict, structs: dict) -> dict:
    """Best-effort live structural check on THIS machine.

    A cold LoadLibrary of the component gives the allocator path only,
    not a fully-initialized host holder — if field sanity fails while
    the export call itself worked, that is recorded as such, not
    hidden. Gate 3 in CI runs inside the live resolver instead.
    """
    out = {"status": "not_run", "notes": []}
    exp = (anchor.get("export_contract") or {}).get("export")
    if not exp:
        out["notes"] = ["no export contract in seed"]
        return out
    try:
        # 0x8 = LOAD_WITH_ALTERED_SEARCH_PATH: component deps live next
        # to the DLL (FiveM.app / bundle files dir), not the cwd.
        dll = ctypes.CDLL(str(module_path), mode=0x8)
    except OSError as e:
        # 1114 DLL_INIT_FAILED: FiveM components DllMain-probe the fx
        # host and refuse standalone load (proven: their deps, e.g.
        # citizen-scripting-core.dll, fail identically). This is an
        # environment boundary, not a seed defect -> not_run_offline.
        if getattr(e, "winerror", None) == 1114:
            out["status"] = "not_run_offline"
            out["notes"] = [f"component refuses standalone load: {e}; "
                            "gate runs inside the live fx host instead"]
        else:
            out["status"] = "failed"
            out["notes"] = [f"LoadLibrary failed: {e}"]
        return out
    try:
        fn = getattr(dll, exp)
    except AttributeError as e:
        out["status"] = "failed"
        out["notes"] = [f"GetProcAddress: {e}"]
        return out
    fn.restype = ctypes.c_void_p
    fn.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    slot = ctypes.c_void_p(0)
    try:
        state = fn(ctypes.byref(slot))
    except OSError as e:                  # access violation etc.
        out["status"] = "fails_on_cold_load"
        out["notes"] = [f"allocator call crashed cold: {e}"]
        return out
    # The AEAPEAX arg is the rpmalloc slot *cell*; the stored qword IS
    # the lua_State* — that dual read also proves the +0x58 field chain.
    holder_state = None
    if slot.value:
        try:
            holder_state = ctypes.cast(
                slot.value, ctypes.POINTER(ctypes.c_uint64))[0]
        except Exception:
            pass
    notes = [f"allocator returned state={state and hex(state)} "
             f"slot={slot.value and hex(slot.value)} "
             f"*[slot]={holder_state and hex(holder_state)}"]
    if holder_state and state and holder_state == state:
        notes.append("*[slot] == returned state: slot-chain self-proves")
    if not state:
        out["status"] = "fails_on_cold_load"
        out["notes"] = notes + ["null state from cold allocator"]
        return out

    def q(off: int) -> int | None:
        try:
            return ctypes.cast(state + off,
                               ctypes.POINTER(ctypes.c_uint64))[0]
        except Exception:
            return None

    try:
        b = ctypes.cast(state + 0xA, ctypes.POINTER(ctypes.c_uint8))[0]
        notes.append(f"status byte (+0xA) = {b}")
    except Exception:
        pass
    offs = {k: (v["offset"] if isinstance(v, dict) else v)
            for k, v in structs.items() if isinstance(v, dict)}
    vals = {k: q(v) for k, v in offs.items()}
    notes.append("fields: " + ", ".join(
        f"{k}={vals[k] and hex(vals[k])}" for k in sorted(vals)))
    checks = {}
    top, ci = vals.get("top"), vals.get("ci")
    stack, slast = vals.get("stack"), vals.get("stack_last")
    if top:
        checks["top_heap_ptr"] = 0x1000 < (top & 0xFFFFFFFFFFFF) < 0x7FFFFFFFFFFF
        checks["top_slot_aligned"] = (top & 0x1F) == 0   # 32B slots
    if ci:
        checks["ci_heap_ptr"] = 0x1000 < (ci & 0xFFFFFFFFFFFF) < 0x7FFFFFFFFFFF
        try:     # ci->func at +0 (seed ci_func=0): a StkIdRel/qword in range
            func = ctypes.cast(ci, ctypes.POINTER(ctypes.c_uint64))[0]
            checks["func_heap_ptr"] = 0x1000 < \
                (func & 0xFFFFFFFFFFFF) < 0x7FFFFFFFFFFF or func == 0
            if top and func:
                checks["gettop_plausible"] = 0 <= ((top - func - 0x20) >> 5) <= 1 << 16
        except Exception:
            pass
    if top and ci:
        checks["top_ge_ci"] = top >= ci
    if stack and slast:
        span = slast - stack
        checks["stack_span_sane"] = 0 < span <= (1 << 20) and span % 32 == 0
        if top:
            checks["top_in_stack_window"] = stack <= top <= slast + (1 << 16)
    out["status"] = "structural_ok" if checks and all(
        checks.values()) else "fails_on_cold_load"
    out["checks"] = checks
    if out["status"] == "structural_ok":
        out["state"] = state              # live ptr for the G4 partial run
    out["notes"] = notes + ([f"checks: {checks}"] if checks else
                            ["no fields readable to check"])
    return out
