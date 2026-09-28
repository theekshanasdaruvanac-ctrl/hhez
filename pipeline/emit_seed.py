"""Emit the committed seed JSON for one module (data/builds/<build>/...).

Composition of already-verified primitives — this file decides nothing,
it only assembles + verifies + serializes:

  anchor  : pipeline.anchor_identify.identify (Layer A/B/C ladder)
  structs : pipeline.derive_struct_offsets.label over field_census
  functions: reg-table ground truth (dumper.luaL_reg) -> patterns from
             the target's OWN bytes (pattern_gen.target_pattern), each
             required pdata-exact and .text-unique
  gates   : G1 static uniqueness (per function/pattern, measured),
            G2 anchor deref STATIC part (unique consumer, writable G,
               disp decodes) ; G3 runtime VerifyState, G4 functional
               1+1==2 -> "not_run" (offline), never silently skipped.

Spec amendment (documented, honest): the 8 Lua *core* API symbols of
the original plan are neither exported nor luaL_Reg-registered in
modern citizen-scripting-lua.dll, and the private fork + LTCG/ICF make
reference-compilation matching fail (probed 1/8). The seed mass is
therefore the luaL_Reg-verified library functions (316 client / 354
server), which ARE ground truth, plus the allocator/liveness anchor
chain. Core-API functions are reached through the anchor + struct
offsets instead of individual patterns.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dumper.pe_parser import Image                          # noqa: E402
from dumper.pdata_walker import walk as pdata_walk          # noqa: E402
from dumper.luaL_reg import find_reg_tables                 # noqa: E402
from dumper.pattern_gen import target_pattern, scan, Pattern  # noqa: E402
from dumper.field_census import scan_module                 # noqa: E402

from pipeline.anchor_identify import identify               # noqa: E402
from pipeline.derive_struct_offsets import label, sha256    # noqa: E402
from pipeline.fetch_artifact import find_lua_module, client_module  # noqa: E402
from pipeline.find_state_anchor import merge_symbols        # noqa: E402

DATA = ROOT / "data"


def _build_of(img: Image, path: Path) -> int:
    """Build id: cached artifact path, else the FileVersion resource
    (FiveM stamps 1.0.0.<buildid> into the DLL's version info)."""
    import re
    m = re.search(r"artifacts[\\/](\d+)[\\/]", str(path))
    if m:
        return int(m.group(1))
    try:
        import pefile
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        best = 0
        for fi in getattr(pe, "FileInfo", []) or []:
            for entry in fi:
                for st in getattr(entry, "StringTable", []) or []:
                    for k, v in st.entries.items():
                        if k in (b"FileVersion", b"ProductVersion"):
                            parts = v.decode(errors="replace").split(".")
                            if parts:
                                best = max(best, int(parts[-1]))
        return best
    except Exception:
        return 0


def emit(module: Path, out_dir: Path, carried: dict | None = None,
         max_fns: int = 400, build_id: int | None = None,
         prev_seed: dict | None = None) -> dict:
    img = Image.load(str(module))
    inv = pdata_walk(img)
    tables = find_reg_tables(img, inv)
    print(f"emit_seed: {len(tables)} reg tables, "
          f"{sum(len(t.entries) for t in tables)} registrations")

    anchor = identify(img, inv, carried)
    print(f"emit_seed: anchor layers {anchor['layers']} -> "
          f"{anchor.get('state_via')}")

    ev = scan_module(img)
    st = label(ev)
    if "error" in st:
        print(f"emit_seed: STRUCTS FAILED: {st['error']}")

    # Function patterns: CARRY FIRST. Every carried pattern still
    # matching uniquely on this module is kept verbatim (name + fresh
    # RVA from the hit's pdata entry). Regeneration has enumeration-
    # order tie-breaks; carrying verbatim means no phantom drift. What
    # the carry missed gets a pattern from this module's own bytes,
    # deduped against the carried set.
    functions = []
    carried_names: set[str] = set()
    carried_texts: set[str] = set()
    for cf in (prev_seed or {}).get("functions") or []:
        if not cf.get("pattern"):
            continue
        hits = scan(img, Pattern.from_text(cf["pattern"]))
        if len(hits) != 1:
            continue
        owner = inv.find(hits[0])
        functions.append({
            "name": cf["name"], "origin": cf.get("origin", "carried"),
            "fn_rva": f"0x{owner.begin:X}" if owner else cf.get("fn_rva"),
            "pattern": cf["pattern"], "mask": cf.get("mask", ""),
            "pattern_len": len(cf["pattern"].split()),
            "unique_hits": 1,
            "pdata_entry_ok": bool(owner),
            "carried": True,
        })
        carried_names.add(cf["name"])
        carried_texts.add(cf["pattern"])

    t0 = time.time()
    seen: set[tuple[int, str]] = set()
    for t in tables:
        for e in t.entries:
            key = (e.fn_rva, e.name)
            if key in seen or e.name in carried_names \
                    or len(functions) >= max_fns:
                continue
            seen.add(key)
            f = inv.find(e.fn_rva)
            size = (f.end - f.begin) if f else 0x400
            pat = target_pattern(img, e.fn_rva, size)
            if pat is None or pat.to_text() in carried_texts:
                continue
            hits = scan(img, pat)
            owner = inv.find(hits[0]) if len(hits) == 1 else None
            functions.append({
                "name": e.name, "origin": t.origin,
                "fn_rva": f"0x{e.fn_rva:X}",
                "pattern": pat.to_text(), "mask": pat.mask(),
                "pattern_len": pat.length(),
                "unique_hits": len(hits),
                "pdata_entry_ok": bool(owner and owner.begin == e.fn_rva),
            })
    print(f"emit_seed: carried {len(carried_names)} / fresh-patterned "
          f"{len(functions) - len(carried_names)} in {time.time()-t0:.0f}s")

    uniq = [f for f in functions
            if f["unique_hits"] == 1 and f["pdata_entry_ok"]]
    rejected = len(functions) - len(uniq)
    functions = uniq            # seed carries ONLY static-unique patterns
    build = build_id or _build_of(img, module)
    g_w = anchor.get("holder_global")

    rec = {
        "schema": 2,
        "build": build,
        # Chains are flavor-tracked: public artifacts are server bundles,
        # a FiveM.app module is the client. Cross-flavor carries are
        # allowed but measured, never assumed.
        "flavor": ("client" if "fivem.app"
                   in str(module.resolve()).lower() else "server"),
        "source": ("artifact" if "artifacts" in module.resolve().parts
                   else "provided"),
        "module": {"name": module.name, "sha256": sha256(module),
                   "code_hash": f"0x{img.code_hash():016X}"},
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generator": "pipeline/emit_seed/1.0.0",
        "anchor": anchor,
        "structs": ({k: st[k] for k in
                     ("top", "l_G", "ci", "stack_last", "stack")}
                    if "error" not in st else {"error": st["error"]}),
        "struct_scalars": ({
            "slot_size": st["slot_size"], "slot_shift": st["slot_shift"],
            "ci_func": st["ci_func_offset"],
            "TValue_tt": st["TValue"]["tt_offset"]}
            if "error" not in st else {}),
        "functions": functions,
        "verification": {
            "g1_static_unique": {
                "ok": bool(functions),
                "carried_patterns": len(functions),
                "rejected_nonunique": rejected},
            "g2_anchor_static": {
                "ok": bool(anchor.get("verification", {}).get("anchor_ok")),
                "notes": (["holder global in writable section; consumer "
                           "pattern unique; field disp decoded from store "
                           "bytes"]
                          if anchor.get("holder_global") else
                          ["holder not statically nameable this module; "
                           "export-contract anchor: field disp decoded "
                           "from unique call+store window, state via "
                           "exported allocator at runtime"])},
            "g3_runtime_verify_state": {"status": "not_run",
                                        "reason": "offline; resolver-side "
                                                  "gate at load time"},
            "g4_functional": {"status": "not_run",
                              "reason": "offline; requires a running "
                                        "citizen scripting host"},
        },
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "lua_state.json"
    out.write_text(json.dumps(rec, indent=2), "utf-8")
    print(f"wrote {out}  ({out.stat().st_size//1024} KiB)")
    return rec


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--module", type=Path, default=None)
    ap.add_argument("--carried", type=Path, default=None,
                    help="previous seed json for Layer A")
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args(argv)

    module = a.module
    if module is None:
        module = client_module(ROOT / "cache") or \
            find_lua_module(max((p for p in (ROOT/"cache"/"artifacts").iterdir()
                                 if p.is_dir()), key=lambda p: int(p.name)))
    if module is None:
        print("emit_seed: no module found", file=sys.stderr)
        return 64
    carried = None
    if a.carried:
        from pipeline.anchor_identify import carried_from_seed
        carried = carried_from_seed(
            json.loads(a.carried.read_text("utf-8"))) or None
    rec = emit(Path(module), a.out or DATA / "builds" / "current", carried,
               build_id=a.build_id)
    v = rec["verification"]
    return 0 if (rec["anchor"].get("verification", {}).get("anchor_ok")
                 and v["g1_static_unique"]["ok"]) else 2


if __name__ == "__main__":
    sys.exit(main())
