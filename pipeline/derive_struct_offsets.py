"""Phase 4 driver — derive lua_State struct offsets per module.

Census (dumper.field_census) -> deterministic labeling. Field ORDER
(top, l_G, ci, stack_last, stack) is source order from citizenfx/lua
luaglm-548 lstate.h; every OFFSET is measured from the binary.

  top/ci/ci.func/slot  : lua_gettop family, verbatim:
        rax=[L+top]; rdx=[L+ci]; sub rax,[rdx+F]; [sub rax,const]; sar K
     winner over most functions; gates 4<=K<=6, F in {None,0},
     const in {0, 1<<K} (gettop removes exactly one slot: self-proof).
  stack_last/stack     : same-K family, other field pair:
        sub [L+Da],[L+Db]; sar K   (stacksize = stack_last - stack)
  l_G                  : hot-read disp strictly between top and ci
     whose derefs walk non-slot-aligned offsets (global_State walk).
  TValue               : size = 1<<K; tt = hottest byte-0-store offset
     through [top-slot base + T] (setnilvalue shape).
  tt (state byte)      : legacy cmp byte [L+0xC],8 census-ABSENT in
     modern builds -> not_observed, verifier uses l_G-equality gate.

Cross-module: values must agree or ship with agreement:false.
Output: data/structs/lua_state_offsets.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dumper.pe_parser import Image                      # noqa: E402
from dumper.field_census import scan_module             # noqa: E402

DATA = ROOT / "data"
FIELDS = ("top", "l_G", "ci", "stack_last", "stack")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hx(v):
    return hex(v) if isinstance(v, int) else str(v)


def label(ev) -> dict:
    """Deterministic field labels from one module's evidence."""
    fam = sorted(ev.family.items(), key=lambda kv: -len(kv[1]))

    gettop = None
    for key, fns in fam:
        Da, Db, F, cc, K = key
        if not isinstance(K, int) or not 4 <= K <= 6:
            continue
        if F not in (None, 0) or cc not in (0, 1 << K):
            continue
        gettop = (key, fns)
        break
    if gettop is None:
        return {"error": "gettop-family not observed",
                "top_families": [[list(map(hx, k)), len(v)]
                                 for k, v in fam[:8]]}
    (topD, ciD, cfunc, gt_const, K), gt_fns = gettop
    slot_size = 1 << K

    sl_key, sl_fns = None, set()
    for key, fns in fam:
        Da, Db, F, cc, KK = key
        if not isinstance(KK, int) or KK != K:
            continue
        if (Da, Db) == (topD, ciD) or F not in (None, 0) or cc != 0:
            continue
        sl_key, sl_fns = key, fns
        break

    lgD, lg_walks = None, {}
    for D in sorted(ev.reads):
        if not (topD < D < ciD) or len(ev.reads[D]) < 10:
            continue
        walks = {F: len(v) for (d, F), v in ev.derefs.items() if d == D}
        deep = {F: c for F, c in walks.items() if abs(F) % 16 != 0}
        if sum(deep.values()) >= 5:
            lgD, lg_walks = D, deep
            break

    ttT, tt_fns = None, set()
    for (baseD, T), fns in sorted(ev.slotnil.items(),
                                  key=lambda kv: -len(kv[1])):
        if baseD == topD:
            ttT, tt_fns = T, fns
            break

    out = {
        "functions_scanned": ev.n_fn,
        "slot_size": slot_size,
        "slot_shift": K,
        "top": {"offset": topD, "functions": len(gt_fns),
                "self_proof_const": gt_const == slot_size},
        "ci": {"offset": ciD, "functions": len(gt_fns)},
        "ci_func_offset": cfunc if cfunc is not None else 0,
        "l_G": {"offset": lgD,
                "functions": len(ev.reads[lgD]) if lgD else 0},
        "stack_last": {"offset": sl_key[0] if sl_key else None,
                       "functions": len(sl_fns)},
        "stack": {"offset": sl_key[1] if sl_key else None,
                  "functions": len(sl_fns)},
        "TValue": {"size": slot_size, "tt_offset": ttT,
                   "tt_functions": len(tt_fns)},
        "tt_state_byte": {"offset": None,
                          "note": "cmp byte [L+D],8 census-EMPTY; "
                                  "runtime gate uses l_G equality"},
    }
    if sl_key is None:
        out["warnings"] = ["stacksize-family not observed; "
                           "stack/stack_last unknown"]
    if lgD is None:
        out.setdefault("warnings", []).append(
            "l_G auto-label failed; manual evidence review needed")
    return out


def analyze(path: Path, label_name: str) -> dict:
    img = Image.load(str(path))
    ev = scan_module(img)
    lab = label(ev)
    # strongest G-share witness: cmp <[L+D]>,[L+D] shape (G(L)==G(L'))
    gshare = {hx(D): len(fns) for D, fns in
              sorted(ev.shared.items(), key=lambda kv: -len(kv[1]))[:3]}
    try:
        shown = str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        shown = str(path)
    rec = {"module": path.name, "label": label_name,
           "path": shown,
           "sha256": sha256(path), "evidence": lab}
    rec["evidence"]["g_share_witness"] = gshare
    return rec


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--client", default=None)
    ap.add_argument("--server", default=None)
    ap.add_argument("--out", default=str(DATA / "structs" /
                                         "lua_state_offsets.json"))
    a = ap.parse_args(argv)

    recs = []
    if a.client:
        recs.append(analyze(Path(a.client), "client"))
    if a.server:
        recs.append(analyze(Path(a.server), "server"))
    if not recs:
        ap.error("give --client and/or --server")

    # agreement across modules
    def field_of(r, *keys):
        e = r["evidence"]
        for k in keys:
            if k not in e:
                return None
            e = e[k]
        return e.get("offset") if isinstance(e, dict) else e

    agree = {}
    for f in FIELDS:
        vals = [field_of(r, f) for r in recs if "error" not in r["evidence"]]
        agree[f] = {"values": [hx(v) if v is not None else None
                               for v in vals],
                    "agree": bool(vals) and all(v == vals[0] for v in vals)}
    slot_vals = [r["evidence"].get("slot_size") for r in recs
                 if "error" not in r["evidence"]]
    agree["slot_size"] = {"values": slot_vals,
                          "agree": bool(slot_vals)
                          and all(v == slot_vals[0] for v in slot_vals)}

    primary = next((r for r in recs if r["label"] == "client"), recs[0])
    pe = primary["evidence"]
    ok = all(a["agree"] for a in agree.values())

    # derived runtime formulas (shape-stable across builds)
    resolver = {
        "state": "holder_global -> read field 0x58  (Phase 3 anchor)",
        "top_ptr": "state + 0x%X" % pe["top"]["offset"],
        "L_G": "state + 0x%X" % pe["l_G"]["offset"],
        "ci": "state + 0x%X" % pe["ci"]["offset"],
        "ci_func": "ci + 0x%X" % pe["ci_func_offset"],
        "gettop": "( *(state+0x%X) - *( *(state+0x%X) + 0x%X ) - 0x%X ) >> %d"
                  % (pe["top"]["offset"], pe["ci"]["offset"],
                     pe["ci_func_offset"], pe["slot_size"],
                     pe["slot_shift"]),
        "stacksize": "(*(state+0x%X) - *(state+0x%X)) >> %d"
                     % (pe["stack_last"]["offset"] or 0,
                        pe["stack"]["offset"] or 0, pe["slot_shift"]),
    }

    out = {
        "schema": 2,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "method": ("census + shape-family labeling; field ORDER from "
                   "luaglm-548 lstate.h (FiveM's lua fork), offsets "
                   "measured from code"),
        "modules": recs,
        "agreement": agree,
        "all_agree": ok,
        "resolver": resolver,
        "notes": [
            "TValue.tt_offset measured via setnilvalue byte stores",
            "state tt byte not observed modern; Gate3 must use l_G "
            "equality + functional probe, NOT tt==ntag",
            "CallInfo.top not load-bearing here (gettop uses ci->func "
            "only); CallInfo.func offset is measured (F operand)",
        ],
    }
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, indent=2), "utf-8")
    print(json.dumps({"all_agree": ok, "agreement": agree,
                      "primary": primary["label"],
                      "resolver": resolver}, indent=2))
    print("wrote", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())