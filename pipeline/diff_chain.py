"""Diff a fresh any-build result against the committed seed.

Pure comparison — no binaries touched. Feeds diff_report.json for the
Phase-7 PR. Sections:

  anchor   : holder/field/shape changes with before/after values
  structs  : per-field offset drift between seed.lst offsets and fresh
  functions: pattern survival of carried seed patterns on the fresh
             module (unique/ambiguous/dead), plus reg-table ground
             truth deltas (new / gone / moved)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _fn_key(f: dict) -> str:
    return f"{f['origin']}:{f['name']}@{f['entry_rva'] if 'entry_rva' in f else ''}"


def diff(seed: dict, fresh: dict, survival: dict | None = None) -> dict:
    out: dict = {"from_build": seed.get("build"), "to_build": fresh.get("build"),
                 "anchor": {}, "structs": {}, "functions": {}}

    sa, fa = seed.get("anchor", {}), fresh.get("anchor", {})
    for k in ("shape", "holder_global", "field_disp"):
        a, b = sa.get(k), fa.get(k)
        if a != b:
            out["anchor"][k] = {"seed": a, "fresh": b}
    out["anchor"]["changed"] = bool(
        {k: v for k, v in out["anchor"].items() if k != "changed"})

    ss, fs = seed.get("structs", {}), fresh.get("structs", {})
    for fld in ("top", "l_G", "ci", "stack_last", "stack",
                "ci_func", "slot_size"):
        a, b = ss.get(fld), fs.get(fld)
        if a is not None and b is not None:
            out["structs"][fld] = {"seed": hex(a) if isinstance(a, int) else a,
                                   "fresh": hex(b) if isinstance(b, int) else b,
                                   "changed": a != b}

    seed_fns = seed.get("functions", [])
    fresh_fns = fresh.get("functions", [])
    snames = {f["name"] for f in seed_fns}
    fnames = {f["name"] for f in fresh_fns}

    surv = {"unique": 0, "ambiguous": 0, "dead": 0,
            "not_replayed": 0, "died_examples": []}
    for name, status in (survival or {}).items():
        if status in surv:
            surv[status] += 1
        if status == "dead" and len(surv["died_examples"]) < 25:
            surv["died_examples"].append(name)
    total = sum(surv[k] for k in ("unique", "ambiguous", "dead"))
    surv["replayed"] = total
    surv["survival_rate"] = (round(surv["unique"] / total, 3)
                             if total else None)
    out["functions"]["pattern_survival"] = surv
    out["functions"]["ground_truth"] = {
        "seed_registrations": len(seed_fns),
        "fresh_registrations": len(fresh_fns),
        "new_names": sorted(fnames - snames)[:50],
        "gone_names": sorted(snames - fnames)[:50],
        "delta_note": ("names compared across reg tables (pdata-verified "
                       "registrations), not pattern hits"),
    }
    return out
