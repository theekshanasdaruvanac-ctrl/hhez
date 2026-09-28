"""Any-build orchestrator — the P5 acceptance driver.

Given a build id (or --module for a local/installed client):

  1. fetch artifact            (pipeline.fetch_artifact; client module
                                resolved from the running FiveM install
                                when the build is the installed one)
  2. load previous seed        (data/builds/<prev>/lua_state.json —
                                chosen automatically as the highest
                                build id below this one, else --seed)
  3. emit fresh seed           (pipeline.emit_seed with Layer-A carried)
  4. replay survival           (each carried function pattern vs the
                                fresh module -> unique/ambiguous/dead)
  5. diff report               (pipeline.diff_chain -> diff_report.json)

Exits 0 when the fresh anchor resolved and function patterns survived
above --min-survival (default 0.5); never silently passes a dead chain.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dumper.pe_parser import Image                          # noqa: E402
from dumper.pattern_gen import Pattern, scan                # noqa: E402

from pipeline.fetch_artifact import (fetch_build, find_lua_module,   # noqa: E402
                                     client_module)
from pipeline.emit_seed import emit                          # noqa: E402
from pipeline.diff_chain import diff                         # noqa: E402

DATA = ROOT / "data"


def module_flavor(module: Path) -> str:
    return ("client" if "fivem.app" in str(Path(module).resolve()).lower()
            else "server")


def prev_seed(build: int, explicit: Path | None,
              flavor: str | None = None) -> tuple[Path | None, dict | None]:
    """Latest committed seed below `build`, same flavor by default.

    Client and server lua modules evolve separately; a cross-flavor
    seed is usable (measured 45% pattern carry) but silently picking it
    would hide real drift. Explicit --seed always wins.
    """
    if explicit:
        return explicit, json.loads(explicit.read_text("utf-8"))
    base = DATA / "builds"
    if not base.is_dir():
        return None, None
    cands = []
    for d in base.iterdir():
        if d.is_dir() and d.name.isdigit() and int(d.name) < build:
            f = d / "lua_state.json"
            if f.exists():
                try:
                    s = json.loads(f.read_text("utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
                cands.append((int(d.name), s.get("flavor"), f, s))
    if not cands:
        return None, None
    cands.sort(key=lambda c: c[0], reverse=True)
    same = [c for c in cands if flavor is None or c[1] == flavor]
    pick = (same or cands)[0]
    return pick[2], pick[3]


def survival(img: Image, seed: dict) -> dict:
    out: dict[str, str] = {}
    for f in seed.get("functions", []):
        if not f.get("pattern"):
            continue
        n = len(scan(img, Pattern.from_text(f["pattern"])))
        out[f["name"]] = ("unique" if n == 1 else
                          "ambiguous" if n > 1 else "dead")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--build", type=int, default=None,
                    help="artifact build id; omit with --module")
    ap.add_argument("--module", type=Path, default=None)
    ap.add_argument("--seed", type=Path, default=None,
                    help="previous seed json (default: newest lower build)")
    ap.add_argument("--build-id", type=int, default=None,
                    help="override build stamp when --module is a raw file")
    ap.add_argument("--min-survival", type=float, default=0.5)
    a = ap.parse_args(argv)

    if a.module:
        module, build = a.module, a.build_id or 0
    elif a.build:
        art = fetch_build(a.build)
        # The bundle for THIS build id, never the installed client — stamps
        # must match the module actually scanned.
        module = find_lua_module(art, prefer_client=False)
        build = a.build
        if module is None:
            print("any_build: module not found in artifact or install",
                  file=sys.stderr)
            return 3
    else:
        from pipeline.fetch_artifact import latest_build
        build = latest_build()
        return main((argv or sys.argv[:1]) + ["--build", str(build)])

    print(f"any_build: build={build} module={module}")
    prev_path, prev = prev_seed(build, a.seed, module_flavor(module))
    print(f"any_build: previous seed: {prev_path or 'NONE (cold chain)'}")

    out_dir = DATA / "builds" / (str(build) if build else "current")
    carried = None
    if prev:
        from pipeline.anchor_identify import carried_from_seed
        carried = carried_from_seed(prev) or None
        print(f"any_build: Layer A carries {sorted(carried) if carried else 'nothing'}")

    rec = emit(Path(module), out_dir, carried=carried, prev_seed=prev)

    img = Image.load(str(module))
    surv = survival(img, prev) if prev else {}
    rep = diff(prev or {}, rec, surv)
    (out_dir / "diff_report.json").write_text(
        json.dumps(rep, indent=2), "utf-8")
    print(f"any_build: wrote {out_dir/'diff_report.json'}")

    sr = rep["functions"]["pattern_survival"]["survival_rate"]
    ok = rec["anchor"].get("verification", {}).get("anchor_ok")
    if sr is not None:
        print(f"any_build: survival {sr} (min {a.min_survival})")
    else:
        print("any_build: cold chain — no survival baseline")
    return 0 if (ok and (sr is None or sr >= a.min_survival)) else 2


if __name__ == "__main__":
    sys.exit(main())
