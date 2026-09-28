"""Phase 2 — Bootstrap: reference-compile Lua, generate seed patterns.

One-time. Output (data/seeds/lua_functions.json) is committed and anchors
every future build's resolution.

Method:
  1. Discover the Lua source releases on lua.org (5.4.x / 5.5.x series).
  2. Compile each candidate as a DLL with the local MSVC at /O2 /MT — the
     same compiler family FiveM ships. Newest first.
  3. Per target symbol: disassemble the REFERENCE body (capstone), grow a
     window — build-variable bytes wildcarded (rip disp32, frame disp,
     frame-size imm, branch disp) — until it matches EXACTLY ONCE in the
     target .text AND the implied entry is a .pdata function start.
  4. Record which reference version produced each symbol's pattern, so the
     struct-offset phase knows the embedded Lua generation.

The spec's community-dump cross-check could not run: the dump JSONs in
FiveM-Offsets-Dumper-main are Discord-gated placeholders ("DM me on
Discord"). Notes record it; gates instead are: unique match, pdata entry,
and a semantic size envelope.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dumper.pe_parser import Image                      # noqa: E402
from dumper.pdata_walker import walk as pdata_walk      # noqa: E402
from dumper.pattern_gen import (                        # noqa: E402
    Pattern, generate, probe_ref_entry, scan, shared_prologue_length,
    target_pattern,
)

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "cache"
DATA = ROOT / "data"

SERIES = ("5.4.", "5.5.")  # major/minor series worth trying
FTP_INDEX = "https://www.lua.org/ftp/"
MAX_VERSIONS = 14

# Symbols to seed. The runtime resolver and the anchor/struct phases need
# exactly these; the set is easy to extend later.
SEED_SYMBOLS = [
    "luaL_newstate", "lua_close", "luaL_loadbufferx", "lua_pcallk",
    "lua_gettop", "lua_settop", "lua_tolstring", "lua_pushvalue",
]

# (min, max) plausible code size in bytes. Guards against a pattern that
# matched a lookalike stub instead of the real function.
SIZE_ENVELOPE = {
    "luaL_newstate": (0x120, 0x2400),
    "lua_close": (0x80, 0xA00),
    "luaL_loadbufferx": (0x80, 0x700),
    "lua_pcallk": (0x60, 0x600),
    "lua_gettop": (8, 0x80),
    "lua_settop": (0x20, 0x260),
    "lua_tolstring": (0x60, 0x480),
    "lua_pushvalue": (0x20, 0x1C0),
}

VSWHERE = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe")

GEN_RE = re.compile(r"lua-(\d\.\d\.\d)\.tar\.gz")


def find_vcvars() -> Path:
    import os
    override = os.environ.get("FIVEM_MSVC_VCVARS")
    if override:
        return Path(override)
    if VSWHERE.exists():
        out = subprocess.run(
            [str(VSWHERE), "-latest", "-products", "*",
             "-find", r"VC\Auxiliary\Build\vcvars64.bat"],
            capture_output=True, text=True, check=True).stdout.strip()
        if out:
            return Path(out)
    raise FileNotFoundError("no vcvars64.bat found; set FIVEM_MSVC_VCVARS")


def discover_versions() -> list[str]:
    """Every Lua x.y.z release on lua.org in the tracked series, newest first."""
    req = urllib.request.Request(FTP_INDEX, headers={"User-Agent": "fivem-lua-pipeline/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        html = r.read().decode("latin-1", "replace")
    vers = {m.group(1) for m in GEN_RE.finditer(html)
            if m.group(1).startswith(SERIES)}
    if not vers:
        raise RuntimeError("lua.org FTP index parsed to zero releases")
    return sorted(vers, key=lambda v: tuple(int(x) for x in v.split(".")),
                  reverse=True)[:MAX_VERSIONS]


def ensure_lua_source(version: str) -> Path:
    src = CACHE / f"lua-{version}" / "src"
    if src.is_dir() and (src / "lua.c").exists():
        return src
    CACHE.mkdir(parents=True, exist_ok=True)
    tar = CACHE / f"lua-{version}.tar.gz"
    url = f"https://www.lua.org/ftp/lua-{version}.tar.gz"
    if not tar.exists():
        print(f"bootstrap: downloading {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "fivem-lua-pipeline/1.0"})
        with urllib.request.urlopen(req, timeout=120) as r, open(tar, "wb") as f:
            shutil.copyfileobj(r, f)
    with tarfile.open(tar) as tf:
        tf.extractall(CACHE, filter="data")
    return src


def build_reference(version: str) -> Path:
    src = ensure_lua_source(version)
    out_dir = CACHE / f"lua-ref-{version}"
    obj_dir = out_dir / "obj"
    dll = out_dir / "lua_ref.dll"
    if dll.exists():
        return dll
    obj_dir.mkdir(parents=True, exist_ok=True)
    vcvars = find_vcvars()

    # lua.c / luac.c own main() — excluded. Everything else goes in.
    sources = sorted(p.name for p in src.glob("*.c") if p.name not in ("lua.c", "luac.c"))
    objs = " ".join(str(obj_dir / (Path(p).stem + ".obj")) for p in sources)
    lines = [
        "@echo off",
        f'call "{vcvars}" >nul',
        f'cd /d "{obj_dir}"',
    ]
    for p in sources:
        lines.append(
            f'cl /nologo /O2 /MT /c /Fo"{obj_dir / (Path(p).stem + ".obj")}" '
            f'/DLUA_CORE /DLUA_BUILD_AS_DLL /DLUA_LIB /I"{src}" "{src / p}"')
    lines.append(f'link /nologo /DLL /OUT:"{dll}" {objs}')
    bat = out_dir / "build_ref.bat"
    bat.write_text("\r\n".join(lines) + "\r\n", encoding="ascii")
    print(f"bootstrap: compiling reference Lua {version} with MSVC /O2 /MT ...")
    proc = subprocess.run(["cmd", "/c", str(bat)], capture_output=True, text=True)
    if proc.returncode != 0 or not dll.exists():
        raise RuntimeError(f"reference build {version} failed:\n"
                           + proc.stdout + "\n" + proc.stderr)
    return dll


def follow_export_stub(img: Image, inv, rva: int) -> tuple[int, int | None]:
    """Exports can be linker stubs rather than the real function.

    Shapes seen in MSVC-built modules:
        jmp rel32                      -> follow
        mov rcx, [rip+disp32] (+jmp)   -> follow the jmp, record the global
    Returns (function_rva, global_rva_loaded_by_the_stub_or_None).
    """
    import struct as _s
    state_global: int | None = None
    cur = rva
    for _ in range(6):
        f = inv.find(cur)
        if f is not None and f.begin == cur:
            return cur, state_global
        body = img.read(cur, 16)
        if body is None:
            return cur, state_global
        p = 0
        if body[p:p + 3] == bytes([0x48, 0x8B, 0x0D]):
            disp = _s.unpack_from("<i", body, p + 3)[0]
            state_global = cur + p + 7 + disp
            p += 7
        if p < len(body) and body[p] == 0xE9:
            disp = _s.unpack_from("<i", body, p + 1)[0]
            nxt = cur + p + 5 + disp
            if nxt == cur:
                return cur, state_global
            cur = nxt
            continue
        return cur, state_global
    return cur, state_global


def _body_span(img: Image, inv, rva: int) -> tuple[int, bytes]:
    """Function extent at `rva`: pdata when present, gap-bounded when not.

    /O2 identical-code folding leaves some exported names on a stub between
    pdata entries (seen for lua_gettop / lua_close in reference builds).
    """
    import bisect
    f = inv.find(rva)
    if f is not None and f.begin == rva:
        body = img.read(rva, f.size())
        if body is not None:
            return f.size(), body
    idx = bisect.bisect_right([g.begin for g in inv.funcs], rva)
    prev_end = inv.funcs[idx - 1].end if idx else 0
    nxt_begin = inv.funcs[idx].begin if idx < len(inv.funcs) else rva + 0x1000
    if not (prev_end <= rva < nxt_begin):
        raise RuntimeError(f"{rva:#x} lies outside the pdata layout")
    span = min(nxt_begin - rva, 0x1000)
    body = img.read(rva, span)
    if body is None:
        raise RuntimeError(f"{rva:#x}: unreadable span")
    cut = len(body)
    while cut > 0 and body[cut - 1] in (0xCC, 0x90):
        cut -= 1
    return cut, body[:cut]


_ref_cache: dict[str, dict] = {}


def reference_function_bodies(version: str) -> dict[str, tuple[int, bytes]]:
    """{symbol: (ref_rva, body)} for one reference build, cached."""
    if version in _ref_cache:
        return _ref_cache[version]
    ref = Image.load(build_reference(version))
    inv = pdata_walk(ref)
    if inv is None:
        raise RuntimeError(f"reference {version} has no .pdata")
    by_name = {e.name: e for e in ref.exports()}
    out: dict[str, tuple[int, bytes]] = {}
    for name in SEED_SYMBOLS:
        exp = by_name.get(name)
        if exp is None or exp.forwarded:
            raise RuntimeError(f"reference {version} does not export {name}")
        rva, _g = follow_export_stub(ref, inv, exp.rva)
        size, body = _body_span(ref, inv, rva)
        if size < 4:
            raise RuntimeError(f"{name}: degenerate span in reference {version}")
        out[name] = (rva, body)
    _ref_cache[version] = out
    return out


def bootstrap(target_dll: Path, build_id: int, *,
              versions: list[str] | None = None) -> dict:
    target = Image.load(target_dll)
    tinv = pdata_walk(target)
    if tinv is None:
        raise RuntimeError("target module has no .pdata")

    if versions is None:
        versions = discover_versions()
    print(f"bootstrap: candidate Lua versions: {', '.join(versions)}")

    functions: dict[str, dict] = {}
    notes: list[str] = []
    solved_by_version: dict[str, str] = {}

    for version in versions:
        todo = [s for s in SEED_SYMBOLS if s not in functions]
        if not todo:
            break
        try:
            bodies = reference_function_bodies(version)
        except Exception as exc:  # a missing/odd release must not stop the sweep
            notes.append(f"reference {version}: skipped ({exc})")
            continue
        prologue = shared_prologue_length(
            [b for _, b in bodies.values()], cap=32) if len(todo) == len(SEED_SYMBOLS) else 0
        wins_here = 0
        for name in todo:
            ref_rva, body = bodies[name]
            result = generate(body, ref_rva, target, start_min=prologue,
                              max_len=64, inventory=tinv)
            if result is None:
                result = generate(body, ref_rva, target, start_min=0,
                                  max_len=64, inventory=tinv)
            if result is None:
                continue
            pat, start, hit = result
            entry = hit - start
            f = tinv.find(entry)
            fn_size = f.size() if f else 0
            lo, hi = SIZE_ENVELOPE[name]
            if not (lo <= fn_size <= hi):
                notes.append(f"{name}@{version}: unique hit {entry:#x} but fn size "
                             f"{fn_size:#x} outside envelope — rejected")
                continue
            functions[name] = {
                "rva": f"0x{entry:X}",
                "pattern": pat.to_text(),
                "mask": pat.mask(),
                "unique": True,
                "pdata_entry_ok": True,
                "fn_size": fn_size,
                "reference_version": version,
                "pattern_offset": start,
            }
            solved_by_version[name] = version
            wins_here += 1
            print(f"  [{version}] {name:20s} rva=0x{entry:X}  "
                  f"win={pat.length():2d}@{start:2d}  size={fn_size:#x}")
        if wins_here:
            print(f"bootstrap: reference {version} matched {wins_here} new symbol(s)")

    for name in SEED_SYMBOLS:
        if name not in functions:
            notes.append(f"{name}: FAILED — no unique pdata-entry pattern from any "
                         f"reference in {', '.join(versions)}")

    dominant = max(set(solved_by_version.values()), key=list(solved_by_version.values()).count,
                   default="?")
    seed = {
        "build": build_id,
        "module": target_dll.name,
        "generator": "pipeline/1.0.0 (bootstrap)",
        "inferred_lua_version": dominant,
        "target_code_hash": f"0x{target.code_hash():016X}",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "reference_compiler": "MSVC /O2 /MT (local BuildTools, vcvars64)",
        "lua_functions": functions,
        "verification": {
            "static_unique": all(v["unique"] for v in functions.values()),
            "pdata_entry_ok": all(v["pdata_entry_ok"] for v in functions.values()),
            "notes": notes + [
                "community-dump cross-check unavailable: FiveM-Offsets-Dumper "
                "JSONs are Discord-gated placeholders; replaced by "
                "unique-match + pdata-entry + size-envelope gates",
            ],
        },
    }
    return seed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", required=True, type=Path,
                    help="FiveM lua module dll (from cache/artifacts/<id>/files)")
    ap.add_argument("--build", required=True, type=int)
    ap.add_argument("--versions", default="",
                    help="comma-separated reference versions (default: auto-discover)")
    ap.add_argument("--out", type=Path, default=DATA / "seeds" / "lua_functions.json")
    args = ap.parse_args(argv)

    vers = [v.strip() for v in args.versions.split(",") if v.strip()] or None
    seed = bootstrap(args.target, args.build, versions=vers)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(seed, indent=2), encoding="utf-8")
    n = len(seed["lua_functions"])
    print(f"bootstrap: wrote {args.out} ({n}/{len(SEED_SYMBOLS)} symbols), "
          f"inferred lua {seed['inferred_lua_version']}")
    return 0 if n == len(SEED_SYMBOLS) else 2


if __name__ == "__main__":
    raise SystemExit(main())
