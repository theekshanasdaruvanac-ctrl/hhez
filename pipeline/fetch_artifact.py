"""Phase 1 — Artifact fetcher: FiveM build id -> extracted binary bundle on disk.

    fetch_build(build_id) -> Path      # cache/artifacts/<build_id>/  (bundle extracted)
    find_lua_module(dir)  -> Path      # citizen-scripting-lua54.dll preferred

The public listing:
    https://runtime.fivem.net/artifacts/fivem/build_server_windows/master/

Observed in the field (2026-09), and handled here:
  * The listing is a Next.js page. A bare GET intermittently returns
    HTTP 500; the same URL with any query string renders the href list.
    So we try the bare URL first and retry with cache-busting query
    strings before giving up.
  * Href entries look like `<build>-<40-hex>/server.7z` (and, on older
    listings, `<build>-<hash>/citizen.zip`). Every artifact name under a
    bundle directory is accepted; the download order prefers the
    archives that actually contain the citizen scripting modules.
  * Old builds are re-published under the newest hash sometimes; the
    latest entry for a build id wins.

Everything is cached under cache/artifacts/<build_id>/ and never
re-downloaded once the .done.json marker is written. Environment
overrides for tests / mirrors:
    FIVEM_LISTING_URL   replaces the listing endpoint
    FIVEM_BASE_URL      replaces the artifact base (used with an explicit bundle dir)
    FIVEM_ARTIFACT_URL  full archive URL; skips the listing entirely
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

import requests

BASE_URL = "https://runtime.fivem.net/artifacts/fivem/build_server_windows/master/"
LISTING_URL = BASE_URL

# Archive names tried in order inside a bundle directory, best evidence first:
# modern server bundles ship server.7z; older ones shipped citizen.zip.
ARTIFACT_NAMES = ("citizen.zip", "server.7z", "server.zip")

BUILD_HREF_RE = re.compile(r"/(\d{2,7})-([0-9a-f]{24,64})/")

LUA_PREFER = ("citizen-scripting-lua54.dll", "citizen-scripting-lua.dll")

_SESSION: requests.Session | None = None


def _session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        _SESSION = requests.Session()
        _SESSION.headers["User-Agent"] = "fivem-lua-state-pipeline/1.0 (+offline CI tooling)"
    return _SESSION


class FetchError(RuntimeError):
    pass


class BuildNotFound(FetchError):
    pass


@dataclass(frozen=True)
class BundleEntry:
    build: int
    digest: str
    url: str
    name: str  # artifact file name, e.g. server.7z


def cache_root() -> Path:
    # repo_root/pipeline/fetch_artifact.py -> repo_root/cache/artifacts
    return Path(__file__).resolve().parent.parent / "cache" / "artifacts"


def _get(url: str, *, timeout: int = 60, stream: bool = False,
         tries: int = 4, backoff: float = 2.0) -> requests.Response:
    last: Exception | None = None
    for attempt in range(tries):
        try:
            r = _session().get(url, timeout=timeout, stream=stream)
            if r.status_code == 200:
                return r
            # The Next.js listing answers 500 on cold renders; a retry usually
            # lands on a warm one. Non-5xx failures are not retryable.
            if r.status_code < 500 and r.status_code != 429:
                r.raise_for_status()
            last = FetchError(f"GET {url} -> HTTP {r.status_code}")
        except requests.RequestException as exc:
            last = exc
        if attempt + 1 < tries:
            time.sleep(backoff * (2 ** attempt))
    raise FetchError(f"GET {url} failed after {tries} tries: {last}")


def list_builds() -> dict[int, list[BundleEntry]]:
    """Parse the listing into {build_id: [BundleEntry per artifact name, ...]}.

    Newest hash wins per build id, and within one bundle directory the
    ARTIFACT_NAMES preference order decides.
    """
    listing_url = os.environ.get("FIVEM_LISTING_URL", LISTING_URL)
    base_url = os.environ.get("FIVEM_BASE_URL", BASE_URL)

    html = ""
    if not os.environ.get("FIVEM_ARTIFACT_URL"):
        candidates = [listing_url] + [
            listing_url + ("&" if "?" in listing_url else "?") + f"r{n}=1"
            for n in range(6)
        ]
        errors: list[str] = []
        for url in candidates:
            try:
                resp = _get(url, tries=1)
            except FetchError as exc:
                errors.append(str(exc))
                continue
            if BUILD_HREF_RE.search(resp.text):
                html = resp.text
                break
            errors.append(f"{url}: served 200 but no build hrefs")
        else:
            raise FetchError(
                "could not fetch a usable artifact listing:\n  " + "\n  ".join(errors)
            )

    found: dict[int, dict[str, BundleEntry]] = {}
    # Full URLs and root-relative hrefs both appear; normalize by capturing
    # build/hash then attaching the configured base.
    for m in BUILD_HREF_RE.finditer(html):
        build = int(m.group(1))
        digest = m.group(2)
        tail = html[m.end(): m.end() + 128]
        name_m = re.match(r"([A-Za-z0-9._+-]+)", tail)
        if not name_m:
            continue
        name = name_m.group(1)
        entry = BundleEntry(build, digest, base_url + f"{build}-{digest}/{name}", name)
        found.setdefault(build, {})[name] = entry
    return {b: list(v.values()) for b, v in found.items()}


def latest_build() -> int:
    builds = list_builds()
    if not builds:
        raise FetchError("listing parsed to zero builds")
    return max(builds)


def _pick_entry(build: int) -> BundleEntry:
    override = os.environ.get("FIVEM_ARTIFACT_URL")
    if override:
        return BundleEntry(build, override.split("/")[-2] if "/" in override.rstrip("/") else "explicit",
                           override, override.rsplit("/", 1)[-1])
    builds = list_builds()
    if build not in builds:
        raise BuildNotFound(f"build {build} is not in the listing "
                            f"(listing holds {len(builds)} entries, "
                            f"newest {max(builds) if builds else '-'})")
    by_name = {e.name: e for e in builds[build]}
    for name in ARTIFACT_NAMES:
        if name in by_name:
            return by_name[name]
    # Unknown archive name from a future listing format: take the first.
    return builds[build][0]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    suffix = archive.suffix.lower()
    if suffix == ".zip":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
    elif suffix == ".7z":
        try:
            import py7zr
        except ImportError as exc:
            raise FetchError(
                "server.7z bundles need py7zr: pip install py7zr") from exc
        with py7zr.SevenZipFile(archive) as z:
            z.extractall(dest)
    else:
        raise FetchError(f"unsupported archive type: {archive.name}")


def _download(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    resp = _get(url, timeout=300, stream=True)
    with tmp.open("wb") as f:
        for chunk in resp.iter_content(1 << 20):
            f.write(chunk)
    tmp.replace(dest)
    return dest


def fetch_build(build_id: int | str = "latest", *, force: bool = False) -> Path:
    """Return the directory holding the extracted bundle for `build_id`.

    Cached forever under cache/artifacts/<build_id>/; `force` re-fetches.
    """
    if str(build_id).lower() in ("latest", ""):
        build_id = latest_build()
    build_id = int(build_id)

    out_dir = cache_root() / str(build_id)
    done = out_dir / ".done.json"
    if done.exists() and not force:
        return out_dir

    entry = _pick_entry(build_id)

    lock = out_dir.with_suffix(".lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)  # Windows: an open handle makes the finally-unlink fail
    except FileExistsError:
        # Another process is mid-fetch for the same build. Wait for its marker.
        deadline = time.time() + 900
        while time.time() < deadline:
            if done.exists():
                return out_dir
            if not lock.exists():
                break
            time.sleep(2)
        raise FetchError(f"another fetch for build {build_id} holds {lock}; retried too long")
    try:
        files_dir = out_dir / "files"
        dl_dir = out_dir / "download"
        if files_dir.exists():
            shutil.rmtree(files_dir)
        archive = _download(entry.url, dl_dir / entry.name)
        _extract(archive, files_dir)

        lua = find_lua_module(out_dir, prefer_client=False)
        try:
            lua_rel = str(lua.relative_to(out_dir))
        except ValueError:
            lua_rel = str(lua)      # absolute fallback (foreign tree)
        manifest = {
            "build": build_id,
            "digest": entry.digest,
            "archive": entry.name,
            "archive_sha256": _sha256(archive),
            "lua_module": lua_rel,
            "lua_sha256": _sha256(lua),
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        done.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        # Keep the archive (re-extraction is cheap insurance against partial
        # trees); drop only the .part leftovers.
        for leftover in dl_dir.glob("*.part"):
            leftover.unlink(missing_ok=True)
        return out_dir
    finally:
        lock.unlink(missing_ok=True)


def client_module(bin_dir: Path) -> Path | None:
    """citizen-scripting-lua.dll *outside* an artifacts tree (a client install
    or a directory extracted directly). None when absent.

    The resolver runs inside the FiveM client, and the server artifact ships
    a stripped subset of the lua module, so a local client copy is always the
    better analysis target and is preferred when present.
    """
    bin_dir = Path(bin_dir)
    name = "citizen-scripting-lua.dll"

    def probe(root: Path) -> Path | None:
        direct = root / name
        if direct.is_file():
            return direct
        for p in sorted(root.rglob(name)):
            if p.is_file() and "artifacts" not in p.parts:
                return p
        return None

    for env in ("FIVEM_CLIENT_DIR", "DSH_FIVEM_CLIENT_DIR"):
        v = os.environ.get(env)
        if v:
            hit = probe(Path(v))
            if hit:
                return hit
    appdata = os.environ.get("LOCALAPPDATA")
    if appdata:
        hit = probe(Path(appdata) / "FiveM" / "FiveM.app")
        if hit:
            return hit
    return probe(bin_dir)


def find_lua_module(bin_dir: Path, *, prefer_client: bool = True) -> Path:
    """Locate the Lua scripting module.

    `bin_dir` may be an artifact root, its files/ subtree, or a client dir.
    With prefer_client, an installed client module wins over the server
    artifact's stripped copy (see client_module).
    """
    bin_dir = Path(bin_dir)
    if prefer_client:
        c = client_module(bin_dir)
        if c is not None:
            return c
    # Preference: the lua54 module name (client builds have shipped both),
    # then the plain name, then anything lua-ish.
    roots = [bin_dir / "files", bin_dir]
    seen: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        if root in seen:
            continue
        seen.add(root)
        all_dlls = sorted(p for p in root.rglob("*.dll") if p.is_file())
        for want in LUA_PREFER:
            for p in all_dlls:
                if p.name.lower() == want:
                    return p
        for p in all_dlls:
            if "lua" in p.name.lower():
                return p
    raise BuildNotFound(f"no lua module found under {bin_dir} "
                        f"(searched {', '.join(str(r) for r in roots)})")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Fetch a FiveM server artifact bundle.")
    ap.add_argument("build", nargs="?", default="latest",
                    help="build id, or 'latest' (default)")
    ap.add_argument("--force", action="store_true", help="re-download even if cached")
    ap.add_argument("--list", action="store_true", help="print the parsed listing and exit")
    args = ap.parse_args(argv)

    try:
        if args.list:
            for b in sorted(list_builds(), reverse=True)[:20]:
                names = ", ".join(e.name for e in list_builds()[b])
                print(f"{b}\t{names}")
            return 0
        out = fetch_build(args.build, force=args.force)
        lua = find_lua_module(out)
        print(out)
        print(f"lua module: {lua}")
        return 0
    except FetchError as exc:
        print(f"fetch_artifact: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
