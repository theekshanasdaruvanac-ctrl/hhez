# GTA5 any-build Lua offset updater - real plan (no stubs)

Target: one toolchain that, for ANY FiveM server/client artifact build and
ANY GTA5 game build (b3095..b3889..future), yields the lua_State chain and
named-function addresses, updates itself when shelves move, and fails
closed instead of guessing.

## Scope - where the cheese actually is (all field-proven in this repo)

- `CitizenFX_SubProcess_game_<N>_aslr.bin` files are game-build LAUNCHER
  STUBS (.NET sections, exception-handler exports, 3.6 MB). No Lua inside -
  proven by parsing game_3751 from artifact 36727. Game build number is
  NOT a key for Lua offsets.
- Lua lives only in `citizen-scripting-lua.dll` (artifact-keyed, byte-stable
  across game builds; measured pattern survival server 35945->36727 = 1.0).
- Therefore: offsets key on the ARTIFACT build (server + client flavors),
  game build is enumerated for compatibility reporting only, module base is
  added at runtime ("-any-game-build" is then automatic: same citizen
  module loads under b3751 or b3889).
- Out of scope, stated honestly: GTA5 natives/native-hash tables (different
  problem, different shelf), standalone non-FiveM GTA5 (no Lua exists).

## G1 - Game-build shelf map (small, first)
- New: `pipeline/fetch_client.py` - parse `build_client/master/` listing
  (same Next.js + hrefs quirks as server shelf; retry pattern reused).
- Per artifact bundle, HEAD-list `caches/fivereborn/` ->
  `CitizenFX_SubProcess_game_<N>_aslr.bin` -> game build ids present.
- Output `data/gamebuilds.json`:
  `{ artifact: 36727, digest, game_builds: [1,1604,...,3751,3788,3889] }`
  newest-per-artifact only, HEAD requests, commit size stays KiB.
- CI detect extends: new game build id = information PR (compatibility
  report), never touches offsets.
- Acceptance: map matches the live shelf (3751 listed under 36727 - rat
  already fetched this dir page once; automation must reproduce it).

## G2 - Client-flavor seeds, automated (the real "game process" half)
- Client artifacts ship the same `citizen-scripting-lua.dll`; client flavor
  HAS the rip-published holder (shape C: 36109 -> holder 0x7B72F0, field
  0x58, consumer site 0x2E20C4, all patterned offline already).
- Generalize `fetch_build(build, flavor)` (server.7z vs client zip layout),
  `find_lua_module(flavor=)`, and seed path
  `data/builds/<build>/client/lua_state.json` (server keeps existing path).
- `any_build.py --flavor client` uses client-flavor prev-seed chain
  (flavor-tracking exists since P7); export contract verified present in
  BOTH flavors (RVA 0x2DDD30 client / 0x41720 server) so shape E fallback
  works client-side too.
- Acceptance: two committed client seeds (>= one installed-client build +
  one artifact build), G1/G2 pass, holder + store-context patterns unique
  across the whole .text.

## G3 - "ANY lua function" - three honest layers
- L-fn-1 REGISTERED ground truth (done): luaL_Reg walk, 354 registrations,
  unique+pdata-exact patterns kept. This covers the full library surface a
  script can actually call by name. Extend walk to client tables too.
- L-fn-2 CORE API by semantics (partly done): lua_gettop-style family
  witness already proves struct offsets; reuse the same machinery for the
  statically-linked lua54 core: derive each core symbol from its CALLER
  graph (registered wrappers call it), name it only when the candidate is
  unique in .text AND pdata-exact. MSVC ICF makes some names provably
  unresolvable -> they go in `functions.unresolvable[]` with reason, NOT a
  guessed pattern. (Spec amendment already recorded; this closes it per
  build.)
- L-fn-3 RUNTIME CENSUS (the actual "any" answer): from a live lua_State,
  walk l_G registry -> _G -> every cfunction value IS the live address of
  every callable; no pattern needed. Lives in the G4 library:
  `EnumerateLuaFunctions(state, out)`. Static bank + live census agree-test
  each other when both available; disagreement = seed bug caught, report.
- Deliverable: `pipeline/function_bank.py` + seed section `functions` +
  `unresolvable`; acceptance: bank = every registered name, coverage
  % measured and printed, no unverifiable name carries a pattern.

## G4 - Runtime resolver library `resolver/` (C++20, the tool itself)
- `GetLuaState()`: LoadLibrary citizen-scripting-lua (base from own module
  link map - we are loaded INSIDE the host as a citizen module; in an
  external/no-inject mode: module base via Toolhelp snapshot by name). THEN
  GetProcAddress("?lua_rpmalloc_state@LuaStateHolder@fx@@...") - export
  contract, present in every build inspected, both flavors -> `&slot` in,
  `*slot == returned state`, self-proving; fallback: seed consumer pattern
  -> holder global -> `*[holder]+0x58`.
- `ResolveLuaFunction(name)`: seed JSON pattern bank -> AOB scan of THIS
  loaded module image -> accept only when exactly 1 hit and it lies in a
  pdata/range-probe-verified function start; else refuse (fail closed).
- `EnumerateLuaFunctions()`: L-fn-3 census walk (offsets from seed:
  top 0x10, l_G 0x18, ci 0x20, stack 0x30, slot 32, tt +0x10).
- Seeds embedded as resource or shipped next to DLL; JSON parsed with a
  vendored single-header parser (picojson) - no network at runtime.
- Acceptance: compiles MSVC x64; file-backed mock tests pass offline (same
  bytes CI verified); live-host verify tool `verify_lua_state.cpp` runs the
  real G3/G4 gates (structural walk + `1+1==2` via lua_pcall) inside a
  running citizen host - fills the only honest gap P6 recorded.

## G5 - The updater UX
- `tool/lua_offsets.py --dll <path.dll>` or `--build N [--flavor c|s]`:
  exact seed hit -> print offsets/address; cache miss -> runs the full
  pipeline live (fetch + Layer E/A/B/C, same code as CI); unknown module
  (private/custom build) -> cold chain on the given file, refuses silent
  partials, prints which layers fired. `--game-build N` accepted purely to
  stamp compatibility against data/gamebuilds.json.
- Exit codes mirror CI (0 usable, 2 chain-broken) so scripts can trust it.

## G6 - CI grows, no rewrite
- `lua-state-dump` matrix: flavor=[server,client]; detect adds
  "new CLIENT artifact?" and safegame-build-map refresh; PR payload per
  flavor dir. Existing jobs unchanged.
- `lua-state-verify` reruns gates over both flavor seeds.

## Order + effort (rat sessions at current pace)
G1(1) -> G2(1) -> G3(2) -> G4(2) -> G5(1) -> G6(1). Each phase reports
files/command/output/wrong-assumptions before the next starts.

## What stays honest forever
- No offset without a witness (pattern/site/family + gate note) ever ships.
- Game .bin files: enumerated, never parsed for Lua.
- Game-side natives: out of scope, one line in README, not a TODO.
- ICF-merged core API names: reported unresolvable, never faked.
- G3/G4 live gates run in live host only (offline DllMain 1114, proven).
