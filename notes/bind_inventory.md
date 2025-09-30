# BUDDIES.DAT content snapshot

_Date:_ 2025-09-28

Ran `python scripts/extract_bind.py assets/TeamBuddiesGameFiles/BUDDIES.DAT --extract --recurse` to refresh the corpus of extracted Team Buddies assets. Key artifacts:

- `exports/bind_index_BUDDIES.DAT.csv` — complete index of 6,228 BIND entries (container id, offsets, sizes).
- `assets/extracted/BUDDIES.DAT/container_XXXX/` — raw payloads unpacked per BIND, including nested `.BND` material.

Notable findings while skimming the index:

- Container `0000` hosts a block of particle textures (`\SMOKE_*.TIM`, `\FLAME*.TIM`, etc.).
- Look for crate-related art via query `CRATE` or `BOX`; present in mid-range containers (to catalogue later).
- BND recursion is enabled, so nested bundles (e.g. `\LEVEL???.BND`) are already unpacked alongside parents.

Next actions:

1. Build quick search helpers (Python/notebook) to slice the index for specific prefixes (e.g. vehicle models, crate states). **✅ `scripts/filter_bind_index.py` now supports substring/regex queries, CSV export, and per-container summaries.**
   - Example: `python scripts/filter_bind_index.py --pattern crate --summarise`
2. Correlate container offsets with runtime file loads observed in Ghidra (bookmark high-traffic `BIND` readers).
3. Cross-reference crate-carry mechanics by locating matching assets (likely `\CRATE.TIM` et al.) and linking them back to suspected physics functions (`FUN_000402e0`, `FUN_000406ac`).

Fresh `crate` sweep (2025-09-28):

- 48 hits written to `exports/crate_entries.csv`.
- Bulk of the logic-style data lives in `container_0288` (`*_CRATECONTENTS.BIN` sequence; 41 small records).
- Textures surface in several containers:
  - `container_0142` → `\CRATES.TIM` (13,984 bytes).
  - `container_0586` → `\UNICRATE.TIM` (2,176 bytes) and `\HO_CRATE.TIM` (2,112 bytes).
  - `container_0587` → gameplay data blob `\DATA\CRATE.BIN` (1,540 bytes).
- `\UNICRATE.TIM` also mirrored in the early particle containers (IDs 0000–0002).

  Process automation:

  - `scripts/filter_bind_index.py` (substring/regex search over the index).
  - `scripts/analyse_crate_contents.py` (parses the `*_CRATECONTENTS.BIN` suite → see `notes/crate_contents_analysis.md`).
