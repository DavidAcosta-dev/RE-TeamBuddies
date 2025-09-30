# Crate contents tables (container_0288)

_Date:_ 2025-09-28

Scripts & outputs:

- `scripts/analyse_crate_contents.py` — parses every `*_CRATECONTENTS.BIN` entry, emitting:
  - `exports/crate_contents_summary.csv`: per-crate, per-slot 16-bit pairs (`value_a`, `value_b`).
  - `exports/crate_value_dictionary.csv`: unique values from both columns with occurrence counts.

- `scripts/filter_bind_index.py --pattern crate` — source inventory used to isolate relevant files (see `exports/crate_entries.csv`).

- `scripts/crossref_crate_values.py` — scans all major gameplay tables (`ACTION/ATTITUDE/BUDDIES/PERCEPT/PROJECTILES/STATICS/TOYS/VEHICLES/WEAPONS`) for little-endian 16-bit matches against the crate ID pool. Output: `exports/crate_value_crossrefs.csv` (4,951 references across 105 unique IDs).

- `scripts/extract_weapon_table.py` → `exports/weapons_table.csv` (89 records × 50 halfwords / 25 dwords). Confirms each weapon entry is 100 bytes; fields `[12,13]` carry the high-ID pairs seen in `value_b`.

- `scripts/extract_projectile_table.py` → `exports/projectiles_table.csv` (82 records × 56 halfwords). Projectiles weigh in at 112 bytes apiece (likely weapon-linked archetypes).

- `scripts/show_function.py FUN_000402e0` — quick grab of exported Ghidra decomp (useful when correlating data structures with suspected loader routines).

## Observations

- Every crate list is 28 bytes: header `count=6`, `reserved=0`, followed by six `(value_a, value_b)` pairs.
- Filenames map one-to-one with themed `.BIN` descriptors (e.g. `10_CRATECONTENTS.BIN` + `10_BT_ALL_FLAME_WEAPONS.BIN`). The script strips the prefix to expose labels (e.g. `ALL_FLAME_WEAPONS`).
- Early campaign areas (indices `0`–`7`) share a default loadout `[38,39,28,40,30,2]` vs `[112,113,104,114,106,3]`. Desert (`index 2`) swaps the last pair to `(3,144)`.
- Specialist crates (`index >= 10`) introduce high-valued IDs: e.g. `value_a=118/120/...` for themed weapon drops, with `value_b` in `119–155` range. Crossref confirms these align with discrete weapon/vehicle payloads.
- Unique value tallies:
  - `value_a`: 46 distinct codes (min `2`, max `178`).
  - `value_b`: 41 distinct codes (min `2`, max `178`).

- Weapon table structure: 89 records, 0x64 bytes each. Decoding as 25 little-endian dwords shows slot `[12]` and `[13]` hold the crate-facing weapon IDs (e.g. record `#3` exposes `(118,119)` used by `ALL_FLAME_WEAPONS`). Neighbouring fields (`[15]` onward) house what look like stat blobs (damage?, cost?, etc.).
- Projectile table structure: 82 records, 0x70 bytes each. High-value crate IDs (e.g. `170`, `177`, `178`) pop up in projectile rows covering muzzle setup and VFX references.

## Cross-reference highlights (2025-09-28)

- `value_b` ≥ 112 map cleanly into `WEAPONS.BIN` third/fourth fields (paired IDs). Example: crate slot `[118,119]` → weapon record `#17` (flame set) and matching entries inside `ACTION/ATTITUDE/STATICS` lumps.
- Baseline crates `[38,39,28,40,30,2]` hit multiple systems: `TOYS.BIN` rows (`value_a`), `WEAPONS.BIN` stat blocks (`value_b`), and AI reaction tables (`ACTION/ATTITUDE/PERCEPT`). Desert swap `(3,144)` pulls a different weapon pair (`WEAPONS #11` for ID 144).
- High-ID `value_a` entries (≥120) correlate strongly with ATTITUDE/BUDDIES state tables and STATICS geometry, suggesting they encode AI package or vehicle class rather than the physical weapon.
- `WEAPONS.BIN` is 89 records × 100 bytes; the crossref script treats each record as 16-bit chunks, so offsets in `crate_value_crossrefs.csv` indicate the byte position within that 100-byte slab.
- Remaining unmatched IDs after crossref: none (the broader scan now resolves all 105 values somewhere in the gameplay tables). Concentrated hits in `PROJECTILES.BIN` and `ACTION.BIN` hint at per-weapon projectile archetypes.

## Weapon struct mapping (2025-09-28)

- `scripts/dump_weapon_record.py` dumps any `WEAPONS.BIN` entry as 16-bit / 32-bit tables and optionally emits `exports/weapons_struct_summary.csv` covering the offsets flagged below.
- Loader routine `FUN_000402e0` copies 0x5C bytes into the runtime weapon state. Mapped pairs so far:
  - Record `0x1C → runtime+0x10`, `0x20 → runtime+0x08`, `0x24 → runtime+0x16` (all 16-bit values).
  - Record `0x28 → runtime+0x18`, `0x2C → runtime+0x20` (dword pointers).
  - Record `0x38..0x48` (five dwords) → runtime `0x24..0x34`; a non-zero `0x3C` toggles flag bit `0x04`.
  - Record `0x4C → runtime+0x3C`, `0x50 → runtime+0x3E`, `0x58 << 6 → runtime+0x40`, `0x5C → runtime+0x50`, `0x60 → runtime+0x54`.
- `FUN_00040a4c` (fire control) references runtime offsets `+0x0C`, `+0x0E`, `+0x3C`, `+0x3E`, and `+0x42`. Those correlate back to record offsets `0x0C/0x0E` (cooldown + spread) and the `0x4C/0x50` shot window pair.
- High crate IDs (`value_b` ≥ 112) appear consistently at record offset `0x30` (dword), with adjacent `0x34` storing the tier upgrade partner. Multiple weapon records reuse the same pair, matching the game's multi-crate upgrade chain.
- Flag byte at runtime `+0x42` accumulates: bit0 (immediate availability), bit1 (record `0x18` non-zero), bit2 (record `0x3C` non-zero), bit3 (record `0x54` non-zero). This offers a quick classifier for special behaviours when inspecting dumps.

## Projectile struct mapping (2025-09-28)

- `scripts/dump_projectile_record.py` mirrors the weapon inspector for `PROJECTILES.BIN`, providing annotated dumps and `exports/projectiles_struct_summary.csv` (82 × 112-byte records).
- Weapon record field `0x2C` holds the projectile archetype index. For example, weapon `#17` points at projectile `#17`, which in turn carries the crate-driven VFX block (`0x64–0x6C`).
- Shared offsets spotted so far:
  - `0x18` / `0x5C` regulate burst loops (mirrors weapon runtime `+0x3E` cadence).
  - `0x24`/`0x4C`/`0x50`/`0x54` encode signed launch velocity vectors (values like `0xFFE2` = −30 align with arced explosives).
  - `0x28`/`0x2C` choose projectile sprite + behaviour packages; these values cross-reference `ACTION/STATICS` hits for the same crate IDs.
  - `0x64`/`0x68`/`0x6C` host high-ID resource handles (VFX/SFX), explaining the secondary crate `value_b` collisions reported by `crossref`.
- Fire control (`FUN_00040a4c`) reads the projectile via the weapon’s runtime pointer chain, so the pairing above closes the loop between crate slot → weapon record → projectile archetype → FX assets.

## Crate → weapon → projectile matrix (2025-09-29)

- `scripts/join_crate_weapon_projectile.py` generates `exports/crate_weapon_projectile_matrix.csv`, fusing each crate slot with matching weapon records and their projectile archetypes. The script flags whether a match came from the primary weapon ID (`value_b` == weapon offset `0x30`) or the upgrade ID (`0x34`).
- Baseline park crate illustrates the chain: slot `[38,112]` → weapon `#0` (`value_b=112`, projectile `#81`), while slot `[39,113]` resolves to the same weapon via the `upgrade` column, confirming the multi-stage unlock pipeline.
- Several slots (e.g. `[28,104]`) still report `weapon_matches=0`; these likely correspond to non-weapon payloads (vehicles / toys) and should be chased through `TOYS.BIN` and friends in a follow-up pass.
- The matrix exposes duplicate weapon hits for high-tier crates: dual rows for `value_b=114` capture both base and elite variants sharing projectile families but diverging in cooldown/range stats.

## Crate payload enrichments (2025-09-29)

- `scripts/join_crate_weapon_projectile.py` now also hydrates each crate slot with the literal `TOYS.BIN` (six word) and `VEHICLES.BIN` (first twelve word) payload snapshots alongside the weapon/proj join.
- `toy_w00…toy_w05` mirror `TOYS.BIN[value_a]`, confirming `value_a` is a direct index. Baseline slots (`value_a` 38/39/28/40/30/2) flip between the two family flags observed in the toy table (`w00=2` vs `w00=3`).
- When `value_b < 86` the new `vehicle_*` columns surface the matching `VEHICLES.BIN` record (e.g. crate slot `[value_b=2]` resolves to vehicle record `#2`, complete with the `0xFFFF` sentinels seen in the raw dump). Higher crates still lean on weapon IDs, leaving the vehicle columns blank.
- Weapon-enabled rows keep their per-match duplication, so downstream tooling that key off `weapon_index` remain compatible.
- Added inline `value_a/value_b` crossref columns (counts + table breakdown) sourced from `crossref_crate_values.py`. Every crate row now surfaces the PSYQ-facing table footprint (ATTITUDE, PERCEPT, STATICS, etc.), smoothing the pivot into runtime analysis.

## Vehicle payload rollup (2025-09-29)

- `scripts/summarize_crate_vehicle_payloads.py` condenses every `vehicle_present=1` row from the matrix, emitting `exports/crate_vehicle_payloads.csv` with one record per `value_b` index.
- The summary shows eleven distinct vehicle-backed payloads. Low-tier crates (`value_b=2/3/4/5`) share the same halfword templates we saw in the raw vehicle table, confirming the matrix is now a lossless join back into `VEHICLES.BIN`.
- `value_b=30` lights up five crate slots, offering a strong lead that this record governs the “heavy weapon” drop vehicles—worth chasing through the ATTITUDE/PERCEPT hits.
- None of the vehicle-tagged crates currently show weapon matches; they’re pure vehicle drops. Next pass should pivot into the PSYQ SDK’s `libgpu`/`libgte` call sites to help name the setup routines that consume these structs.

## Toy payload rollup (2025-09-29)

- `scripts/summarize_crate_toy_payloads.py` mirrors the vehicle summary for `TOYS.BIN`, yielding `exports/crate_toy_payloads.csv` (61 unique `value_a` indices).
- Baseline story crates collapse into two main templates: flag `w00=1` (core campaign) vs `w00=3` (thematic/skirmish sets). Their `w02` field lines up with the crate slot number, reinforcing the direct index relationship.
- Higher themed crates (`value_a` ≥ 30) showcase the curated loadouts: e.g. `value_a=32` (heavy weapons) and `value_a=33` (grenade focus) roll across multiple mission labels. These should tie cleanly into AI behaviour tables now that we can key off the toy words.
- Several toy indices (e.g. `15`, `37–39`) coincide with known mission scripting beats. We can now sample their runtime usage to see which PSYQ input/audio helpers (`libpad`, `libspu`) they touch when spawning support gadgets.

## Cross-table / PSYQ domain summary (2025-09-29)

- `scripts/summarize_crate_crossrefs.py` fuses the crate pairs with `crate_value_crossrefs.csv`, rolling every crate index into `exports/crate_crossref_summary.csv`.
- Each row accounts for total hits per gameplay table (`ACTION/ATTITUDE/…`) and buckets them into rough PSYQ-facing domains (`render` → `libgpu/libgte`, `support` → `libspu/libpad`, etc.).
- Early campaign crates (0/1) spike in the AI domain (`PERCEPT/ATTITUDE`) while snow/late-game crates (`index 4`) show heavy render/combat overlap—prime targets when combing through PSYQ draw routines for crate-driven FX.
- The dominant-domain hint column is perfect for triaging which crates to chase in Ghidra: rendering-heavy crates should intersect the geometry upload paths, while support-heavy crates likely schedule pad/SPU helpers.

## Crossref heatmap totals (2025-09-29)

- `scripts/summarize_crossref_overall.py` provides two helper exports:
  - `exports/crossref_table_totals.csv` — aggregate hit counts per table (PERCEPT leads at 10,458 hits, followed by ACTION at 5,786 and VEHICLES/BUDDIES at ~4.4k each).
  - `exports/crossref_table_top_crates.csv` — top crate contributors per table (e.g. ICE_AREA `index 4` dominates PERCEPT/ACTION/ATTITUDE, while heavy weapon crates `index 32/33/34` blanket the combat/render mix).
- These totals confirm that PERCEPT/ATTITUDE data is the primary driver behind crate values; expect `libgte` vector math in the surrounding routines.
- VEHICLES.BIN’s high count (4,422) underscores the need to map those structs into `libgpu` primitive emitters and `libgte` transforms soon.
  - Companion Ghidra script `ghidra_scripts/CrossrefDomainLogger.py` can now read the summary CSV and auto-annotate any instructions referencing crate value symbols with their dominant PSYQ domain.

## Value-level domain map (2025-09-29)

- `scripts/summarize_value_domains.py` collapses the crossref data per value ID, emitting `exports/crate_value_domain_summary.csv` (105 rows).
- Each value now carries: (a) whether it appears as `value_a`/`value_b`, (b) per-table hit counts, and (c) a dominant PSYQ domain (plus hint). Context strings (`crate_index:label:slot`) make it trivial to spot which missions exercise a value.
- Example: `value=2` lands in both `value_a` and `value_b` across 12 slots, with 499 ATTITUDE and 680 PERCEPT hits → a pure AI domain candidate. `value=4` trends render-heavy, pointing straight at `libgpu`/`libgte` geometry prep.
- Use this sheet alongside `crate_weapon_projectile_matrix.csv` to decide whether a lingering unmatched crate payload is a combat stat blob, an FX bundle, or a support gadget before cracking the disassembly.
- `scripts/join_crate_weapon_projectile.py` now inlines these domain descriptors so every crate row reports both `value_a` and `value_b` domains, hints, kinds, and slot contexts.
- `scripts/summarize_crate_domain_counts.py` pivots the matrix back into `exports/crate_domain_pivot.csv`, showing per-crate domain tallies (`value_a`, `value_b`, combined). Handy when scanning for crates dominated by render vs support payloads.
- `scripts/query_crate_payload.py --crate N [--slot M]` offers a quick CLI lookup for any crate slot, echoing value domains, crossref counts, toy/vehicle halfwords, and weapon ties straight from the joined matrix.

## Non-weapon payload sweep (2025-09-29)

- `scripts/summarize_unmatched_crate_payloads.py` scans the matrix for slots without weapon hits and collates their cross-table appearances into `exports/crate_unmatched_payloads.csv`.
- 40 distinct `value_b` codes currently lack weapon records; most spike across `PERCEPT`, `ACTION`, and `VEHICLES`, with smaller hits in `TOYS.BIN`/`POWERUP.BIN` — pointing to support crates, vehicles, and scripted gadgets rather than firearms.
- Early campaign crates (`value_b` 2–5) still register residual `WEAPONS.BIN` counts via the crossref, implying shared stats with ally AI arsenals even when no player weapon entry exists.
- Next steps: build focused extractors for `TOYS.BIN` and `VEHICLES.BIN` akin to the weapon/projectile tooling so these IDs can be decoded and linked back to crate behaviours.

## Tooling snippets

- Get detailed ref fan-out for a specific ID (e.g. 118):

  ```pwsh
  python -c "import csv;from collections import defaultdict;refs=defaultdict(list);
  with open('exports/crate_value_crossrefs.csv',newline='') as f:
      reader=csv.DictReader(f)
      for row in reader: refs[int(row['value'])].append(row);
  for hit in refs[118]: print(hit)"
  ```

- Dump suspect loader decomp:

  ```pwsh
  python scripts/show_function.py FUN_000402e0
  ```

## Next steps

- Solidify field semantics:
  - `value_b` → weapon payload IDs (`WEAPONS.BIN` offsets; validate by spotting same pairs inside projectile tables).
  - `value_a` → behaviour/asset bundle IDs (heavy overlap with `ACTION/ATTITUDE/PERCEPT/STATICS`).
  - Extract representative records (e.g. weapon entry #17) and reverse individual fields.
- Cross-check loader code paths (`FUN_000402e0`, `FUN_0004033c`) with the crate tables: both copy 0x5C-byte structs and branch via jump tables — look for loops iterating six pairs.
- Expand crossref script into a richer report (join crate index + label + resolved weapon/behaviour names).
- Decode `toy_wXX` and `vehicle_wXX` semantics now that the raw fields travel with each crate row; correlate the repeating constants with ATTITUDE/BUDDIES hits.
- Trace the runtime constructors that feed `VEHICLES.BIN` records into PSYQ driver calls (expect `libgpu` prim setup and `libgte` matrix uploads) so we can label the vehicle spawn pipeline.
- Follow the toy indices through the allocator paths that light up PSYQ subsystems (`libspu` for SFX toys, `libpad` for remote triggers) to firm up payload semantics.
- Use the new PSYQ domain heatmap to pick tracer targets (render-heavy crates first, then support-heavy) and map them to the corresponding SDK libraries.
- Prioritize ICE_AREA (index 4) and weapon set crates (32/33/34) when instrumenting PSYQ draw/audio helpers—those indexes explain the majority of ACTION/PERCEPT/VEHICLES hits.
- When mapping individual value IDs, lean on `crate_value_domain_summary.csv` to shortlist the tables and PSYQ subsystems likely responsible; chase those in Ghidra before diving into broader scans.
- Feed the CSVs into a notebook for visual diff across mission areas (heatmap of weapon distribution, etc.).
