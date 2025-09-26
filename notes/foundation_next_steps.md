# Foundational Acceleration Roadmap (Initial Actions)

## 1. PSYQ SDK → Ghidra Function ID Database

### Inventory

`assets/PSYQ_SDK` currently holds 90+ static libraries. Core runtime libraries:

- `psyq/lib/*.LIB`
- `psyq/psx/lib/*.LIB`
- `psyq/psx/lib/patches/*.LIB`
- specialised add-on libs (CARD, TMD, MTAP, etc.)

Specific counts (see `scripts/logs/fidb_lib_inventory.txt` once generated) were captured via:

```powershell
pwsh -NoLogo -NoProfile -Command "Get-ChildItem -Path assets/PSYQ_SDK -Recurse -Include *.lib | Sort-Object FullName"
```

### Proposed workflow

1. **Normalise paths** – copy the list above into `scripts/data/fidb_libs.txt` (one path per line) so automated scripts have a stable manifest.
2. **Headless import** – add a Ghidra headless script (`ghidra_scripts/GenerateFidb.java` or Python) that:
   - Imports each library into a temporary project (`./ghidra_proj/fidb_tmp.gpr`).
   - Runs *Function ID → Create Database from Programs* on the project aggregate.
   - Exports the resulting `.fidb` to `exports/fidb/psyq_stdlib.fidb`.
3. **Validation** – load any PSYQ sample binary, apply the new FIDB, confirm libc/libgpu functions auto-label.
4. **Distribution** – commit the `.fidb` and manifest so other operators can re-generate it deterministically.

### Immediate next step

- [x] Create `scripts/data/fidb_libs.txt` and populate with the inventory (generated via `python scripts/generate_fidb_manifest.py --include-patches`).
- [x] Scaffold `ghidra_scripts/GenerateFidb.py` to wire the headless pipeline.
- [ ] Decide whether to slim the manifest to a smaller core set before first `.fidb` run (currently includes 50 archives: base, psx, and patch variants).

## 2. Debug Symbol Reconnaissance

The SDK already contains a rich set of `.SYM`/`.MAP` files (see `pwsh -Command "Get-ChildItem ..."` output). While they target demo projects, they are invaluable for:

- Recovering standard structure layouts.
- Extracting compiler-generated naming conventions.
- Seeding the type archive.

### Action items

- [x] Export the `.MAP` symbol→address tables into CSV (`exports/symbols/sdk_map_symbols.csv`).
- [x] Add automation under `scripts/export_map_symbols.py` to regenerate the dataset (also emits `sdk_symbol_summary.csv`).
- [x] Derive high-confidence rename payload (`exports/symbols/sdk_symbol_labels.json`) via `scripts/build_sdk_symbol_labels.py`.
- [x] Author `ghidra_scripts/ApplySdkSymbols.py` to apply the labels inside an active project.
- [x] Categorise symbols by subsystem (`exports/symbols/sdk_symbol_groups.csv`, `sdk_symbol_group_counts.csv`) via `scripts/categorize_sdk_symbols.py`.
- [x] Attach category metadata to the label payload and surface per-category subsets (`scripts/filter_symbol_labels.py`, outputs `.graphics.json`, `.audio.json`, etc.).
- [x] Generate subsystem dossiers (`notes/symbol_dossiers/*.md`) and plain-text label maps for external tooling (`scripts/generate_category_dossier.py`, `scripts/export_labels_as_map.py`).
- [ ] Diff map exports against our game binary to spot shared function IDs.
- [ ] Extend the search to `TeamBuddiesGameFiles/` once legal constraints are cleared.

## 3. Central Type Archive (`datatypes/tb_types.h`)

- ✅ Initial header scaffold created (`datatypes/tb_types.h`).
- [ ] Populate with vetted structs as discoveries graduate from notebooks (physics, crates, AI, camera, etc.).
- [ ] Add unit tests / linting to ensure struct offsets stay in sync (e.g., clang `static_assert` against known field offsets).

## 4. Interface-First Headers

### Physics

- ✅ `include/physics.h` drafted with integrator-facing prototypes.
- [ ] Backfill each prototype with linkages to actual function addresses (doc comment tags like `@addr 0x21C64`).
- [ ] Mirror this pattern for asset streaming, AI brain scheduler, audio mixer, etc.

## 5. Parallelisation Enablement

Once the steps above are in motion:

- Maintain a shared changelog in `notes/sync_log.md` summarising new types/interfaces per commit.
- Introduce a lightweight review checklist (`docs/review_checklist.md`) so each subsystem diff confirms: types updated, interface touched, docs regenerated.

---

**Next check-in suggestion:**

- Decide on the minimal library set for the first `.fidb` run.
- Approve extraction of demo `.MAP` symbol tables into `exports/symbols/`.
- Assign owners for the next interface headers (AI, Asset streamer).
