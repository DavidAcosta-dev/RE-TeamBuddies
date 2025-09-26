# PSYQ Symbol Exports

This directory houses machine-readable symbol tables extracted from the PSYQ SDK
samples. They power automated matching against the Team Buddies binaries and any
future FIDB enrichment work.

## Artifacts

- `sdk_map_symbols.csv` – raw concatenation of 74 MAP files (19,056 symbol rows)
  with columns:
  - `map_file`: repo-relative path of the originating MAP file
  - `symbol`: linker-provided export name
  - `address_hex`: hex address as reported by the sample build
  - `annotation`: any trailing text on the source line (section, size, etc.)
- `sdk_symbol_summary.csv` – per-symbol aggregation distilled from the raw CSV
  via `scripts/export_map_symbols.py`. Columns capture the canonical address
  (highest frequency), total observations, distinct addresses, unique MAP
  origins, and a histogram of alternative addresses.
- `sdk_symbol_labels.json` – filtered high-confidence symbols generated with
  `scripts/build_sdk_symbol_labels.py` (default: observations ≥ 2, unique
  address, address range 0x80000000–0x8FFFFFFF). Each entry now carries a
  `categories` field (graphics, audio, cdrom, etc.) to support targeted rename
  passes via `ghidra_scripts/ApplySdkSymbols.py`.
- `sdk_symbol_groups.csv` – per-symbol category metadata inferred from MAP
  source paths using `scripts/categorize_sdk_symbols.py`.
- `sdk_symbol_group_counts.csv` – aggregate counts per category (graphics,
  audio, CD-ROM, etc.) derived from the grouping pass.
- `sdk_symbol_labels.json.<category>.json` – filtered subsets created with
  `scripts/filter_symbol_labels.py` (examples: `.graphics.json`, `.audio.json`,
  `.cdrom.json`, `.ui.json`).
- `sdk_symbol_labels.map` – plain-text dump (`address symbol categories`) created via
  `scripts/export_labels_as_map.py` for quick ingest into external tooling.

## Regeneration

```pwsh
python scripts/export_map_symbols.py
python scripts/build_sdk_symbol_labels.py
python scripts/categorize_sdk_symbols.py
python scripts/filter_symbol_labels.py --include graphics
python scripts/export_labels_as_map.py
```

The first script walks `assets/PSYQ_SDK` for `.MAP` files, emits the raw CSV,
and then produces the summary dataset automatically. The second script filters
the summary into a rename-ready JSON payload (with categories). The third pass
applies heuristic categorisation to aid subsystem owners. The final command
demonstrates emitting a category-specific subset for focused rename sessions.
Outputs are overwritten on each run, keeping the exports deterministic.

## Next steps

- Compare canonical addresses with the actual Team Buddies binary (e.g. via
  `ghidra_scripts/ApplySdkSymbols.py`) to confirm linker reuse and seed
  function renaming efforts.
- Extend the summary to surface module grouping (e.g., GPU vs SPU) so subsystem
  owners can zero in on relevant call patterns quickly.
- Add filters or allowlists for subsystem-specific exports when applying
  labels, so header owners can iterate independently (supported via
  `ApplySdkSymbols.py include_categories=...`).
- Use `sdk_symbol_group_counts.csv` to prioritise which subsystems warrant
  deeper dives (e.g., graphics-heavy functions vs. audio pipelines).
