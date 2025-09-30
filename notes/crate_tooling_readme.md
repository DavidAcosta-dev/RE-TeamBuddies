# Crate tooling quick-start (2025-09-29)

This note captures the current data pipeline and the key commands for working
with the crate/weapon reverse-engineering suite. It assumes a checkout of the
`tb-re` workspace with the Python virtual environment already configured
(`.venv`).

## 1. Full data refresh

Run the extract + join pipeline in order:

1. `scripts/analyse_crate_contents.py`
   - Parses every `*_CRATECONTENTS.BIN` file and emits
     `exports/crate_contents_summary.csv` + `exports/crate_value_dictionary.csv`.
2. `scripts/extract_weapon_table.py`, `scripts/extract_projectile_table.py`,
   `scripts/extract_toys_table.py`, `scripts/extract_vehicles_table.py`
   - Decode each table to CSVs under `exports/` (weapons, projectiles,
     support toys, vehicles).
3. `scripts/crossref_crate_values.py`
   - Cross-references all crate value IDs against the gameplay tables; writes
     `exports/crate_value_crossrefs.csv`.
4. `scripts/join_crate_weapon_projectile.py`
   - Produces the master join `exports/crate_weapon_projectile_matrix.csv`
     with toy/vehicle halfwords, weapon/projectile hits, crossref summaries,
     and PSYQ domain hints.

## 2. Analytics rollups (optional but recommended)

Once the core matrix exists, refresh the downstream summaries:

- `scripts/summarize_crate_crossrefs.py` →
  `exports/crate_crossref_summary.csv`
- `scripts/summarize_crossref_overall.py` →
  `exports/crossref_table_totals.csv`, `exports/crossref_table_top_crates.csv`
- `scripts/summarize_crate_vehicle_payloads.py` →
  `exports/crate_vehicle_payloads.csv`
- `scripts/summarize_crate_toy_payloads.py` →
  `exports/crate_toy_payloads.csv`
- `scripts/summarize_value_domains.py` →
  `exports/crate_value_domain_summary.csv`
- `scripts/summarize_crate_domain_counts.py` →
  `exports/crate_domain_pivot.csv`
- `scripts/prioritize_psyq_trace_targets.py` →
  `exports/psyq_trace_targets.csv` + `exports/psyq_trace_targets.md`
- `scripts/summarize_psyq_focus.py` →
  `exports/psyq_focus_report.md`
- `scripts/prepare_field_truth_sheet.py` →
  `exports/psyq_field_truth_sheet.csv`
- `scripts/summarize_field_truth_progress.py` →
  `exports/psyq_field_truth_progress.md`
- `scripts/recommend_field_truth_targets.py` →
  `exports/psyq_field_truth_next.md`

Each report adds a different perspective (crate-level domain mix, per-value
PSYQ alignment, vehicle/toy snapshots).

## 3. Quick lookups

Use the helper CLI to inspect crate payloads directly:

```pwsh
& .venv/Scripts/python.exe scripts/query_crate_payload.py --crate 4
```

Add `--slot N` (0-5) to narrow to a single entry. The output echoes value
IDs, domains, crossref counts, toy/vehicle halfwords, and weapon matches.
When `scripts/prioritize_psyq_trace_targets.py` has been run, the CLI prints
an aggregate header with crate-level domain counts, PSYQ priority tier, and
focus hints to guide runtime tracing.

## 4. Ghidra integration

Copy `ghidra_scripts/CrossrefDomainLogger.py` into the Ghidra script
repository or run it from the project root. It will read
`exports/crate_crossref_summary.csv` and annotate instructions referencing
crate value symbols with their PSYQ domain + hint, guiding runtime tracing.

## 5. Recommended tracing workflow

1. Use `exports/crate_domain_pivot.csv` to pick crates dominated by the
   subsystem you’re targeting (AI/render/support).
2. Look up detailed slot info via `query_crate_payload.py` and the matrix CSV.
3. In Ghidra, run `CrossrefDomainLogger.py`, then navigate to the crate loader
   functions (`FUN_000402e0` et al.). Follow the annotations to the PSYQ calls
   (`libgte`, `libgpu`, `libspu`, `libpad`).
4. Feed any newly identified fields or behaviors back into the CSVs/notes.

## 5. Field truthing & progress tracking

- Generate `exports/psyq_field_truth_sheet.csv` via
  `scripts/prepare_field_truth_sheet.py` (defaults to `high` and `second`
  priority crates). The sheet lists every slot with predicted domains,
  crossref counts, and PSYQ focus hints, plus empty columns for observed calls
  and notes.
- Use it as the live checklist while instrumenting PSYQ libraries in Ghidra.
  Update each row with confirmed call signatures (`AddPrim`, `RotMatrix`,
  `SpuSetVoiceAttr`, etc.) and flag mismatches for follow-up.
- See `notes/psyq_field_truth_plan.md` for the end-to-end tracing procedure
  and version control tips.
- After each instrumentation pass, run
  `scripts/summarize_field_truth_progress.py` to regenerate
  `exports/psyq_field_truth_progress.md` and track slot-level verification
  percentages by priority.
- Before each session, run `scripts/recommend_field_truth_targets.py` to view
  `exports/psyq_field_truth_next.md`, a short list of the highest-value slots
  per priority that still need verification.
- Log discoveries with `scripts/update_field_truth_slot.py` (supports dry
  runs, append mode, observer names, and automatic backups).
- If you're running Ghidra in headless mode, generate a batch job via
  `scripts/generate_ghidra_field_truth_job.py` to produce
  `exports/ghidra_field_truth_job.json` (includes project path, headless
  executable, script path, and filtered slot targets). Pass extra script args
  with `--extra=--flag` syntax.
- Turn the job into runnable shell commands with
  `scripts/emit_ghidra_headless_commands.py` (defaults to PowerShell;
  supports `--shell bash`, `--program-pattern`, and `--limit`). It writes
  `exports/ghidra_headless_commands.ps1` or a bash script you can execute
  directly.

## 6. Troubleshooting tips

- If a script complains about missing CSVs, rerun the upstream step listed
  above (each `summarize_*.py` depends on the matrix).
- The Ghidra script will show missing `ghidra.*` imports when linted outside
  Ghidra—this is expected. Execute it within Ghidra to resolve the modules.
- For ad-hoc analysis, open the CSVs in a spreadsheet or load them into a
  notebook; all columns use plain integers/strings for compatibility.

With this pipeline in place, you can reproduce the entire crate dataset or
zoom in on any single slot in seconds, keeping the RE loop tight while we
map the remaining PSYQ runtime logic.
