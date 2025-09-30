# PSYQ crate trace targets (2025-09-29)

Digest of crate indexes whose cross-reference profiles make them ideal for
instrumenting PSYQ library calls during the next reverse-engineering pass.

## Automation refresher

Run `scripts/prioritize_psyq_trace_targets.py` after regenerating the crate
matrix and domain pivot. It emits both `exports/psyq_trace_targets.csv` and
`exports/psyq_trace_targets.md`, ranking every crate by blended PSYQ tracing
score (domain coverage + cross-reference density). Use the generated Markdown
as the up-to-date baseline, then curate highlights below when planning a
focused session.

For domain-specific drilldowns, run `scripts/summarize_psyq_focus.py` to
produce `exports/psyq_focus_report.md`, which lists the top crates per domain
with priority tiers and focus hints.

When you're ready to record runtime observations, generate
`exports/psyq_field_truth_sheet.csv` via `scripts/prepare_field_truth_sheet.py`
and follow the checklist outlined in `notes/psyq_field_truth_plan.md`.
Track completion with `scripts/summarize_field_truth_progress.py`
(`exports/psyq_field_truth_progress.md`).
Use `scripts/recommend_field_truth_targets.py` to surface the next slots to
instrument (`exports/psyq_field_truth_next.md`).
Apply findings with `scripts/update_field_truth_slot.py`, which writes
observed PSYQ calls/notes back to the checklist (backups saved automatically).
Need a headless batch? Generate `exports/ghidra_field_truth_job.json` via
`scripts/generate_ghidra_field_truth_job.py` and feed it into your Ghidra
automation harness. For turnkey command lists, run
`scripts/emit_ghidra_headless_commands.py` to write shell commands that invoke
`analyzeHeadless` for each queued crate/slot.

## High-priority crates

| Crate index | Label              | Highlights | PSYQ focus |
|-------------|-------------------|------------|------------|
| 4           | ICE_AREA          | Leads ACTION/ATTITUDE/PERCEPT totals; heavy VEHICLES coverage | `libgpu` primitive setup, `libgte` transforms, possible `libspu` ambient FX |
| 32          | (heavy weapons)   | Massive ACTION/PERCEPT footprint, strong VEHICLES hits | `libgte` targeting + `libgpu` HUD/FX |
| 33          | (grenade focus)   | Mirrors index 32, strong STATICS overlap | `libgpu` FX quads, `libgte` projectile vectors |
| 24          | STEALTH_2         | High BUDDIES/VEHICLES counts | `libgpu` stealth vehicle spawn path, `libspu` stealth SFX |
| 34          | (missile focus)   | ATTITUDE spike, cross-couples with PROJECTILES | `libgte` targeting logic, `libgpu` projectile mesh emitters |

## Second wave

| Crate index | Label             | Highlights | PSYQ focus |
|-------------|------------------|------------|------------|
| 0 / 1       | PARK / PLAINS    | Baseline crates, good control group for AI behaviour profiling | `libgte` AI vector math, `libpad` for tutorial cues |
| 30          | (vehicle heavy)  | Highest vehicle payload fan-out | `libgpu` vehicle model upload, `libgte` camera adjustments |
| 21          | FLYING_3         | Elevated ATTITUDE with unique PROJECTILES mix | `libgte` altitude logic + `libspu` flight loop |
| 7           | MOON_AREA        | Balanced AI/render mix with unique STATICS hits | `libgpu` lunar FX primitives |

## Workflow suggestions

1. Hook the crate loader routines in Ghidra and watch for calls into PSYQ
   libraries listed above. Prioritize `FUN_000402e0` and neighbours already
   noted in the weapon analysis.
2. For each crate, log the indices passed into `libgte` matrix functions
   (`RotMatrix`, `SetTransMatrix`, etc.) to tie specific payload words to
   runtime transforms.
3. Mirror the logging for `libgpu` primitive builders (`AddPrim`, `DrawOTag`)
   to capture vehicle/toy geometry usage.
4. Use `libspu`/`libpad` call traces to classify support crates (toys and
   gadgets) — align the captured indices with `crate_toy_payloads.csv`.
5. Feed validated mappings back into `crate_crossref_summary.csv` so the
   dominant-domain hints can be promoted to actual subsystem labels.
6. When isolating a stubborn value ID, consult `crate_value_domain_summary.csv`
   (or the inlined columns in `crate_weapon_projectile_matrix.csv`) to
   confirm its dominant table/PSYQ domain before hunting for the
   corresponding runtime structure.
7. For crate-level prioritization, use `crate_domain_pivot.csv` to identify
   which missions skew toward AI/render/support before selecting Ghidra
   trace targets.

Maintaining these targets alongside the CSV exports should keep the PSYQ
reverse-engineering sprint focused and measurable.
