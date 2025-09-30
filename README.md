# RE-TeamBuddies Workspace Guide

## Purpose

This workspace holds the reverse-engineering effort for _Team Buddies_ alongside Unity prototypes used to validate findings. It captures tooling, scripts, and accumulated research artifacts required to rebuild game logic from the original PlayStation binaries.

## Pipeline at a Glance

1. **Data Capture** – Import PS1 binaries into the Ghidra project in `ghidra_proj/` using the bundled `ghidra_11.4.2_PUBLIC` distribution.
2. **Headless Analysis** – Generate headless jobs with `scripts/emit_ghidra_headless_commands.py` and execute them through `support/analyzeHeadless.bat`.
3. **Field Truth Tracing** – Run `ghidra_scripts/FieldTruthTracer.py` via the headless pipeline. Supply crate/slot metadata either through CLI arguments (preferred) or the `FT_*` environment variables.
4. **Research Notes & Datasets** – Store metric-heavy exports under `inventory/`, structured Markdown research in the repository root, and Unity-ready data in `unity_proto/` or `TeamBuddies/Assets/`.
5. **Reconstruction** – Translate verified routines into human-readable sources within `reconstructed_src/` and wire them up for testing in Unity.

The following diagram illustrates the flow:

```text
PS1 Binaries → Ghidra Project (TBProject) → Headless Analysis → FieldTruthTracer Logs
                                                    ↓
                                              Exports & Notes → Reconstructed Source → Unity Prototype
```

## Automation & Tooling

- `scripts/generate_workspace_inventory.py`: produces a CSV, Markdown, and optional JSON index covering **every file** in both the `tb-re` and Unity `TeamBuddies` workspaces.
- `scripts/emit_ghidra_headless_commands.py`: emits ready-to-run headless commands, inserting the required `--` separator and provisioning `FT_*` environment variables automatically.
- `scripts/build_call_map_index.py`: consolidates function evidence from vertical/secondary notes and mapping exports into a searchable index.
- `scripts/generate_field_truth_stubs.py`: turns FieldTruth log hits into starter translation units under `reconstructed_src/field_truth/`.
- `ghidra_scripts/`: Jython utilities for headless diagnostics (`FieldTruthTracer.py`, `ListLoaders.py`, `EchoArgs.py`).
- `.venv/`: Python environment housing dependencies for all automation scripts.

## Keeping the Inventory Fresh

The inventory lives under `inventory/` and is generated automatically. Regenerate it anytime after adding, removing, or restructuring files:

```powershell
.\.venv\Scripts\python.exe scripts\generate_workspace_inventory.py c:/Users/Acost/tb-re c:/Users/Acost/Desktop/Projects/game-dev/unity-repos/TeamBuddies --output-dir inventory --json
```

Outputs:

- `inventory/workspace_inventory.csv` – machine-readable manifest (path, type, size, description).
- `inventory/workspace_inventory.md` – human-readable snapshot with counts and per-entry descriptions.
- `inventory/workspace_inventory.json` – optional JSON mirror for downstream tooling.

## Reconstructed Source Code

Use `reconstructed_src/` to collect clean-room implementations of decompiled or traced behaviour. Organise by subsystem (e.g., `engine/`, `ai/`, `physics/`). Each file should document its origin (offset, tracer evidence) and dependencies back into the original binary. This directory is the canonical source for rebuilt modules destined for Unity or standalone tooling.

## Unity Prototype Workspace

The sibling `TeamBuddies/` project is a standard Unity project used to validate findings. Keep experimental behaviours under `Assets/ReverseEngineeringTB/`, and wire new reconstructed scripts from `reconstructed_src/` via C# shims when ready.

## Next Steps

- Prioritise function mapping: expand the existing `secondary_*` and `vertical_*` note sets into a consolidated call-map index that tracks offsets, callers, and inferred responsibilities.
- Tighten decompilation workflow: script the round-trip from `FieldTruthTracer` results into stubbed C-like pseudocode stored under `reconstructed_src/`, keeping Unity integration out of the critical path until translations are validated.
- Enrich trace evidence: link each reconstructed routine back to the relevant headless logs, binary offsets, and data tables so future automation can spot regressions or ambiguities quickly.
