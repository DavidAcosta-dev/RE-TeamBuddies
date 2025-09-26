# Team Buddies Q12 Alignment Checklist

Generated: 2025-09-25

## Purpose

Track the high-scoring fixed-point (`>> 0xC` / `<< 0xC`) functions from `exports/q12_math_candidates.md` and map them to equivalent routines in the Wipeout PSX sources. Use this sheet to coordinate naming, struct reconstruction, and config tuning.

## Latest Overlay Snapshot

- `scripts/generate_q12_overlay_report.py` now emits `exports/q12_overlay_report.md`, combining the math candidates with integrator/orientation scans.
- Current counts: 3 functions overlap both integrator and orientation heuristics, 9 are integrator-only, 2 orientation-only, 52 remain uncategorised Q12 heavy.
- Use the overlay table to prioritize which symbols receive Wipeout-derived names and which need callgraph validation next.
- Integrator ∩ Orientation focus: FUN_00022e5c, FUN_00023000, and FUN_00023210—all direct position writers matching the Wipeout `SetUnitVectors` pattern.
- The 0x128–0x18C config band is now represented as `TbActorConfigBlock` (see `datatypes/tb_types.h`), so callgraph notes can reference named fields like `config.resistance_q12` directly.

## Top Candidates & Evidence

| Rank | TB Function | EA | Q12 Score | Observed Responsibilities | Wipeout Reference | Notes |
| --- | --- | --- | ---: | --- | --- | --- |
| 1 | FUN_00044f80 | 0x044f80 | 40 | Writes normalized vectors into `TbPhysicsState` (+0x34/+0x3A), scales by shared magnitude `iVar12` with `>> 0xC`. | `SetUnitVectors` (DYNAM.C) | Examine callers around 0x044a14 to confirm paired heading/pitch recalculation; rename to `tbPhysicsRebuildBasis` once proven. |
| 2 | FUN_00032c18 | 0x032c18 | 36 | Massive actor init routine: masks angles to 0x0FFF, copies Q12 vectors into slots 0x134+, computes `(height * invMag) >> 0xC`. | `shipTrkReaction` setup + `ShipData` priming | Align offsets with `TbPhysicsIntegratorConfig` (new fields) to solidify struct layout. |
| 3 | FUN_0001e750 | 0x01e750 | 24 | Integrates velocity into position with repetitive `>> 0xC`, applies conditional damping. | `shipTrkReaction` grounded branch | Compare constants against `gravity_q12`, `track_magnet_q12`, `resistance_q12` to ensure config controls map cleanly. |
| 4 | FUN_0001e7b4 | 0x01e7b4 | 24 | Companion routine to 0x01e750, appears to handle airborne step (absence of magnet writes). | `shipTrkReaction` airborne branch | Verify flag transitions around `TbPhysicsState.flags` to capture FLYING semantics. |
| 5 | FUN_00044a14 | 0x044a14 | 24 | Produces normalization factor fed into 0x044f80; heavy Q12 multiply/shift pattern. | `SetUnitVectors` precursor | Tag as `tbPhysicsComputeBasisMagnitude` once basis chain is mapped. |

## Config Field Mapping

| Config Field | Default (hypothesis) | Wipeout Analogue | Next Validation Step |
| --- | --- | --- | --- |
| `gravity_q12` | `TB_Q12(-24.0f)` | `GRAVITY` in `DYNAM.C` | Cross-check with vertical integrator constants to confirm sign. |
| `drag_shift` | 1 | velocity damp shift | Trace uses around FUN_000029f8 to confirm bit-shift semantics. |
| `track_magnet_q12` | TBD | `TRACK_MAGNET` | Search for literal `0x11a` or similar magnet constants in candidate functions. |
| `resistance_q12` | TBD | `ShipData.resistance` | Compare writes in 0x032c18 to struct fields updated by Wipeout’s ship setup. |
| `skid_friction_q12` | TBD | `ShipData.skid` | Inspect lateral-velocity dampers (likely 0x046024/0x0475dc) for usage. |

## Action Items

1. **Callgraph tagging**: Annotate FUN_00044a14 → FUN_00044f80 → FUN_0001e750 chain in Ghidra with Wipeout-equivalent names.
2. **Struct sketch**: Expand the provisional `TbActorState` diagram to include offsets 0x128–0x16C populated by FUN_00032c18.
3. **Config tuning tests**: Once `tbPhysicsGetConfig` implementation is stubbed, run scripted experiments adjusting `track_magnet_q12` and `resistance_q12` to confirm behavioural impact.
4. **Trig wrappers**: Group FUN_0001f5a8/0x1f5d4 cluster under a shared trig utility module referencing Wipeout’s `rsin/rcos` macros.
5. **Documentation sync**: Update `orientation_candidates.md` with findings after callgraph inspection.

Keep this checklist in sync with future `scripts/find_q12_math_patterns.py` runs—if new bundles surface, append additional rows with evidence and cross-links.
