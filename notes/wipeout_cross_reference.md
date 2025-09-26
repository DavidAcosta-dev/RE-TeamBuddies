# Wipeout PSX → Team Buddies Cross-Reference

Generated: 2025-09-25

## 1. High-Level Overview

The `assets/WIPESRC/Wipeout PSX/` sources are a complete PSYQ-era racing engine. Many runtime patterns match what we observe in Team Buddies disassemblies:

- Fixed-point math everywhere (Q12) and the standard `rsin/rcos` trig helpers.
- Struct-driven world graph (`TrackSection`) and actors (`ShipData`) with function pointer updates.
- Input, physics, and combat subsystems compiled into modular update routines.

This note captures direct parallels that can accelerate naming and tooling for Team Buddies.

## 2. Physics & Motion Parallels

| Wipeout Symbol | File | Key Behaviour | Team Buddies Clue |
| --- | --- | --- | --- |
| `shipTrkReaction` | `DYNAM.C` | Integrates thrust along `unitVecNose`, snaps to track plane, handles FLYING vs grounded states, applies `TRACK_MAGNET` and drag. | TB integrator around FUN_000029f8—uses same Q12 arithmetic, drag logic, and plane collision constants. Names like `TbPhysicsIntegrateBody` map cleanly. |
| `SetUnitVectors` | `DYNAM.C` | Recomputes `unitVecNose`/`unitVecWing` from `hdg/pitch/roll` using `rsin/rcos`, updates section membership. | TB orientation helpers likely mirror formulas. Use to verify signs when building `tbPhysicsOrientationToForward`. |
| `GetTargetPos`, `PlaneLineCollision`, `GetMag/Ang` | `DYNAM.C` + math helpers | Plane intersection, angle sums, magnitude. | Search TB binaries for similar math signature to label shared utility functions. |
| `ShipData` fields (`vpivot`, `apivot`, `resistance`, `skid`) | `ships.h` | Provide tunable drag, acceleration, and braking. | TB’s physics state probably has near-identical layout—key for struct reconstruction. |

### Immediate Physics Actions

- Cross-check TB’s suspected drag constants against `TRACK_MAGNET`, `TARGETHEIGHT`, and `resistance` ranges from Wipeout.
- Locate TB routines performing `sar(v, 6)` (velocity to position) to anchor physics integration naming.
- Use Wipeout’s `FLYING` transition logic as template when documenting TB crate toss or airborne states.
- Mine Ghidra exports with `scripts/find_q12_math_patterns.py` to prioritize functions showing heavy `>> 0xc` / `sar()` usage.
- Mirror Wipeout tuning knobs directly: `TbPhysicsIntegratorConfig` now exposes `track_magnet_q12`, `resistance_q12`, and `skid_friction_q12` alongside `gravity_q12`/`drag_shift` for rapid experimentation.
- Review `exports/q12_overlay_report.md` after each scan to see which candidates intersect both integrator and orientation heuristics.

### Q12 Candidate Alignment

| TB Function | EA | Q12 Score | Wipeout Analogue | Rationale | Next Step |
| --- | --- | --- | --- | --- | --- |
| `FUN_00044f80` | 0x044f80 | 40 | `SetUnitVectors` | Normalizes orientation basis with repeated `>> 0xC` writes into +0x34/+0x3A, mirroring Wipeout’s forward/right recompute. | Confirm caller writes to TbPhysicsState orientation fields; label as `tbPhysicsRebuildBasis` once validated. |
| `FUN_00032c18` | 0x032c18 | 36 | `ShipInitFromGrid` + `shipTrkReaction` preload | Massive struct copy with pervasive Q12 shifts; populates height, drag, and magnet fields akin to `ShipData` initialization. | Map offsets to `TbActorState` prototype to nail down config structure. |
| `FUN_0001e750` | 0x01e750 | 24 | `shipTrkReaction` (grounded step) | Performs chained `>>0xC` position updates and velocity damping; lives near existing integrator suspects. | Compare callgraph with `TbPhysicsIntegrateBody`; verify gravity constant usage. |
| `FUN_00022dc8`/`FUN_00022e5c` | 0x022dc8 / 0x022e5c | 12 | `SetUnitVectors` helpers | Both emit paired position `>>0xC` shifts; already flagged by integrator scans as orientation updates. | Merge with orientation candidate list; annotate in Ghidra as axis recompute. |
| `FUN_00023210` | 0x023210 | 8 | `SetUnitVectors` vertical align step | Direct position writes with `>>0xC` on stick-derived deltas; matches Wipeout’s blended orientation/altitude adjust. | Treat as overlay “intersection” proof—rename alongside 22e5c/23000. |
| `FUN_0001f5a8` cluster | 0x01f5a8–0x01f610 | 12 | `rsin`/`rcos` wrappers | Exclusive `<<0xC` usage matches Wipeout trig pipelines. | Cross-link to `orientation_candidates.md` and tag as trig table loaders. |

## 3. Control/Input & Ship Update Pipeline

- `UpdateShips`/`UpdateShipsSerial` iterate over `ShipData[]` and call the `update` function pointer—matching TB’s entity update slots.
- `UpdatePlayerShipNorm` manages pad input, throttle ramp `(thrust_mag += FR15U+1)`, steering via `vhdg`, and special statuses (`ELECTROED`, `REVCONNED`). Identical frame constants (`FR10`, `FR40`, etc.) pop up in TB control code.
- Start sequence functions (`GeneralStartProcs`, `UpdatePlayerShip*Start`) show countdown timers and camera triggers—useful for labelling TB’s mission intro logic.

**Action**: When TB disassembly shows per-frame increments of ~0x101 or pad bitmasks, copy Wipeout’s naming (e.g., `THRUST_INCREMENT`, `headingInc`) to maintain consistency.

## 4. Track & World Graph Insights

- `TrackSection` stores `centre`, `prevSection`, `nextSection`, optional `junction`, radii, face lists, and view lists. Flags (`Jump`, `Junction*`, `SPEED_UP`) drive gameplay.
- `Ship2Track` plus magnetism ensures alignment with `TRACK_BASE` faces; the code toggles `LSIDE` attribute depending on the normal.

These structures echo the mission/sector graphs suspected in Team Buddies overlays. If we identify a TB struct with a `centre` vector and adjacency pointers, we can confidently name it a `TbPathSection` using Wipeout conventions.

## 5. Weapons & Combat Hooks

- `WeaponData` struct plus `LaunchWeapon`, `UpdateRocket`, etc., rely on durations like `ROCKET_DURATION (20*FR10)`. TB uses similar timers for grenades/crates.
- `WeaponGrid` ties track sections to pickup availability, tinting faces. In TB, crate spawn pads probably use the same attribute pattern.

**Action**: align TB’s weapon timers with these macros to double-check unit conversions; use names `weaponGrid`, `LaunchWeapon` when labelling call sites.

## 6. Rendering & Skeleton System

- `object.h` enumerates primitive types (`F3`, `FT4`, `GT4`, etc.) and includes `Skeleton` (hierarchical transforms). TB’s rendering code likely retained the same primitive structs even if reorganized.
- Global arrays (`TextureTable`, `PrimitiveBuffer0/1`, `OT`) expose memory layout; spotting these patterns in TB dumps can speed up data segment annotation.

## 7. Shared Constants & Utility Conventions

- Angles: 4096 == 360°, `ang()` normalizes. Use this to justify naming TB’s normalization function.
- Fixed-point: velocity shifts by `VELOCITY_SHIFT (6)` for position integration; force scaling uses `>>12` multiplies.
- Frame-time macros: `FR60`, `FR50`, `FR30` for PAL/NTSC differences. Team Buddies uses `FR50` heavily—values match.

## 8. Naming & Label Suggestions for Team Buddies

| TB Feature | Proposed Name (from Wipeout) | Rationale |
| --- | --- | --- |
| 0x29f8 integrator | `tbPhysicsIntegrateBody` | Same responsibilities as `shipTrkReaction`’s grounded branch. |
| Forward-vector helper | `tbPhysicsOrientationToForward` | Mirrors `SetUnitVectors` formulas. |
| Actor state flags | `TB_ACTOR_FLAG_FLYING`, `TB_ACTOR_FLAG_RACING`, etc. | Reuse Wipeout flag semantics where matches observed bit usage. |
| Per-entity update pointer | `update` or `updateControl` field in struct | Wipeout pattern demonstrates pointer-based state machine. |
| Timer macros | `TB_FR10`, `TB_FR40` | Mirror Wipeout macros to clarify conversions. |

## 9. Follow-up Work

1. **Math primitive parity**: locate TB functions whose call graphs match `PlaneLineCollision`, `GetTargetPos`, `GetAng` to accelerate symbol renaming.
2. **Struct alignment**: provisional `TbActorState` + `TbActorConfigBlock` now live in `datatypes/tb_types.h`; next up is mapping the leading 0x128 bytes and validating offsets against MAIN.EXE callsites.
3. **Physics tuning**: extend `TbPhysicsIntegratorConfig` with `track_magnet`, `resistance`, `skid` to support scriptable tweaks during RE experiments.
4. **AI/Rescue behaviour**: inspect TB code for `UpdateRescueDroid`-like fallbacks (function pointer swap + counter) to understand failure recovery.
5. **Weapon timers**: correlate TB durations with `FR10/FR40` macros to standardize naming of timed events.

---
Use this note as the base reference when mapping Team Buddies fragments to named functions. If we dive deeper into other subdirectories (e.g., `combat.c`, `camera.c`), append sections here to keep the cross-project knowledge in one place.
