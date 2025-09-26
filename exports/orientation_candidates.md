# Orientation Candidate Functions

Detected 13 functions via trig mask / table heuristic.

- FUN_00001ad4
- FUN_00005c9c
- FUN_00007034
- FUN_00007420
- FUN_000145c8
- FUN_000209dc
- FUN_00022e5c
- FUN_00023000
- FUN_00023210
- FUN_0002cc00
- FUN_000402e0
- FUN_0004033c
- FUN_000475dc

## Priority Intersection (Integrator + Orientation)

The following candidates now register as both integrators and orientation routines in `exports/q12_overlay_report.md`; treat them as first-class renaming targets with Wipeout analogues (`SetUnitVectors` family):

- FUN_00022e5c — writes position and heading vectors; likely axis recompute helper.
- FUN_00023000 — sister routine with identical shift/normalize pattern; probable forward/right basis builder.
- FUN_00023210 — blended orientation + vertical alignment step; uses direct position writes with `>> 0xC` shifts.
