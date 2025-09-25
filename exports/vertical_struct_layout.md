# Vertical Struct Layout (Provisional)

Reverse engineered from FUN_0001a320 (initializer), FUN_0001abfc (update), and related helpers.

| Offset | Size | Name (proposed)     | Type    | Observed Behavior |
|--------|------|---------------------|---------|-------------------|
| 0x30   | 4    | phaseCompleteFlag   | int     | Set to 1 on rollover (FUN_0001abfc) |
| 0x3c   | 4    | phaseToggleA        | int     | XOR 1 after emit (phase alternation) |
| 0x40   | 4    | phaseToggleB        | int     | XOR 1 after emit; used to index phase pair |
| 0x44   | 4    | mode                | int     | Initialized to 3; scales step & amplitude |
| 0x4c   | 2    | baseA               | short   | Lower bound for phase A (init 0) |
| 0x4e   | 2    | ???                 | short   | Zeroed at init; paired with extent? |
| 0x50   | 2    | extentA             | short   | Half of (mode * 0x140); amplitude A |
| 0x52   | 2    | ??extentMirrorA     | short   | Mirrors extent values (init 0xF0) |
| 0x54   | 2    | baseB               | short   | Zero at init (phase B base) |
| 0x56   | 2    | extentB             | short   | 0xF0 at init (placeholder amplitude B) |
| 0x58   | 2    | extentA_copy        | short   | Duplicate of extentA (init logic) |
| 0x5a   | 2    | extentA_copy2       | short   | Another duplicate (init logic) |
| 0x5c   | 2    | vertProgress        | short   | Accumulates by step; reset on rollover |
| 0x5e   | 2    | vertProgressPrev    | short   | Set to base on rollover (snapshot) |
| 0x60   | 2    | vertStep            | short   | (mode * 0x10)/2; used in progress increment |
| 0x62   | 2    | vertScale           | short   | 0xF0 (or environment supplied); multiplied with step for scaled emit |
| 0x88   | 4    | activationGate      | int     | Widely zeroed/reset; fast-path updater checks `(param_1+0x88)==0`; set to 1 in some init variants (FUN_0001ab7c/ab94) suggesting enable state |

## Update Logic Summary (FUN_0001abfc / fast-path variants)

1. progress += step
2. If progress < baseCurrent + extentCurrent: compute scaled = (step * scale) >> 1 and dispatch via FUN_0002d220, then flip an index (0x3c) selecting which slot feeds FUN_0001a440 next frame.
3. Else (progress reached/exceeded bound): phaseCompleteFlag = 1; reset progress & progressPrev to (phaseToggleB-dependent base pair); XOR phaseToggleB and phaseToggleA.

## Emitter & Gating Interaction

Current confirmed check: emitters gate on `*(short *)(secondary + 0x60)` >= 0 (vertStep non-negative). No direct read of vertProgress (0x5c) yet surfaced in scanners—pending broader search or manual review.

- Activation gate (+0x88) now evidenced as a general-purpose enable / context pointer slot: 168 references (see `vertical_offset_0x88_usage.md`). Core vertical path resets it to 0 in multiple helper stubs (FUN_0001a348/1a3b0/1a440) and tests for zero before performing fast-path emission (FUN_0001a528). Separate functions set it to 1 (FUN_0001ab7c/1ab94) indicating a state transition enabling alt behavior.
- Are there dynamic adjustments to vertScale (0x62) beyond initial 0xF0? FUN_0001a614 sets 0x62 to `*(short *)(param_1 + 0x2c)` in some path; no other scale writers found yet.

## Amplitude Field External Usage

`vertical_amplitude_consumers.md` surfaced >1800 references to offsets 0x50–0x5a & related bases (0x54 etc.) across many functions not in the core writer set. High density of reads at +0x50 and +0x54 used as short displacements added to pointers passed to function pointers at +0x54 (pattern: call through vtable-like slot at struct+0x54 with argument `base + *(short*)(struct+0x50)`). This suggests these pairs feed generalized dispatch or lookup (possibly animation frame, table index, or per-phase offset). Copies of extentA (0x58/0x5a) appear seldom mutated outside initializer implying cached amplitude for secondary consumers (maybe collision or visual effect layering). Pending tighter clustering to separate generic engine object layout reuse vs the vertical-specific secondary struct.

## Flag Usage Summary

`vertical_flag_usage_summary.md` indicates 125 functions referencing +0x24 (readiness) with heavy read-only usage (no external writers beyond known initializers and environment scanner). +0x8c remains much rarer; writes clustered in small init/teardown helpers and update variants; supports hypothesis: +0x8c is an override/activation bit toggled infrequently.

## Open Questions

- Are 0x4e / 0x52 distinct semantic roles (e.g., minClamp / visualExtent) vs mirrors? Need reads in other functions.
- Is vertProgress exported elsewhere for actual Y height or is height derived from another struct using these parameters?
- Distinguish which +0x50/+0x54 usage sites refer to this secondary vertical struct vs engine-global object layouts (risk of over-attribution due to structural overlap).
- Confirm if +0x88 ever holds a pointer (some writes use GP-relative constants) vs pure flag; need type discrimination (short vs int assignments present).

## Next Steps

- Address-literal & pointer-table scan to locate invocation sites for writers (indirect dispatch suspicion).
- Extend search for reads of +0x5c / +0x5e in unrelated functions to confirm height usage.
- Integrate refined vertical semantics into JS prototype once export relationship is confirmed.

*This document will be updated as additional linkage and read sites are confirmed.*
