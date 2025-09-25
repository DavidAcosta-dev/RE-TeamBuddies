# Crate State Machine (Reverse Engineered)

## Overview

Actor structure maintains three scheduler slot pointers:

- +0x38 : base/carry idle state (installed at init; scheduled first)
- +0x3c : pickup pipeline state (entered via input mask 0x40)
- +0x40 : throw/release pipeline state (entered via input mask 0x10)

Two paired per-frame callbacks passed to scheduler (FUN_00035324):

- crate_stateframe_cb_primary (FUN_00023f50): lightweight, generic per-frame gate/tick wrapper.
- crate_stateframe_cb_secondary (FUN_000240a0): same pair but also drives FUN_00035cc0 in multiple callsites (animation/effect advancement step). Confirmed in long-running visual setup routine FUN_0002273c.

Throw vs Pickup polarity field (+0x24):

- 0x1000 : neutral / init / pickup-in-progress.
- 0xfffff000 : throw initiated (crate_throw_start).

Other important fields:

- +0x14 : set to 6 by crate_pickup_start.
- +0x1c : set to 0x1000 in pickup, zeroed in throw.
- +0x20 : cleared in both pickup and throw start.

Global counters (gp-relative):

- -0x7dee : incremented on throw start; seeded to 1 in reset/init.
- -0x7de4 / -0x7dec : ancillary progression / flags (still pending deeper semantic labels).

## Transition Summary

```text
[Idle/Carry  (+0x38, +0x24=0x1000)]
   Input 0x40 (pickup) -> crate_pickup_start (FUN_00021424) -> schedule +0x3c (pickup state)
   Input 0x10 (throw)  -> crate_throw_start  (FUN_00021cf0) -> schedule +0x40 (throw state, +0x24=0xfffff000)

Pickup state (+0x3c): driven by cb pair (FUN_000240a0,FUN_00023f50). Hub/helper entry observed in FUN_000235d4/23534/23544/23588/2391c.
Throw state  (+0x40): driven by cb pair (FUN_000240a0,FUN_00023f50). Entry from hub/helpers on 0x10.
Both states return to base/carry state (+0x38) under their own completion conditions (timer/anim end), restoring +0x24=0x1000.
```

## Scheduler Call Contract (final)

FUN_00035324(context, stateSlotPtr, crate_stateframe_cb_secondary, crate_stateframe_cb_primary)

- context: actor root pointer (gp-based)
- stateSlotPtr: *(actor + offset) where offset is one of {0x38,0x3c,0x40}
- callbacks: paired frame functions executed per tick; secondary performs heavier work (including FUN_00035cc0), primary closes the frame.

## Final Names

- crate_scheduler_install: FUN_00035324
- crate_stateframe_cb_primary: FUN_00023f50
- crate_stateframe_cb_secondary: FUN_000240a0
- crate_pickup_start: FUN_00021424 (field writer; installed before +0x3c schedule)
- crate_throw_start:  FUN_00021cf0 (field writer; installed before +0x40 schedule)
- crate_base_idle_install: FUN_000204e4 (observed installing +0x38 with pair FUN_00024230/FUN_000241f0)
- crate_base_idle_driver:  FUN_00008528 (observed scheduling +0x38 with pair FUN_000240a0/FUN_00023f50)

Notes:

- The input hub FUN_000235d4 (and helpers FUN_00023534/23544/23588/2391c) dispatch 0x40 (pickup) via FUN_00021424 then schedule +0x3c, and dispatch 0x10 (throw) to schedule +0x40 (reaching FUN_00021cf0 via slot management at 0x0a464/0x0a6f4).
- FUN_00035cc0 is consistently used from secondary path in visual setup and tick code; labeled as crate_anim_step for future decomp passes.

## Open Questions / TODO

- Return conditions from +0x3c/+0x40 to +0x38 are implied by timing/anim completion; precise predicates can be annotated once label propagation is done in the cb_secondary path.

---
Generated automatically as part of reverse engineering documentation.
