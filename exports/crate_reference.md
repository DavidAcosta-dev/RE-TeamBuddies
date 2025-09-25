# Crate Interaction Reference

Derived from candidate edges, input/action masks, and coarse timing constants. Intended for quick navigation and naming pass.

## Confirmed Entry Points

<!-- BEGIN: confirmed-entry-points -->

- crate_pickup_start: FUN_00021424 (writes +0x1c=0x1000, +0x20=0, +0x24=0, +0x14=6)
- crate_throw_start:  FUN_00021cf0 (writes +0x1c=0, +0x20=0, +0x24=0xfffff000)
- scheduler install:  FUN_00035324(context, slotPtr, cb_secondary=FUN_000240a0, cb_primary=FUN_00023f50)
- base idle installer: FUN_000204e4 → schedules +0x38 with pair FUN_00024230/FUN_000241f0 in some contexts

<!-- END: confirmed-entry-points -->

## Pickup Handlers (0x40 / slot 0x3c)

| Candidate | Pad | Slots | SchedLike | Callers | Callees |
|-----------|-----|-------|-----------|---------|---------|
| FUN_000235d4 |  | 0x3c,0x40 |  | FUN_00002f34,FUN_0001a804,FUN_000235d4 | FUN_0001cc58,FUN_00021424,FUN_000235d4,FUN_000246d8,FUN_00024bbc,FUN_00035324 |
| FUN_00023588 | 0x10,0x40 | 0x3c,0x40 |  | FUN_00009708,FUN_00023588 | FUN_0001cc58,FUN_00021424,FUN_00023588,FUN_000246d8,FUN_00024bbc,FUN_00035324 |
| FUN_00008528 |  | 0x38,0x3c | FUN_00035324 | FUN_00008528 | FUN_00008528,FUN_0001cba8,FUN_0001cc58,FUN_0001f5d4,FUN_00020484,FUN_000204e4 |
| FUN_00009708 |  | 0x38,0x3c,0x40 |  | FUN_00009708 | FUN_00009708,FUN_0001cc58,FUN_0001cc68,FUN_0001d600,FUN_0001f5e8,FUN_00021c64 |
| FUN_000171fc |  | 0x3c |  | FUN_000171fc | FUN_000171fc,FUN_0001cb60,FUN_0001cc58,FUN_0001d600,FUN_0001dd68,FUN_0002e148 |
| FUN_000090e0 |  | 0x38,0x3c,0x40 | FUN_00032278,FUN_00035324 | FUN_000090e0 | FUN_000090e0,FUN_0001caf0,FUN_0001cbb8,FUN_0001cc38,FUN_0001cc58,FUN_0001d600 |
| FUN_0001a348 |  | 0x38,0x3c,0x40 |  | FUN_00002f34,FUN_0001a348,FUN_0001a804 | FUN_0001a348,FUN_0001f5e8 |
| FUN_0002391c |  | 0x3c | FUN_00035324 | FUN_000080a0,FUN_0001f734,FUN_00022234,FUN_0002391c | FUN_0002391c,FUN_000246d8,FUN_00035324 |

## Throw Handlers (0x10 / slot 0x40)

| Candidate | Pad | Slots | SchedLike | Callers | Callees |
|-----------|-----|-------|-----------|---------|---------|
| FUN_000235d4 |  | 0x3c,0x40 |  | FUN_00002f34,FUN_0001a804,FUN_000235d4 | FUN_0001cc58,FUN_00021424,FUN_000235d4,FUN_000246d8,FUN_00024bbc,FUN_00035324 |
| FUN_0001a804 |  | 0x40 | FUN_0002245c | FUN_0001a804 | FUN_00018878,FUN_0001a348,FUN_0001a734,FUN_0001a804,FUN_0001d600,FUN_0002245c |
| FUN_00023588 | 0x10,0x40 | 0x3c,0x40 |  | FUN_00009708,FUN_00023588 | FUN_0001cc58,FUN_00021424,FUN_00023588,FUN_000246d8,FUN_00024bbc,FUN_00035324 |
| FUN_00009708 |  | 0x38,0x3c,0x40 |  | FUN_00009708 | FUN_00009708,FUN_0001cc58,FUN_0001cc68,FUN_0001d600,FUN_0001f5e8,FUN_00021c64 |
| FUN_000090e0 |  | 0x38,0x3c,0x40 | FUN_00032278,FUN_00035324 | FUN_000090e0 | FUN_000090e0,FUN_0001caf0,FUN_0001cbb8,FUN_0001cc38,FUN_0001cc58,FUN_0001d600 |
| FUN_0001a348 |  | 0x38,0x3c,0x40 |  | FUN_00002f34,FUN_0001a348,FUN_0001a804 | FUN_0001a348,FUN_0001f5e8 |


## Timing Constants (coarse, top)

_Timing list not available_

## Scheduler Callback Summary

### Slot 0x38
Top callback pairs:
- crate_stateframe_cb_secondary , crate_stateframe_cb_primary  (x6)
- base_idle_alt_cb_secondary , base_idle_alt_cb_primary  (x6)
- ? , ?  (x3)
Top callers:
- crate_base_idle_driver (x6)
- crate_base_idle_install (x6)
- FUN_000090e0 (x3)

### Slot 0x3c
Top callback pairs:
- crate_stateframe_cb_secondary , crate_stateframe_cb_primary  (x15)
Top callers:
- input_hub_helper_a (x3)
- input_hub_helper_b (x3)
- input_hub_helper_c (x3)
- input_hub_main (x3)
- input_hub_helper_pickup (x3)

### Slot 0x40
Top callback pairs:
- crate_stateframe_cb_secondary , crate_stateframe_cb_primary  (x12)
Top callers:
- input_hub_helper_a (x3)
- input_hub_helper_b (x3)
- input_hub_helper_c (x3)
- input_hub_main (x3)

### Slot (unspecified)
Top callback pairs:
- ? , ?  (x6)
Top callers:
- crate_base_idle_driver (x3)
- crate_scheduler_install (x3)
## Crate: Return-to-Base Predicates

### Primary (cb2 param)

| callback | branch | predicate | evidence |
|---|---|---|---|
| crate_stateframe_cb_primary | if-true | unaff_s5 != 0 | base slot write |
## Crate: Implicit Return Installs

### Pair: crate_stateframe_cb_secondary , crate_stateframe_cb_primary  (x6)
- crate_base_idle_driver (x6)

### Pair: base_idle_alt_cb_secondary , base_idle_alt_cb_primary  (x6)
- crate_base_idle_install (x6)

### Pair: ? , ?  (x3)
- FUN_000090e0 (x3)
## Crate: Base Return Drivers

### crate_base_idle_driver  (x6)
- Pair: crate_stateframe_cb_secondary , crate_stateframe_cb_primary  (x6)
- Predicates: (none found)

### crate_base_idle_install  (x6)
- Pair: base_idle_alt_cb_secondary , base_idle_alt_cb_primary  (x6)
- Predicates: param_2 == 0

### FUN_000090e0  (x3)
- Pair: ? , ?  (x3)
- Predicates: iVar4 != 0
## Crate: Return Linkages (cb → base)

- crate_stateframe_cb_primary ← crate_base_idle_driver (depth 0)
  - predicates: (none found)
- crate_stateframe_cb_secondary ← crate_base_idle_driver (depth 0)
  - predicates: (none found)
- base_idle_alt_cb_primary ← crate_base_idle_install (depth 0)
  - predicates: param_2 == 0
- base_idle_alt_cb_secondary ← crate_base_idle_install (depth 0)
  - predicates: param_2 == 0
## Crate: Automation Coverage Summary

- explicit return predicates: 1
- cb → base linkages: 4
