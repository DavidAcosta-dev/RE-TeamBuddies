# Crate System: Final Mapping (names → addresses/roles)

- FUN_00035324 → crate_scheduler_install(context, slotPtr, cb_secondary=FUN_000240a0, cb_primary=FUN_00023f50)
- FUN_00023f50 → crate_stateframe_cb_primary (frame close/lightweight)
- FUN_000240a0 → crate_stateframe_cb_secondary (does work; drives FUN_00035cc0)
- FUN_00035cc0 → crate_anim_step (animation/effect advancement; ticked by secondary)
- FUN_00021424 → crate_pickup_start (writes +0x1c=0x1000, +0x20=0, +0x24=0, +0x14=6)
- FUN_00021cf0 → crate_throw_start (writes +0x1c=0, +0x20=0, +0x24=0xfffff000)
- FUN_00008528 → crate_base_idle_driver (schedules +0x38 with 240a0/23f50)
- FUN_000204e4 → crate_base_idle_install (schedules +0x38 with 24230/241f0)
- FUN_000235d4 → input_hub_main (dispatch 0x40 -> pickup via +0x3c; 0x10 -> throw via +0x40)
- FUN_00023534/00023544/00023588/0002391c → input_hub_helpers (mirror slot scheduling)

Slot roles:

- +0x38 → Base/Carry Idle
- +0x3c → Pickup pipeline
- +0x40 → Throw/Release pipeline

Confirmed callback pairs per slot:

- 0x38: (240a0,23f50), (24230,241f0)
- 0x3c: (240a0,23f50)
- 0x40: (240a0,23f50)

Notes: See crate_reference.md for counts, callers, and timing context.
