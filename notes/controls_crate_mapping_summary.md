# Controls & Crate System Mapping (final)

Summary of finalized mappings around input hub and crate actions. See also exports/crate_final_mapping.md.

- input hub: FUN_000235d4 → input_decode_dispatch
  - mask 0x40: calls FUN_00021424 then schedules anim via +0x3c
    - FUN_00021424 → crate_pickup_start
      - writes: +0x1c=0x1000, +0x20=0, +0x24=0, +0x14=6
      - SFX/HUD: 0x24bbc/0x246d8
  - mask 0x10: schedules release via +0x40 (throw flow), with callbacks 0x800240a0/0x80023f50
  - mask 0x2: checked but does not schedule release here

- inverse state writers:
  - FUN_00021974 → crate_state_reset_init
    - writes: +0x1c=0, +0x20=0, +0x24=0x1000; clears +0x48/+0x4c/+0x50
    - seeds -0x7dee = 1; resets -0x7de4 = 0; integrates with small state machine at 0x21878/0x2193c
    - invoked in startup init (FUN_000099ac); not reached via +0x40 scheduling
  - FUN_00021cf0 → crate_throw_start
    - writes: +0x1c=0, +0x20=0, +0x24=0xfffff000; *(in_v0+0x34)=1
    - callers: FUN_0000a464, FUN_0000a6f4 (manage +0x40 slot array)
      - 0x0a464: iterate up to 8 slots; if slot present, FUN_00021870(slot,+0x40)=in_v0 → sets (slot+0x40) = in_v0
      - 0x0a6f4: if 21cf0 != 0 then allocate/add a slot; calls 216f8 (slot init: *slot+0x34=0) and 21708 (set +0x14 from (21cf0+0x10))

- input helpers: FUN_00023534, 00023544, 00023588
  - mirror hub logic; on 0x40 branch they also call 0x21424 and schedule via +0x3c; on 0x2/0x10 they schedule via +0x40

- animation scheduler: FUN_00035324(context, slotPtr, cb_secondary=FUN_000240a0, cb_primary=FUN_00023f50)
  - base idle uses +0x38; pickup uses +0x3c; release actions use +0x40
  - base idle installer: FUN_000204e4 may install (FUN_00024230,FUN_000241f0) pair into +0x38

Confirmed: mask 0x10 triggers the +0x40 release flow (throw), which reaches FUN_00021cf0 (crate_throw_start). Mask 0x2 is checked but does not schedule the +0x40 flow in the hub/helpers. FUN_00021974 is used for init/reset, not as a release entry.

Next validation steps:

- Verify whether any non-hub paths can schedule +0x40 (e.g., contextual actions) and whether they also land in crate_throw_start.
- Search for any SFX/HUD cues unique to throw to annotate 0x240a0/0x23f50 roles.
- If a distinct “drop” exists, identify its state writer; otherwise, treat “drop” as absence-of-throw within hub context.
