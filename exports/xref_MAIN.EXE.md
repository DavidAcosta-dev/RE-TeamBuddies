# XRef sheet for MAIN.EXE

### main_update @ 0x000090e0 | size=1104 | in=0 out=31 deg=31
- callees (31): FUN_0001caf0, phys_FUN_0001cbb8, sync_wait, stub_return_zero, update_state_dispatch, FUN_0001f610, suspect_FUN_0001fab8, FUN_000211ac, FUN_00021318, FUN_00021478, FUN_00021ef4, FUN_00022144, suspect_FUN_0002233c, FUN_00024b78, FUN_00031978, FUN_00031a48, FUN_00031c7c, FUN_00032278, FUN_00035324, FUN_00035360

### main_update @ 0x000090e0 | size=1104 | in=0 out=31 deg=31
- callees (31): FUN_0001caf0, phys_FUN_0001cbb8, sync_wait, stub_return_zero, update_state_dispatch, FUN_0001f610, suspect_FUN_0001fab8, FUN_000211ac, FUN_00021318, FUN_00021478, FUN_00021ef4, FUN_00022144, suspect_FUN_0002233c, FUN_00024b78, FUN_00031978, FUN_00031a48, FUN_00031c7c, FUN_00032278, FUN_00035324, FUN_00035360

### sync_wait @ 0x0001cc38 | size=12 | in=6 out=1 deg=7
- callers (6): main_update, phys_FUN_00021c64, FUN_00021ff4, FUN_00023d74, FUN_00023f50, FUN_000240a0
- callees (1): sync_wait

### sync_wait @ 0x0001cc38 | size=12 | in=6 out=1 deg=7
- callers (6): main_update, phys_FUN_00021c64, FUN_00021ff4, FUN_00023d74, FUN_00023f50, FUN_000240a0
- callees (1): sync_wait

### FUN_000211ac @ 0x000211ac | size=92 | in=2 out=2 deg=4
- callers (2): main_update, FUN_0002105c
- callees (2): suspect_FUN_00023390, FUN_00038414

### phys_FUN_00021c64 @ 0x00021c64 | size=108 | in=3 out=1 deg=4
- callers (3): suspect_input_update_gate, FUN_0000a5ec, FUN_0000a7d4
- callees (1): sync_wait

### FUN_00021ff4 @ 0x00021ff4 | size=296 | in=0 out=4 deg=4
- callees (4): sync_wait, FUN_00038674, FUN_00038b34, FUN_00038e94

### FUN_00023d74 @ 0x00023d74 | size=476 | in=0 out=5 deg=5
- callees (5): stub_ret0_FUN_0001a4a0, sync_wait, suspect_FUN_00035554, FUN_00035cc0, FUN_0003aad4

### FUN_00023f50 @ 0x00023f50 | size=336 | in=2 out=2 deg=4
- callers (2): suspect_FUN_00008ce4, FUN_0000c9f0
- callees (2): stub_ret0_FUN_0001a4a0, sync_wait

### FUN_000240a0 @ 0x000240a0 | size=260 | in=3 out=3 deg=6
- callers (3): stub_ret0_FUN_00008528, suspect_FUN_00008ce4, FUN_0000ca30
- callees (3): stub_ret0_FUN_0001a4a0, sync_wait, FUN_00035cc0

