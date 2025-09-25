# Logic map for MAIN.EXE

Seed: main_update (FUN_000090e0)

## Per-frame pipeline

- input: ~0 nodes
- update: ~47 nodes (depth<=2)
- physics: ~1 nodes
- render: ~0 nodes
- audio: ~0 nodes
- vsync: ~2 nodes

## Key nodes

- main_update @ 0x000090e0 | size=1104 | in=0 out=31 | tags=[] | lvl=0
- FUN_0001caf0 @ 0x0001caf0 | size=12 | in=1 out=0 | tags=[] | lvl=1
- phys_FUN_0001cbb8 @ 0x0001cbb8 | size=32 | in=2 out=1 | tags=[physics] | lvl=1
- sync_wait @ 0x0001cc38 | size=12 | in=6 out=1 | tags=[vsync] | lvl=1
- stub_return_zero @ 0x0001cc58 | size=16 | in=51 out=0 | tags=[] | lvl=1
- update_state_dispatch @ 0x0001d600 | size=284 | in=18 out=2 | tags=[] | lvl=1
- FUN_0001f610 @ 0x0001f610 | size=144 | in=3 out=1 | tags=[] | lvl=1
- render_tick @ 0x0001fab8 | size=764 | in=1 out=8 | tags=[] | lvl=1
- FUN_000211ac @ 0x000211ac | size=92 | in=2 out=2 | tags=[] | lvl=1
- FUN_00021318 @ 0x00021318 | size=28 | in=1 out=0 | tags=[] | lvl=1
- FUN_00021478 @ 0x00021478 | size=36 | in=1 out=1 | tags=[] | lvl=1
- FUN_00021ef4 @ 0x00021ef4 | size=112 | in=1 out=1 | tags=[] | lvl=1
- FUN_00022144 @ 0x00022144 | size=240 | in=2 out=1 | tags=[] | lvl=1
- suspect_FUN_0002233c @ 0x0002233c | size=252 | in=4 out=3 | tags=[] | lvl=1
- FUN_00024b78 @ 0x00024b78 | size=4 | in=1 out=0 | tags=[] | lvl=1
- FUN_00031978 @ 0x00031978 | size=20 | in=2 out=0 | tags=[] | lvl=1
- FUN_00031a48 @ 0x00031a48 | size=1 | in=1 out=0 | tags=[] | lvl=1
- FUN_00031c7c @ 0x00031c7c | size=12 | in=2 out=0 | tags=[] | lvl=1
- FUN_00032278 @ 0x00032278 | size=200 | in=2 out=0 | tags=[] | lvl=1
- FUN_00035324 @ 0x00035324 | size=1 | in=5 out=0 | tags=[] | lvl=1
- FUN_00035360 @ 0x00035360 | size=4 | in=6 out=0 | tags=[] | lvl=1
- FUN_00035464 @ 0x00035464 | size=1 | in=6 out=0 | tags=[] | lvl=1
- FUN_000354f0 @ 0x000354f0 | size=4 | in=2 out=0 | tags=[] | lvl=1
- suspect_FUN_00035554 @ 0x00035554 | size=1 | in=13 out=0 | tags=[] | lvl=1
- FUN_000356b4 @ 0x000356b4 | size=1 | in=2 out=0 | tags=[] | lvl=1
- FUN_00035800 @ 0x00035800 | size=4 | in=3 out=0 | tags=[] | lvl=1
- FUN_00035914 @ 0x00035914 | size=1 | in=2 out=0 | tags=[] | lvl=1
- FUN_00036754 @ 0x00036754 | size=1 | in=1 out=0 | tags=[] | lvl=1
- FUN_00036f34 @ 0x00036f34 | size=1 | in=1 out=0 | tags=[] | lvl=1
- FUN_00039a34 @ 0x00039a34 | size=4 | in=1 out=0 | tags=[] | lvl=1
- alloc_mem_thunk @ 0x0001f5c0 | size=8 | in=32 out=0 | tags=[] | lvl=1
- thunk_FUN_00034460 @ 0x0001cc48 | size=8 | in=1 out=0 | tags=[] | lvl=1
- sync_wait @ 0x00034460 | size=4 | in=2 out=0 | tags=[vsync] | lvl=2
- suspect_action_handler_01_lvl1 @ 0x00034f08 | size=4 | in=1 out=0 | tags=[] | lvl=2
- suspect_action_handler_02_lvl1 @ 0x00034f40 | size=4 | in=1 out=0 | tags=[] | lvl=2
- FUN_00036d5c @ 0x00036d5c | size=1 | in=1 out=0 | tags=[] | lvl=2
- stub_ret0_FUN_0001c7fc @ 0x0001c7fc | size=64 | in=5 out=1 | tags=[] | lvl=2
- stub_ret0_FUN_0001c83c @ 0x0001c83c | size=32 | in=2 out=3 | tags=[] | lvl=2
- FUN_00021fd4 @ 0x00021fd4 | size=32 | in=5 out=0 | tags=[] | lvl=2
- FUN_00035858 @ 0x00035858 | size=4 | in=2 out=0 | tags=[] | lvl=2
- FUN_00035884 @ 0x00035884 | size=1 | in=2 out=0 | tags=[] | lvl=2
- suspect_FUN_00023390 @ 0x00023390 | size=16 | in=9 out=1 | tags=[] | lvl=2
- FUN_00038414 @ 0x00038414 | size=1 | in=2 out=0 | tags=[] | lvl=2
- FUN_00038674 @ 0x00038674 | size=4 | in=5 out=0 | tags=[] | lvl=2
- FUN_00038b34 @ 0x00038b34 | size=1 | in=2 out=0 | tags=[] | lvl=2
- FUN_0003591c @ 0x0003591c | size=1 | in=3 out=0 | tags=[] | lvl=2
- FUN_00039c38 @ 0x00039c38 | size=1 | in=3 out=0 | tags=[] | lvl=2

## Edges (level<2)

- main_update -> FUN_0001caf0 [FUN_000090e0 -> FUN_0001caf0]
- main_update -> phys_FUN_0001cbb8 [FUN_000090e0 -> FUN_0001cbb8]
- main_update -> sync_wait [FUN_000090e0 -> FUN_0001cc38]
- main_update -> stub_return_zero [FUN_000090e0 -> FUN_0001cc58]
- main_update -> update_state_dispatch [FUN_000090e0 -> FUN_0001d600]
- main_update -> FUN_0001f610 [FUN_000090e0 -> FUN_0001f610]
- main_update -> render_tick [FUN_000090e0 -> FUN_0001fab8]
- main_update -> FUN_000211ac [FUN_000090e0 -> FUN_000211ac]
- main_update -> FUN_00021318 [FUN_000090e0 -> FUN_00021318]
- main_update -> FUN_00021478 [FUN_000090e0 -> FUN_00021478]
- main_update -> FUN_00021ef4 [FUN_000090e0 -> FUN_00021ef4]
- main_update -> FUN_00022144 [FUN_000090e0 -> FUN_00022144]
- main_update -> suspect_FUN_0002233c [FUN_000090e0 -> FUN_0002233c]
- main_update -> FUN_00024b78 [FUN_000090e0 -> FUN_00024b78]
- main_update -> FUN_00031978 [FUN_000090e0 -> FUN_00031978]
- main_update -> FUN_00031a48 [FUN_000090e0 -> FUN_00031a48]
- main_update -> FUN_00031c7c [FUN_000090e0 -> FUN_00031c7c]
- main_update -> FUN_00032278 [FUN_000090e0 -> FUN_00032278]
- main_update -> FUN_00035324 [FUN_000090e0 -> FUN_00035324]
- main_update -> FUN_00035360 [FUN_000090e0 -> FUN_00035360]
- main_update -> FUN_00035464 [FUN_000090e0 -> FUN_00035464]
- main_update -> FUN_000354f0 [FUN_000090e0 -> FUN_000354f0]
- main_update -> suspect_FUN_00035554 [FUN_000090e0 -> FUN_00035554]
- main_update -> FUN_000356b4 [FUN_000090e0 -> FUN_000356b4]
- main_update -> FUN_00035800 [FUN_000090e0 -> FUN_00035800]
- main_update -> FUN_00035914 [FUN_000090e0 -> FUN_00035914]
- main_update -> FUN_00036754 [FUN_000090e0 -> FUN_00036754]
- main_update -> FUN_00036f34 [FUN_000090e0 -> FUN_00036f34]
- main_update -> FUN_00039a34 [FUN_000090e0 -> FUN_00039a34]
- main_update -> alloc_mem_thunk [FUN_000090e0 -> thunk_FUN_0001f5d4]
- main_update -> thunk_FUN_00034460 [FUN_000090e0 -> thunk_FUN_00034460]
- phys_FUN_0001cbb8 -> sync_wait [FUN_0001cbb8 -> FUN_00034460]
- sync_wait -> sync_wait [FUN_0001cc38 -> FUN_00034460]
- update_state_dispatch -> suspect_action_handler_01_lvl1 [FUN_0001d600 -> FUN_00034f08]
- update_state_dispatch -> suspect_action_handler_02_lvl1 [FUN_0001d600 -> FUN_00034f40]
- FUN_0001f610 -> FUN_00036d5c [FUN_0001f610 -> FUN_00036d5c]
- render_tick -> stub_ret0_FUN_0001c7fc [FUN_0001fab8 -> FUN_0001c7fc]
- render_tick -> stub_ret0_FUN_0001c83c [FUN_0001fab8 -> FUN_0001c83c]
- render_tick -> FUN_00021fd4 [FUN_0001fab8 -> FUN_00021fd4]
- render_tick -> FUN_00035360 [FUN_0001fab8 -> FUN_00035360]
- render_tick -> FUN_00035464 [FUN_0001fab8 -> FUN_00035464]
- render_tick -> FUN_00035858 [FUN_0001fab8 -> FUN_00035858]
- render_tick -> FUN_00035884 [FUN_0001fab8 -> FUN_00035884]
- render_tick -> alloc_mem_thunk [FUN_0001fab8 -> thunk_FUN_0001f5d4]
- FUN_000211ac -> suspect_FUN_00023390 [FUN_000211ac -> FUN_00023390]
- FUN_000211ac -> FUN_00038414 [FUN_000211ac -> FUN_00038414]
- FUN_00021478 -> suspect_FUN_00023390 [FUN_00021478 -> FUN_00023390]
- FUN_00021ef4 -> FUN_00038674 [FUN_00021ef4 -> FUN_00038674]
- FUN_00022144 -> FUN_00038b34 [FUN_00022144 -> FUN_00038b34]
- suspect_FUN_0002233c -> FUN_0003591c [FUN_0002233c -> FUN_0003591c]
- suspect_FUN_0002233c -> FUN_00039c38 [FUN_0002233c -> FUN_00039c38]
- suspect_FUN_0002233c -> alloc_mem_thunk [FUN_0002233c -> thunk_FUN_0001f5d4]
