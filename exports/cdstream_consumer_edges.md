# Consumer candidate callers/callees


## MAIN.EXE:cdstream_alloc_and_init_queue (FUN_0001dd04) @ 0x1dd04

- Callers:

  - MAIN.EXE:cdstream_process_queue (FUN_000021d4)

  - MAIN.EXE:cdstream_register_callback2 (FUN_000028d8)

  - MAIN.EXE:FUN_00012c80 (FUN_00012c80)

  - MAIN.EXE:FUN_00015ab8 (FUN_00015ab8)

  - MAIN.EXE:FUN_00016780 (FUN_00016780)

  - MAIN.EXE:FUN_0001a0ec (FUN_0001a0ec)

- Callees:

  - MAIN.EXE:thunk_FUN_0001f5d4 (thunk_FUN_0001f5d4)


## MAIN.EXE:cdstream_noop (FUN_0001a100) @ 0x1a100

- Callers:

  - MAIN.EXE:cdstream_init_or_start (FUN_00002434)

  - MAIN.EXE:FUN_0000292c (FUN_0000292c)

  - MAIN.EXE:FUN_00002ab0 (FUN_00002ab0)

- Callees: (none)


## MAIN.EXE:cdstream_maybe_enqueue_pair (FUN_0001dd78) @ 0x1dd78

- Callers:

  - MAIN.EXE:cdstream_process_queue (FUN_000021d4)

  - MAIN.EXE:cdstream_init_or_start (FUN_00002434)

  - MAIN.EXE:cdstream_reset (FUN_000026f4)

- Callees:

  - MAIN.EXE:cdstream_setup_entry (FUN_0001a440)


## MAIN.EXE:cdstream_setup_entry (FUN_0001a440) @ 0x1a440

- Callers:

  - MAIN.EXE:FUN_00000edc (FUN_00000edc)

  - MAIN.EXE:FUN_0001a1c4 (FUN_0001a1c4)

  - MAIN.EXE:FUN_0001abfc (FUN_0001abfc)

  - MAIN.EXE:cdstream_maybe_enqueue_pair (FUN_0001dd78)

  - MAIN.EXE:FUN_0001de58 (FUN_0001de58)

- Callees: (none)


## MAIN.EXE:FUN_00030a98 (FUN_00030a98) @ 0x30a98

- Callers:

  - MAIN.EXE:cdstream_stage_payload (FUN_00019ec0)

- Callees: (none)
