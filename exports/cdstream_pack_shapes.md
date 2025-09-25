# CD stream pack shapes (heuristic order of events)


## MAIN.EXE:cdstream_device_pump (FUN_000197bc) @ 0x197bc

- Sequence: INC_SECTOR -> POLL_READY -> DMA_1F8 -> SECTOR_800 -> CMD_ISSUE -> HDR_MAGIC -> SUBHDR_FILTER -> RING_REWIND -> FINAL_A -> HDR_SKIP_20 -> DISPATCH -> FINAL_B -> RESET_PTRS


## MAIN.EXE:cdstream_stage_payload (FUN_00019ec0) @ 0x19ec0

- Sequence: FINAL_A -> PACK_END_CHECK -> DMA_1F8 -> SECTOR_800 -> HDR_SKIP_20 -> INC_SECTOR -> FINAL_B -> CMD_ISSUE -> DISPATCH


## MAIN.EXE:cdstream_init_or_start (FUN_00002434) @ 0x2434

- Sequence: SECTOR_800 -> FINAL_A -> CMD_ISSUE -> DMA_1F8 -> HDR_SKIP_20 -> INC_SECTOR -> DISPATCH -> FINAL_B


## MAIN.EXE:cdstream_reset (FUN_000026f4) @ 0x26f4

- Sequence: SECTOR_800


## MAIN.EXE:cdstream_poll_idle (FUN_00002584) @ 0x2584

- Sequence: (no markers found)


## MAIN.EXE:cdstream_advance_and_dispatch (FUN_0001a028) @ 0x1a028

- Sequence: INC_SECTOR -> DISPATCH -> HDR_SKIP_20


## MAIN.EXE:cdstream_advance_and_dispatch2 (FUN_0001a038) @ 0x1a038

- Sequence: DISPATCH
