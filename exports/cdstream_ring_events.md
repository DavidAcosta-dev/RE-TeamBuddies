# CD stream ring events (heuristic)

## MAIN.EXE:cdstream_init_or_start (FUN_00002434)

- Detected events: cmd_1323, cmd_1325, cmd_word_a, cmd_word_c, flag_final, hdr_skip, idx_inc, payload_1f8, reset_3c, reset_40, sector_800
- Callees: cdstream_advance_and_dispatch2, cdstream_noop, FUN_0001dd78

## MAIN.EXE:cdstream_process_queue (FUN_000021d4)

- Callees: FUN_0001dd04, FUN_0001dd78

## MAIN.EXE:cdstream_poll_idle (FUN_00002584)

- Callees: cdstream_memcpy_sector, cdstream_stage_payload

## MAIN.EXE:cdstream_reset (FUN_000026f4)

- Detected events: sector_800
- Callees: cdstream_advance_and_dispatch, FUN_0001cc58, update_state_dispatch, FUN_0001dd78

## MAIN.EXE:cdstream_register_callback2 (FUN_000028d8)

- Callees: FUN_0001dd04

## MAIN.EXE:cdstream_device_pump (FUN_000197bc)

- Detected events: cmd_1323, cmd_1325, cmd_word_a, cmd_word_b, cmd_word_c, flag_final, hdr_skip, header_magic, idx_inc, payload_1f8, reset_3c, reset_40, sector_800, subhdr_filter
- Callees: cd_poll_ready, cd_ring_rewind, cd_reset_ptrs, thunk_FUN_00040020

## MAIN.EXE:cdstream_stage_payload (FUN_00019ec0)

- Detected events: cmd_1323, cmd_1325, cmd_word_a, flag_final, hdr_skip, idx_inc, payload_1f8, reset_3c, reset_40, sector_800
- Callees: FUN_00030a98, cd_dma_copy_partial, cd_cmd_finalize_b, cd_cmd_dispatch, thunk_FUN_00040020

## MAIN.EXE:cdstream_memcpy_sector (FUN_000199d4)

- Detected events: sector_800
- Callees: cd_dma_copy_partial

## MAIN.EXE:cdstream_advance_and_dispatch (FUN_0001a028)

- Detected events: hdr_skip, idx_inc

## MAIN.EXE:cdstream_advance_and_dispatch2 (FUN_0001a038)

- Callees: cd_cmd_dispatch

