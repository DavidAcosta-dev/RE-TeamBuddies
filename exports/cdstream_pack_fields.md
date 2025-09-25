# CD stream pack/header fields (heuristic)

Indices used on _DAT_80059e9c[...] across key functions (higher = more usage):

- index[2]: used 5x | roles: curr_sector_matches_counter:1, curr_equals_total_minus_1:1 | suggest: curr_sector_index
- index[3]: used 4x | roles: total_minus_1_equals_curr:1 | suggest: total_sectors
- index[4]: used 3x | roles: track_matches_state_3c:1, track_mismatch_state_30:1 | suggest: track_or_channel
- index[1]: used 1x | roles: sub_mode_bits_>>10&0x1f:1 | suggest: sub_mode_bits

## Evidence snippets

### index[0]

- header_magic present in MAIN.EXE:FUN_000197bc

### index[1]

- sub_mode compare present in MAIN.EXE:FUN_000197bc

### index[2]

- curr sector eq local counter in MAIN.EXE:FUN_000197bc
- curr vs total-1 present in MAIN.EXE:FUN_00019ec0

### index[3]

- total-1 vs curr present in MAIN.EXE:FUN_00019ec0

### index[4]

- track eq state_3c in MAIN.EXE:FUN_000197bc
- track ne expected state_30 in MAIN.EXE:FUN_000197bc

