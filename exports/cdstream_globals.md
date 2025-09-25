# CD stream globals and suggestions

Functions scanned:
- MAIN.EXE:cdstream_device_pump (FUN_000197bc)
- MAIN.EXE:cdstream_stage_payload (FUN_00019ec0)
- MAIN.EXE:cdstream_register_callback2 (FUN_000028d8)
- MAIN.EXE:cdstream_reset (FUN_000026f4)
- MAIN.EXE:cdstream_process_queue (FUN_000021d4)
- MAIN.EXE:cdstream_poll_idle (FUN_00002584)
- MAIN.EXE:cdstream_init_or_start (FUN_00002434)
- MAIN.EXE:cdstream_memcpy_sector (FUN_000199d4)

## Global usage counts (overall)

- _DAT_80059e9c => used 152x | suggest: cds_hdr_9c
- _DAT_80057a1c => used 152x | suggest: cds_state_1c
- _DAT_80057a18 => used 108x | suggest: cds_state_18
- _DAT_80057a20 => used 76x | suggest: cds_state_20
- _DAT_80057a10 => used 60x | suggest: cds_state_10
- _DAT_8003cc58 => used 56x | suggest: cds_gbl_58
- _DAT_80053b08 => used 52x | suggest: cds_hw_08
- _DAT_80057a40 => used 48x | suggest: cds_state_40
- _DAT_8003cb9c => used 36x | suggest: cds_gbl_9c
- _DAT_8003cc54 => used 36x | suggest: cds_gbl_54
- _DAT_8003cb90 => used 36x | suggest: cds_gbl_90
- _DAT_80057a08 => used 36x | suggest: cds_state_08
- _DAT_80057a3c => used 36x | suggest: cds_state_3c
- _DAT_80057a24 => used 32x | suggest: cds_state_24
- _DAT_80053af0 => used 32x | suggest: cds_hw_f0
- _DAT_80053af4 => used 32x | suggest: cds_hw_f4
- _DAT_80057a38 => used 32x | suggest: cds_state_38
- _DAT_8003cbac => used 24x | suggest: cds_gbl_ac
- _DAT_80059e98 => used 24x | suggest: cds_hdr_98
- _DAT_80057a2c => used 20x | suggest: cds_state_2c
- _DAT_8003cbb8 => used 16x | suggest: cds_gbl_b8
- _DAT_80057a14 => used 16x | suggest: cds_state_14
- _DAT_80057a4c => used 16x | suggest: cds_state_4c
- _DAT_80057a34 => used 16x | suggest: cds_state_34
- _DAT_8003cbe0 => used 12x | suggest: cds_gbl_e0
- _DAT_80057a0c => used 12x | suggest: cds_state_0c
- _DAT_80057a48 => used 12x | suggest: cds_state_48
- _DAT_8003cbc0 => used 12x | suggest: cds_gbl_c0
- _DAT_8003cbb4 => used 8x | suggest: cds_gbl_b4
- _DAT_8003cbdc => used 8x | suggest: cds_gbl_dc
- _DAT_80053ae4 => used 8x | suggest: cds_hw_e4
- _DAT_80053aec => used 8x | suggest: cds_hw_ec
- _DAT_80053b04 => used 8x | suggest: cds_hw_04
- _DAT_80057a30 => used 8x | suggest: cds_state_30
- _DAT_8003cbbc => used 4x | suggest: cds_gbl_bc
- _DAT_8003cb94 => used 4x | suggest: cds_gbl_94
- _DAT_80053b00 => used 4x | suggest: cds_hw_00
- _DAT_80057a44 => used 4x | suggest: cds_state_44
- _DAT_80057a80 => used 4x | suggest: cds_state_80
- _DAT_80053ae8 => used 4x | suggest: cds_hw_e8

## Per-function usage

### MAIN.EXE:cdstream_device_pump (FUN_000197bc)

- _DAT_80059e9c: 108
- _DAT_80057a1c: 88
- _DAT_80057a18: 60
- _DAT_80057a20: 44
- _DAT_80053b08: 36
- _DAT_80057a40: 28
- _DAT_80057a3c: 28
- _DAT_80057a24: 28
- _DAT_80057a08: 20
- _DAT_80057a10: 20
- _DAT_80053af0: 16
- _DAT_80053af4: 16
- _DAT_80057a2c: 16
- _DAT_80059e98: 16
- _DAT_80057a38: 12
- _DAT_80057a34: 12
- _DAT_80057a14: 8
- _DAT_80053ae4: 8
- _DAT_80053aec: 8
- _DAT_80053b04: 8
- _DAT_80057a30: 8
- _DAT_80057a4c: 8
- _DAT_80057a0c: 8
- _DAT_80053b00: 4
- _DAT_80057a44: 4
- _DAT_80057a80: 4
- _DAT_80053ae8: 4
- _DAT_80057a48: 4

### MAIN.EXE:cdstream_stage_payload (FUN_00019ec0)

- _DAT_80057a1c: 24
- _DAT_80057a10: 20
- _DAT_80057a18: 20
- _DAT_80059e9c: 12
- _DAT_80057a40: 8
- _DAT_80053af0: 8
- _DAT_80053af4: 8
- _DAT_80057a38: 8
- _DAT_80057a20: 8
- _DAT_80057a14: 4
- _DAT_80057a3c: 4
- _DAT_80057a4c: 4
- _DAT_80057a48: 4

### MAIN.EXE:cdstream_register_callback2 (FUN_000028d8)


### MAIN.EXE:cdstream_reset (FUN_000026f4)

- _DAT_8003cbc0: 12
- _DAT_8003cb90: 12
- _DAT_8003cc54: 8
- _DAT_8003cc58: 8
- _DAT_8003cb9c: 8
- _DAT_8003cbb8: 8
- _DAT_8003cbac: 8
- _DAT_8003cbbc: 4
- _DAT_8003cb94: 4

### MAIN.EXE:cdstream_process_queue (FUN_000021d4)

- _DAT_8003cc58: 40
- _DAT_8003cc54: 20
- _DAT_8003cb9c: 16
- _DAT_8003cbe0: 12
- _DAT_8003cbb4: 8
- _DAT_8003cb90: 8
- _DAT_8003cbdc: 8

### MAIN.EXE:cdstream_poll_idle (FUN_00002584)

- _DAT_80053b08: 4
- _DAT_8003cc54: 4
- _DAT_8003cc58: 4
- _DAT_8003cb9c: 4
- _DAT_8003cb90: 4

### MAIN.EXE:cdstream_init_or_start (FUN_00002434)

- _DAT_80057a1c: 40
- _DAT_80059e9c: 28
- _DAT_80057a18: 28
- _DAT_80057a20: 24
- _DAT_80057a10: 20
- _DAT_8003cbac: 16
- _DAT_80057a08: 16
- _DAT_8003cb90: 12
- _DAT_80053b08: 12
- _DAT_80057a40: 12
- _DAT_80057a38: 12
- _DAT_8003cbb8: 8
- _DAT_8003cb9c: 8
- _DAT_80053af0: 8
- _DAT_80053af4: 8
- _DAT_80059e98: 8
- _DAT_8003cc58: 4
- _DAT_8003cc54: 4
- _DAT_80057a24: 4
- _DAT_80057a0c: 4
- _DAT_80057a14: 4
- _DAT_80057a3c: 4
- _DAT_80057a4c: 4
- _DAT_80057a48: 4
- _DAT_80057a34: 4
- _DAT_80057a2c: 4

### MAIN.EXE:cdstream_memcpy_sector (FUN_000199d4)

- _DAT_80059e9c: 4

