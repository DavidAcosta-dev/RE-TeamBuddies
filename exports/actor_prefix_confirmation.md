# TbActorPrefix Offset Confirmation

Functions checked: FUN_00022dc8, FUN_00022e5c, FUN_00023000, FUN_00023110, FUN_00023180, FUN_00023210, FUN_00032c18, FUN_00044a14, FUN_00044f80

| Function | 0x08 | 0x0C | 0x10 | 0x20 | 0x22 | 0x24 | 0x26 | 0x34 | 0x36 | 0x38 | 0x3A | 0x3C | 0x3E | 0x40 | 0x44 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FUN_00022dc8 | 0 | 40 | 0 | 4 | 0 | 4 | 0 | 12 | 8 | 12 | 0 | 0 | 0 | 0 | 0 |
| FUN_00022e5c | 0 | 44 | 4 | 0 | 0 | 0 | 0 | 12 | 8 | 12 | 0 | 0 | 0 | 0 | 0 |
| FUN_00023000 | 0 | 32 | 0 | 0 | 0 | 0 | 0 | 12 | 8 | 12 | 0 | 0 | 0 | 0 | 0 |
| FUN_00023110 | 0 | 32 | 0 | 0 | 0 | 0 | 0 | 4 | 4 | 8 | 0 | 0 | 0 | 0 | 0 |
| FUN_00023180 | 0 | 24 | 8 | 0 | 0 | 0 | 0 | 4 | 0 | 4 | 0 | 0 | 0 | 0 | 0 |
| FUN_00023210 | 0 | 16 | 4 | 0 | 0 | 0 | 0 | 4 | 0 | 4 | 0 | 0 | 0 | 0 | 0 |
| FUN_00032c18 | 0 | 0 | 4 | 0 | 4 | 4 | 4 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| FUN_00044a14 | 0 | 12 | 0 | 12 | 0 | 0 | 0 | 24 | 44 | 24 | 0 | 8 | 8 | 8 | 28 |
| FUN_00044f80 | 0 | 12 | 8 | 16 | 0 | 0 | 0 | 8 | 8 | 8 | 0 | 44 | 32 | 28 | 32 |

Notes:
- Position updates should show 0x08/0x0C/0x10 usage in integrators.
- Basis recompute/normalize should show 0x3C/0x3E/0x40 (source) and 0x34/0x36/0x38 (dest).
- Speed reads/writes expected at 0x44 in basis-related functions.
