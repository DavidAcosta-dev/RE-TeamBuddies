# Flag set/clear pattern analysis (+0x24 / +0x8c)

## Summary Counts

- 0x24 clear_0: 16
- 0x24 copy_from_struct: 4
- 0x24 other: 64
- 0x24 set_1: 4
- 0x8c clear_0: 16
- 0x8c copy_from_struct: 4
- 0x8c indirect_copy: 4
- 0x8c other: 4
- 0x8c set_1: 4

## Detailed Writes

| Function | EA | Line | Offset | Class | ValueExpr |
|----------|----|------|--------|-------|-----------|
| FUN_00028e58 | 0x28e58 | 17 | 0x8c | indirect_copy | `*(undefined4 *)(param_2 + 0x1c)` |
| FUN_0002e8f4 | 0x2e8f4 | 66 | 0x24 | clear_0 | `0` |
| FUN_0003339c | 0x3339c | 62 | 0x24 | clear_0 | `0` |
| FUN_000352ac | 0x352ac | 69 | 0x24 | other | `(undefined2)local_38` |
| FUN_00037d1c | 0x37d1c | 45 | 0x24 | other | `(undefined2)local_38` |
| FUN_0003a014 | 0x3a014 | 67 | 0x24 | other | `(undefined2)local_38` |
| FUN_0003ea40 | 0x3ea40 | 67 | 0x24 | other | `(undefined2)local_38` |
| FUN_00046024 | 0x46024 | 54 | 0x24 | clear_0 | `0` |
| FUN_00046024 | 0x46024 | 91 | 0x24 | other | `(undefined2)local_3c` |
| FUN_00046024 | 0x46024 | 115 | 0x24 | other | `(short)uVar5` |
| FUN_00008104 | 0x8104 | 53 | 0x24 | other | `local_14` |
| FUN_000082fc | 0x82fc | 54 | 0x24 | other | `local_14` |
| FUN_000082fc | 0x82fc | 63 | 0x24 | other | `local_14` |
| FUN_000011d0 | 0x11d0 | 59 | 0x24 | other | `local_14` |
| FUN_000011d0 | 0x11d0 | 76 | 0x24 | other | `local_14` |
| FUN_00003454 | 0x3454 | 74 | 0x24 | other | `local_14` |
| FUN_000080e8 | 0x80e8 | 14 | 0x8c | clear_0 | `0` |
| FUN_00008158 | 0x8158 | 38 | 0x8c | other | `iVar3` |
| FUN_000083ac | 0x83ac | 12 | 0x8c | clear_0 | `0` |
| FUN_00008528 | 0x8528 | 17 | 0x8c | clear_0 | `0` |
| FUN_00008528 | 0x8528 | 20 | 0x8c | copy_from_struct | `*(int *)(param_1 + 0x8c) + 1` |
| FUN_00008528 | 0x8528 | 90 | 0x8c | clear_0 | `0` |
| FUN_0000cd04 | 0xcd04 | 7 | 0x24 | other | `100` |
| FUN_0000d1c0 | 0xd1c0 | 8 | 0x24 | other | `param_2` |
| FUN_0001a320 | 0x1a320 | 48 | 0x24 | clear_0 | `0` |
| FUN_0001a320 | 0x1a320 | 56 | 0x8c | set_1 | `1` |
| FUN_0001a614 | 0x1a614 | 18 | 0x24 | set_1 | `1` |
| FUN_0001e1f4 | 0x1e1f4 | 13 | 0x24 | copy_from_struct | `*(undefined2 *)(param_1 + 0x20)` |
| FUN_0001e674 | 0x1e674 | 27 | 0x24 | other | `(short)in_v1` |
| FUN_000042f8 | 0x42f8 | 71 | 0x24 | other | `*(undefined2 *)(_DAT_800cedb0 + 0x26)` |
| FUN_00028e58 | 0x28e58 | 17 | 0x8c | indirect_copy | `*(undefined4 *)(param_2 + 0x1c)` |
| FUN_0002e8f4 | 0x2e8f4 | 66 | 0x24 | clear_0 | `0` |
| FUN_0003339c | 0x3339c | 62 | 0x24 | clear_0 | `0` |
| FUN_000352ac | 0x352ac | 69 | 0x24 | other | `(undefined2)local_38` |
| FUN_00037d1c | 0x37d1c | 45 | 0x24 | other | `(undefined2)local_38` |
| FUN_0003a014 | 0x3a014 | 67 | 0x24 | other | `(undefined2)local_38` |
| FUN_0003ea40 | 0x3ea40 | 67 | 0x24 | other | `(undefined2)local_38` |
| FUN_00046024 | 0x46024 | 54 | 0x24 | clear_0 | `0` |
| FUN_00046024 | 0x46024 | 91 | 0x24 | other | `(undefined2)local_3c` |
| FUN_00046024 | 0x46024 | 115 | 0x24 | other | `(short)uVar5` |
| FUN_00028e58 | 0x28e58 | 17 | 0x8c | indirect_copy | `*(undefined4 *)(param_2 + 0x1c)` |
| FUN_0002e8f4 | 0x2e8f4 | 66 | 0x24 | clear_0 | `0` |
| FUN_0003339c | 0x3339c | 62 | 0x24 | clear_0 | `0` |
| FUN_000352ac | 0x352ac | 69 | 0x24 | other | `(undefined2)local_38` |
| FUN_00037d1c | 0x37d1c | 45 | 0x24 | other | `(undefined2)local_38` |
| FUN_0003a014 | 0x3a014 | 67 | 0x24 | other | `(undefined2)local_38` |
| FUN_0003ea40 | 0x3ea40 | 67 | 0x24 | other | `(undefined2)local_38` |
| FUN_00046024 | 0x46024 | 54 | 0x24 | clear_0 | `0` |
| FUN_00046024 | 0x46024 | 91 | 0x24 | other | `(undefined2)local_3c` |
| FUN_00046024 | 0x46024 | 115 | 0x24 | other | `(short)uVar5` |
| FUN_00008104 | 0x8104 | 53 | 0x24 | other | `local_14` |
| FUN_000082fc | 0x82fc | 54 | 0x24 | other | `local_14` |
| FUN_000082fc | 0x82fc | 63 | 0x24 | other | `local_14` |
| FUN_000011d0 | 0x11d0 | 59 | 0x24 | other | `local_14` |
| FUN_000011d0 | 0x11d0 | 76 | 0x24 | other | `local_14` |
| FUN_00003454 | 0x3454 | 74 | 0x24 | other | `local_14` |
| FUN_000080e8 | 0x80e8 | 14 | 0x8c | clear_0 | `0` |
| FUN_00008158 | 0x8158 | 38 | 0x8c | other | `iVar3` |
| FUN_000083ac | 0x83ac | 12 | 0x8c | clear_0 | `0` |
| FUN_00008528 | 0x8528 | 17 | 0x8c | clear_0 | `0` |
| FUN_00008528 | 0x8528 | 20 | 0x8c | copy_from_struct | `*(int *)(param_1 + 0x8c) + 1` |
| FUN_00008528 | 0x8528 | 90 | 0x8c | clear_0 | `0` |
| FUN_0000cd04 | 0xcd04 | 7 | 0x24 | other | `100` |
| FUN_0000d1c0 | 0xd1c0 | 8 | 0x24 | other | `param_2` |
| FUN_0001a320 | 0x1a320 | 48 | 0x24 | clear_0 | `0` |
| FUN_0001a320 | 0x1a320 | 56 | 0x8c | set_1 | `1` |
| FUN_0001a614 | 0x1a614 | 18 | 0x24 | set_1 | `1` |
| FUN_0001e1f4 | 0x1e1f4 | 13 | 0x24 | copy_from_struct | `*(undefined2 *)(param_1 + 0x20)` |
| FUN_0001e674 | 0x1e674 | 27 | 0x24 | other | `(short)in_v1` |
| FUN_000042f8 | 0x42f8 | 71 | 0x24 | other | `*(undefined2 *)(_DAT_800cedb0 + 0x26)` |
| FUN_00028e58 | 0x28e58 | 17 | 0x8c | indirect_copy | `*(undefined4 *)(param_2 + 0x1c)` |
| FUN_0002e8f4 | 0x2e8f4 | 66 | 0x24 | clear_0 | `0` |
| FUN_0003339c | 0x3339c | 62 | 0x24 | clear_0 | `0` |
| FUN_000352ac | 0x352ac | 69 | 0x24 | other | `(undefined2)local_38` |
| FUN_00037d1c | 0x37d1c | 45 | 0x24 | other | `(undefined2)local_38` |
| FUN_0003a014 | 0x3a014 | 67 | 0x24 | other | `(undefined2)local_38` |
| FUN_0003ea40 | 0x3ea40 | 67 | 0x24 | other | `(undefined2)local_38` |
| FUN_00046024 | 0x46024 | 54 | 0x24 | clear_0 | `0` |
| FUN_00046024 | 0x46024 | 91 | 0x24 | other | `(undefined2)local_3c` |
| FUN_00046024 | 0x46024 | 115 | 0x24 | other | `(short)uVar5` |
| FUN_00008104 | 0x8104 | 53 | 0x24 | other | `local_14` |
| FUN_000082fc | 0x82fc | 54 | 0x24 | other | `local_14` |
| FUN_000082fc | 0x82fc | 63 | 0x24 | other | `local_14` |
| FUN_000011d0 | 0x11d0 | 59 | 0x24 | other | `local_14` |
| FUN_000011d0 | 0x11d0 | 76 | 0x24 | other | `local_14` |
| FUN_00003454 | 0x3454 | 74 | 0x24 | other | `local_14` |
| FUN_000080e8 | 0x80e8 | 14 | 0x8c | clear_0 | `0` |
| FUN_00008158 | 0x8158 | 38 | 0x8c | other | `iVar3` |
| FUN_000083ac | 0x83ac | 12 | 0x8c | clear_0 | `0` |
| FUN_00008528 | 0x8528 | 17 | 0x8c | clear_0 | `0` |
| FUN_00008528 | 0x8528 | 20 | 0x8c | copy_from_struct | `*(int *)(param_1 + 0x8c) + 1` |
| FUN_00008528 | 0x8528 | 90 | 0x8c | clear_0 | `0` |
| FUN_0000cd04 | 0xcd04 | 7 | 0x24 | other | `100` |
| FUN_0000d1c0 | 0xd1c0 | 8 | 0x24 | other | `param_2` |
| FUN_0001a320 | 0x1a320 | 48 | 0x24 | clear_0 | `0` |
| FUN_0001a320 | 0x1a320 | 56 | 0x8c | set_1 | `1` |
| FUN_0001a614 | 0x1a614 | 18 | 0x24 | set_1 | `1` |
| FUN_0001e1f4 | 0x1e1f4 | 13 | 0x24 | copy_from_struct | `*(undefined2 *)(param_1 + 0x20)` |
| FUN_0001e674 | 0x1e674 | 27 | 0x24 | other | `(short)in_v1` |
| FUN_000042f8 | 0x42f8 | 71 | 0x24 | other | `*(undefined2 *)(_DAT_800cedb0 + 0x26)` |
| FUN_00008104 | 0x8104 | 53 | 0x24 | other | `local_14` |
| FUN_000082fc | 0x82fc | 54 | 0x24 | other | `local_14` |
| FUN_000082fc | 0x82fc | 63 | 0x24 | other | `local_14` |
| FUN_000011d0 | 0x11d0 | 59 | 0x24 | other | `local_14` |
| FUN_000011d0 | 0x11d0 | 76 | 0x24 | other | `local_14` |
| FUN_00003454 | 0x3454 | 74 | 0x24 | other | `local_14` |
| FUN_000080e8 | 0x80e8 | 14 | 0x8c | clear_0 | `0` |
| FUN_00008158 | 0x8158 | 38 | 0x8c | other | `iVar3` |
| FUN_000083ac | 0x83ac | 12 | 0x8c | clear_0 | `0` |
| FUN_00008528 | 0x8528 | 17 | 0x8c | clear_0 | `0` |
| FUN_00008528 | 0x8528 | 20 | 0x8c | copy_from_struct | `*(int *)(param_1 + 0x8c) + 1` |
| FUN_00008528 | 0x8528 | 90 | 0x8c | clear_0 | `0` |
| FUN_0000cd04 | 0xcd04 | 7 | 0x24 | other | `100` |
| FUN_0000d1c0 | 0xd1c0 | 8 | 0x24 | other | `param_2` |
| FUN_0001a320 | 0x1a320 | 48 | 0x24 | clear_0 | `0` |
| FUN_0001a320 | 0x1a320 | 56 | 0x8c | set_1 | `1` |
| FUN_0001a614 | 0x1a614 | 18 | 0x24 | set_1 | `1` |
| FUN_0001e1f4 | 0x1e1f4 | 13 | 0x24 | copy_from_struct | `*(undefined2 *)(param_1 + 0x20)` |
| FUN_0001e674 | 0x1e674 | 27 | 0x24 | other | `(short)in_v1` |
| FUN_000042f8 | 0x42f8 | 71 | 0x24 | other | `*(undefined2 *)(_DAT_800cedb0 + 0x26)` |
