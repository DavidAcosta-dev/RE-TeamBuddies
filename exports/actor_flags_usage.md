# Actor Flags (+0x26) Usage Report

Functions touching +0x26: 59

## Top Masks

| Mask | Count | Kind | Bits | PoT |
| --- | ---: | --- | --- | ---: |
| 0x26 | 64 | AND,OR,CMP | 1,2,5 | 0 |
| 0x0 | 32 | AND,CMP |  | 0 |
| 0x1 | 24 | AND,OR,CMP | 0 | 1 |
| 0x1F | 20 | AND,OR,CMP | 0,1,2,3,4 | 0 |
| 0x1A | 8 | AND,CMP | 1,3,4 | 0 |
| 0x20 | 8 | AND,CMP | 5 | 1 |
| 0x14 | 8 | AND,CMP | 2,4 | 0 |
| 0xD | 4 | CMP | 0,2,3 | 0 |
| 0xB8 | 4 | AND | 3,4,5,7 | 0 |
| 0xFFF | 4 | AND | 0,1,2,3,4,5,6,7,8,9,10,11 | 0 |
| 0x7FFEB162 | 4 | AND | 1,5,6,8,12,13,15 | 0 |
| 0x4 | 4 | AND | 2 | 1 |
| 0x7FFA8F60 | 4 | CMP | 5,6,8,9,10,11,15 | 0 |
| 0x10000 | 4 | CMP |  | 1 |
| 0x10 | 4 | CMP | 4 | 1 |

## Per-function usage (top 40)

| Function | EA | Bin | Ops | AND | OR | XOR | CMP | ~ | Sample |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| FUN_00000a64 | 0x000a64 | ROT.BIN | 48 | 16 | 16 | 0 | 16 | 0 | *(ushort *)(iVar2 + 0x26) = *(ushort *)(iVar2 + 0x26) | (ushort)(1 << ((int)sVar1 & 0x1fU)); |
| FUN_00046024 | 0x046024 | GAME.BIN | 32 | 16 | 0 | 0 | 16 | 0 | if ((*(short *)(param_1 + 0x1a) == 0) && (*(short *)(param_1 + 0x26) == 0)) { |
| FUN_0000cf48 | 0x00cf48 | MAIN.EXE | 32 | 16 | 0 | 0 | 16 | 0 | if ((*(char *)(param_1 + 0x20) != '\0') && (cVar1 = *(char *)(param_1 + 0x26), cVar1 != 0)) { |
| FUN_00000a30 | 0x000a30 | ROT.BIN | 32 | 16 | 0 | 0 | 16 | 0 | return (int)(uint)*(ushort *)(iVar1 + 0x26) >> (*(ushort *)(param_1 + 0x14) & 0x1f) & 1; |
| FUN_00044754 | 0x044754 | GAME.BIN | 20 | 20 | 0 | 0 | 0 | 0 | (int)*(short *)((*(ushort *)(*(int *)(param_1 + 0xb8) + 0x26) & 0xfff) * 4 + -0x7ffeb162)) { |
| FUN_00043348 | 0x043348 | GAME.BIN | 12 | 0 | 0 | 0 | 12 | 0 | piVar4[0xd] = (uint)(*(int *)(param_2 + 0x26) == 1); |
| FUN_00002160 | 0x002160 | MNU.BIN | 12 | 0 | 0 | 0 | 12 | 0 | iVar9 = (iVar9 + 0x26) * 0x10000 >> 0x10; |
| FUN_000114a4 | 0x0114a4 | MAIN.EXE | 8 | 0 | 0 | 0 | 8 | 0 | ((int)*(short *)(iVar1 + -0x7ffa8f60) == (int)*(char *)(iVar8 + 0x26))) { |
| FUN_00015064 | 0x015064 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_0001cbb4 | 0x01cbb4 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_00020284 | 0x020284 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 | *(undefined2 *)((int)puVar8 + iVar5 + 0x26) = 0x3c; |
| FUN_00025c18 | 0x025c18 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 | puVar6 = (ushort *)(param_1 + 0x26 + iVar4); |
| FUN_00025eb0 | 0x025eb0 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 | *psVar7 = *(short *)(param_1 + iVar4 + 0x26); |
| FUN_0002ffac | 0x02ffac | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 | *(short *)(iVar12 + 0x26) = (short)uVar9; |
| FUN_00032c18 | 0x032c18 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 | *(undefined2 *)(iVar2 + 0x18a) = *(undefined2 *)(param_2 + 0x26); |
| FUN_0003339c | 0x03339c | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_000337f0 | 0x0337f0 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_00033f50 | 0x033f50 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_00034a08 | 0x034a08 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_00034d8c | 0x034d8c | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_00035088 | 0x035088 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_000352ac | 0x0352ac | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 | *(short *)(param_1 + 0x26) = -(short)local_28; |
| FUN_000356ac | 0x0356ac | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_00036900 | 0x036900 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_00036c34 | 0x036c34 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_00037824 | 0x037824 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_00037d1c | 0x037d1c | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 | *(undefined2 *)(param_1 + 0x26) = local_28; |
| FUN_000384e0 | 0x0384e0 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_00038748 | 0x038748 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 | (int)(short)*(ushort *)(param_1 + 0x26) * |
| FUN_000390c8 | 0x0390c8 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_000396b4 | 0x0396b4 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_0003a014 | 0x03a014 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 | *(short *)(param_1 + 0x26) = -(short)local_28; |
| FUN_0003b8ac | 0x03b8ac | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_0003baf8 | 0x03baf8 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 | local_2c = *(ushort *)(param_1 + 0x26); |
| FUN_0003c74c | 0x03c74c | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_0003df28 | 0x03df28 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_0003e494 | 0x03e494 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_0003e4b4 | 0x03e4b4 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 |  |
| FUN_0003ea40 | 0x03ea40 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 | *(short *)(param_1 + 0x26) = -(short)local_28; |
| FUN_00042904 | 0x042904 | GAME.BIN | 0 | 0 | 0 | 0 | 0 | 0 | *(undefined2 *)(iVar6 + 0x26) = 1; |

## Suggested Flag Bits (draft)

- FLAG_BIT_00 = 0x0001
- FLAG_BIT_01 = 0x0020
- FLAG_BIT_02 = 0x0004
- FLAG_BIT_03 = 0x10000
- FLAG_BIT_04 = 0x0010
