# Input edge inspector for MAIN.EXE

## FUN_00010944 (FUN_00010944) @ 0x00010944 | score=12 | lvl=-1 | masks=0 | edges=3

- iVar5 = *(int *)(&DAT_80056fc0 + (_DAT_8005778c & 0xff) * 4) +
- ((int)((int)(short)_DAT_8005778c & 0xff00U) >> 8) * 0xb0;
- FUN_0002b080((int)DAT_8005777a - (int)DAT_80057788 & 0x3f);
- uVar6 = param_1 & 0xff;
- *(undefined2 *)((param_1 & 0xff) * 0x36 + -0x7ffa8f74) = 10;
- if ((_DAT_80042358 & 1 << (iVar4 >> 0x10 & 0x1fU)) == 0) {
- (&DAT_800570a5)[(param_1 & 0xff) * 0x36] = 2;
- uVar2 = (ushort)(1 << (uVar6 - 0x10 & 0x1f));
- _DAT_80057598 = _DAT_80057598 & ~_DAT_8005759a;
- _DAT_8005759c = _DAT_8005759c & ~_DAT_8005759e;
- _DAT_80057740 = _DAT_80057740 & ~uVar2;

## FUN_0000f85c (FUN_0000f85c) @ 0x0000f85c | score=11 | lvl=-1 | masks=1 | edges=2

- _DAT_80057044 = _DAT_80057044 + 1 & 0xf;
- *(uint *)(&DAT_80057048 + _DAT_80057044 * 4) | 1 << (uVar5 & 0x1f);
- uVar4 = 1 << (uVar6 & 0x1f);
- uVar1 = 1 << (uVar6 - 0x10 & 0x1f);
- FUN_0002b050(0,(uVar1 & 0xff) << 0x10 | (int)(short)uVar4);
- _DAT_8005759a = _DAT_8005759a & ~_DAT_80057598;
- _DAT_8005759e = _DAT_8005759e & ~_DAT_8005759c;
- local_68 = 1 << (uVar5 & 0x1f);
- if ((*pbVar9 & 0x10) != 0) {

## FUN_000132c0 (FUN_000132c0) @ 0x000132c0 | score=4 | lvl=-1 | masks=0 | edges=1

- if ((param_1 & ~_DAT_800424ec) != 0) {
- uVar2 = _DAT_800424e4 & 0x1f;
- uVar1 = _DAT_800424e4 & 0x1f;
- if ((*_DAT_8004257c & 0x40000000) != 0) {
- if (((*puVar4 & 0x40000000) != 0) ||
- (((*puVar4 & 0x80000000) != 0 && ((uint)(((int)param_1 >> uVar2) << uVar1) <= puVar4[1]))))

