# Snippets for LEGGIT.EXE

## 1. phys_FUN_000145c8 @ 0x000145c8  tags:physics  score:36

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Removing unreachable block (ram,0x00014740) */
/* WARNING: Removing unreachable block (ram,0x00014754) */
/* WARNING: Removing unreachable block (ram,0x0001475c) */
/* WARNING: Removing unreachable block (ram,0x00014764) */
/* WARNING: Removing unreachable block (ram,0x00014820) */
/* WARNING: Removing unreachable block (ram,0x00014834) */
/* WARNING: Removing unreachable block (ram,0x0001483c) */
/* WARNING: Removing unreachable block (ram,0x00014844) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_000145c8(uint *param_1)

{
  bool bVar1;
  undefined2 uVar2;
  uint uVar3;
  int iVar4;
  ushort uVar5;
  ushort uVar6;
  uint uVar7;
  uint uVar8;
  ushort *puVar9;
  
  uVar8 = 0;
  uVar7 = param_1[1];
  puVar9 = (ushort *)&DAT_80038f3c;
  bVar1 = uVar7 == 0;
  do {
    if ((*param_1 & 1 << (uVar8 & 0x1f)) != 0) {
      if ((bVar1) || ((uVar7 & 0x10) != 0)) {
        *(short *)(uVar8 * 0x10 + _DAT_80038dd0 + 4) = (short)param_1[5];
      }
      if ((bVar1) || ((uVar7 & 0x40) != 0)) {
        *puVar9 = (ushort)param_1[6];
      }
      if ((bVar1) || ((uVar7 & 0x20) != 0)) {
        uVar2 = func_0x000348f4(*puVar9 >> 8,*puVar9 & 0xff,*(ushort *)((int)param_1 + 0x16) >> 8,
                                *(ushort *)((int)param_1 + 0x16) & 0xff);
        *(undefined2 *)(uVar8 * 0x10 + _DAT_80038dd0 + 4) = uVar2;
      }
      if ((bVar1) || ((uVar7 & 1) != 0)) {
        if (((bVar1) || ((uVar7 & 4) != 0)) &&
           (uVar3 = (int)(((ushort)param_1[3] - 1) * 0x10000) >> 0x10, uVar3 < 7)) {
                    /* WARNING: Could not emulate address calculation at 0x000146f4 */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)(uVar3 * 4 + -0x7ffde948))();
          return;
        }
        *(ushort *)(uVar8 * 0x10 + _DAT_80038dd0) = (ushort)param_1[2] & 0x7fff;
      }
      if ((bVar1) || ((uVar7 & 2) != 0)) {
        if (((bVar1) || ((uVar7 & 8) != 0)) &&
           (uVar3 = (int)((*(ushort *)((int)param_1 + 0xe) - 1) * 0x10000) >> 0x10, uVar3 < 7)) {
                    /* WARNING: Could not emulate address calculation at 0x000147d4 */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)(uVar3 * 4 + -0x7ffde928))();
          return;
        }
        *(ushort *)(uVar8 * 0x10 + _DAT_80038dd0 + 2) = *(ushort *)((int)param_1 + 10) & 0x7fff;
      }
      if ((bVar1) || ((uVar7 & 0x80) != 0)) {
        func_0x0002f9b4(uVar8 << 3 | 3,param_1[7]);
      }
      if ((bVar1) || ((uVar7 & 0x10000) != 0)) {
        func_0x0002f9b4(uVar8 << 3 | 7,param_1[8]);
      }
      if ((bVar1) || ((uVar7 & 0x20000) != 0)) {
        *(undefined2 *)(uVar8 * 0x10 + _DAT_80038dd0 + 8) = *(undefined2 *)((int)param_1 + 0x3a);
      }
      if ((bVar1) || ((uVar7 & 0x40000) != 0)) {
        *(short *)(uVar8 * 0x10 + _DAT_80038dd0 + 10) = (short)param_1[0xf];
      }
      if ((bVar1) || ((uVar7 & 0x800) != 0)) {
        uVar5 = (ushort)param_1[0xc];
        if (0x7f < uVar5) {
          uVar5 = 0x7f;
        }
        uVar6 = 0;
        if (((bVar1) || ((uVar7 & 0x100) != 0)) && (param_1[9] == 5)) {
          uVar6 = 0x80;
        }
        iVar4 = uVar8 * 0x10 + _DAT_80038dd0;
        *(ushort *)(iVar4 + 8) = *(ushort *)(iVar4 + 8) & 0xff | (uVar5 | uVar6) << 8;
      }
      if ((bVar1) || ((uVar7 & 0x1000) != 0)) {
        uVar5 = *(ushort *)((int)param_1 + 0x32);
        if (0xf < uVar5) {
          uVar5 = 0xf;
        }
        iVar4 = uVar8 * 0x10 + _DAT_80038dd0;
        *(ushort *)(iVar4 + 8) = *(ushort *)(iVar4 + 8) & 0xff0f | uVar5 << 4;
      }
      if ((bVar1) || ((uVar7 & 0x2000) != 0)) {
        uVar5 = (ushort)param_1[0xd];
        if (0x7f < uVar5) {
          uVar5 = 0x7f;
        }
        uVar6 = 0x100;
        if ((bVar1) || ((uVar7 & 0x200) != 0)) {
          uVar3 = param_1[10];
          if ((uVar3 == 5) || (((int)uVar3 < 6 || (uVar3 != 7)))) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          uVar6 = 0x300;
        }
        iVar4 = uVar8 * 0x10 + _DAT_80038dd0;
        *(ushort *)(iVar4 + 10) = *(ushort *)(iVar4 + 10) & 0x3f | (uVar5 | uVar6) << 6;
      }
      if ((bVar1) || ((uVar7 & 0x4000) != 0)) {
        uVar5 = *(ushort *)((int)param_1 + 0x36);
        if (0x1f < uVar5) {
          uVar5 = 0x1f;
        }
        uVar6 = 0;
        if ((((bVar1) || ((uVar7 & 0x400) != 0)) && (param_1[0xb] != 3)) && (param_1[0xb] == 7)) {
          uVar6 = 0x20;
        }
        iVar4 = uVar8 * 0x10 + _DAT_80038dd0;
        *(ushort *)(iVar4 + 10) = *(ushort *)(iVar4 + 10) & 0xffc0 | uVar5 | uVar6;
      }
      if ((bVar1) || ((uVar7 & 0x8000) != 0)) {
        uVar5 = (ushort)param_1[0xe];
        if (0xf < uVar5) {
          uVar5 = 0xf;
        }
        iVar4 = uVar8 * 0x10 + _DAT_80038dd0;
        *(ushort *)(iVar4 + 8) = *(ushort *)(iVar4 + 8) & 0xfff0 | uVar5;
      }
    }
    uVar8 = uVar8 + 1;
    puVar9 = puVar9 + 1;
    if (0x17 < (int)uVar8) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  } while( true );
}


```

## 2. phys_FUN_000145c8 @ 0x000145c8  tags:physics  score:36

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Removing unreachable block (ram,0x00014740) */
/* WARNING: Removing unreachable block (ram,0x00014754) */
/* WARNING: Removing unreachable block (ram,0x0001475c) */
/* WARNING: Removing unreachable block (ram,0x00014764) */
/* WARNING: Removing unreachable block (ram,0x00014820) */
/* WARNING: Removing unreachable block (ram,0x00014834) */
/* WARNING: Removing unreachable block (ram,0x0001483c) */
/* WARNING: Removing unreachable block (ram,0x00014844) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_000145c8(uint *param_1)

{
  bool bVar1;
  undefined2 uVar2;
  uint uVar3;
  int iVar4;
  ushort uVar5;
  ushort uVar6;
  uint uVar7;
  uint uVar8;
  ushort *puVar9;
  
  uVar8 = 0;
  uVar7 = param_1[1];
  puVar9 = (ushort *)&DAT_80038f3c;
  bVar1 = uVar7 == 0;
  do {
    if ((*param_1 & 1 << (uVar8 & 0x1f)) != 0) {
      if ((bVar1) || ((uVar7 & 0x10) != 0)) {
        *(short *)(uVar8 * 0x10 + _DAT_80038dd0 + 4) = (short)param_1[5];
      }
      if ((bVar1) || ((uVar7 & 0x40) != 0)) {
        *puVar9 = (ushort)param_1[6];
      }
      if ((bVar1) || ((uVar7 & 0x20) != 0)) {
        uVar2 = func_0x000348f4(*puVar9 >> 8,*puVar9 & 0xff,*(ushort *)((int)param_1 + 0x16) >> 8,
                                *(ushort *)((int)param_1 + 0x16) & 0xff);
        *(undefined2 *)(uVar8 * 0x10 + _DAT_80038dd0 + 4) = uVar2;
      }
      if ((bVar1) || ((uVar7 & 1) != 0)) {
        if (((bVar1) || ((uVar7 & 4) != 0)) &&
           (uVar3 = (int)(((ushort)param_1[3] - 1) * 0x10000) >> 0x10, uVar3 < 7)) {
                    /* WARNING: Could not emulate address calculation at 0x000146f4 */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)(uVar3 * 4 + -0x7ffde948))();
          return;
        }
        *(ushort *)(uVar8 * 0x10 + _DAT_80038dd0) = (ushort)param_1[2] & 0x7fff;
      }
      if ((bVar1) || ((uVar7 & 2) != 0)) {
        if (((bVar1) || ((uVar7 & 8) != 0)) &&
           (uVar3 = (int)((*(ushort *)((int)param_1 + 0xe) - 1) * 0x10000) >> 0x10, uVar3 < 7)) {
                    /* WARNING: Could not emulate address calculation at 0x000147d4 */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)(uVar3 * 4 + -0x7ffde928))();
          return;
        }
        *(ushort *)(uVar8 * 0x10 + _DAT_80038dd0 + 2) = *(ushort *)((int)param_1 + 10) & 0x7fff;
      }
      if ((bVar1) || ((uVar7 & 0x80) != 0)) {
        func_0x0002f9b4(uVar8 << 3 | 3,param_1[7]);
      }
      if ((bVar1) || ((uVar7 & 0x10000) != 0)) {
        func_0x0002f9b4(uVar8 << 3 | 7,param_1[8]);
      }
      if ((bVar1) || ((uVar7 & 0x20000) != 0)) {
        *(undefined2 *)(uVar8 * 0x10 + _DAT_80038dd0 + 8) = *(undefined2 *)((int)param_1 + 0x3a);
      }
      if ((bVar1) || ((uVar7 & 0x40000) != 0)) {
        *(short *)(uVar8 * 0x10 + _DAT_80038dd0 + 10) = (short)param_1[0xf];
      }
      if ((bVar1) || ((uVar7 & 0x800) != 0)) {
        uVar5 = (ushort)param_1[0xc];
        if (0x7f < uVar5) {
          uVar5 = 0x7f;
        }
        uVar6 = 0;
        if (((bVar1) || ((uVar7 & 0x100) != 0)) && (param_1[9] == 5)) {
          uVar6 = 0x80;
        }
        iVar4 = uVar8 * 0x10 + _DAT_80038dd0;
        *(ushort *)(iVar4 + 8) = *(ushort *)(iVar4 + 8) & 0xff | (uVar5 | uVar6) << 8;
      }
      if ((bVar1) || ((uVar7 & 0x1000) != 0)) {
        uVar5 = *(ushort *)((int)param_1 + 0x32);
        if (0xf < uVar5) {
          uVar5 = 0xf;
        }
        iVar4 = uVar8 * 0x10 + _DAT_80038dd0;
        *(ushort *)(iVar4 + 8) = *(ushort *)(iVar4 + 8) & 0xff0f | uVar5 << 4;
      }
      if ((bVar1) || ((uVar7 & 0x2000) != 0)) {
        uVar5 = (ushort)param_1[0xd];
        if (0x7f < uVar5) {
          uVar5 = 0x7f;
        }
        uVar6 = 0x100;
        if ((bVar1) || ((uVar7 & 0x200) != 0)) {
          uVar3 = param_1[10];
          if ((uVar3 == 5) || (((int)uVar3 < 6 || (uVar3 != 7)))) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          uVar6 = 0x300;
        }
        iVar4 = uVar8 * 0x10 + _DAT_80038dd0;
        *(ushort *)(iVar4 + 10) = *(ushort *)(iVar4 + 10) & 0x3f | (uVar5 | uVar6) << 6;
      }
      if ((bVar1) || ((uVar7 & 0x4000) != 0)) {
        uVar5 = *(ushort *)((int)param_1 + 0x36);
        if (0x1f < uVar5) {
          uVar5 = 0x1f;
        }
        uVar6 = 0;
        if ((((bVar1) || ((uVar7 & 0x400) != 0)) && (param_1[0xb] != 3)) && (param_1[0xb] == 7)) {
          uVar6 = 0x20;
        }
        iVar4 = uVar8 * 0x10 + _DAT_80038dd0;
        *(ushort *)(iVar4 + 10) = *(ushort *)(iVar4 + 10) & 0xffc0 | uVar5 | uVar6;
      }
      if ((bVar1) || ((uVar7 & 0x8000) != 0)) {
        uVar5 = (ushort)param_1[0xe];
        if (0xf < uVar5) {
          uVar5 = 0xf;
        }
        iVar4 = uVar8 * 0x10 + _DAT_80038dd0;
        *(ushort *)(iVar4 + 8) = *(ushort *)(iVar4 + 8) & 0xfff0 | uVar5;
      }
    }
    uVar8 = uVar8 + 1;
    puVar9 = puVar9 + 1;
    if (0x17 < (int)uVar8) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  } while( true );
}


```

