# Snippets for GAME.BIN

## 1. phys_FUN_000402e0 @ 0x000402e0  tags:physics  score:20

```c

void FUN_000402e0(int param_1,undefined4 param_2,int param_3,int param_4)

{
  bool bVar1;
  ushort uVar2;
  int in_v0;
  int iVar3;
  uint uVar4;
  
  bVar1 = in_v0 != 0;
  *(ushort *)(param_3 + 0x42) = (ushort)bVar1;
  uVar2 = (ushort)bVar1;
  if (*(int *)(param_4 + 0x18) != 0) {
    uVar2 = bVar1 | 2;
  }
  *(ushort *)(param_3 + 0x42) = uVar2;
  uVar4 = 0;
  *(undefined2 *)(param_3 + 0x10) = *(undefined2 *)(param_4 + 0x1c);
  *(undefined2 *)(param_3 + 8) = *(undefined2 *)(param_4 + 0x20);
  *(undefined2 *)(param_3 + 0x16) = *(undefined2 *)(param_4 + 0x24);
  *(undefined4 *)(param_3 + 0x18) = *(undefined4 *)(param_4 + 0x28);
  *(undefined4 *)(param_3 + 0x20) = *(undefined4 *)(param_4 + 0x2c);
  do {
    iVar3 = uVar4 * 4;
    uVar4 = uVar4 + 1 & 0xffff;
    *(undefined4 *)(param_3 + 0x24 + iVar3) = *(undefined4 *)(param_4 + 0x38 + iVar3);
  } while (uVar4 < 5);
  uVar2 = *(ushort *)(param_3 + 0x42);
  if (*(int *)(param_4 + 0x3c) != 0) {
    uVar2 = uVar2 | 4;
  }
  *(ushort *)(param_3 + 0x42) = uVar2;
  *(undefined2 *)(param_3 + 0x3c) = *(undefined2 *)(param_4 + 0x4c);
  *(undefined2 *)(param_3 + 0x3e) = *(undefined2 *)(param_4 + 0x50);
  uVar2 = *(ushort *)(param_3 + 0x42);
  if (*(int *)(param_4 + 0x54) != 0) {
    uVar2 = uVar2 | 8;
  }
  *(ushort *)(param_3 + 0x42) = uVar2;
  *(short *)(param_3 + 0x40) = *(short *)(param_4 + 0x58) << 6;
  *(undefined2 *)(param_3 + 0x50) = *(undefined2 *)(param_4 + 0x5c);
  *(undefined4 *)(param_3 + 0x54) = *(undefined4 *)(param_4 + 0x60);
  if (param_1 - 0x26U < 0x2b) {
                    /* WARNING: Could not emulate address calculation at 0x000403e8 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)((param_1 - 0x26U) * 4 + -0x7ff38ca4))();
    return;
  }
  if (param_1 - 8U < 0x50) {
                    /* WARNING: Could not emulate address calculation at 0x00040420 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)((param_1 - 8U) * 4 + -0x7ff38bf4))();
    return;
  }
  return;
}


```

## 2. phys_FUN_000402e0 @ 0x000402e0  tags:physics  score:20

```c

void FUN_000402e0(int param_1,undefined4 param_2,int param_3,int param_4)

{
  bool bVar1;
  ushort uVar2;
  int in_v0;
  int iVar3;
  uint uVar4;
  
  bVar1 = in_v0 != 0;
  *(ushort *)(param_3 + 0x42) = (ushort)bVar1;
  uVar2 = (ushort)bVar1;
  if (*(int *)(param_4 + 0x18) != 0) {
    uVar2 = bVar1 | 2;
  }
  *(ushort *)(param_3 + 0x42) = uVar2;
  uVar4 = 0;
  *(undefined2 *)(param_3 + 0x10) = *(undefined2 *)(param_4 + 0x1c);
  *(undefined2 *)(param_3 + 8) = *(undefined2 *)(param_4 + 0x20);
  *(undefined2 *)(param_3 + 0x16) = *(undefined2 *)(param_4 + 0x24);
  *(undefined4 *)(param_3 + 0x18) = *(undefined4 *)(param_4 + 0x28);
  *(undefined4 *)(param_3 + 0x20) = *(undefined4 *)(param_4 + 0x2c);
  do {
    iVar3 = uVar4 * 4;
    uVar4 = uVar4 + 1 & 0xffff;
    *(undefined4 *)(param_3 + 0x24 + iVar3) = *(undefined4 *)(param_4 + 0x38 + iVar3);
  } while (uVar4 < 5);
  uVar2 = *(ushort *)(param_3 + 0x42);
  if (*(int *)(param_4 + 0x3c) != 0) {
    uVar2 = uVar2 | 4;
  }
  *(ushort *)(param_3 + 0x42) = uVar2;
  *(undefined2 *)(param_3 + 0x3c) = *(undefined2 *)(param_4 + 0x4c);
  *(undefined2 *)(param_3 + 0x3e) = *(undefined2 *)(param_4 + 0x50);
  uVar2 = *(ushort *)(param_3 + 0x42);
  if (*(int *)(param_4 + 0x54) != 0) {
    uVar2 = uVar2 | 8;
  }
  *(ushort *)(param_3 + 0x42) = uVar2;
  *(short *)(param_3 + 0x40) = *(short *)(param_4 + 0x58) << 6;
  *(undefined2 *)(param_3 + 0x50) = *(undefined2 *)(param_4 + 0x5c);
  *(undefined4 *)(param_3 + 0x54) = *(undefined4 *)(param_4 + 0x60);
  if (param_1 - 0x26U < 0x2b) {
                    /* WARNING: Could not emulate address calculation at 0x000403e8 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)((param_1 - 0x26U) * 4 + -0x7ff38ca4))();
    return;
  }
  if (param_1 - 8U < 0x50) {
                    /* WARNING: Could not emulate address calculation at 0x00040420 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)((param_1 - 8U) * 4 + -0x7ff38bf4))();
    return;
  }
  return;
}


```

## 3. phys_FUN_0004033c @ 0x0004033c  tags:physics  score:21

```c

void FUN_0004033c(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  undefined4 in_v0;
  ushort uVar1;
  int iVar2;
  uint in_t0;
  int in_t1;
  int in_t2;
  uint in_t3;
  uint in_t4;
  
  *(undefined4 *)(param_3 + 0x20) = in_v0;
  do {
    iVar2 = in_t0 * 4;
    in_t0 = in_t0 + 1 & 0xffff;
    *(undefined4 *)(in_t2 + iVar2) = *(undefined4 *)(in_t1 + iVar2);
  } while (in_t0 < 5);
  uVar1 = *(ushort *)(param_3 + 0x42);
  if (*(int *)(param_4 + 0x3c) != 0) {
    uVar1 = uVar1 | 4;
  }
  *(ushort *)(param_3 + 0x42) = uVar1;
  *(undefined2 *)(param_3 + 0x3c) = *(undefined2 *)(param_4 + 0x4c);
  *(undefined2 *)(param_3 + 0x3e) = *(undefined2 *)(param_4 + 0x50);
  uVar1 = *(ushort *)(param_3 + 0x42);
  if (*(int *)(param_4 + 0x54) != 0) {
    uVar1 = uVar1 | 8;
  }
  *(ushort *)(param_3 + 0x42) = uVar1;
  *(short *)(param_3 + 0x40) = *(short *)(param_4 + 0x58) << 6;
  *(undefined2 *)(param_3 + 0x50) = *(undefined2 *)(param_4 + 0x5c);
  *(undefined4 *)(param_3 + 0x54) = *(undefined4 *)(param_4 + 0x60);
  if (in_t3 < 0x2b) {
                    /* WARNING: Could not emulate address calculation at 0x000403e8 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(in_t3 * 4 + -0x7ff38ca4))();
    return;
  }
  if (in_t4 < 0x50) {
                    /* WARNING: Could not emulate address calculation at 0x00040420 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(in_t4 * 4 + -0x7ff38bf4))();
    return;
  }
  return;
}


```

## 4. phys_FUN_0004033c @ 0x0004033c  tags:physics  score:21

```c

void FUN_0004033c(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  undefined4 in_v0;
  ushort uVar1;
  int iVar2;
  uint in_t0;
  int in_t1;
  int in_t2;
  uint in_t3;
  uint in_t4;
  
  *(undefined4 *)(param_3 + 0x20) = in_v0;
  do {
    iVar2 = in_t0 * 4;
    in_t0 = in_t0 + 1 & 0xffff;
    *(undefined4 *)(in_t2 + iVar2) = *(undefined4 *)(in_t1 + iVar2);
  } while (in_t0 < 5);
  uVar1 = *(ushort *)(param_3 + 0x42);
  if (*(int *)(param_4 + 0x3c) != 0) {
    uVar1 = uVar1 | 4;
  }
  *(ushort *)(param_3 + 0x42) = uVar1;
  *(undefined2 *)(param_3 + 0x3c) = *(undefined2 *)(param_4 + 0x4c);
  *(undefined2 *)(param_3 + 0x3e) = *(undefined2 *)(param_4 + 0x50);
  uVar1 = *(ushort *)(param_3 + 0x42);
  if (*(int *)(param_4 + 0x54) != 0) {
    uVar1 = uVar1 | 8;
  }
  *(ushort *)(param_3 + 0x42) = uVar1;
  *(short *)(param_3 + 0x40) = *(short *)(param_4 + 0x58) << 6;
  *(undefined2 *)(param_3 + 0x50) = *(undefined2 *)(param_4 + 0x5c);
  *(undefined4 *)(param_3 + 0x54) = *(undefined4 *)(param_4 + 0x60);
  if (in_t3 < 0x2b) {
                    /* WARNING: Could not emulate address calculation at 0x000403e8 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(in_t3 * 4 + -0x7ff38ca4))();
    return;
  }
  if (in_t4 < 0x50) {
                    /* WARNING: Could not emulate address calculation at 0x00040420 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(in_t4 * 4 + -0x7ff38bf4))();
    return;
  }
  return;
}


```

## 5. phys_FUN_00040a98 @ 0x00040a98  tags:physics  score:43

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_00040a98(void)

{
  bool bVar1;
  short sVar2;
  undefined2 uVar3;
  bool bVar4;
  ushort uVar5;
  int in_v0;
  int iVar6;
  uint uVar7;
  uint uVar8;
  undefined4 uVar9;
  int iVar10;
  int unaff_s1;
  int unaff_s2;
  ushort uVar11;
  int unaff_s4;
  
  if (in_v0 != 0) {
    iVar6 = func_0x00105824();
    if ((iVar6 == 0) && (iVar6 = func_0x001059c4(), iVar6 != 0xb)) {
      return 0;
    }
    *(short *)(unaff_s1 + 0xce) = *(short *)(unaff_s1 + 0xce) + 1;
    sVar2 = *(short *)(*(int *)(unaff_s1 + 0xc0) + 0xc);
    *(short *)(unaff_s1 + 0xbc) = sVar2;
    if (sVar2 == 0) {
      FUN_0004033c(1,*(int *)(unaff_s1 + 0xd4) + 8,0xfff,
                   *(undefined2 *)(*(int *)(unaff_s1 + 0xc0) + 6));
    }
    bVar4 = false;
    bVar1 = _DAT_80119618 == 0;
    *(undefined4 *)(unaff_s1 + 0xf0) = _DAT_800c02ac;
    if (bVar1) {
      uVar11 = 0;
      if (*(short *)(*(int *)(unaff_s1 + 0xc0) + 0x3e) != 0) {
        do {
          if ((*(ushort *)(*(int *)(unaff_s1 + 0xc0) + 0x42) & 1) != 0) {
            iVar10 = (uint)*(ushort *)(*(int *)(unaff_s1 + 0xc0) + 0xe) << 0x10;
            uVar7 = FUN_000209dc();
            uVar8 = FUN_000209dc();
            iVar6 = (uVar8 & 0xfff) + 0x400;
            if (iVar6 == 0) {
              trap(7);
            }
            unaff_s4 = (int)(short)((((((int)((uVar7 & 0xfff) * (iVar10 >> 0x10)) >> 0xc) -
                                      (iVar10 >> 0x11)) * 0x10000 >> 0x10) << 10) / iVar6);
          }
          unaff_s2 = func_0x00106cc0(*(undefined4 *)(*(int *)(unaff_s1 + 0xc0) + 0x1c),
                                     *(undefined4 *)(unaff_s1 + 0xd4));
          if (unaff_s2 == 0) {
            return 0;
          }
          *(undefined2 *)(unaff_s2 + 0xea) = *(undefined2 *)(*(int *)(unaff_s1 + 0xc0) + 6);
          iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
          iVar6 = (**(code **)(iVar6 + 0x1c))
                            (*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x18));
          uVar9 = _DAT_800bc8f0;
          if ((iVar6 == 3) && (*(int *)(*(int *)(unaff_s1 + 0xd4) + 0x160) == 0x4f)) {
            *(undefined4 *)(unaff_s2 + 0xdc) = _DAT_800bc8f0;
            func_0x00074950(unaff_s2,uVar9);
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          if ((iVar6 == 0) && (iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 0x328), iVar6 != 0)) {
            *(int *)(unaff_s2 + 0xdc) = iVar6;
            func_0x00074950(unaff_s2);
          }
          if ((*(ushort *)(*(int *)(unaff_s1 + 0xc0) + 0x42) >> 4 & 1) != 0) {
            *(uint *)(unaff_s2 + 0xd0) = *(uint *)(unaff_s2 + 0xd0) | 0x20;
          }
          iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
          uVar3 = *(undefined2 *)(*(int *)(unaff_s1 + 0xc0) + 0x12);
          iVar6 = (**(code **)(iVar6 + 0x24))
                            (*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x20));
          if (iVar6 == 1) {
            func_0x0007a87c(*(undefined4 *)(*(int *)(unaff_s1 + 0xd4) + 0x318),0,uVar3);
            iVar6 = *(int *)(unaff_s1 + 0xd4);
            if (*(short *)(iVar6 + 0x334) != 0x41) {
              (**(code **)(*(int *)(iVar6 + 4) + 0x5c))
                        (iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x58),uVar3);
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
            *(uint *)(unaff_s2 + 0xd0) = *(uint *)(unaff_s2 + 0xd0) | 0x10;
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
          (**(code **)(iVar6 + 0x5c))
                    (*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x58),uVar3);
          func_0x0010b63c(unaff_s2,unaff_s4);
          if (!bVar4) {
            func_0x000857c4(unaff_s2);
            bVar4 = true;
          }
          iVar6 = func_0x001059c4();
          if (iVar6 == 0xb) {
            *(undefined4 *)(unaff_s2 + 8) = *(undefined4 *)(*(int *)(unaff_s1 + 0xd4) + 8);
            *(undefined4 *)(unaff_s2 + 0xc) = *(undefined4 *)(*(int *)(unaff_s1 + 0xd4) + 0xc);
            func_0x00060e40(*(undefined4 *)(unaff_s1 + 0xd4));
            func_0x00078870(*(undefined4 *)(unaff_s1 + 0xd4),0x30000);
            iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
            (**(code **)(iVar6 + 0x4c))
                      (*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x48),999);
          }
          uVar5 = *(short *)(unaff_s1 + 0xea) + 1;
          *(ushort *)(unaff_s1 + 0xea) = uVar5;
          if (*(ushort *)(unaff_s1 + 0xe8) <= uVar5) {
            *(undefined2 *)(unaff_s1 + 0xea) = 0;
          }
          uVar11 = uVar11 + 1;
        } while (uVar11 < *(ushort *)(*(int *)(unaff_s1 + 0xc0) + 0x3e));
      }
      iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
      iVar6 = (**(code **)(iVar6 + 0x1c))(*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x18))
      ;
      if (iVar6 == 0) {
        iVar6 = *(int *)(unaff_s1 + 0xd4);
        iVar10 = (int)*(short *)(*(int *)(unaff_s1 + 0xc0) + 0x40);
        *(short *)(iVar6 + 0x114) =
             *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);
        iVar6 = *(int *)(unaff_s1 + 0xd4);
        *(short *)(iVar6 + 0x118) =
             *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);
        iVar6 = func_0x001059c4();
        if (iVar6 - 2U < 0x4b) {
                    /* WARNING: Could not emulate address calculation at 0x00040ee0 */
                    /* WARNING: Treating indirect jump as call */
          uVar9 = (**(code **)((iVar6 - 2U) * 4 + -0x7ff38914))();
          return uVar9;
        }
      }
      else {
        iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
        iVar6 = (**(code **)(iVar6 + 0x1c))
                          (*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x18));
        if ((iVar6 == 3) && (iVar6 = *(int *)(unaff_s1 + 0xd4), *(int *)(iVar6 + 0x164) != 0xb)) {
          uVar7 = FUN_00022e5c((int)*(short *)(unaff_s2 + 0x3c),(int)*(short *)(unaff_s2 + 0x40));
          iVar10 = (uVar7 & 0xfff) * 4;
          (**(code **)(*(int *)(iVar6 + 4) + 0x84))
                    (iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x80),
                     (int)*(short *)(iVar10 + -0x7ffeb164),(int)*(short *)(iVar10 + -0x7ffeb162));
        }
      }
      if ((*(ushort *)(*(int *)(unaff_s1 + 0xc0) + 0x42) >> 5 & 1) == 0) {
        iVar6 = func_0x001059c4();
        if (iVar6 == 0xb) {
          if (*(int *)(unaff_s1 + 0xf4) != 0) {
            FUN_0003e4b4();
            *(undefined4 *)(unaff_s1 + 0xf4) = 0;
            halt_baddata();
          }
        }
        else {
          FUN_0004033c(0,*(int *)(unaff_s1 + 0xd4) + 8,0xfff,
                       *(undefined2 *)(*(int *)(unaff_s1 + 0xc0) + 6));
        }
        *(undefined4 *)(unaff_s1 + 0xf4) = 0;
      }
      else if ((*(int *)(unaff_s1 + 0x100) != 0) || (*(int *)(unaff_s1 + 0xf4) == 0)) {
        if (*(int *)(unaff_s1 + 0xf4) != 0) {
          FUN_0003e4b4();
        }
        uVar9 = FUN_0004033c(0,*(int *)(unaff_s1 + 0xd4) + 8,0xfff,
                             *(undefined2 *)(*(int *)(unaff_s1 + 0xc0) + 6));
        *(undefined4 *)(unaff_s1 + 0xf4) = uVar9;
        *(undefined4 *)(unaff_s1 + 0x100) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
      iVar6 = (**(code **)(iVar6 + 0x24))(*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x20))
      ;
      if (iVar6 != 3) {
        if (iVar6 < 4) {
          if (iVar6 != 1) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
        }
        else {
          if (8 < iVar6) {
            return 1;
          }
          if (iVar6 < 7) {
            return 1;
          }
        }
        *(short *)(*(int *)(unaff_s1 + 0xd4) + 0x2ae) =
             *(short *)(*(int *)(unaff_s1 + 0xd4) + 0x2ae) + 1;
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 0x1b8);
      if (iVar6 != 0) {
        *(short *)(iVar6 + 0x2ae) = *(short *)(iVar6 + 0x2ae) + 1;
      }
    }
  }
  return 1;
}


```

## 6. phys_FUN_00040a98 @ 0x00040a98  tags:physics  score:43

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_00040a98(void)

{
  bool bVar1;
  short sVar2;
  undefined2 uVar3;
  bool bVar4;
  ushort uVar5;
  int in_v0;
  int iVar6;
  uint uVar7;
  uint uVar8;
  undefined4 uVar9;
  int iVar10;
  int unaff_s1;
  int unaff_s2;
  ushort uVar11;
  int unaff_s4;
  
  if (in_v0 != 0) {
    iVar6 = func_0x00105824();
    if ((iVar6 == 0) && (iVar6 = func_0x001059c4(), iVar6 != 0xb)) {
      return 0;
    }
    *(short *)(unaff_s1 + 0xce) = *(short *)(unaff_s1 + 0xce) + 1;
    sVar2 = *(short *)(*(int *)(unaff_s1 + 0xc0) + 0xc);
    *(short *)(unaff_s1 + 0xbc) = sVar2;
    if (sVar2 == 0) {
      FUN_0004033c(1,*(int *)(unaff_s1 + 0xd4) + 8,0xfff,
                   *(undefined2 *)(*(int *)(unaff_s1 + 0xc0) + 6));
    }
    bVar4 = false;
    bVar1 = _DAT_80119618 == 0;
    *(undefined4 *)(unaff_s1 + 0xf0) = _DAT_800c02ac;
    if (bVar1) {
      uVar11 = 0;
      if (*(short *)(*(int *)(unaff_s1 + 0xc0) + 0x3e) != 0) {
        do {
          if ((*(ushort *)(*(int *)(unaff_s1 + 0xc0) + 0x42) & 1) != 0) {
            iVar10 = (uint)*(ushort *)(*(int *)(unaff_s1 + 0xc0) + 0xe) << 0x10;
            uVar7 = FUN_000209dc();
            uVar8 = FUN_000209dc();
            iVar6 = (uVar8 & 0xfff) + 0x400;
            if (iVar6 == 0) {
              trap(7);
            }
            unaff_s4 = (int)(short)((((((int)((uVar7 & 0xfff) * (iVar10 >> 0x10)) >> 0xc) -
                                      (iVar10 >> 0x11)) * 0x10000 >> 0x10) << 10) / iVar6);
          }
          unaff_s2 = func_0x00106cc0(*(undefined4 *)(*(int *)(unaff_s1 + 0xc0) + 0x1c),
                                     *(undefined4 *)(unaff_s1 + 0xd4));
          if (unaff_s2 == 0) {
            return 0;
          }
          *(undefined2 *)(unaff_s2 + 0xea) = *(undefined2 *)(*(int *)(unaff_s1 + 0xc0) + 6);
          iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
          iVar6 = (**(code **)(iVar6 + 0x1c))
                            (*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x18));
          uVar9 = _DAT_800bc8f0;
          if ((iVar6 == 3) && (*(int *)(*(int *)(unaff_s1 + 0xd4) + 0x160) == 0x4f)) {
            *(undefined4 *)(unaff_s2 + 0xdc) = _DAT_800bc8f0;
            func_0x00074950(unaff_s2,uVar9);
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          if ((iVar6 == 0) && (iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 0x328), iVar6 != 0)) {
            *(int *)(unaff_s2 + 0xdc) = iVar6;
            func_0x00074950(unaff_s2);
          }
          if ((*(ushort *)(*(int *)(unaff_s1 + 0xc0) + 0x42) >> 4 & 1) != 0) {
            *(uint *)(unaff_s2 + 0xd0) = *(uint *)(unaff_s2 + 0xd0) | 0x20;
          }
          iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
          uVar3 = *(undefined2 *)(*(int *)(unaff_s1 + 0xc0) + 0x12);
          iVar6 = (**(code **)(iVar6 + 0x24))
                            (*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x20));
          if (iVar6 == 1) {
            func_0x0007a87c(*(undefined4 *)(*(int *)(unaff_s1 + 0xd4) + 0x318),0,uVar3);
            iVar6 = *(int *)(unaff_s1 + 0xd4);
            if (*(short *)(iVar6 + 0x334) != 0x41) {
              (**(code **)(*(int *)(iVar6 + 4) + 0x5c))
                        (iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x58),uVar3);
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
            *(uint *)(unaff_s2 + 0xd0) = *(uint *)(unaff_s2 + 0xd0) | 0x10;
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
          (**(code **)(iVar6 + 0x5c))
                    (*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x58),uVar3);
          func_0x0010b63c(unaff_s2,unaff_s4);
          if (!bVar4) {
            func_0x000857c4(unaff_s2);
            bVar4 = true;
          }
          iVar6 = func_0x001059c4();
          if (iVar6 == 0xb) {
            *(undefined4 *)(unaff_s2 + 8) = *(undefined4 *)(*(int *)(unaff_s1 + 0xd4) + 8);
            *(undefined4 *)(unaff_s2 + 0xc) = *(undefined4 *)(*(int *)(unaff_s1 + 0xd4) + 0xc);
            func_0x00060e40(*(undefined4 *)(unaff_s1 + 0xd4));
            func_0x00078870(*(undefined4 *)(unaff_s1 + 0xd4),0x30000);
            iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
            (**(code **)(iVar6 + 0x4c))
                      (*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x48),999);
          }
          uVar5 = *(short *)(unaff_s1 + 0xea) + 1;
          *(ushort *)(unaff_s1 + 0xea) = uVar5;
          if (*(ushort *)(unaff_s1 + 0xe8) <= uVar5) {
            *(undefined2 *)(unaff_s1 + 0xea) = 0;
          }
          uVar11 = uVar11 + 1;
        } while (uVar11 < *(ushort *)(*(int *)(unaff_s1 + 0xc0) + 0x3e));
      }
      iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
      iVar6 = (**(code **)(iVar6 + 0x1c))(*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x18))
      ;
      if (iVar6 == 0) {
        iVar6 = *(int *)(unaff_s1 + 0xd4);
        iVar10 = (int)*(short *)(*(int *)(unaff_s1 + 0xc0) + 0x40);
        *(short *)(iVar6 + 0x114) =
             *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);
        iVar6 = *(int *)(unaff_s1 + 0xd4);
        *(short *)(iVar6 + 0x118) =
             *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);
        iVar6 = func_0x001059c4();
        if (iVar6 - 2U < 0x4b) {
                    /* WARNING: Could not emulate address calculation at 0x00040ee0 */
                    /* WARNING: Treating indirect jump as call */
          uVar9 = (**(code **)((iVar6 - 2U) * 4 + -0x7ff38914))();
          return uVar9;
        }
      }
      else {
        iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
        iVar6 = (**(code **)(iVar6 + 0x1c))
                          (*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x18));
        if ((iVar6 == 3) && (iVar6 = *(int *)(unaff_s1 + 0xd4), *(int *)(iVar6 + 0x164) != 0xb)) {
          uVar7 = FUN_00022e5c((int)*(short *)(unaff_s2 + 0x3c),(int)*(short *)(unaff_s2 + 0x40));
          iVar10 = (uVar7 & 0xfff) * 4;
          (**(code **)(*(int *)(iVar6 + 4) + 0x84))
                    (iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x80),
                     (int)*(short *)(iVar10 + -0x7ffeb164),(int)*(short *)(iVar10 + -0x7ffeb162));
        }
      }
      if ((*(ushort *)(*(int *)(unaff_s1 + 0xc0) + 0x42) >> 5 & 1) == 0) {
        iVar6 = func_0x001059c4();
        if (iVar6 == 0xb) {
          if (*(int *)(unaff_s1 + 0xf4) != 0) {
            FUN_0003e4b4();
            *(undefined4 *)(unaff_s1 + 0xf4) = 0;
            halt_baddata();
          }
        }
        else {
          FUN_0004033c(0,*(int *)(unaff_s1 + 0xd4) + 8,0xfff,
                       *(undefined2 *)(*(int *)(unaff_s1 + 0xc0) + 6));
        }
        *(undefined4 *)(unaff_s1 + 0xf4) = 0;
      }
      else if ((*(int *)(unaff_s1 + 0x100) != 0) || (*(int *)(unaff_s1 + 0xf4) == 0)) {
        if (*(int *)(unaff_s1 + 0xf4) != 0) {
          FUN_0003e4b4();
        }
        uVar9 = FUN_0004033c(0,*(int *)(unaff_s1 + 0xd4) + 8,0xfff,
                             *(undefined2 *)(*(int *)(unaff_s1 + 0xc0) + 6));
        *(undefined4 *)(unaff_s1 + 0xf4) = uVar9;
        *(undefined4 *)(unaff_s1 + 0x100) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
      iVar6 = (**(code **)(iVar6 + 0x24))(*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x20))
      ;
      if (iVar6 != 3) {
        if (iVar6 < 4) {
          if (iVar6 != 1) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
        }
        else {
          if (8 < iVar6) {
            return 1;
          }
          if (iVar6 < 7) {
            return 1;
          }
        }
        *(short *)(*(int *)(unaff_s1 + 0xd4) + 0x2ae) =
             *(short *)(*(int *)(unaff_s1 + 0xd4) + 0x2ae) + 1;
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 0x1b8);
      if (iVar6 != 0) {
        *(short *)(iVar6 + 0x2ae) = *(short *)(iVar6 + 0x2ae) + 1;
      }
    }
  }
  return 1;
}


```

## 7. phys_FUN_000406ac @ 0x000406ac  tags:physics  score:16

```c

/* WARNING: Control flow encountered bad instruction data */

undefined4 FUN_000406ac(int param_1)

{
  undefined2 uVar1;
  undefined4 uVar2;
  int in_v1;
  int iVar3;
  undefined4 *unaff_s0;
  int unaff_s1;
  int unaff_s2;
  int unaff_s3;
  int unaff_s4;
  
  (**(code **)(in_v1 + 0x1c))(unaff_s1 + param_1);
  *unaff_s0 = 0;
  unaff_s0[1] = 0;
  func_0x000ad8f8();
  *(undefined4 **)(unaff_s1 + 100) = unaff_s0;
  if (unaff_s3 == 0) {
    return 0;
  }
  *(int *)(unaff_s1 + 0xc0) = unaff_s3;
  if (unaff_s2 - 0x25U < 0x33) {
                    /* WARNING: Could not emulate address calculation at 0x000406fc */
                    /* WARNING: Treating indirect jump as call */
    uVar2 = (**(code **)((unaff_s2 - 0x25U) * 4 + -0x7ff38ab4))();
    return uVar2;
  }
  uVar2 = func_0x001059c4();
  uVar2 = func_0x000ea2fc(2,uVar2);
  *(undefined4 *)(unaff_s1 + 0xdc) = uVar2;
  func_0x00105c04();
  iVar3 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
  iVar3 = (**(code **)(iVar3 + 0x1c))(*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar3 + 0x18));
  if (iVar3 != 3) {
    func_0x00105f3c();
  }
  uVar1 = *(undefined2 *)(*(int *)(unaff_s1 + 0xc0) + 0x14);
  *(undefined2 *)(unaff_s1 + 0xd0) = uVar1;
  if (*(int *)(unaff_s1 + 0xd4) != 0) {
    if (unaff_s4 == 0) {
      func_0x000779f4(*(int *)(unaff_s1 + 0xd4),uVar1);
    }
    *(undefined2 *)(unaff_s1 + 0xd0) = 0;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


```

## 8. phys_FUN_000406ac @ 0x000406ac  tags:physics  score:16

```c

/* WARNING: Control flow encountered bad instruction data */

undefined4 FUN_000406ac(int param_1)

{
  undefined2 uVar1;
  undefined4 uVar2;
  int in_v1;
  int iVar3;
  undefined4 *unaff_s0;
  int unaff_s1;
  int unaff_s2;
  int unaff_s3;
  int unaff_s4;
  
  (**(code **)(in_v1 + 0x1c))(unaff_s1 + param_1);
  *unaff_s0 = 0;
  unaff_s0[1] = 0;
  func_0x000ad8f8();
  *(undefined4 **)(unaff_s1 + 100) = unaff_s0;
  if (unaff_s3 == 0) {
    return 0;
  }
  *(int *)(unaff_s1 + 0xc0) = unaff_s3;
  if (unaff_s2 - 0x25U < 0x33) {
                    /* WARNING: Could not emulate address calculation at 0x000406fc */
                    /* WARNING: Treating indirect jump as call */
    uVar2 = (**(code **)((unaff_s2 - 0x25U) * 4 + -0x7ff38ab4))();
    return uVar2;
  }
  uVar2 = func_0x001059c4();
  uVar2 = func_0x000ea2fc(2,uVar2);
  *(undefined4 *)(unaff_s1 + 0xdc) = uVar2;
  func_0x00105c04();
  iVar3 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
  iVar3 = (**(code **)(iVar3 + 0x1c))(*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar3 + 0x18));
  if (iVar3 != 3) {
    func_0x00105f3c();
  }
  uVar1 = *(undefined2 *)(*(int *)(unaff_s1 + 0xc0) + 0x14);
  *(undefined2 *)(unaff_s1 + 0xd0) = uVar1;
  if (*(int *)(unaff_s1 + 0xd4) != 0) {
    if (unaff_s4 == 0) {
      func_0x000779f4(*(int *)(unaff_s1 + 0xd4),uVar1);
    }
    *(undefined2 *)(unaff_s1 + 0xd0) = 0;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


```

## 9. phys_FUN_00031b38 @ 0x00031b38  tags:physics  score:49

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Removing unreachable block (ram,0x00031fb0) */
/* WARNING: Removing unreachable block (ram,0x00031fb4) */
/* WARNING: Removing unreachable block (ram,0x00032004) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00031b38(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  short *psVar4;
  uint uVar5;
  undefined4 uVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  undefined2 uVar10;
  int iVar11;
  uint uVar12;
  undefined4 local_f8 [30];
  int local_80 [10];
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  uint local_34;
  short *local_30;
  uint local_2c;
  
  uVar5 = 0;
  psVar4 = _DAT_800c088c;
  uVar12 = 0;
  do {
    iVar1 = func_0x000f5b78(uVar5,1);
    local_2c = uVar12 + 1;
    local_30 = psVar4 + 1;
    if (((iVar1 != 0) && (*(int *)(iVar1 + 0x180) != 0)) &&
       (iVar2 = *(int *)(*psVar4 * 4 + -0x7ff3fc08), iVar2 != 0)) {
      iVar2 = *(int *)(iVar2 + 0x24);
      iVar11 = (int)*(short *)(iVar2 + 2);
      if (iVar11 != 0) {
        uVar5 = 0;
        local_38 = 0;
        iVar2 = *(int *)(iVar2 + 8);
        *(undefined2 *)(iVar1 + 0x88) = 0xffff;
        local_58 = _DAT_800c64f4;
        local_54 = _DAT_800c64f8;
        local_50 = _DAT_800c64fc;
        local_4c = _DAT_800c6500;
        local_48 = _DAT_800c64f4;
        local_44 = _DAT_800c64f8;
        local_34 = uVar12 - 0xd;
        local_40 = _DAT_800c64fc;
        local_3c = _DAT_800c6500;
        if (0 < iVar11) {
          iVar7 = iVar2 + 0x54;
          uVar8 = 0;
          do {
            uVar9 = uVar8;
            if (iVar2 != 0) {
              if (uVar5 == 0) {
                func_0x000f671c(&local_58,&local_50,iVar2);
              }
              iVar3 = FUN_00023210(0x800c6504,iVar7,8);
              if (iVar3 == 0) {
                *(undefined2 *)(iVar1 + 0x88) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
              iVar3 = FUN_00023210(0x800c6510,iVar7,8);
              if (iVar3 == 0) {
                *(undefined2 *)(iVar1 + 0x88) = 1;
              }
              iVar3 = FUN_00023210(0x800c651c,iVar7,4);
              if (iVar3 == 0) {
                iVar2 = FUN_00023358(iVar2 + 0x59);
                iVar11 = iVar2 * 8 + iVar1;
                *(undefined4 *)(iVar11 + 0x28) = *(undefined4 *)(iVar7 + -0x4c);
                *(undefined4 *)(iVar11 + 0x2c) = *(undefined4 *)(iVar7 + -0x48);
                psVar4 = (short *)(iVar1 + 0x32 + (iVar2 + -1) * 8);
                *psVar4 = *psVar4 + 200;
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
              iVar3 = FUN_00023210(0x800c6524,iVar7,5);
              uVar10 = (undefined2)uVar5;
              if (iVar3 == 0) {
                iVar11 = FUN_00023358(iVar2 + 0x5a);
                iVar1 = iVar1 + (iVar11 + -1) * 2;
                *(undefined2 *)(iVar1 + 0xb4) = uVar10;
                *(undefined2 *)(iVar1 + 0xc4) = *(undefined2 *)(iVar7 + -0x10);
                func_0x000f671c(&local_58,&local_50,iVar2);
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
              iVar3 = FUN_00023210(0x800c652c,iVar7,5);
              if (iVar3 == 0) {
                iVar2 = FUN_00023358(iVar2 + 0x5a);
                *(undefined2 *)(iVar1 + (iVar2 + -1) * 2 + 0xb8) = uVar10;
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
              iVar3 = FUN_00023210(0x800c6534,iVar7,6);
              if (((iVar3 == 0) || (iVar3 = FUN_00023210(0x800c653c,iVar7,6), iVar3 == 0)) ||
                 ((iVar3 = FUN_00023210(0x800c6544,iVar7,4), iVar3 == 0 && (uVar12 == 0x51)))) {
                *(undefined2 *)(iVar1 + 0xc0) = uVar10;
                uVar6 = *(undefined4 *)(iVar7 + -0x48);
                *(undefined4 *)(iVar1 + 0x102) = *(undefined4 *)(iVar7 + -0x4c);
                *(undefined4 *)(iVar1 + 0x106) = uVar6;
                func_0x000f671c(&local_48,&local_40,iVar2);
                halt_baddata();
              }
              iVar3 = FUN_00023210(0x800c654c,iVar7,7);
              if (iVar3 == 0) {
                *(undefined2 *)(iVar1 + 0xc2) = uVar10;
                func_0x000f671c(&local_58,&local_50,iVar2);
                halt_baddata();
              }
              iVar3 = FUN_00023210(0x800c6554,iVar7,6);
              if (iVar3 == 0) {
                halt_baddata();
              }
              iVar3 = FUN_00023210(0x800c655c,iVar7,6);
              if (iVar3 == 0) {
                uVar9 = uVar8 + 1 & 0xffff;
                local_80[uVar8] = iVar2;
                uVar6 = *(undefined4 *)(iVar7 + -0x48);
                local_f8[uVar8 * 2] = *(undefined4 *)(iVar7 + -0x4c);
                local_f8[uVar8 * 2 + 1] = uVar6;
              }
              iVar7 = iVar7 + 0x74;
              iVar2 = iVar2 + 0x74;
            }
            uVar5 = uVar5 + 1 & 0xffff;
            uVar8 = uVar9;
          } while ((int)uVar5 < iVar11);
        }
        *(undefined2 *)(iVar1 + 0x78) = 0;
        *(short *)(iVar1 + 0x7c) = (short)local_38;
        if (*(short *)(iVar1 + 0xc0) < 0) {
          *(undefined4 *)(iVar1 + 0x80) = 0;
        }
        else {
          *(undefined4 *)(iVar1 + 0x80) = 1;
        }
        if (local_34 < 0x45) {
                    /* WARNING: Could not emulate address calculation at 0x00032030 */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)(local_34 * 4 + -0x7ff39a9c))();
          return;
        }
        *(undefined4 *)(iVar1 + 0x84) = 0;
        if ((*(int *)(iVar1 + 300) == 7) || (*(int *)(iVar1 + 300) == 0x19)) {
          *(undefined2 *)(iVar1 + 0x78) = 0;
        }
        if (*(short *)(iVar1 + 0x88) < 0) {
          *(undefined2 *)(iVar1 + 0x88) = 0;
        }
        *(undefined2 *)(iVar1 + 0xac) = 500;
        if (*(short *)(iVar1 + 0x148) == 0) {
          *(undefined2 *)(iVar1 + 0x8a) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        iVar11 = (*(ushort *)(iVar1 + 0x148) & 0xfff) * 4;
        iVar2 = (int)*(short *)(iVar11 + -0x7ffeb164);
        if (iVar2 == 0) {
          trap(7);
        }
        *(short *)(iVar1 + 0x8a) = (short)((*(short *)(iVar11 + -0x7ffeb162) * 500) / iVar2);
        if (-1 < (int)(short)local_50 - (int)(short)local_58) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        *(short *)(iVar1 + 0x8c) = (short)local_58 - (short)local_50;
        if (-1 < (int)local_50._2_2_ - (int)local_58._2_2_) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        *(short *)(iVar1 + 0x8e) = local_58._2_2_ - local_50._2_2_;
        if (-1 < (int)(short)local_4c - (int)(short)local_54) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        *(short *)(iVar1 + 0x90) = (short)local_54 - (short)local_4c;
        *(short *)(iVar1 + 0x9c) = (short)((int)(short)local_58 + (int)(short)local_50 >> 1);
        *(short *)(iVar1 + 0x9e) = (short)((int)local_58._2_2_ + (int)local_50._2_2_ >> 1);
        *(short *)(iVar1 + 0xa0) = (short)((int)(short)local_54 + (int)(short)local_4c >> 1);
        if (-1 < (int)local_40._2_2_ - (int)local_48._2_2_) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        *(short *)(iVar1 + 0x94) = local_48._2_2_ - local_40._2_2_;
        if (-1 < (int)local_40._2_2_ - (int)local_48._2_2_) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        *(short *)(iVar1 + 0x96) = local_48._2_2_ - local_40._2_2_;
        if (-1 < (int)(short)local_3c - (int)(short)local_44) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        *(short *)(iVar1 + 0x98) = (short)local_44 - (short)local_3c;
        *(short *)(iVar1 + 0xa4) = (short)((int)(short)local_48 + (int)(short)local_40 >> 1);
        *(short *)(iVar1 + 0xa6) = (short)((int)local_48._2_2_ + (int)local_40._2_2_ >> 1);
        *(short *)(iVar1 + 0xa8) = (short)((int)(short)local_44 + (int)(short)local_3c >> 1);
        if (*(uint *)(iVar1 + 300) < 0x54) {
                    /* WARNING: Could not emulate address calculation at 0x000322f0 */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)(*(uint *)(iVar1 + 300) * 4 + -0x7ff39984))();
          return;
        }
        *(undefined2 *)(iVar1 + 0x7a) = 0;
      }
    }
    uVar5 = local_2c & 0xffff;
    psVar4 = local_30;
    uVar12 = local_2c;
    if (0x53 < local_2c) {
      return;
    }
  } while( true );
}


```

## 10. phys_FUN_00031b38 @ 0x00031b38  tags:physics  score:49

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Removing unreachable block (ram,0x00031fb0) */
/* WARNING: Removing unreachable block (ram,0x00031fb4) */
/* WARNING: Removing unreachable block (ram,0x00032004) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00031b38(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  short *psVar4;
  uint uVar5;
  undefined4 uVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  undefined2 uVar10;
  int iVar11;
  uint uVar12;
  undefined4 local_f8 [30];
  int local_80 [10];
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  uint local_34;
  short *local_30;
  uint local_2c;
  
  uVar5 = 0;
  psVar4 = _DAT_800c088c;
  uVar12 = 0;
  do {
    iVar1 = func_0x000f5b78(uVar5,1);
    local_2c = uVar12 + 1;
    local_30 = psVar4 + 1;
    if (((iVar1 != 0) && (*(int *)(iVar1 + 0x180) != 0)) &&
       (iVar2 = *(int *)(*psVar4 * 4 + -0x7ff3fc08), iVar2 != 0)) {
      iVar2 = *(int *)(iVar2 + 0x24);
      iVar11 = (int)*(short *)(iVar2 + 2);
      if (iVar11 != 0) {
        uVar5 = 0;
        local_38 = 0;
        iVar2 = *(int *)(iVar2 + 8);
        *(undefined2 *)(iVar1 + 0x88) = 0xffff;
        local_58 = _DAT_800c64f4;
        local_54 = _DAT_800c64f8;
        local_50 = _DAT_800c64fc;
        local_4c = _DAT_800c6500;
        local_48 = _DAT_800c64f4;
        local_44 = _DAT_800c64f8;
        local_34 = uVar12 - 0xd;
        local_40 = _DAT_800c64fc;
        local_3c = _DAT_800c6500;
        if (0 < iVar11) {
          iVar7 = iVar2 + 0x54;
          uVar8 = 0;
          do {
            uVar9 = uVar8;
            if (iVar2 != 0) {
              if (uVar5 == 0) {
                func_0x000f671c(&local_58,&local_50,iVar2);
              }
              iVar3 = FUN_00023210(0x800c6504,iVar7,8);
              if (iVar3 == 0) {
                *(undefined2 *)(iVar1 + 0x88) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
              iVar3 = FUN_00023210(0x800c6510,iVar7,8);
              if (iVar3 == 0) {
                *(undefined2 *)(iVar1 + 0x88) = 1;
              }
              iVar3 = FUN_00023210(0x800c651c,iVar7,4);
              if (iVar3 == 0) {
                iVar2 = FUN_00023358(iVar2 + 0x59);
                iVar11 = iVar2 * 8 + iVar1;
                *(undefined4 *)(iVar11 + 0x28) = *(undefined4 *)(iVar7 + -0x4c);
                *(undefined4 *)(iVar11 + 0x2c) = *(undefined4 *)(iVar7 + -0x48);
                psVar4 = (short *)(iVar1 + 0x32 + (iVar2 + -1) * 8);
                *psVar4 = *psVar4 + 200;
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
              iVar3 = FUN_00023210(0x800c6524,iVar7,5);
              uVar10 = (undefined2)uVar5;
              if (iVar3 == 0) {
                iVar11 = FUN_00023358(iVar2 + 0x5a);
                iVar1 = iVar1 + (iVar11 + -1) * 2;
                *(undefined2 *)(iVar1 + 0xb4) = uVar10;
                *(undefined2 *)(iVar1 + 0xc4) = *(undefined2 *)(iVar7 + -0x10);
                func_0x000f671c(&local_58,&local_50,iVar2);
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
              iVar3 = FUN_00023210(0x800c652c,iVar7,5);
              if (iVar3 == 0) {
                iVar2 = FUN_00023358(iVar2 + 0x5a);
                *(undefined2 *)(iVar1 + (iVar2 + -1) * 2 + 0xb8) = uVar10;
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
              iVar3 = FUN_00023210(0x800c6534,iVar7,6);
              if (((iVar3 == 0) || (iVar3 = FUN_00023210(0x800c653c,iVar7,6), iVar3 == 0)) ||
                 ((iVar3 = FUN_00023210(0x800c6544,iVar7,4), iVar3 == 0 && (uVar12 == 0x51)))) {
                *(undefined2 *)(iVar1 + 0xc0) = uVar10;
                uVar6 = *(undefined4 *)(iVar7 + -0x48);
                *(undefined4 *)(iVar1 + 0x102) = *(undefined4 *)(iVar7 + -0x4c);
                *(undefined4 *)(iVar1 + 0x106) = uVar6;
                func_0x000f671c(&local_48,&local_40,iVar2);
                halt_baddata();
              }
              iVar3 = FUN_00023210(0x800c654c,iVar7,7);
              if (iVar3 == 0) {
                *(undefined2 *)(iVar1 + 0xc2) = uVar10;
                func_0x000f671c(&local_58,&local_50,iVar2);
                halt_baddata();
              }
              iVar3 = FUN_00023210(0x800c6554,iVar7,6);
              if (iVar3 == 0) {
                halt_baddata();
              }
              iVar3 = FUN_00023210(0x800c655c,iVar7,6);
              if (iVar3 == 0) {
                uVar9 = uVar8 + 1 & 0xffff;
                local_80[uVar8] = iVar2;
                uVar6 = *(undefined4 *)(iVar7 + -0x48);
                local_f8[uVar8 * 2] = *(undefined4 *)(iVar7 + -0x4c);
                local_f8[uVar8 * 2 + 1] = uVar6;
              }
              iVar7 = iVar7 + 0x74;
              iVar2 = iVar2 + 0x74;
            }
            uVar5 = uVar5 + 1 & 0xffff;
            uVar8 = uVar9;
          } while ((int)uVar5 < iVar11);
        }
        *(undefined2 *)(iVar1 + 0x78) = 0;
        *(short *)(iVar1 + 0x7c) = (short)local_38;
        if (*(short *)(iVar1 + 0xc0) < 0) {
          *(undefined4 *)(iVar1 + 0x80) = 0;
        }
        else {
          *(undefined4 *)(iVar1 + 0x80) = 1;
        }
        if (local_34 < 0x45) {
                    /* WARNING: Could not emulate address calculation at 0x00032030 */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)(local_34 * 4 + -0x7ff39a9c))();
          return;
        }
        *(undefined4 *)(iVar1 + 0x84) = 0;
        if ((*(int *)(iVar1 + 300) == 7) || (*(int *)(iVar1 + 300) == 0x19)) {
          *(undefined2 *)(iVar1 + 0x78) = 0;
        }
        if (*(short *)(iVar1 + 0x88) < 0) {
          *(undefined2 *)(iVar1 + 0x88) = 0;
        }
        *(undefined2 *)(iVar1 + 0xac) = 500;
        if (*(short *)(iVar1 + 0x148) == 0) {
          *(undefined2 *)(iVar1 + 0x8a) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        iVar11 = (*(ushort *)(iVar1 + 0x148) & 0xfff) * 4;
        iVar2 = (int)*(short *)(iVar11 + -0x7ffeb164);
        if (iVar2 == 0) {
          trap(7);
        }
        *(short *)(iVar1 + 0x8a) = (short)((*(short *)(iVar11 + -0x7ffeb162) * 500) / iVar2);
        if (-1 < (int)(short)local_50 - (int)(short)local_58) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        *(short *)(iVar1 + 0x8c) = (short)local_58 - (short)local_50;
        if (-1 < (int)local_50._2_2_ - (int)local_58._2_2_) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        *(short *)(iVar1 + 0x8e) = local_58._2_2_ - local_50._2_2_;
        if (-1 < (int)(short)local_4c - (int)(short)local_54) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        *(short *)(iVar1 + 0x90) = (short)local_54 - (short)local_4c;
        *(short *)(iVar1 + 0x9c) = (short)((int)(short)local_58 + (int)(short)local_50 >> 1);
        *(short *)(iVar1 + 0x9e) = (short)((int)local_58._2_2_ + (int)local_50._2_2_ >> 1);
        *(short *)(iVar1 + 0xa0) = (short)((int)(short)local_54 + (int)(short)local_4c >> 1);
        if (-1 < (int)local_40._2_2_ - (int)local_48._2_2_) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        *(short *)(iVar1 + 0x94) = local_48._2_2_ - local_40._2_2_;
        if (-1 < (int)local_40._2_2_ - (int)local_48._2_2_) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        *(short *)(iVar1 + 0x96) = local_48._2_2_ - local_40._2_2_;
        if (-1 < (int)(short)local_3c - (int)(short)local_44) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        *(short *)(iVar1 + 0x98) = (short)local_44 - (short)local_3c;
        *(short *)(iVar1 + 0xa4) = (short)((int)(short)local_48 + (int)(short)local_40 >> 1);
        *(short *)(iVar1 + 0xa6) = (short)((int)local_48._2_2_ + (int)local_40._2_2_ >> 1);
        *(short *)(iVar1 + 0xa8) = (short)((int)(short)local_44 + (int)(short)local_3c >> 1);
        if (*(uint *)(iVar1 + 300) < 0x54) {
                    /* WARNING: Could not emulate address calculation at 0x000322f0 */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)(*(uint *)(iVar1 + 300) * 4 + -0x7ff39984))();
          return;
        }
        *(undefined2 *)(iVar1 + 0x7a) = 0;
      }
    }
    uVar5 = local_2c & 0xffff;
    psVar4 = local_30;
    uVar12 = local_2c;
    if (0x53 < local_2c) {
      return;
    }
  } while( true );
}


```

## 11. phys_FUN_000475dc @ 0x000475dc  tags:physics  score:46

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_000475dc(int param_1,short param_2)

{
  short sVar1;
  undefined2 uVar2;
  short sVar3;
  int iVar4;
  undefined4 *puVar5;
  ushort uVar6;
  uint uVar7;
  short *psVar8;
  undefined4 uVar9;
  ushort *puVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  int iVar13;
  uint uVar14;
  int iVar15;
  int local_30;
  int local_2c;
  int local_28;
  
  iVar4 = *(int *)(param_1 + 0xd8);
  iVar13 = *(int *)(iVar4 + 0xbc);
  iVar15 = *(int *)(iVar13 + 0xc0);
  uVar14 = (uint)param_2;
  iVar4 = (**(code **)(*(int *)(iVar4 + 4) + 0x1c))(iVar4 + *(short *)(*(int *)(iVar4 + 4) + 0x18));
  if (iVar4 != 3) {
    if (*(int *)(iVar13 + 100) != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    iVar4 = *(int *)(*(int *)(param_1 + 0xd8) + 0x328);
    if (iVar4 == 0) {
      sVar1 = *(short *)(*(int *)(param_1 + 0xd8) + 0x44);
      uVar7 = *(ushort *)(iVar15 + 6) - 2;
      if (uVar7 < 0x4b) {
                    /* WARNING: Could not emulate address calculation at 0x00047838 */
                    /* WARNING: Treating indirect jump as call */
        (**(code **)(uVar7 * 4 + -0x7ff385fc))();
        return;
      }
      uVar9 = *(undefined4 *)((*(uint *)(iVar15 + 0x18) & 0xfff) * 4 + -0x7ffeb164);
      iVar4 = *(int *)(param_1 + 0xd8);
      setCopControlWord(2,0,*(undefined4 *)(iVar4 + 0xe4));
      setCopControlWord(2,0x800,*(undefined4 *)(iVar4 + 0xe8));
      setCopControlWord(2,0x1000,*(undefined4 *)(iVar4 + 0xec));
      setCopControlWord(2,0x1800,*(undefined4 *)(iVar4 + 0xf0));
      setCopControlWord(2,0x2000,*(undefined4 *)(iVar4 + 0xf4));
      if (**(short **)(param_1 + 0xb8) == 0x4d) {
        uVar14 = (int)*(short *)((_DAT_800c0284 & 0x1f) * 0x200 + -0x7ffeb162) >> 4;
        uVar9 = *(undefined4 *)
                 ((*(short *)((_DAT_800c0284 & 0xf) * 0x400 + -0x7ffeb164) + -0x100 >> 3 & 0x3ffcU)
                 + 0x80014e9c);
      }
      *(short *)(param_1 + 0x3e) = -(short)uVar9;
      *(undefined2 *)(param_1 + 0x3c) = 0;
      *(short *)(param_1 + 0x40) = (short)((uint)uVar9 >> 0x10);
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x3c));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
      copFunction(2,0x49e012);
      uVar9 = getCopReg(2,0x4800);
      uVar11 = getCopReg(2,0x5000);
      uVar12 = getCopReg(2,0x5800);
      *(ushort *)(param_1 + 0x3c) = (ushort)uVar9;
      *(short *)(param_1 + 0x3e) = (short)uVar11;
      *(short *)(param_1 + 0x40) = (short)uVar12;
      iVar4 = *(int *)(param_1 + 0xd8);
      setCopControlWord(2,0,*(undefined4 *)(iVar4 + 0xd0));
      setCopControlWord(2,0x800,*(undefined4 *)(iVar4 + 0xd4));
      setCopControlWord(2,0x1000,*(undefined4 *)(iVar4 + 0xd8));
      setCopControlWord(2,0x1800,*(undefined4 *)(iVar4 + 0xdc));
      setCopControlWord(2,0x2000,*(undefined4 *)(iVar4 + 0xe0));
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x3c));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
      copFunction(2,0x49e012);
      puVar10 = (ushort *)(param_1 + 0x3c);
      uVar9 = getCopReg(2,0x4800);
      uVar11 = getCopReg(2,0x5000);
      uVar12 = getCopReg(2,0x5800);
      *puVar10 = (ushort)uVar9;
      *(short *)(param_1 + 0x3e) = (short)uVar11;
      *(short *)(param_1 + 0x40) = (short)uVar12;
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar13 + 0xc4);
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar13 + 200);
      if (uVar14 != 0) {
        uVar7 = *(uint *)((uVar14 & 0xfff) * 4 + -0x7ffeb164);
        uVar14 = (int)uVar7 >> 0x10 & 0xffff;
        setCopControlWord(2,0,uVar14);
        uVar7 = uVar7 & 0xffff;
        setCopControlWord(2,0x2000,uVar14);
        setCopControlWord(2,0x800,uVar7);
        setCopControlWord(2,0x1000,0x1000);
        setCopControlWord(2,0x1800,-uVar7 & 0xffff);
        setCopReg(2,0x4800,(uint)*puVar10);
        setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
        setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
        copFunction(2,0x49e012);
        uVar9 = getCopReg(2,0x4800);
        uVar11 = getCopReg(2,0x5000);
        uVar12 = getCopReg(2,0x5800);
        *puVar10 = (ushort)uVar9;
        *(short *)(param_1 + 0x3e) = (short)uVar11;
        *(short *)(param_1 + 0x40) = (short)uVar12;
      }
      sVar3 = func_0x00105a68(*(undefined4 *)(*(int *)(param_1 + 0xd8) + 0xbc));
      iVar4 = ((int)sVar3 + (int)sVar1) * 0x10000;
      local_28 = iVar4 >> 0x10;
      local_30 = *(short *)(param_1 + 0x3c) * local_28;
      if ((local_30 < 0) && (-0x1000 < local_30)) {
        local_30 = 0;
      }
      local_2c = *(short *)(param_1 + 0x3e) * local_28;
      if ((local_2c < 0) && (-0x1000 < local_2c)) {
        local_2c = 0;
      }
      local_28 = *(short *)(param_1 + 0x40) * local_28;
      if ((local_28 < 0) && (-0x1000 < local_28)) {
        local_28 = 0;
      }
      *(short *)(param_1 + 0x44) = (short)((uint)iVar4 >> 0x10);
      *(short *)(param_1 + 0x34) = (short)(local_30 >> 0xc);
      *(short *)(param_1 + 0x36) = (short)(local_2c >> 0xc);
      *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0xc);
      *(short *)(param_1 + 0x38) = (short)(local_28 >> 0xc);
      *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(param_1 + 8);
      func_0x0010a55c(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                      param_1 + 0x10);
      *(short *)(param_1 + 0x10) = *(short *)(param_1 + 0x10) + -0x400;
      *(ushort *)(param_1 + 0x12) = 0x400U - *(short *)(param_1 + 0x12) & 0xfff;
      func_0x000b0e20(param_1 + 0x10,param_1 + 0x18);
      uVar6 = *(ushort *)(param_1 + 0xc4);
      if ((int)(uint)*(ushort *)(param_1 + 0xc4) < (int)(short)*(ushort *)(param_1 + 0x44)) {
        uVar6 = *(ushort *)(param_1 + 0x44);
      }
      *(ushort *)(param_1 + 0xc4) = uVar6;
      if (0x40 < **(ushort **)(param_1 + 0xb8)) {
        psVar8 = *(short **)(param_1 + 0xb8);
        if (((*psVar8 != 0x53) && (*(int *)(psVar8 + 0x1a) == 0)) && (*(int *)(psVar8 + 0x1c) == 0))
        {
          puVar5 = (undefined4 *)func_0x000ad888();
          uVar9 = (**(code **)(*(int *)(param_1 + 4) + 0x1c))
                            (param_1 + *(short *)(*(int *)(param_1 + 4) + 0x18));
          uVar2 = **(undefined2 **)(param_1 + 0xb8);
          *puVar5 = 0;
          puVar5[1] = 0;
          func_0x000ad8f8(puVar5,uVar9,uVar2);
          *(undefined4 **)(param_1 + 100) = puVar5;
        }
        iVar4 = *(int *)(param_1 + 0xb8);
        if (*(int *)(iVar4 + 0x34) != 0) {
          func_0x0010c1b0(param_1);
          *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;
          iVar4 = *(int *)(param_1 + 0xb8);
        }
        if (*(char *)(iVar4 + 5) == '\x04') {
          uVar9 = func_0x0010834c(param_1);
          *(undefined4 *)(param_1 + 0xd4) = uVar9;
          *(undefined2 *)(param_1 + 0xc2) = *(undefined2 *)(*(int *)(param_1 + 0xb8) + 0x28);
        }
        return;
      }
                    /* WARNING: Could not emulate address calculation at 0x00047be4 */
                    /* WARNING: Treating indirect jump as call */
      (**(code **)((uint)**(ushort **)(param_1 + 0xb8) * 4 + -0x7ff384cc))();
      return;
    }
    func_0x000f2f90(iVar4);
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


```

## 12. phys_FUN_000475dc @ 0x000475dc  tags:physics  score:46

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_000475dc(int param_1,short param_2)

{
  short sVar1;
  undefined2 uVar2;
  short sVar3;
  int iVar4;
  undefined4 *puVar5;
  ushort uVar6;
  uint uVar7;
  short *psVar8;
  undefined4 uVar9;
  ushort *puVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  int iVar13;
  uint uVar14;
  int iVar15;
  int local_30;
  int local_2c;
  int local_28;
  
  iVar4 = *(int *)(param_1 + 0xd8);
  iVar13 = *(int *)(iVar4 + 0xbc);
  iVar15 = *(int *)(iVar13 + 0xc0);
  uVar14 = (uint)param_2;
  iVar4 = (**(code **)(*(int *)(iVar4 + 4) + 0x1c))(iVar4 + *(short *)(*(int *)(iVar4 + 4) + 0x18));
  if (iVar4 != 3) {
    if (*(int *)(iVar13 + 100) != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    iVar4 = *(int *)(*(int *)(param_1 + 0xd8) + 0x328);
    if (iVar4 == 0) {
      sVar1 = *(short *)(*(int *)(param_1 + 0xd8) + 0x44);
      uVar7 = *(ushort *)(iVar15 + 6) - 2;
      if (uVar7 < 0x4b) {
                    /* WARNING: Could not emulate address calculation at 0x00047838 */
                    /* WARNING: Treating indirect jump as call */
        (**(code **)(uVar7 * 4 + -0x7ff385fc))();
        return;
      }
      uVar9 = *(undefined4 *)((*(uint *)(iVar15 + 0x18) & 0xfff) * 4 + -0x7ffeb164);
      iVar4 = *(int *)(param_1 + 0xd8);
      setCopControlWord(2,0,*(undefined4 *)(iVar4 + 0xe4));
      setCopControlWord(2,0x800,*(undefined4 *)(iVar4 + 0xe8));
      setCopControlWord(2,0x1000,*(undefined4 *)(iVar4 + 0xec));
      setCopControlWord(2,0x1800,*(undefined4 *)(iVar4 + 0xf0));
      setCopControlWord(2,0x2000,*(undefined4 *)(iVar4 + 0xf4));
      if (**(short **)(param_1 + 0xb8) == 0x4d) {
        uVar14 = (int)*(short *)((_DAT_800c0284 & 0x1f) * 0x200 + -0x7ffeb162) >> 4;
        uVar9 = *(undefined4 *)
                 ((*(short *)((_DAT_800c0284 & 0xf) * 0x400 + -0x7ffeb164) + -0x100 >> 3 & 0x3ffcU)
                 + 0x80014e9c);
      }
      *(short *)(param_1 + 0x3e) = -(short)uVar9;
      *(undefined2 *)(param_1 + 0x3c) = 0;
      *(short *)(param_1 + 0x40) = (short)((uint)uVar9 >> 0x10);
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x3c));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
      copFunction(2,0x49e012);
      uVar9 = getCopReg(2,0x4800);
      uVar11 = getCopReg(2,0x5000);
      uVar12 = getCopReg(2,0x5800);
      *(ushort *)(param_1 + 0x3c) = (ushort)uVar9;
      *(short *)(param_1 + 0x3e) = (short)uVar11;
      *(short *)(param_1 + 0x40) = (short)uVar12;
      iVar4 = *(int *)(param_1 + 0xd8);
      setCopControlWord(2,0,*(undefined4 *)(iVar4 + 0xd0));
      setCopControlWord(2,0x800,*(undefined4 *)(iVar4 + 0xd4));
      setCopControlWord(2,0x1000,*(undefined4 *)(iVar4 + 0xd8));
      setCopControlWord(2,0x1800,*(undefined4 *)(iVar4 + 0xdc));
      setCopControlWord(2,0x2000,*(undefined4 *)(iVar4 + 0xe0));
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x3c));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
      copFunction(2,0x49e012);
      puVar10 = (ushort *)(param_1 + 0x3c);
      uVar9 = getCopReg(2,0x4800);
      uVar11 = getCopReg(2,0x5000);
      uVar12 = getCopReg(2,0x5800);
      *puVar10 = (ushort)uVar9;
      *(short *)(param_1 + 0x3e) = (short)uVar11;
      *(short *)(param_1 + 0x40) = (short)uVar12;
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar13 + 0xc4);
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar13 + 200);
      if (uVar14 != 0) {
        uVar7 = *(uint *)((uVar14 & 0xfff) * 4 + -0x7ffeb164);
        uVar14 = (int)uVar7 >> 0x10 & 0xffff;
        setCopControlWord(2,0,uVar14);
        uVar7 = uVar7 & 0xffff;
        setCopControlWord(2,0x2000,uVar14);
        setCopControlWord(2,0x800,uVar7);
        setCopControlWord(2,0x1000,0x1000);
        setCopControlWord(2,0x1800,-uVar7 & 0xffff);
        setCopReg(2,0x4800,(uint)*puVar10);
        setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
        setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
        copFunction(2,0x49e012);
        uVar9 = getCopReg(2,0x4800);
        uVar11 = getCopReg(2,0x5000);
        uVar12 = getCopReg(2,0x5800);
        *puVar10 = (ushort)uVar9;
        *(short *)(param_1 + 0x3e) = (short)uVar11;
        *(short *)(param_1 + 0x40) = (short)uVar12;
      }
      sVar3 = func_0x00105a68(*(undefined4 *)(*(int *)(param_1 + 0xd8) + 0xbc));
      iVar4 = ((int)sVar3 + (int)sVar1) * 0x10000;
      local_28 = iVar4 >> 0x10;
      local_30 = *(short *)(param_1 + 0x3c) * local_28;
      if ((local_30 < 0) && (-0x1000 < local_30)) {
        local_30 = 0;
      }
      local_2c = *(short *)(param_1 + 0x3e) * local_28;
      if ((local_2c < 0) && (-0x1000 < local_2c)) {
        local_2c = 0;
      }
      local_28 = *(short *)(param_1 + 0x40) * local_28;
      if ((local_28 < 0) && (-0x1000 < local_28)) {
        local_28 = 0;
      }
      *(short *)(param_1 + 0x44) = (short)((uint)iVar4 >> 0x10);
      *(short *)(param_1 + 0x34) = (short)(local_30 >> 0xc);
      *(short *)(param_1 + 0x36) = (short)(local_2c >> 0xc);
      *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0xc);
      *(short *)(param_1 + 0x38) = (short)(local_28 >> 0xc);
      *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(param_1 + 8);
      func_0x0010a55c(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                      param_1 + 0x10);
      *(short *)(param_1 + 0x10) = *(short *)(param_1 + 0x10) + -0x400;
      *(ushort *)(param_1 + 0x12) = 0x400U - *(short *)(param_1 + 0x12) & 0xfff;
      func_0x000b0e20(param_1 + 0x10,param_1 + 0x18);
      uVar6 = *(ushort *)(param_1 + 0xc4);
      if ((int)(uint)*(ushort *)(param_1 + 0xc4) < (int)(short)*(ushort *)(param_1 + 0x44)) {
        uVar6 = *(ushort *)(param_1 + 0x44);
      }
      *(ushort *)(param_1 + 0xc4) = uVar6;
      if (0x40 < **(ushort **)(param_1 + 0xb8)) {
        psVar8 = *(short **)(param_1 + 0xb8);
        if (((*psVar8 != 0x53) && (*(int *)(psVar8 + 0x1a) == 0)) && (*(int *)(psVar8 + 0x1c) == 0))
        {
          puVar5 = (undefined4 *)func_0x000ad888();
          uVar9 = (**(code **)(*(int *)(param_1 + 4) + 0x1c))
                            (param_1 + *(short *)(*(int *)(param_1 + 4) + 0x18));
          uVar2 = **(undefined2 **)(param_1 + 0xb8);
          *puVar5 = 0;
          puVar5[1] = 0;
          func_0x000ad8f8(puVar5,uVar9,uVar2);
          *(undefined4 **)(param_1 + 100) = puVar5;
        }
        iVar4 = *(int *)(param_1 + 0xb8);
        if (*(int *)(iVar4 + 0x34) != 0) {
          func_0x0010c1b0(param_1);
          *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;
          iVar4 = *(int *)(param_1 + 0xb8);
        }
        if (*(char *)(iVar4 + 5) == '\x04') {
          uVar9 = func_0x0010834c(param_1);
          *(undefined4 *)(param_1 + 0xd4) = uVar9;
          *(undefined2 *)(param_1 + 0xc2) = *(undefined2 *)(*(int *)(param_1 + 0xb8) + 0x28);
        }
        return;
      }
                    /* WARNING: Could not emulate address calculation at 0x00047be4 */
                    /* WARNING: Treating indirect jump as call */
      (**(code **)((uint)**(ushort **)(param_1 + 0xb8) * 4 + -0x7ff384cc))();
      return;
    }
    func_0x000f2f90(iVar4);
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


```

## 13. phys_FUN_00048150 @ 0x00048150  tags:physics  score:33

```c

/* WARNING: Control flow encountered bad instruction data */

void FUN_00048150(int param_1)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  short sVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  undefined4 local_48;
  uint local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  short local_30;
  short sStack_2e;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  iVar5 = *(int *)(param_1 + 0xd8);
  local_48 = *(uint *)(param_1 + 8);
  local_44 = *(uint *)(param_1 + 0xc);
  if ((iVar5 != 0) &&
     (iVar5 = (**(code **)(*(int *)(iVar5 + 4) + 0x1c))
                        (iVar5 + *(short *)(*(int *)(iVar5 + 4) + 0x18)), iVar5 == 0)) {
    iVar5 = *(int *)(param_1 + 0xd8);
    if (*(int *)(iVar5 + 0x268) != 0) {
      local_40 = CONCAT22(*(short *)(*(int *)(iVar5 + 0x268) + 0x6e) - local_48._2_2_,
                          *(short *)(*(int *)(iVar5 + 0x268) + 0x6c) - (short)local_48);
      local_3c = CONCAT22(local_3c._2_2_,
                          *(short *)(*(int *)(iVar5 + 0x268) + 0x70) - (short)local_44);
      local_38 = local_40;
      local_34 = local_3c;
      func_0x00109758(param_1,local_40,local_3c,param_1 + 0x3c);
    }
  }
  uVar9 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x14);
  FUN_00023000(&local_38,0,8);
  local_38._0_2_ = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x3c)) >> 0xc);
  local_38._2_2_ = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x3e)) >> 0xc);
  local_40 = CONCAT22(local_38._2_2_,(short)local_38);
  sVar4 = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x40)) >> 0xc);
  local_34 = CONCAT22(local_34._2_2_,sVar4);
  local_3c = local_34;
  iVar5 = *(int *)(param_1 + 0xdc);
  local_38._0_2_ = (short)local_38 + (short)local_48;
  bVar1 = true;
  local_38._2_2_ = local_38._2_2_ + local_48._2_2_;
  local_34 = CONCAT22(local_34._2_2_,sVar4 + (short)local_44);
  if (iVar5 == 0) {
    iVar5 = *(int *)(param_1 + 0xd8);
  }
  iVar2 = func_0x0006df40(0x4b,&local_48,&local_38,iVar5);
  if (((**(short **)(param_1 + 0xb8) == 5) || (**(short **)(param_1 + 0xb8) == 0x3e)) &&
     (iVar2 == 0)) {
    local_38._2_2_ = local_38._2_2_ + 0x15e;
    local_48._2_2_ = local_48._2_2_ + 300;
    iVar2 = func_0x0006df40(0x4b,&local_48,&local_38,iVar5);
    local_38._2_2_ = local_38._2_2_ + -0x15e;
    local_48 = CONCAT22(local_48._2_2_ + -300,(short)local_48);
  }
  FUN_00023000(&local_28,0,8);
  local_30 = (short)((int)*(short *)(param_1 + 0x3c) >> 4);
  sStack_2e = (short)((int)*(short *)(param_1 + 0x3e) >> 4);
  local_24 = CONCAT22(local_24._2_2_,(short)((int)*(short *)(param_1 + 0x40) >> 4));
  local_2c = local_24;
  iVar5 = param_1 + 8;
  if (iVar2 == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  iVar8 = (*(uint *)(iVar2 + 8) & 0xffff) - (local_48 & 0xffff);
  iVar7 = (*(uint *)(iVar2 + 8) >> 0x10) - (local_48 >> 0x10);
  iVar6 = (*(uint *)(iVar2 + 0xc) & 0xffff) - (local_44 & 0xffff);
  local_28 = CONCAT22((short)iVar7,(short)iVar8);
  iVar7 = (int)*(short *)(param_1 + 0x3c) * (iVar8 * 0x10000 >> 0x10) +
          (int)*(short *)(param_1 + 0x3e) * (iVar7 * 0x10000 >> 0x10) +
          (int)*(short *)(param_1 + 0x40) * (iVar6 * 0x10000 >> 0x10) >> 0xc;
  if (iVar7 < 0) {
    iVar7 = -iVar7;
  }
  local_24._2_2_ = (undefined2)(*(uint *)(iVar2 + 0xc) >> 0x10);
  local_24 = CONCAT22(local_24._2_2_,(short)iVar6);
  if (0x100 < iVar7) {
    iVar7 = func_0x000ab4d0(iVar5);
    if (*(short *)(param_1 + 10) < iVar7) {
      *(short *)(param_1 + 8) = *(short *)(param_1 + 8) + local_30;
      *(short *)(param_1 + 10) = *(short *)(param_1 + 10) + sStack_2e;
      *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + (short)local_2c;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    bVar1 = false;
  }
  if (bVar1) {
    (**(code **)(*(int *)(iVar2 + 4) + 0x3c))
              (iVar2 + *(short *)(*(int *)(iVar2 + 4) + 0x38),param_1);
    FUN_0004033c(2,iVar5,0xfff,*(undefined2 *)(param_1 + 0xea));
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  uVar9 = **(ushort **)(param_1 + 0xb8) - 5;
  if (uVar9 < 0x49) {
                    /* WARNING: Could not emulate address calculation at 0x00048620 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(uVar9 * 4 + -0x7ff383c4))();
    return;
  }
  func_0x00084688(2,&local_48,0);
  uVar3 = func_0x00084204();
  func_0x00087394(uVar3,*(int *)(*(int *)(param_1 + 0xd8) + 0xbc) + 0xc4,iVar5,0x50,0,0);
  return;
}


```

## 14. phys_FUN_00048150 @ 0x00048150  tags:physics  score:33

```c

/* WARNING: Control flow encountered bad instruction data */

void FUN_00048150(int param_1)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  short sVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  undefined4 local_48;
  uint local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  short local_30;
  short sStack_2e;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  iVar5 = *(int *)(param_1 + 0xd8);
  local_48 = *(uint *)(param_1 + 8);
  local_44 = *(uint *)(param_1 + 0xc);
  if ((iVar5 != 0) &&
     (iVar5 = (**(code **)(*(int *)(iVar5 + 4) + 0x1c))
                        (iVar5 + *(short *)(*(int *)(iVar5 + 4) + 0x18)), iVar5 == 0)) {
    iVar5 = *(int *)(param_1 + 0xd8);
    if (*(int *)(iVar5 + 0x268) != 0) {
      local_40 = CONCAT22(*(short *)(*(int *)(iVar5 + 0x268) + 0x6e) - local_48._2_2_,
                          *(short *)(*(int *)(iVar5 + 0x268) + 0x6c) - (short)local_48);
      local_3c = CONCAT22(local_3c._2_2_,
                          *(short *)(*(int *)(iVar5 + 0x268) + 0x70) - (short)local_44);
      local_38 = local_40;
      local_34 = local_3c;
      func_0x00109758(param_1,local_40,local_3c,param_1 + 0x3c);
    }
  }
  uVar9 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x14);
  FUN_00023000(&local_38,0,8);
  local_38._0_2_ = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x3c)) >> 0xc);
  local_38._2_2_ = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x3e)) >> 0xc);
  local_40 = CONCAT22(local_38._2_2_,(short)local_38);
  sVar4 = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x40)) >> 0xc);
  local_34 = CONCAT22(local_34._2_2_,sVar4);
  local_3c = local_34;
  iVar5 = *(int *)(param_1 + 0xdc);
  local_38._0_2_ = (short)local_38 + (short)local_48;
  bVar1 = true;
  local_38._2_2_ = local_38._2_2_ + local_48._2_2_;
  local_34 = CONCAT22(local_34._2_2_,sVar4 + (short)local_44);
  if (iVar5 == 0) {
    iVar5 = *(int *)(param_1 + 0xd8);
  }
  iVar2 = func_0x0006df40(0x4b,&local_48,&local_38,iVar5);
  if (((**(short **)(param_1 + 0xb8) == 5) || (**(short **)(param_1 + 0xb8) == 0x3e)) &&
     (iVar2 == 0)) {
    local_38._2_2_ = local_38._2_2_ + 0x15e;
    local_48._2_2_ = local_48._2_2_ + 300;
    iVar2 = func_0x0006df40(0x4b,&local_48,&local_38,iVar5);
    local_38._2_2_ = local_38._2_2_ + -0x15e;
    local_48 = CONCAT22(local_48._2_2_ + -300,(short)local_48);
  }
  FUN_00023000(&local_28,0,8);
  local_30 = (short)((int)*(short *)(param_1 + 0x3c) >> 4);
  sStack_2e = (short)((int)*(short *)(param_1 + 0x3e) >> 4);
  local_24 = CONCAT22(local_24._2_2_,(short)((int)*(short *)(param_1 + 0x40) >> 4));
  local_2c = local_24;
  iVar5 = param_1 + 8;
  if (iVar2 == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  iVar8 = (*(uint *)(iVar2 + 8) & 0xffff) - (local_48 & 0xffff);
  iVar7 = (*(uint *)(iVar2 + 8) >> 0x10) - (local_48 >> 0x10);
  iVar6 = (*(uint *)(iVar2 + 0xc) & 0xffff) - (local_44 & 0xffff);
  local_28 = CONCAT22((short)iVar7,(short)iVar8);
  iVar7 = (int)*(short *)(param_1 + 0x3c) * (iVar8 * 0x10000 >> 0x10) +
          (int)*(short *)(param_1 + 0x3e) * (iVar7 * 0x10000 >> 0x10) +
          (int)*(short *)(param_1 + 0x40) * (iVar6 * 0x10000 >> 0x10) >> 0xc;
  if (iVar7 < 0) {
    iVar7 = -iVar7;
  }
  local_24._2_2_ = (undefined2)(*(uint *)(iVar2 + 0xc) >> 0x10);
  local_24 = CONCAT22(local_24._2_2_,(short)iVar6);
  if (0x100 < iVar7) {
    iVar7 = func_0x000ab4d0(iVar5);
    if (*(short *)(param_1 + 10) < iVar7) {
      *(short *)(param_1 + 8) = *(short *)(param_1 + 8) + local_30;
      *(short *)(param_1 + 10) = *(short *)(param_1 + 10) + sStack_2e;
      *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + (short)local_2c;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    bVar1 = false;
  }
  if (bVar1) {
    (**(code **)(*(int *)(iVar2 + 4) + 0x3c))
              (iVar2 + *(short *)(*(int *)(iVar2 + 4) + 0x38),param_1);
    FUN_0004033c(2,iVar5,0xfff,*(undefined2 *)(param_1 + 0xea));
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  uVar9 = **(ushort **)(param_1 + 0xb8) - 5;
  if (uVar9 < 0x49) {
                    /* WARNING: Could not emulate address calculation at 0x00048620 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(uVar9 * 4 + -0x7ff383c4))();
    return;
  }
  func_0x00084688(2,&local_48,0);
  uVar3 = func_0x00084204();
  func_0x00087394(uVar3,*(int *)(*(int *)(param_1 + 0xd8) + 0xbc) + 0xc4,iVar5,0x50,0,0);
  return;
}


```

## 15. phys_FUN_0000f8e4 @ 0x0000f8e4  tags:physics  score:33

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_0000f8e4(int *param_1,undefined4 param_2,ushort *param_3,ushort *param_4)

{
  ushort uVar1;
  ushort uVar2;
  short sVar3;
  short sVar4;
  undefined4 uVar5;
  short sVar6;
  short sVar7;
  int iVar8;
  uint uVar9;
  undefined4 local_38;
  uint local_34;
  undefined4 local_30;
  uint local_2c;
  
  local_38 = 0;
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  sVar6 = (short)((uint)*param_4 - (uint)*param_3);
  iVar8 = (int)(((uint)*param_4 - (uint)*param_3) * 0x10000) >> 0x10;
  uVar1 = param_4[1];
  uVar2 = param_3[1];
  if (iVar8 < 0) {
    iVar8 = -iVar8;
  }
  sVar7 = (short)iVar8;
  sVar3 = (short)((uint)param_4[2] - (uint)param_3[2]);
  iVar8 = (int)(((uint)param_4[2] - (uint)param_3[2]) * 0x10000) >> 0x10;
  if (iVar8 < 0) {
    iVar8 = -iVar8;
  }
  sVar4 = (short)iVar8;
  iVar8 = (int)sVar7 - (int)sVar4;
  if (iVar8 < 0) {
    iVar8 = (int)sVar4 - (int)sVar7;
  }
  if (((iVar8 < 0x80) || (sVar7 < 0x80)) || (sVar4 < 0x80)) {
    uVar9 = **(ushort **)(*param_1 + 0x18) - 0x61;
    if (uVar9 < 0x14) {
                    /* WARNING: Could not emulate address calculation at 0x0000fa08 */
                    /* WARNING: Treating indirect jump as call */
      uVar5 = (**(code **)(uVar9 * 4 + -0x7ff3b49c))();
      return uVar5;
    }
    func_0x000d336c(param_1);
  }
  else {
    if (sVar4 < sVar7) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if (0 < sVar3) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    local_38 = *(undefined4 *)param_3;
    local_34 = (uint)(ushort)(sVar3 + sVar7 + param_3[2]);
    local_30 = CONCAT22(param_3[1],sVar6 + *param_3);
    local_2c = (uint)(ushort)(param_3[2] - sVar7);
    iVar8 = func_0x000d1378(*param_1,param_3,&local_38,0x240,0xfffffe00,0);
    if (((iVar8 != 0) || (_DAT_800be5fc != 0)) ||
       (uVar9 = func_0x000ac4e4(&local_38,param_3), (uVar9 & 0x10) != 0)) {
      iVar8 = func_0x000d1378(*param_1,param_3,&local_30,0x240,0xfffffe00,0);
      if (((iVar8 == 0) && (_DAT_800be5fc == 0)) &&
         (uVar9 = func_0x000ac4e4(&local_30), (uVar9 & 0x10) == 0)) {
        iVar8 = func_0x000d1378(*param_1,&local_30,param_4,0x240,0xfffffe00,0);
        if ((iVar8 == 0) && (_DAT_800be5fc == 0)) {
          uVar5 = func_0x000d336c(param_1);
          func_0x000ceeb4(*param_1,uVar5,param_4,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        func_0x000ceeb4(*param_1,*(undefined2 *)(*param_1 + 0x14),param_4,0);
        uVar5 = func_0x000d336c(param_1);
        func_0x000ceeb4(*param_1,uVar5,&local_30,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      func_0x000ceeb4(*param_1,*(undefined2 *)(*param_1 + 0x14),param_4,0);
      local_38 = CONCAT22(param_3[1] + ((short)(uVar1 - uVar2) >> 1),*param_3 + (sVar6 >> 1));
      local_34 = CONCAT22(local_34._2_2_,param_3[2] + (sVar3 >> 1));
      uVar5 = func_0x000d32a4(param_1);
      func_0x000ceeb4(*param_1,uVar5,&local_38,0);
      return 1;
    }
    iVar8 = func_0x000d1378(*param_1,&local_38,param_4,0x240,0xfffffe00,0);
    if ((iVar8 == 0) && (_DAT_800be5fc == 0)) {
      uVar5 = func_0x000d336c(param_1);
      func_0x000ceeb4(*param_1,uVar5,param_4,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    func_0x000ceeb4(*param_1,*(undefined2 *)(*param_1 + 0x14),param_4,0);
    func_0x000d336c(param_1);
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


```

## 16. phys_FUN_0000f8e4 @ 0x0000f8e4  tags:physics  score:33

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_0000f8e4(int *param_1,undefined4 param_2,ushort *param_3,ushort *param_4)

{
  ushort uVar1;
  ushort uVar2;
  short sVar3;
  short sVar4;
  undefined4 uVar5;
  short sVar6;
  short sVar7;
  int iVar8;
  uint uVar9;
  undefined4 local_38;
  uint local_34;
  undefined4 local_30;
  uint local_2c;
  
  local_38 = 0;
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  sVar6 = (short)((uint)*param_4 - (uint)*param_3);
  iVar8 = (int)(((uint)*param_4 - (uint)*param_3) * 0x10000) >> 0x10;
  uVar1 = param_4[1];
  uVar2 = param_3[1];
  if (iVar8 < 0) {
    iVar8 = -iVar8;
  }
  sVar7 = (short)iVar8;
  sVar3 = (short)((uint)param_4[2] - (uint)param_3[2]);
  iVar8 = (int)(((uint)param_4[2] - (uint)param_3[2]) * 0x10000) >> 0x10;
  if (iVar8 < 0) {
    iVar8 = -iVar8;
  }
  sVar4 = (short)iVar8;
  iVar8 = (int)sVar7 - (int)sVar4;
  if (iVar8 < 0) {
    iVar8 = (int)sVar4 - (int)sVar7;
  }
  if (((iVar8 < 0x80) || (sVar7 < 0x80)) || (sVar4 < 0x80)) {
    uVar9 = **(ushort **)(*param_1 + 0x18) - 0x61;
    if (uVar9 < 0x14) {
                    /* WARNING: Could not emulate address calculation at 0x0000fa08 */
                    /* WARNING: Treating indirect jump as call */
      uVar5 = (**(code **)(uVar9 * 4 + -0x7ff3b49c))();
      return uVar5;
    }
    func_0x000d336c(param_1);
  }
  else {
    if (sVar4 < sVar7) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if (0 < sVar3) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    local_38 = *(undefined4 *)param_3;
    local_34 = (uint)(ushort)(sVar3 + sVar7 + param_3[2]);
    local_30 = CONCAT22(param_3[1],sVar6 + *param_3);
    local_2c = (uint)(ushort)(param_3[2] - sVar7);
    iVar8 = func_0x000d1378(*param_1,param_3,&local_38,0x240,0xfffffe00,0);
    if (((iVar8 != 0) || (_DAT_800be5fc != 0)) ||
       (uVar9 = func_0x000ac4e4(&local_38,param_3), (uVar9 & 0x10) != 0)) {
      iVar8 = func_0x000d1378(*param_1,param_3,&local_30,0x240,0xfffffe00,0);
      if (((iVar8 == 0) && (_DAT_800be5fc == 0)) &&
         (uVar9 = func_0x000ac4e4(&local_30), (uVar9 & 0x10) == 0)) {
        iVar8 = func_0x000d1378(*param_1,&local_30,param_4,0x240,0xfffffe00,0);
        if ((iVar8 == 0) && (_DAT_800be5fc == 0)) {
          uVar5 = func_0x000d336c(param_1);
          func_0x000ceeb4(*param_1,uVar5,param_4,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        func_0x000ceeb4(*param_1,*(undefined2 *)(*param_1 + 0x14),param_4,0);
        uVar5 = func_0x000d336c(param_1);
        func_0x000ceeb4(*param_1,uVar5,&local_30,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      func_0x000ceeb4(*param_1,*(undefined2 *)(*param_1 + 0x14),param_4,0);
      local_38 = CONCAT22(param_3[1] + ((short)(uVar1 - uVar2) >> 1),*param_3 + (sVar6 >> 1));
      local_34 = CONCAT22(local_34._2_2_,param_3[2] + (sVar3 >> 1));
      uVar5 = func_0x000d32a4(param_1);
      func_0x000ceeb4(*param_1,uVar5,&local_38,0);
      return 1;
    }
    iVar8 = func_0x000d1378(*param_1,&local_38,param_4,0x240,0xfffffe00,0);
    if ((iVar8 == 0) && (_DAT_800be5fc == 0)) {
      uVar5 = func_0x000d336c(param_1);
      func_0x000ceeb4(*param_1,uVar5,param_4,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    func_0x000ceeb4(*param_1,*(undefined2 *)(*param_1 + 0x14),param_4,0);
    func_0x000d336c(param_1);
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


```

