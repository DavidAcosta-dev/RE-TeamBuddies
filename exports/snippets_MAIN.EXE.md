# Snippets for MAIN.EXE

## 1. phys_FUN_0001cc08 @ 0x0001cc08  tags:physics  score:18

```c

void FUN_0001cc08(void)

{
  int in_v0;
  
                    /* WARNING: Could not recover jumptable at 0x0001cc18. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(in_v0 + -0x7ffc3a14))();
  return;
}


```

## 2. phys_FUN_0001cc08 @ 0x0001cc08  tags:physics  score:18

```c

void FUN_0001cc08(void)

{
  int in_v0;
  
                    /* WARNING: Could not recover jumptable at 0x0001cc18. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(in_v0 + -0x7ffc3a14))();
  return;
}


```

## 3. spu_apply_channel_params @ 0x00014f80  tags:physics  score:41

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Removing unreachable block (ram,0x000150f8) */
/* WARNING: Removing unreachable block (ram,0x0001510c) */
/* WARNING: Removing unreachable block (ram,0x00015114) */
/* WARNING: Removing unreachable block (ram,0x0001511c) */
/* WARNING: Removing unreachable block (ram,0x000151d8) */
/* WARNING: Removing unreachable block (ram,0x000151ec) */
/* WARNING: Removing unreachable block (ram,0x000151f4) */
/* WARNING: Removing unreachable block (ram,0x000151fc) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00014f80(uint *param_1)

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
  puVar9 = (ushort *)&DAT_80042530;
  bVar1 = uVar7 == 0;
  do {
    if ((*param_1 & 1 << (uVar8 & 0x1f)) != 0) {
      if ((bVar1) || ((uVar7 & 0x10) != 0)) {
        *(short *)(uVar8 * 0x10 + _DAT_800424d0 + 4) = (short)param_1[5];
      }
      if ((bVar1) || ((uVar7 & 0x40) != 0)) {
        *puVar9 = (ushort)param_1[6];
      }
      if ((bVar1) || ((uVar7 & 0x20) != 0)) {
        uVar2 = FUN_0002c580(*puVar9 >> 8,*puVar9 & 0xff,*(ushort *)((int)param_1 + 0x16) >> 8,
                             *(ushort *)((int)param_1 + 0x16) & 0xff);
        *(undefined2 *)(uVar8 * 0x10 + _DAT_800424d0 + 4) = uVar2;
      }
      if ((bVar1) || ((uVar7 & 1) != 0)) {
        if (((bVar1) || ((uVar7 & 4) != 0)) &&
           (uVar3 = (int)(((ushort)param_1[3] - 1) * 0x10000) >> 0x10, uVar3 < 7)) {
                    /* WARNING: Could not emulate address calculation at 0x000150ac */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)(uVar3 * 4 + -0x7ffc3fd4))();
          return;
        }
        *(ushort *)(uVar8 * 0x10 + _DAT_800424d0) = (ushort)param_1[2] & 0x7fff;
      }
      if ((bVar1) || ((uVar7 & 2) != 0)) {
        if (((bVar1) || ((uVar7 & 8) != 0)) &&
           (uVar3 = (int)((*(ushort *)((int)param_1 + 0xe) - 1) * 0x10000) >> 0x10, uVar3 < 7)) {
                    /* WARNING: Could not emulate address calculation at 0x0001518c */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)(uVar3 * 4 + -0x7ffc3fb4))();
          return;
        }
        *(ushort *)(uVar8 * 0x10 + _DAT_800424d0 + 2) = *(ushort *)((int)param_1 + 10) & 0x7fff;
      }
      if ((bVar1) || ((uVar7 & 0x80) != 0)) {
        FUN_0002a2e0(uVar8 << 3 | 3,param_1[7]);
      }
      if ((bVar1) || ((uVar7 & 0x10000) != 0)) {
        FUN_0002a2e0(uVar8 << 3 | 7,param_1[8]);
      }
      if ((bVar1) || ((uVar7 & 0x20000) != 0)) {
        *(undefined2 *)(uVar8 * 0x10 + _DAT_800424d0 + 8) = *(undefined2 *)((int)param_1 + 0x3a);
      }
      if ((bVar1) || ((uVar7 & 0x40000) != 0)) {
        *(short *)(uVar8 * 0x10 + _DAT_800424d0 + 10) = (short)param_1[0xf];
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
        iVar4 = uVar8 * 0x10 + _DAT_800424d0;
        *(ushort *)(iVar4 + 8) = *(ushort *)(iVar4 + 8) & 0xff | (uVar5 | uVar6) << 8;
      }
      if ((bVar1) || ((uVar7 & 0x1000) != 0)) {
        uVar5 = *(ushort *)((int)param_1 + 0x32);
        if (0xf < uVar5) {
          uVar5 = 0xf;
        }
        iVar4 = uVar8 * 0x10 + _DAT_800424d0;
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
          if (uVar3 == 5) {
            FUN_0002cc00();
            return;
          }
          if ((int)uVar3 < 6) {
            if (uVar3 != 1) {
              FUN_0002cc00();
              return;
            }
            FUN_0002cc00();
            return;
          }
          if (uVar3 != 7) {
            FUN_0002cc00();
            return;
          }
          uVar6 = 0x300;
        }
        iVar4 = uVar8 * 0x10 + _DAT_800424d0;
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
        iVar4 = uVar8 * 0x10 + _DAT_800424d0;
        *(ushort *)(iVar4 + 10) = *(ushort *)(iVar4 + 10) & 0xffc0 | uVar5 | uVar6;
      }
      if ((bVar1) || ((uVar7 & 0x8000) != 0)) {
        uVar5 = (ushort)param_1[0xe];
        if (0xf < uVar5) {
          uVar5 = 0xf;
        }
        iVar4 = uVar8 * 0x10 + _DAT_800424d0;
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

## 4. phys_FUN_00021c64 @ 0x00021c64  tags:physics  score:16

```c

void FUN_00021c64(void)

{
  int iVar1;
  int unaff_gp;
  
  *(undefined2 *)(unaff_gp + -0x7dec) = 0;
  iVar1 = FUN_0001cc38();
  *(undefined2 *)(unaff_gp + -0x7dee) = 0;
  *(int *)(unaff_gp + -0x7de8) = iVar1 % 0x9c4;
  if ((*(short *)(unaff_gp + -0x7dec) == 1) && ((uint)(int)*(short *)(unaff_gp + -0x7dee) < 7)) {
                    /* WARNING: Could not emulate address calculation at 0x00021cc8 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(*(short *)(unaff_gp + -0x7dee) * 4 + -0x7ffc3814))();
    return;
  }
  return;
}


```

## 5. phys_FUN_00021b4c @ 0x00021b4c  tags:physics  score:15

```c

void FUN_00021b4c(void)

{
  undefined4 in_v0;
  int unaff_s0;
  int unaff_gp;
  
  *(undefined4 *)(unaff_s0 + 0x50) = in_v0;
  FUN_00038414();
  if (*(int *)(unaff_gp + -0x7de4) == 0xf) {
    *(undefined4 *)(unaff_gp + -0x7de4) = 0;
    *(undefined2 *)(unaff_gp + -0x7dee) = 7;
  }
  if ((*(short *)(unaff_gp + -0x7dec) == 1) && ((uint)(int)*(short *)(unaff_gp + -0x7dee) < 7)) {
                    /* WARNING: Could not emulate address calculation at 0x00021cc8 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(*(short *)(unaff_gp + -0x7dee) * 4 + -0x7ffc3814))();
    return;
  }
  return;
}


```

## 6. stub_ret0_FUN_0001cba8 @ 0x0001cba8  tags:auto,physics,ret0  score:14

```c

undefined4 FUN_0001cba8(undefined4 param_1,int param_2,int param_3)

{
  code *in_v0;
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = (*in_v0)();
  if (param_2 < 0) {
    uVar2 = FUN_00034460();
    return uVar2;
  }
  if (param_2 < (int)(uint)*(byte *)(iVar1 + 0xe9)) {
    if (param_3 - 1U < 5) {
                    /* WARNING: Could not emulate address calculation at 0x0001cc10 */
                    /* WARNING: Treating indirect jump as call */
      uVar2 = (**(code **)((param_3 - 1U) * 4 + -0x7ffc3a14))();
      return uVar2;
    }
  }
  return 0;
}


```

## 7. phys_FUN_0001cba8 @ 0x0001cba8  tags:physics  score:14

```c

undefined4 FUN_0001cba8(undefined4 param_1,int param_2,int param_3)

{
  code *in_v0;
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = (*in_v0)();
  if (param_2 < 0) {
    uVar2 = FUN_00034460();
    return uVar2;
  }
  if (param_2 < (int)(uint)*(byte *)(iVar1 + 0xe9)) {
    if (param_3 - 1U < 5) {
                    /* WARNING: Could not emulate address calculation at 0x0001cc10 */
                    /* WARNING: Treating indirect jump as call */
      uVar2 = (**(code **)((param_3 - 1U) * 4 + -0x7ffc3a14))();
      return uVar2;
    }
  }
  return 0;
}


```

## 8. phys_FUN_00021c64 @ 0x00021c64  tags:physics  score:15

```c

void FUN_00021c64(void)

{
  int iVar1;
  int unaff_gp;
  
  *(undefined2 *)(unaff_gp + -0x7dec) = 0;
  iVar1 = FUN_0001cc38();
  *(undefined2 *)(unaff_gp + -0x7dee) = 0;
  *(int *)(unaff_gp + -0x7de8) = iVar1 % 0x9c4;
  if ((*(short *)(unaff_gp + -0x7dec) == 1) && ((uint)(int)*(short *)(unaff_gp + -0x7dee) < 7)) {
                    /* WARNING: Could not emulate address calculation at 0x00021cc8 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(*(short *)(unaff_gp + -0x7dee) * 4 + -0x7ffc3814))();
    return;
  }
  return;
}


```

## 9. phys_FUN_00021b4c @ 0x00021b4c  tags:physics  score:14

```c

void FUN_00021b4c(void)

{
  undefined4 in_v0;
  int unaff_s0;
  int unaff_gp;
  
  *(undefined4 *)(unaff_s0 + 0x50) = in_v0;
  FUN_00038414();
  if (*(int *)(unaff_gp + -0x7de4) == 0xf) {
    *(undefined4 *)(unaff_gp + -0x7de4) = 0;
    *(undefined2 *)(unaff_gp + -0x7dee) = 7;
  }
  if ((*(short *)(unaff_gp + -0x7dec) == 1) && ((uint)(int)*(short *)(unaff_gp + -0x7dee) < 7)) {
                    /* WARNING: Could not emulate address calculation at 0x00021cc8 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(*(short *)(unaff_gp + -0x7dee) * 4 + -0x7ffc3814))();
    return;
  }
  return;
}


```

## 10. stub_ret0_FUN_0001cbb8 @ 0x0001cbb8  tags:auto,physics,ret0  score:13

```c

undefined4 FUN_0001cbb8(undefined4 param_1,undefined4 param_2,int param_3)

{
  code *in_v0;
  int iVar1;
  undefined4 uVar2;
  int unaff_s0;
  
  iVar1 = (*in_v0)();
  if (unaff_s0 < 0) {
    uVar2 = FUN_00034460();
    return uVar2;
  }
  if (unaff_s0 < (int)(uint)*(byte *)(iVar1 + 0xe9)) {
    if (param_3 - 1U < 5) {
                    /* WARNING: Could not emulate address calculation at 0x0001cc10 */
                    /* WARNING: Treating indirect jump as call */
      uVar2 = (**(code **)((param_3 - 1U) * 4 + -0x7ffc3a14))();
      return uVar2;
    }
  }
  return 0;
}


```

## 11. stub_ret0_FUN_0001f340 @ 0x0001f340  tags:auto,physics,ret0  score:13

```c

undefined4 FUN_0001f340(int param_1,uint param_2,int param_3)

{
  undefined4 uVar1;
  int iVar2;
  int unaff_gp;
  
  iVar2 = param_2 * 4;
  if (*(int *)(iVar2 + **(int **)(unaff_gp + -0x7e64) * 0x38 + param_1 + 0x70) + param_3 <
      *(int *)(iVar2 + param_1 + 0xe0)) {
    if (param_2 < 0xe) {
                    /* WARNING: Could not emulate address calculation at 0x0001f3a8 */
                    /* WARNING: Treating indirect jump as call */
      uVar1 = (**(code **)(iVar2 + -0x7ffc39bc))();
      return uVar1;
    }
    FUN_0001cc58(0x80053c28);
  }
  return 0;
}


```

## 12. phys_FUN_0001f340 @ 0x0001f340  tags:physics  score:13

```c

undefined4 FUN_0001f340(int param_1,uint param_2,int param_3)

{
  undefined4 uVar1;
  int iVar2;
  int unaff_gp;
  
  iVar2 = param_2 * 4;
  if (*(int *)(iVar2 + **(int **)(unaff_gp + -0x7e64) * 0x38 + param_1 + 0x70) + param_3 <
      *(int *)(iVar2 + param_1 + 0xe0)) {
    if (param_2 < 0xe) {
                    /* WARNING: Could not emulate address calculation at 0x0001f3a8 */
                    /* WARNING: Treating indirect jump as call */
      uVar1 = (**(code **)(iVar2 + -0x7ffc39bc))();
      return uVar1;
    }
    FUN_0001cc58(0x80053c28);
  }
  return 0;
}


```

## 13. phys_FUN_0001ef54 @ 0x0001ef54  tags:physics  score:14

```c

void FUN_0001ef54(int param_1,uint param_2,undefined4 param_3)

{
  FUN_0001cc58(0x80053be8);
  FUN_000366c8(param_1,param_2 & 0xff);
  if (param_2 < 0xe) {
                    /* WARNING: Could not emulate address calculation at 0x0001efb0 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(param_2 * 4 + -0x7ffc39f4))();
    return;
  }
  FUN_0001cc58(0x80053bfc,param_2);
  *(undefined4 *)(param_2 * 4 + param_1 + 0xe0) = param_3;
  return;
}


```

## 14. phys_FUN_000219ac @ 0x000219ac  tags:physics  score:12

```c

void FUN_000219ac(void)

{
  int iVar1;
  int unaff_gp;
  
  iVar1 = FUN_00038674();
  if (iVar1 != 0) {
    *(undefined2 *)(unaff_gp + -0x7dee) = 2;
  }
  if ((*(short *)(unaff_gp + -0x7dec) == 1) && ((uint)(int)*(short *)(unaff_gp + -0x7dee) < 7)) {
                    /* WARNING: Could not emulate address calculation at 0x00021cc8 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(*(short *)(unaff_gp + -0x7dee) * 4 + -0x7ffc3814))();
    return;
  }
  return;
}


```

## 15. stub_ret0_FUN_0001cbd8 @ 0x0001cbd8  tags:auto,physics,ret0  score:12

```c

undefined4 FUN_0001cbd8(void)

{
  undefined4 uVar1;
  int in_v1;
  int unaff_s0;
  int unaff_s1;
  
  if (unaff_s0 < (int)(uint)*(byte *)(in_v1 + 0xe9)) {
    if (unaff_s1 - 1U < 5) {
                    /* WARNING: Could not emulate address calculation at 0x0001cc10 */
                    /* WARNING: Treating indirect jump as call */
      uVar1 = (**(code **)((unaff_s1 - 1U) * 4 + -0x7ffc3a14))();
      return uVar1;
    }
  }
  return 0;
}


```

## 16. phys_FUN_0001cbb8 @ 0x0001cbb8  tags:physics  score:12

```c

undefined4 FUN_0001cbb8(undefined4 param_1,undefined4 param_2,int param_3)

{
  code *in_v0;
  int iVar1;
  undefined4 uVar2;
  int unaff_s0;
  
  iVar1 = (*in_v0)();
  if (unaff_s0 < 0) {
    uVar2 = FUN_00034460();
    return uVar2;
  }
  if (unaff_s0 < (int)(uint)*(byte *)(iVar1 + 0xe9)) {
    if (param_3 - 1U < 5) {
                    /* WARNING: Could not emulate address calculation at 0x0001cc10 */
                    /* WARNING: Treating indirect jump as call */
      uVar2 = (**(code **)((param_3 - 1U) * 4 + -0x7ffc3a14))();
      return uVar2;
    }
  }
  return 0;
}


```

