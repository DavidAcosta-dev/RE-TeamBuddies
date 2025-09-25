# Gravity Vertical Field Patterns

Target functions scanned: 23

## FUN_00006dd0

VertRefs: 0  Shifts: 1

_No vertical offset context blocks._

## FUN_0001eb14

VertRefs: 0  Shifts: 0

_No vertical offset context blocks._

## FUN_0001ec7c

VertRefs: 4  Shifts: 1

  }
  *(undefined2 *)(piVar6 + 0x13) = 0xa00;
  uVar4 = 0x19;
  if (*(int *)(param_2 + 0x3c) != 0) {
    uVar4 = param_2[0x3c];
  }
  *(ushort *)((int)piVar6 + 0x4e) = uVar4;
---
    trap(7);
  }
  piVar6[0x14] = (int)(((uint)*(ushort *)(piVar6 + 0x13) << 0xc) / (uint)uVar4) >> 0xc;
  iVar3 = *(int *)(param_2 + 0x34);
  if (iVar3 == 0) {
    iVar3 = 4000;
  }
---
  piVar6[0x15] = iVar3;
  piVar6[0x16] = 0x1000;
  uVar2 = 8;
  if (*(int *)(param_2 + 0x38) != 0) {
    uVar2 = param_2[0x38];
  }
  *(undefined2 *)(piVar6 + 0x17) = uVar2;
---
  }
  *(undefined2 *)(piVar6 + 0x17) = uVar2;
  uVar2 = 10;
  if (*(int *)(param_2 + 0x36) != 0) {
    uVar2 = param_2[0x36];
  }
  *(undefined2 *)((int)piVar6 + 0x5e) = uVar2;
---
## FUN_000211b0

VertRefs: 0  Shifts: 0

_No vertical offset context blocks._

## FUN_00022e5c

VertRefs: 8  Shifts: 3

                          (int)sStack00000022 * (int)sStack00000022 +
                          (int)sStack00000024 * (int)sStack00000024);
    iVar10 = (iVar10 + -300) * 0x10000 >> 0x10;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar10 * (iVar5 >> uVar7) >> 0xf))
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x34) = sVar3;
    sVar9 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar10 * (iVar8 >> uVar1) >> 0xf))
---
    iVar10 = (iVar10 + -300) * 0x10000 >> 0x10;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar10 * (iVar5 >> uVar7) >> 0xf))
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x34) = sVar3;
    sVar9 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar10 * (iVar8 >> uVar1) >> 0xf))
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x36) = sVar9;
---
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar10 * (iVar5 >> uVar7) >> 0xf))
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x34) = sVar3;
    sVar9 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar10 * (iVar8 >> uVar1) >> 0xf))
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x36) = sVar9;
    *(short *)(unaff_s2 + 8) = *(short *)(unaff_s2 + 8) + sVar3;
---
    *(short *)(unaff_s2 + 0x34) = sVar3;
    sVar9 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar10 * (iVar8 >> uVar1) >> 0xf))
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x36) = sVar9;
    *(short *)(unaff_s2 + 8) = *(short *)(unaff_s2 + 8) + sVar3;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x38) - (iVar10 * (iVar6 >> uVar2) >> 0xf))
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
---
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x36) = sVar9;
    *(short *)(unaff_s2 + 8) = *(short *)(unaff_s2 + 8) + sVar3;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x38) - (iVar10 * (iVar6 >> uVar2) >> 0xf))
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x38) = sVar3;
    *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + sVar9;
---
    *(short *)(unaff_s2 + 8) = *(short *)(unaff_s2 + 8) + sVar3;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x38) - (iVar10 * (iVar6 >> uVar2) >> 0xf))
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x38) = sVar3;
    *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + sVar9;
    *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar3;
    iVar10 = func_0x000ab4d0(unaff_s2 + 8);
---
    iVar10 = -(iVar11 * 0x10000 >> 0x10) * iVar6 - (iVar5 * 0x10000 >> 0x10) * iVar8 >> 0xc;
    if (iVar10 < 0) {
      iVar10 = iVar10 + -10;
      *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);
      *(short *)(unaff_s2 + 0x38) = (short)(-iVar8 >> 7);
      *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar10 * iVar6) >> 0xc);
      *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar10 * iVar8) >> 0xc);
---
    if (iVar10 < 0) {
      iVar10 = iVar10 + -10;
      *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);
      *(short *)(unaff_s2 + 0x38) = (short)(-iVar8 >> 7);
      *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar10 * iVar6) >> 0xc);
      *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar10 * iVar8) >> 0xc);
    }
---
## FUN_00023000

VertRefs: 8  Shifts: 2

  iVar3 = FUN_00023180((int)(short)param_9 * (int)(short)param_9 +
                       (int)param_9._2_2_ * (int)param_9._2_2_ + (int)param_10 * (int)param_10);
  iVar3 = (iVar3 + -300) * 0x10000 >> 0x10;
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar3 * param_11 >> 0xf)) * 0x10000)
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x34) = sVar1;
  sVar5 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar3 * param_12 >> 0xf)) * 0x10000)
---
  iVar3 = (iVar3 + -300) * 0x10000 >> 0x10;
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar3 * param_11 >> 0xf)) * 0x10000)
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x34) = sVar1;
  sVar5 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar3 * param_12 >> 0xf)) * 0x10000)
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x36) = sVar5;
---
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar3 * param_11 >> 0xf)) * 0x10000)
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x34) = sVar1;
  sVar5 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar3 * param_12 >> 0xf)) * 0x10000)
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x36) = sVar5;
  *(short *)(unaff_s2 + 8) = *(short *)(unaff_s2 + 8) + sVar1;
---
  *(short *)(unaff_s2 + 0x34) = sVar1;
  sVar5 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar3 * param_12 >> 0xf)) * 0x10000)
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x36) = sVar5;
  *(short *)(unaff_s2 + 8) = *(short *)(unaff_s2 + 8) + sVar1;
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x38) -
                         (iVar3 * (param_13 * param_2 >> (in_stack_00000040 & 0x1f)) >> 0xf)) *
---
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x36) = sVar5;
  *(short *)(unaff_s2 + 8) = *(short *)(unaff_s2 + 8) + sVar1;
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x38) -
                         (iVar3 * (param_13 * param_2 >> (in_stack_00000040 & 0x1f)) >> 0xf)) *
                        0x10000) >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x38) = sVar1;
---
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x38) -
                         (iVar3 * (param_13 * param_2 >> (in_stack_00000040 & 0x1f)) >> 0xf)) *
                        0x10000) >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x38) = sVar1;
  *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + sVar5;
  *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar1;
  iVar3 = func_0x000ab4d0(unaff_s2 + 8);
---
          0xc;
  if (iVar3 < 0) {
    iVar3 = iVar3 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar4 >> 7);
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar3 * iVar6) >> 0xc);
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar3 * iVar4) >> 0xc);
---
  if (iVar3 < 0) {
    iVar3 = iVar3 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar4 >> 7);
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar3 * iVar6) >> 0xc);
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar3 * iVar4) >> 0xc);
  }
---
## FUN_00023180

VertRefs: 2  Shifts: 3

  iVar2 = -(iVar3 * 0x10000 >> 0x10) * iVar6 - (iVar4 * 0x10000 >> 0x10) * iVar5 >> 0xc;
  if (iVar2 < 0) {
    iVar2 = iVar2 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar5 >> 7);
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar2 * iVar6) >> 0xc);
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar2 * iVar5) >> 0xc);
---
  if (iVar2 < 0) {
    iVar2 = iVar2 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar5 >> 7);
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar2 * iVar6) >> 0xc);
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar2 * iVar5) >> 0xc);
  }
---
## FUN_00023698

VertRefs: 1  Shifts: 2

  int iVar5;
  
  iVar5 = (*(ushort *)(param_1 + 0xd4) & 0xfff) * 4;
  *(short *)(param_1 + 10) = *(short *)(param_1 + 10) + (*(short *)(param_1 + 0x36) >> 6);
  uVar4 = (int)((uint)*(ushort *)(param_1 + 0xd6) * (int)*(short *)(iVar5 + -0x7ffeb164)) >> 0xc;
  *(short *)(param_1 + 0x10) = (short)uVar4;
  uVar3 = (int)((uint)*(ushort *)(param_1 + 0xd6) * (int)*(short *)(iVar5 + -0x7ffeb162)) >> 0xc;
---
## FUN_0002566c

VertRefs: 0  Shifts: 0

_No vertical offset context blocks._

## FUN_00026c68

VertRefs: 8  Shifts: 3

  int iVar5;
  int iVar6;
  
  iVar5 = (uint)*(ushort *)(param_1 + 0x36) << 0x10;
  iVar4 = iVar5 >> 0x10;
  iVar6 = param_1 + 8;
  if (iVar4 < 0x1001) {
---
    sVar2 = *(short *)(param_1 + 10);
    iVar4 = func_0x000ab4d0(iVar6);
    if (iVar4 < (int)sVar2 + (iVar5 >> 0x16)) {
      *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x36) * -0x400 >> 0xc);
      uVar1 = func_0x000ab4d0(iVar6);
      *(undefined2 *)(param_1 + 10) = uVar1;
      uVar3 = FUN_000209dc();
---
      uVar3 = FUN_000209dc();
      iVar4 = *(int *)(((uVar3 & 0x7f) - 0x40 & 0xfff) * 4 + -0x7ffeb164);
      iVar5 = (int)(short)iVar4;
      sVar2 = (short)((iVar4 >> 0x10) * (int)*(short *)(param_1 + 0x34) -
                      iVar5 * *(short *)(param_1 + 0x38) >> 0xc);
      *(short *)(param_1 + 0x34) = sVar2;
      *(short *)(param_1 + 0x38) =
---
      iVar4 = *(int *)(((uVar3 & 0x7f) - 0x40 & 0xfff) * 4 + -0x7ffeb164);
      iVar5 = (int)(short)iVar4;
      sVar2 = (short)((iVar4 >> 0x10) * (int)*(short *)(param_1 + 0x34) -
                      iVar5 * *(short *)(param_1 + 0x38) >> 0xc);
      *(short *)(param_1 + 0x34) = sVar2;
      *(short *)(param_1 + 0x38) =
           (short)(((int)sVar2 + (int)*(short *)(param_1 + 0x38)) * iVar5 >> 0xc);
---
      iVar5 = (int)(short)iVar4;
      sVar2 = (short)((iVar4 >> 0x10) * (int)*(short *)(param_1 + 0x34) -
                      iVar5 * *(short *)(param_1 + 0x38) >> 0xc);
      *(short *)(param_1 + 0x34) = sVar2;
      *(short *)(param_1 + 0x38) =
           (short)(((int)sVar2 + (int)*(short *)(param_1 + 0x38)) * iVar5 >> 0xc);
      FUN_000402e0(0x18,iVar6,3000);
---
      sVar2 = (short)((iVar4 >> 0x10) * (int)*(short *)(param_1 + 0x34) -
                      iVar5 * *(short *)(param_1 + 0x38) >> 0xc);
      *(short *)(param_1 + 0x34) = sVar2;
      *(short *)(param_1 + 0x38) =
           (short)(((int)sVar2 + (int)*(short *)(param_1 + 0x38)) * iVar5 >> 0xc);
      FUN_000402e0(0x18,iVar6,3000);
                    /* WARNING: Bad instruction - Truncating control flow here */
---
                      iVar5 * *(short *)(param_1 + 0x38) >> 0xc);
      *(short *)(param_1 + 0x34) = sVar2;
      *(short *)(param_1 + 0x38) =
           (short)(((int)sVar2 + (int)*(short *)(param_1 + 0x38)) * iVar5 >> 0xc);
      FUN_000402e0(0x18,iVar6,3000);
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
---
## FUN_00032c18

VertRefs: 0  Shifts: 9

_No vertical offset context blocks._

## FUN_00040a4c

VertRefs: 6  Shifts: 3

  *(undefined4 *)(param_1 + 0xf0) = _DAT_800c02ac;
  if (bVar1) {
    uVar11 = 0;
    if (*(short *)(*(int *)(param_1 + 0xc0) + 0x3e) != 0) {
      do {
        if ((*(ushort *)(*(int *)(param_1 + 0xc0) + 0x42) & 1) != 0) {
          iVar10 = (uint)*(ushort *)(*(int *)(param_1 + 0xc0) + 0xe) << 0x10;
---
          iVar10 = (uint)*(ushort *)(*(int *)(param_1 + 0xc0) + 0xe) << 0x10;
          uVar7 = FUN_000209dc();
          uVar8 = FUN_000209dc();
          iVar6 = (uVar8 & 0xfff) + 0x400;
          if (iVar6 == 0) {
            trap(7);
          }
---
          *(undefined2 *)(param_1 + 0xea) = 0;
        }
        uVar11 = uVar11 + 1;
      } while (uVar11 < *(ushort *)(*(int *)(param_1 + 0xc0) + 0x3e));
    }
    iVar6 = *(int *)(*(int *)(param_1 + 0xd4) + 4);
    iVar6 = (**(code **)(iVar6 + 0x1c))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar6 + 0x18));
---
    iVar6 = (**(code **)(iVar6 + 0x1c))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar6 + 0x18));
    if (iVar6 == 0) {
      iVar6 = *(int *)(param_1 + 0xd4);
      iVar10 = (int)*(short *)(*(int *)(param_1 + 0xc0) + 0x40);
      *(short *)(iVar6 + 0x114) =
           *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);
      iVar6 = *(int *)(param_1 + 0xd4);
---
      iVar6 = *(int *)(*(int *)(param_1 + 0xd4) + 4);
      iVar6 = (**(code **)(iVar6 + 0x1c))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar6 + 0x18));
      if ((iVar6 == 3) && (iVar6 = *(int *)(param_1 + 0xd4), *(int *)(iVar6 + 0x164) != 0xb)) {
        uVar7 = FUN_00022e5c((int)*(short *)(iVar10 + 0x3c),(int)*(short *)(iVar10 + 0x40));
        iVar10 = (uVar7 & 0xfff) * 4;
        (**(code **)(*(int *)(iVar6 + 4) + 0x84))
                  (iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x80),
---
## FUN_00040a98

VertRefs: 6  Shifts: 3

    *(undefined4 *)(unaff_s1 + 0xf0) = _DAT_800c02ac;
    if (bVar1) {
      uVar11 = 0;
      if (*(short *)(*(int *)(unaff_s1 + 0xc0) + 0x3e) != 0) {
        do {
          if ((*(ushort *)(*(int *)(unaff_s1 + 0xc0) + 0x42) & 1) != 0) {
            iVar10 = (uint)*(ushort *)(*(int *)(unaff_s1 + 0xc0) + 0xe) << 0x10;
---
            iVar10 = (uint)*(ushort *)(*(int *)(unaff_s1 + 0xc0) + 0xe) << 0x10;
            uVar7 = FUN_000209dc();
            uVar8 = FUN_000209dc();
            iVar6 = (uVar8 & 0xfff) + 0x400;
            if (iVar6 == 0) {
              trap(7);
            }
---
            *(undefined2 *)(unaff_s1 + 0xea) = 0;
          }
          uVar11 = uVar11 + 1;
        } while (uVar11 < *(ushort *)(*(int *)(unaff_s1 + 0xc0) + 0x3e));
      }
      iVar6 = *(int *)(*(int *)(unaff_s1 + 0xd4) + 4);
      iVar6 = (**(code **)(iVar6 + 0x1c))(*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x18))
---
      ;
      if (iVar6 == 0) {
        iVar6 = *(int *)(unaff_s1 + 0xd4);
        iVar10 = (int)*(short *)(*(int *)(unaff_s1 + 0xc0) + 0x40);
        *(short *)(iVar6 + 0x114) =
             *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);
        iVar6 = *(int *)(unaff_s1 + 0xd4);
---
        iVar6 = (**(code **)(iVar6 + 0x1c))
                          (*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x18));
        if ((iVar6 == 3) && (iVar6 = *(int *)(unaff_s1 + 0xd4), *(int *)(iVar6 + 0x164) != 0xb)) {
          uVar7 = FUN_00022e5c((int)*(short *)(unaff_s2 + 0x3c),(int)*(short *)(unaff_s2 + 0x40));
          iVar10 = (uVar7 & 0xfff) * 4;
          (**(code **)(*(int *)(iVar6 + 4) + 0x84))
                    (iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x80),
---
## FUN_000438fc

VertRefs: 12  Shifts: 2

    cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 5);
    if (cVar1 != '\x01') {
      if (((cVar1 == '\x06') && ((*(uint *)(param_1 + 0x50) & 4) != 0)) &&
         (0 < *(short *)(param_1 + 0x36))) {
        bVar4 = 1;
      }
      if ((*(uint *)(param_1 + 0xd0) & 4) != 0) {
---
        bVar4 = 1;
      }
      if ((*(uint *)(param_1 + 0xd0) & 4) != 0) {
        iVar7 = *(int *)(param_1 + 0xbc) - (int)*(short *)(param_1 + 0x44);
        *(int *)(param_1 + 0xbc) = iVar7;
        if (iVar7 < 0) {
          iVar7 = 0;
---
          if (iVar7 != 0) {
            uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x18);
            if (uVar8 != 0) {
              *(short *)(param_1 + 0x34) =
                   -(short)((int)(uVar8 * (int)*(short *)(param_1 + 0x34)) >> 0xc);
              *(short *)(param_1 + 0x38) =
                   -(short)((int)(uVar8 * (int)*(short *)(param_1 + 0x38)) >> 0xc);
---
            uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x18);
            if (uVar8 != 0) {
              *(short *)(param_1 + 0x34) =
                   -(short)((int)(uVar8 * (int)*(short *)(param_1 + 0x34)) >> 0xc);
              *(short *)(param_1 + 0x38) =
                   -(short)((int)(uVar8 * (int)*(short *)(param_1 + 0x38)) >> 0xc);
                    /* WARNING: Bad instruction - Truncating control flow here */
---
            if (uVar8 != 0) {
              *(short *)(param_1 + 0x34) =
                   -(short)((int)(uVar8 * (int)*(short *)(param_1 + 0x34)) >> 0xc);
              *(short *)(param_1 + 0x38) =
                   -(short)((int)(uVar8 * (int)*(short *)(param_1 + 0x38)) >> 0xc);
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
---
              *(short *)(param_1 + 0x34) =
                   -(short)((int)(uVar8 * (int)*(short *)(param_1 + 0x34)) >> 0xc);
              *(short *)(param_1 + 0x38) =
                   -(short)((int)(uVar8 * (int)*(short *)(param_1 + 0x38)) >> 0xc);
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
---
            if (iVar12 != 0) {
              *(undefined4 *)(iVar12 + 0x338) = *(undefined4 *)(param_1 + 8);
              uVar6 = *(undefined4 *)(param_1 + 0xc);
              *(undefined4 *)(iVar12 + 0x340) = uVar5;
              *(undefined4 *)(iVar12 + 0x33c) = uVar6;
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
---
            iVar12 = *(int *)(param_1 + 0xd8);
            *(undefined4 *)(iVar12 + 0x338) = *(undefined4 *)(param_1 + 8);
            uVar6 = *(undefined4 *)(param_1 + 0xc);
            *(undefined4 *)(iVar12 + 0x340) = uVar5;
            *(undefined4 *)(iVar12 + 0x33c) = uVar6;
          }
        }
---
              *(uint *)(iVar12 + 0x98) = uVar8 * uVar8;
              *(undefined4 *)(iVar12 + 8) = *(undefined4 *)(param_1 + 8);
              *(undefined4 *)(iVar12 + 0xc) = *(undefined4 *)(param_1 + 0xc);
              *(undefined4 *)(iVar12 + 0x3c) = *(undefined4 *)(param_1 + 0x3c);
              *(undefined4 *)(iVar12 + 0x40) = *(undefined4 *)(param_1 + 0x40);
              if (*(int *)(param_1 + 0xdc) != 0) {
                *(int *)(iVar12 + 0xdc) = *(int *)(param_1 + 0xdc);
---
              *(undefined4 *)(iVar12 + 8) = *(undefined4 *)(param_1 + 8);
              *(undefined4 *)(iVar12 + 0xc) = *(undefined4 *)(param_1 + 0xc);
              *(undefined4 *)(iVar12 + 0x3c) = *(undefined4 *)(param_1 + 0x3c);
              *(undefined4 *)(iVar12 + 0x40) = *(undefined4 *)(param_1 + 0x40);
              if (*(int *)(param_1 + 0xdc) != 0) {
                *(int *)(iVar12 + 0xdc) = *(int *)(param_1 + 0xdc);
                func_0x00074950(iVar12);
---
## FUN_000443b8

VertRefs: 5  Shifts: 1

      if ((0 < (int)(((uint)*(ushort *)(param_2 + 0xb0) - (uint)*(ushort *)(param_2 + 0xb2)) *
                    0x10000)) && ((iVar2 != 0 || (**(int **)(param_2 + 0x11c) != 0x22)))) {
        iVar3 = *(int *)(param_1 + 0xd8);
        if ((iVar3 != 0) && ((*(int *)(*(int *)(param_1 + 0xb8) + 0x34) == 0 && (iVar2 == 0)))) {
          iVar3 = (**(code **)(*(int *)(iVar3 + 4) + 0x1c))
                            (iVar3 + *(short *)(*(int *)(iVar3 + 4) + 0x18));
          if (iVar3 == 3) {
---
            local_24 = local_34;
            local_28 = uVar1;
            func_0x00109758(param_1,uVar1,local_34,&local_30);
            iVar3 = (int)local_30 * (int)*(short *)(param_1 + 0x3c) +
                    (int)local_2e * (int)*(short *)(param_1 + 0x3e) +
                    (int)local_2c * (int)*(short *)(param_1 + 0x40) >> 0xc;
            if (*(int *)(*(int *)(param_1 + 0xb8) + 0x38) == 0) {
---
            local_28 = uVar1;
            func_0x00109758(param_1,uVar1,local_34,&local_30);
            iVar3 = (int)local_30 * (int)*(short *)(param_1 + 0x3c) +
                    (int)local_2e * (int)*(short *)(param_1 + 0x3e) +
                    (int)local_2c * (int)*(short *)(param_1 + 0x40) >> 0xc;
            if (*(int *)(*(int *)(param_1 + 0xb8) + 0x38) == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
---
            func_0x00109758(param_1,uVar1,local_34,&local_30);
            iVar3 = (int)local_30 * (int)*(short *)(param_1 + 0x3c) +
                    (int)local_2e * (int)*(short *)(param_1 + 0x3e) +
                    (int)local_2c * (int)*(short *)(param_1 + 0x40) >> 0xc;
            if (*(int *)(*(int *)(param_1 + 0xb8) + 0x38) == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
---
            iVar3 = (int)local_30 * (int)*(short *)(param_1 + 0x3c) +
                    (int)local_2e * (int)*(short *)(param_1 + 0x3e) +
                    (int)local_2c * (int)*(short *)(param_1 + 0x40) >> 0xc;
            if (*(int *)(*(int *)(param_1 + 0xb8) + 0x38) == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
---
## FUN_00044754

VertRefs: 3  Shifts: 1

  local_18 = local_28;
  local_14 = local_24;
  func_0x00109758(param_1,local_28,local_24,&local_20);
  if ((int)local_20 * (int)*(short *)(param_1 + 0x3c) +
      (int)local_1e * (int)*(short *)(param_1 + 0x3e) +
      (int)local_1c * (int)*(short *)(param_1 + 0x40) >> 0xc <
      (int)*(short *)((*(ushort *)(*(int *)(param_1 + 0xb8) + 0x26) & 0xfff) * 4 + -0x7ffeb162)) {
---
  local_14 = local_24;
  func_0x00109758(param_1,local_28,local_24,&local_20);
  if ((int)local_20 * (int)*(short *)(param_1 + 0x3c) +
      (int)local_1e * (int)*(short *)(param_1 + 0x3e) +
      (int)local_1c * (int)*(short *)(param_1 + 0x40) >> 0xc <
      (int)*(short *)((*(ushort *)(*(int *)(param_1 + 0xb8) + 0x26) & 0xfff) * 4 + -0x7ffeb162)) {
    *param_2 = 0;
---
  func_0x00109758(param_1,local_28,local_24,&local_20);
  if ((int)local_20 * (int)*(short *)(param_1 + 0x3c) +
      (int)local_1e * (int)*(short *)(param_1 + 0x3e) +
      (int)local_1c * (int)*(short *)(param_1 + 0x40) >> 0xc <
      (int)*(short *)((*(ushort *)(*(int *)(param_1 + 0xb8) + 0x26) & 0xfff) * 4 + -0x7ffeb162)) {
    *param_2 = 0;
  }
---
## FUN_00044a14

VertRefs: 36  Shifts: 6

  
  iVar2 = func_0x000ab4d0(param_1 + 8);
  if ((*(short *)(*(int *)(param_1 + 0xb8) + 0x18) != 0) &&
     ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44))) {
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) | 4;
  }
  if (*(short *)(param_1 + 10) <= iVar2) {
---
    return;
  }
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 5) == '\x04') && (0 < *(int *)(param_1 + 0xbc))) {
    if ((*(short *)(param_1 + 0x34) != 0) || (*(short *)(param_1 + 0x38) != 0)) {
      *(undefined2 *)(param_1 + 0x36) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
---
  }
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 5) == '\x04') && (0 < *(int *)(param_1 + 0xbc))) {
    if ((*(short *)(param_1 + 0x34) != 0) || (*(short *)(param_1 + 0x38) != 0)) {
      *(undefined2 *)(param_1 + 0x36) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
---
      halt_baddata();
    }
    uVar1 = 0xffff;
    if (*(short *)(param_1 + 0x36) == 0) {
      uVar1 = 0xfff6;
    }
    *(undefined2 *)(param_1 + 0x36) = uVar1;
---
    if (*(short *)(param_1 + 0x36) == 0) {
      uVar1 = 0xfff6;
    }
    *(undefined2 *)(param_1 + 0x36) = uVar1;
    *(short *)(param_1 + 0x44) =
         (short)((int)*(short *)(param_1 + 0x3c) * (int)*(short *)(param_1 + 0x34) +
                 (int)*(short *)(param_1 + 0x3e) * (int)*(short *)(param_1 + 0x36) +
---
      uVar1 = 0xfff6;
    }
    *(undefined2 *)(param_1 + 0x36) = uVar1;
    *(short *)(param_1 + 0x44) =
         (short)((int)*(short *)(param_1 + 0x3c) * (int)*(short *)(param_1 + 0x34) +
                 (int)*(short *)(param_1 + 0x3e) * (int)*(short *)(param_1 + 0x36) +
                 (int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc);
---
    }
    *(undefined2 *)(param_1 + 0x36) = uVar1;
    *(short *)(param_1 + 0x44) =
         (short)((int)*(short *)(param_1 + 0x3c) * (int)*(short *)(param_1 + 0x34) +
                 (int)*(short *)(param_1 + 0x3e) * (int)*(short *)(param_1 + 0x36) +
                 (int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc);
    uVar1 = func_0x000ab4d0(param_1 + 8);
---
    *(undefined2 *)(param_1 + 0x36) = uVar1;
    *(short *)(param_1 + 0x44) =
         (short)((int)*(short *)(param_1 + 0x3c) * (int)*(short *)(param_1 + 0x34) +
                 (int)*(short *)(param_1 + 0x3e) * (int)*(short *)(param_1 + 0x36) +
                 (int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc);
    uVar1 = func_0x000ab4d0(param_1 + 8);
    *(undefined2 *)(param_1 + 10) = uVar1;
---
    *(short *)(param_1 + 0x44) =
         (short)((int)*(short *)(param_1 + 0x3c) * (int)*(short *)(param_1 + 0x34) +
                 (int)*(short *)(param_1 + 0x3e) * (int)*(short *)(param_1 + 0x36) +
                 (int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc);
    uVar1 = func_0x000ab4d0(param_1 + 8);
    *(undefined2 *)(param_1 + 10) = uVar1;
    iVar2 = func_0x000a9678((int)*(short *)(param_1 + 8),(int)*(short *)(param_1 + 0xc));
---
    *(undefined2 *)(param_1 + 10) = uVar1;
    iVar2 = func_0x000a9678((int)*(short *)(param_1 + 8),(int)*(short *)(param_1 + 0xc));
    if (iVar2 != 0) {
      *(undefined2 *)(param_1 + 0x44) = 0;
    }
    func_0x00109ff4(param_1);
    if (*(short *)(param_1 + 0x44) == 0) {
---
      *(undefined2 *)(param_1 + 0x44) = 0;
    }
    func_0x00109ff4(param_1);
    if (*(short *)(param_1 + 0x44) == 0) {
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;
      halt_baddata();
    }
---
  do {
    uVar4 = (int)uVar4 >> 1;
    local_20 = CONCAT22(*(short *)(param_1 + 10) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x36)) >> 0xc),
                        *(short *)(param_1 + 8) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x34)) >> 0xc));
    local_1c = CONCAT22(local_1c._2_2_,
---
    local_20 = CONCAT22(*(short *)(param_1 + 10) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x36)) >> 0xc),
                        *(short *)(param_1 + 8) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x34)) >> 0xc));
    local_1c = CONCAT22(local_1c._2_2_,
                        *(short *)(param_1 + 0xc) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x38)) >> 0xc));
---
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x34)) >> 0xc));
    local_1c = CONCAT22(local_1c._2_2_,
                        *(short *)(param_1 + 0xc) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x38)) >> 0xc));
    iVar2 = func_0x000ab4d0(&local_20);
    if (iVar2 < local_20._2_2_) {
                    /* WARNING: Bad instruction - Truncating control flow here */
---
    }
  }
  else {
    *(short *)(param_1 + 0x36) = (short)((int)-((int)*(short *)(param_1 + 0x36) * uVar4) >> 0xc);
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 1 & 1) != 0) {
      uVar5 = *(uint *)((*(ushort *)(param_1 + 200) & 0x7f) * 4 + -0x7ffeb164);
      uVar4 = uVar5 >> 0x10;
---
      setCopControlWord(2,0x800,uVar5);
      setCopControlWord(2,0x1000,0x1000);
      setCopControlWord(2,0x1800,-uVar5 & 0xffff);
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x34));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x36));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x38));
      copFunction(2,0x49e012);
---
      setCopControlWord(2,0x1000,0x1000);
      setCopControlWord(2,0x1800,-uVar5 & 0xffff);
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x34));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x36));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x38));
      copFunction(2,0x49e012);
      uVar6 = getCopReg(2,0x4800);
---
      setCopControlWord(2,0x1800,-uVar5 & 0xffff);
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x34));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x36));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x38));
      copFunction(2,0x49e012);
      uVar6 = getCopReg(2,0x4800);
      uVar7 = getCopReg(2,0x5000);
---
      uVar6 = getCopReg(2,0x4800);
      uVar7 = getCopReg(2,0x5000);
      uVar8 = getCopReg(2,0x5800);
      *(short *)(param_1 + 0x34) = (short)uVar6;
      *(short *)(param_1 + 0x36) = (short)uVar7;
      *(short *)(param_1 + 0x38) = (short)uVar8;
    }
---
      uVar7 = getCopReg(2,0x5000);
      uVar8 = getCopReg(2,0x5800);
      *(short *)(param_1 + 0x34) = (short)uVar6;
      *(short *)(param_1 + 0x36) = (short)uVar7;
      *(short *)(param_1 + 0x38) = (short)uVar8;
    }
    func_0x00109ff4(param_1);
---
      uVar8 = getCopReg(2,0x5800);
      *(short *)(param_1 + 0x34) = (short)uVar6;
      *(short *)(param_1 + 0x36) = (short)uVar7;
      *(short *)(param_1 + 0x38) = (short)uVar8;
    }
    func_0x00109ff4(param_1);
    if ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44)) {
---
      *(short *)(param_1 + 0x38) = (short)uVar8;
    }
    func_0x00109ff4(param_1);
    if ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44)) {
      uVar1 = (undefined2)
              ((int)*(short *)(param_1 + 0x34) * (int)*(short *)(param_1 + 0x3c) +
               (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +
---
    func_0x00109ff4(param_1);
    if ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44)) {
      uVar1 = (undefined2)
              ((int)*(short *)(param_1 + 0x34) * (int)*(short *)(param_1 + 0x3c) +
               (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +
               (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc);
      *(undefined2 *)(param_1 + 0xc4) = uVar1;
---
    if ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44)) {
      uVar1 = (undefined2)
              ((int)*(short *)(param_1 + 0x34) * (int)*(short *)(param_1 + 0x3c) +
               (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +
               (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc);
      *(undefined2 *)(param_1 + 0xc4) = uVar1;
      *(undefined2 *)(param_1 + 0x44) = uVar1;
---
      uVar1 = (undefined2)
              ((int)*(short *)(param_1 + 0x34) * (int)*(short *)(param_1 + 0x3c) +
               (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +
               (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc);
      *(undefined2 *)(param_1 + 0xc4) = uVar1;
      *(undefined2 *)(param_1 + 0x44) = uVar1;
    }
---
               (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +
               (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc);
      *(undefined2 *)(param_1 + 0xc4) = uVar1;
      *(undefined2 *)(param_1 + 0x44) = uVar1;
    }
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffdff | 0x40;
    func_0x00076790(param_1);
---
    if (uVar4 < 3) {
      uVar4 = 3;
    }
    iVar2 = (int)*(short *)(param_1 + 0x36);
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
---
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    if (((iVar2 <= (int)uVar4) || ((int)*(short *)(param_1 + 0x44) <= (int)uVar4)) &&
       (func_0x0010a4f8(param_1), (*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0)) {
      *(undefined2 *)(param_1 + 0xc0) = 0;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 3;
---
## FUN_00044f80

VertRefs: 40  Shifts: 10

        if ((uVar8 >> 4 & 1) != 0) {
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);
          sVar3 = 0x80;
          if (0x80 < (int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1)) {
            sVar3 = *(short *)(param_1 + 0x44) - uVar1;
          }
          sVar6 = *(short *)(param_1 + 10);
---
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);
          sVar3 = 0x80;
          if (0x80 < (int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1)) {
            sVar3 = *(short *)(param_1 + 0x44) - uVar1;
          }
          sVar6 = *(short *)(param_1 + 10);
          *(short *)(param_1 + 0x44) = sVar3;
---
            sVar3 = *(short *)(param_1 + 0x44) - uVar1;
          }
          sVar6 = *(short *)(param_1 + 10);
          *(short *)(param_1 + 0x44) = sVar3;
          iVar12 = func_0x000ab4d0(param_1 + 8);
          if ((((int)sVar6 < iVar12 + -0x100) && (*(short *)(param_1 + 0x3e) < 1)) &&
             (iVar12 = -(int)*(short *)(param_1 + 0x3e), (*(uint *)(param_1 + 0x50) & 4) == 0)) {
---
          sVar6 = *(short *)(param_1 + 10);
          *(short *)(param_1 + 0x44) = sVar3;
          iVar12 = func_0x000ab4d0(param_1 + 8);
          if ((((int)sVar6 < iVar12 + -0x100) && (*(short *)(param_1 + 0x3e) < 1)) &&
             (iVar12 = -(int)*(short *)(param_1 + 0x3e), (*(uint *)(param_1 + 0x50) & 4) == 0)) {
            if (iVar12 < 0x20) {
              iVar12 = 0x20;
---
          *(short *)(param_1 + 0x44) = sVar3;
          iVar12 = func_0x000ab4d0(param_1 + 8);
          if ((((int)sVar6 < iVar12 + -0x100) && (*(short *)(param_1 + 0x3e) < 1)) &&
             (iVar12 = -(int)*(short *)(param_1 + 0x3e), (*(uint *)(param_1 + 0x50) & 4) == 0)) {
            if (iVar12 < 0x20) {
              iVar12 = 0x20;
            }
---
            if (iVar12 < 0x20) {
              iVar12 = 0x20;
            }
            *(short *)(param_1 + 0x3e) = (short)iVar12;
            func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                            param_1 + 0x3c);
          }
---
              iVar12 = 0x20;
            }
            *(short *)(param_1 + 0x3e) = (short)iVar12;
            func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                            param_1 + 0x3c);
          }
          iVar12 = (int)*(short *)(param_1 + 0x44);
---
            }
            *(short *)(param_1 + 0x3e) = (short)iVar12;
            func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                            param_1 + 0x3c);
          }
          iVar12 = (int)*(short *)(param_1 + 0x44);
          *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);
---
            func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                            param_1 + 0x3c);
          }
          iVar12 = (int)*(short *)(param_1 + 0x44);
          *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);
          *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);
          *(short *)(param_1 + 0x38) = (short)(*(short *)(param_1 + 0x40) * iVar12 >> 0xc);
---
                            param_1 + 0x3c);
          }
          iVar12 = (int)*(short *)(param_1 + 0x44);
          *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);
          *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);
          *(short *)(param_1 + 0x38) = (short)(*(short *)(param_1 + 0x40) * iVar12 >> 0xc);
          halt_baddata();
---
          }
          iVar12 = (int)*(short *)(param_1 + 0x44);
          *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);
          *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);
          *(short *)(param_1 + 0x38) = (short)(*(short *)(param_1 + 0x40) * iVar12 >> 0xc);
          halt_baddata();
        }
---
          iVar12 = (int)*(short *)(param_1 + 0x44);
          *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);
          *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);
          *(short *)(param_1 + 0x38) = (short)(*(short *)(param_1 + 0x40) * iVar12 >> 0xc);
          halt_baddata();
        }
        if ((uVar8 >> 3 & 1) == 0) {
---
        }
        if ((uVar8 >> 3 & 1) == 0) {
          func_0x00109e70(param_1);
          func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                          param_1 + 0x3c);
          halt_baddata();
        }
---
        if ((uVar8 >> 3 & 1) == 0) {
          func_0x00109e70(param_1);
          func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                          param_1 + 0x3c);
          halt_baddata();
        }
        return;
---
      local_2c = CONCAT22(uStack_4a,*(short *)(iVar12 + 0x70) - *(ushort *)(param_1 + 0xc));
      local_30 = local_50;
      func_0x00109758(param_1,local_50,local_2c,&local_48);
      local_30 = CONCAT22(local_46 - *(short *)(param_1 + 0x3e),
                          local_48 - *(short *)(param_1 + 0x3c));
      local_2c = CONCAT22(local_2c._2_2_,local_44 - *(short *)(param_1 + 0x40));
      local_20 = local_30;
---
      local_30 = local_50;
      func_0x00109758(param_1,local_50,local_2c,&local_48);
      local_30 = CONCAT22(local_46 - *(short *)(param_1 + 0x3e),
                          local_48 - *(short *)(param_1 + 0x3c));
      local_2c = CONCAT22(local_2c._2_2_,local_44 - *(short *)(param_1 + 0x40));
      local_20 = local_30;
      local_1c = local_2c;
---
      func_0x00109758(param_1,local_50,local_2c,&local_48);
      local_30 = CONCAT22(local_46 - *(short *)(param_1 + 0x3e),
                          local_48 - *(short *)(param_1 + 0x3c));
      local_2c = CONCAT22(local_2c._2_2_,local_44 - *(short *)(param_1 + 0x40));
      local_20 = local_30;
      local_1c = local_2c;
      func_0x00109758(param_1,local_30,local_2c,auStack_28);
---
      local_20 = local_30;
      local_1c = local_2c;
      func_0x00109758(param_1,local_30,local_2c,auStack_28);
      iVar12 = func_0x0010a95c(param_1,param_1 + 0x3c,&local_48,auStack_40);
      iVar9 = (int)*(short *)(param_1 + 0x3c) * (int)local_48 +
              (int)*(short *)(param_1 + 0x3e) * (int)local_46 +
              (int)*(short *)(param_1 + 0x40) * (int)local_44 >> 0xc;
---
      local_1c = local_2c;
      func_0x00109758(param_1,local_30,local_2c,auStack_28);
      iVar12 = func_0x0010a95c(param_1,param_1 + 0x3c,&local_48,auStack_40);
      iVar9 = (int)*(short *)(param_1 + 0x3c) * (int)local_48 +
              (int)*(short *)(param_1 + 0x3e) * (int)local_46 +
              (int)*(short *)(param_1 + 0x40) * (int)local_44 >> 0xc;
      func_0x0010a95c(param_1,auStack_40,param_1 + 0x3c,&local_38);
---
      func_0x00109758(param_1,local_30,local_2c,auStack_28);
      iVar12 = func_0x0010a95c(param_1,param_1 + 0x3c,&local_48,auStack_40);
      iVar9 = (int)*(short *)(param_1 + 0x3c) * (int)local_48 +
              (int)*(short *)(param_1 + 0x3e) * (int)local_46 +
              (int)*(short *)(param_1 + 0x40) * (int)local_44 >> 0xc;
      func_0x0010a95c(param_1,auStack_40,param_1 + 0x3c,&local_38);
      local_20 = local_38;
---
      iVar12 = func_0x0010a95c(param_1,param_1 + 0x3c,&local_48,auStack_40);
      iVar9 = (int)*(short *)(param_1 + 0x3c) * (int)local_48 +
              (int)*(short *)(param_1 + 0x3e) * (int)local_46 +
              (int)*(short *)(param_1 + 0x40) * (int)local_44 >> 0xc;
      func_0x0010a95c(param_1,auStack_40,param_1 + 0x3c,&local_38);
      local_20 = local_38;
      local_1c = local_34;
---
      iVar9 = (int)*(short *)(param_1 + 0x3c) * (int)local_48 +
              (int)*(short *)(param_1 + 0x3e) * (int)local_46 +
              (int)*(short *)(param_1 + 0x40) * (int)local_44 >> 0xc;
      func_0x0010a95c(param_1,auStack_40,param_1 + 0x3c,&local_38);
      local_20 = local_38;
      local_1c = local_34;
      func_0x00109758(param_1,local_38,local_34,&local_38);
---
      if ((iVar12 == 0) && (iVar9 < 0)) {
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) != 0) {
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);
          sVar3 = *(short *)(param_1 + 0x44) - uVar1;
          if ((int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1) < 1) {
            sVar3 = 0;
          }
---
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) != 0) {
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);
          sVar3 = *(short *)(param_1 + 0x44) - uVar1;
          if ((int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1) < 1) {
            sVar3 = 0;
          }
          *(short *)(param_1 + 0x44) = sVar3;
---
          if ((int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1) < 1) {
            sVar3 = 0;
          }
          *(short *)(param_1 + 0x44) = sVar3;
        }
        func_0x0010a6ec(param_1);
      }
---
          iVar12 = (int)*(short *)(iVar9 + -0x7ffeb164);
          iVar9 = (int)*(short *)(iVar9 + -0x7ffeb162);
        }
        iVar11 = (int)*(short *)(param_1 + 0x44);
        sVar7 = (short)(iVar9 * *(short *)(param_1 + 0x3c) + iVar12 * (short)local_38 >> 0xc);
        sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc);
        sVar6 = (short)(iVar9 * *(short *)(param_1 + 0x40) + iVar12 * (short)local_34 >> 0xc);
---
          iVar9 = (int)*(short *)(iVar9 + -0x7ffeb162);
        }
        iVar11 = (int)*(short *)(param_1 + 0x44);
        sVar7 = (short)(iVar9 * *(short *)(param_1 + 0x3c) + iVar12 * (short)local_38 >> 0xc);
        sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc);
        sVar6 = (short)(iVar9 * *(short *)(param_1 + 0x40) + iVar12 * (short)local_34 >> 0xc);
        *(short *)(param_1 + 0x3c) = sVar7;
---
        }
        iVar11 = (int)*(short *)(param_1 + 0x44);
        sVar7 = (short)(iVar9 * *(short *)(param_1 + 0x3c) + iVar12 * (short)local_38 >> 0xc);
        sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc);
        sVar6 = (short)(iVar9 * *(short *)(param_1 + 0x40) + iVar12 * (short)local_34 >> 0xc);
        *(short *)(param_1 + 0x3c) = sVar7;
        *(short *)(param_1 + 0x3e) = sVar3;
---
        iVar11 = (int)*(short *)(param_1 + 0x44);
        sVar7 = (short)(iVar9 * *(short *)(param_1 + 0x3c) + iVar12 * (short)local_38 >> 0xc);
        sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc);
        sVar6 = (short)(iVar9 * *(short *)(param_1 + 0x40) + iVar12 * (short)local_34 >> 0xc);
        *(short *)(param_1 + 0x3c) = sVar7;
        *(short *)(param_1 + 0x3e) = sVar3;
        *(short *)(param_1 + 0x40) = sVar6;
---
        sVar7 = (short)(iVar9 * *(short *)(param_1 + 0x3c) + iVar12 * (short)local_38 >> 0xc);
        sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc);
        sVar6 = (short)(iVar9 * *(short *)(param_1 + 0x40) + iVar12 * (short)local_34 >> 0xc);
        *(short *)(param_1 + 0x3c) = sVar7;
        *(short *)(param_1 + 0x3e) = sVar3;
        *(short *)(param_1 + 0x40) = sVar6;
        *(short *)(param_1 + 0x34) = (short)(sVar7 * iVar11 >> 0xc);
---
        sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc);
        sVar6 = (short)(iVar9 * *(short *)(param_1 + 0x40) + iVar12 * (short)local_34 >> 0xc);
        *(short *)(param_1 + 0x3c) = sVar7;
        *(short *)(param_1 + 0x3e) = sVar3;
        *(short *)(param_1 + 0x40) = sVar6;
        *(short *)(param_1 + 0x34) = (short)(sVar7 * iVar11 >> 0xc);
        *(short *)(param_1 + 0x36) = (short)(sVar3 * iVar11 >> 0xc);
---
        sVar6 = (short)(iVar9 * *(short *)(param_1 + 0x40) + iVar12 * (short)local_34 >> 0xc);
        *(short *)(param_1 + 0x3c) = sVar7;
        *(short *)(param_1 + 0x3e) = sVar3;
        *(short *)(param_1 + 0x40) = sVar6;
        *(short *)(param_1 + 0x34) = (short)(sVar7 * iVar11 >> 0xc);
        *(short *)(param_1 + 0x36) = (short)(sVar3 * iVar11 >> 0xc);
        *(short *)(param_1 + 0x38) = (short)(sVar6 * iVar11 >> 0xc);
---
        *(short *)(param_1 + 0x3c) = sVar7;
        *(short *)(param_1 + 0x3e) = sVar3;
        *(short *)(param_1 + 0x40) = sVar6;
        *(short *)(param_1 + 0x34) = (short)(sVar7 * iVar11 >> 0xc);
        *(short *)(param_1 + 0x36) = (short)(sVar3 * iVar11 >> 0xc);
        *(short *)(param_1 + 0x38) = (short)(sVar6 * iVar11 >> 0xc);
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {
---
        *(short *)(param_1 + 0x3e) = sVar3;
        *(short *)(param_1 + 0x40) = sVar6;
        *(short *)(param_1 + 0x34) = (short)(sVar7 * iVar11 >> 0xc);
        *(short *)(param_1 + 0x36) = (short)(sVar3 * iVar11 >> 0xc);
        *(short *)(param_1 + 0x38) = (short)(sVar6 * iVar11 >> 0xc);
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {
          func_0x00109e70(param_1);
---
        *(short *)(param_1 + 0x40) = sVar6;
        *(short *)(param_1 + 0x34) = (short)(sVar7 * iVar11 >> 0xc);
        *(short *)(param_1 + 0x36) = (short)(sVar3 * iVar11 >> 0xc);
        *(short *)(param_1 + 0x38) = (short)(sVar6 * iVar11 >> 0xc);
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {
          func_0x00109e70(param_1);
          return;
---
## FUN_00045a80

VertRefs: 11  Shifts: 2

  if ((*(int *)(param_1 + 0xcc) != 0) &&
     ((((*(uint *)(param_1 + 0xd0) & 4) == 0 || (*(int *)(param_1 + 0xbc) < 1)) ||
      (*(short *)(*(int *)(param_1 + 0xb8) + 10) == 0)))) {
    sVar1 = *(short *)(param_1 + 0x36);
    psVar5 = (short *)(param_1 + 0x34);
    bVar3 = 0;
    do {
---
     ((((*(uint *)(param_1 + 0xd0) & 4) == 0 || (*(int *)(param_1 + 0xbc) < 1)) ||
      (*(short *)(*(int *)(param_1 + 0xb8) + 10) == 0)))) {
    sVar1 = *(short *)(param_1 + 0x36);
    psVar5 = (short *)(param_1 + 0x34);
    bVar3 = 0;
    do {
      bVar3 = bVar3 + 1;
---
      psVar5 = psVar5 + 1;
    } while (bVar3 < 3);
    func_0x00109ff4(param_1);
    uVar4 = (int)*(short *)(param_1 + 0x34) * (int)*(short *)(param_1 + 0x3c) +
            (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +
            (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc;
    if ((((*(uint *)(param_1 + 0xd0) & 4) == 0) || (*(int *)(param_1 + 0xbc) < 1)) ||
---
    } while (bVar3 < 3);
    func_0x00109ff4(param_1);
    uVar4 = (int)*(short *)(param_1 + 0x34) * (int)*(short *)(param_1 + 0x3c) +
            (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +
            (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc;
    if ((((*(uint *)(param_1 + 0xd0) & 4) == 0) || (*(int *)(param_1 + 0xbc) < 1)) ||
       ((*(short *)(param_1 + 0x36) == 0 && (sVar1 < 0)))) {
---
    func_0x00109ff4(param_1);
    uVar4 = (int)*(short *)(param_1 + 0x34) * (int)*(short *)(param_1 + 0x3c) +
            (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +
            (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc;
    if ((((*(uint *)(param_1 + 0xd0) & 4) == 0) || (*(int *)(param_1 + 0xbc) < 1)) ||
       ((*(short *)(param_1 + 0x36) == 0 && (sVar1 < 0)))) {
      if ((int)uVar4 < 0xb) {
---
            (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +
            (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc;
    if ((((*(uint *)(param_1 + 0xd0) & 4) == 0) || (*(int *)(param_1 + 0xbc) < 1)) ||
       ((*(short *)(param_1 + 0x36) == 0 && (sVar1 < 0)))) {
      if ((int)uVar4 < 0xb) {
        *(undefined2 *)(param_1 + 0xc4) = 0;
        *(undefined4 *)(param_1 + 0xbc) = 0;
---
      uVar4 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 8);
    }
    *(short *)(param_1 + 0xc4) = (short)uVar4;
    iVar2 = (int)*(short *)(param_1 + 0x34);
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
---
      iVar2 = -iVar2;
    }
    if (iVar2 < 10) {
      iVar2 = (int)*(short *)(param_1 + 0x38);
      if (iVar2 < 0) {
        iVar2 = -iVar2;
      }
---
## FUN_00046024

VertRefs: 20  Shifts: 3

  
  *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0xc);
  if (*(short *)(param_1 + 0x44) != 0) {
    *(short *)(param_1 + 8) = *(short *)(param_1 + 8) + *(short *)(param_1 + 0x34);
    *(short *)(param_1 + 10) = *(short *)(param_1 + 10) + *(short *)(param_1 + 0x36);
    *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + *(short *)(param_1 + 0x38);
---
  *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0xc);
  if (*(short *)(param_1 + 0x44) != 0) {
    *(short *)(param_1 + 8) = *(short *)(param_1 + 8) + *(short *)(param_1 + 0x34);
    *(short *)(param_1 + 10) = *(short *)(param_1 + 10) + *(short *)(param_1 + 0x36);
    *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + *(short *)(param_1 + 0x38);
                    /* WARNING: Bad instruction - Truncating control flow here */
---
  *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0xc);
  if (*(short *)(param_1 + 0x44) != 0) {
    *(short *)(param_1 + 8) = *(short *)(param_1 + 8) + *(short *)(param_1 + 0x34);
    *(short *)(param_1 + 10) = *(short *)(param_1 + 10) + *(short *)(param_1 + 0x36);
    *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + *(short *)(param_1 + 0x38);
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
---
  if (*(short *)(param_1 + 0x44) != 0) {
    *(short *)(param_1 + 8) = *(short *)(param_1 + 8) + *(short *)(param_1 + 0x34);
    *(short *)(param_1 + 10) = *(short *)(param_1 + 10) + *(short *)(param_1 + 0x36);
    *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + *(short *)(param_1 + 0x38);
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
---
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) | 4;
  }
  if (((*(uint *)(param_1 + 0x50) & 4) == 0) &&
     (((int)((uint)*(ushort *)(param_1 + 0x36) << 0x10) < 1 ||
      (((*(uint *)(param_1 + 0xd0) & 4) != 0 && (0 < *(int *)(param_1 + 0xbc))))))) {
    if ((*(uint *)(param_1 + 0x50) & 0x20) != 0) {
      uVar1 = func_0x000ab4d0(param_1 + 8);
---
    }
    func_0x00109ae0(param_1);
    func_0x0010b600(param_1);
    if (10 < *(short *)(param_1 + 0x44)) {
      if (*(int *)(param_1 + 0x3c) == 0) {
        *(undefined4 *)(param_1 + 0x18) = 0x1000;
        *(undefined4 *)(param_1 + 0x1c) = 0;
---
    func_0x00109ae0(param_1);
    func_0x0010b600(param_1);
    if (10 < *(short *)(param_1 + 0x44)) {
      if (*(int *)(param_1 + 0x3c) == 0) {
        *(undefined4 *)(param_1 + 0x18) = 0x1000;
        *(undefined4 *)(param_1 + 0x1c) = 0;
        *(undefined4 *)(param_1 + 0x20) = 0x1000;
---
        *(undefined4 *)(param_1 + 0x20) = 0x1000;
        *(undefined4 *)(param_1 + 0x24) = 0;
        *(undefined2 *)(param_1 + 0x28) = 0x1000;
        if (*(short *)(param_1 + 0x40) < 0) {
          *(undefined2 *)(param_1 + 0x18) = 0xf000;
          *(undefined2 *)(param_1 + 0x28) = 0xf000;
                    /* WARNING: Bad instruction - Truncating control flow here */
---
        }
      }
      else {
        *(undefined2 *)(param_1 + 0x1c) = *(undefined2 *)(param_1 + 0x3c);
        *(undefined2 *)(param_1 + 0x22) = *(undefined2 *)(param_1 + 0x3e);
        *(undefined2 *)(param_1 + 0x28) = *(undefined2 *)(param_1 + 0x40);
        FUN_00023000(&local_40,0,8);
---
      }
      else {
        *(undefined2 *)(param_1 + 0x1c) = *(undefined2 *)(param_1 + 0x3c);
        *(undefined2 *)(param_1 + 0x22) = *(undefined2 *)(param_1 + 0x3e);
        *(undefined2 *)(param_1 + 0x28) = *(undefined2 *)(param_1 + 0x40);
        FUN_00023000(&local_40,0,8);
        iVar2 = (int)*(short *)(param_1 + 0x3e);
---
      else {
        *(undefined2 *)(param_1 + 0x1c) = *(undefined2 *)(param_1 + 0x3c);
        *(undefined2 *)(param_1 + 0x22) = *(undefined2 *)(param_1 + 0x3e);
        *(undefined2 *)(param_1 + 0x28) = *(undefined2 *)(param_1 + 0x40);
        FUN_00023000(&local_40,0,8);
        iVar2 = (int)*(short *)(param_1 + 0x3e);
        local_40 = CONCAT22(0x1000 - (short)(iVar2 * iVar2 >> 0xc),
---
        *(undefined2 *)(param_1 + 0x22) = *(undefined2 *)(param_1 + 0x3e);
        *(undefined2 *)(param_1 + 0x28) = *(undefined2 *)(param_1 + 0x40);
        FUN_00023000(&local_40,0,8);
        iVar2 = (int)*(short *)(param_1 + 0x3e);
        local_40 = CONCAT22(0x1000 - (short)(iVar2 * iVar2 >> 0xc),
                            -(short)(iVar2 * *(short *)(param_1 + 0x3c) >> 0xc));
        local_3c = CONCAT22(local_3c._2_2_,-(short)(iVar2 * *(short *)(param_1 + 0x40) >> 0xc));
---
        FUN_00023000(&local_40,0,8);
        iVar2 = (int)*(short *)(param_1 + 0x3e);
        local_40 = CONCAT22(0x1000 - (short)(iVar2 * iVar2 >> 0xc),
                            -(short)(iVar2 * *(short *)(param_1 + 0x3c) >> 0xc));
        local_3c = CONCAT22(local_3c._2_2_,-(short)(iVar2 * *(short *)(param_1 + 0x40) >> 0xc));
        local_48 = local_40;
        local_44 = local_3c;
---
        iVar2 = (int)*(short *)(param_1 + 0x3e);
        local_40 = CONCAT22(0x1000 - (short)(iVar2 * iVar2 >> 0xc),
                            -(short)(iVar2 * *(short *)(param_1 + 0x3c) >> 0xc));
        local_3c = CONCAT22(local_3c._2_2_,-(short)(iVar2 * *(short *)(param_1 + 0x40) >> 0xc));
        local_48 = local_40;
        local_44 = local_3c;
        if ((*(short *)(param_1 + 0x3c) == 0) && (*(short *)(param_1 + 0x40) == 0)) {
---
        local_3c = CONCAT22(local_3c._2_2_,-(short)(iVar2 * *(short *)(param_1 + 0x40) >> 0xc));
        local_48 = local_40;
        local_44 = local_3c;
        if ((*(short *)(param_1 + 0x3c) == 0) && (*(short *)(param_1 + 0x40) == 0)) {
          if ((*(short *)(param_1 + 0x1a) == 0) && (*(short *)(param_1 + 0x26) == 0)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
---
        local_38 = local_48;
        local_34 = local_44;
        func_0x00109758(param_1,local_48,local_44,&local_48);
        func_0x0010a95c(param_1,&local_48,param_1 + 0x3c,&local_40);
        *(undefined2 *)(param_1 + 0x1a) = (undefined2)local_48;
        *(undefined2 *)(param_1 + 0x20) = local_48._2_2_;
        *(undefined2 *)(param_1 + 0x26) = (undefined2)local_44;
---
      }
    }
    *(ushort *)(param_1 + 200) = *(short *)(param_1 + 200) + 0xa4U & 0xfff;
    if (*(int *)(*(int *)(param_1 + 0xb8) + 0x40) == 0) {
      FUN_00023000(&local_40,0,8);
      local_3c = CONCAT22(local_3c._2_2_,*(undefined2 *)(param_1 + 200));
      local_48 = local_40;
---
    }
    return;
  }
  *(ushort *)(param_1 + 0x36) =
       *(ushort *)(param_1 + 0x36) +
       (short)((int)(((uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0xe) -
                     (*(short *)(*(int *)(param_1 + 0xb8) + 0x2a) + -0x1000)) * 5) >> 0xb);
---
    return;
  }
  *(ushort *)(param_1 + 0x36) =
       *(ushort *)(param_1 + 0x36) +
       (short)((int)(((uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0xe) -
                     (*(short *)(*(int *)(param_1 + 0xb8) + 0x2a) + -0x1000)) * 5) >> 0xb);
  func_0x00109ff4(param_1);
---
## FUN_000475dc

VertRefs: 32  Shifts: 3

    }
    iVar4 = *(int *)(*(int *)(param_1 + 0xd8) + 0x328);
    if (iVar4 == 0) {
      sVar1 = *(short *)(*(int *)(param_1 + 0xd8) + 0x44);
      uVar7 = *(ushort *)(iVar15 + 6) - 2;
      if (uVar7 < 0x4b) {
                    /* WARNING: Could not emulate address calculation at 0x00047838 */
---
                 ((*(short *)((_DAT_800c0284 & 0xf) * 0x400 + -0x7ffeb164) + -0x100 >> 3 & 0x3ffcU)
                 + 0x80014e9c);
      }
      *(short *)(param_1 + 0x3e) = -(short)uVar9;
      *(undefined2 *)(param_1 + 0x3c) = 0;
      *(short *)(param_1 + 0x40) = (short)((uint)uVar9 >> 0x10);
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x3c));
---
                 + 0x80014e9c);
      }
      *(short *)(param_1 + 0x3e) = -(short)uVar9;
      *(undefined2 *)(param_1 + 0x3c) = 0;
      *(short *)(param_1 + 0x40) = (short)((uint)uVar9 >> 0x10);
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x3c));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
---
      }
      *(short *)(param_1 + 0x3e) = -(short)uVar9;
      *(undefined2 *)(param_1 + 0x3c) = 0;
      *(short *)(param_1 + 0x40) = (short)((uint)uVar9 >> 0x10);
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x3c));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
---
      *(short *)(param_1 + 0x3e) = -(short)uVar9;
      *(undefined2 *)(param_1 + 0x3c) = 0;
      *(short *)(param_1 + 0x40) = (short)((uint)uVar9 >> 0x10);
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x3c));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
      copFunction(2,0x49e012);
---
      *(undefined2 *)(param_1 + 0x3c) = 0;
      *(short *)(param_1 + 0x40) = (short)((uint)uVar9 >> 0x10);
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x3c));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
      copFunction(2,0x49e012);
      uVar9 = getCopReg(2,0x4800);
---
      *(short *)(param_1 + 0x40) = (short)((uint)uVar9 >> 0x10);
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x3c));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
      copFunction(2,0x49e012);
      uVar9 = getCopReg(2,0x4800);
      uVar11 = getCopReg(2,0x5000);
---
      uVar9 = getCopReg(2,0x4800);
      uVar11 = getCopReg(2,0x5000);
      uVar12 = getCopReg(2,0x5800);
      *(ushort *)(param_1 + 0x3c) = (ushort)uVar9;
      *(short *)(param_1 + 0x3e) = (short)uVar11;
      *(short *)(param_1 + 0x40) = (short)uVar12;
      iVar4 = *(int *)(param_1 + 0xd8);
---
      uVar11 = getCopReg(2,0x5000);
      uVar12 = getCopReg(2,0x5800);
      *(ushort *)(param_1 + 0x3c) = (ushort)uVar9;
      *(short *)(param_1 + 0x3e) = (short)uVar11;
      *(short *)(param_1 + 0x40) = (short)uVar12;
      iVar4 = *(int *)(param_1 + 0xd8);
      setCopControlWord(2,0,*(undefined4 *)(iVar4 + 0xd0));
---
      uVar12 = getCopReg(2,0x5800);
      *(ushort *)(param_1 + 0x3c) = (ushort)uVar9;
      *(short *)(param_1 + 0x3e) = (short)uVar11;
      *(short *)(param_1 + 0x40) = (short)uVar12;
      iVar4 = *(int *)(param_1 + 0xd8);
      setCopControlWord(2,0,*(undefined4 *)(iVar4 + 0xd0));
      setCopControlWord(2,0x800,*(undefined4 *)(iVar4 + 0xd4));
---
      setCopControlWord(2,0x1000,*(undefined4 *)(iVar4 + 0xd8));
      setCopControlWord(2,0x1800,*(undefined4 *)(iVar4 + 0xdc));
      setCopControlWord(2,0x2000,*(undefined4 *)(iVar4 + 0xe0));
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x3c));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
      copFunction(2,0x49e012);
---
      setCopControlWord(2,0x1800,*(undefined4 *)(iVar4 + 0xdc));
      setCopControlWord(2,0x2000,*(undefined4 *)(iVar4 + 0xe0));
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x3c));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
      copFunction(2,0x49e012);
      puVar10 = (ushort *)(param_1 + 0x3c);
---
      setCopControlWord(2,0x2000,*(undefined4 *)(iVar4 + 0xe0));
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x3c));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
      copFunction(2,0x49e012);
      puVar10 = (ushort *)(param_1 + 0x3c);
      uVar9 = getCopReg(2,0x4800);
---
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
      copFunction(2,0x49e012);
      puVar10 = (ushort *)(param_1 + 0x3c);
      uVar9 = getCopReg(2,0x4800);
      uVar11 = getCopReg(2,0x5000);
      uVar12 = getCopReg(2,0x5800);
---
      uVar11 = getCopReg(2,0x5000);
      uVar12 = getCopReg(2,0x5800);
      *puVar10 = (ushort)uVar9;
      *(short *)(param_1 + 0x3e) = (short)uVar11;
      *(short *)(param_1 + 0x40) = (short)uVar12;
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar13 + 0xc4);
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar13 + 200);
---
      uVar12 = getCopReg(2,0x5800);
      *puVar10 = (ushort)uVar9;
      *(short *)(param_1 + 0x3e) = (short)uVar11;
      *(short *)(param_1 + 0x40) = (short)uVar12;
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar13 + 0xc4);
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar13 + 200);
      if (uVar14 != 0) {
---
        setCopControlWord(2,0x1000,0x1000);
        setCopControlWord(2,0x1800,-uVar7 & 0xffff);
        setCopReg(2,0x4800,(uint)*puVar10);
        setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
        setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
        copFunction(2,0x49e012);
        uVar9 = getCopReg(2,0x4800);
---
        setCopControlWord(2,0x1800,-uVar7 & 0xffff);
        setCopReg(2,0x4800,(uint)*puVar10);
        setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
        setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
        copFunction(2,0x49e012);
        uVar9 = getCopReg(2,0x4800);
        uVar11 = getCopReg(2,0x5000);
---
        uVar11 = getCopReg(2,0x5000);
        uVar12 = getCopReg(2,0x5800);
        *puVar10 = (ushort)uVar9;
        *(short *)(param_1 + 0x3e) = (short)uVar11;
        *(short *)(param_1 + 0x40) = (short)uVar12;
      }
      sVar3 = func_0x00105a68(*(undefined4 *)(*(int *)(param_1 + 0xd8) + 0xbc));
---
        uVar12 = getCopReg(2,0x5800);
        *puVar10 = (ushort)uVar9;
        *(short *)(param_1 + 0x3e) = (short)uVar11;
        *(short *)(param_1 + 0x40) = (short)uVar12;
      }
      sVar3 = func_0x00105a68(*(undefined4 *)(*(int *)(param_1 + 0xd8) + 0xbc));
      iVar4 = ((int)sVar3 + (int)sVar1) * 0x10000;
---
      sVar3 = func_0x00105a68(*(undefined4 *)(*(int *)(param_1 + 0xd8) + 0xbc));
      iVar4 = ((int)sVar3 + (int)sVar1) * 0x10000;
      local_28 = iVar4 >> 0x10;
      local_30 = *(short *)(param_1 + 0x3c) * local_28;
      if ((local_30 < 0) && (-0x1000 < local_30)) {
        local_30 = 0;
      }
---
      if ((local_30 < 0) && (-0x1000 < local_30)) {
        local_30 = 0;
      }
      local_2c = *(short *)(param_1 + 0x3e) * local_28;
      if ((local_2c < 0) && (-0x1000 < local_2c)) {
        local_2c = 0;
      }
---
      if ((local_2c < 0) && (-0x1000 < local_2c)) {
        local_2c = 0;
      }
      local_28 = *(short *)(param_1 + 0x40) * local_28;
      if ((local_28 < 0) && (-0x1000 < local_28)) {
        local_28 = 0;
      }
---
      if ((local_28 < 0) && (-0x1000 < local_28)) {
        local_28 = 0;
      }
      *(short *)(param_1 + 0x44) = (short)((uint)iVar4 >> 0x10);
      *(short *)(param_1 + 0x34) = (short)(local_30 >> 0xc);
      *(short *)(param_1 + 0x36) = (short)(local_2c >> 0xc);
      *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0xc);
---
        local_28 = 0;
      }
      *(short *)(param_1 + 0x44) = (short)((uint)iVar4 >> 0x10);
      *(short *)(param_1 + 0x34) = (short)(local_30 >> 0xc);
      *(short *)(param_1 + 0x36) = (short)(local_2c >> 0xc);
      *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0xc);
      *(short *)(param_1 + 0x38) = (short)(local_28 >> 0xc);
---
      }
      *(short *)(param_1 + 0x44) = (short)((uint)iVar4 >> 0x10);
      *(short *)(param_1 + 0x34) = (short)(local_30 >> 0xc);
      *(short *)(param_1 + 0x36) = (short)(local_2c >> 0xc);
      *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0xc);
      *(short *)(param_1 + 0x38) = (short)(local_28 >> 0xc);
      *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(param_1 + 8);
---
      *(short *)(param_1 + 0x34) = (short)(local_30 >> 0xc);
      *(short *)(param_1 + 0x36) = (short)(local_2c >> 0xc);
      *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0xc);
      *(short *)(param_1 + 0x38) = (short)(local_28 >> 0xc);
      *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(param_1 + 8);
      func_0x0010a55c(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                      param_1 + 0x10);
---
      *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0xc);
      *(short *)(param_1 + 0x38) = (short)(local_28 >> 0xc);
      *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(param_1 + 8);
      func_0x0010a55c(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                      param_1 + 0x10);
      *(short *)(param_1 + 0x10) = *(short *)(param_1 + 0x10) + -0x400;
      *(ushort *)(param_1 + 0x12) = 0x400U - *(short *)(param_1 + 0x12) & 0xfff;
---
      *(ushort *)(param_1 + 0x12) = 0x400U - *(short *)(param_1 + 0x12) & 0xfff;
      func_0x000b0e20(param_1 + 0x10,param_1 + 0x18);
      uVar6 = *(ushort *)(param_1 + 0xc4);
      if ((int)(uint)*(ushort *)(param_1 + 0xc4) < (int)(short)*(ushort *)(param_1 + 0x44)) {
        uVar6 = *(ushort *)(param_1 + 0x44);
      }
      *(ushort *)(param_1 + 0xc4) = uVar6;
---
      func_0x000b0e20(param_1 + 0x10,param_1 + 0x18);
      uVar6 = *(ushort *)(param_1 + 0xc4);
      if ((int)(uint)*(ushort *)(param_1 + 0xc4) < (int)(short)*(ushort *)(param_1 + 0x44)) {
        uVar6 = *(ushort *)(param_1 + 0x44);
      }
      *(ushort *)(param_1 + 0xc4) = uVar6;
      if (0x40 < **(ushort **)(param_1 + 0xb8)) {
---
          *(undefined4 **)(param_1 + 100) = puVar5;
        }
        iVar4 = *(int *)(param_1 + 0xb8);
        if (*(int *)(iVar4 + 0x34) != 0) {
          func_0x0010c1b0(param_1);
          *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;
          iVar4 = *(int *)(param_1 + 0xb8);
---
## FUN_00048150

VertRefs: 12  Shifts: 4

                          *(short *)(*(int *)(iVar5 + 0x268) + 0x70) - (short)local_44);
      local_38 = local_40;
      local_34 = local_3c;
      func_0x00109758(param_1,local_40,local_3c,param_1 + 0x3c);
    }
  }
  uVar9 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x14);
---
  }
  uVar9 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x14);
  FUN_00023000(&local_38,0,8);
  local_38._0_2_ = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x3c)) >> 0xc);
  local_38._2_2_ = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x3e)) >> 0xc);
  local_40 = CONCAT22(local_38._2_2_,(short)local_38);
  sVar4 = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x40)) >> 0xc);
---
  uVar9 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x14);
  FUN_00023000(&local_38,0,8);
  local_38._0_2_ = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x3c)) >> 0xc);
  local_38._2_2_ = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x3e)) >> 0xc);
  local_40 = CONCAT22(local_38._2_2_,(short)local_38);
  sVar4 = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x40)) >> 0xc);
  local_34 = CONCAT22(local_34._2_2_,sVar4);
---
  local_38._0_2_ = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x3c)) >> 0xc);
  local_38._2_2_ = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x3e)) >> 0xc);
  local_40 = CONCAT22(local_38._2_2_,(short)local_38);
  sVar4 = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x40)) >> 0xc);
  local_34 = CONCAT22(local_34._2_2_,sVar4);
  local_3c = local_34;
  iVar5 = *(int *)(param_1 + 0xdc);
---
    local_48 = CONCAT22(local_48._2_2_ + -300,(short)local_48);
  }
  FUN_00023000(&local_28,0,8);
  local_30 = (short)((int)*(short *)(param_1 + 0x3c) >> 4);
  sStack_2e = (short)((int)*(short *)(param_1 + 0x3e) >> 4);
  local_24 = CONCAT22(local_24._2_2_,(short)((int)*(short *)(param_1 + 0x40) >> 4));
  local_2c = local_24;
---
  }
  FUN_00023000(&local_28,0,8);
  local_30 = (short)((int)*(short *)(param_1 + 0x3c) >> 4);
  sStack_2e = (short)((int)*(short *)(param_1 + 0x3e) >> 4);
  local_24 = CONCAT22(local_24._2_2_,(short)((int)*(short *)(param_1 + 0x40) >> 4));
  local_2c = local_24;
  iVar5 = param_1 + 8;
---
  FUN_00023000(&local_28,0,8);
  local_30 = (short)((int)*(short *)(param_1 + 0x3c) >> 4);
  sStack_2e = (short)((int)*(short *)(param_1 + 0x3e) >> 4);
  local_24 = CONCAT22(local_24._2_2_,(short)((int)*(short *)(param_1 + 0x40) >> 4));
  local_2c = local_24;
  iVar5 = param_1 + 8;
  if (iVar2 == 0) {
---
  iVar7 = (*(uint *)(iVar2 + 8) >> 0x10) - (local_48 >> 0x10);
  iVar6 = (*(uint *)(iVar2 + 0xc) & 0xffff) - (local_44 & 0xffff);
  local_28 = CONCAT22((short)iVar7,(short)iVar8);
  iVar7 = (int)*(short *)(param_1 + 0x3c) * (iVar8 * 0x10000 >> 0x10) +
          (int)*(short *)(param_1 + 0x3e) * (iVar7 * 0x10000 >> 0x10) +
          (int)*(short *)(param_1 + 0x40) * (iVar6 * 0x10000 >> 0x10) >> 0xc;
  if (iVar7 < 0) {
---
  iVar6 = (*(uint *)(iVar2 + 0xc) & 0xffff) - (local_44 & 0xffff);
  local_28 = CONCAT22((short)iVar7,(short)iVar8);
  iVar7 = (int)*(short *)(param_1 + 0x3c) * (iVar8 * 0x10000 >> 0x10) +
          (int)*(short *)(param_1 + 0x3e) * (iVar7 * 0x10000 >> 0x10) +
          (int)*(short *)(param_1 + 0x40) * (iVar6 * 0x10000 >> 0x10) >> 0xc;
  if (iVar7 < 0) {
    iVar7 = -iVar7;
---
  local_28 = CONCAT22((short)iVar7,(short)iVar8);
  iVar7 = (int)*(short *)(param_1 + 0x3c) * (iVar8 * 0x10000 >> 0x10) +
          (int)*(short *)(param_1 + 0x3e) * (iVar7 * 0x10000 >> 0x10) +
          (int)*(short *)(param_1 + 0x40) * (iVar6 * 0x10000 >> 0x10) >> 0xc;
  if (iVar7 < 0) {
    iVar7 = -iVar7;
  }
---
    bVar1 = false;
  }
  if (bVar1) {
    (**(code **)(*(int *)(iVar2 + 4) + 0x3c))
              (iVar2 + *(short *)(*(int *)(iVar2 + 4) + 0x38),param_1);
    FUN_0004033c(2,iVar5,0xfff,*(undefined2 *)(param_1 + 0xea));
                    /* WARNING: Bad instruction - Truncating control flow here */
---
  }
  if (bVar1) {
    (**(code **)(*(int *)(iVar2 + 4) + 0x3c))
              (iVar2 + *(short *)(*(int *)(iVar2 + 4) + 0x38),param_1);
    FUN_0004033c(2,iVar5,0xfff,*(undefined2 *)(param_1 + 0xea));
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
---
## FUN_000489a8

VertRefs: 14  Shifts: 4

  uVar15 = (uint)*(ushort *)(iVar16 + 8);
  iVar4 = func_0x00081248(param_1 + 0x68);
  if (*(short *)(param_1 + 10) + iVar4 < iVar3) {
    if (*(int *)(iVar16 + 0x38) == 0) {
      iVar4 = *(int *)(param_1 + 0xb8);
      if (*(char *)(iVar4 + 5) == '\x06') {
        uVar15 = 0x200;
---
            uVar7 = getCopReg(2,0x4800);
            uVar12 = getCopReg(2,0x5000);
            uVar13 = getCopReg(2,0x5800);
            *(short *)(iVar3 + 0x3c) = (short)uVar7;
            *(short *)(iVar3 + 0x3e) = (short)uVar12;
            *(short *)(iVar3 + 0x40) = (short)uVar13;
            *(short *)(iVar3 + 0x44) = (short)uVar15;
---
            uVar12 = getCopReg(2,0x5000);
            uVar13 = getCopReg(2,0x5800);
            *(short *)(iVar3 + 0x3c) = (short)uVar7;
            *(short *)(iVar3 + 0x3e) = (short)uVar12;
            *(short *)(iVar3 + 0x40) = (short)uVar13;
            *(short *)(iVar3 + 0x44) = (short)uVar15;
            *(short *)(iVar3 + 0x34) = (short)((int)((int)*(short *)(iVar3 + 0x3c) * uVar15) >> 0xc)
---
            uVar13 = getCopReg(2,0x5800);
            *(short *)(iVar3 + 0x3c) = (short)uVar7;
            *(short *)(iVar3 + 0x3e) = (short)uVar12;
            *(short *)(iVar3 + 0x40) = (short)uVar13;
            *(short *)(iVar3 + 0x44) = (short)uVar15;
            *(short *)(iVar3 + 0x34) = (short)((int)((int)*(short *)(iVar3 + 0x3c) * uVar15) >> 0xc)
            ;
---
            *(short *)(iVar3 + 0x3c) = (short)uVar7;
            *(short *)(iVar3 + 0x3e) = (short)uVar12;
            *(short *)(iVar3 + 0x40) = (short)uVar13;
            *(short *)(iVar3 + 0x44) = (short)uVar15;
            *(short *)(iVar3 + 0x34) = (short)((int)((int)*(short *)(iVar3 + 0x3c) * uVar15) >> 0xc)
            ;
            *(short *)(iVar3 + 0x36) = (short)((int)((int)*(short *)(iVar3 + 0x3e) * uVar15) >> 0xc)
---
            *(short *)(iVar3 + 0x3e) = (short)uVar12;
            *(short *)(iVar3 + 0x40) = (short)uVar13;
            *(short *)(iVar3 + 0x44) = (short)uVar15;
            *(short *)(iVar3 + 0x34) = (short)((int)((int)*(short *)(iVar3 + 0x3c) * uVar15) >> 0xc)
            ;
            *(short *)(iVar3 + 0x36) = (short)((int)((int)*(short *)(iVar3 + 0x3e) * uVar15) >> 0xc)
            ;
---
            *(short *)(iVar3 + 0x44) = (short)uVar15;
            *(short *)(iVar3 + 0x34) = (short)((int)((int)*(short *)(iVar3 + 0x3c) * uVar15) >> 0xc)
            ;
            *(short *)(iVar3 + 0x36) = (short)((int)((int)*(short *)(iVar3 + 0x3e) * uVar15) >> 0xc)
            ;
            *(short *)(iVar3 + 0x38) = (short)((int)((int)*(short *)(iVar3 + 0x40) * uVar15) >> 0xc)
            ;
---
            ;
            *(short *)(iVar3 + 0x36) = (short)((int)((int)*(short *)(iVar3 + 0x3e) * uVar15) >> 0xc)
            ;
            *(short *)(iVar3 + 0x38) = (short)((int)((int)*(short *)(iVar3 + 0x40) * uVar15) >> 0xc)
            ;
            *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(param_1 + 8);
            *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(param_1 + 0xc);
---
        } while ((int)uVar6 < (int)*(short *)(*(int *)(param_1 + 0xb8) + 0x48));
      }
      uVar9 = 0;
      if (*(int *)(iVar16 + 0x38) != 0) {
        uVar7 = func_0x00084204();
        func_0x00087010(uVar7,1,iVar14,0x300,0);
        return;
---
      }
      do {
        iVar3 = 0xc00000;
        if (0 < *(short *)(iVar16 + 0x3e)) {
          iVar3 = 0xc0;
        }
        uVar10 = FUN_000209dc();
---
  }
  else {
    sVar2 = func_0x00081248(param_1 + 0x68);
    *(short *)(param_1 + 10) = (short)iVar3 - (sVar2 + 0x40);
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
---
