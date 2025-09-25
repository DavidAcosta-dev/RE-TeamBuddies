# Orientation Focus Context

Threshold: score >= 1.5
Total selected: 16

## FUN_00048150 (score 2.0)

                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  iVar8 = (*(uint *)(iVar2 + 8) & 0xffff) - (local_48 & 0xffff);
  iVar7 = (*(uint *)(iVar2 + 8) >> 0x10) - (local_48 >> 0x10);
  iVar6 = (*(uint *)(iVar2 + 0xc) & 0xffff) - (local_44 & 0xffff);
  local_28 = CONCAT22((short)iVar7,(short)iVar8);
---
  }
  iVar8 = (*(uint *)(iVar2 + 8) & 0xffff) - (local_48 & 0xffff);
  iVar7 = (*(uint *)(iVar2 + 8) >> 0x10) - (local_48 >> 0x10);
  iVar6 = (*(uint *)(iVar2 + 0xc) & 0xffff) - (local_44 & 0xffff);
  local_28 = CONCAT22((short)iVar7,(short)iVar8);
  iVar7 = (int)*(short *)(param_1 + 0x3c) * (iVar8 * 0x10000 >> 0x10) +
          (int)*(short *)(param_1 + 0x3e) * (iVar7 * 0x10000 >> 0x10) +

## FUN_000475dc (score 2.0)

        (**(code **)(uVar7 * 4 + -0x7ff385fc))();
        return;
      }
      uVar9 = *(undefined4 *)((*(uint *)(iVar15 + 0x18) & 0xfff) * 4 + -0x7ffeb164);
      iVar4 = *(int *)(param_1 + 0xd8);
      setCopControlWord(2,0,*(undefined4 *)(iVar4 + 0xe4));
      setCopControlWord(2,0x800,*(undefined4 *)(iVar4 + 0xe8));
---
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar13 + 0xc4);
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar13 + 200);
      if (uVar14 != 0) {
        uVar7 = *(uint *)((uVar14 & 0xfff) * 4 + -0x7ffeb164);
        uVar14 = (int)uVar7 >> 0x10 & 0xffff;
        setCopControlWord(2,0,uVar14);
        uVar7 = uVar7 & 0xffff;
---
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar13 + 200);
      if (uVar14 != 0) {
        uVar7 = *(uint *)((uVar14 & 0xfff) * 4 + -0x7ffeb164);
        uVar14 = (int)uVar7 >> 0x10 & 0xffff;
        setCopControlWord(2,0,uVar14);
        uVar7 = uVar7 & 0xffff;
        setCopControlWord(2,0x2000,uVar14);
---
        uVar7 = *(uint *)((uVar14 & 0xfff) * 4 + -0x7ffeb164);
        uVar14 = (int)uVar7 >> 0x10 & 0xffff;
        setCopControlWord(2,0,uVar14);
        uVar7 = uVar7 & 0xffff;
        setCopControlWord(2,0x2000,uVar14);
        setCopControlWord(2,0x800,uVar7);
        setCopControlWord(2,0x1000,0x1000);
---
        setCopControlWord(2,0x2000,uVar14);
        setCopControlWord(2,0x800,uVar7);
        setCopControlWord(2,0x1000,0x1000);
        setCopControlWord(2,0x1800,-uVar7 & 0xffff);
        setCopReg(2,0x4800,(uint)*puVar10);
        setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x3e));
        setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x40));
---
      func_0x0010a55c(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                      param_1 + 0x10);
      *(short *)(param_1 + 0x10) = *(short *)(param_1 + 0x10) + -0x400;
      *(ushort *)(param_1 + 0x12) = 0x400U - *(short *)(param_1 + 0x12) & 0xfff;
      func_0x000b0e20(param_1 + 0x10,param_1 + 0x18);
      uVar6 = *(ushort *)(param_1 + 0xc4);
      if ((int)(uint)*(ushort *)(param_1 + 0xc4) < (int)(short)*(ushort *)(param_1 + 0x44)) {
---
        iVar4 = *(int *)(param_1 + 0xb8);
        if (*(int *)(iVar4 + 0x34) != 0) {
          func_0x0010c1b0(param_1);
          *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;
          iVar4 = *(int *)(param_1 + 0xb8);
        }
        if (*(char *)(iVar4 + 5) == '\x04') {

## FUN_00040a98 (score 2.0)

            iVar10 = (uint)*(ushort *)(*(int *)(unaff_s1 + 0xc0) + 0xe) << 0x10;
            uVar7 = FUN_000209dc();
            uVar8 = FUN_000209dc();
            iVar6 = (uVar8 & 0xfff) + 0x400;
            if (iVar6 == 0) {
              trap(7);
            }
---
            if (iVar6 == 0) {
              trap(7);
            }
            unaff_s4 = (int)(short)((((((int)((uVar7 & 0xfff) * (iVar10 >> 0x10)) >> 0xc) -
                                      (iVar10 >> 0x11)) * 0x10000 >> 0x10) << 10) / iVar6);
          }
          unaff_s2 = func_0x00106cc0(*(undefined4 *)(*(int *)(unaff_s1 + 0xc0) + 0x1c),
---
            }
            unaff_s4 = (int)(short)((((((int)((uVar7 & 0xfff) * (iVar10 >> 0x10)) >> 0xc) -
                                      (iVar10 >> 0x11)) * 0x10000 >> 0x10) << 10) / iVar6);
          }
          unaff_s2 = func_0x00106cc0(*(undefined4 *)(*(int *)(unaff_s1 + 0xc0) + 0x1c),
---
                          (*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x18));
        if ((iVar6 == 3) && (iVar6 = *(int *)(unaff_s1 + 0xd4), *(int *)(iVar6 + 0x164) != 0xb)) {
          uVar7 = FUN_00022e5c((int)*(short *)(unaff_s2 + 0x3c),(int)*(short *)(unaff_s2 + 0x40));
          iVar10 = (uVar7 & 0xfff) * 4;
          (**(code **)(*(int *)(iVar6 + 4) + 0x84))
                    (iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x80),
                     (int)*(short *)(iVar10 + -0x7ffeb164),(int)*(short *)(iVar10 + -0x7ffeb162));

## FUN_0004033c (score 2.0)

  *(undefined4 *)(param_3 + 0x20) = in_v0;
  do {
    iVar2 = in_t0 * 4;
    in_t0 = in_t0 + 1 & 0xffff;
    *(undefined4 *)(in_t2 + iVar2) = *(undefined4 *)(in_t1 + iVar2);
  } while (in_t0 < 5);
  uVar1 = *(ushort *)(param_3 + 0x42);

## FUN_000402e0 (score 2.0)

  *(undefined4 *)(param_3 + 0x20) = *(undefined4 *)(param_4 + 0x2c);
  do {
    iVar3 = uVar4 * 4;
    uVar4 = uVar4 + 1 & 0xffff;
    *(undefined4 *)(param_3 + 0x24 + iVar3) = *(undefined4 *)(param_4 + 0x38 + iVar3);
  } while (uVar4 < 5);
  uVar2 = *(ushort *)(param_3 + 0x42);

## FUN_0003e4b4 (score 2.0)

  undefined4 in_stack_00000014;
  
  while( true ) {
    unaff_s1 = unaff_s1 + 1 & 0xffff;
    if (*(ushort *)(*(int *)(unaff_s3 + 0x1a8) + 0x7a) <= unaff_s1) break;
    puVar2 = (ushort *)(*(int *)(unaff_s3 + 0x1a8) + unaff_s1 * 8);
    setCopReg(2,0x4800,(uint)*puVar2);
---
      iVar3 = 0;
      do {
        *(short *)(iVar3 + unaff_s3 + 0x266) = (short)unaff_s2;
        uVar4 = uVar4 + 1 & 0xffff;
        iVar3 = uVar4 << 3;
      } while (uVar4 < *(ushort *)(*(int *)(unaff_s3 + 0x1a8) + 0x7a));
    }

## FUN_0003e494 (score 2.0)

      unaff_s2 = (int)in_v0;
    }
    do {
      unaff_s1 = unaff_s1 + 1 & 0xffff;
      if (*(ushort *)(*(int *)(unaff_s3 + 0x1a8) + 0x7a) <= unaff_s1) {
        if (unaff_s2 != 0x7fffffff) {
          uVar3 = 0;
---
            iVar2 = 0;
            do {
              *(short *)(iVar2 + unaff_s3 + 0x266) = (short)unaff_s2;
              uVar3 = uVar3 + 1 & 0xffff;
              iVar2 = uVar3 << 3;
            } while (uVar3 < *(ushort *)(*(int *)(unaff_s3 + 0x1a8) + 0x7a));
          }

## FUN_00031b38 (score 2.0)

              }
              iVar3 = FUN_00023210(0x800c655c,iVar7,6);
              if (iVar3 == 0) {
                uVar9 = uVar8 + 1 & 0xffff;
                local_80[uVar8] = iVar2;
                uVar6 = *(undefined4 *)(iVar7 + -0x48);
                local_f8[uVar8 * 2] = *(undefined4 *)(iVar7 + -0x4c);
---
                local_80[uVar8] = iVar2;
                uVar6 = *(undefined4 *)(iVar7 + -0x48);
                local_f8[uVar8 * 2] = *(undefined4 *)(iVar7 + -0x4c);
                local_f8[uVar8 * 2 + 1] = uVar6;
              }
---
                uVar6 = *(undefined4 *)(iVar7 + -0x48);
                local_f8[uVar8 * 2] = *(undefined4 *)(iVar7 + -0x4c);
                local_f8[uVar8 * 2 + 1] = uVar6;
              }
              iVar7 = iVar7 + 0x74;
---
              iVar7 = iVar7 + 0x74;
              iVar2 = iVar2 + 0x74;
            }
            uVar5 = uVar5 + 1 & 0xffff;
            uVar8 = uVar9;
          } while ((int)uVar5 < iVar11);
        }
---
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        iVar11 = (*(ushort *)(iVar1 + 0x148) & 0xfff) * 4;
        iVar2 = (int)*(short *)(iVar11 + -0x7ffeb164);
        if (iVar2 == 0) {
          trap(7);
---
        *(undefined2 *)(iVar1 + 0x7a) = 0;
      }
    }
    uVar5 = local_2c & 0xffff;
    psVar4 = local_30;
    uVar12 = local_2c;
    if (0x53 < local_2c) {

## FUN_00023180 (score 2.0)

  
  *(undefined2 *)(unaff_s2 + 10) = in_v0;
  *(undefined4 *)(in_a3 + 0x10) = 1;
  iVar3 = (uint)*(ushort *)(unaff_s2 + 8) - (in_stack_00000010 & 0xffff);
  uStack00000020 = (undefined2)iVar3;
  sStack00000022 = *(short *)(unaff_s2 + 10) - in_stack_00000010._2_2_;
  iVar4 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uint)in_stack_00000014;
---
  sStack00000022 = *(short *)(unaff_s2 + 10) - in_stack_00000010._2_2_;
  iVar4 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uint)in_stack_00000014;
  uStack00000024 = (undefined2)iVar4;
  iVar2 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;
  iVar6 = (int)*(short *)(iVar2 + -0x7ffeb164);
  iVar5 = (int)*(short *)(iVar2 + -0x7ffeb162);
  iVar2 = -(iVar3 * 0x10000 >> 0x10) * iVar6 - (iVar4 * 0x10000 >> 0x10) * iVar5 >> 0xc;

## FUN_00023110 (score 2.0)

  }
  *(undefined4 *)(unaff_s2 + 0x78) = 1;
  sStack00000022 = *(short *)(unaff_s2 + 10) - param_5._2_2_;
  iVar3 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;
  iVar5 = (int)*(short *)(iVar3 + -0x7ffeb164);
  iVar4 = (int)*(short *)(iVar3 + -0x7ffeb162);
  iVar3 = -((int)(((uint)*(ushort *)(unaff_s2 + 8) - (param_5 & 0xffff)) * 0x10000) >> 0x10) * iVar5
---
  iVar3 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;
  iVar5 = (int)*(short *)(iVar3 + -0x7ffeb164);
  iVar4 = (int)*(short *)(iVar3 + -0x7ffeb162);
  iVar3 = -((int)(((uint)*(ushort *)(unaff_s2 + 8) - (param_5 & 0xffff)) * 0x10000) >> 0x10) * iVar5
          - ((int)(((uint)*(ushort *)(unaff_s2 + 0xc) - (uint)param_6) * 0x10000) >> 0x10) * iVar4
          >> 0xc;
  if (iVar3 < 0) {

## FUN_00023000 (score 2.0)

    *(short *)(unaff_s2 + 10) = (short)iVar3;
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 1;
  iVar3 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;
  iVar6 = (int)*(short *)(iVar3 + -0x7ffeb164);
  iVar4 = (int)*(short *)(iVar3 + -0x7ffeb162);
  iVar3 = -((int)(((uint)*(ushort *)(unaff_s2 + 8) - (uint)param_5) * 0x10000) >> 0x10) * iVar6 -

## FUN_00022e5c (score 2.0)

          uVar7 = FUN_00022e5c((int)*(short *)(unaff_s2 + 0x3c),(int)*(short *)(unaff_s2 + 0x40));

          iVar10 = (uVar7 & 0xfff) * 4;

          (**(code **)(*(int *)(iVar6 + 4) + 0x84))


## FUN_00007420 (score 2.0)

        _DAT_8004d6ee = _DAT_800d16a6;
        for (uVar8 = (int)_DAT_800d16a0 + (int)_DAT_800d16a2; _DAT_800d16a0 = _DAT_8004d6e8,
            _DAT_800d16a6 = _DAT_8004d6ee, uVar8 < 4; uVar8 = uVar8 + 1) {
          *(undefined2 *)(&DAT_8004d712 + (uVar8 & 0xffff) * 2) = 3;
          _DAT_8004d6e8 = _DAT_800d16a0;
          _DAT_8004d6ee = _DAT_800d16a6;
        }
---
            do {
              uVar3 = *puVar9;
              puVar9 = puVar9 + 0xc;
              uVar10 = uVar8 & 0xffff;
              uVar8 = uVar8 + 1;
              *(char *)(uVar10 + 0x8004d758) = (char)uVar3;
            } while (uVar8 < 4);

## FUN_00005c9c (score 2.0)

  iVar2 = 0;
  do {
    *(undefined4 *)(iVar2 + -0x7ff30500) = 0;
    uVar4 = uVar4 + 1 & 0xffff;
    iVar2 = uVar4 << 2;
  } while (uVar4 < 9);
  uVar4 = 0;
---
      uVar8 = uVar5;
    }
    uVar3 = func_0x000ada5c(iVar6,*(undefined4 *)(iVar7 + 0x24));
    uVar4 = uVar4 + 1 & 0xffff;
    *(undefined4 *)(*(int *)(iVar2 + -0x7ff30f50) * 4 + -0x7ff30500) = uVar3;
    iVar2 = uVar4 << 2;
  } while (uVar4 < 6);

## FUN_00001ad4 (score 2.0)

    return;
  }
  if (param_3 != 0) {
    iVar4 = *(int *)((_DAT_800ceda4 & 0xfff) * 4 + -0x7ffeb164);
    iVar5 = iVar4 >> 0x10;
    iVar4 = (int)(short)iVar4;
    *param_1 = (short)(iVar5 * (short)param_1[4] + iVar4 * (short)param_1[6] >> 0xc);
---
  uVar1 = param_1[0x13];
  uVar2 = param_1[0x12];
  if ((uint)uVar1 != (uint)uVar2) {
    uVar6 = (uint)uVar1 - (uint)uVar2 & 0xfff;
    if (0x800 < uVar6) {
      uVar6 = uVar6 - 0x1000;
    }
---
    }
    param_1[0x12] = uVar2 + (short)iVar4;
    uVar1 = param_1[0x12];
    param_1[0x12] = uVar1 & 0xfff;
    if (((uVar1 & 0xfff) - param_1[0x13] & 0xfff) == 0) {
      param_1[0x12] = param_1[0x13];
    }
---
    param_1[0x12] = uVar2 + (short)iVar4;
    uVar1 = param_1[0x12];
    param_1[0x12] = uVar1 & 0xfff;
    if (((uVar1 & 0xfff) - param_1[0x13] & 0xfff) == 0) {
      param_1[0x12] = param_1[0x13];
    }
  }

## FUN_000431e4 (score 1.5)

  int unaff_s5;
  
  do {
    uVar4 = unaff_s0 + 1 & 0xffff;
    *(uint *)((uint)*(ushort *)(param_4 + unaff_s0 * 2) * 4 + in_t0) = param_1 + unaff_s0 * 0x50;
    unaff_s0 = uVar4;
  } while (uVar4 < unaff_s1);
---
  do {
    uVar4 = unaff_s0 + 1 & 0xffff;
    *(uint *)((uint)*(ushort *)(param_4 + unaff_s0 * 2) * 4 + in_t0) = param_1 + unaff_s0 * 0x50;
    unaff_s0 = uVar4;
  } while (uVar4 < unaff_s1);
---
    do {
      uVar3 = (uint)*(ushort *)(&stack0x00000010 + iVar1);
      func_0x001073a8(uVar3,unaff_s4 + uVar3 * 0x6c,unaff_s4 + iVar2 * 0x6c + uVar3 * 4);
      uVar4 = uVar4 + 1 & 0xffff;
      iVar1 = uVar4 << 1;
    } while (uVar4 < unaff_s1);
  }
---
      func_0x001073a8(uVar3,unaff_s4 + uVar3 * 0x6c,unaff_s4 + iVar2 * 0x6c + uVar3 * 4);
      uVar4 = uVar4 + 1 & 0xffff;
      iVar1 = uVar4 << 1;
    } while (uVar4 < unaff_s1);
  }

