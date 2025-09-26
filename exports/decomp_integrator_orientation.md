# Integrator/Orientation Decomp (Annotated)

## FUN_00022dc8 (GAME.BIN) @ 0x022dc8


/* WARNING: Control flow encountered bad instruction data */

void FUN_00022dc8(int param_1)

{
  short sVar1;
  undefined2 uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  short sVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined4 in_t3;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 uStack_58;
  uint local_54;
  undefined4 uStack_50;
  uint uStack_4c;
  short sStack_48;
  short sStack_46;
  short sStack_44;
  int iStack_40;
  int iStack_3c;
  int iStack_38;
  int iStack_30;
  int iStack_2c;
  uint auStack_28 [2];
  
  uVar3 = func_0x000f55e4(*(undefined4 *)(param_1 + 0xec),param_1);
  FUN_00023000(&uStack_58,0,8);
  iVar4 = *(int *)(param_1 + 0xec);
  setCopControlWord(2,0,*(undefined4 *)(iVar4 + 0x18));
  setCopControlWord(2,0x800,*(undefined4 *)(iVar4 + 0x1c));
  setCopControlWord(2,0x1000,*(undefined4 *)(iVar4 + 0x20));    // ANG.yaw
  setCopControlWord(2,0x1800,*(undefined4 *)(iVar4 + 0x24));    // ANG.roll
  setCopControlWord(2,0x2000,*(undefined4 *)(iVar4 + 0x28));
  iVar9 = (int)*(short *)(iVar4 + 0x152);
  iVar10 = (int)*(short *)(iVar4 + 0x154);
  setCopControlWord(2,0x2800,(int)*(short *)(iVar4 + 0x150));
  setCopControlWord(2,0x3000,iVar9);
  setCopControlWord(2,0x3800,iVar10);
  setCopReg(2,0x4800,uStack_58 & 0xffff);    // ANGLE_MASK
  setCopReg(2,0x5000,uStack_58 >> 0x10);
  setCopReg(2,0x5800,(uint)(ushort)((short)(-(int)*(short *)(*(int *)(iVar4 + 0x1a8) + 0x90) / 2) -
                                   0x80));
  copFunction(2,0x498012);
  uVar11 = getCopReg(2,0x4800);
  uVar12 = getCopReg(2,0x5000);
  uVar13 = getCopReg(2,0x5800);
  uStack_58 = CONCAT22((short)uVar12,(short)uVar11);
  local_54 = CONCAT22(local_54._2_2_,(short)uVar13);
  if (uVar3 != 0) {
    iVar4 = *(int *)(*(int *)(param_1 + 0xec) + (uVar3 - 1) * 4 + 0x184);
    uVar5 = *(uint *)(iVar4 + 8);
    uStack_4c = *(uint *)(iVar4 + 0xc);    // POS.y
    uStack_50._2_2_ = (short)(uVar5 >> 0x10);
    iVar6 = (uint)*(ushort *)(param_1 + 0xc) - (uStack_4c & 0xffff);    // POS.y ANGLE_MASK
    iVar4 = (uint)*(ushort *)(param_1 + 8) - (uVar5 & 0xffff);    // ANGLE_MASK
    sStack_48 = (short)iVar4;
    sStack_44 = (short)iVar6;
    sStack_46 = *(short *)(param_1 + 10) - uStack_50._2_2_;
    uStack_50 = uVar5;
    sVar1 = FUN_00022e5c(iVar6 * 0x10000 >> 0x10,iVar4 * 0x10000 >> 0x10);
    iStack_40 = (int)sStack_48;
    iStack_3c = (int)sStack_46;
    iStack_38 = (int)sStack_44;
    *(short *)(param_1 + 0x12) = -sVar1;
    setCopReg(2,iVar9,iStack_40);
    setCopReg(2,iVar10,iStack_3c);
    setCopReg(2,in_t3,iStack_38);
    copFunction(2,0xa00428);
    iVar9 = getCopReg(2,0xc800);
    iVar4 = getCopReg(2,0xd000);
    iStack_30 = getCopReg(2,0xd800);
    iStack_30 = iVar9 + iVar4 + iStack_30;
    FUN_00022bac(iStack_30,&iStack_2c,auStack_28);
    iStack_40 = iStack_40 * iStack_2c >> (auStack_28[0] & 0x1f);
    iStack_3c = iStack_3c * iStack_2c >> (auStack_28[0] & 0x1f);
    iStack_38 = iStack_38 * iStack_2c >> (auStack_28[0] & 0x1f);
    iVar4 = FUN_00023180((int)sStack_48 * (int)sStack_48 + (int)sStack_46 * (int)sStack_46 +
                         (int)sStack_44 * (int)sStack_44);
    iVar4 = (iVar4 + -300) * 0x10000 >> 0x10;
    sVar1 = (short)(((int)(((uint)*(ushort *)(param_1 + 0x34) - (iVar4 * iStack_40 >> 0xf)) *    // BD.x
                          0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(param_1 + 0x34) = sVar1;    // BD.x
    sVar7 = (short)(((int)(((uint)*(ushort *)(param_1 + 0x36) - (iVar4 * iStack_3c >> 0xf)) *    // BD.y
                          0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(param_1 + 0x36) = sVar7;    // BD.y
    *(short *)(param_1 + 8) = *(short *)(param_1 + 8) + sVar1;
    sVar1 = (short)(((int)(((uint)*(ushort *)(param_1 + 0x38) - (iVar4 * iStack_38 >> 0xf)) *    // BD.z
                          0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(param_1 + 0x38) = sVar1;    // BD.z
    *(short *)(param_1 + 10) = *(short *)(param_1 + 10) + sVar7;
    *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + sVar1;    // POS.y POS.y
    iVar4 = func_0x000ab4d0(param_1 + 8);
    if (iVar4 < *(short *)(param_1 + 10)) {
      *(short *)(param_1 + 10) = (short)iVar4;
    }
    *(undefined4 *)(param_1 + 0x78) = 1;
    iVar9 = (uint)*(ushort *)(param_1 + 8) - (uStack_58 & 0xffff);    // ANGLE_MASK
    sStack_48 = (short)iVar9;
    sStack_46 = *(short *)(param_1 + 10) - uStack_58._2_2_;
    iVar10 = (uint)*(ushort *)(param_1 + 0xc) - (local_54 & 0xffff);    // POS.y ANGLE_MASK
    sStack_44 = (short)iVar10;
    iVar4 = (*(ushort *)(*(int *)(param_1 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
    iVar8 = (int)*(short *)(iVar4 + -0x7ffeb164);
    iVar6 = (int)*(short *)(iVar4 + -0x7ffeb162);
    iVar4 = -(iVar9 * 0x10000 >> 0x10) * iVar8 - (iVar10 * 0x10000 >> 0x10) * iVar6 >> 0xc;    // Q12_SHIFT Q12_PROD
    if (iVar4 < 0) {
      iVar4 = iVar4 + -10;
      *(short *)(param_1 + 0x34) = (short)(-iVar8 >> 7);    // BD.x
      *(short *)(param_1 + 0x38) = (short)(-iVar6 >> 7);    // BD.z
      *(ushort *)(param_1 + 8) = *(ushort *)(param_1 + 8) - (short)(-(iVar4 * iVar8) >> 0xc);    // Q12_SHIFT Q12_PROD
      *(ushort *)(param_1 + 0xc) = *(ushort *)(param_1 + 0xc) - (short)(-(iVar4 * iVar6) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
    }
    iVar4 = *(int *)(param_1 + 0xec);
    uVar5 = 0;
    if (*(short *)(iVar4 + 0x182) != 0) {
      do {
        iVar9 = uVar5 * 4;
        if (uVar5 != uVar3) {
          *(undefined4 *)(*(int *)(iVar4 + iVar9 + 0x184) + 0x78) = 1;
          func_0x000e8cfc(param_1,*(undefined4 *)(*(int *)(param_1 + 0xec) + iVar9 + 0x184));
          *(undefined4 *)(*(int *)(*(int *)(param_1 + 0xec) + iVar9 + 0x184) + 0x78) = 4;
        }
        iVar4 = *(int *)(param_1 + 0xec);
        uVar5 = uVar5 + 1;
      } while (uVar5 < *(ushort *)(iVar4 + 0x182));
    }
    *(undefined4 *)(param_1 + 0x78) = 4;
    uVar2 = 0xc100;
    if ((*(short *)(param_1 + 8) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(param_1 + 8))) {
      *(undefined2 *)(param_1 + 8) = uVar2;
    }
    uVar2 = 0xc100;
    if ((*(short *)(param_1 + 0xc) < -0x3f00) ||    // POS.y
       (uVar2 = 0x3f00, 0x3f00 < *(short *)(param_1 + 0xc))) {    // POS.y
      *(undefined2 *)(param_1 + 0xc) = uVar2;    // POS.y
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00022e5c (GAME.BIN) @ 0x022e5c


/* WARNING: Control flow encountered bad instruction data */

void FUN_00022e5c(int param_1)

{
  uint uVar1;
  uint uVar2;
  short sVar3;
  undefined2 uVar4;
  int in_v1;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  short sVar9;
  int iVar10;
  int iVar11;
  undefined4 in_t3;
  undefined4 in_t4;
  undefined4 uVar12;
  undefined4 uVar13;
  uint uVar14;
  ushort *unaff_s0;
  int unaff_s2;
  uint unaff_s5;
  int iVar15;
  uint uStack00000010;
  uint uStack00000018;
  uint uStack0000001c;
  short sStack00000020;
  short sStack00000022;
  short sStack00000024;
  int in_stack_0000003c;
  uint in_stack_00000040;
  
  setCopControlWord(2,0x1000,in_t4);
  setCopControlWord(2,0x1800,*(undefined4 *)(in_v1 + 0xc));    // POS.y
  setCopControlWord(2,0x2000,*(undefined4 *)(in_v1 + 0x10));    // POS.z
  iVar10 = (int)*(short *)(param_1 + 0x152);
  iVar11 = (int)*(short *)(param_1 + 0x154);
  setCopControlWord(2,0x2800,(int)*(short *)(param_1 + 0x150));
  setCopControlWord(2,0x3000,iVar10);
  setCopControlWord(2,0x3800,iVar11);
  setCopReg(2,0x4800,(uint)*unaff_s0);
  setCopReg(2,0x5000,(uint)unaff_s0[1]);
  setCopReg(2,0x5800,(uint)unaff_s0[2]);
  copFunction(2,0x498012);
  uVar12 = getCopReg(2,0x4800);
  uVar13 = getCopReg(2,0x5000);
  uVar14 = getCopReg(2,0x5800);
  uStack00000010 = CONCAT22((short)uVar13,(short)uVar12);
  if (unaff_s5 != 0) {
    iVar5 = *(int *)(*(int *)(unaff_s2 + 0xec) + (unaff_s5 - 1) * 4 + 0x184);
    uVar7 = *(uint *)(iVar5 + 8);
    uStack0000001c = *(uint *)(iVar5 + 0xc);    // POS.y
    uStack00000018._2_2_ = (short)(uVar7 >> 0x10);
    iVar8 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uStack0000001c & 0xffff);    // POS.y ANGLE_MASK
    iVar5 = (uint)*(ushort *)(unaff_s2 + 8) - (uVar7 & 0xffff);    // ANGLE_MASK
    sStack00000020 = (short)iVar5;
    sStack00000024 = (short)iVar8;
    sStack00000022 = *(short *)(unaff_s2 + 10) - uStack00000018._2_2_;
    uStack00000018 = uVar7;
    sVar3 = FUN_00022e5c(iVar8 * 0x10000 >> 0x10,iVar5 * 0x10000 >> 0x10);
    iVar5 = (int)sStack00000020;
    iVar8 = (int)sStack00000022;
    iVar6 = (int)sStack00000024;
    *(short *)(unaff_s2 + 0x12) = -sVar3;
    setCopReg(2,iVar10,iVar5);
    setCopReg(2,iVar11,iVar8);
    setCopReg(2,in_t3,iVar6);
    copFunction(2,0xa00428);
    iVar15 = getCopReg(2,0xc800);
    iVar10 = getCopReg(2,0xd000);
    iVar11 = getCopReg(2,0xd800);
    FUN_00022bac(iVar15 + iVar10 + iVar11,&stack0x0000003c,&stack0x00000040);
    iVar5 = iVar5 * in_stack_0000003c;
    iVar8 = iVar8 * in_stack_0000003c;
    iVar6 = iVar6 * in_stack_0000003c;
    uVar7 = in_stack_00000040 & 0x1f;
    uVar1 = in_stack_00000040 & 0x1f;
    uVar2 = in_stack_00000040 & 0x1f;
    iVar10 = FUN_00023180((int)sStack00000020 * (int)sStack00000020 +
                          (int)sStack00000022 * (int)sStack00000022 +
                          (int)sStack00000024 * (int)sStack00000024);
    iVar10 = (iVar10 + -300) * 0x10000 >> 0x10;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar10 * (iVar5 >> uVar7) >> 0xf))    // BD.x
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x34) = sVar3;    // BD.x
    sVar9 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar10 * (iVar8 >> uVar1) >> 0xf))    // BD.y
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x36) = sVar9;    // BD.y
    *(short *)(unaff_s2 + 8) = *(short *)(unaff_s2 + 8) + sVar3;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x38) - (iVar10 * (iVar6 >> uVar2) >> 0xf))    // BD.z
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x38) = sVar3;    // BD.z
    *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + sVar9;
    *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar3;    // POS.y POS.y
    iVar10 = func_0x000ab4d0(unaff_s2 + 8);
    if (iVar10 < *(short *)(unaff_s2 + 10)) {
      *(short *)(unaff_s2 + 10) = (short)iVar10;
    }
    *(undefined4 *)(unaff_s2 + 0x78) = 1;
    iVar11 = (uint)*(ushort *)(unaff_s2 + 8) - (uStack00000010 & 0xffff);    // ANGLE_MASK
    sStack00000020 = (short)iVar11;
    sStack00000022 = *(short *)(unaff_s2 + 10) - uStack00000010._2_2_;
    iVar5 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uVar14 & 0xffff);    // POS.y ANGLE_MASK
    sStack00000024 = (short)iVar5;
    iVar10 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
    iVar6 = (int)*(short *)(iVar10 + -0x7ffeb164);
    iVar8 = (int)*(short *)(iVar10 + -0x7ffeb162);
    iVar10 = -(iVar11 * 0x10000 >> 0x10) * iVar6 - (iVar5 * 0x10000 >> 0x10) * iVar8 >> 0xc;    // Q12_SHIFT Q12_PROD
    if (iVar10 < 0) {
      iVar10 = iVar10 + -10;
      *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);    // BD.x
      *(short *)(unaff_s2 + 0x38) = (short)(-iVar8 >> 7);    // BD.z
      *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar10 * iVar6) >> 0xc);    // Q12_SHIFT Q12_PROD
      *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar10 * iVar8) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
    }
    iVar10 = *(int *)(unaff_s2 + 0xec);
    uVar14 = 0;
    if (*(short *)(iVar10 + 0x182) != 0) {
      do {
        if (uVar14 != unaff_s5) {
          *(undefined4 *)(*(int *)(iVar10 + uVar14 * 4 + 0x184) + 0x78) = 1;
          func_0x000e8cfc();
          *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar14 * 4 + 0x184) + 0x78) = 4;
        }
        iVar10 = *(int *)(unaff_s2 + 0xec);
        uVar14 = uVar14 + 1;
      } while (uVar14 < *(ushort *)(iVar10 + 0x182));
    }
    *(undefined4 *)(unaff_s2 + 0x78) = 4;
    uVar4 = 0xc100;
    if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar4 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8)))
    {
      *(undefined2 *)(unaff_s2 + 8) = uVar4;
    }
    uVar4 = 0xc100;
    if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
       (uVar4 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
      *(undefined2 *)(unaff_s2 + 0xc) = uVar4;    // POS.y
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00023000 (GAME.BIN) @ 0x023000


void FUN_00023000(undefined4 param_1,int param_2,undefined4 param_3,int param_4,ushort param_5,
                 ushort param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9,
                 short param_10,undefined4 param_11,undefined4 param_12,int param_13)

{
  short sVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  short sVar5;
  int in_t0;
  int iVar6;
  uint uVar7;
  int unaff_s2;
  uint unaff_s5;
  uint in_stack_00000040;
  
  param_11 = in_t0 >> (in_stack_00000040 & 0x1f);
  param_12 = param_4 * param_2 >> (in_stack_00000040 & 0x1f);
  iVar3 = FUN_00023180((int)(short)param_9 * (int)(short)param_9 +
                       (int)param_9._2_2_ * (int)param_9._2_2_ + (int)param_10 * (int)param_10);
  iVar3 = (iVar3 + -300) * 0x10000 >> 0x10;
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar3 * param_11 >> 0xf)) * 0x10000)    // BD.x
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x34) = sVar1;    // BD.x
  sVar5 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar3 * param_12 >> 0xf)) * 0x10000)    // BD.y
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x36) = sVar5;    // BD.y
  *(short *)(unaff_s2 + 8) = *(short *)(unaff_s2 + 8) + sVar1;
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x38) -    // BD.z
                         (iVar3 * (param_13 * param_2 >> (in_stack_00000040 & 0x1f)) >> 0xf)) *
                        0x10000) >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x38) = sVar1;    // BD.z
  *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + sVar5;
  *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar1;    // POS.y POS.y
  iVar3 = func_0x000ab4d0(unaff_s2 + 8);
  if (iVar3 < *(short *)(unaff_s2 + 10)) {
    *(short *)(unaff_s2 + 10) = (short)iVar3;
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 1;
  iVar3 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
  iVar6 = (int)*(short *)(iVar3 + -0x7ffeb164);
  iVar4 = (int)*(short *)(iVar3 + -0x7ffeb162);
  iVar3 = -((int)(((uint)*(ushort *)(unaff_s2 + 8) - (uint)param_5) * 0x10000) >> 0x10) * iVar6 -
          ((int)(((uint)*(ushort *)(unaff_s2 + 0xc) - (uint)param_6) * 0x10000) >> 0x10) * iVar4 >>    // POS.y Q12_SHIFT
          0xc;
  if (iVar3 < 0) {
    iVar3 = iVar3 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);    // BD.x
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar4 >> 7);    // BD.z
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar3 * iVar6) >> 0xc);    // Q12_SHIFT Q12_PROD
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar3 * iVar4) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
  }
  iVar3 = *(int *)(unaff_s2 + 0xec);
  uVar7 = 0;
  if (*(short *)(iVar3 + 0x182) != 0) {
    do {
      if (uVar7 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar3 + uVar7 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar7 * 4 + 0x184) + 0x78) = 4;
      }
      iVar3 = *(int *)(unaff_s2 + 0xec);
      uVar7 = uVar7 + 1;
    } while (uVar7 < *(ushort *)(iVar3 + 0x182));
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 4;
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar2;
  }
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar2;    // POS.y
  }
  return;
}


---

## FUN_00023110 (GAME.BIN) @ 0x023110


void FUN_00023110(undefined4 param_1,undefined4 param_2,short param_3,short param_4,uint param_5,
                 ushort param_6)

{
  short sVar1;
  undefined2 uVar2;
  int iVar3;
  int in_v1;
  int iVar4;
  short in_t0;
  int iVar5;
  uint uVar6;
  int unaff_s2;
  uint unaff_s5;
  int in_lo;
  short sStack00000022;
  
  *(short *)(unaff_s2 + 0x36) = param_4;    // BD.y
  *(short *)(unaff_s2 + 8) = param_3 + in_t0;
  sVar1 = (short)(((in_v1 - (in_lo >> 0xf)) * 0x10000 >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x38) = sVar1;    // BD.z
  *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + param_4;
  *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar1;    // POS.y POS.y
  iVar3 = func_0x000ab4d0();
  if (iVar3 < *(short *)(unaff_s2 + 10)) {
    *(short *)(unaff_s2 + 10) = (short)iVar3;
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 1;
  sStack00000022 = *(short *)(unaff_s2 + 10) - param_5._2_2_;
  iVar3 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
  iVar5 = (int)*(short *)(iVar3 + -0x7ffeb164);
  iVar4 = (int)*(short *)(iVar3 + -0x7ffeb162);
  iVar3 = -((int)(((uint)*(ushort *)(unaff_s2 + 8) - (param_5 & 0xffff)) * 0x10000) >> 0x10) * iVar5    // ANGLE_MASK
          - ((int)(((uint)*(ushort *)(unaff_s2 + 0xc) - (uint)param_6) * 0x10000) >> 0x10) * iVar4    // POS.y Q12_SHIFT
          >> 0xc;    // Q12_SHIFT
  if (iVar3 < 0) {
    iVar3 = iVar3 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar5 >> 7);    // BD.x
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar4 >> 7);    // BD.z
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar3 * iVar5) >> 0xc);    // Q12_SHIFT Q12_PROD
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar3 * iVar4) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
  }
  iVar3 = *(int *)(unaff_s2 + 0xec);
  uVar6 = 0;
  if (*(short *)(iVar3 + 0x182) != 0) {
    do {
      if (uVar6 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar3 + uVar6 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar6 * 4 + 0x184) + 0x78) = 4;
      }
      iVar3 = *(int *)(unaff_s2 + 0xec);
      uVar6 = uVar6 + 1;
    } while (uVar6 < *(ushort *)(iVar3 + 0x182));
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 4;
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar2;
  }
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar2;    // POS.y
  }
  return;
}


---

## FUN_00023180 (GAME.BIN) @ 0x023180


void FUN_00023180(void)

{
  undefined2 in_v0;
  undefined2 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int in_a3;
  int iVar6;
  uint uVar7;
  int unaff_s2;
  uint unaff_s5;
  uint in_stack_00000010;
  ushort in_stack_00000014;
  undefined2 uStack00000020;
  short sStack00000022;
  undefined2 uStack00000024;
  
  *(undefined2 *)(unaff_s2 + 10) = in_v0;
  *(undefined4 *)(in_a3 + 0x10) = 1;    // POS.z
  iVar3 = (uint)*(ushort *)(unaff_s2 + 8) - (in_stack_00000010 & 0xffff);    // ANGLE_MASK
  uStack00000020 = (undefined2)iVar3;
  sStack00000022 = *(short *)(unaff_s2 + 10) - in_stack_00000010._2_2_;
  iVar4 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uint)in_stack_00000014;    // POS.y
  uStack00000024 = (undefined2)iVar4;
  iVar2 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
  iVar6 = (int)*(short *)(iVar2 + -0x7ffeb164);
  iVar5 = (int)*(short *)(iVar2 + -0x7ffeb162);
  iVar2 = -(iVar3 * 0x10000 >> 0x10) * iVar6 - (iVar4 * 0x10000 >> 0x10) * iVar5 >> 0xc;    // Q12_SHIFT Q12_PROD
  if (iVar2 < 0) {
    iVar2 = iVar2 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);    // BD.x
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar5 >> 7);    // BD.z
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar2 * iVar6) >> 0xc);    // Q12_SHIFT Q12_PROD
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar2 * iVar5) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
  }
  iVar2 = *(int *)(unaff_s2 + 0xec);
  uVar7 = 0;
  if (*(short *)(iVar2 + 0x182) != 0) {
    do {
      if (uVar7 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar2 + uVar7 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar7 * 4 + 0x184) + 0x78) = 4;
      }
      iVar2 = *(int *)(unaff_s2 + 0xec);
      uVar7 = uVar7 + 1;
    } while (uVar7 < *(ushort *)(iVar2 + 0x182));
  }
  *(undefined4 *)(in_a3 + 0x10) = 4;    // POS.z
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar1;
  }
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar1;    // POS.y
  }
  return;
}


---

## FUN_00023210 (GAME.BIN) @ 0x023210


void FUN_00023210(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  undefined2 uVar1;
  int in_v1;
  int iVar2;
  int in_t0;
  short in_t1;
  short in_t2;
  uint uVar3;
  int unaff_s2;
  uint unaff_s5;
  
  *(short *)(unaff_s2 + 0x34) = (short)(-in_t0 >> 7);    // BD.x
  *(short *)(unaff_s2 + 0x38) = (short)(-param_3 >> 7);    // BD.z
  *(short *)(unaff_s2 + 8) = in_t2 - (short)(-((in_v1 + -10) * in_t0) >> 0xc);    // Q12_SHIFT Q12_PROD
  *(short *)(unaff_s2 + 0xc) = in_t1 - (short)(-((in_v1 + -10) * param_3) >> 0xc);    // POS.y Q12_SHIFT Q12_PROD
  iVar2 = *(int *)(unaff_s2 + 0xec);
  uVar3 = 0;
  if (*(short *)(iVar2 + 0x182) != 0) {
    do {
      if (uVar3 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar2 + uVar3 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar3 * 4 + 0x184) + 0x78) = 4;
      }
      iVar2 = *(int *)(unaff_s2 + 0xec);
      uVar3 = uVar3 + 1;
    } while (uVar3 < *(ushort *)(iVar2 + 0x182));
  }
  *(undefined4 *)(param_4 + 0x10) = 4;    // POS.z
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar1;
  }
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar1;    // POS.y
  }
  return;
}


---

## FUN_00032c18 (GAME.BIN) @ 0x032c18


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00032c18(uint param_1,undefined4 *param_2)

{
  undefined2 uVar1;
  int iVar2;
  undefined4 uVar3;
  short sVar4;
  undefined2 *puVar5;
  short sVar6;
  undefined2 *puVar7;
  int iVar8;
  undefined2 *puVar9;
  uint uVar10;
  
  param_1 = param_1 & 0xffff;    // ANGLE_MASK
  iVar2 = func_0x000f5b78(param_1,0);
  *(uint *)(iVar2 + 300) = param_1;
  *(undefined4 *)(iVar2 + 0x128) = *param_2;
  uVar3 = func_0x000743a4(1,param_1);
  *(undefined4 *)(iVar2 + 0x134) = uVar3;
  *(short *)(iVar2 + 0x138) = (short)((uint)param_2[4] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x13a) = (short)((uint)param_2[5] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x13c) = (short)((uint)param_2[6] >> 6);    // POS_SHIFT6
  sVar6 = (short)((uint)param_2[7] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x13e) = sVar6;
  sVar4 = (short)((uint)param_2[8] >> 0xc);    // Q12_SHIFT
  *(short *)(iVar2 + 0x140) = sVar4;
  *(short *)(iVar2 + 0x142) = (short)((uint)-param_2[9] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x144) = (short)((uint)param_2[10] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(short *)(iVar2 + 0x146) = (short)((uint)param_2[0xb] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x148) = *(undefined2 *)(param_2 + 0xd);
  *(undefined2 *)(iVar2 + 0x14a) = *(undefined2 *)(param_2 + 0xe);
  *(undefined2 *)(iVar2 + 0x14c) = *(undefined2 *)(param_2 + 0x10);    // POS.z
  iVar8 = (int)sVar6;
  *(short *)(iVar2 + 0x14e) = (short)((uint)param_2[0x12] >> 6);    // POS_SHIFT6
  if (iVar8 != 0) {
    if (iVar8 == 0) {
      trap(7);
    }
    *(short *)(iVar2 + 0x152) = (short)((sVar4 * 0x477) / iVar8);
  }
  *(undefined2 *)(iVar2 + 0x154) = *(undefined2 *)(param_2 + 0x18);
  *(short *)(iVar2 + 0x156) = (short)((uint)(param_2[0x18] * param_2[0x1b]) >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x15a) = *(undefined2 *)(param_2 + 0x19);
  *(undefined2 *)(iVar2 + 0x158) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar2 + 0x15c) = *(undefined2 *)(param_2 + 0x1c);
  *(undefined2 *)(iVar2 + 0x15e) = *(undefined2 *)(param_2 + 0x16);
  *(undefined2 *)(iVar2 + 0x150) = *(undefined2 *)(param_2 + 0x17);
  *(short *)(iVar2 + 0x160) = (short)((uint)param_2[0x1d] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x162) = *(undefined2 *)(param_2 + 0x21);
  *(short *)(iVar2 + 0x164) = (short)((uint)param_2[0x1f] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x166) = *(undefined2 *)(param_2 + 0x22);    // ANG.pitch
  *(short *)(iVar2 + 0x168) = (short)((uint)param_2[0x1e] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x16a) = *(undefined2 *)(param_2 + 0x23);
  *(short *)(iVar2 + 0x16c) = (short)((uint)param_2[0x20] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x16e) = *(undefined2 *)(param_2 + 0x24);    // ANG.roll
  *(short *)(iVar2 + 0x170) = (short)((uint)param_2[0x15] >> 0xc);    // Q12_SHIFT Q12_PROD
  sVar4 = (short)((uint)param_2[0x14] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x172) = sVar4;
  sVar6 = *(short *)(iVar2 + 0x128);
  if ((sVar6 == 4) || (sVar6 == 0xb)) {
    *(short *)(iVar2 + 0x174) = sVar4 * 3;
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  *(short *)(iVar2 + 0x174) = sVar4;
  *(undefined2 *)(iVar2 + 0x176) = *(undefined2 *)(param_2 + 1);
  *(undefined2 *)(iVar2 + 0x178) = *(undefined2 *)(param_2 + 2);
  uVar10 = 0;
  *(undefined2 *)(iVar2 + 0x17a) = *(undefined2 *)(param_2 + 3);
  uVar1 = *(undefined2 *)(param_2 + 0x27);
  *(undefined4 *)(iVar2 + 0x180) = 0;
  *(undefined2 *)(iVar2 + 0x17c) = uVar1;
  uVar1 = *(undefined2 *)(param_2 + 3);
  *(undefined2 *)(iVar2 + 0xb8) = 0xffff;
  *(undefined2 *)(iVar2 + 0xba) = 0xffff;
  *(undefined2 *)(iVar2 + 0xbc) = 0xffff;
  *(undefined2 *)(iVar2 + 0xbe) = 0xffff;
  *(undefined2 *)(iVar2 + 0xb4) = 0xffff;
  *(undefined2 *)(iVar2 + 0xb6) = 0xffff;
  *(undefined2 *)(iVar2 + 0xc0) = 0xffff;
  *(undefined2 *)(iVar2 + 0x17a) = uVar1;
  puVar9 = (undefined2 *)(iVar2 + 0xcc);
  *(undefined4 *)(iVar2 + 0x130) = param_2[0x25];
  puVar7 = (undefined2 *)(iVar2 + 0xca);
  *(undefined2 *)(iVar2 + 0x18a) = *(undefined2 *)(param_2 + 0x26);    // FLAGS
  puVar5 = (undefined2 *)(iVar2 + 200);
  *(undefined2 *)(iVar2 + 0x18c) = *(undefined2 *)(param_2 + 0x2b);
  do {
    *puVar5 = 0;
    *puVar7 = 0;
    *puVar9 = 0;
    puVar9 = puVar9 + 3;
    puVar7 = puVar7 + 3;
    uVar10 = uVar10 + 1;
    puVar5 = puVar5 + 3;
  } while (uVar10 < 9);
  if (param_1 - 6 < 0x4b) {
                    /* WARNING: Could not emulate address calculation at 0x00032f34 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)((param_1 - 6) * 4 + -0x7ff39824))();
    return;
  }
  func_0x000f719c(iVar2);
  if ((sVar6 == 5) || (uVar1 = 3000, sVar6 == 7)) {
    uVar1 = 6000;
  }
  *(undefined2 *)(iVar2 + 0xb0) = uVar1;
  *(undefined2 *)(iVar2 + 0x184) = *(undefined2 *)(param_2 + 0x28);
  *(undefined2 *)(iVar2 + 0x186) = *(undefined2 *)(param_2 + 0x29);
  uVar1 = *(undefined2 *)(param_2 + 0x2a);
  *(undefined2 *)(iVar2 + 0xfe) = 0x50;
  *(undefined2 *)(iVar2 + 0x188) = uVar1;
  if ((param_1 != 8) && (param_1 != 0x4a)) {
    if (param_1 == 10) {
      *(undefined2 *)(iVar2 + 0x11a) = 0;
      *(undefined2 *)(iVar2 + 0x11c) = 0xff60;
      *(undefined2 *)(iVar2 + 0x11e) = 0xfe8e;
      *(undefined2 *)(iVar2 + 0x120) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if (param_1 == 0x4c) {
      *(undefined2 *)(iVar2 + 0x11c) = 0xfe70;
      *(undefined2 *)(iVar2 + 0x11a) = 0;
      *(undefined2 *)(iVar2 + 0x11e) = 0;
      *(undefined2 *)(iVar2 + 0x120) = 1;
    }
    if (sVar6 == 6) {
      if (*(short *)(iVar2 + 0x13e) == 0) {
        trap(7);
      }
      iVar8 = (int)_DAT_8011966e * (int)_DAT_8011966e;
      if (iVar8 == 0) {
        trap(7);
      }
      *(short *)(iVar2 + 0xb2) =
           (short)((((int)*(short *)(iVar2 + 0x138) * (int)*(short *)(iVar2 + 0x138)) /
                    (int)*(short *)(iVar2 + 0x13e) << 0x11) / iVar8);
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00044a14 (GAME.BIN) @ 0x044a14


/* WARNING: Control flow encountered bad instruction data */

void FUN_00044a14(int param_1)

{
  undefined2 uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 local_20;
  undefined4 local_1c;
  
  iVar2 = func_0x000ab4d0(param_1 + 8);
  if ((*(short *)(*(int *)(param_1 + 0xb8) + 0x18) != 0) &&
     ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44))) {    // SPD
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) | 4;
  }
  if (*(short *)(param_1 + 10) <= iVar2) {
    return;
  }
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 5) == '\x04') && (0 < *(int *)(param_1 + 0xbc))) {
    if ((*(short *)(param_1 + 0x34) != 0) || (*(short *)(param_1 + 0x38) != 0)) {    // BD.x BD.z
      *(undefined2 *)(param_1 + 0x36) = 0;    // BD.y
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    uVar1 = 0xffff;
    if (*(short *)(param_1 + 0x36) == 0) {    // BD.y
      uVar1 = 0xfff6;
    }
    *(undefined2 *)(param_1 + 0x36) = uVar1;    // BD.y
    *(short *)(param_1 + 0x44) =    // SPD
         (short)((int)*(short *)(param_1 + 0x3c) * (int)*(short *)(param_1 + 0x34) +    // BS.x BD.x
                 (int)*(short *)(param_1 + 0x3e) * (int)*(short *)(param_1 + 0x36) +    // BS.y BD.y
                 (int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc);    // BS.z BD.z Q12_SHIFT Q12_PROD
    uVar1 = func_0x000ab4d0(param_1 + 8);
    *(undefined2 *)(param_1 + 10) = uVar1;
    iVar2 = func_0x000a9678((int)*(short *)(param_1 + 8),(int)*(short *)(param_1 + 0xc));    // POS.y
    if (iVar2 != 0) {
      *(undefined2 *)(param_1 + 0x44) = 0;    // SPD
    }
    func_0x00109ff4(param_1);
    if (*(short *)(param_1 + 0x44) == 0) {    // SPD
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // ANGLE_MASK
      halt_baddata();
    }
    return;
  }
  iVar3 = (int)*(short *)(param_1 + 10);
  if (iVar3 <= iVar2) {
    return;
  }
  if (iVar3 - iVar2 < 0) {
    if (iVar2 - iVar3 < 0x33) goto LAB_00044c9c;
  }
  else if (iVar3 - iVar2 < 0x33) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  uVar4 = 0x1000;
  do {
    uVar4 = (int)uVar4 >> 1;
    local_20 = CONCAT22(*(short *)(param_1 + 10) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x36)) >> 0xc),    // BD.y Q12_SHIFT Q12_PROD
                        *(short *)(param_1 + 8) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x34)) >> 0xc));    // BD.x Q12_SHIFT Q12_PROD
    local_1c = CONCAT22(local_1c._2_2_,
                        *(short *)(param_1 + 0xc) -    // POS.y
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x38)) >> 0xc));    // BD.z Q12_SHIFT Q12_PROD
    iVar2 = func_0x000ab4d0(&local_20);
    if (iVar2 < local_20._2_2_) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    iVar3 = iVar2 - local_20._2_2_;
    if (iVar3 < 0) {
      iVar3 = local_20._2_2_ - iVar2;
    }
  } while ((0x31 < iVar3) && (99 < uVar4));
  *(undefined4 *)(param_1 + 8) = local_20;
  *(undefined4 *)(param_1 + 0xc) = local_1c;    // POS.y
LAB_00044c9c:
  *(short *)(param_1 + 10) = (short)iVar2;
  if ((*(uint *)(param_1 + 0xd0) & 1) != 0) {
    *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 2;
  }
  uVar4 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x18);
  if (uVar4 == 0) {
    func_0x00084688(0xf,param_1 + 8,0);
    func_0x0010a4f8(param_1);
    uVar5 = *(uint *)(param_1 + 0xd0);
    uVar4 = uVar5 | 8;
    if ((uVar5 & 1) == 0) {
      uVar4 = uVar5 & 0xfffffff7;    // ANGLE_MASK
    }
    *(uint *)(param_1 + 0xd0) = uVar4;
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0) {    // ANG.yaw
      *(undefined2 *)(param_1 + 0xc0) = 0;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 3;
      uVar4 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
      if (uVar4 < 0x41) {
        uVar4 = 0x40;
      }
      if ((*(uint *)(param_1 + 0xd0) & 0x10) != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      *(short *)(param_1 + 0x9c) = (short)uVar4;
      *(uint *)(param_1 + 0x98) = uVar4 * uVar4;
    }
  }
  else {
    *(short *)(param_1 + 0x36) = (short)((int)-((int)*(short *)(param_1 + 0x36) * uVar4) >> 0xc);    // BD.y BD.y Q12_SHIFT Q12_PROD
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 1 & 1) != 0) {    // ANG.yaw
      uVar5 = *(uint *)((*(ushort *)(param_1 + 200) & 0x7f) * 4 + -0x7ffeb164);
      uVar4 = uVar5 >> 0x10;
      setCopControlWord(2,0,uVar4);
      uVar5 = uVar5 & 0xffff;    // ANGLE_MASK
      setCopControlWord(2,0x2000,uVar4);
      setCopControlWord(2,0x800,uVar5);
      setCopControlWord(2,0x1000,0x1000);
      setCopControlWord(2,0x1800,-uVar5 & 0xffff);    // ANGLE_MASK
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x34));    // BD.x
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x36));    // BD.y
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x38));    // BD.z
      copFunction(2,0x49e012);
      uVar6 = getCopReg(2,0x4800);
      uVar7 = getCopReg(2,0x5000);
      uVar8 = getCopReg(2,0x5800);
      *(short *)(param_1 + 0x34) = (short)uVar6;    // BD.x
      *(short *)(param_1 + 0x36) = (short)uVar7;    // BD.y
      *(short *)(param_1 + 0x38) = (short)uVar8;    // BD.z
    }
    func_0x00109ff4(param_1);
    if ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44)) {    // SPD
      uVar1 = (undefined2)
              ((int)*(short *)(param_1 + 0x34) * (int)*(short *)(param_1 + 0x3c) +    // BD.x BS.x
               (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +    // BD.y BS.y
               (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc);    // BD.z BS.z Q12_SHIFT Q12_PROD
      *(undefined2 *)(param_1 + 0xc4) = uVar1;
      *(undefined2 *)(param_1 + 0x44) = uVar1;    // SPD
    }
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffdff | 0x40;    // ANGLE_MASK
    func_0x00076790(param_1);
    uVar4 = (uint)(*(ushort *)(*(int *)(param_1 + 0xb8) + 8) >> 3);
    if (uVar4 < 3) {
      uVar4 = 3;
    }
    iVar2 = (int)*(short *)(param_1 + 0x36);    // BD.y
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    if (((iVar2 <= (int)uVar4) || ((int)*(short *)(param_1 + 0x44) <= (int)uVar4)) &&    // SPD
       (func_0x0010a4f8(param_1), (*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0)) {    // ANG.yaw
      *(undefined2 *)(param_1 + 0xc0) = 0;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 3;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  return;
}


---

## FUN_00044f80 (GAME.BIN) @ 0x044f80


/* WARNING: Control flow encountered bad instruction data */

void FUN_00044f80(int param_1)

{
  ushort uVar1;
  bool bVar2;
  short sVar3;
  undefined4 uVar4;
  uint uVar5;
  short sVar6;
  short sVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined4 local_50;
  undefined4 local_4c;
  undefined2 uStack_4a;
  short local_48;
  short local_46;
  short local_44;
  undefined1 auStack_40 [8];
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined1 auStack_28 [8];
  undefined4 local_20;
  undefined4 local_1c;
  
  iVar12 = *(int *)(param_1 + 0xd4);
  if (iVar12 != 0) {
    iVar9 = (int)(((uint)*(ushort *)(param_1 + 8) - (uint)*(ushort *)(iVar12 + 0x6c)) * 0x10000) >>
            0x10;
    iVar11 = (int)(((uint)*(ushort *)(param_1 + 10) - (uint)*(ushort *)(iVar12 + 0x6e)) * 0x10000)
             >> 0x10;
    iVar12 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)    // POS.y
             >> 0x10;
    uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
    if ((uint)(iVar9 * iVar9 + iVar11 * iVar11 + iVar12 * iVar12) <= uVar8 * uVar8) {
      uVar5 = 0x40;
      if (0x40 < uVar8) {
        uVar5 = uVar8;
      }
      *(short *)(param_1 + 0x9c) = (short)uVar5;
      *(uint *)(param_1 + 0x98) = uVar5 * uVar5;
      func_0x0010a4f8(param_1);
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  if (*(int *)(param_1 + 0xbc) < 1) {
    if ((*(uint *)(param_1 + 0x50) & 4) != 0) {
      return;
    }
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) | 4;
  }
  else {
    if (0 < *(short *)(param_1 + 0xc2)) {
      *(short *)(param_1 + 0xc2) = *(short *)(param_1 + 0xc2) + -1;
    }
    iVar12 = *(int *)(param_1 + 0xd4);
    if (iVar12 == 0) {
      if (*(short *)(param_1 + 0xc2) < 1) {
        uVar4 = func_0x0010834c(param_1);
        *(undefined4 *)(param_1 + 0xd4) = uVar4;
        *(undefined2 *)(param_1 + 0xc2) = *(undefined2 *)(*(int *)(param_1 + 0xb8) + 0x28);
        iVar12 = *(int *)(param_1 + 0xd4);
      }
      if (iVar12 == 0) {
        uVar8 = *(uint *)(*(int *)(param_1 + 0xb8) + 0x20);    // ANG.yaw
        if ((uVar8 >> 4 & 1) != 0) {
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);    // POS.z
          sVar3 = 0x80;
          if (0x80 < (int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1)) {    // SPD
            sVar3 = *(short *)(param_1 + 0x44) - uVar1;    // SPD
          }
          sVar6 = *(short *)(param_1 + 10);
          *(short *)(param_1 + 0x44) = sVar3;    // SPD
          iVar12 = func_0x000ab4d0(param_1 + 8);
          if ((((int)sVar6 < iVar12 + -0x100) && (*(short *)(param_1 + 0x3e) < 1)) &&    // BS.y
             (iVar12 = -(int)*(short *)(param_1 + 0x3e), (*(uint *)(param_1 + 0x50) & 4) == 0)) {    // BS.y
            if (iVar12 < 0x20) {
              iVar12 = 0x20;
            }
            *(short *)(param_1 + 0x3e) = (short)iVar12;    // BS.y
            func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),    // BS.x BS.z
                            param_1 + 0x3c);    // BS.x
          }
          iVar12 = (int)*(short *)(param_1 + 0x44);    // SPD
          *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);    // BD.x BS.x Q12_SHIFT Q12_PROD
          *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);    // BD.y BS.y Q12_SHIFT Q12_PROD
          *(short *)(param_1 + 0x38) = (short)(*(short *)(param_1 + 0x40) * iVar12 >> 0xc);    // BD.z BS.z Q12_SHIFT Q12_PROD
          halt_baddata();
        }
        if ((uVar8 >> 3 & 1) == 0) {
          func_0x00109e70(param_1);
          func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),    // BS.x BS.z
                          param_1 + 0x3c);    // BS.x
          halt_baddata();
        }
        return;
      }
    }
    iVar11 = (int)(((uint)*(ushort *)(param_1 + 8) - (uint)*(ushort *)(iVar12 + 0x6c)) * 0x10000) >>
             0x10;
    iVar10 = (int)(((uint)*(ushort *)(param_1 + 10) - (uint)*(ushort *)(iVar12 + 0x6e)) * 0x10000)
             >> 0x10;
    iVar9 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)    // POS.y
            >> 0x10;
    uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
    if (uVar8 * uVar8 < (uint)(iVar11 * iVar11 + iVar10 * iVar10 + iVar9 * iVar9)) {
      local_50 = CONCAT22(*(short *)(iVar12 + 0x6e) - *(ushort *)(param_1 + 10),
                          *(short *)(iVar12 + 0x6c) - *(ushort *)(param_1 + 8));
      local_2c = CONCAT22(uStack_4a,*(short *)(iVar12 + 0x70) - *(ushort *)(param_1 + 0xc));    // POS.y
      local_30 = local_50;
      func_0x00109758(param_1,local_50,local_2c,&local_48);
      local_30 = CONCAT22(local_46 - *(short *)(param_1 + 0x3e),    // BS.y
                          local_48 - *(short *)(param_1 + 0x3c));    // BS.x
      local_2c = CONCAT22(local_2c._2_2_,local_44 - *(short *)(param_1 + 0x40));    // BS.z
      local_20 = local_30;
      local_1c = local_2c;
      func_0x00109758(param_1,local_30,local_2c,auStack_28);
      iVar12 = func_0x0010a95c(param_1,param_1 + 0x3c,&local_48,auStack_40);    // BS.x
      iVar9 = (int)*(short *)(param_1 + 0x3c) * (int)local_48 +    // BS.x
              (int)*(short *)(param_1 + 0x3e) * (int)local_46 +    // BS.y
              (int)*(short *)(param_1 + 0x40) * (int)local_44 >> 0xc;    // BS.z Q12_SHIFT Q12_PROD
      func_0x0010a95c(param_1,auStack_40,param_1 + 0x3c,&local_38);    // BS.x
      local_20 = local_38;
      local_1c = local_34;
      func_0x00109758(param_1,local_38,local_34,&local_38);
      if (4000 < iVar9) {
        iVar11 = iVar12;
        if (iVar12 < 0) {
          iVar11 = -iVar12;
        }
        if (iVar11 < 1000) {
          if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {    // ANG.yaw
            return;
          }
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
      if ((iVar12 == 0) && (iVar9 < 0)) {
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) != 0) {    // ANG.yaw
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);    // POS.z
          sVar3 = *(short *)(param_1 + 0x44) - uVar1;    // SPD
          if ((int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1) < 1) {    // SPD
            sVar3 = 0;
          }
          *(short *)(param_1 + 0x44) = sVar3;    // SPD
        }
        func_0x0010a6ec(param_1);
      }
      else {
        uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x12);
        bVar2 = iVar9 < *(short *)((uVar8 & 0xfff) * 4 + -0x7ffeb162);    // ANGLE_MASK
        if (bVar2) {
          if (iVar12 < 0) {
            uVar8 = 0x1000 - uVar8 & 0xfff;    // ANGLE_MASK
          }
          iVar9 = (uVar8 & 0xfff) * 4;    // ANGLE_MASK
          iVar12 = (int)*(short *)(iVar9 + -0x7ffeb164);
          iVar9 = (int)*(short *)(iVar9 + -0x7ffeb162);
        }
        iVar11 = (int)*(short *)(param_1 + 0x44);    // SPD
        sVar7 = (short)(iVar9 * *(short *)(param_1 + 0x3c) + iVar12 * (short)local_38 >> 0xc);    // BS.x Q12_SHIFT Q12_PROD
        sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc);    // BS.y Q12_SHIFT Q12_PROD
        sVar6 = (short)(iVar9 * *(short *)(param_1 + 0x40) + iVar12 * (short)local_34 >> 0xc);    // BS.z Q12_SHIFT Q12_PROD
        *(short *)(param_1 + 0x3c) = sVar7;    // BS.x
        *(short *)(param_1 + 0x3e) = sVar3;    // BS.y
        *(short *)(param_1 + 0x40) = sVar6;    // BS.z
        *(short *)(param_1 + 0x34) = (short)(sVar7 * iVar11 >> 0xc);    // BD.x Q12_SHIFT Q12_PROD
        *(short *)(param_1 + 0x36) = (short)(sVar3 * iVar11 >> 0xc);    // BD.y Q12_SHIFT Q12_PROD
        *(short *)(param_1 + 0x38) = (short)(sVar6 * iVar11 >> 0xc);    // BD.z Q12_SHIFT Q12_PROD
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {    // ANG.yaw
          func_0x00109e70(param_1);
          return;
        }
        if (bVar2) {
          func_0x00109f60(param_1);
        }
        else {
          func_0x00109e70(param_1);
        }
      }
    }
    else {
      uVar5 = 0x40;
      if (0x40 < uVar8) {
        uVar5 = uVar8;
      }
      *(short *)(param_1 + 0x9c) = (short)uVar5;
      *(uint *)(param_1 + 0x98) = uVar5 * uVar5;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // ANGLE_MASK
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_0001e750 (MAIN.EXE) @ 0x01e750


undefined4 FUN_0001e750(short *param_1,int *param_2)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  short sVar6;
  short sVar7;
  short sVar8;
  undefined4 *puVar9;
  int iVar10;
  int unaff_gp;
  short sVar11;
  short local_44;
  short local_40;
  short local_3c;
  short local_38;
  short sStack_34;
  short sStack_30;
  undefined2 uStack_2e;
  undefined2 uStack_2c;
  short sStack_28;
  short sStack_26;
  undefined4 auStack_20 [8];
  
  local_44 = param_1[8];
  local_40 = param_1[9];
  sVar6 = param_1[10];
  local_3c = param_1[0xc];
  sVar5 = param_1[0xb];
  local_38 = param_1[0x10];
  sVar7 = param_1[0xd];
  sStack_34 = param_1[0x12];
  sVar4 = param_1[0xe];
  sVar3 = param_1[0xf];
  sVar11 = param_1[0x11];
  sVar8 = param_1[0x13];
  puVar9 = (undefined4 *)&DAT_8003bf2c;
  puVar2 = auStack_20;
  iVar10 = 8;
  do {
    iVar10 = iVar10 + -1;
    *puVar2 = *puVar9;
    puVar9 = puVar9 + 1;
    puVar2 = puVar2 + 1;
  } while (0 < iVar10);
  if (param_1[4] != 0) {
    FUN_0001f340((int)param_1[4],auStack_20);
    sStack_30 = local_44 - param_1[5];
    uStack_2e = (undefined2)((((int)local_40 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    local_44 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    local_40 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    sStack_30 = sVar6 - param_1[5];
    uStack_2e = (undefined2)((((int)sVar5 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar6 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar5 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    sStack_30 = local_3c - param_1[5];
    uStack_2e = (undefined2)((((int)sVar7 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    local_3c = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sStack_30 = sVar4 - param_1[5];
    sVar7 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    uStack_2e = (undefined2)((((int)sVar3 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar4 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar3 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    if (0x100 < param_1[1]) {
      sStack_30 = local_38 - param_1[5];
      uStack_2e = (undefined2)((((int)sVar11 - (int)param_1[6]) * 0x1000) / 0x780);
      uStack_2c = 0;
      FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
      local_38 = sStack_28 + param_1[5];
      iVar10 = sStack_26 * 0x780;
      if (iVar10 < 0) {
        iVar10 = iVar10 + 0xfff;
      }
      sVar11 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
      sStack_30 = sStack_34 - param_1[5];
      uStack_2e = (undefined2)((((int)sVar8 - (int)param_1[6]) * 0x1000) / 0x780);
      uStack_2c = 0;
      FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
      sStack_34 = sStack_28 + param_1[5];
      iVar10 = sStack_26 * 0x780;
      if (iVar10 < 0) {
        iVar10 = iVar10 + 0xfff;
      }
      sVar8 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    }
  }
  iVar10 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
  if (iVar10 == 0) {
    uVar1 = 0;
  }
  else {
    *(undefined1 *)(iVar10 + 3) = 9;
    *(undefined1 *)(iVar10 + 7) = 0x2c;
    *(short *)(iVar10 + 8) = local_44;
    *(short *)(iVar10 + 10) = local_40;
    *(short *)(iVar10 + 0x10) = sVar6;    // POS.z
    *(short *)(iVar10 + 0x12) = sVar5;
    *(short *)(iVar10 + 0x18) = local_3c;
    *(short *)(iVar10 + 0x1a) = sVar7;
    *(short *)(iVar10 + 0x20) = sVar4;    // ANG.yaw
    *(short *)(iVar10 + 0x22) = sVar3;    // ANG.pitch
    *(char *)(iVar10 + 0xc) = (char)param_1[0x14];    // POS.y
    *(char *)(iVar10 + 0xd) = (char)param_1[0x17];
    *(undefined1 *)(iVar10 + 0x14) = *(undefined1 *)((int)param_1 + 0x29);
    *(undefined1 *)(iVar10 + 0x15) = *(undefined1 *)((int)param_1 + 0x2f);
    *(char *)(iVar10 + 0x1c) = (char)param_1[0x15];
    *(char *)(iVar10 + 0x1d) = (char)param_1[0x18];
    *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2b);    // ANG.roll
    *(undefined1 *)(iVar10 + 0x25) = *(undefined1 *)((int)param_1 + 0x31);
    *(char *)(iVar10 + 4) = (char)param_1[0x1a];
    *(undefined1 *)(iVar10 + 5) = *(undefined1 *)((int)param_1 + 0x35);
    *(char *)(iVar10 + 6) = (char)param_1[0x1b];
    *(short *)(iVar10 + 0xe) = param_1[0x1e];
    *(short *)(iVar10 + 0x16) = param_1[0x1c];
    FUN_0001c89c(iVar10,(int)param_1[3]);
    FUN_0001c85c(*param_2 + *param_1 * 4,iVar10);
    FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    if (0x100 < param_1[1]) {
      iVar10 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
      if (iVar10 == 0) {
        return 0;
      }
      *(undefined1 *)(iVar10 + 3) = 9;
      *(undefined1 *)(iVar10 + 7) = 0x2c;
      *(short *)(iVar10 + 8) = sVar6;
      *(short *)(iVar10 + 10) = sVar5;
      *(short *)(iVar10 + 0x10) = local_38;    // POS.z
      *(short *)(iVar10 + 0x12) = sVar11;
      *(short *)(iVar10 + 0x18) = sVar4;
      *(short *)(iVar10 + 0x1a) = sVar3;
      *(short *)(iVar10 + 0x20) = sStack_34;    // ANG.yaw
      *(short *)(iVar10 + 0x22) = sVar8;    // ANG.pitch
      *(undefined1 *)(iVar10 + 0xc) = 0;    // POS.y
      *(undefined1 *)(iVar10 + 0xd) = *(undefined1 *)((int)param_1 + 0x2f);
      *(char *)(iVar10 + 0x14) = (char)param_1[0x16];
      *(char *)(iVar10 + 0x15) = (char)param_1[0x19];
      *(undefined1 *)(iVar10 + 0x1c) = 0;
      *(undefined1 *)(iVar10 + 0x1d) = *(undefined1 *)((int)param_1 + 0x31);
      *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2d);    // ANG.roll
      *(undefined1 *)(iVar10 + 0x25) = *(undefined1 *)((int)param_1 + 0x33);
      *(char *)(iVar10 + 4) = (char)param_1[0x1a];
      *(undefined1 *)(iVar10 + 5) = *(undefined1 *)((int)param_1 + 0x35);
      *(char *)(iVar10 + 6) = (char)param_1[0x1b];
      *(short *)(iVar10 + 0xe) = param_1[0x1e];
      *(short *)(iVar10 + 0x16) = param_1[0x1d];
      FUN_0001c89c(iVar10,(int)param_1[3]);
      FUN_0001c85c(*param_2 + *param_1 * 4,iVar10);
      FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    }
    uVar1 = 1;
  }
  return uVar1;
}


---

## FUN_0001e7b4 (MAIN.EXE) @ 0x01e7b4


undefined4 FUN_0001e7b4(undefined4 param_1,int *param_2)

{
  int in_v0;
  undefined4 uVar1;
  undefined4 *puVar2;
  short *unaff_s0;
  short sVar3;
  short sVar4;
  int unaff_s4;
  short unaff_s5;
  int unaff_s6;
  short sVar5;
  int in_t8;
  undefined4 *puVar6;
  int iVar7;
  int unaff_gp;
  short sVar8;
  short in_stack_0000003c;
  int in_stack_00000040;
  short in_stack_00000044;
  short in_stack_00000048;
  int iStack0000004c;
  short sStack00000050;
  undefined2 uStack00000052;
  undefined2 in_stack_00000054;
  short sStack00000058;
  short sStack0000005a;
  int *piStack00000084;
  
  sVar4 = unaff_s0[0xe];
  sVar3 = unaff_s0[0xf];
  sVar8 = unaff_s0[0x11];
  sVar5 = unaff_s0[0x13];
  puVar6 = (undefined4 *)(in_t8 + -0x40d4);
  puVar2 = (undefined4 *)&stack0x00000060;
  iVar7 = 8;
  piStack00000084 = param_2;
  do {
    iVar7 = iVar7 + -1;
    *puVar2 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar2 = puVar2 + 1;
  } while (0 < iVar7);
  iStack0000004c = in_v0;
  if (unaff_s0[4] != 0) {
    FUN_0001f340((int)unaff_s0[4],&stack0x00000060);
    sStack00000050 = in_stack_0000003c - unaff_s0[5];
    uStack00000052 = (undefined2)(((in_stack_00000040 - unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_0000003c = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    in_stack_00000040 = ((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    sStack00000050 = unaff_s5 - unaff_s0[5];
    uStack00000052 = (undefined2)(((unaff_s4 - unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    unaff_s5 = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    unaff_s4 = ((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    sStack00000050 = in_stack_00000044 - unaff_s0[5];
    uStack00000052 = (undefined2)(((unaff_s6 - unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_00000044 = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    sStack00000050 = sVar4 - unaff_s0[5];
    unaff_s6 = ((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    uStack00000052 = (undefined2)((((int)sVar3 - (int)unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    sVar4 = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    sVar3 = (short)((uint)(((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    if (0x100 < unaff_s0[1]) {
      sStack00000050 = in_stack_00000048 - unaff_s0[5];
      uStack00000052 = (undefined2)((((int)sVar8 - (int)unaff_s0[6]) * 0x1000) / 0x780);
      in_stack_00000054 = 0;
      FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
      in_stack_00000048 = sStack00000058 + unaff_s0[5];
      iVar7 = sStack0000005a * 0x780;
      if (iVar7 < 0) {
        iVar7 = iVar7 + 0xfff;
      }
      sVar8 = (short)((uint)(((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
      sStack00000050 = (short)iStack0000004c - unaff_s0[5];
      uStack00000052 = (undefined2)((((int)sVar5 - (int)unaff_s0[6]) * 0x1000) / 0x780);
      in_stack_00000054 = 0;
      FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
      iStack0000004c = ((int)sStack00000058 + (int)unaff_s0[5]) * 0x10000 >> 0x10;
      iVar7 = sStack0000005a * 0x780;
      if (iVar7 < 0) {
        iVar7 = iVar7 + 0xfff;
      }
      sVar5 = (short)((uint)(((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    }
  }
  iVar7 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
  if (iVar7 == 0) {
    uVar1 = 0;
  }
  else {
    *(undefined1 *)(iVar7 + 3) = 9;
    *(undefined1 *)(iVar7 + 7) = 0x2c;
    *(short *)(iVar7 + 8) = in_stack_0000003c;
    *(short *)(iVar7 + 10) = (short)in_stack_00000040;
    *(short *)(iVar7 + 0x10) = unaff_s5;    // POS.z
    *(short *)(iVar7 + 0x12) = (short)unaff_s4;
    *(short *)(iVar7 + 0x18) = in_stack_00000044;
    *(short *)(iVar7 + 0x1a) = (short)unaff_s6;
    *(short *)(iVar7 + 0x20) = sVar4;    // ANG.yaw
    *(short *)(iVar7 + 0x22) = sVar3;    // ANG.pitch
    *(char *)(iVar7 + 0xc) = (char)unaff_s0[0x14];    // POS.y
    *(char *)(iVar7 + 0xd) = (char)unaff_s0[0x17];
    *(undefined1 *)(iVar7 + 0x14) = *(undefined1 *)((int)unaff_s0 + 0x29);
    *(undefined1 *)(iVar7 + 0x15) = *(undefined1 *)((int)unaff_s0 + 0x2f);
    *(char *)(iVar7 + 0x1c) = (char)unaff_s0[0x15];
    *(char *)(iVar7 + 0x1d) = (char)unaff_s0[0x18];
    *(undefined1 *)(iVar7 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2b);    // ANG.roll
    *(undefined1 *)(iVar7 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x31);
    *(char *)(iVar7 + 4) = (char)unaff_s0[0x1a];
    *(undefined1 *)(iVar7 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
    *(char *)(iVar7 + 6) = (char)unaff_s0[0x1b];
    *(short *)(iVar7 + 0xe) = unaff_s0[0x1e];
    *(short *)(iVar7 + 0x16) = unaff_s0[0x1c];
    FUN_0001c89c(iVar7,(int)unaff_s0[3]);
    FUN_0001c85c(*piStack00000084 + *unaff_s0 * 4,iVar7);
    FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    if (0x100 < unaff_s0[1]) {
      iVar7 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
      if (iVar7 == 0) {
        return 0;
      }
      *(undefined1 *)(iVar7 + 3) = 9;
      *(undefined1 *)(iVar7 + 7) = 0x2c;
      *(short *)(iVar7 + 8) = unaff_s5;
      *(short *)(iVar7 + 10) = (short)unaff_s4;
      *(short *)(iVar7 + 0x10) = in_stack_00000048;    // POS.z
      *(short *)(iVar7 + 0x12) = sVar8;
      *(short *)(iVar7 + 0x18) = sVar4;
      *(short *)(iVar7 + 0x1a) = sVar3;
      *(short *)(iVar7 + 0x20) = (short)iStack0000004c;    // ANG.yaw
      *(short *)(iVar7 + 0x22) = sVar5;    // ANG.pitch
      *(undefined1 *)(iVar7 + 0xc) = 0;    // POS.y
      *(undefined1 *)(iVar7 + 0xd) = *(undefined1 *)((int)unaff_s0 + 0x2f);
      *(char *)(iVar7 + 0x14) = (char)unaff_s0[0x16];
      *(char *)(iVar7 + 0x15) = (char)unaff_s0[0x19];
      *(undefined1 *)(iVar7 + 0x1c) = 0;
      *(undefined1 *)(iVar7 + 0x1d) = *(undefined1 *)((int)unaff_s0 + 0x31);
      *(undefined1 *)(iVar7 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2d);    // ANG.roll
      *(undefined1 *)(iVar7 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x33);
      *(char *)(iVar7 + 4) = (char)unaff_s0[0x1a];
      *(undefined1 *)(iVar7 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
      *(char *)(iVar7 + 6) = (char)unaff_s0[0x1b];
      *(short *)(iVar7 + 0xe) = unaff_s0[0x1e];
      *(short *)(iVar7 + 0x16) = unaff_s0[0x1d];
      FUN_0001c89c(iVar7,(int)unaff_s0[3]);
      FUN_0001c85c(*piStack00000084 + *unaff_s0 * 4,iVar7);
      FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    }
    uVar1 = 1;
  }
  return uVar1;
}


---

## FUN_0001ea04 (MAIN.EXE) @ 0x01ea04


undefined4 FUN_0001ea04(void)

{
  short sVar1;
  short in_v0;
  undefined4 uVar2;
  undefined2 in_v1;
  short *unaff_s0;
  int unaff_s1;
  undefined2 uVar3;
  undefined2 unaff_s4;
  undefined2 unaff_s5;
  undefined2 unaff_s6;
  int unaff_s7;
  int unaff_gp;
  int unaff_s8;
  int iVar4;
  int iVar5;
  undefined2 in_stack_0000003c;
  undefined2 in_stack_00000040;
  undefined2 in_stack_00000044;
  short in_stack_00000048;
  short in_stack_0000004c;
  short sStack00000050;
  undefined2 uStack00000052;
  undefined2 in_stack_00000054;
  short sStack00000058;
  short sStack0000005a;
  int *in_stack_00000084;
  
  iVar4 = sStack0000005a * unaff_s1;
  if (iVar4 < 0) {
    iVar4 = iVar4 + 0xfff;
  }
  sVar1 = unaff_s0[6];
  if (0x100 < unaff_s0[1]) {
    sStack00000050 = in_stack_00000048 - in_v0;
    uStack00000052 = (undefined2)(((unaff_s8 - unaff_s0[6]) * 0x1000) / unaff_s1);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_00000048 = sStack00000058 + unaff_s0[5];
    iVar5 = sStack0000005a * unaff_s1;
    if (iVar5 < 0) {
      iVar5 = iVar5 + 0xfff;
    }
    unaff_s8 = ((int)unaff_s0[6] + (iVar5 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    sStack00000050 = in_stack_0000004c - unaff_s0[5];
    uStack00000052 = (undefined2)(((unaff_s7 - unaff_s0[6]) * 0x1000) / unaff_s1);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_0000004c = sStack00000058 + unaff_s0[5];
    iVar5 = sStack0000005a * unaff_s1;
    if (iVar5 < 0) {
      iVar5 = iVar5 + 0xfff;
    }
    unaff_s7 = ((int)unaff_s0[6] + (iVar5 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
  }
  iVar5 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
  if (iVar5 == 0) {
    uVar2 = 0;
  }
  else {
    *(undefined1 *)(iVar5 + 3) = 9;
    *(undefined1 *)(iVar5 + 7) = 0x2c;
    *(undefined2 *)(iVar5 + 8) = in_stack_0000003c;
    *(undefined2 *)(iVar5 + 10) = in_stack_00000040;
    *(undefined2 *)(iVar5 + 0x10) = unaff_s5;    // POS.z
    *(undefined2 *)(iVar5 + 0x12) = unaff_s4;
    *(undefined2 *)(iVar5 + 0x18) = in_stack_00000044;
    *(undefined2 *)(iVar5 + 0x1a) = unaff_s6;
    *(undefined2 *)(iVar5 + 0x20) = in_v1;    // ANG.yaw
    uVar3 = (undefined2)((uint)(((int)sVar1 + (iVar4 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    *(undefined2 *)(iVar5 + 0x22) = uVar3;    // ANG.pitch
    *(char *)(iVar5 + 0xc) = (char)unaff_s0[0x14];    // POS.y
    *(char *)(iVar5 + 0xd) = (char)unaff_s0[0x17];
    *(undefined1 *)(iVar5 + 0x14) = *(undefined1 *)((int)unaff_s0 + 0x29);
    *(undefined1 *)(iVar5 + 0x15) = *(undefined1 *)((int)unaff_s0 + 0x2f);
    *(char *)(iVar5 + 0x1c) = (char)unaff_s0[0x15];
    *(char *)(iVar5 + 0x1d) = (char)unaff_s0[0x18];
    *(undefined1 *)(iVar5 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2b);    // ANG.roll
    *(undefined1 *)(iVar5 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x31);
    *(char *)(iVar5 + 4) = (char)unaff_s0[0x1a];
    *(undefined1 *)(iVar5 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
    *(char *)(iVar5 + 6) = (char)unaff_s0[0x1b];
    *(short *)(iVar5 + 0xe) = unaff_s0[0x1e];
    *(short *)(iVar5 + 0x16) = unaff_s0[0x1c];
    FUN_0001c89c(iVar5,(int)unaff_s0[3]);
    FUN_0001c85c(*in_stack_00000084 + *unaff_s0 * 4,iVar5);
    FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    if (0x100 < unaff_s0[1]) {
      iVar4 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
      if (iVar4 == 0) {
        return 0;
      }
      *(undefined1 *)(iVar4 + 3) = 9;
      *(undefined1 *)(iVar4 + 7) = 0x2c;
      *(undefined2 *)(iVar4 + 8) = unaff_s5;
      *(undefined2 *)(iVar4 + 10) = unaff_s4;
      *(short *)(iVar4 + 0x10) = in_stack_00000048;    // POS.z
      *(short *)(iVar4 + 0x12) = (short)unaff_s8;
      *(undefined2 *)(iVar4 + 0x18) = in_v1;
      *(undefined2 *)(iVar4 + 0x1a) = uVar3;
      *(short *)(iVar4 + 0x20) = in_stack_0000004c;    // ANG.yaw
      *(short *)(iVar4 + 0x22) = (short)unaff_s7;    // ANG.pitch
      *(undefined1 *)(iVar4 + 0xc) = 0;    // POS.y
      *(undefined1 *)(iVar4 + 0xd) = *(undefined1 *)((int)unaff_s0 + 0x2f);
      *(char *)(iVar4 + 0x14) = (char)unaff_s0[0x16];
      *(char *)(iVar4 + 0x15) = (char)unaff_s0[0x19];
      *(undefined1 *)(iVar4 + 0x1c) = 0;
      *(undefined1 *)(iVar4 + 0x1d) = *(undefined1 *)((int)unaff_s0 + 0x31);
      *(undefined1 *)(iVar4 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2d);    // ANG.roll
      *(undefined1 *)(iVar4 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x33);
      *(char *)(iVar4 + 4) = (char)unaff_s0[0x1a];
      *(undefined1 *)(iVar4 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
      *(char *)(iVar4 + 6) = (char)unaff_s0[0x1b];
      *(short *)(iVar4 + 0xe) = unaff_s0[0x1e];
      *(short *)(iVar4 + 0x16) = unaff_s0[0x1d];
      FUN_0001c89c(iVar4,(int)unaff_s0[3]);
      FUN_0001c85c(*in_stack_00000084 + *unaff_s0 * 4,iVar4);
      FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    }
    uVar2 = 1;
  }
  return uVar2;
}


---

## FUN_00022dc8 (GAME.BIN) @ 0x022dc8


/* WARNING: Control flow encountered bad instruction data */

void FUN_00022dc8(int param_1)

{
  short sVar1;
  undefined2 uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  short sVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined4 in_t3;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 uStack_58;
  uint local_54;
  undefined4 uStack_50;
  uint uStack_4c;
  short sStack_48;
  short sStack_46;
  short sStack_44;
  int iStack_40;
  int iStack_3c;
  int iStack_38;
  int iStack_30;
  int iStack_2c;
  uint auStack_28 [2];
  
  uVar3 = func_0x000f55e4(*(undefined4 *)(param_1 + 0xec),param_1);
  FUN_00023000(&uStack_58,0,8);
  iVar4 = *(int *)(param_1 + 0xec);
  setCopControlWord(2,0,*(undefined4 *)(iVar4 + 0x18));
  setCopControlWord(2,0x800,*(undefined4 *)(iVar4 + 0x1c));
  setCopControlWord(2,0x1000,*(undefined4 *)(iVar4 + 0x20));    // ANG.yaw
  setCopControlWord(2,0x1800,*(undefined4 *)(iVar4 + 0x24));    // ANG.roll
  setCopControlWord(2,0x2000,*(undefined4 *)(iVar4 + 0x28));
  iVar9 = (int)*(short *)(iVar4 + 0x152);
  iVar10 = (int)*(short *)(iVar4 + 0x154);
  setCopControlWord(2,0x2800,(int)*(short *)(iVar4 + 0x150));
  setCopControlWord(2,0x3000,iVar9);
  setCopControlWord(2,0x3800,iVar10);
  setCopReg(2,0x4800,uStack_58 & 0xffff);    // ANGLE_MASK
  setCopReg(2,0x5000,uStack_58 >> 0x10);
  setCopReg(2,0x5800,(uint)(ushort)((short)(-(int)*(short *)(*(int *)(iVar4 + 0x1a8) + 0x90) / 2) -
                                   0x80));
  copFunction(2,0x498012);
  uVar11 = getCopReg(2,0x4800);
  uVar12 = getCopReg(2,0x5000);
  uVar13 = getCopReg(2,0x5800);
  uStack_58 = CONCAT22((short)uVar12,(short)uVar11);
  local_54 = CONCAT22(local_54._2_2_,(short)uVar13);
  if (uVar3 != 0) {
    iVar4 = *(int *)(*(int *)(param_1 + 0xec) + (uVar3 - 1) * 4 + 0x184);
    uVar5 = *(uint *)(iVar4 + 8);
    uStack_4c = *(uint *)(iVar4 + 0xc);    // POS.y
    uStack_50._2_2_ = (short)(uVar5 >> 0x10);
    iVar6 = (uint)*(ushort *)(param_1 + 0xc) - (uStack_4c & 0xffff);    // POS.y ANGLE_MASK
    iVar4 = (uint)*(ushort *)(param_1 + 8) - (uVar5 & 0xffff);    // ANGLE_MASK
    sStack_48 = (short)iVar4;
    sStack_44 = (short)iVar6;
    sStack_46 = *(short *)(param_1 + 10) - uStack_50._2_2_;
    uStack_50 = uVar5;
    sVar1 = FUN_00022e5c(iVar6 * 0x10000 >> 0x10,iVar4 * 0x10000 >> 0x10);
    iStack_40 = (int)sStack_48;
    iStack_3c = (int)sStack_46;
    iStack_38 = (int)sStack_44;
    *(short *)(param_1 + 0x12) = -sVar1;
    setCopReg(2,iVar9,iStack_40);
    setCopReg(2,iVar10,iStack_3c);
    setCopReg(2,in_t3,iStack_38);
    copFunction(2,0xa00428);
    iVar9 = getCopReg(2,0xc800);
    iVar4 = getCopReg(2,0xd000);
    iStack_30 = getCopReg(2,0xd800);
    iStack_30 = iVar9 + iVar4 + iStack_30;
    FUN_00022bac(iStack_30,&iStack_2c,auStack_28);
    iStack_40 = iStack_40 * iStack_2c >> (auStack_28[0] & 0x1f);
    iStack_3c = iStack_3c * iStack_2c >> (auStack_28[0] & 0x1f);
    iStack_38 = iStack_38 * iStack_2c >> (auStack_28[0] & 0x1f);
    iVar4 = FUN_00023180((int)sStack_48 * (int)sStack_48 + (int)sStack_46 * (int)sStack_46 +
                         (int)sStack_44 * (int)sStack_44);
    iVar4 = (iVar4 + -300) * 0x10000 >> 0x10;
    sVar1 = (short)(((int)(((uint)*(ushort *)(param_1 + 0x34) - (iVar4 * iStack_40 >> 0xf)) *    // BD.x
                          0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(param_1 + 0x34) = sVar1;    // BD.x
    sVar7 = (short)(((int)(((uint)*(ushort *)(param_1 + 0x36) - (iVar4 * iStack_3c >> 0xf)) *    // BD.y
                          0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(param_1 + 0x36) = sVar7;    // BD.y
    *(short *)(param_1 + 8) = *(short *)(param_1 + 8) + sVar1;
    sVar1 = (short)(((int)(((uint)*(ushort *)(param_1 + 0x38) - (iVar4 * iStack_38 >> 0xf)) *    // BD.z
                          0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(param_1 + 0x38) = sVar1;    // BD.z
    *(short *)(param_1 + 10) = *(short *)(param_1 + 10) + sVar7;
    *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + sVar1;    // POS.y POS.y
    iVar4 = func_0x000ab4d0(param_1 + 8);
    if (iVar4 < *(short *)(param_1 + 10)) {
      *(short *)(param_1 + 10) = (short)iVar4;
    }
    *(undefined4 *)(param_1 + 0x78) = 1;
    iVar9 = (uint)*(ushort *)(param_1 + 8) - (uStack_58 & 0xffff);    // ANGLE_MASK
    sStack_48 = (short)iVar9;
    sStack_46 = *(short *)(param_1 + 10) - uStack_58._2_2_;
    iVar10 = (uint)*(ushort *)(param_1 + 0xc) - (local_54 & 0xffff);    // POS.y ANGLE_MASK
    sStack_44 = (short)iVar10;
    iVar4 = (*(ushort *)(*(int *)(param_1 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
    iVar8 = (int)*(short *)(iVar4 + -0x7ffeb164);
    iVar6 = (int)*(short *)(iVar4 + -0x7ffeb162);
    iVar4 = -(iVar9 * 0x10000 >> 0x10) * iVar8 - (iVar10 * 0x10000 >> 0x10) * iVar6 >> 0xc;    // Q12_SHIFT Q12_PROD
    if (iVar4 < 0) {
      iVar4 = iVar4 + -10;
      *(short *)(param_1 + 0x34) = (short)(-iVar8 >> 7);    // BD.x
      *(short *)(param_1 + 0x38) = (short)(-iVar6 >> 7);    // BD.z
      *(ushort *)(param_1 + 8) = *(ushort *)(param_1 + 8) - (short)(-(iVar4 * iVar8) >> 0xc);    // Q12_SHIFT Q12_PROD
      *(ushort *)(param_1 + 0xc) = *(ushort *)(param_1 + 0xc) - (short)(-(iVar4 * iVar6) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
    }
    iVar4 = *(int *)(param_1 + 0xec);
    uVar5 = 0;
    if (*(short *)(iVar4 + 0x182) != 0) {
      do {
        iVar9 = uVar5 * 4;
        if (uVar5 != uVar3) {
          *(undefined4 *)(*(int *)(iVar4 + iVar9 + 0x184) + 0x78) = 1;
          func_0x000e8cfc(param_1,*(undefined4 *)(*(int *)(param_1 + 0xec) + iVar9 + 0x184));
          *(undefined4 *)(*(int *)(*(int *)(param_1 + 0xec) + iVar9 + 0x184) + 0x78) = 4;
        }
        iVar4 = *(int *)(param_1 + 0xec);
        uVar5 = uVar5 + 1;
      } while (uVar5 < *(ushort *)(iVar4 + 0x182));
    }
    *(undefined4 *)(param_1 + 0x78) = 4;
    uVar2 = 0xc100;
    if ((*(short *)(param_1 + 8) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(param_1 + 8))) {
      *(undefined2 *)(param_1 + 8) = uVar2;
    }
    uVar2 = 0xc100;
    if ((*(short *)(param_1 + 0xc) < -0x3f00) ||    // POS.y
       (uVar2 = 0x3f00, 0x3f00 < *(short *)(param_1 + 0xc))) {    // POS.y
      *(undefined2 *)(param_1 + 0xc) = uVar2;    // POS.y
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00022e5c (GAME.BIN) @ 0x022e5c


/* WARNING: Control flow encountered bad instruction data */

void FUN_00022e5c(int param_1)

{
  uint uVar1;
  uint uVar2;
  short sVar3;
  undefined2 uVar4;
  int in_v1;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  short sVar9;
  int iVar10;
  int iVar11;
  undefined4 in_t3;
  undefined4 in_t4;
  undefined4 uVar12;
  undefined4 uVar13;
  uint uVar14;
  ushort *unaff_s0;
  int unaff_s2;
  uint unaff_s5;
  int iVar15;
  uint uStack00000010;
  uint uStack00000018;
  uint uStack0000001c;
  short sStack00000020;
  short sStack00000022;
  short sStack00000024;
  int in_stack_0000003c;
  uint in_stack_00000040;
  
  setCopControlWord(2,0x1000,in_t4);
  setCopControlWord(2,0x1800,*(undefined4 *)(in_v1 + 0xc));    // POS.y
  setCopControlWord(2,0x2000,*(undefined4 *)(in_v1 + 0x10));    // POS.z
  iVar10 = (int)*(short *)(param_1 + 0x152);
  iVar11 = (int)*(short *)(param_1 + 0x154);
  setCopControlWord(2,0x2800,(int)*(short *)(param_1 + 0x150));
  setCopControlWord(2,0x3000,iVar10);
  setCopControlWord(2,0x3800,iVar11);
  setCopReg(2,0x4800,(uint)*unaff_s0);
  setCopReg(2,0x5000,(uint)unaff_s0[1]);
  setCopReg(2,0x5800,(uint)unaff_s0[2]);
  copFunction(2,0x498012);
  uVar12 = getCopReg(2,0x4800);
  uVar13 = getCopReg(2,0x5000);
  uVar14 = getCopReg(2,0x5800);
  uStack00000010 = CONCAT22((short)uVar13,(short)uVar12);
  if (unaff_s5 != 0) {
    iVar5 = *(int *)(*(int *)(unaff_s2 + 0xec) + (unaff_s5 - 1) * 4 + 0x184);
    uVar7 = *(uint *)(iVar5 + 8);
    uStack0000001c = *(uint *)(iVar5 + 0xc);    // POS.y
    uStack00000018._2_2_ = (short)(uVar7 >> 0x10);
    iVar8 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uStack0000001c & 0xffff);    // POS.y ANGLE_MASK
    iVar5 = (uint)*(ushort *)(unaff_s2 + 8) - (uVar7 & 0xffff);    // ANGLE_MASK
    sStack00000020 = (short)iVar5;
    sStack00000024 = (short)iVar8;
    sStack00000022 = *(short *)(unaff_s2 + 10) - uStack00000018._2_2_;
    uStack00000018 = uVar7;
    sVar3 = FUN_00022e5c(iVar8 * 0x10000 >> 0x10,iVar5 * 0x10000 >> 0x10);
    iVar5 = (int)sStack00000020;
    iVar8 = (int)sStack00000022;
    iVar6 = (int)sStack00000024;
    *(short *)(unaff_s2 + 0x12) = -sVar3;
    setCopReg(2,iVar10,iVar5);
    setCopReg(2,iVar11,iVar8);
    setCopReg(2,in_t3,iVar6);
    copFunction(2,0xa00428);
    iVar15 = getCopReg(2,0xc800);
    iVar10 = getCopReg(2,0xd000);
    iVar11 = getCopReg(2,0xd800);
    FUN_00022bac(iVar15 + iVar10 + iVar11,&stack0x0000003c,&stack0x00000040);
    iVar5 = iVar5 * in_stack_0000003c;
    iVar8 = iVar8 * in_stack_0000003c;
    iVar6 = iVar6 * in_stack_0000003c;
    uVar7 = in_stack_00000040 & 0x1f;
    uVar1 = in_stack_00000040 & 0x1f;
    uVar2 = in_stack_00000040 & 0x1f;
    iVar10 = FUN_00023180((int)sStack00000020 * (int)sStack00000020 +
                          (int)sStack00000022 * (int)sStack00000022 +
                          (int)sStack00000024 * (int)sStack00000024);
    iVar10 = (iVar10 + -300) * 0x10000 >> 0x10;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar10 * (iVar5 >> uVar7) >> 0xf))    // BD.x
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x34) = sVar3;    // BD.x
    sVar9 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar10 * (iVar8 >> uVar1) >> 0xf))    // BD.y
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x36) = sVar9;    // BD.y
    *(short *)(unaff_s2 + 8) = *(short *)(unaff_s2 + 8) + sVar3;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x38) - (iVar10 * (iVar6 >> uVar2) >> 0xf))    // BD.z
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x38) = sVar3;    // BD.z
    *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + sVar9;
    *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar3;    // POS.y POS.y
    iVar10 = func_0x000ab4d0(unaff_s2 + 8);
    if (iVar10 < *(short *)(unaff_s2 + 10)) {
      *(short *)(unaff_s2 + 10) = (short)iVar10;
    }
    *(undefined4 *)(unaff_s2 + 0x78) = 1;
    iVar11 = (uint)*(ushort *)(unaff_s2 + 8) - (uStack00000010 & 0xffff);    // ANGLE_MASK
    sStack00000020 = (short)iVar11;
    sStack00000022 = *(short *)(unaff_s2 + 10) - uStack00000010._2_2_;
    iVar5 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uVar14 & 0xffff);    // POS.y ANGLE_MASK
    sStack00000024 = (short)iVar5;
    iVar10 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
    iVar6 = (int)*(short *)(iVar10 + -0x7ffeb164);
    iVar8 = (int)*(short *)(iVar10 + -0x7ffeb162);
    iVar10 = -(iVar11 * 0x10000 >> 0x10) * iVar6 - (iVar5 * 0x10000 >> 0x10) * iVar8 >> 0xc;    // Q12_SHIFT Q12_PROD
    if (iVar10 < 0) {
      iVar10 = iVar10 + -10;
      *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);    // BD.x
      *(short *)(unaff_s2 + 0x38) = (short)(-iVar8 >> 7);    // BD.z
      *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar10 * iVar6) >> 0xc);    // Q12_SHIFT Q12_PROD
      *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar10 * iVar8) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
    }
    iVar10 = *(int *)(unaff_s2 + 0xec);
    uVar14 = 0;
    if (*(short *)(iVar10 + 0x182) != 0) {
      do {
        if (uVar14 != unaff_s5) {
          *(undefined4 *)(*(int *)(iVar10 + uVar14 * 4 + 0x184) + 0x78) = 1;
          func_0x000e8cfc();
          *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar14 * 4 + 0x184) + 0x78) = 4;
        }
        iVar10 = *(int *)(unaff_s2 + 0xec);
        uVar14 = uVar14 + 1;
      } while (uVar14 < *(ushort *)(iVar10 + 0x182));
    }
    *(undefined4 *)(unaff_s2 + 0x78) = 4;
    uVar4 = 0xc100;
    if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar4 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8)))
    {
      *(undefined2 *)(unaff_s2 + 8) = uVar4;
    }
    uVar4 = 0xc100;
    if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
       (uVar4 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
      *(undefined2 *)(unaff_s2 + 0xc) = uVar4;    // POS.y
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00023000 (GAME.BIN) @ 0x023000


void FUN_00023000(undefined4 param_1,int param_2,undefined4 param_3,int param_4,ushort param_5,
                 ushort param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9,
                 short param_10,undefined4 param_11,undefined4 param_12,int param_13)

{
  short sVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  short sVar5;
  int in_t0;
  int iVar6;
  uint uVar7;
  int unaff_s2;
  uint unaff_s5;
  uint in_stack_00000040;
  
  param_11 = in_t0 >> (in_stack_00000040 & 0x1f);
  param_12 = param_4 * param_2 >> (in_stack_00000040 & 0x1f);
  iVar3 = FUN_00023180((int)(short)param_9 * (int)(short)param_9 +
                       (int)param_9._2_2_ * (int)param_9._2_2_ + (int)param_10 * (int)param_10);
  iVar3 = (iVar3 + -300) * 0x10000 >> 0x10;
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar3 * param_11 >> 0xf)) * 0x10000)    // BD.x
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x34) = sVar1;    // BD.x
  sVar5 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar3 * param_12 >> 0xf)) * 0x10000)    // BD.y
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x36) = sVar5;    // BD.y
  *(short *)(unaff_s2 + 8) = *(short *)(unaff_s2 + 8) + sVar1;
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x38) -    // BD.z
                         (iVar3 * (param_13 * param_2 >> (in_stack_00000040 & 0x1f)) >> 0xf)) *
                        0x10000) >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x38) = sVar1;    // BD.z
  *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + sVar5;
  *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar1;    // POS.y POS.y
  iVar3 = func_0x000ab4d0(unaff_s2 + 8);
  if (iVar3 < *(short *)(unaff_s2 + 10)) {
    *(short *)(unaff_s2 + 10) = (short)iVar3;
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 1;
  iVar3 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
  iVar6 = (int)*(short *)(iVar3 + -0x7ffeb164);
  iVar4 = (int)*(short *)(iVar3 + -0x7ffeb162);
  iVar3 = -((int)(((uint)*(ushort *)(unaff_s2 + 8) - (uint)param_5) * 0x10000) >> 0x10) * iVar6 -
          ((int)(((uint)*(ushort *)(unaff_s2 + 0xc) - (uint)param_6) * 0x10000) >> 0x10) * iVar4 >>    // POS.y Q12_SHIFT
          0xc;
  if (iVar3 < 0) {
    iVar3 = iVar3 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);    // BD.x
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar4 >> 7);    // BD.z
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar3 * iVar6) >> 0xc);    // Q12_SHIFT Q12_PROD
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar3 * iVar4) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
  }
  iVar3 = *(int *)(unaff_s2 + 0xec);
  uVar7 = 0;
  if (*(short *)(iVar3 + 0x182) != 0) {
    do {
      if (uVar7 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar3 + uVar7 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar7 * 4 + 0x184) + 0x78) = 4;
      }
      iVar3 = *(int *)(unaff_s2 + 0xec);
      uVar7 = uVar7 + 1;
    } while (uVar7 < *(ushort *)(iVar3 + 0x182));
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 4;
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar2;
  }
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar2;    // POS.y
  }
  return;
}


---

## FUN_00023110 (GAME.BIN) @ 0x023110


void FUN_00023110(undefined4 param_1,undefined4 param_2,short param_3,short param_4,uint param_5,
                 ushort param_6)

{
  short sVar1;
  undefined2 uVar2;
  int iVar3;
  int in_v1;
  int iVar4;
  short in_t0;
  int iVar5;
  uint uVar6;
  int unaff_s2;
  uint unaff_s5;
  int in_lo;
  short sStack00000022;
  
  *(short *)(unaff_s2 + 0x36) = param_4;    // BD.y
  *(short *)(unaff_s2 + 8) = param_3 + in_t0;
  sVar1 = (short)(((in_v1 - (in_lo >> 0xf)) * 0x10000 >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x38) = sVar1;    // BD.z
  *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + param_4;
  *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar1;    // POS.y POS.y
  iVar3 = func_0x000ab4d0();
  if (iVar3 < *(short *)(unaff_s2 + 10)) {
    *(short *)(unaff_s2 + 10) = (short)iVar3;
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 1;
  sStack00000022 = *(short *)(unaff_s2 + 10) - param_5._2_2_;
  iVar3 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
  iVar5 = (int)*(short *)(iVar3 + -0x7ffeb164);
  iVar4 = (int)*(short *)(iVar3 + -0x7ffeb162);
  iVar3 = -((int)(((uint)*(ushort *)(unaff_s2 + 8) - (param_5 & 0xffff)) * 0x10000) >> 0x10) * iVar5    // ANGLE_MASK
          - ((int)(((uint)*(ushort *)(unaff_s2 + 0xc) - (uint)param_6) * 0x10000) >> 0x10) * iVar4    // POS.y Q12_SHIFT
          >> 0xc;    // Q12_SHIFT
  if (iVar3 < 0) {
    iVar3 = iVar3 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar5 >> 7);    // BD.x
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar4 >> 7);    // BD.z
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar3 * iVar5) >> 0xc);    // Q12_SHIFT Q12_PROD
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar3 * iVar4) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
  }
  iVar3 = *(int *)(unaff_s2 + 0xec);
  uVar6 = 0;
  if (*(short *)(iVar3 + 0x182) != 0) {
    do {
      if (uVar6 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar3 + uVar6 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar6 * 4 + 0x184) + 0x78) = 4;
      }
      iVar3 = *(int *)(unaff_s2 + 0xec);
      uVar6 = uVar6 + 1;
    } while (uVar6 < *(ushort *)(iVar3 + 0x182));
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 4;
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar2;
  }
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar2;    // POS.y
  }
  return;
}


---

## FUN_00023180 (GAME.BIN) @ 0x023180


void FUN_00023180(void)

{
  undefined2 in_v0;
  undefined2 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int in_a3;
  int iVar6;
  uint uVar7;
  int unaff_s2;
  uint unaff_s5;
  uint in_stack_00000010;
  ushort in_stack_00000014;
  undefined2 uStack00000020;
  short sStack00000022;
  undefined2 uStack00000024;
  
  *(undefined2 *)(unaff_s2 + 10) = in_v0;
  *(undefined4 *)(in_a3 + 0x10) = 1;    // POS.z
  iVar3 = (uint)*(ushort *)(unaff_s2 + 8) - (in_stack_00000010 & 0xffff);    // ANGLE_MASK
  uStack00000020 = (undefined2)iVar3;
  sStack00000022 = *(short *)(unaff_s2 + 10) - in_stack_00000010._2_2_;
  iVar4 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uint)in_stack_00000014;    // POS.y
  uStack00000024 = (undefined2)iVar4;
  iVar2 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
  iVar6 = (int)*(short *)(iVar2 + -0x7ffeb164);
  iVar5 = (int)*(short *)(iVar2 + -0x7ffeb162);
  iVar2 = -(iVar3 * 0x10000 >> 0x10) * iVar6 - (iVar4 * 0x10000 >> 0x10) * iVar5 >> 0xc;    // Q12_SHIFT Q12_PROD
  if (iVar2 < 0) {
    iVar2 = iVar2 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);    // BD.x
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar5 >> 7);    // BD.z
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar2 * iVar6) >> 0xc);    // Q12_SHIFT Q12_PROD
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar2 * iVar5) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
  }
  iVar2 = *(int *)(unaff_s2 + 0xec);
  uVar7 = 0;
  if (*(short *)(iVar2 + 0x182) != 0) {
    do {
      if (uVar7 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar2 + uVar7 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar7 * 4 + 0x184) + 0x78) = 4;
      }
      iVar2 = *(int *)(unaff_s2 + 0xec);
      uVar7 = uVar7 + 1;
    } while (uVar7 < *(ushort *)(iVar2 + 0x182));
  }
  *(undefined4 *)(in_a3 + 0x10) = 4;    // POS.z
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar1;
  }
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar1;    // POS.y
  }
  return;
}


---

## FUN_00023210 (GAME.BIN) @ 0x023210


void FUN_00023210(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  undefined2 uVar1;
  int in_v1;
  int iVar2;
  int in_t0;
  short in_t1;
  short in_t2;
  uint uVar3;
  int unaff_s2;
  uint unaff_s5;
  
  *(short *)(unaff_s2 + 0x34) = (short)(-in_t0 >> 7);    // BD.x
  *(short *)(unaff_s2 + 0x38) = (short)(-param_3 >> 7);    // BD.z
  *(short *)(unaff_s2 + 8) = in_t2 - (short)(-((in_v1 + -10) * in_t0) >> 0xc);    // Q12_SHIFT Q12_PROD
  *(short *)(unaff_s2 + 0xc) = in_t1 - (short)(-((in_v1 + -10) * param_3) >> 0xc);    // POS.y Q12_SHIFT Q12_PROD
  iVar2 = *(int *)(unaff_s2 + 0xec);
  uVar3 = 0;
  if (*(short *)(iVar2 + 0x182) != 0) {
    do {
      if (uVar3 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar2 + uVar3 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar3 * 4 + 0x184) + 0x78) = 4;
      }
      iVar2 = *(int *)(unaff_s2 + 0xec);
      uVar3 = uVar3 + 1;
    } while (uVar3 < *(ushort *)(iVar2 + 0x182));
  }
  *(undefined4 *)(param_4 + 0x10) = 4;    // POS.z
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar1;
  }
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar1;    // POS.y
  }
  return;
}


---

## FUN_00032c18 (GAME.BIN) @ 0x032c18


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00032c18(uint param_1,undefined4 *param_2)

{
  undefined2 uVar1;
  int iVar2;
  undefined4 uVar3;
  short sVar4;
  undefined2 *puVar5;
  short sVar6;
  undefined2 *puVar7;
  int iVar8;
  undefined2 *puVar9;
  uint uVar10;
  
  param_1 = param_1 & 0xffff;    // ANGLE_MASK
  iVar2 = func_0x000f5b78(param_1,0);
  *(uint *)(iVar2 + 300) = param_1;
  *(undefined4 *)(iVar2 + 0x128) = *param_2;
  uVar3 = func_0x000743a4(1,param_1);
  *(undefined4 *)(iVar2 + 0x134) = uVar3;
  *(short *)(iVar2 + 0x138) = (short)((uint)param_2[4] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x13a) = (short)((uint)param_2[5] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x13c) = (short)((uint)param_2[6] >> 6);    // POS_SHIFT6
  sVar6 = (short)((uint)param_2[7] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x13e) = sVar6;
  sVar4 = (short)((uint)param_2[8] >> 0xc);    // Q12_SHIFT
  *(short *)(iVar2 + 0x140) = sVar4;
  *(short *)(iVar2 + 0x142) = (short)((uint)-param_2[9] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x144) = (short)((uint)param_2[10] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(short *)(iVar2 + 0x146) = (short)((uint)param_2[0xb] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x148) = *(undefined2 *)(param_2 + 0xd);
  *(undefined2 *)(iVar2 + 0x14a) = *(undefined2 *)(param_2 + 0xe);
  *(undefined2 *)(iVar2 + 0x14c) = *(undefined2 *)(param_2 + 0x10);    // POS.z
  iVar8 = (int)sVar6;
  *(short *)(iVar2 + 0x14e) = (short)((uint)param_2[0x12] >> 6);    // POS_SHIFT6
  if (iVar8 != 0) {
    if (iVar8 == 0) {
      trap(7);
    }
    *(short *)(iVar2 + 0x152) = (short)((sVar4 * 0x477) / iVar8);
  }
  *(undefined2 *)(iVar2 + 0x154) = *(undefined2 *)(param_2 + 0x18);
  *(short *)(iVar2 + 0x156) = (short)((uint)(param_2[0x18] * param_2[0x1b]) >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x15a) = *(undefined2 *)(param_2 + 0x19);
  *(undefined2 *)(iVar2 + 0x158) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar2 + 0x15c) = *(undefined2 *)(param_2 + 0x1c);
  *(undefined2 *)(iVar2 + 0x15e) = *(undefined2 *)(param_2 + 0x16);
  *(undefined2 *)(iVar2 + 0x150) = *(undefined2 *)(param_2 + 0x17);
  *(short *)(iVar2 + 0x160) = (short)((uint)param_2[0x1d] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x162) = *(undefined2 *)(param_2 + 0x21);
  *(short *)(iVar2 + 0x164) = (short)((uint)param_2[0x1f] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x166) = *(undefined2 *)(param_2 + 0x22);    // ANG.pitch
  *(short *)(iVar2 + 0x168) = (short)((uint)param_2[0x1e] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x16a) = *(undefined2 *)(param_2 + 0x23);
  *(short *)(iVar2 + 0x16c) = (short)((uint)param_2[0x20] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x16e) = *(undefined2 *)(param_2 + 0x24);    // ANG.roll
  *(short *)(iVar2 + 0x170) = (short)((uint)param_2[0x15] >> 0xc);    // Q12_SHIFT Q12_PROD
  sVar4 = (short)((uint)param_2[0x14] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x172) = sVar4;
  sVar6 = *(short *)(iVar2 + 0x128);
  if ((sVar6 == 4) || (sVar6 == 0xb)) {
    *(short *)(iVar2 + 0x174) = sVar4 * 3;
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  *(short *)(iVar2 + 0x174) = sVar4;
  *(undefined2 *)(iVar2 + 0x176) = *(undefined2 *)(param_2 + 1);
  *(undefined2 *)(iVar2 + 0x178) = *(undefined2 *)(param_2 + 2);
  uVar10 = 0;
  *(undefined2 *)(iVar2 + 0x17a) = *(undefined2 *)(param_2 + 3);
  uVar1 = *(undefined2 *)(param_2 + 0x27);
  *(undefined4 *)(iVar2 + 0x180) = 0;
  *(undefined2 *)(iVar2 + 0x17c) = uVar1;
  uVar1 = *(undefined2 *)(param_2 + 3);
  *(undefined2 *)(iVar2 + 0xb8) = 0xffff;
  *(undefined2 *)(iVar2 + 0xba) = 0xffff;
  *(undefined2 *)(iVar2 + 0xbc) = 0xffff;
  *(undefined2 *)(iVar2 + 0xbe) = 0xffff;
  *(undefined2 *)(iVar2 + 0xb4) = 0xffff;
  *(undefined2 *)(iVar2 + 0xb6) = 0xffff;
  *(undefined2 *)(iVar2 + 0xc0) = 0xffff;
  *(undefined2 *)(iVar2 + 0x17a) = uVar1;
  puVar9 = (undefined2 *)(iVar2 + 0xcc);
  *(undefined4 *)(iVar2 + 0x130) = param_2[0x25];
  puVar7 = (undefined2 *)(iVar2 + 0xca);
  *(undefined2 *)(iVar2 + 0x18a) = *(undefined2 *)(param_2 + 0x26);    // FLAGS
  puVar5 = (undefined2 *)(iVar2 + 200);
  *(undefined2 *)(iVar2 + 0x18c) = *(undefined2 *)(param_2 + 0x2b);
  do {
    *puVar5 = 0;
    *puVar7 = 0;
    *puVar9 = 0;
    puVar9 = puVar9 + 3;
    puVar7 = puVar7 + 3;
    uVar10 = uVar10 + 1;
    puVar5 = puVar5 + 3;
  } while (uVar10 < 9);
  if (param_1 - 6 < 0x4b) {
                    /* WARNING: Could not emulate address calculation at 0x00032f34 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)((param_1 - 6) * 4 + -0x7ff39824))();
    return;
  }
  func_0x000f719c(iVar2);
  if ((sVar6 == 5) || (uVar1 = 3000, sVar6 == 7)) {
    uVar1 = 6000;
  }
  *(undefined2 *)(iVar2 + 0xb0) = uVar1;
  *(undefined2 *)(iVar2 + 0x184) = *(undefined2 *)(param_2 + 0x28);
  *(undefined2 *)(iVar2 + 0x186) = *(undefined2 *)(param_2 + 0x29);
  uVar1 = *(undefined2 *)(param_2 + 0x2a);
  *(undefined2 *)(iVar2 + 0xfe) = 0x50;
  *(undefined2 *)(iVar2 + 0x188) = uVar1;
  if ((param_1 != 8) && (param_1 != 0x4a)) {
    if (param_1 == 10) {
      *(undefined2 *)(iVar2 + 0x11a) = 0;
      *(undefined2 *)(iVar2 + 0x11c) = 0xff60;
      *(undefined2 *)(iVar2 + 0x11e) = 0xfe8e;
      *(undefined2 *)(iVar2 + 0x120) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if (param_1 == 0x4c) {
      *(undefined2 *)(iVar2 + 0x11c) = 0xfe70;
      *(undefined2 *)(iVar2 + 0x11a) = 0;
      *(undefined2 *)(iVar2 + 0x11e) = 0;
      *(undefined2 *)(iVar2 + 0x120) = 1;
    }
    if (sVar6 == 6) {
      if (*(short *)(iVar2 + 0x13e) == 0) {
        trap(7);
      }
      iVar8 = (int)_DAT_8011966e * (int)_DAT_8011966e;
      if (iVar8 == 0) {
        trap(7);
      }
      *(short *)(iVar2 + 0xb2) =
           (short)((((int)*(short *)(iVar2 + 0x138) * (int)*(short *)(iVar2 + 0x138)) /
                    (int)*(short *)(iVar2 + 0x13e) << 0x11) / iVar8);
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00044a14 (GAME.BIN) @ 0x044a14


/* WARNING: Control flow encountered bad instruction data */

void FUN_00044a14(int param_1)

{
  undefined2 uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 local_20;
  undefined4 local_1c;
  
  iVar2 = func_0x000ab4d0(param_1 + 8);
  if ((*(short *)(*(int *)(param_1 + 0xb8) + 0x18) != 0) &&
     ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44))) {    // SPD
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) | 4;
  }
  if (*(short *)(param_1 + 10) <= iVar2) {
    return;
  }
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 5) == '\x04') && (0 < *(int *)(param_1 + 0xbc))) {
    if ((*(short *)(param_1 + 0x34) != 0) || (*(short *)(param_1 + 0x38) != 0)) {    // BD.x BD.z
      *(undefined2 *)(param_1 + 0x36) = 0;    // BD.y
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    uVar1 = 0xffff;
    if (*(short *)(param_1 + 0x36) == 0) {    // BD.y
      uVar1 = 0xfff6;
    }
    *(undefined2 *)(param_1 + 0x36) = uVar1;    // BD.y
    *(short *)(param_1 + 0x44) =    // SPD
         (short)((int)*(short *)(param_1 + 0x3c) * (int)*(short *)(param_1 + 0x34) +    // BS.x BD.x
                 (int)*(short *)(param_1 + 0x3e) * (int)*(short *)(param_1 + 0x36) +    // BS.y BD.y
                 (int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc);    // BS.z BD.z Q12_SHIFT Q12_PROD
    uVar1 = func_0x000ab4d0(param_1 + 8);
    *(undefined2 *)(param_1 + 10) = uVar1;
    iVar2 = func_0x000a9678((int)*(short *)(param_1 + 8),(int)*(short *)(param_1 + 0xc));    // POS.y
    if (iVar2 != 0) {
      *(undefined2 *)(param_1 + 0x44) = 0;    // SPD
    }
    func_0x00109ff4(param_1);
    if (*(short *)(param_1 + 0x44) == 0) {    // SPD
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // ANGLE_MASK
      halt_baddata();
    }
    return;
  }
  iVar3 = (int)*(short *)(param_1 + 10);
  if (iVar3 <= iVar2) {
    return;
  }
  if (iVar3 - iVar2 < 0) {
    if (iVar2 - iVar3 < 0x33) goto LAB_00044c9c;
  }
  else if (iVar3 - iVar2 < 0x33) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  uVar4 = 0x1000;
  do {
    uVar4 = (int)uVar4 >> 1;
    local_20 = CONCAT22(*(short *)(param_1 + 10) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x36)) >> 0xc),    // BD.y Q12_SHIFT Q12_PROD
                        *(short *)(param_1 + 8) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x34)) >> 0xc));    // BD.x Q12_SHIFT Q12_PROD
    local_1c = CONCAT22(local_1c._2_2_,
                        *(short *)(param_1 + 0xc) -    // POS.y
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x38)) >> 0xc));    // BD.z Q12_SHIFT Q12_PROD
    iVar2 = func_0x000ab4d0(&local_20);
    if (iVar2 < local_20._2_2_) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    iVar3 = iVar2 - local_20._2_2_;
    if (iVar3 < 0) {
      iVar3 = local_20._2_2_ - iVar2;
    }
  } while ((0x31 < iVar3) && (99 < uVar4));
  *(undefined4 *)(param_1 + 8) = local_20;
  *(undefined4 *)(param_1 + 0xc) = local_1c;    // POS.y
LAB_00044c9c:
  *(short *)(param_1 + 10) = (short)iVar2;
  if ((*(uint *)(param_1 + 0xd0) & 1) != 0) {
    *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 2;
  }
  uVar4 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x18);
  if (uVar4 == 0) {
    func_0x00084688(0xf,param_1 + 8,0);
    func_0x0010a4f8(param_1);
    uVar5 = *(uint *)(param_1 + 0xd0);
    uVar4 = uVar5 | 8;
    if ((uVar5 & 1) == 0) {
      uVar4 = uVar5 & 0xfffffff7;    // ANGLE_MASK
    }
    *(uint *)(param_1 + 0xd0) = uVar4;
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0) {    // ANG.yaw
      *(undefined2 *)(param_1 + 0xc0) = 0;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 3;
      uVar4 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
      if (uVar4 < 0x41) {
        uVar4 = 0x40;
      }
      if ((*(uint *)(param_1 + 0xd0) & 0x10) != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      *(short *)(param_1 + 0x9c) = (short)uVar4;
      *(uint *)(param_1 + 0x98) = uVar4 * uVar4;
    }
  }
  else {
    *(short *)(param_1 + 0x36) = (short)((int)-((int)*(short *)(param_1 + 0x36) * uVar4) >> 0xc);    // BD.y BD.y Q12_SHIFT Q12_PROD
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 1 & 1) != 0) {    // ANG.yaw
      uVar5 = *(uint *)((*(ushort *)(param_1 + 200) & 0x7f) * 4 + -0x7ffeb164);
      uVar4 = uVar5 >> 0x10;
      setCopControlWord(2,0,uVar4);
      uVar5 = uVar5 & 0xffff;    // ANGLE_MASK
      setCopControlWord(2,0x2000,uVar4);
      setCopControlWord(2,0x800,uVar5);
      setCopControlWord(2,0x1000,0x1000);
      setCopControlWord(2,0x1800,-uVar5 & 0xffff);    // ANGLE_MASK
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x34));    // BD.x
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x36));    // BD.y
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x38));    // BD.z
      copFunction(2,0x49e012);
      uVar6 = getCopReg(2,0x4800);
      uVar7 = getCopReg(2,0x5000);
      uVar8 = getCopReg(2,0x5800);
      *(short *)(param_1 + 0x34) = (short)uVar6;    // BD.x
      *(short *)(param_1 + 0x36) = (short)uVar7;    // BD.y
      *(short *)(param_1 + 0x38) = (short)uVar8;    // BD.z
    }
    func_0x00109ff4(param_1);
    if ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44)) {    // SPD
      uVar1 = (undefined2)
              ((int)*(short *)(param_1 + 0x34) * (int)*(short *)(param_1 + 0x3c) +    // BD.x BS.x
               (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +    // BD.y BS.y
               (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc);    // BD.z BS.z Q12_SHIFT Q12_PROD
      *(undefined2 *)(param_1 + 0xc4) = uVar1;
      *(undefined2 *)(param_1 + 0x44) = uVar1;    // SPD
    }
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffdff | 0x40;    // ANGLE_MASK
    func_0x00076790(param_1);
    uVar4 = (uint)(*(ushort *)(*(int *)(param_1 + 0xb8) + 8) >> 3);
    if (uVar4 < 3) {
      uVar4 = 3;
    }
    iVar2 = (int)*(short *)(param_1 + 0x36);    // BD.y
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    if (((iVar2 <= (int)uVar4) || ((int)*(short *)(param_1 + 0x44) <= (int)uVar4)) &&    // SPD
       (func_0x0010a4f8(param_1), (*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0)) {    // ANG.yaw
      *(undefined2 *)(param_1 + 0xc0) = 0;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 3;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  return;
}


---

## FUN_00044f80 (GAME.BIN) @ 0x044f80


/* WARNING: Control flow encountered bad instruction data */

void FUN_00044f80(int param_1)

{
  ushort uVar1;
  bool bVar2;
  short sVar3;
  undefined4 uVar4;
  uint uVar5;
  short sVar6;
  short sVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined4 local_50;
  undefined4 local_4c;
  undefined2 uStack_4a;
  short local_48;
  short local_46;
  short local_44;
  undefined1 auStack_40 [8];
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined1 auStack_28 [8];
  undefined4 local_20;
  undefined4 local_1c;
  
  iVar12 = *(int *)(param_1 + 0xd4);
  if (iVar12 != 0) {
    iVar9 = (int)(((uint)*(ushort *)(param_1 + 8) - (uint)*(ushort *)(iVar12 + 0x6c)) * 0x10000) >>
            0x10;
    iVar11 = (int)(((uint)*(ushort *)(param_1 + 10) - (uint)*(ushort *)(iVar12 + 0x6e)) * 0x10000)
             >> 0x10;
    iVar12 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)    // POS.y
             >> 0x10;
    uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
    if ((uint)(iVar9 * iVar9 + iVar11 * iVar11 + iVar12 * iVar12) <= uVar8 * uVar8) {
      uVar5 = 0x40;
      if (0x40 < uVar8) {
        uVar5 = uVar8;
      }
      *(short *)(param_1 + 0x9c) = (short)uVar5;
      *(uint *)(param_1 + 0x98) = uVar5 * uVar5;
      func_0x0010a4f8(param_1);
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  if (*(int *)(param_1 + 0xbc) < 1) {
    if ((*(uint *)(param_1 + 0x50) & 4) != 0) {
      return;
    }
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) | 4;
  }
  else {
    if (0 < *(short *)(param_1 + 0xc2)) {
      *(short *)(param_1 + 0xc2) = *(short *)(param_1 + 0xc2) + -1;
    }
    iVar12 = *(int *)(param_1 + 0xd4);
    if (iVar12 == 0) {
      if (*(short *)(param_1 + 0xc2) < 1) {
        uVar4 = func_0x0010834c(param_1);
        *(undefined4 *)(param_1 + 0xd4) = uVar4;
        *(undefined2 *)(param_1 + 0xc2) = *(undefined2 *)(*(int *)(param_1 + 0xb8) + 0x28);
        iVar12 = *(int *)(param_1 + 0xd4);
      }
      if (iVar12 == 0) {
        uVar8 = *(uint *)(*(int *)(param_1 + 0xb8) + 0x20);    // ANG.yaw
        if ((uVar8 >> 4 & 1) != 0) {
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);    // POS.z
          sVar3 = 0x80;
          if (0x80 < (int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1)) {    // SPD
            sVar3 = *(short *)(param_1 + 0x44) - uVar1;    // SPD
          }
          sVar6 = *(short *)(param_1 + 10);
          *(short *)(param_1 + 0x44) = sVar3;    // SPD
          iVar12 = func_0x000ab4d0(param_1 + 8);
          if ((((int)sVar6 < iVar12 + -0x100) && (*(short *)(param_1 + 0x3e) < 1)) &&    // BS.y
             (iVar12 = -(int)*(short *)(param_1 + 0x3e), (*(uint *)(param_1 + 0x50) & 4) == 0)) {    // BS.y
            if (iVar12 < 0x20) {
              iVar12 = 0x20;
            }
            *(short *)(param_1 + 0x3e) = (short)iVar12;    // BS.y
            func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),    // BS.x BS.z
                            param_1 + 0x3c);    // BS.x
          }
          iVar12 = (int)*(short *)(param_1 + 0x44);    // SPD
          *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);    // BD.x BS.x Q12_SHIFT Q12_PROD
          *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);    // BD.y BS.y Q12_SHIFT Q12_PROD
          *(short *)(param_1 + 0x38) = (short)(*(short *)(param_1 + 0x40) * iVar12 >> 0xc);    // BD.z BS.z Q12_SHIFT Q12_PROD
          halt_baddata();
        }
        if ((uVar8 >> 3 & 1) == 0) {
          func_0x00109e70(param_1);
          func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),    // BS.x BS.z
                          param_1 + 0x3c);    // BS.x
          halt_baddata();
        }
        return;
      }
    }
    iVar11 = (int)(((uint)*(ushort *)(param_1 + 8) - (uint)*(ushort *)(iVar12 + 0x6c)) * 0x10000) >>
             0x10;
    iVar10 = (int)(((uint)*(ushort *)(param_1 + 10) - (uint)*(ushort *)(iVar12 + 0x6e)) * 0x10000)
             >> 0x10;
    iVar9 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)    // POS.y
            >> 0x10;
    uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
    if (uVar8 * uVar8 < (uint)(iVar11 * iVar11 + iVar10 * iVar10 + iVar9 * iVar9)) {
      local_50 = CONCAT22(*(short *)(iVar12 + 0x6e) - *(ushort *)(param_1 + 10),
                          *(short *)(iVar12 + 0x6c) - *(ushort *)(param_1 + 8));
      local_2c = CONCAT22(uStack_4a,*(short *)(iVar12 + 0x70) - *(ushort *)(param_1 + 0xc));    // POS.y
      local_30 = local_50;
      func_0x00109758(param_1,local_50,local_2c,&local_48);
      local_30 = CONCAT22(local_46 - *(short *)(param_1 + 0x3e),    // BS.y
                          local_48 - *(short *)(param_1 + 0x3c));    // BS.x
      local_2c = CONCAT22(local_2c._2_2_,local_44 - *(short *)(param_1 + 0x40));    // BS.z
      local_20 = local_30;
      local_1c = local_2c;
      func_0x00109758(param_1,local_30,local_2c,auStack_28);
      iVar12 = func_0x0010a95c(param_1,param_1 + 0x3c,&local_48,auStack_40);    // BS.x
      iVar9 = (int)*(short *)(param_1 + 0x3c) * (int)local_48 +    // BS.x
              (int)*(short *)(param_1 + 0x3e) * (int)local_46 +    // BS.y
              (int)*(short *)(param_1 + 0x40) * (int)local_44 >> 0xc;    // BS.z Q12_SHIFT Q12_PROD
      func_0x0010a95c(param_1,auStack_40,param_1 + 0x3c,&local_38);    // BS.x
      local_20 = local_38;
      local_1c = local_34;
      func_0x00109758(param_1,local_38,local_34,&local_38);
      if (4000 < iVar9) {
        iVar11 = iVar12;
        if (iVar12 < 0) {
          iVar11 = -iVar12;
        }
        if (iVar11 < 1000) {
          if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {    // ANG.yaw
            return;
          }
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
      if ((iVar12 == 0) && (iVar9 < 0)) {
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) != 0) {    // ANG.yaw
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);    // POS.z
          sVar3 = *(short *)(param_1 + 0x44) - uVar1;    // SPD
          if ((int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1) < 1) {    // SPD
            sVar3 = 0;
          }
          *(short *)(param_1 + 0x44) = sVar3;    // SPD
        }
        func_0x0010a6ec(param_1);
      }
      else {
        uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x12);
        bVar2 = iVar9 < *(short *)((uVar8 & 0xfff) * 4 + -0x7ffeb162);    // ANGLE_MASK
        if (bVar2) {
          if (iVar12 < 0) {
            uVar8 = 0x1000 - uVar8 & 0xfff;    // ANGLE_MASK
          }
          iVar9 = (uVar8 & 0xfff) * 4;    // ANGLE_MASK
          iVar12 = (int)*(short *)(iVar9 + -0x7ffeb164);
          iVar9 = (int)*(short *)(iVar9 + -0x7ffeb162);
        }
        iVar11 = (int)*(short *)(param_1 + 0x44);    // SPD
        sVar7 = (short)(iVar9 * *(short *)(param_1 + 0x3c) + iVar12 * (short)local_38 >> 0xc);    // BS.x Q12_SHIFT Q12_PROD
        sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc);    // BS.y Q12_SHIFT Q12_PROD
        sVar6 = (short)(iVar9 * *(short *)(param_1 + 0x40) + iVar12 * (short)local_34 >> 0xc);    // BS.z Q12_SHIFT Q12_PROD
        *(short *)(param_1 + 0x3c) = sVar7;    // BS.x
        *(short *)(param_1 + 0x3e) = sVar3;    // BS.y
        *(short *)(param_1 + 0x40) = sVar6;    // BS.z
        *(short *)(param_1 + 0x34) = (short)(sVar7 * iVar11 >> 0xc);    // BD.x Q12_SHIFT Q12_PROD
        *(short *)(param_1 + 0x36) = (short)(sVar3 * iVar11 >> 0xc);    // BD.y Q12_SHIFT Q12_PROD
        *(short *)(param_1 + 0x38) = (short)(sVar6 * iVar11 >> 0xc);    // BD.z Q12_SHIFT Q12_PROD
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {    // ANG.yaw
          func_0x00109e70(param_1);
          return;
        }
        if (bVar2) {
          func_0x00109f60(param_1);
        }
        else {
          func_0x00109e70(param_1);
        }
      }
    }
    else {
      uVar5 = 0x40;
      if (0x40 < uVar8) {
        uVar5 = uVar8;
      }
      *(short *)(param_1 + 0x9c) = (short)uVar5;
      *(uint *)(param_1 + 0x98) = uVar5 * uVar5;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // ANGLE_MASK
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00022dc8 (GAME.BIN) @ 0x022dc8


/* WARNING: Control flow encountered bad instruction data */

void FUN_00022dc8(int param_1)

{
  short sVar1;
  undefined2 uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  short sVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined4 in_t3;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 uStack_58;
  uint local_54;
  undefined4 uStack_50;
  uint uStack_4c;
  short sStack_48;
  short sStack_46;
  short sStack_44;
  int iStack_40;
  int iStack_3c;
  int iStack_38;
  int iStack_30;
  int iStack_2c;
  uint auStack_28 [2];
  
  uVar3 = func_0x000f55e4(*(undefined4 *)(param_1 + 0xec),param_1);
  FUN_00023000(&uStack_58,0,8);
  iVar4 = *(int *)(param_1 + 0xec);
  setCopControlWord(2,0,*(undefined4 *)(iVar4 + 0x18));
  setCopControlWord(2,0x800,*(undefined4 *)(iVar4 + 0x1c));
  setCopControlWord(2,0x1000,*(undefined4 *)(iVar4 + 0x20));    // ANG.yaw
  setCopControlWord(2,0x1800,*(undefined4 *)(iVar4 + 0x24));    // ANG.roll
  setCopControlWord(2,0x2000,*(undefined4 *)(iVar4 + 0x28));
  iVar9 = (int)*(short *)(iVar4 + 0x152);
  iVar10 = (int)*(short *)(iVar4 + 0x154);
  setCopControlWord(2,0x2800,(int)*(short *)(iVar4 + 0x150));
  setCopControlWord(2,0x3000,iVar9);
  setCopControlWord(2,0x3800,iVar10);
  setCopReg(2,0x4800,uStack_58 & 0xffff);    // ANGLE_MASK
  setCopReg(2,0x5000,uStack_58 >> 0x10);
  setCopReg(2,0x5800,(uint)(ushort)((short)(-(int)*(short *)(*(int *)(iVar4 + 0x1a8) + 0x90) / 2) -
                                   0x80));
  copFunction(2,0x498012);
  uVar11 = getCopReg(2,0x4800);
  uVar12 = getCopReg(2,0x5000);
  uVar13 = getCopReg(2,0x5800);
  uStack_58 = CONCAT22((short)uVar12,(short)uVar11);
  local_54 = CONCAT22(local_54._2_2_,(short)uVar13);
  if (uVar3 != 0) {
    iVar4 = *(int *)(*(int *)(param_1 + 0xec) + (uVar3 - 1) * 4 + 0x184);
    uVar5 = *(uint *)(iVar4 + 8);
    uStack_4c = *(uint *)(iVar4 + 0xc);    // POS.y
    uStack_50._2_2_ = (short)(uVar5 >> 0x10);
    iVar6 = (uint)*(ushort *)(param_1 + 0xc) - (uStack_4c & 0xffff);    // POS.y ANGLE_MASK
    iVar4 = (uint)*(ushort *)(param_1 + 8) - (uVar5 & 0xffff);    // ANGLE_MASK
    sStack_48 = (short)iVar4;
    sStack_44 = (short)iVar6;
    sStack_46 = *(short *)(param_1 + 10) - uStack_50._2_2_;
    uStack_50 = uVar5;
    sVar1 = FUN_00022e5c(iVar6 * 0x10000 >> 0x10,iVar4 * 0x10000 >> 0x10);
    iStack_40 = (int)sStack_48;
    iStack_3c = (int)sStack_46;
    iStack_38 = (int)sStack_44;
    *(short *)(param_1 + 0x12) = -sVar1;
    setCopReg(2,iVar9,iStack_40);
    setCopReg(2,iVar10,iStack_3c);
    setCopReg(2,in_t3,iStack_38);
    copFunction(2,0xa00428);
    iVar9 = getCopReg(2,0xc800);
    iVar4 = getCopReg(2,0xd000);
    iStack_30 = getCopReg(2,0xd800);
    iStack_30 = iVar9 + iVar4 + iStack_30;
    FUN_00022bac(iStack_30,&iStack_2c,auStack_28);
    iStack_40 = iStack_40 * iStack_2c >> (auStack_28[0] & 0x1f);
    iStack_3c = iStack_3c * iStack_2c >> (auStack_28[0] & 0x1f);
    iStack_38 = iStack_38 * iStack_2c >> (auStack_28[0] & 0x1f);
    iVar4 = FUN_00023180((int)sStack_48 * (int)sStack_48 + (int)sStack_46 * (int)sStack_46 +
                         (int)sStack_44 * (int)sStack_44);
    iVar4 = (iVar4 + -300) * 0x10000 >> 0x10;
    sVar1 = (short)(((int)(((uint)*(ushort *)(param_1 + 0x34) - (iVar4 * iStack_40 >> 0xf)) *    // BD.x
                          0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(param_1 + 0x34) = sVar1;    // BD.x
    sVar7 = (short)(((int)(((uint)*(ushort *)(param_1 + 0x36) - (iVar4 * iStack_3c >> 0xf)) *    // BD.y
                          0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(param_1 + 0x36) = sVar7;    // BD.y
    *(short *)(param_1 + 8) = *(short *)(param_1 + 8) + sVar1;
    sVar1 = (short)(((int)(((uint)*(ushort *)(param_1 + 0x38) - (iVar4 * iStack_38 >> 0xf)) *    // BD.z
                          0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(param_1 + 0x38) = sVar1;    // BD.z
    *(short *)(param_1 + 10) = *(short *)(param_1 + 10) + sVar7;
    *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + sVar1;    // POS.y POS.y
    iVar4 = func_0x000ab4d0(param_1 + 8);
    if (iVar4 < *(short *)(param_1 + 10)) {
      *(short *)(param_1 + 10) = (short)iVar4;
    }
    *(undefined4 *)(param_1 + 0x78) = 1;
    iVar9 = (uint)*(ushort *)(param_1 + 8) - (uStack_58 & 0xffff);    // ANGLE_MASK
    sStack_48 = (short)iVar9;
    sStack_46 = *(short *)(param_1 + 10) - uStack_58._2_2_;
    iVar10 = (uint)*(ushort *)(param_1 + 0xc) - (local_54 & 0xffff);    // POS.y ANGLE_MASK
    sStack_44 = (short)iVar10;
    iVar4 = (*(ushort *)(*(int *)(param_1 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
    iVar8 = (int)*(short *)(iVar4 + -0x7ffeb164);
    iVar6 = (int)*(short *)(iVar4 + -0x7ffeb162);
    iVar4 = -(iVar9 * 0x10000 >> 0x10) * iVar8 - (iVar10 * 0x10000 >> 0x10) * iVar6 >> 0xc;    // Q12_SHIFT Q12_PROD
    if (iVar4 < 0) {
      iVar4 = iVar4 + -10;
      *(short *)(param_1 + 0x34) = (short)(-iVar8 >> 7);    // BD.x
      *(short *)(param_1 + 0x38) = (short)(-iVar6 >> 7);    // BD.z
      *(ushort *)(param_1 + 8) = *(ushort *)(param_1 + 8) - (short)(-(iVar4 * iVar8) >> 0xc);    // Q12_SHIFT Q12_PROD
      *(ushort *)(param_1 + 0xc) = *(ushort *)(param_1 + 0xc) - (short)(-(iVar4 * iVar6) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
    }
    iVar4 = *(int *)(param_1 + 0xec);
    uVar5 = 0;
    if (*(short *)(iVar4 + 0x182) != 0) {
      do {
        iVar9 = uVar5 * 4;
        if (uVar5 != uVar3) {
          *(undefined4 *)(*(int *)(iVar4 + iVar9 + 0x184) + 0x78) = 1;
          func_0x000e8cfc(param_1,*(undefined4 *)(*(int *)(param_1 + 0xec) + iVar9 + 0x184));
          *(undefined4 *)(*(int *)(*(int *)(param_1 + 0xec) + iVar9 + 0x184) + 0x78) = 4;
        }
        iVar4 = *(int *)(param_1 + 0xec);
        uVar5 = uVar5 + 1;
      } while (uVar5 < *(ushort *)(iVar4 + 0x182));
    }
    *(undefined4 *)(param_1 + 0x78) = 4;
    uVar2 = 0xc100;
    if ((*(short *)(param_1 + 8) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(param_1 + 8))) {
      *(undefined2 *)(param_1 + 8) = uVar2;
    }
    uVar2 = 0xc100;
    if ((*(short *)(param_1 + 0xc) < -0x3f00) ||    // POS.y
       (uVar2 = 0x3f00, 0x3f00 < *(short *)(param_1 + 0xc))) {    // POS.y
      *(undefined2 *)(param_1 + 0xc) = uVar2;    // POS.y
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00022e5c (GAME.BIN) @ 0x022e5c


/* WARNING: Control flow encountered bad instruction data */

void FUN_00022e5c(int param_1)

{
  uint uVar1;
  uint uVar2;
  short sVar3;
  undefined2 uVar4;
  int in_v1;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  short sVar9;
  int iVar10;
  int iVar11;
  undefined4 in_t3;
  undefined4 in_t4;
  undefined4 uVar12;
  undefined4 uVar13;
  uint uVar14;
  ushort *unaff_s0;
  int unaff_s2;
  uint unaff_s5;
  int iVar15;
  uint uStack00000010;
  uint uStack00000018;
  uint uStack0000001c;
  short sStack00000020;
  short sStack00000022;
  short sStack00000024;
  int in_stack_0000003c;
  uint in_stack_00000040;
  
  setCopControlWord(2,0x1000,in_t4);
  setCopControlWord(2,0x1800,*(undefined4 *)(in_v1 + 0xc));    // POS.y
  setCopControlWord(2,0x2000,*(undefined4 *)(in_v1 + 0x10));    // POS.z
  iVar10 = (int)*(short *)(param_1 + 0x152);
  iVar11 = (int)*(short *)(param_1 + 0x154);
  setCopControlWord(2,0x2800,(int)*(short *)(param_1 + 0x150));
  setCopControlWord(2,0x3000,iVar10);
  setCopControlWord(2,0x3800,iVar11);
  setCopReg(2,0x4800,(uint)*unaff_s0);
  setCopReg(2,0x5000,(uint)unaff_s0[1]);
  setCopReg(2,0x5800,(uint)unaff_s0[2]);
  copFunction(2,0x498012);
  uVar12 = getCopReg(2,0x4800);
  uVar13 = getCopReg(2,0x5000);
  uVar14 = getCopReg(2,0x5800);
  uStack00000010 = CONCAT22((short)uVar13,(short)uVar12);
  if (unaff_s5 != 0) {
    iVar5 = *(int *)(*(int *)(unaff_s2 + 0xec) + (unaff_s5 - 1) * 4 + 0x184);
    uVar7 = *(uint *)(iVar5 + 8);
    uStack0000001c = *(uint *)(iVar5 + 0xc);    // POS.y
    uStack00000018._2_2_ = (short)(uVar7 >> 0x10);
    iVar8 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uStack0000001c & 0xffff);    // POS.y ANGLE_MASK
    iVar5 = (uint)*(ushort *)(unaff_s2 + 8) - (uVar7 & 0xffff);    // ANGLE_MASK
    sStack00000020 = (short)iVar5;
    sStack00000024 = (short)iVar8;
    sStack00000022 = *(short *)(unaff_s2 + 10) - uStack00000018._2_2_;
    uStack00000018 = uVar7;
    sVar3 = FUN_00022e5c(iVar8 * 0x10000 >> 0x10,iVar5 * 0x10000 >> 0x10);
    iVar5 = (int)sStack00000020;
    iVar8 = (int)sStack00000022;
    iVar6 = (int)sStack00000024;
    *(short *)(unaff_s2 + 0x12) = -sVar3;
    setCopReg(2,iVar10,iVar5);
    setCopReg(2,iVar11,iVar8);
    setCopReg(2,in_t3,iVar6);
    copFunction(2,0xa00428);
    iVar15 = getCopReg(2,0xc800);
    iVar10 = getCopReg(2,0xd000);
    iVar11 = getCopReg(2,0xd800);
    FUN_00022bac(iVar15 + iVar10 + iVar11,&stack0x0000003c,&stack0x00000040);
    iVar5 = iVar5 * in_stack_0000003c;
    iVar8 = iVar8 * in_stack_0000003c;
    iVar6 = iVar6 * in_stack_0000003c;
    uVar7 = in_stack_00000040 & 0x1f;
    uVar1 = in_stack_00000040 & 0x1f;
    uVar2 = in_stack_00000040 & 0x1f;
    iVar10 = FUN_00023180((int)sStack00000020 * (int)sStack00000020 +
                          (int)sStack00000022 * (int)sStack00000022 +
                          (int)sStack00000024 * (int)sStack00000024);
    iVar10 = (iVar10 + -300) * 0x10000 >> 0x10;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar10 * (iVar5 >> uVar7) >> 0xf))    // BD.x
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x34) = sVar3;    // BD.x
    sVar9 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar10 * (iVar8 >> uVar1) >> 0xf))    // BD.y
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x36) = sVar9;    // BD.y
    *(short *)(unaff_s2 + 8) = *(short *)(unaff_s2 + 8) + sVar3;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x38) - (iVar10 * (iVar6 >> uVar2) >> 0xf))    // BD.z
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x38) = sVar3;    // BD.z
    *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + sVar9;
    *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar3;    // POS.y POS.y
    iVar10 = func_0x000ab4d0(unaff_s2 + 8);
    if (iVar10 < *(short *)(unaff_s2 + 10)) {
      *(short *)(unaff_s2 + 10) = (short)iVar10;
    }
    *(undefined4 *)(unaff_s2 + 0x78) = 1;
    iVar11 = (uint)*(ushort *)(unaff_s2 + 8) - (uStack00000010 & 0xffff);    // ANGLE_MASK
    sStack00000020 = (short)iVar11;
    sStack00000022 = *(short *)(unaff_s2 + 10) - uStack00000010._2_2_;
    iVar5 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uVar14 & 0xffff);    // POS.y ANGLE_MASK
    sStack00000024 = (short)iVar5;
    iVar10 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
    iVar6 = (int)*(short *)(iVar10 + -0x7ffeb164);
    iVar8 = (int)*(short *)(iVar10 + -0x7ffeb162);
    iVar10 = -(iVar11 * 0x10000 >> 0x10) * iVar6 - (iVar5 * 0x10000 >> 0x10) * iVar8 >> 0xc;    // Q12_SHIFT Q12_PROD
    if (iVar10 < 0) {
      iVar10 = iVar10 + -10;
      *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);    // BD.x
      *(short *)(unaff_s2 + 0x38) = (short)(-iVar8 >> 7);    // BD.z
      *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar10 * iVar6) >> 0xc);    // Q12_SHIFT Q12_PROD
      *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar10 * iVar8) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
    }
    iVar10 = *(int *)(unaff_s2 + 0xec);
    uVar14 = 0;
    if (*(short *)(iVar10 + 0x182) != 0) {
      do {
        if (uVar14 != unaff_s5) {
          *(undefined4 *)(*(int *)(iVar10 + uVar14 * 4 + 0x184) + 0x78) = 1;
          func_0x000e8cfc();
          *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar14 * 4 + 0x184) + 0x78) = 4;
        }
        iVar10 = *(int *)(unaff_s2 + 0xec);
        uVar14 = uVar14 + 1;
      } while (uVar14 < *(ushort *)(iVar10 + 0x182));
    }
    *(undefined4 *)(unaff_s2 + 0x78) = 4;
    uVar4 = 0xc100;
    if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar4 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8)))
    {
      *(undefined2 *)(unaff_s2 + 8) = uVar4;
    }
    uVar4 = 0xc100;
    if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
       (uVar4 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
      *(undefined2 *)(unaff_s2 + 0xc) = uVar4;    // POS.y
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00023000 (GAME.BIN) @ 0x023000


void FUN_00023000(undefined4 param_1,int param_2,undefined4 param_3,int param_4,ushort param_5,
                 ushort param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9,
                 short param_10,undefined4 param_11,undefined4 param_12,int param_13)

{
  short sVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  short sVar5;
  int in_t0;
  int iVar6;
  uint uVar7;
  int unaff_s2;
  uint unaff_s5;
  uint in_stack_00000040;
  
  param_11 = in_t0 >> (in_stack_00000040 & 0x1f);
  param_12 = param_4 * param_2 >> (in_stack_00000040 & 0x1f);
  iVar3 = FUN_00023180((int)(short)param_9 * (int)(short)param_9 +
                       (int)param_9._2_2_ * (int)param_9._2_2_ + (int)param_10 * (int)param_10);
  iVar3 = (iVar3 + -300) * 0x10000 >> 0x10;
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar3 * param_11 >> 0xf)) * 0x10000)    // BD.x
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x34) = sVar1;    // BD.x
  sVar5 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar3 * param_12 >> 0xf)) * 0x10000)    // BD.y
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x36) = sVar5;    // BD.y
  *(short *)(unaff_s2 + 8) = *(short *)(unaff_s2 + 8) + sVar1;
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x38) -    // BD.z
                         (iVar3 * (param_13 * param_2 >> (in_stack_00000040 & 0x1f)) >> 0xf)) *
                        0x10000) >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x38) = sVar1;    // BD.z
  *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + sVar5;
  *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar1;    // POS.y POS.y
  iVar3 = func_0x000ab4d0(unaff_s2 + 8);
  if (iVar3 < *(short *)(unaff_s2 + 10)) {
    *(short *)(unaff_s2 + 10) = (short)iVar3;
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 1;
  iVar3 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
  iVar6 = (int)*(short *)(iVar3 + -0x7ffeb164);
  iVar4 = (int)*(short *)(iVar3 + -0x7ffeb162);
  iVar3 = -((int)(((uint)*(ushort *)(unaff_s2 + 8) - (uint)param_5) * 0x10000) >> 0x10) * iVar6 -
          ((int)(((uint)*(ushort *)(unaff_s2 + 0xc) - (uint)param_6) * 0x10000) >> 0x10) * iVar4 >>    // POS.y Q12_SHIFT
          0xc;
  if (iVar3 < 0) {
    iVar3 = iVar3 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);    // BD.x
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar4 >> 7);    // BD.z
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar3 * iVar6) >> 0xc);    // Q12_SHIFT Q12_PROD
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar3 * iVar4) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
  }
  iVar3 = *(int *)(unaff_s2 + 0xec);
  uVar7 = 0;
  if (*(short *)(iVar3 + 0x182) != 0) {
    do {
      if (uVar7 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar3 + uVar7 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar7 * 4 + 0x184) + 0x78) = 4;
      }
      iVar3 = *(int *)(unaff_s2 + 0xec);
      uVar7 = uVar7 + 1;
    } while (uVar7 < *(ushort *)(iVar3 + 0x182));
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 4;
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar2;
  }
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar2;    // POS.y
  }
  return;
}


---

## FUN_00023110 (GAME.BIN) @ 0x023110


void FUN_00023110(undefined4 param_1,undefined4 param_2,short param_3,short param_4,uint param_5,
                 ushort param_6)

{
  short sVar1;
  undefined2 uVar2;
  int iVar3;
  int in_v1;
  int iVar4;
  short in_t0;
  int iVar5;
  uint uVar6;
  int unaff_s2;
  uint unaff_s5;
  int in_lo;
  short sStack00000022;
  
  *(short *)(unaff_s2 + 0x36) = param_4;    // BD.y
  *(short *)(unaff_s2 + 8) = param_3 + in_t0;
  sVar1 = (short)(((in_v1 - (in_lo >> 0xf)) * 0x10000 >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x38) = sVar1;    // BD.z
  *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + param_4;
  *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar1;    // POS.y POS.y
  iVar3 = func_0x000ab4d0();
  if (iVar3 < *(short *)(unaff_s2 + 10)) {
    *(short *)(unaff_s2 + 10) = (short)iVar3;
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 1;
  sStack00000022 = *(short *)(unaff_s2 + 10) - param_5._2_2_;
  iVar3 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
  iVar5 = (int)*(short *)(iVar3 + -0x7ffeb164);
  iVar4 = (int)*(short *)(iVar3 + -0x7ffeb162);
  iVar3 = -((int)(((uint)*(ushort *)(unaff_s2 + 8) - (param_5 & 0xffff)) * 0x10000) >> 0x10) * iVar5    // ANGLE_MASK
          - ((int)(((uint)*(ushort *)(unaff_s2 + 0xc) - (uint)param_6) * 0x10000) >> 0x10) * iVar4    // POS.y Q12_SHIFT
          >> 0xc;    // Q12_SHIFT
  if (iVar3 < 0) {
    iVar3 = iVar3 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar5 >> 7);    // BD.x
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar4 >> 7);    // BD.z
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar3 * iVar5) >> 0xc);    // Q12_SHIFT Q12_PROD
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar3 * iVar4) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
  }
  iVar3 = *(int *)(unaff_s2 + 0xec);
  uVar6 = 0;
  if (*(short *)(iVar3 + 0x182) != 0) {
    do {
      if (uVar6 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar3 + uVar6 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar6 * 4 + 0x184) + 0x78) = 4;
      }
      iVar3 = *(int *)(unaff_s2 + 0xec);
      uVar6 = uVar6 + 1;
    } while (uVar6 < *(ushort *)(iVar3 + 0x182));
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 4;
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar2;
  }
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar2;    // POS.y
  }
  return;
}


---

## FUN_00023180 (GAME.BIN) @ 0x023180


void FUN_00023180(void)

{
  undefined2 in_v0;
  undefined2 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int in_a3;
  int iVar6;
  uint uVar7;
  int unaff_s2;
  uint unaff_s5;
  uint in_stack_00000010;
  ushort in_stack_00000014;
  undefined2 uStack00000020;
  short sStack00000022;
  undefined2 uStack00000024;
  
  *(undefined2 *)(unaff_s2 + 10) = in_v0;
  *(undefined4 *)(in_a3 + 0x10) = 1;    // POS.z
  iVar3 = (uint)*(ushort *)(unaff_s2 + 8) - (in_stack_00000010 & 0xffff);    // ANGLE_MASK
  uStack00000020 = (undefined2)iVar3;
  sStack00000022 = *(short *)(unaff_s2 + 10) - in_stack_00000010._2_2_;
  iVar4 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uint)in_stack_00000014;    // POS.y
  uStack00000024 = (undefined2)iVar4;
  iVar2 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
  iVar6 = (int)*(short *)(iVar2 + -0x7ffeb164);
  iVar5 = (int)*(short *)(iVar2 + -0x7ffeb162);
  iVar2 = -(iVar3 * 0x10000 >> 0x10) * iVar6 - (iVar4 * 0x10000 >> 0x10) * iVar5 >> 0xc;    // Q12_SHIFT Q12_PROD
  if (iVar2 < 0) {
    iVar2 = iVar2 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);    // BD.x
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar5 >> 7);    // BD.z
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar2 * iVar6) >> 0xc);    // Q12_SHIFT Q12_PROD
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar2 * iVar5) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
  }
  iVar2 = *(int *)(unaff_s2 + 0xec);
  uVar7 = 0;
  if (*(short *)(iVar2 + 0x182) != 0) {
    do {
      if (uVar7 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar2 + uVar7 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar7 * 4 + 0x184) + 0x78) = 4;
      }
      iVar2 = *(int *)(unaff_s2 + 0xec);
      uVar7 = uVar7 + 1;
    } while (uVar7 < *(ushort *)(iVar2 + 0x182));
  }
  *(undefined4 *)(in_a3 + 0x10) = 4;    // POS.z
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar1;
  }
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar1;    // POS.y
  }
  return;
}


---

## FUN_00023210 (GAME.BIN) @ 0x023210


void FUN_00023210(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  undefined2 uVar1;
  int in_v1;
  int iVar2;
  int in_t0;
  short in_t1;
  short in_t2;
  uint uVar3;
  int unaff_s2;
  uint unaff_s5;
  
  *(short *)(unaff_s2 + 0x34) = (short)(-in_t0 >> 7);    // BD.x
  *(short *)(unaff_s2 + 0x38) = (short)(-param_3 >> 7);    // BD.z
  *(short *)(unaff_s2 + 8) = in_t2 - (short)(-((in_v1 + -10) * in_t0) >> 0xc);    // Q12_SHIFT Q12_PROD
  *(short *)(unaff_s2 + 0xc) = in_t1 - (short)(-((in_v1 + -10) * param_3) >> 0xc);    // POS.y Q12_SHIFT Q12_PROD
  iVar2 = *(int *)(unaff_s2 + 0xec);
  uVar3 = 0;
  if (*(short *)(iVar2 + 0x182) != 0) {
    do {
      if (uVar3 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar2 + uVar3 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar3 * 4 + 0x184) + 0x78) = 4;
      }
      iVar2 = *(int *)(unaff_s2 + 0xec);
      uVar3 = uVar3 + 1;
    } while (uVar3 < *(ushort *)(iVar2 + 0x182));
  }
  *(undefined4 *)(param_4 + 0x10) = 4;    // POS.z
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar1;
  }
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar1;    // POS.y
  }
  return;
}


---

## FUN_00032c18 (GAME.BIN) @ 0x032c18


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00032c18(uint param_1,undefined4 *param_2)

{
  undefined2 uVar1;
  int iVar2;
  undefined4 uVar3;
  short sVar4;
  undefined2 *puVar5;
  short sVar6;
  undefined2 *puVar7;
  int iVar8;
  undefined2 *puVar9;
  uint uVar10;
  
  param_1 = param_1 & 0xffff;    // ANGLE_MASK
  iVar2 = func_0x000f5b78(param_1,0);
  *(uint *)(iVar2 + 300) = param_1;
  *(undefined4 *)(iVar2 + 0x128) = *param_2;
  uVar3 = func_0x000743a4(1,param_1);
  *(undefined4 *)(iVar2 + 0x134) = uVar3;
  *(short *)(iVar2 + 0x138) = (short)((uint)param_2[4] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x13a) = (short)((uint)param_2[5] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x13c) = (short)((uint)param_2[6] >> 6);    // POS_SHIFT6
  sVar6 = (short)((uint)param_2[7] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x13e) = sVar6;
  sVar4 = (short)((uint)param_2[8] >> 0xc);    // Q12_SHIFT
  *(short *)(iVar2 + 0x140) = sVar4;
  *(short *)(iVar2 + 0x142) = (short)((uint)-param_2[9] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x144) = (short)((uint)param_2[10] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(short *)(iVar2 + 0x146) = (short)((uint)param_2[0xb] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x148) = *(undefined2 *)(param_2 + 0xd);
  *(undefined2 *)(iVar2 + 0x14a) = *(undefined2 *)(param_2 + 0xe);
  *(undefined2 *)(iVar2 + 0x14c) = *(undefined2 *)(param_2 + 0x10);    // POS.z
  iVar8 = (int)sVar6;
  *(short *)(iVar2 + 0x14e) = (short)((uint)param_2[0x12] >> 6);    // POS_SHIFT6
  if (iVar8 != 0) {
    if (iVar8 == 0) {
      trap(7);
    }
    *(short *)(iVar2 + 0x152) = (short)((sVar4 * 0x477) / iVar8);
  }
  *(undefined2 *)(iVar2 + 0x154) = *(undefined2 *)(param_2 + 0x18);
  *(short *)(iVar2 + 0x156) = (short)((uint)(param_2[0x18] * param_2[0x1b]) >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x15a) = *(undefined2 *)(param_2 + 0x19);
  *(undefined2 *)(iVar2 + 0x158) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar2 + 0x15c) = *(undefined2 *)(param_2 + 0x1c);
  *(undefined2 *)(iVar2 + 0x15e) = *(undefined2 *)(param_2 + 0x16);
  *(undefined2 *)(iVar2 + 0x150) = *(undefined2 *)(param_2 + 0x17);
  *(short *)(iVar2 + 0x160) = (short)((uint)param_2[0x1d] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x162) = *(undefined2 *)(param_2 + 0x21);
  *(short *)(iVar2 + 0x164) = (short)((uint)param_2[0x1f] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x166) = *(undefined2 *)(param_2 + 0x22);    // ANG.pitch
  *(short *)(iVar2 + 0x168) = (short)((uint)param_2[0x1e] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x16a) = *(undefined2 *)(param_2 + 0x23);
  *(short *)(iVar2 + 0x16c) = (short)((uint)param_2[0x20] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x16e) = *(undefined2 *)(param_2 + 0x24);    // ANG.roll
  *(short *)(iVar2 + 0x170) = (short)((uint)param_2[0x15] >> 0xc);    // Q12_SHIFT Q12_PROD
  sVar4 = (short)((uint)param_2[0x14] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x172) = sVar4;
  sVar6 = *(short *)(iVar2 + 0x128);
  if ((sVar6 == 4) || (sVar6 == 0xb)) {
    *(short *)(iVar2 + 0x174) = sVar4 * 3;
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  *(short *)(iVar2 + 0x174) = sVar4;
  *(undefined2 *)(iVar2 + 0x176) = *(undefined2 *)(param_2 + 1);
  *(undefined2 *)(iVar2 + 0x178) = *(undefined2 *)(param_2 + 2);
  uVar10 = 0;
  *(undefined2 *)(iVar2 + 0x17a) = *(undefined2 *)(param_2 + 3);
  uVar1 = *(undefined2 *)(param_2 + 0x27);
  *(undefined4 *)(iVar2 + 0x180) = 0;
  *(undefined2 *)(iVar2 + 0x17c) = uVar1;
  uVar1 = *(undefined2 *)(param_2 + 3);
  *(undefined2 *)(iVar2 + 0xb8) = 0xffff;
  *(undefined2 *)(iVar2 + 0xba) = 0xffff;
  *(undefined2 *)(iVar2 + 0xbc) = 0xffff;
  *(undefined2 *)(iVar2 + 0xbe) = 0xffff;
  *(undefined2 *)(iVar2 + 0xb4) = 0xffff;
  *(undefined2 *)(iVar2 + 0xb6) = 0xffff;
  *(undefined2 *)(iVar2 + 0xc0) = 0xffff;
  *(undefined2 *)(iVar2 + 0x17a) = uVar1;
  puVar9 = (undefined2 *)(iVar2 + 0xcc);
  *(undefined4 *)(iVar2 + 0x130) = param_2[0x25];
  puVar7 = (undefined2 *)(iVar2 + 0xca);
  *(undefined2 *)(iVar2 + 0x18a) = *(undefined2 *)(param_2 + 0x26);    // FLAGS
  puVar5 = (undefined2 *)(iVar2 + 200);
  *(undefined2 *)(iVar2 + 0x18c) = *(undefined2 *)(param_2 + 0x2b);
  do {
    *puVar5 = 0;
    *puVar7 = 0;
    *puVar9 = 0;
    puVar9 = puVar9 + 3;
    puVar7 = puVar7 + 3;
    uVar10 = uVar10 + 1;
    puVar5 = puVar5 + 3;
  } while (uVar10 < 9);
  if (param_1 - 6 < 0x4b) {
                    /* WARNING: Could not emulate address calculation at 0x00032f34 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)((param_1 - 6) * 4 + -0x7ff39824))();
    return;
  }
  func_0x000f719c(iVar2);
  if ((sVar6 == 5) || (uVar1 = 3000, sVar6 == 7)) {
    uVar1 = 6000;
  }
  *(undefined2 *)(iVar2 + 0xb0) = uVar1;
  *(undefined2 *)(iVar2 + 0x184) = *(undefined2 *)(param_2 + 0x28);
  *(undefined2 *)(iVar2 + 0x186) = *(undefined2 *)(param_2 + 0x29);
  uVar1 = *(undefined2 *)(param_2 + 0x2a);
  *(undefined2 *)(iVar2 + 0xfe) = 0x50;
  *(undefined2 *)(iVar2 + 0x188) = uVar1;
  if ((param_1 != 8) && (param_1 != 0x4a)) {
    if (param_1 == 10) {
      *(undefined2 *)(iVar2 + 0x11a) = 0;
      *(undefined2 *)(iVar2 + 0x11c) = 0xff60;
      *(undefined2 *)(iVar2 + 0x11e) = 0xfe8e;
      *(undefined2 *)(iVar2 + 0x120) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if (param_1 == 0x4c) {
      *(undefined2 *)(iVar2 + 0x11c) = 0xfe70;
      *(undefined2 *)(iVar2 + 0x11a) = 0;
      *(undefined2 *)(iVar2 + 0x11e) = 0;
      *(undefined2 *)(iVar2 + 0x120) = 1;
    }
    if (sVar6 == 6) {
      if (*(short *)(iVar2 + 0x13e) == 0) {
        trap(7);
      }
      iVar8 = (int)_DAT_8011966e * (int)_DAT_8011966e;
      if (iVar8 == 0) {
        trap(7);
      }
      *(short *)(iVar2 + 0xb2) =
           (short)((((int)*(short *)(iVar2 + 0x138) * (int)*(short *)(iVar2 + 0x138)) /
                    (int)*(short *)(iVar2 + 0x13e) << 0x11) / iVar8);
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00044a14 (GAME.BIN) @ 0x044a14


/* WARNING: Control flow encountered bad instruction data */

void FUN_00044a14(int param_1)

{
  undefined2 uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 local_20;
  undefined4 local_1c;
  
  iVar2 = func_0x000ab4d0(param_1 + 8);
  if ((*(short *)(*(int *)(param_1 + 0xb8) + 0x18) != 0) &&
     ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44))) {    // SPD
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) | 4;
  }
  if (*(short *)(param_1 + 10) <= iVar2) {
    return;
  }
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 5) == '\x04') && (0 < *(int *)(param_1 + 0xbc))) {
    if ((*(short *)(param_1 + 0x34) != 0) || (*(short *)(param_1 + 0x38) != 0)) {    // BD.x BD.z
      *(undefined2 *)(param_1 + 0x36) = 0;    // BD.y
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    uVar1 = 0xffff;
    if (*(short *)(param_1 + 0x36) == 0) {    // BD.y
      uVar1 = 0xfff6;
    }
    *(undefined2 *)(param_1 + 0x36) = uVar1;    // BD.y
    *(short *)(param_1 + 0x44) =    // SPD
         (short)((int)*(short *)(param_1 + 0x3c) * (int)*(short *)(param_1 + 0x34) +    // BS.x BD.x
                 (int)*(short *)(param_1 + 0x3e) * (int)*(short *)(param_1 + 0x36) +    // BS.y BD.y
                 (int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc);    // BS.z BD.z Q12_SHIFT Q12_PROD
    uVar1 = func_0x000ab4d0(param_1 + 8);
    *(undefined2 *)(param_1 + 10) = uVar1;
    iVar2 = func_0x000a9678((int)*(short *)(param_1 + 8),(int)*(short *)(param_1 + 0xc));    // POS.y
    if (iVar2 != 0) {
      *(undefined2 *)(param_1 + 0x44) = 0;    // SPD
    }
    func_0x00109ff4(param_1);
    if (*(short *)(param_1 + 0x44) == 0) {    // SPD
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // ANGLE_MASK
      halt_baddata();
    }
    return;
  }
  iVar3 = (int)*(short *)(param_1 + 10);
  if (iVar3 <= iVar2) {
    return;
  }
  if (iVar3 - iVar2 < 0) {
    if (iVar2 - iVar3 < 0x33) goto LAB_00044c9c;
  }
  else if (iVar3 - iVar2 < 0x33) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  uVar4 = 0x1000;
  do {
    uVar4 = (int)uVar4 >> 1;
    local_20 = CONCAT22(*(short *)(param_1 + 10) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x36)) >> 0xc),    // BD.y Q12_SHIFT Q12_PROD
                        *(short *)(param_1 + 8) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x34)) >> 0xc));    // BD.x Q12_SHIFT Q12_PROD
    local_1c = CONCAT22(local_1c._2_2_,
                        *(short *)(param_1 + 0xc) -    // POS.y
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x38)) >> 0xc));    // BD.z Q12_SHIFT Q12_PROD
    iVar2 = func_0x000ab4d0(&local_20);
    if (iVar2 < local_20._2_2_) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    iVar3 = iVar2 - local_20._2_2_;
    if (iVar3 < 0) {
      iVar3 = local_20._2_2_ - iVar2;
    }
  } while ((0x31 < iVar3) && (99 < uVar4));
  *(undefined4 *)(param_1 + 8) = local_20;
  *(undefined4 *)(param_1 + 0xc) = local_1c;    // POS.y
LAB_00044c9c:
  *(short *)(param_1 + 10) = (short)iVar2;
  if ((*(uint *)(param_1 + 0xd0) & 1) != 0) {
    *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 2;
  }
  uVar4 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x18);
  if (uVar4 == 0) {
    func_0x00084688(0xf,param_1 + 8,0);
    func_0x0010a4f8(param_1);
    uVar5 = *(uint *)(param_1 + 0xd0);
    uVar4 = uVar5 | 8;
    if ((uVar5 & 1) == 0) {
      uVar4 = uVar5 & 0xfffffff7;    // ANGLE_MASK
    }
    *(uint *)(param_1 + 0xd0) = uVar4;
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0) {    // ANG.yaw
      *(undefined2 *)(param_1 + 0xc0) = 0;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 3;
      uVar4 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
      if (uVar4 < 0x41) {
        uVar4 = 0x40;
      }
      if ((*(uint *)(param_1 + 0xd0) & 0x10) != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      *(short *)(param_1 + 0x9c) = (short)uVar4;
      *(uint *)(param_1 + 0x98) = uVar4 * uVar4;
    }
  }
  else {
    *(short *)(param_1 + 0x36) = (short)((int)-((int)*(short *)(param_1 + 0x36) * uVar4) >> 0xc);    // BD.y BD.y Q12_SHIFT Q12_PROD
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 1 & 1) != 0) {    // ANG.yaw
      uVar5 = *(uint *)((*(ushort *)(param_1 + 200) & 0x7f) * 4 + -0x7ffeb164);
      uVar4 = uVar5 >> 0x10;
      setCopControlWord(2,0,uVar4);
      uVar5 = uVar5 & 0xffff;    // ANGLE_MASK
      setCopControlWord(2,0x2000,uVar4);
      setCopControlWord(2,0x800,uVar5);
      setCopControlWord(2,0x1000,0x1000);
      setCopControlWord(2,0x1800,-uVar5 & 0xffff);    // ANGLE_MASK
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x34));    // BD.x
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x36));    // BD.y
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x38));    // BD.z
      copFunction(2,0x49e012);
      uVar6 = getCopReg(2,0x4800);
      uVar7 = getCopReg(2,0x5000);
      uVar8 = getCopReg(2,0x5800);
      *(short *)(param_1 + 0x34) = (short)uVar6;    // BD.x
      *(short *)(param_1 + 0x36) = (short)uVar7;    // BD.y
      *(short *)(param_1 + 0x38) = (short)uVar8;    // BD.z
    }
    func_0x00109ff4(param_1);
    if ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44)) {    // SPD
      uVar1 = (undefined2)
              ((int)*(short *)(param_1 + 0x34) * (int)*(short *)(param_1 + 0x3c) +    // BD.x BS.x
               (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +    // BD.y BS.y
               (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc);    // BD.z BS.z Q12_SHIFT Q12_PROD
      *(undefined2 *)(param_1 + 0xc4) = uVar1;
      *(undefined2 *)(param_1 + 0x44) = uVar1;    // SPD
    }
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffdff | 0x40;    // ANGLE_MASK
    func_0x00076790(param_1);
    uVar4 = (uint)(*(ushort *)(*(int *)(param_1 + 0xb8) + 8) >> 3);
    if (uVar4 < 3) {
      uVar4 = 3;
    }
    iVar2 = (int)*(short *)(param_1 + 0x36);    // BD.y
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    if (((iVar2 <= (int)uVar4) || ((int)*(short *)(param_1 + 0x44) <= (int)uVar4)) &&    // SPD
       (func_0x0010a4f8(param_1), (*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0)) {    // ANG.yaw
      *(undefined2 *)(param_1 + 0xc0) = 0;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 3;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  return;
}


---

## FUN_00044f80 (GAME.BIN) @ 0x044f80


/* WARNING: Control flow encountered bad instruction data */

void FUN_00044f80(int param_1)

{
  ushort uVar1;
  bool bVar2;
  short sVar3;
  undefined4 uVar4;
  uint uVar5;
  short sVar6;
  short sVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined4 local_50;
  undefined4 local_4c;
  undefined2 uStack_4a;
  short local_48;
  short local_46;
  short local_44;
  undefined1 auStack_40 [8];
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined1 auStack_28 [8];
  undefined4 local_20;
  undefined4 local_1c;
  
  iVar12 = *(int *)(param_1 + 0xd4);
  if (iVar12 != 0) {
    iVar9 = (int)(((uint)*(ushort *)(param_1 + 8) - (uint)*(ushort *)(iVar12 + 0x6c)) * 0x10000) >>
            0x10;
    iVar11 = (int)(((uint)*(ushort *)(param_1 + 10) - (uint)*(ushort *)(iVar12 + 0x6e)) * 0x10000)
             >> 0x10;
    iVar12 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)    // POS.y
             >> 0x10;
    uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
    if ((uint)(iVar9 * iVar9 + iVar11 * iVar11 + iVar12 * iVar12) <= uVar8 * uVar8) {
      uVar5 = 0x40;
      if (0x40 < uVar8) {
        uVar5 = uVar8;
      }
      *(short *)(param_1 + 0x9c) = (short)uVar5;
      *(uint *)(param_1 + 0x98) = uVar5 * uVar5;
      func_0x0010a4f8(param_1);
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  if (*(int *)(param_1 + 0xbc) < 1) {
    if ((*(uint *)(param_1 + 0x50) & 4) != 0) {
      return;
    }
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) | 4;
  }
  else {
    if (0 < *(short *)(param_1 + 0xc2)) {
      *(short *)(param_1 + 0xc2) = *(short *)(param_1 + 0xc2) + -1;
    }
    iVar12 = *(int *)(param_1 + 0xd4);
    if (iVar12 == 0) {
      if (*(short *)(param_1 + 0xc2) < 1) {
        uVar4 = func_0x0010834c(param_1);
        *(undefined4 *)(param_1 + 0xd4) = uVar4;
        *(undefined2 *)(param_1 + 0xc2) = *(undefined2 *)(*(int *)(param_1 + 0xb8) + 0x28);
        iVar12 = *(int *)(param_1 + 0xd4);
      }
      if (iVar12 == 0) {
        uVar8 = *(uint *)(*(int *)(param_1 + 0xb8) + 0x20);    // ANG.yaw
        if ((uVar8 >> 4 & 1) != 0) {
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);    // POS.z
          sVar3 = 0x80;
          if (0x80 < (int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1)) {    // SPD
            sVar3 = *(short *)(param_1 + 0x44) - uVar1;    // SPD
          }
          sVar6 = *(short *)(param_1 + 10);
          *(short *)(param_1 + 0x44) = sVar3;    // SPD
          iVar12 = func_0x000ab4d0(param_1 + 8);
          if ((((int)sVar6 < iVar12 + -0x100) && (*(short *)(param_1 + 0x3e) < 1)) &&    // BS.y
             (iVar12 = -(int)*(short *)(param_1 + 0x3e), (*(uint *)(param_1 + 0x50) & 4) == 0)) {    // BS.y
            if (iVar12 < 0x20) {
              iVar12 = 0x20;
            }
            *(short *)(param_1 + 0x3e) = (short)iVar12;    // BS.y
            func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),    // BS.x BS.z
                            param_1 + 0x3c);    // BS.x
          }
          iVar12 = (int)*(short *)(param_1 + 0x44);    // SPD
          *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);    // BD.x BS.x Q12_SHIFT Q12_PROD
          *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);    // BD.y BS.y Q12_SHIFT Q12_PROD
          *(short *)(param_1 + 0x38) = (short)(*(short *)(param_1 + 0x40) * iVar12 >> 0xc);    // BD.z BS.z Q12_SHIFT Q12_PROD
          halt_baddata();
        }
        if ((uVar8 >> 3 & 1) == 0) {
          func_0x00109e70(param_1);
          func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),    // BS.x BS.z
                          param_1 + 0x3c);    // BS.x
          halt_baddata();
        }
        return;
      }
    }
    iVar11 = (int)(((uint)*(ushort *)(param_1 + 8) - (uint)*(ushort *)(iVar12 + 0x6c)) * 0x10000) >>
             0x10;
    iVar10 = (int)(((uint)*(ushort *)(param_1 + 10) - (uint)*(ushort *)(iVar12 + 0x6e)) * 0x10000)
             >> 0x10;
    iVar9 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)    // POS.y
            >> 0x10;
    uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
    if (uVar8 * uVar8 < (uint)(iVar11 * iVar11 + iVar10 * iVar10 + iVar9 * iVar9)) {
      local_50 = CONCAT22(*(short *)(iVar12 + 0x6e) - *(ushort *)(param_1 + 10),
                          *(short *)(iVar12 + 0x6c) - *(ushort *)(param_1 + 8));
      local_2c = CONCAT22(uStack_4a,*(short *)(iVar12 + 0x70) - *(ushort *)(param_1 + 0xc));    // POS.y
      local_30 = local_50;
      func_0x00109758(param_1,local_50,local_2c,&local_48);
      local_30 = CONCAT22(local_46 - *(short *)(param_1 + 0x3e),    // BS.y
                          local_48 - *(short *)(param_1 + 0x3c));    // BS.x
      local_2c = CONCAT22(local_2c._2_2_,local_44 - *(short *)(param_1 + 0x40));    // BS.z
      local_20 = local_30;
      local_1c = local_2c;
      func_0x00109758(param_1,local_30,local_2c,auStack_28);
      iVar12 = func_0x0010a95c(param_1,param_1 + 0x3c,&local_48,auStack_40);    // BS.x
      iVar9 = (int)*(short *)(param_1 + 0x3c) * (int)local_48 +    // BS.x
              (int)*(short *)(param_1 + 0x3e) * (int)local_46 +    // BS.y
              (int)*(short *)(param_1 + 0x40) * (int)local_44 >> 0xc;    // BS.z Q12_SHIFT Q12_PROD
      func_0x0010a95c(param_1,auStack_40,param_1 + 0x3c,&local_38);    // BS.x
      local_20 = local_38;
      local_1c = local_34;
      func_0x00109758(param_1,local_38,local_34,&local_38);
      if (4000 < iVar9) {
        iVar11 = iVar12;
        if (iVar12 < 0) {
          iVar11 = -iVar12;
        }
        if (iVar11 < 1000) {
          if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {    // ANG.yaw
            return;
          }
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
      if ((iVar12 == 0) && (iVar9 < 0)) {
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) != 0) {    // ANG.yaw
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);    // POS.z
          sVar3 = *(short *)(param_1 + 0x44) - uVar1;    // SPD
          if ((int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1) < 1) {    // SPD
            sVar3 = 0;
          }
          *(short *)(param_1 + 0x44) = sVar3;    // SPD
        }
        func_0x0010a6ec(param_1);
      }
      else {
        uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x12);
        bVar2 = iVar9 < *(short *)((uVar8 & 0xfff) * 4 + -0x7ffeb162);    // ANGLE_MASK
        if (bVar2) {
          if (iVar12 < 0) {
            uVar8 = 0x1000 - uVar8 & 0xfff;    // ANGLE_MASK
          }
          iVar9 = (uVar8 & 0xfff) * 4;    // ANGLE_MASK
          iVar12 = (int)*(short *)(iVar9 + -0x7ffeb164);
          iVar9 = (int)*(short *)(iVar9 + -0x7ffeb162);
        }
        iVar11 = (int)*(short *)(param_1 + 0x44);    // SPD
        sVar7 = (short)(iVar9 * *(short *)(param_1 + 0x3c) + iVar12 * (short)local_38 >> 0xc);    // BS.x Q12_SHIFT Q12_PROD
        sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc);    // BS.y Q12_SHIFT Q12_PROD
        sVar6 = (short)(iVar9 * *(short *)(param_1 + 0x40) + iVar12 * (short)local_34 >> 0xc);    // BS.z Q12_SHIFT Q12_PROD
        *(short *)(param_1 + 0x3c) = sVar7;    // BS.x
        *(short *)(param_1 + 0x3e) = sVar3;    // BS.y
        *(short *)(param_1 + 0x40) = sVar6;    // BS.z
        *(short *)(param_1 + 0x34) = (short)(sVar7 * iVar11 >> 0xc);    // BD.x Q12_SHIFT Q12_PROD
        *(short *)(param_1 + 0x36) = (short)(sVar3 * iVar11 >> 0xc);    // BD.y Q12_SHIFT Q12_PROD
        *(short *)(param_1 + 0x38) = (short)(sVar6 * iVar11 >> 0xc);    // BD.z Q12_SHIFT Q12_PROD
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {    // ANG.yaw
          func_0x00109e70(param_1);
          return;
        }
        if (bVar2) {
          func_0x00109f60(param_1);
        }
        else {
          func_0x00109e70(param_1);
        }
      }
    }
    else {
      uVar5 = 0x40;
      if (0x40 < uVar8) {
        uVar5 = uVar8;
      }
      *(short *)(param_1 + 0x9c) = (short)uVar5;
      *(uint *)(param_1 + 0x98) = uVar5 * uVar5;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // ANGLE_MASK
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_0001e750 (MAIN.EXE) @ 0x01e750


undefined4 FUN_0001e750(short *param_1,int *param_2)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  short sVar6;
  short sVar7;
  short sVar8;
  undefined4 *puVar9;
  int iVar10;
  int unaff_gp;
  short sVar11;
  short local_44;
  short local_40;
  short local_3c;
  short local_38;
  short sStack_34;
  short sStack_30;
  undefined2 uStack_2e;
  undefined2 uStack_2c;
  short sStack_28;
  short sStack_26;
  undefined4 auStack_20 [8];
  
  local_44 = param_1[8];
  local_40 = param_1[9];
  sVar6 = param_1[10];
  local_3c = param_1[0xc];
  sVar5 = param_1[0xb];
  local_38 = param_1[0x10];
  sVar7 = param_1[0xd];
  sStack_34 = param_1[0x12];
  sVar4 = param_1[0xe];
  sVar3 = param_1[0xf];
  sVar11 = param_1[0x11];
  sVar8 = param_1[0x13];
  puVar9 = (undefined4 *)&DAT_8003bf2c;
  puVar2 = auStack_20;
  iVar10 = 8;
  do {
    iVar10 = iVar10 + -1;
    *puVar2 = *puVar9;
    puVar9 = puVar9 + 1;
    puVar2 = puVar2 + 1;
  } while (0 < iVar10);
  if (param_1[4] != 0) {
    FUN_0001f340((int)param_1[4],auStack_20);
    sStack_30 = local_44 - param_1[5];
    uStack_2e = (undefined2)((((int)local_40 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    local_44 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    local_40 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    sStack_30 = sVar6 - param_1[5];
    uStack_2e = (undefined2)((((int)sVar5 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar6 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar5 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    sStack_30 = local_3c - param_1[5];
    uStack_2e = (undefined2)((((int)sVar7 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    local_3c = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sStack_30 = sVar4 - param_1[5];
    sVar7 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    uStack_2e = (undefined2)((((int)sVar3 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar4 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar3 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    if (0x100 < param_1[1]) {
      sStack_30 = local_38 - param_1[5];
      uStack_2e = (undefined2)((((int)sVar11 - (int)param_1[6]) * 0x1000) / 0x780);
      uStack_2c = 0;
      FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
      local_38 = sStack_28 + param_1[5];
      iVar10 = sStack_26 * 0x780;
      if (iVar10 < 0) {
        iVar10 = iVar10 + 0xfff;
      }
      sVar11 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
      sStack_30 = sStack_34 - param_1[5];
      uStack_2e = (undefined2)((((int)sVar8 - (int)param_1[6]) * 0x1000) / 0x780);
      uStack_2c = 0;
      FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
      sStack_34 = sStack_28 + param_1[5];
      iVar10 = sStack_26 * 0x780;
      if (iVar10 < 0) {
        iVar10 = iVar10 + 0xfff;
      }
      sVar8 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    }
  }
  iVar10 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
  if (iVar10 == 0) {
    uVar1 = 0;
  }
  else {
    *(undefined1 *)(iVar10 + 3) = 9;
    *(undefined1 *)(iVar10 + 7) = 0x2c;
    *(short *)(iVar10 + 8) = local_44;
    *(short *)(iVar10 + 10) = local_40;
    *(short *)(iVar10 + 0x10) = sVar6;    // POS.z
    *(short *)(iVar10 + 0x12) = sVar5;
    *(short *)(iVar10 + 0x18) = local_3c;
    *(short *)(iVar10 + 0x1a) = sVar7;
    *(short *)(iVar10 + 0x20) = sVar4;    // ANG.yaw
    *(short *)(iVar10 + 0x22) = sVar3;    // ANG.pitch
    *(char *)(iVar10 + 0xc) = (char)param_1[0x14];    // POS.y
    *(char *)(iVar10 + 0xd) = (char)param_1[0x17];
    *(undefined1 *)(iVar10 + 0x14) = *(undefined1 *)((int)param_1 + 0x29);
    *(undefined1 *)(iVar10 + 0x15) = *(undefined1 *)((int)param_1 + 0x2f);
    *(char *)(iVar10 + 0x1c) = (char)param_1[0x15];
    *(char *)(iVar10 + 0x1d) = (char)param_1[0x18];
    *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2b);    // ANG.roll
    *(undefined1 *)(iVar10 + 0x25) = *(undefined1 *)((int)param_1 + 0x31);
    *(char *)(iVar10 + 4) = (char)param_1[0x1a];
    *(undefined1 *)(iVar10 + 5) = *(undefined1 *)((int)param_1 + 0x35);
    *(char *)(iVar10 + 6) = (char)param_1[0x1b];
    *(short *)(iVar10 + 0xe) = param_1[0x1e];
    *(short *)(iVar10 + 0x16) = param_1[0x1c];
    FUN_0001c89c(iVar10,(int)param_1[3]);
    FUN_0001c85c(*param_2 + *param_1 * 4,iVar10);
    FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    if (0x100 < param_1[1]) {
      iVar10 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
      if (iVar10 == 0) {
        return 0;
      }
      *(undefined1 *)(iVar10 + 3) = 9;
      *(undefined1 *)(iVar10 + 7) = 0x2c;
      *(short *)(iVar10 + 8) = sVar6;
      *(short *)(iVar10 + 10) = sVar5;
      *(short *)(iVar10 + 0x10) = local_38;    // POS.z
      *(short *)(iVar10 + 0x12) = sVar11;
      *(short *)(iVar10 + 0x18) = sVar4;
      *(short *)(iVar10 + 0x1a) = sVar3;
      *(short *)(iVar10 + 0x20) = sStack_34;    // ANG.yaw
      *(short *)(iVar10 + 0x22) = sVar8;    // ANG.pitch
      *(undefined1 *)(iVar10 + 0xc) = 0;    // POS.y
      *(undefined1 *)(iVar10 + 0xd) = *(undefined1 *)((int)param_1 + 0x2f);
      *(char *)(iVar10 + 0x14) = (char)param_1[0x16];
      *(char *)(iVar10 + 0x15) = (char)param_1[0x19];
      *(undefined1 *)(iVar10 + 0x1c) = 0;
      *(undefined1 *)(iVar10 + 0x1d) = *(undefined1 *)((int)param_1 + 0x31);
      *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2d);    // ANG.roll
      *(undefined1 *)(iVar10 + 0x25) = *(undefined1 *)((int)param_1 + 0x33);
      *(char *)(iVar10 + 4) = (char)param_1[0x1a];
      *(undefined1 *)(iVar10 + 5) = *(undefined1 *)((int)param_1 + 0x35);
      *(char *)(iVar10 + 6) = (char)param_1[0x1b];
      *(short *)(iVar10 + 0xe) = param_1[0x1e];
      *(short *)(iVar10 + 0x16) = param_1[0x1d];
      FUN_0001c89c(iVar10,(int)param_1[3]);
      FUN_0001c85c(*param_2 + *param_1 * 4,iVar10);
      FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    }
    uVar1 = 1;
  }
  return uVar1;
}


---

## FUN_0001e7b4 (MAIN.EXE) @ 0x01e7b4


undefined4 FUN_0001e7b4(undefined4 param_1,int *param_2)

{
  int in_v0;
  undefined4 uVar1;
  undefined4 *puVar2;
  short *unaff_s0;
  short sVar3;
  short sVar4;
  int unaff_s4;
  short unaff_s5;
  int unaff_s6;
  short sVar5;
  int in_t8;
  undefined4 *puVar6;
  int iVar7;
  int unaff_gp;
  short sVar8;
  short in_stack_0000003c;
  int in_stack_00000040;
  short in_stack_00000044;
  short in_stack_00000048;
  int iStack0000004c;
  short sStack00000050;
  undefined2 uStack00000052;
  undefined2 in_stack_00000054;
  short sStack00000058;
  short sStack0000005a;
  int *piStack00000084;
  
  sVar4 = unaff_s0[0xe];
  sVar3 = unaff_s0[0xf];
  sVar8 = unaff_s0[0x11];
  sVar5 = unaff_s0[0x13];
  puVar6 = (undefined4 *)(in_t8 + -0x40d4);
  puVar2 = (undefined4 *)&stack0x00000060;
  iVar7 = 8;
  piStack00000084 = param_2;
  do {
    iVar7 = iVar7 + -1;
    *puVar2 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar2 = puVar2 + 1;
  } while (0 < iVar7);
  iStack0000004c = in_v0;
  if (unaff_s0[4] != 0) {
    FUN_0001f340((int)unaff_s0[4],&stack0x00000060);
    sStack00000050 = in_stack_0000003c - unaff_s0[5];
    uStack00000052 = (undefined2)(((in_stack_00000040 - unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_0000003c = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    in_stack_00000040 = ((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    sStack00000050 = unaff_s5 - unaff_s0[5];
    uStack00000052 = (undefined2)(((unaff_s4 - unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    unaff_s5 = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    unaff_s4 = ((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    sStack00000050 = in_stack_00000044 - unaff_s0[5];
    uStack00000052 = (undefined2)(((unaff_s6 - unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_00000044 = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    sStack00000050 = sVar4 - unaff_s0[5];
    unaff_s6 = ((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    uStack00000052 = (undefined2)((((int)sVar3 - (int)unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    sVar4 = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    sVar3 = (short)((uint)(((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    if (0x100 < unaff_s0[1]) {
      sStack00000050 = in_stack_00000048 - unaff_s0[5];
      uStack00000052 = (undefined2)((((int)sVar8 - (int)unaff_s0[6]) * 0x1000) / 0x780);
      in_stack_00000054 = 0;
      FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
      in_stack_00000048 = sStack00000058 + unaff_s0[5];
      iVar7 = sStack0000005a * 0x780;
      if (iVar7 < 0) {
        iVar7 = iVar7 + 0xfff;
      }
      sVar8 = (short)((uint)(((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
      sStack00000050 = (short)iStack0000004c - unaff_s0[5];
      uStack00000052 = (undefined2)((((int)sVar5 - (int)unaff_s0[6]) * 0x1000) / 0x780);
      in_stack_00000054 = 0;
      FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
      iStack0000004c = ((int)sStack00000058 + (int)unaff_s0[5]) * 0x10000 >> 0x10;
      iVar7 = sStack0000005a * 0x780;
      if (iVar7 < 0) {
        iVar7 = iVar7 + 0xfff;
      }
      sVar5 = (short)((uint)(((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    }
  }
  iVar7 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
  if (iVar7 == 0) {
    uVar1 = 0;
  }
  else {
    *(undefined1 *)(iVar7 + 3) = 9;
    *(undefined1 *)(iVar7 + 7) = 0x2c;
    *(short *)(iVar7 + 8) = in_stack_0000003c;
    *(short *)(iVar7 + 10) = (short)in_stack_00000040;
    *(short *)(iVar7 + 0x10) = unaff_s5;    // POS.z
    *(short *)(iVar7 + 0x12) = (short)unaff_s4;
    *(short *)(iVar7 + 0x18) = in_stack_00000044;
    *(short *)(iVar7 + 0x1a) = (short)unaff_s6;
    *(short *)(iVar7 + 0x20) = sVar4;    // ANG.yaw
    *(short *)(iVar7 + 0x22) = sVar3;    // ANG.pitch
    *(char *)(iVar7 + 0xc) = (char)unaff_s0[0x14];    // POS.y
    *(char *)(iVar7 + 0xd) = (char)unaff_s0[0x17];
    *(undefined1 *)(iVar7 + 0x14) = *(undefined1 *)((int)unaff_s0 + 0x29);
    *(undefined1 *)(iVar7 + 0x15) = *(undefined1 *)((int)unaff_s0 + 0x2f);
    *(char *)(iVar7 + 0x1c) = (char)unaff_s0[0x15];
    *(char *)(iVar7 + 0x1d) = (char)unaff_s0[0x18];
    *(undefined1 *)(iVar7 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2b);    // ANG.roll
    *(undefined1 *)(iVar7 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x31);
    *(char *)(iVar7 + 4) = (char)unaff_s0[0x1a];
    *(undefined1 *)(iVar7 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
    *(char *)(iVar7 + 6) = (char)unaff_s0[0x1b];
    *(short *)(iVar7 + 0xe) = unaff_s0[0x1e];
    *(short *)(iVar7 + 0x16) = unaff_s0[0x1c];
    FUN_0001c89c(iVar7,(int)unaff_s0[3]);
    FUN_0001c85c(*piStack00000084 + *unaff_s0 * 4,iVar7);
    FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    if (0x100 < unaff_s0[1]) {
      iVar7 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
      if (iVar7 == 0) {
        return 0;
      }
      *(undefined1 *)(iVar7 + 3) = 9;
      *(undefined1 *)(iVar7 + 7) = 0x2c;
      *(short *)(iVar7 + 8) = unaff_s5;
      *(short *)(iVar7 + 10) = (short)unaff_s4;
      *(short *)(iVar7 + 0x10) = in_stack_00000048;    // POS.z
      *(short *)(iVar7 + 0x12) = sVar8;
      *(short *)(iVar7 + 0x18) = sVar4;
      *(short *)(iVar7 + 0x1a) = sVar3;
      *(short *)(iVar7 + 0x20) = (short)iStack0000004c;    // ANG.yaw
      *(short *)(iVar7 + 0x22) = sVar5;    // ANG.pitch
      *(undefined1 *)(iVar7 + 0xc) = 0;    // POS.y
      *(undefined1 *)(iVar7 + 0xd) = *(undefined1 *)((int)unaff_s0 + 0x2f);
      *(char *)(iVar7 + 0x14) = (char)unaff_s0[0x16];
      *(char *)(iVar7 + 0x15) = (char)unaff_s0[0x19];
      *(undefined1 *)(iVar7 + 0x1c) = 0;
      *(undefined1 *)(iVar7 + 0x1d) = *(undefined1 *)((int)unaff_s0 + 0x31);
      *(undefined1 *)(iVar7 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2d);    // ANG.roll
      *(undefined1 *)(iVar7 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x33);
      *(char *)(iVar7 + 4) = (char)unaff_s0[0x1a];
      *(undefined1 *)(iVar7 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
      *(char *)(iVar7 + 6) = (char)unaff_s0[0x1b];
      *(short *)(iVar7 + 0xe) = unaff_s0[0x1e];
      *(short *)(iVar7 + 0x16) = unaff_s0[0x1d];
      FUN_0001c89c(iVar7,(int)unaff_s0[3]);
      FUN_0001c85c(*piStack00000084 + *unaff_s0 * 4,iVar7);
      FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    }
    uVar1 = 1;
  }
  return uVar1;
}


---

## FUN_0001ea04 (MAIN.EXE) @ 0x01ea04


undefined4 FUN_0001ea04(void)

{
  short sVar1;
  short in_v0;
  undefined4 uVar2;
  undefined2 in_v1;
  short *unaff_s0;
  int unaff_s1;
  undefined2 uVar3;
  undefined2 unaff_s4;
  undefined2 unaff_s5;
  undefined2 unaff_s6;
  int unaff_s7;
  int unaff_gp;
  int unaff_s8;
  int iVar4;
  int iVar5;
  undefined2 in_stack_0000003c;
  undefined2 in_stack_00000040;
  undefined2 in_stack_00000044;
  short in_stack_00000048;
  short in_stack_0000004c;
  short sStack00000050;
  undefined2 uStack00000052;
  undefined2 in_stack_00000054;
  short sStack00000058;
  short sStack0000005a;
  int *in_stack_00000084;
  
  iVar4 = sStack0000005a * unaff_s1;
  if (iVar4 < 0) {
    iVar4 = iVar4 + 0xfff;
  }
  sVar1 = unaff_s0[6];
  if (0x100 < unaff_s0[1]) {
    sStack00000050 = in_stack_00000048 - in_v0;
    uStack00000052 = (undefined2)(((unaff_s8 - unaff_s0[6]) * 0x1000) / unaff_s1);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_00000048 = sStack00000058 + unaff_s0[5];
    iVar5 = sStack0000005a * unaff_s1;
    if (iVar5 < 0) {
      iVar5 = iVar5 + 0xfff;
    }
    unaff_s8 = ((int)unaff_s0[6] + (iVar5 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    sStack00000050 = in_stack_0000004c - unaff_s0[5];
    uStack00000052 = (undefined2)(((unaff_s7 - unaff_s0[6]) * 0x1000) / unaff_s1);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_0000004c = sStack00000058 + unaff_s0[5];
    iVar5 = sStack0000005a * unaff_s1;
    if (iVar5 < 0) {
      iVar5 = iVar5 + 0xfff;
    }
    unaff_s7 = ((int)unaff_s0[6] + (iVar5 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
  }
  iVar5 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
  if (iVar5 == 0) {
    uVar2 = 0;
  }
  else {
    *(undefined1 *)(iVar5 + 3) = 9;
    *(undefined1 *)(iVar5 + 7) = 0x2c;
    *(undefined2 *)(iVar5 + 8) = in_stack_0000003c;
    *(undefined2 *)(iVar5 + 10) = in_stack_00000040;
    *(undefined2 *)(iVar5 + 0x10) = unaff_s5;    // POS.z
    *(undefined2 *)(iVar5 + 0x12) = unaff_s4;
    *(undefined2 *)(iVar5 + 0x18) = in_stack_00000044;
    *(undefined2 *)(iVar5 + 0x1a) = unaff_s6;
    *(undefined2 *)(iVar5 + 0x20) = in_v1;    // ANG.yaw
    uVar3 = (undefined2)((uint)(((int)sVar1 + (iVar4 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    *(undefined2 *)(iVar5 + 0x22) = uVar3;    // ANG.pitch
    *(char *)(iVar5 + 0xc) = (char)unaff_s0[0x14];    // POS.y
    *(char *)(iVar5 + 0xd) = (char)unaff_s0[0x17];
    *(undefined1 *)(iVar5 + 0x14) = *(undefined1 *)((int)unaff_s0 + 0x29);
    *(undefined1 *)(iVar5 + 0x15) = *(undefined1 *)((int)unaff_s0 + 0x2f);
    *(char *)(iVar5 + 0x1c) = (char)unaff_s0[0x15];
    *(char *)(iVar5 + 0x1d) = (char)unaff_s0[0x18];
    *(undefined1 *)(iVar5 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2b);    // ANG.roll
    *(undefined1 *)(iVar5 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x31);
    *(char *)(iVar5 + 4) = (char)unaff_s0[0x1a];
    *(undefined1 *)(iVar5 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
    *(char *)(iVar5 + 6) = (char)unaff_s0[0x1b];
    *(short *)(iVar5 + 0xe) = unaff_s0[0x1e];
    *(short *)(iVar5 + 0x16) = unaff_s0[0x1c];
    FUN_0001c89c(iVar5,(int)unaff_s0[3]);
    FUN_0001c85c(*in_stack_00000084 + *unaff_s0 * 4,iVar5);
    FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    if (0x100 < unaff_s0[1]) {
      iVar4 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
      if (iVar4 == 0) {
        return 0;
      }
      *(undefined1 *)(iVar4 + 3) = 9;
      *(undefined1 *)(iVar4 + 7) = 0x2c;
      *(undefined2 *)(iVar4 + 8) = unaff_s5;
      *(undefined2 *)(iVar4 + 10) = unaff_s4;
      *(short *)(iVar4 + 0x10) = in_stack_00000048;    // POS.z
      *(short *)(iVar4 + 0x12) = (short)unaff_s8;
      *(undefined2 *)(iVar4 + 0x18) = in_v1;
      *(undefined2 *)(iVar4 + 0x1a) = uVar3;
      *(short *)(iVar4 + 0x20) = in_stack_0000004c;    // ANG.yaw
      *(short *)(iVar4 + 0x22) = (short)unaff_s7;    // ANG.pitch
      *(undefined1 *)(iVar4 + 0xc) = 0;    // POS.y
      *(undefined1 *)(iVar4 + 0xd) = *(undefined1 *)((int)unaff_s0 + 0x2f);
      *(char *)(iVar4 + 0x14) = (char)unaff_s0[0x16];
      *(char *)(iVar4 + 0x15) = (char)unaff_s0[0x19];
      *(undefined1 *)(iVar4 + 0x1c) = 0;
      *(undefined1 *)(iVar4 + 0x1d) = *(undefined1 *)((int)unaff_s0 + 0x31);
      *(undefined1 *)(iVar4 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2d);    // ANG.roll
      *(undefined1 *)(iVar4 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x33);
      *(char *)(iVar4 + 4) = (char)unaff_s0[0x1a];
      *(undefined1 *)(iVar4 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
      *(char *)(iVar4 + 6) = (char)unaff_s0[0x1b];
      *(short *)(iVar4 + 0xe) = unaff_s0[0x1e];
      *(short *)(iVar4 + 0x16) = unaff_s0[0x1d];
      FUN_0001c89c(iVar4,(int)unaff_s0[3]);
      FUN_0001c85c(*in_stack_00000084 + *unaff_s0 * 4,iVar4);
      FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    }
    uVar2 = 1;
  }
  return uVar2;
}


---

## FUN_00022dc8 (GAME.BIN) @ 0x022dc8


/* WARNING: Control flow encountered bad instruction data */

void FUN_00022dc8(int param_1)

{
  short sVar1;
  undefined2 uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  short sVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined4 in_t3;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 uStack_58;
  uint local_54;
  undefined4 uStack_50;
  uint uStack_4c;
  short sStack_48;
  short sStack_46;
  short sStack_44;
  int iStack_40;
  int iStack_3c;
  int iStack_38;
  int iStack_30;
  int iStack_2c;
  uint auStack_28 [2];
  
  uVar3 = func_0x000f55e4(*(undefined4 *)(param_1 + 0xec),param_1);
  FUN_00023000(&uStack_58,0,8);
  iVar4 = *(int *)(param_1 + 0xec);
  setCopControlWord(2,0,*(undefined4 *)(iVar4 + 0x18));
  setCopControlWord(2,0x800,*(undefined4 *)(iVar4 + 0x1c));
  setCopControlWord(2,0x1000,*(undefined4 *)(iVar4 + 0x20));    // ANG.yaw
  setCopControlWord(2,0x1800,*(undefined4 *)(iVar4 + 0x24));    // ANG.roll
  setCopControlWord(2,0x2000,*(undefined4 *)(iVar4 + 0x28));
  iVar9 = (int)*(short *)(iVar4 + 0x152);
  iVar10 = (int)*(short *)(iVar4 + 0x154);
  setCopControlWord(2,0x2800,(int)*(short *)(iVar4 + 0x150));
  setCopControlWord(2,0x3000,iVar9);
  setCopControlWord(2,0x3800,iVar10);
  setCopReg(2,0x4800,uStack_58 & 0xffff);    // ANGLE_MASK
  setCopReg(2,0x5000,uStack_58 >> 0x10);
  setCopReg(2,0x5800,(uint)(ushort)((short)(-(int)*(short *)(*(int *)(iVar4 + 0x1a8) + 0x90) / 2) -
                                   0x80));
  copFunction(2,0x498012);
  uVar11 = getCopReg(2,0x4800);
  uVar12 = getCopReg(2,0x5000);
  uVar13 = getCopReg(2,0x5800);
  uStack_58 = CONCAT22((short)uVar12,(short)uVar11);
  local_54 = CONCAT22(local_54._2_2_,(short)uVar13);
  if (uVar3 != 0) {
    iVar4 = *(int *)(*(int *)(param_1 + 0xec) + (uVar3 - 1) * 4 + 0x184);
    uVar5 = *(uint *)(iVar4 + 8);
    uStack_4c = *(uint *)(iVar4 + 0xc);    // POS.y
    uStack_50._2_2_ = (short)(uVar5 >> 0x10);
    iVar6 = (uint)*(ushort *)(param_1 + 0xc) - (uStack_4c & 0xffff);    // POS.y ANGLE_MASK
    iVar4 = (uint)*(ushort *)(param_1 + 8) - (uVar5 & 0xffff);    // ANGLE_MASK
    sStack_48 = (short)iVar4;
    sStack_44 = (short)iVar6;
    sStack_46 = *(short *)(param_1 + 10) - uStack_50._2_2_;
    uStack_50 = uVar5;
    sVar1 = FUN_00022e5c(iVar6 * 0x10000 >> 0x10,iVar4 * 0x10000 >> 0x10);
    iStack_40 = (int)sStack_48;
    iStack_3c = (int)sStack_46;
    iStack_38 = (int)sStack_44;
    *(short *)(param_1 + 0x12) = -sVar1;
    setCopReg(2,iVar9,iStack_40);
    setCopReg(2,iVar10,iStack_3c);
    setCopReg(2,in_t3,iStack_38);
    copFunction(2,0xa00428);
    iVar9 = getCopReg(2,0xc800);
    iVar4 = getCopReg(2,0xd000);
    iStack_30 = getCopReg(2,0xd800);
    iStack_30 = iVar9 + iVar4 + iStack_30;
    FUN_00022bac(iStack_30,&iStack_2c,auStack_28);
    iStack_40 = iStack_40 * iStack_2c >> (auStack_28[0] & 0x1f);
    iStack_3c = iStack_3c * iStack_2c >> (auStack_28[0] & 0x1f);
    iStack_38 = iStack_38 * iStack_2c >> (auStack_28[0] & 0x1f);
    iVar4 = FUN_00023180((int)sStack_48 * (int)sStack_48 + (int)sStack_46 * (int)sStack_46 +
                         (int)sStack_44 * (int)sStack_44);
    iVar4 = (iVar4 + -300) * 0x10000 >> 0x10;
    sVar1 = (short)(((int)(((uint)*(ushort *)(param_1 + 0x34) - (iVar4 * iStack_40 >> 0xf)) *    // BD.x
                          0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(param_1 + 0x34) = sVar1;    // BD.x
    sVar7 = (short)(((int)(((uint)*(ushort *)(param_1 + 0x36) - (iVar4 * iStack_3c >> 0xf)) *    // BD.y
                          0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(param_1 + 0x36) = sVar7;    // BD.y
    *(short *)(param_1 + 8) = *(short *)(param_1 + 8) + sVar1;
    sVar1 = (short)(((int)(((uint)*(ushort *)(param_1 + 0x38) - (iVar4 * iStack_38 >> 0xf)) *    // BD.z
                          0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(param_1 + 0x38) = sVar1;    // BD.z
    *(short *)(param_1 + 10) = *(short *)(param_1 + 10) + sVar7;
    *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + sVar1;    // POS.y POS.y
    iVar4 = func_0x000ab4d0(param_1 + 8);
    if (iVar4 < *(short *)(param_1 + 10)) {
      *(short *)(param_1 + 10) = (short)iVar4;
    }
    *(undefined4 *)(param_1 + 0x78) = 1;
    iVar9 = (uint)*(ushort *)(param_1 + 8) - (uStack_58 & 0xffff);    // ANGLE_MASK
    sStack_48 = (short)iVar9;
    sStack_46 = *(short *)(param_1 + 10) - uStack_58._2_2_;
    iVar10 = (uint)*(ushort *)(param_1 + 0xc) - (local_54 & 0xffff);    // POS.y ANGLE_MASK
    sStack_44 = (short)iVar10;
    iVar4 = (*(ushort *)(*(int *)(param_1 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
    iVar8 = (int)*(short *)(iVar4 + -0x7ffeb164);
    iVar6 = (int)*(short *)(iVar4 + -0x7ffeb162);
    iVar4 = -(iVar9 * 0x10000 >> 0x10) * iVar8 - (iVar10 * 0x10000 >> 0x10) * iVar6 >> 0xc;    // Q12_SHIFT Q12_PROD
    if (iVar4 < 0) {
      iVar4 = iVar4 + -10;
      *(short *)(param_1 + 0x34) = (short)(-iVar8 >> 7);    // BD.x
      *(short *)(param_1 + 0x38) = (short)(-iVar6 >> 7);    // BD.z
      *(ushort *)(param_1 + 8) = *(ushort *)(param_1 + 8) - (short)(-(iVar4 * iVar8) >> 0xc);    // Q12_SHIFT Q12_PROD
      *(ushort *)(param_1 + 0xc) = *(ushort *)(param_1 + 0xc) - (short)(-(iVar4 * iVar6) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
    }
    iVar4 = *(int *)(param_1 + 0xec);
    uVar5 = 0;
    if (*(short *)(iVar4 + 0x182) != 0) {
      do {
        iVar9 = uVar5 * 4;
        if (uVar5 != uVar3) {
          *(undefined4 *)(*(int *)(iVar4 + iVar9 + 0x184) + 0x78) = 1;
          func_0x000e8cfc(param_1,*(undefined4 *)(*(int *)(param_1 + 0xec) + iVar9 + 0x184));
          *(undefined4 *)(*(int *)(*(int *)(param_1 + 0xec) + iVar9 + 0x184) + 0x78) = 4;
        }
        iVar4 = *(int *)(param_1 + 0xec);
        uVar5 = uVar5 + 1;
      } while (uVar5 < *(ushort *)(iVar4 + 0x182));
    }
    *(undefined4 *)(param_1 + 0x78) = 4;
    uVar2 = 0xc100;
    if ((*(short *)(param_1 + 8) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(param_1 + 8))) {
      *(undefined2 *)(param_1 + 8) = uVar2;
    }
    uVar2 = 0xc100;
    if ((*(short *)(param_1 + 0xc) < -0x3f00) ||    // POS.y
       (uVar2 = 0x3f00, 0x3f00 < *(short *)(param_1 + 0xc))) {    // POS.y
      *(undefined2 *)(param_1 + 0xc) = uVar2;    // POS.y
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00022e5c (GAME.BIN) @ 0x022e5c


/* WARNING: Control flow encountered bad instruction data */

void FUN_00022e5c(int param_1)

{
  uint uVar1;
  uint uVar2;
  short sVar3;
  undefined2 uVar4;
  int in_v1;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  short sVar9;
  int iVar10;
  int iVar11;
  undefined4 in_t3;
  undefined4 in_t4;
  undefined4 uVar12;
  undefined4 uVar13;
  uint uVar14;
  ushort *unaff_s0;
  int unaff_s2;
  uint unaff_s5;
  int iVar15;
  uint uStack00000010;
  uint uStack00000018;
  uint uStack0000001c;
  short sStack00000020;
  short sStack00000022;
  short sStack00000024;
  int in_stack_0000003c;
  uint in_stack_00000040;
  
  setCopControlWord(2,0x1000,in_t4);
  setCopControlWord(2,0x1800,*(undefined4 *)(in_v1 + 0xc));    // POS.y
  setCopControlWord(2,0x2000,*(undefined4 *)(in_v1 + 0x10));    // POS.z
  iVar10 = (int)*(short *)(param_1 + 0x152);
  iVar11 = (int)*(short *)(param_1 + 0x154);
  setCopControlWord(2,0x2800,(int)*(short *)(param_1 + 0x150));
  setCopControlWord(2,0x3000,iVar10);
  setCopControlWord(2,0x3800,iVar11);
  setCopReg(2,0x4800,(uint)*unaff_s0);
  setCopReg(2,0x5000,(uint)unaff_s0[1]);
  setCopReg(2,0x5800,(uint)unaff_s0[2]);
  copFunction(2,0x498012);
  uVar12 = getCopReg(2,0x4800);
  uVar13 = getCopReg(2,0x5000);
  uVar14 = getCopReg(2,0x5800);
  uStack00000010 = CONCAT22((short)uVar13,(short)uVar12);
  if (unaff_s5 != 0) {
    iVar5 = *(int *)(*(int *)(unaff_s2 + 0xec) + (unaff_s5 - 1) * 4 + 0x184);
    uVar7 = *(uint *)(iVar5 + 8);
    uStack0000001c = *(uint *)(iVar5 + 0xc);    // POS.y
    uStack00000018._2_2_ = (short)(uVar7 >> 0x10);
    iVar8 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uStack0000001c & 0xffff);    // POS.y ANGLE_MASK
    iVar5 = (uint)*(ushort *)(unaff_s2 + 8) - (uVar7 & 0xffff);    // ANGLE_MASK
    sStack00000020 = (short)iVar5;
    sStack00000024 = (short)iVar8;
    sStack00000022 = *(short *)(unaff_s2 + 10) - uStack00000018._2_2_;
    uStack00000018 = uVar7;
    sVar3 = FUN_00022e5c(iVar8 * 0x10000 >> 0x10,iVar5 * 0x10000 >> 0x10);
    iVar5 = (int)sStack00000020;
    iVar8 = (int)sStack00000022;
    iVar6 = (int)sStack00000024;
    *(short *)(unaff_s2 + 0x12) = -sVar3;
    setCopReg(2,iVar10,iVar5);
    setCopReg(2,iVar11,iVar8);
    setCopReg(2,in_t3,iVar6);
    copFunction(2,0xa00428);
    iVar15 = getCopReg(2,0xc800);
    iVar10 = getCopReg(2,0xd000);
    iVar11 = getCopReg(2,0xd800);
    FUN_00022bac(iVar15 + iVar10 + iVar11,&stack0x0000003c,&stack0x00000040);
    iVar5 = iVar5 * in_stack_0000003c;
    iVar8 = iVar8 * in_stack_0000003c;
    iVar6 = iVar6 * in_stack_0000003c;
    uVar7 = in_stack_00000040 & 0x1f;
    uVar1 = in_stack_00000040 & 0x1f;
    uVar2 = in_stack_00000040 & 0x1f;
    iVar10 = FUN_00023180((int)sStack00000020 * (int)sStack00000020 +
                          (int)sStack00000022 * (int)sStack00000022 +
                          (int)sStack00000024 * (int)sStack00000024);
    iVar10 = (iVar10 + -300) * 0x10000 >> 0x10;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar10 * (iVar5 >> uVar7) >> 0xf))    // BD.x
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x34) = sVar3;    // BD.x
    sVar9 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar10 * (iVar8 >> uVar1) >> 0xf))    // BD.y
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x36) = sVar9;    // BD.y
    *(short *)(unaff_s2 + 8) = *(short *)(unaff_s2 + 8) + sVar3;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x38) - (iVar10 * (iVar6 >> uVar2) >> 0xf))    // BD.z
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x38) = sVar3;    // BD.z
    *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + sVar9;
    *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar3;    // POS.y POS.y
    iVar10 = func_0x000ab4d0(unaff_s2 + 8);
    if (iVar10 < *(short *)(unaff_s2 + 10)) {
      *(short *)(unaff_s2 + 10) = (short)iVar10;
    }
    *(undefined4 *)(unaff_s2 + 0x78) = 1;
    iVar11 = (uint)*(ushort *)(unaff_s2 + 8) - (uStack00000010 & 0xffff);    // ANGLE_MASK
    sStack00000020 = (short)iVar11;
    sStack00000022 = *(short *)(unaff_s2 + 10) - uStack00000010._2_2_;
    iVar5 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uVar14 & 0xffff);    // POS.y ANGLE_MASK
    sStack00000024 = (short)iVar5;
    iVar10 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
    iVar6 = (int)*(short *)(iVar10 + -0x7ffeb164);
    iVar8 = (int)*(short *)(iVar10 + -0x7ffeb162);
    iVar10 = -(iVar11 * 0x10000 >> 0x10) * iVar6 - (iVar5 * 0x10000 >> 0x10) * iVar8 >> 0xc;    // Q12_SHIFT Q12_PROD
    if (iVar10 < 0) {
      iVar10 = iVar10 + -10;
      *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);    // BD.x
      *(short *)(unaff_s2 + 0x38) = (short)(-iVar8 >> 7);    // BD.z
      *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar10 * iVar6) >> 0xc);    // Q12_SHIFT Q12_PROD
      *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar10 * iVar8) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
    }
    iVar10 = *(int *)(unaff_s2 + 0xec);
    uVar14 = 0;
    if (*(short *)(iVar10 + 0x182) != 0) {
      do {
        if (uVar14 != unaff_s5) {
          *(undefined4 *)(*(int *)(iVar10 + uVar14 * 4 + 0x184) + 0x78) = 1;
          func_0x000e8cfc();
          *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar14 * 4 + 0x184) + 0x78) = 4;
        }
        iVar10 = *(int *)(unaff_s2 + 0xec);
        uVar14 = uVar14 + 1;
      } while (uVar14 < *(ushort *)(iVar10 + 0x182));
    }
    *(undefined4 *)(unaff_s2 + 0x78) = 4;
    uVar4 = 0xc100;
    if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar4 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8)))
    {
      *(undefined2 *)(unaff_s2 + 8) = uVar4;
    }
    uVar4 = 0xc100;
    if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
       (uVar4 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
      *(undefined2 *)(unaff_s2 + 0xc) = uVar4;    // POS.y
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00023000 (GAME.BIN) @ 0x023000


void FUN_00023000(undefined4 param_1,int param_2,undefined4 param_3,int param_4,ushort param_5,
                 ushort param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9,
                 short param_10,undefined4 param_11,undefined4 param_12,int param_13)

{
  short sVar1;
  undefined2 uVar2;
  int iVar3;
  int iVar4;
  short sVar5;
  int in_t0;
  int iVar6;
  uint uVar7;
  int unaff_s2;
  uint unaff_s5;
  uint in_stack_00000040;
  
  param_11 = in_t0 >> (in_stack_00000040 & 0x1f);
  param_12 = param_4 * param_2 >> (in_stack_00000040 & 0x1f);
  iVar3 = FUN_00023180((int)(short)param_9 * (int)(short)param_9 +
                       (int)param_9._2_2_ * (int)param_9._2_2_ + (int)param_10 * (int)param_10);
  iVar3 = (iVar3 + -300) * 0x10000 >> 0x10;
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar3 * param_11 >> 0xf)) * 0x10000)    // BD.x
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x34) = sVar1;    // BD.x
  sVar5 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x36) - (iVar3 * param_12 >> 0xf)) * 0x10000)    // BD.y
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x36) = sVar5;    // BD.y
  *(short *)(unaff_s2 + 8) = *(short *)(unaff_s2 + 8) + sVar1;
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x38) -    // BD.z
                         (iVar3 * (param_13 * param_2 >> (in_stack_00000040 & 0x1f)) >> 0xf)) *
                        0x10000) >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x38) = sVar1;    // BD.z
  *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + sVar5;
  *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar1;    // POS.y POS.y
  iVar3 = func_0x000ab4d0(unaff_s2 + 8);
  if (iVar3 < *(short *)(unaff_s2 + 10)) {
    *(short *)(unaff_s2 + 10) = (short)iVar3;
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 1;
  iVar3 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
  iVar6 = (int)*(short *)(iVar3 + -0x7ffeb164);
  iVar4 = (int)*(short *)(iVar3 + -0x7ffeb162);
  iVar3 = -((int)(((uint)*(ushort *)(unaff_s2 + 8) - (uint)param_5) * 0x10000) >> 0x10) * iVar6 -
          ((int)(((uint)*(ushort *)(unaff_s2 + 0xc) - (uint)param_6) * 0x10000) >> 0x10) * iVar4 >>    // POS.y Q12_SHIFT
          0xc;
  if (iVar3 < 0) {
    iVar3 = iVar3 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);    // BD.x
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar4 >> 7);    // BD.z
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar3 * iVar6) >> 0xc);    // Q12_SHIFT Q12_PROD
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar3 * iVar4) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
  }
  iVar3 = *(int *)(unaff_s2 + 0xec);
  uVar7 = 0;
  if (*(short *)(iVar3 + 0x182) != 0) {
    do {
      if (uVar7 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar3 + uVar7 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar7 * 4 + 0x184) + 0x78) = 4;
      }
      iVar3 = *(int *)(unaff_s2 + 0xec);
      uVar7 = uVar7 + 1;
    } while (uVar7 < *(ushort *)(iVar3 + 0x182));
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 4;
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar2;
  }
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar2;    // POS.y
  }
  return;
}


---

## FUN_00023110 (GAME.BIN) @ 0x023110


void FUN_00023110(undefined4 param_1,undefined4 param_2,short param_3,short param_4,uint param_5,
                 ushort param_6)

{
  short sVar1;
  undefined2 uVar2;
  int iVar3;
  int in_v1;
  int iVar4;
  short in_t0;
  int iVar5;
  uint uVar6;
  int unaff_s2;
  uint unaff_s5;
  int in_lo;
  short sStack00000022;
  
  *(short *)(unaff_s2 + 0x36) = param_4;    // BD.y
  *(short *)(unaff_s2 + 8) = param_3 + in_t0;
  sVar1 = (short)(((in_v1 - (in_lo >> 0xf)) * 0x10000 >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x38) = sVar1;    // BD.z
  *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + param_4;
  *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar1;    // POS.y POS.y
  iVar3 = func_0x000ab4d0();
  if (iVar3 < *(short *)(unaff_s2 + 10)) {
    *(short *)(unaff_s2 + 10) = (short)iVar3;
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 1;
  sStack00000022 = *(short *)(unaff_s2 + 10) - param_5._2_2_;
  iVar3 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
  iVar5 = (int)*(short *)(iVar3 + -0x7ffeb164);
  iVar4 = (int)*(short *)(iVar3 + -0x7ffeb162);
  iVar3 = -((int)(((uint)*(ushort *)(unaff_s2 + 8) - (param_5 & 0xffff)) * 0x10000) >> 0x10) * iVar5    // ANGLE_MASK
          - ((int)(((uint)*(ushort *)(unaff_s2 + 0xc) - (uint)param_6) * 0x10000) >> 0x10) * iVar4    // POS.y Q12_SHIFT
          >> 0xc;    // Q12_SHIFT
  if (iVar3 < 0) {
    iVar3 = iVar3 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar5 >> 7);    // BD.x
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar4 >> 7);    // BD.z
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar3 * iVar5) >> 0xc);    // Q12_SHIFT Q12_PROD
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar3 * iVar4) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
  }
  iVar3 = *(int *)(unaff_s2 + 0xec);
  uVar6 = 0;
  if (*(short *)(iVar3 + 0x182) != 0) {
    do {
      if (uVar6 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar3 + uVar6 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar6 * 4 + 0x184) + 0x78) = 4;
      }
      iVar3 = *(int *)(unaff_s2 + 0xec);
      uVar6 = uVar6 + 1;
    } while (uVar6 < *(ushort *)(iVar3 + 0x182));
  }
  *(undefined4 *)(unaff_s2 + 0x78) = 4;
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar2;
  }
  uVar2 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar2;    // POS.y
  }
  return;
}


---

## FUN_00023180 (GAME.BIN) @ 0x023180


void FUN_00023180(void)

{
  undefined2 in_v0;
  undefined2 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int in_a3;
  int iVar6;
  uint uVar7;
  int unaff_s2;
  uint unaff_s5;
  uint in_stack_00000010;
  ushort in_stack_00000014;
  undefined2 uStack00000020;
  short sStack00000022;
  undefined2 uStack00000024;
  
  *(undefined2 *)(unaff_s2 + 10) = in_v0;
  *(undefined4 *)(in_a3 + 0x10) = 1;    // POS.z
  iVar3 = (uint)*(ushort *)(unaff_s2 + 8) - (in_stack_00000010 & 0xffff);    // ANGLE_MASK
  uStack00000020 = (undefined2)iVar3;
  sStack00000022 = *(short *)(unaff_s2 + 10) - in_stack_00000010._2_2_;
  iVar4 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uint)in_stack_00000014;    // POS.y
  uStack00000024 = (undefined2)iVar4;
  iVar2 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;    // ANGLE_MASK
  iVar6 = (int)*(short *)(iVar2 + -0x7ffeb164);
  iVar5 = (int)*(short *)(iVar2 + -0x7ffeb162);
  iVar2 = -(iVar3 * 0x10000 >> 0x10) * iVar6 - (iVar4 * 0x10000 >> 0x10) * iVar5 >> 0xc;    // Q12_SHIFT Q12_PROD
  if (iVar2 < 0) {
    iVar2 = iVar2 + -10;
    *(short *)(unaff_s2 + 0x34) = (short)(-iVar6 >> 7);    // BD.x
    *(short *)(unaff_s2 + 0x38) = (short)(-iVar5 >> 7);    // BD.z
    *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar2 * iVar6) >> 0xc);    // Q12_SHIFT Q12_PROD
    *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar2 * iVar5) >> 0xc);    // POS.y POS.y Q12_SHIFT Q12_PROD
  }
  iVar2 = *(int *)(unaff_s2 + 0xec);
  uVar7 = 0;
  if (*(short *)(iVar2 + 0x182) != 0) {
    do {
      if (uVar7 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar2 + uVar7 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar7 * 4 + 0x184) + 0x78) = 4;
      }
      iVar2 = *(int *)(unaff_s2 + 0xec);
      uVar7 = uVar7 + 1;
    } while (uVar7 < *(ushort *)(iVar2 + 0x182));
  }
  *(undefined4 *)(in_a3 + 0x10) = 4;    // POS.z
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar1;
  }
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar1;    // POS.y
  }
  return;
}


---

## FUN_00023210 (GAME.BIN) @ 0x023210


void FUN_00023210(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  undefined2 uVar1;
  int in_v1;
  int iVar2;
  int in_t0;
  short in_t1;
  short in_t2;
  uint uVar3;
  int unaff_s2;
  uint unaff_s5;
  
  *(short *)(unaff_s2 + 0x34) = (short)(-in_t0 >> 7);    // BD.x
  *(short *)(unaff_s2 + 0x38) = (short)(-param_3 >> 7);    // BD.z
  *(short *)(unaff_s2 + 8) = in_t2 - (short)(-((in_v1 + -10) * in_t0) >> 0xc);    // Q12_SHIFT Q12_PROD
  *(short *)(unaff_s2 + 0xc) = in_t1 - (short)(-((in_v1 + -10) * param_3) >> 0xc);    // POS.y Q12_SHIFT Q12_PROD
  iVar2 = *(int *)(unaff_s2 + 0xec);
  uVar3 = 0;
  if (*(short *)(iVar2 + 0x182) != 0) {
    do {
      if (uVar3 != unaff_s5) {
        *(undefined4 *)(*(int *)(iVar2 + uVar3 * 4 + 0x184) + 0x78) = 1;
        func_0x000e8cfc();
        *(undefined4 *)(*(int *)(*(int *)(unaff_s2 + 0xec) + uVar3 * 4 + 0x184) + 0x78) = 4;
      }
      iVar2 = *(int *)(unaff_s2 + 0xec);
      uVar3 = uVar3 + 1;
    } while (uVar3 < *(ushort *)(iVar2 + 0x182));
  }
  *(undefined4 *)(param_4 + 0x10) = 4;    // POS.z
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
    *(undefined2 *)(unaff_s2 + 8) = uVar1;
  }
  uVar1 = 0xc100;
  if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) ||    // POS.y
     (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) {    // POS.y
    *(undefined2 *)(unaff_s2 + 0xc) = uVar1;    // POS.y
  }
  return;
}


---

## FUN_00032c18 (GAME.BIN) @ 0x032c18


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00032c18(uint param_1,undefined4 *param_2)

{
  undefined2 uVar1;
  int iVar2;
  undefined4 uVar3;
  short sVar4;
  undefined2 *puVar5;
  short sVar6;
  undefined2 *puVar7;
  int iVar8;
  undefined2 *puVar9;
  uint uVar10;
  
  param_1 = param_1 & 0xffff;    // ANGLE_MASK
  iVar2 = func_0x000f5b78(param_1,0);
  *(uint *)(iVar2 + 300) = param_1;
  *(undefined4 *)(iVar2 + 0x128) = *param_2;
  uVar3 = func_0x000743a4(1,param_1);
  *(undefined4 *)(iVar2 + 0x134) = uVar3;
  *(short *)(iVar2 + 0x138) = (short)((uint)param_2[4] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x13a) = (short)((uint)param_2[5] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x13c) = (short)((uint)param_2[6] >> 6);    // POS_SHIFT6
  sVar6 = (short)((uint)param_2[7] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x13e) = sVar6;
  sVar4 = (short)((uint)param_2[8] >> 0xc);    // Q12_SHIFT
  *(short *)(iVar2 + 0x140) = sVar4;
  *(short *)(iVar2 + 0x142) = (short)((uint)-param_2[9] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x144) = (short)((uint)param_2[10] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(short *)(iVar2 + 0x146) = (short)((uint)param_2[0xb] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x148) = *(undefined2 *)(param_2 + 0xd);
  *(undefined2 *)(iVar2 + 0x14a) = *(undefined2 *)(param_2 + 0xe);
  *(undefined2 *)(iVar2 + 0x14c) = *(undefined2 *)(param_2 + 0x10);    // POS.z
  iVar8 = (int)sVar6;
  *(short *)(iVar2 + 0x14e) = (short)((uint)param_2[0x12] >> 6);    // POS_SHIFT6
  if (iVar8 != 0) {
    if (iVar8 == 0) {
      trap(7);
    }
    *(short *)(iVar2 + 0x152) = (short)((sVar4 * 0x477) / iVar8);
  }
  *(undefined2 *)(iVar2 + 0x154) = *(undefined2 *)(param_2 + 0x18);
  *(short *)(iVar2 + 0x156) = (short)((uint)(param_2[0x18] * param_2[0x1b]) >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x15a) = *(undefined2 *)(param_2 + 0x19);
  *(undefined2 *)(iVar2 + 0x158) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar2 + 0x15c) = *(undefined2 *)(param_2 + 0x1c);
  *(undefined2 *)(iVar2 + 0x15e) = *(undefined2 *)(param_2 + 0x16);
  *(undefined2 *)(iVar2 + 0x150) = *(undefined2 *)(param_2 + 0x17);
  *(short *)(iVar2 + 0x160) = (short)((uint)param_2[0x1d] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x162) = *(undefined2 *)(param_2 + 0x21);
  *(short *)(iVar2 + 0x164) = (short)((uint)param_2[0x1f] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x166) = *(undefined2 *)(param_2 + 0x22);    // ANG.pitch
  *(short *)(iVar2 + 0x168) = (short)((uint)param_2[0x1e] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x16a) = *(undefined2 *)(param_2 + 0x23);
  *(short *)(iVar2 + 0x16c) = (short)((uint)param_2[0x20] >> 0xc);    // Q12_SHIFT Q12_PROD
  *(undefined2 *)(iVar2 + 0x16e) = *(undefined2 *)(param_2 + 0x24);    // ANG.roll
  *(short *)(iVar2 + 0x170) = (short)((uint)param_2[0x15] >> 0xc);    // Q12_SHIFT Q12_PROD
  sVar4 = (short)((uint)param_2[0x14] >> 6);    // POS_SHIFT6
  *(short *)(iVar2 + 0x172) = sVar4;
  sVar6 = *(short *)(iVar2 + 0x128);
  if ((sVar6 == 4) || (sVar6 == 0xb)) {
    *(short *)(iVar2 + 0x174) = sVar4 * 3;
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  *(short *)(iVar2 + 0x174) = sVar4;
  *(undefined2 *)(iVar2 + 0x176) = *(undefined2 *)(param_2 + 1);
  *(undefined2 *)(iVar2 + 0x178) = *(undefined2 *)(param_2 + 2);
  uVar10 = 0;
  *(undefined2 *)(iVar2 + 0x17a) = *(undefined2 *)(param_2 + 3);
  uVar1 = *(undefined2 *)(param_2 + 0x27);
  *(undefined4 *)(iVar2 + 0x180) = 0;
  *(undefined2 *)(iVar2 + 0x17c) = uVar1;
  uVar1 = *(undefined2 *)(param_2 + 3);
  *(undefined2 *)(iVar2 + 0xb8) = 0xffff;
  *(undefined2 *)(iVar2 + 0xba) = 0xffff;
  *(undefined2 *)(iVar2 + 0xbc) = 0xffff;
  *(undefined2 *)(iVar2 + 0xbe) = 0xffff;
  *(undefined2 *)(iVar2 + 0xb4) = 0xffff;
  *(undefined2 *)(iVar2 + 0xb6) = 0xffff;
  *(undefined2 *)(iVar2 + 0xc0) = 0xffff;
  *(undefined2 *)(iVar2 + 0x17a) = uVar1;
  puVar9 = (undefined2 *)(iVar2 + 0xcc);
  *(undefined4 *)(iVar2 + 0x130) = param_2[0x25];
  puVar7 = (undefined2 *)(iVar2 + 0xca);
  *(undefined2 *)(iVar2 + 0x18a) = *(undefined2 *)(param_2 + 0x26);    // FLAGS
  puVar5 = (undefined2 *)(iVar2 + 200);
  *(undefined2 *)(iVar2 + 0x18c) = *(undefined2 *)(param_2 + 0x2b);
  do {
    *puVar5 = 0;
    *puVar7 = 0;
    *puVar9 = 0;
    puVar9 = puVar9 + 3;
    puVar7 = puVar7 + 3;
    uVar10 = uVar10 + 1;
    puVar5 = puVar5 + 3;
  } while (uVar10 < 9);
  if (param_1 - 6 < 0x4b) {
                    /* WARNING: Could not emulate address calculation at 0x00032f34 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)((param_1 - 6) * 4 + -0x7ff39824))();
    return;
  }
  func_0x000f719c(iVar2);
  if ((sVar6 == 5) || (uVar1 = 3000, sVar6 == 7)) {
    uVar1 = 6000;
  }
  *(undefined2 *)(iVar2 + 0xb0) = uVar1;
  *(undefined2 *)(iVar2 + 0x184) = *(undefined2 *)(param_2 + 0x28);
  *(undefined2 *)(iVar2 + 0x186) = *(undefined2 *)(param_2 + 0x29);
  uVar1 = *(undefined2 *)(param_2 + 0x2a);
  *(undefined2 *)(iVar2 + 0xfe) = 0x50;
  *(undefined2 *)(iVar2 + 0x188) = uVar1;
  if ((param_1 != 8) && (param_1 != 0x4a)) {
    if (param_1 == 10) {
      *(undefined2 *)(iVar2 + 0x11a) = 0;
      *(undefined2 *)(iVar2 + 0x11c) = 0xff60;
      *(undefined2 *)(iVar2 + 0x11e) = 0xfe8e;
      *(undefined2 *)(iVar2 + 0x120) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if (param_1 == 0x4c) {
      *(undefined2 *)(iVar2 + 0x11c) = 0xfe70;
      *(undefined2 *)(iVar2 + 0x11a) = 0;
      *(undefined2 *)(iVar2 + 0x11e) = 0;
      *(undefined2 *)(iVar2 + 0x120) = 1;
    }
    if (sVar6 == 6) {
      if (*(short *)(iVar2 + 0x13e) == 0) {
        trap(7);
      }
      iVar8 = (int)_DAT_8011966e * (int)_DAT_8011966e;
      if (iVar8 == 0) {
        trap(7);
      }
      *(short *)(iVar2 + 0xb2) =
           (short)((((int)*(short *)(iVar2 + 0x138) * (int)*(short *)(iVar2 + 0x138)) /
                    (int)*(short *)(iVar2 + 0x13e) << 0x11) / iVar8);
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00044a14 (GAME.BIN) @ 0x044a14


/* WARNING: Control flow encountered bad instruction data */

void FUN_00044a14(int param_1)

{
  undefined2 uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 local_20;
  undefined4 local_1c;
  
  iVar2 = func_0x000ab4d0(param_1 + 8);
  if ((*(short *)(*(int *)(param_1 + 0xb8) + 0x18) != 0) &&
     ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44))) {    // SPD
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) | 4;
  }
  if (*(short *)(param_1 + 10) <= iVar2) {
    return;
  }
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 5) == '\x04') && (0 < *(int *)(param_1 + 0xbc))) {
    if ((*(short *)(param_1 + 0x34) != 0) || (*(short *)(param_1 + 0x38) != 0)) {    // BD.x BD.z
      *(undefined2 *)(param_1 + 0x36) = 0;    // BD.y
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    uVar1 = 0xffff;
    if (*(short *)(param_1 + 0x36) == 0) {    // BD.y
      uVar1 = 0xfff6;
    }
    *(undefined2 *)(param_1 + 0x36) = uVar1;    // BD.y
    *(short *)(param_1 + 0x44) =    // SPD
         (short)((int)*(short *)(param_1 + 0x3c) * (int)*(short *)(param_1 + 0x34) +    // BS.x BD.x
                 (int)*(short *)(param_1 + 0x3e) * (int)*(short *)(param_1 + 0x36) +    // BS.y BD.y
                 (int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc);    // BS.z BD.z Q12_SHIFT Q12_PROD
    uVar1 = func_0x000ab4d0(param_1 + 8);
    *(undefined2 *)(param_1 + 10) = uVar1;
    iVar2 = func_0x000a9678((int)*(short *)(param_1 + 8),(int)*(short *)(param_1 + 0xc));    // POS.y
    if (iVar2 != 0) {
      *(undefined2 *)(param_1 + 0x44) = 0;    // SPD
    }
    func_0x00109ff4(param_1);
    if (*(short *)(param_1 + 0x44) == 0) {    // SPD
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // ANGLE_MASK
      halt_baddata();
    }
    return;
  }
  iVar3 = (int)*(short *)(param_1 + 10);
  if (iVar3 <= iVar2) {
    return;
  }
  if (iVar3 - iVar2 < 0) {
    if (iVar2 - iVar3 < 0x33) goto LAB_00044c9c;
  }
  else if (iVar3 - iVar2 < 0x33) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  uVar4 = 0x1000;
  do {
    uVar4 = (int)uVar4 >> 1;
    local_20 = CONCAT22(*(short *)(param_1 + 10) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x36)) >> 0xc),    // BD.y Q12_SHIFT Q12_PROD
                        *(short *)(param_1 + 8) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x34)) >> 0xc));    // BD.x Q12_SHIFT Q12_PROD
    local_1c = CONCAT22(local_1c._2_2_,
                        *(short *)(param_1 + 0xc) -    // POS.y
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x38)) >> 0xc));    // BD.z Q12_SHIFT Q12_PROD
    iVar2 = func_0x000ab4d0(&local_20);
    if (iVar2 < local_20._2_2_) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    iVar3 = iVar2 - local_20._2_2_;
    if (iVar3 < 0) {
      iVar3 = local_20._2_2_ - iVar2;
    }
  } while ((0x31 < iVar3) && (99 < uVar4));
  *(undefined4 *)(param_1 + 8) = local_20;
  *(undefined4 *)(param_1 + 0xc) = local_1c;    // POS.y
LAB_00044c9c:
  *(short *)(param_1 + 10) = (short)iVar2;
  if ((*(uint *)(param_1 + 0xd0) & 1) != 0) {
    *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 2;
  }
  uVar4 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x18);
  if (uVar4 == 0) {
    func_0x00084688(0xf,param_1 + 8,0);
    func_0x0010a4f8(param_1);
    uVar5 = *(uint *)(param_1 + 0xd0);
    uVar4 = uVar5 | 8;
    if ((uVar5 & 1) == 0) {
      uVar4 = uVar5 & 0xfffffff7;    // ANGLE_MASK
    }
    *(uint *)(param_1 + 0xd0) = uVar4;
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0) {    // ANG.yaw
      *(undefined2 *)(param_1 + 0xc0) = 0;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 3;
      uVar4 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
      if (uVar4 < 0x41) {
        uVar4 = 0x40;
      }
      if ((*(uint *)(param_1 + 0xd0) & 0x10) != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      *(short *)(param_1 + 0x9c) = (short)uVar4;
      *(uint *)(param_1 + 0x98) = uVar4 * uVar4;
    }
  }
  else {
    *(short *)(param_1 + 0x36) = (short)((int)-((int)*(short *)(param_1 + 0x36) * uVar4) >> 0xc);    // BD.y BD.y Q12_SHIFT Q12_PROD
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 1 & 1) != 0) {    // ANG.yaw
      uVar5 = *(uint *)((*(ushort *)(param_1 + 200) & 0x7f) * 4 + -0x7ffeb164);
      uVar4 = uVar5 >> 0x10;
      setCopControlWord(2,0,uVar4);
      uVar5 = uVar5 & 0xffff;    // ANGLE_MASK
      setCopControlWord(2,0x2000,uVar4);
      setCopControlWord(2,0x800,uVar5);
      setCopControlWord(2,0x1000,0x1000);
      setCopControlWord(2,0x1800,-uVar5 & 0xffff);    // ANGLE_MASK
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x34));    // BD.x
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x36));    // BD.y
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x38));    // BD.z
      copFunction(2,0x49e012);
      uVar6 = getCopReg(2,0x4800);
      uVar7 = getCopReg(2,0x5000);
      uVar8 = getCopReg(2,0x5800);
      *(short *)(param_1 + 0x34) = (short)uVar6;    // BD.x
      *(short *)(param_1 + 0x36) = (short)uVar7;    // BD.y
      *(short *)(param_1 + 0x38) = (short)uVar8;    // BD.z
    }
    func_0x00109ff4(param_1);
    if ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44)) {    // SPD
      uVar1 = (undefined2)
              ((int)*(short *)(param_1 + 0x34) * (int)*(short *)(param_1 + 0x3c) +    // BD.x BS.x
               (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +    // BD.y BS.y
               (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc);    // BD.z BS.z Q12_SHIFT Q12_PROD
      *(undefined2 *)(param_1 + 0xc4) = uVar1;
      *(undefined2 *)(param_1 + 0x44) = uVar1;    // SPD
    }
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffdff | 0x40;    // ANGLE_MASK
    func_0x00076790(param_1);
    uVar4 = (uint)(*(ushort *)(*(int *)(param_1 + 0xb8) + 8) >> 3);
    if (uVar4 < 3) {
      uVar4 = 3;
    }
    iVar2 = (int)*(short *)(param_1 + 0x36);    // BD.y
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    if (((iVar2 <= (int)uVar4) || ((int)*(short *)(param_1 + 0x44) <= (int)uVar4)) &&    // SPD
       (func_0x0010a4f8(param_1), (*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0)) {    // ANG.yaw
      *(undefined2 *)(param_1 + 0xc0) = 0;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 3;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  return;
}


---

## FUN_00044f80 (GAME.BIN) @ 0x044f80


/* WARNING: Control flow encountered bad instruction data */

void FUN_00044f80(int param_1)

{
  ushort uVar1;
  bool bVar2;
  short sVar3;
  undefined4 uVar4;
  uint uVar5;
  short sVar6;
  short sVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined4 local_50;
  undefined4 local_4c;
  undefined2 uStack_4a;
  short local_48;
  short local_46;
  short local_44;
  undefined1 auStack_40 [8];
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined1 auStack_28 [8];
  undefined4 local_20;
  undefined4 local_1c;
  
  iVar12 = *(int *)(param_1 + 0xd4);
  if (iVar12 != 0) {
    iVar9 = (int)(((uint)*(ushort *)(param_1 + 8) - (uint)*(ushort *)(iVar12 + 0x6c)) * 0x10000) >>
            0x10;
    iVar11 = (int)(((uint)*(ushort *)(param_1 + 10) - (uint)*(ushort *)(iVar12 + 0x6e)) * 0x10000)
             >> 0x10;
    iVar12 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)    // POS.y
             >> 0x10;
    uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
    if ((uint)(iVar9 * iVar9 + iVar11 * iVar11 + iVar12 * iVar12) <= uVar8 * uVar8) {
      uVar5 = 0x40;
      if (0x40 < uVar8) {
        uVar5 = uVar8;
      }
      *(short *)(param_1 + 0x9c) = (short)uVar5;
      *(uint *)(param_1 + 0x98) = uVar5 * uVar5;
      func_0x0010a4f8(param_1);
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  if (*(int *)(param_1 + 0xbc) < 1) {
    if ((*(uint *)(param_1 + 0x50) & 4) != 0) {
      return;
    }
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) | 4;
  }
  else {
    if (0 < *(short *)(param_1 + 0xc2)) {
      *(short *)(param_1 + 0xc2) = *(short *)(param_1 + 0xc2) + -1;
    }
    iVar12 = *(int *)(param_1 + 0xd4);
    if (iVar12 == 0) {
      if (*(short *)(param_1 + 0xc2) < 1) {
        uVar4 = func_0x0010834c(param_1);
        *(undefined4 *)(param_1 + 0xd4) = uVar4;
        *(undefined2 *)(param_1 + 0xc2) = *(undefined2 *)(*(int *)(param_1 + 0xb8) + 0x28);
        iVar12 = *(int *)(param_1 + 0xd4);
      }
      if (iVar12 == 0) {
        uVar8 = *(uint *)(*(int *)(param_1 + 0xb8) + 0x20);    // ANG.yaw
        if ((uVar8 >> 4 & 1) != 0) {
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);    // POS.z
          sVar3 = 0x80;
          if (0x80 < (int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1)) {    // SPD
            sVar3 = *(short *)(param_1 + 0x44) - uVar1;    // SPD
          }
          sVar6 = *(short *)(param_1 + 10);
          *(short *)(param_1 + 0x44) = sVar3;    // SPD
          iVar12 = func_0x000ab4d0(param_1 + 8);
          if ((((int)sVar6 < iVar12 + -0x100) && (*(short *)(param_1 + 0x3e) < 1)) &&    // BS.y
             (iVar12 = -(int)*(short *)(param_1 + 0x3e), (*(uint *)(param_1 + 0x50) & 4) == 0)) {    // BS.y
            if (iVar12 < 0x20) {
              iVar12 = 0x20;
            }
            *(short *)(param_1 + 0x3e) = (short)iVar12;    // BS.y
            func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),    // BS.x BS.z
                            param_1 + 0x3c);    // BS.x
          }
          iVar12 = (int)*(short *)(param_1 + 0x44);    // SPD
          *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);    // BD.x BS.x Q12_SHIFT Q12_PROD
          *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);    // BD.y BS.y Q12_SHIFT Q12_PROD
          *(short *)(param_1 + 0x38) = (short)(*(short *)(param_1 + 0x40) * iVar12 >> 0xc);    // BD.z BS.z Q12_SHIFT Q12_PROD
          halt_baddata();
        }
        if ((uVar8 >> 3 & 1) == 0) {
          func_0x00109e70(param_1);
          func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),    // BS.x BS.z
                          param_1 + 0x3c);    // BS.x
          halt_baddata();
        }
        return;
      }
    }
    iVar11 = (int)(((uint)*(ushort *)(param_1 + 8) - (uint)*(ushort *)(iVar12 + 0x6c)) * 0x10000) >>
             0x10;
    iVar10 = (int)(((uint)*(ushort *)(param_1 + 10) - (uint)*(ushort *)(iVar12 + 0x6e)) * 0x10000)
             >> 0x10;
    iVar9 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)    // POS.y
            >> 0x10;
    uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
    if (uVar8 * uVar8 < (uint)(iVar11 * iVar11 + iVar10 * iVar10 + iVar9 * iVar9)) {
      local_50 = CONCAT22(*(short *)(iVar12 + 0x6e) - *(ushort *)(param_1 + 10),
                          *(short *)(iVar12 + 0x6c) - *(ushort *)(param_1 + 8));
      local_2c = CONCAT22(uStack_4a,*(short *)(iVar12 + 0x70) - *(ushort *)(param_1 + 0xc));    // POS.y
      local_30 = local_50;
      func_0x00109758(param_1,local_50,local_2c,&local_48);
      local_30 = CONCAT22(local_46 - *(short *)(param_1 + 0x3e),    // BS.y
                          local_48 - *(short *)(param_1 + 0x3c));    // BS.x
      local_2c = CONCAT22(local_2c._2_2_,local_44 - *(short *)(param_1 + 0x40));    // BS.z
      local_20 = local_30;
      local_1c = local_2c;
      func_0x00109758(param_1,local_30,local_2c,auStack_28);
      iVar12 = func_0x0010a95c(param_1,param_1 + 0x3c,&local_48,auStack_40);    // BS.x
      iVar9 = (int)*(short *)(param_1 + 0x3c) * (int)local_48 +    // BS.x
              (int)*(short *)(param_1 + 0x3e) * (int)local_46 +    // BS.y
              (int)*(short *)(param_1 + 0x40) * (int)local_44 >> 0xc;    // BS.z Q12_SHIFT Q12_PROD
      func_0x0010a95c(param_1,auStack_40,param_1 + 0x3c,&local_38);    // BS.x
      local_20 = local_38;
      local_1c = local_34;
      func_0x00109758(param_1,local_38,local_34,&local_38);
      if (4000 < iVar9) {
        iVar11 = iVar12;
        if (iVar12 < 0) {
          iVar11 = -iVar12;
        }
        if (iVar11 < 1000) {
          if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {    // ANG.yaw
            return;
          }
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
      if ((iVar12 == 0) && (iVar9 < 0)) {
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) != 0) {    // ANG.yaw
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);    // POS.z
          sVar3 = *(short *)(param_1 + 0x44) - uVar1;    // SPD
          if ((int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1) < 1) {    // SPD
            sVar3 = 0;
          }
          *(short *)(param_1 + 0x44) = sVar3;    // SPD
        }
        func_0x0010a6ec(param_1);
      }
      else {
        uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x12);
        bVar2 = iVar9 < *(short *)((uVar8 & 0xfff) * 4 + -0x7ffeb162);    // ANGLE_MASK
        if (bVar2) {
          if (iVar12 < 0) {
            uVar8 = 0x1000 - uVar8 & 0xfff;    // ANGLE_MASK
          }
          iVar9 = (uVar8 & 0xfff) * 4;    // ANGLE_MASK
          iVar12 = (int)*(short *)(iVar9 + -0x7ffeb164);
          iVar9 = (int)*(short *)(iVar9 + -0x7ffeb162);
        }
        iVar11 = (int)*(short *)(param_1 + 0x44);    // SPD
        sVar7 = (short)(iVar9 * *(short *)(param_1 + 0x3c) + iVar12 * (short)local_38 >> 0xc);    // BS.x Q12_SHIFT Q12_PROD
        sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc);    // BS.y Q12_SHIFT Q12_PROD
        sVar6 = (short)(iVar9 * *(short *)(param_1 + 0x40) + iVar12 * (short)local_34 >> 0xc);    // BS.z Q12_SHIFT Q12_PROD
        *(short *)(param_1 + 0x3c) = sVar7;    // BS.x
        *(short *)(param_1 + 0x3e) = sVar3;    // BS.y
        *(short *)(param_1 + 0x40) = sVar6;    // BS.z
        *(short *)(param_1 + 0x34) = (short)(sVar7 * iVar11 >> 0xc);    // BD.x Q12_SHIFT Q12_PROD
        *(short *)(param_1 + 0x36) = (short)(sVar3 * iVar11 >> 0xc);    // BD.y Q12_SHIFT Q12_PROD
        *(short *)(param_1 + 0x38) = (short)(sVar6 * iVar11 >> 0xc);    // BD.z Q12_SHIFT Q12_PROD
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {    // ANG.yaw
          func_0x00109e70(param_1);
          return;
        }
        if (bVar2) {
          func_0x00109f60(param_1);
        }
        else {
          func_0x00109e70(param_1);
        }
      }
    }
    else {
      uVar5 = 0x40;
      if (0x40 < uVar8) {
        uVar5 = uVar8;
      }
      *(short *)(param_1 + 0x9c) = (short)uVar5;
      *(uint *)(param_1 + 0x98) = uVar5 * uVar5;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // ANGLE_MASK
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_0001e750 (MAIN.EXE) @ 0x01e750


undefined4 FUN_0001e750(short *param_1,int *param_2)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  short sVar6;
  short sVar7;
  short sVar8;
  undefined4 *puVar9;
  int iVar10;
  int unaff_gp;
  short sVar11;
  short local_44;
  short local_40;
  short local_3c;
  short local_38;
  short sStack_34;
  short sStack_30;
  undefined2 uStack_2e;
  undefined2 uStack_2c;
  short sStack_28;
  short sStack_26;
  undefined4 auStack_20 [8];
  
  local_44 = param_1[8];
  local_40 = param_1[9];
  sVar6 = param_1[10];
  local_3c = param_1[0xc];
  sVar5 = param_1[0xb];
  local_38 = param_1[0x10];
  sVar7 = param_1[0xd];
  sStack_34 = param_1[0x12];
  sVar4 = param_1[0xe];
  sVar3 = param_1[0xf];
  sVar11 = param_1[0x11];
  sVar8 = param_1[0x13];
  puVar9 = (undefined4 *)&DAT_8003bf2c;
  puVar2 = auStack_20;
  iVar10 = 8;
  do {
    iVar10 = iVar10 + -1;
    *puVar2 = *puVar9;
    puVar9 = puVar9 + 1;
    puVar2 = puVar2 + 1;
  } while (0 < iVar10);
  if (param_1[4] != 0) {
    FUN_0001f340((int)param_1[4],auStack_20);
    sStack_30 = local_44 - param_1[5];
    uStack_2e = (undefined2)((((int)local_40 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    local_44 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    local_40 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    sStack_30 = sVar6 - param_1[5];
    uStack_2e = (undefined2)((((int)sVar5 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar6 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar5 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    sStack_30 = local_3c - param_1[5];
    uStack_2e = (undefined2)((((int)sVar7 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    local_3c = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sStack_30 = sVar4 - param_1[5];
    sVar7 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    uStack_2e = (undefined2)((((int)sVar3 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar4 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar3 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    if (0x100 < param_1[1]) {
      sStack_30 = local_38 - param_1[5];
      uStack_2e = (undefined2)((((int)sVar11 - (int)param_1[6]) * 0x1000) / 0x780);
      uStack_2c = 0;
      FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
      local_38 = sStack_28 + param_1[5];
      iVar10 = sStack_26 * 0x780;
      if (iVar10 < 0) {
        iVar10 = iVar10 + 0xfff;
      }
      sVar11 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
      sStack_30 = sStack_34 - param_1[5];
      uStack_2e = (undefined2)((((int)sVar8 - (int)param_1[6]) * 0x1000) / 0x780);
      uStack_2c = 0;
      FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
      sStack_34 = sStack_28 + param_1[5];
      iVar10 = sStack_26 * 0x780;
      if (iVar10 < 0) {
        iVar10 = iVar10 + 0xfff;
      }
      sVar8 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    }
  }
  iVar10 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
  if (iVar10 == 0) {
    uVar1 = 0;
  }
  else {
    *(undefined1 *)(iVar10 + 3) = 9;
    *(undefined1 *)(iVar10 + 7) = 0x2c;
    *(short *)(iVar10 + 8) = local_44;
    *(short *)(iVar10 + 10) = local_40;
    *(short *)(iVar10 + 0x10) = sVar6;    // POS.z
    *(short *)(iVar10 + 0x12) = sVar5;
    *(short *)(iVar10 + 0x18) = local_3c;
    *(short *)(iVar10 + 0x1a) = sVar7;
    *(short *)(iVar10 + 0x20) = sVar4;    // ANG.yaw
    *(short *)(iVar10 + 0x22) = sVar3;    // ANG.pitch
    *(char *)(iVar10 + 0xc) = (char)param_1[0x14];    // POS.y
    *(char *)(iVar10 + 0xd) = (char)param_1[0x17];
    *(undefined1 *)(iVar10 + 0x14) = *(undefined1 *)((int)param_1 + 0x29);
    *(undefined1 *)(iVar10 + 0x15) = *(undefined1 *)((int)param_1 + 0x2f);
    *(char *)(iVar10 + 0x1c) = (char)param_1[0x15];
    *(char *)(iVar10 + 0x1d) = (char)param_1[0x18];
    *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2b);    // ANG.roll
    *(undefined1 *)(iVar10 + 0x25) = *(undefined1 *)((int)param_1 + 0x31);
    *(char *)(iVar10 + 4) = (char)param_1[0x1a];
    *(undefined1 *)(iVar10 + 5) = *(undefined1 *)((int)param_1 + 0x35);
    *(char *)(iVar10 + 6) = (char)param_1[0x1b];
    *(short *)(iVar10 + 0xe) = param_1[0x1e];
    *(short *)(iVar10 + 0x16) = param_1[0x1c];
    FUN_0001c89c(iVar10,(int)param_1[3]);
    FUN_0001c85c(*param_2 + *param_1 * 4,iVar10);
    FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    if (0x100 < param_1[1]) {
      iVar10 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
      if (iVar10 == 0) {
        return 0;
      }
      *(undefined1 *)(iVar10 + 3) = 9;
      *(undefined1 *)(iVar10 + 7) = 0x2c;
      *(short *)(iVar10 + 8) = sVar6;
      *(short *)(iVar10 + 10) = sVar5;
      *(short *)(iVar10 + 0x10) = local_38;    // POS.z
      *(short *)(iVar10 + 0x12) = sVar11;
      *(short *)(iVar10 + 0x18) = sVar4;
      *(short *)(iVar10 + 0x1a) = sVar3;
      *(short *)(iVar10 + 0x20) = sStack_34;    // ANG.yaw
      *(short *)(iVar10 + 0x22) = sVar8;    // ANG.pitch
      *(undefined1 *)(iVar10 + 0xc) = 0;    // POS.y
      *(undefined1 *)(iVar10 + 0xd) = *(undefined1 *)((int)param_1 + 0x2f);
      *(char *)(iVar10 + 0x14) = (char)param_1[0x16];
      *(char *)(iVar10 + 0x15) = (char)param_1[0x19];
      *(undefined1 *)(iVar10 + 0x1c) = 0;
      *(undefined1 *)(iVar10 + 0x1d) = *(undefined1 *)((int)param_1 + 0x31);
      *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2d);    // ANG.roll
      *(undefined1 *)(iVar10 + 0x25) = *(undefined1 *)((int)param_1 + 0x33);
      *(char *)(iVar10 + 4) = (char)param_1[0x1a];
      *(undefined1 *)(iVar10 + 5) = *(undefined1 *)((int)param_1 + 0x35);
      *(char *)(iVar10 + 6) = (char)param_1[0x1b];
      *(short *)(iVar10 + 0xe) = param_1[0x1e];
      *(short *)(iVar10 + 0x16) = param_1[0x1d];
      FUN_0001c89c(iVar10,(int)param_1[3]);
      FUN_0001c85c(*param_2 + *param_1 * 4,iVar10);
      FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    }
    uVar1 = 1;
  }
  return uVar1;
}


---

## FUN_0001e7b4 (MAIN.EXE) @ 0x01e7b4


undefined4 FUN_0001e7b4(undefined4 param_1,int *param_2)

{
  int in_v0;
  undefined4 uVar1;
  undefined4 *puVar2;
  short *unaff_s0;
  short sVar3;
  short sVar4;
  int unaff_s4;
  short unaff_s5;
  int unaff_s6;
  short sVar5;
  int in_t8;
  undefined4 *puVar6;
  int iVar7;
  int unaff_gp;
  short sVar8;
  short in_stack_0000003c;
  int in_stack_00000040;
  short in_stack_00000044;
  short in_stack_00000048;
  int iStack0000004c;
  short sStack00000050;
  undefined2 uStack00000052;
  undefined2 in_stack_00000054;
  short sStack00000058;
  short sStack0000005a;
  int *piStack00000084;
  
  sVar4 = unaff_s0[0xe];
  sVar3 = unaff_s0[0xf];
  sVar8 = unaff_s0[0x11];
  sVar5 = unaff_s0[0x13];
  puVar6 = (undefined4 *)(in_t8 + -0x40d4);
  puVar2 = (undefined4 *)&stack0x00000060;
  iVar7 = 8;
  piStack00000084 = param_2;
  do {
    iVar7 = iVar7 + -1;
    *puVar2 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar2 = puVar2 + 1;
  } while (0 < iVar7);
  iStack0000004c = in_v0;
  if (unaff_s0[4] != 0) {
    FUN_0001f340((int)unaff_s0[4],&stack0x00000060);
    sStack00000050 = in_stack_0000003c - unaff_s0[5];
    uStack00000052 = (undefined2)(((in_stack_00000040 - unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_0000003c = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    in_stack_00000040 = ((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    sStack00000050 = unaff_s5 - unaff_s0[5];
    uStack00000052 = (undefined2)(((unaff_s4 - unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    unaff_s5 = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    unaff_s4 = ((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    sStack00000050 = in_stack_00000044 - unaff_s0[5];
    uStack00000052 = (undefined2)(((unaff_s6 - unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_00000044 = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    sStack00000050 = sVar4 - unaff_s0[5];
    unaff_s6 = ((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    uStack00000052 = (undefined2)((((int)sVar3 - (int)unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    sVar4 = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    sVar3 = (short)((uint)(((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    if (0x100 < unaff_s0[1]) {
      sStack00000050 = in_stack_00000048 - unaff_s0[5];
      uStack00000052 = (undefined2)((((int)sVar8 - (int)unaff_s0[6]) * 0x1000) / 0x780);
      in_stack_00000054 = 0;
      FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
      in_stack_00000048 = sStack00000058 + unaff_s0[5];
      iVar7 = sStack0000005a * 0x780;
      if (iVar7 < 0) {
        iVar7 = iVar7 + 0xfff;
      }
      sVar8 = (short)((uint)(((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
      sStack00000050 = (short)iStack0000004c - unaff_s0[5];
      uStack00000052 = (undefined2)((((int)sVar5 - (int)unaff_s0[6]) * 0x1000) / 0x780);
      in_stack_00000054 = 0;
      FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
      iStack0000004c = ((int)sStack00000058 + (int)unaff_s0[5]) * 0x10000 >> 0x10;
      iVar7 = sStack0000005a * 0x780;
      if (iVar7 < 0) {
        iVar7 = iVar7 + 0xfff;
      }
      sVar5 = (short)((uint)(((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    }
  }
  iVar7 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
  if (iVar7 == 0) {
    uVar1 = 0;
  }
  else {
    *(undefined1 *)(iVar7 + 3) = 9;
    *(undefined1 *)(iVar7 + 7) = 0x2c;
    *(short *)(iVar7 + 8) = in_stack_0000003c;
    *(short *)(iVar7 + 10) = (short)in_stack_00000040;
    *(short *)(iVar7 + 0x10) = unaff_s5;    // POS.z
    *(short *)(iVar7 + 0x12) = (short)unaff_s4;
    *(short *)(iVar7 + 0x18) = in_stack_00000044;
    *(short *)(iVar7 + 0x1a) = (short)unaff_s6;
    *(short *)(iVar7 + 0x20) = sVar4;    // ANG.yaw
    *(short *)(iVar7 + 0x22) = sVar3;    // ANG.pitch
    *(char *)(iVar7 + 0xc) = (char)unaff_s0[0x14];    // POS.y
    *(char *)(iVar7 + 0xd) = (char)unaff_s0[0x17];
    *(undefined1 *)(iVar7 + 0x14) = *(undefined1 *)((int)unaff_s0 + 0x29);
    *(undefined1 *)(iVar7 + 0x15) = *(undefined1 *)((int)unaff_s0 + 0x2f);
    *(char *)(iVar7 + 0x1c) = (char)unaff_s0[0x15];
    *(char *)(iVar7 + 0x1d) = (char)unaff_s0[0x18];
    *(undefined1 *)(iVar7 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2b);    // ANG.roll
    *(undefined1 *)(iVar7 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x31);
    *(char *)(iVar7 + 4) = (char)unaff_s0[0x1a];
    *(undefined1 *)(iVar7 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
    *(char *)(iVar7 + 6) = (char)unaff_s0[0x1b];
    *(short *)(iVar7 + 0xe) = unaff_s0[0x1e];
    *(short *)(iVar7 + 0x16) = unaff_s0[0x1c];
    FUN_0001c89c(iVar7,(int)unaff_s0[3]);
    FUN_0001c85c(*piStack00000084 + *unaff_s0 * 4,iVar7);
    FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    if (0x100 < unaff_s0[1]) {
      iVar7 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
      if (iVar7 == 0) {
        return 0;
      }
      *(undefined1 *)(iVar7 + 3) = 9;
      *(undefined1 *)(iVar7 + 7) = 0x2c;
      *(short *)(iVar7 + 8) = unaff_s5;
      *(short *)(iVar7 + 10) = (short)unaff_s4;
      *(short *)(iVar7 + 0x10) = in_stack_00000048;    // POS.z
      *(short *)(iVar7 + 0x12) = sVar8;
      *(short *)(iVar7 + 0x18) = sVar4;
      *(short *)(iVar7 + 0x1a) = sVar3;
      *(short *)(iVar7 + 0x20) = (short)iStack0000004c;    // ANG.yaw
      *(short *)(iVar7 + 0x22) = sVar5;    // ANG.pitch
      *(undefined1 *)(iVar7 + 0xc) = 0;    // POS.y
      *(undefined1 *)(iVar7 + 0xd) = *(undefined1 *)((int)unaff_s0 + 0x2f);
      *(char *)(iVar7 + 0x14) = (char)unaff_s0[0x16];
      *(char *)(iVar7 + 0x15) = (char)unaff_s0[0x19];
      *(undefined1 *)(iVar7 + 0x1c) = 0;
      *(undefined1 *)(iVar7 + 0x1d) = *(undefined1 *)((int)unaff_s0 + 0x31);
      *(undefined1 *)(iVar7 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2d);    // ANG.roll
      *(undefined1 *)(iVar7 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x33);
      *(char *)(iVar7 + 4) = (char)unaff_s0[0x1a];
      *(undefined1 *)(iVar7 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
      *(char *)(iVar7 + 6) = (char)unaff_s0[0x1b];
      *(short *)(iVar7 + 0xe) = unaff_s0[0x1e];
      *(short *)(iVar7 + 0x16) = unaff_s0[0x1d];
      FUN_0001c89c(iVar7,(int)unaff_s0[3]);
      FUN_0001c85c(*piStack00000084 + *unaff_s0 * 4,iVar7);
      FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    }
    uVar1 = 1;
  }
  return uVar1;
}


---

## FUN_0001ea04 (MAIN.EXE) @ 0x01ea04


undefined4 FUN_0001ea04(void)

{
  short sVar1;
  short in_v0;
  undefined4 uVar2;
  undefined2 in_v1;
  short *unaff_s0;
  int unaff_s1;
  undefined2 uVar3;
  undefined2 unaff_s4;
  undefined2 unaff_s5;
  undefined2 unaff_s6;
  int unaff_s7;
  int unaff_gp;
  int unaff_s8;
  int iVar4;
  int iVar5;
  undefined2 in_stack_0000003c;
  undefined2 in_stack_00000040;
  undefined2 in_stack_00000044;
  short in_stack_00000048;
  short in_stack_0000004c;
  short sStack00000050;
  undefined2 uStack00000052;
  undefined2 in_stack_00000054;
  short sStack00000058;
  short sStack0000005a;
  int *in_stack_00000084;
  
  iVar4 = sStack0000005a * unaff_s1;
  if (iVar4 < 0) {
    iVar4 = iVar4 + 0xfff;
  }
  sVar1 = unaff_s0[6];
  if (0x100 < unaff_s0[1]) {
    sStack00000050 = in_stack_00000048 - in_v0;
    uStack00000052 = (undefined2)(((unaff_s8 - unaff_s0[6]) * 0x1000) / unaff_s1);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_00000048 = sStack00000058 + unaff_s0[5];
    iVar5 = sStack0000005a * unaff_s1;
    if (iVar5 < 0) {
      iVar5 = iVar5 + 0xfff;
    }
    unaff_s8 = ((int)unaff_s0[6] + (iVar5 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    sStack00000050 = in_stack_0000004c - unaff_s0[5];
    uStack00000052 = (undefined2)(((unaff_s7 - unaff_s0[6]) * 0x1000) / unaff_s1);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_0000004c = sStack00000058 + unaff_s0[5];
    iVar5 = sStack0000005a * unaff_s1;
    if (iVar5 < 0) {
      iVar5 = iVar5 + 0xfff;
    }
    unaff_s7 = ((int)unaff_s0[6] + (iVar5 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
  }
  iVar5 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
  if (iVar5 == 0) {
    uVar2 = 0;
  }
  else {
    *(undefined1 *)(iVar5 + 3) = 9;
    *(undefined1 *)(iVar5 + 7) = 0x2c;
    *(undefined2 *)(iVar5 + 8) = in_stack_0000003c;
    *(undefined2 *)(iVar5 + 10) = in_stack_00000040;
    *(undefined2 *)(iVar5 + 0x10) = unaff_s5;    // POS.z
    *(undefined2 *)(iVar5 + 0x12) = unaff_s4;
    *(undefined2 *)(iVar5 + 0x18) = in_stack_00000044;
    *(undefined2 *)(iVar5 + 0x1a) = unaff_s6;
    *(undefined2 *)(iVar5 + 0x20) = in_v1;    // ANG.yaw
    uVar3 = (undefined2)((uint)(((int)sVar1 + (iVar4 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    *(undefined2 *)(iVar5 + 0x22) = uVar3;    // ANG.pitch
    *(char *)(iVar5 + 0xc) = (char)unaff_s0[0x14];    // POS.y
    *(char *)(iVar5 + 0xd) = (char)unaff_s0[0x17];
    *(undefined1 *)(iVar5 + 0x14) = *(undefined1 *)((int)unaff_s0 + 0x29);
    *(undefined1 *)(iVar5 + 0x15) = *(undefined1 *)((int)unaff_s0 + 0x2f);
    *(char *)(iVar5 + 0x1c) = (char)unaff_s0[0x15];
    *(char *)(iVar5 + 0x1d) = (char)unaff_s0[0x18];
    *(undefined1 *)(iVar5 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2b);    // ANG.roll
    *(undefined1 *)(iVar5 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x31);
    *(char *)(iVar5 + 4) = (char)unaff_s0[0x1a];
    *(undefined1 *)(iVar5 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
    *(char *)(iVar5 + 6) = (char)unaff_s0[0x1b];
    *(short *)(iVar5 + 0xe) = unaff_s0[0x1e];
    *(short *)(iVar5 + 0x16) = unaff_s0[0x1c];
    FUN_0001c89c(iVar5,(int)unaff_s0[3]);
    FUN_0001c85c(*in_stack_00000084 + *unaff_s0 * 4,iVar5);
    FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    if (0x100 < unaff_s0[1]) {
      iVar4 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
      if (iVar4 == 0) {
        return 0;
      }
      *(undefined1 *)(iVar4 + 3) = 9;
      *(undefined1 *)(iVar4 + 7) = 0x2c;
      *(undefined2 *)(iVar4 + 8) = unaff_s5;
      *(undefined2 *)(iVar4 + 10) = unaff_s4;
      *(short *)(iVar4 + 0x10) = in_stack_00000048;    // POS.z
      *(short *)(iVar4 + 0x12) = (short)unaff_s8;
      *(undefined2 *)(iVar4 + 0x18) = in_v1;
      *(undefined2 *)(iVar4 + 0x1a) = uVar3;
      *(short *)(iVar4 + 0x20) = in_stack_0000004c;    // ANG.yaw
      *(short *)(iVar4 + 0x22) = (short)unaff_s7;    // ANG.pitch
      *(undefined1 *)(iVar4 + 0xc) = 0;    // POS.y
      *(undefined1 *)(iVar4 + 0xd) = *(undefined1 *)((int)unaff_s0 + 0x2f);
      *(char *)(iVar4 + 0x14) = (char)unaff_s0[0x16];
      *(char *)(iVar4 + 0x15) = (char)unaff_s0[0x19];
      *(undefined1 *)(iVar4 + 0x1c) = 0;
      *(undefined1 *)(iVar4 + 0x1d) = *(undefined1 *)((int)unaff_s0 + 0x31);
      *(undefined1 *)(iVar4 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2d);    // ANG.roll
      *(undefined1 *)(iVar4 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x33);
      *(char *)(iVar4 + 4) = (char)unaff_s0[0x1a];
      *(undefined1 *)(iVar4 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
      *(char *)(iVar4 + 6) = (char)unaff_s0[0x1b];
      *(short *)(iVar4 + 0xe) = unaff_s0[0x1e];
      *(short *)(iVar4 + 0x16) = unaff_s0[0x1d];
      FUN_0001c89c(iVar4,(int)unaff_s0[3]);
      FUN_0001c85c(*in_stack_00000084 + *unaff_s0 * 4,iVar4);
      FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    }
    uVar2 = 1;
  }
  return uVar2;
}


---

## FUN_0001e750 (MAIN.EXE) @ 0x01e750


undefined4 FUN_0001e750(short *param_1,int *param_2)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  short sVar6;
  short sVar7;
  short sVar8;
  undefined4 *puVar9;
  int iVar10;
  int unaff_gp;
  short sVar11;
  short local_44;
  short local_40;
  short local_3c;
  short local_38;
  short sStack_34;
  short sStack_30;
  undefined2 uStack_2e;
  undefined2 uStack_2c;
  short sStack_28;
  short sStack_26;
  undefined4 auStack_20 [8];
  
  local_44 = param_1[8];
  local_40 = param_1[9];
  sVar6 = param_1[10];
  local_3c = param_1[0xc];
  sVar5 = param_1[0xb];
  local_38 = param_1[0x10];
  sVar7 = param_1[0xd];
  sStack_34 = param_1[0x12];
  sVar4 = param_1[0xe];
  sVar3 = param_1[0xf];
  sVar11 = param_1[0x11];
  sVar8 = param_1[0x13];
  puVar9 = (undefined4 *)&DAT_8003bf2c;
  puVar2 = auStack_20;
  iVar10 = 8;
  do {
    iVar10 = iVar10 + -1;
    *puVar2 = *puVar9;
    puVar9 = puVar9 + 1;
    puVar2 = puVar2 + 1;
  } while (0 < iVar10);
  if (param_1[4] != 0) {
    FUN_0001f340((int)param_1[4],auStack_20);
    sStack_30 = local_44 - param_1[5];
    uStack_2e = (undefined2)((((int)local_40 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    local_44 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    local_40 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    sStack_30 = sVar6 - param_1[5];
    uStack_2e = (undefined2)((((int)sVar5 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar6 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar5 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    sStack_30 = local_3c - param_1[5];
    uStack_2e = (undefined2)((((int)sVar7 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    local_3c = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sStack_30 = sVar4 - param_1[5];
    sVar7 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    uStack_2e = (undefined2)((((int)sVar3 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar4 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar3 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    if (0x100 < param_1[1]) {
      sStack_30 = local_38 - param_1[5];
      uStack_2e = (undefined2)((((int)sVar11 - (int)param_1[6]) * 0x1000) / 0x780);
      uStack_2c = 0;
      FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
      local_38 = sStack_28 + param_1[5];
      iVar10 = sStack_26 * 0x780;
      if (iVar10 < 0) {
        iVar10 = iVar10 + 0xfff;
      }
      sVar11 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
      sStack_30 = sStack_34 - param_1[5];
      uStack_2e = (undefined2)((((int)sVar8 - (int)param_1[6]) * 0x1000) / 0x780);
      uStack_2c = 0;
      FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
      sStack_34 = sStack_28 + param_1[5];
      iVar10 = sStack_26 * 0x780;
      if (iVar10 < 0) {
        iVar10 = iVar10 + 0xfff;
      }
      sVar8 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    }
  }
  iVar10 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
  if (iVar10 == 0) {
    uVar1 = 0;
  }
  else {
    *(undefined1 *)(iVar10 + 3) = 9;
    *(undefined1 *)(iVar10 + 7) = 0x2c;
    *(short *)(iVar10 + 8) = local_44;
    *(short *)(iVar10 + 10) = local_40;
    *(short *)(iVar10 + 0x10) = sVar6;    // POS.z
    *(short *)(iVar10 + 0x12) = sVar5;
    *(short *)(iVar10 + 0x18) = local_3c;
    *(short *)(iVar10 + 0x1a) = sVar7;
    *(short *)(iVar10 + 0x20) = sVar4;    // ANG.yaw
    *(short *)(iVar10 + 0x22) = sVar3;    // ANG.pitch
    *(char *)(iVar10 + 0xc) = (char)param_1[0x14];    // POS.y
    *(char *)(iVar10 + 0xd) = (char)param_1[0x17];
    *(undefined1 *)(iVar10 + 0x14) = *(undefined1 *)((int)param_1 + 0x29);
    *(undefined1 *)(iVar10 + 0x15) = *(undefined1 *)((int)param_1 + 0x2f);
    *(char *)(iVar10 + 0x1c) = (char)param_1[0x15];
    *(char *)(iVar10 + 0x1d) = (char)param_1[0x18];
    *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2b);    // ANG.roll
    *(undefined1 *)(iVar10 + 0x25) = *(undefined1 *)((int)param_1 + 0x31);
    *(char *)(iVar10 + 4) = (char)param_1[0x1a];
    *(undefined1 *)(iVar10 + 5) = *(undefined1 *)((int)param_1 + 0x35);
    *(char *)(iVar10 + 6) = (char)param_1[0x1b];
    *(short *)(iVar10 + 0xe) = param_1[0x1e];
    *(short *)(iVar10 + 0x16) = param_1[0x1c];
    FUN_0001c89c(iVar10,(int)param_1[3]);
    FUN_0001c85c(*param_2 + *param_1 * 4,iVar10);
    FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    if (0x100 < param_1[1]) {
      iVar10 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
      if (iVar10 == 0) {
        return 0;
      }
      *(undefined1 *)(iVar10 + 3) = 9;
      *(undefined1 *)(iVar10 + 7) = 0x2c;
      *(short *)(iVar10 + 8) = sVar6;
      *(short *)(iVar10 + 10) = sVar5;
      *(short *)(iVar10 + 0x10) = local_38;    // POS.z
      *(short *)(iVar10 + 0x12) = sVar11;
      *(short *)(iVar10 + 0x18) = sVar4;
      *(short *)(iVar10 + 0x1a) = sVar3;
      *(short *)(iVar10 + 0x20) = sStack_34;    // ANG.yaw
      *(short *)(iVar10 + 0x22) = sVar8;    // ANG.pitch
      *(undefined1 *)(iVar10 + 0xc) = 0;    // POS.y
      *(undefined1 *)(iVar10 + 0xd) = *(undefined1 *)((int)param_1 + 0x2f);
      *(char *)(iVar10 + 0x14) = (char)param_1[0x16];
      *(char *)(iVar10 + 0x15) = (char)param_1[0x19];
      *(undefined1 *)(iVar10 + 0x1c) = 0;
      *(undefined1 *)(iVar10 + 0x1d) = *(undefined1 *)((int)param_1 + 0x31);
      *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2d);    // ANG.roll
      *(undefined1 *)(iVar10 + 0x25) = *(undefined1 *)((int)param_1 + 0x33);
      *(char *)(iVar10 + 4) = (char)param_1[0x1a];
      *(undefined1 *)(iVar10 + 5) = *(undefined1 *)((int)param_1 + 0x35);
      *(char *)(iVar10 + 6) = (char)param_1[0x1b];
      *(short *)(iVar10 + 0xe) = param_1[0x1e];
      *(short *)(iVar10 + 0x16) = param_1[0x1d];
      FUN_0001c89c(iVar10,(int)param_1[3]);
      FUN_0001c85c(*param_2 + *param_1 * 4,iVar10);
      FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    }
    uVar1 = 1;
  }
  return uVar1;
}


---

## FUN_0001e7b4 (MAIN.EXE) @ 0x01e7b4


undefined4 FUN_0001e7b4(undefined4 param_1,int *param_2)

{
  int in_v0;
  undefined4 uVar1;
  undefined4 *puVar2;
  short *unaff_s0;
  short sVar3;
  short sVar4;
  int unaff_s4;
  short unaff_s5;
  int unaff_s6;
  short sVar5;
  int in_t8;
  undefined4 *puVar6;
  int iVar7;
  int unaff_gp;
  short sVar8;
  short in_stack_0000003c;
  int in_stack_00000040;
  short in_stack_00000044;
  short in_stack_00000048;
  int iStack0000004c;
  short sStack00000050;
  undefined2 uStack00000052;
  undefined2 in_stack_00000054;
  short sStack00000058;
  short sStack0000005a;
  int *piStack00000084;
  
  sVar4 = unaff_s0[0xe];
  sVar3 = unaff_s0[0xf];
  sVar8 = unaff_s0[0x11];
  sVar5 = unaff_s0[0x13];
  puVar6 = (undefined4 *)(in_t8 + -0x40d4);
  puVar2 = (undefined4 *)&stack0x00000060;
  iVar7 = 8;
  piStack00000084 = param_2;
  do {
    iVar7 = iVar7 + -1;
    *puVar2 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar2 = puVar2 + 1;
  } while (0 < iVar7);
  iStack0000004c = in_v0;
  if (unaff_s0[4] != 0) {
    FUN_0001f340((int)unaff_s0[4],&stack0x00000060);
    sStack00000050 = in_stack_0000003c - unaff_s0[5];
    uStack00000052 = (undefined2)(((in_stack_00000040 - unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_0000003c = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    in_stack_00000040 = ((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    sStack00000050 = unaff_s5 - unaff_s0[5];
    uStack00000052 = (undefined2)(((unaff_s4 - unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    unaff_s5 = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    unaff_s4 = ((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    sStack00000050 = in_stack_00000044 - unaff_s0[5];
    uStack00000052 = (undefined2)(((unaff_s6 - unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_00000044 = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    sStack00000050 = sVar4 - unaff_s0[5];
    unaff_s6 = ((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    uStack00000052 = (undefined2)((((int)sVar3 - (int)unaff_s0[6]) * 0x1000) / 0x780);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    sVar4 = sStack00000058 + unaff_s0[5];
    iVar7 = sStack0000005a * 0x780;
    if (iVar7 < 0) {
      iVar7 = iVar7 + 0xfff;
    }
    sVar3 = (short)((uint)(((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    if (0x100 < unaff_s0[1]) {
      sStack00000050 = in_stack_00000048 - unaff_s0[5];
      uStack00000052 = (undefined2)((((int)sVar8 - (int)unaff_s0[6]) * 0x1000) / 0x780);
      in_stack_00000054 = 0;
      FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
      in_stack_00000048 = sStack00000058 + unaff_s0[5];
      iVar7 = sStack0000005a * 0x780;
      if (iVar7 < 0) {
        iVar7 = iVar7 + 0xfff;
      }
      sVar8 = (short)((uint)(((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
      sStack00000050 = (short)iStack0000004c - unaff_s0[5];
      uStack00000052 = (undefined2)((((int)sVar5 - (int)unaff_s0[6]) * 0x1000) / 0x780);
      in_stack_00000054 = 0;
      FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
      iStack0000004c = ((int)sStack00000058 + (int)unaff_s0[5]) * 0x10000 >> 0x10;
      iVar7 = sStack0000005a * 0x780;
      if (iVar7 < 0) {
        iVar7 = iVar7 + 0xfff;
      }
      sVar5 = (short)((uint)(((int)unaff_s0[6] + (iVar7 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    }
  }
  iVar7 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
  if (iVar7 == 0) {
    uVar1 = 0;
  }
  else {
    *(undefined1 *)(iVar7 + 3) = 9;
    *(undefined1 *)(iVar7 + 7) = 0x2c;
    *(short *)(iVar7 + 8) = in_stack_0000003c;
    *(short *)(iVar7 + 10) = (short)in_stack_00000040;
    *(short *)(iVar7 + 0x10) = unaff_s5;    // POS.z
    *(short *)(iVar7 + 0x12) = (short)unaff_s4;
    *(short *)(iVar7 + 0x18) = in_stack_00000044;
    *(short *)(iVar7 + 0x1a) = (short)unaff_s6;
    *(short *)(iVar7 + 0x20) = sVar4;    // ANG.yaw
    *(short *)(iVar7 + 0x22) = sVar3;    // ANG.pitch
    *(char *)(iVar7 + 0xc) = (char)unaff_s0[0x14];    // POS.y
    *(char *)(iVar7 + 0xd) = (char)unaff_s0[0x17];
    *(undefined1 *)(iVar7 + 0x14) = *(undefined1 *)((int)unaff_s0 + 0x29);
    *(undefined1 *)(iVar7 + 0x15) = *(undefined1 *)((int)unaff_s0 + 0x2f);
    *(char *)(iVar7 + 0x1c) = (char)unaff_s0[0x15];
    *(char *)(iVar7 + 0x1d) = (char)unaff_s0[0x18];
    *(undefined1 *)(iVar7 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2b);    // ANG.roll
    *(undefined1 *)(iVar7 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x31);
    *(char *)(iVar7 + 4) = (char)unaff_s0[0x1a];
    *(undefined1 *)(iVar7 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
    *(char *)(iVar7 + 6) = (char)unaff_s0[0x1b];
    *(short *)(iVar7 + 0xe) = unaff_s0[0x1e];
    *(short *)(iVar7 + 0x16) = unaff_s0[0x1c];
    FUN_0001c89c(iVar7,(int)unaff_s0[3]);
    FUN_0001c85c(*piStack00000084 + *unaff_s0 * 4,iVar7);
    FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    if (0x100 < unaff_s0[1]) {
      iVar7 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
      if (iVar7 == 0) {
        return 0;
      }
      *(undefined1 *)(iVar7 + 3) = 9;
      *(undefined1 *)(iVar7 + 7) = 0x2c;
      *(short *)(iVar7 + 8) = unaff_s5;
      *(short *)(iVar7 + 10) = (short)unaff_s4;
      *(short *)(iVar7 + 0x10) = in_stack_00000048;    // POS.z
      *(short *)(iVar7 + 0x12) = sVar8;
      *(short *)(iVar7 + 0x18) = sVar4;
      *(short *)(iVar7 + 0x1a) = sVar3;
      *(short *)(iVar7 + 0x20) = (short)iStack0000004c;    // ANG.yaw
      *(short *)(iVar7 + 0x22) = sVar5;    // ANG.pitch
      *(undefined1 *)(iVar7 + 0xc) = 0;    // POS.y
      *(undefined1 *)(iVar7 + 0xd) = *(undefined1 *)((int)unaff_s0 + 0x2f);
      *(char *)(iVar7 + 0x14) = (char)unaff_s0[0x16];
      *(char *)(iVar7 + 0x15) = (char)unaff_s0[0x19];
      *(undefined1 *)(iVar7 + 0x1c) = 0;
      *(undefined1 *)(iVar7 + 0x1d) = *(undefined1 *)((int)unaff_s0 + 0x31);
      *(undefined1 *)(iVar7 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2d);    // ANG.roll
      *(undefined1 *)(iVar7 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x33);
      *(char *)(iVar7 + 4) = (char)unaff_s0[0x1a];
      *(undefined1 *)(iVar7 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
      *(char *)(iVar7 + 6) = (char)unaff_s0[0x1b];
      *(short *)(iVar7 + 0xe) = unaff_s0[0x1e];
      *(short *)(iVar7 + 0x16) = unaff_s0[0x1d];
      FUN_0001c89c(iVar7,(int)unaff_s0[3]);
      FUN_0001c85c(*piStack00000084 + *unaff_s0 * 4,iVar7);
      FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    }
    uVar1 = 1;
  }
  return uVar1;
}


---

## FUN_0001ea04 (MAIN.EXE) @ 0x01ea04


undefined4 FUN_0001ea04(void)

{
  short sVar1;
  short in_v0;
  undefined4 uVar2;
  undefined2 in_v1;
  short *unaff_s0;
  int unaff_s1;
  undefined2 uVar3;
  undefined2 unaff_s4;
  undefined2 unaff_s5;
  undefined2 unaff_s6;
  int unaff_s7;
  int unaff_gp;
  int unaff_s8;
  int iVar4;
  int iVar5;
  undefined2 in_stack_0000003c;
  undefined2 in_stack_00000040;
  undefined2 in_stack_00000044;
  short in_stack_00000048;
  short in_stack_0000004c;
  short sStack00000050;
  undefined2 uStack00000052;
  undefined2 in_stack_00000054;
  short sStack00000058;
  short sStack0000005a;
  int *in_stack_00000084;
  
  iVar4 = sStack0000005a * unaff_s1;
  if (iVar4 < 0) {
    iVar4 = iVar4 + 0xfff;
  }
  sVar1 = unaff_s0[6];
  if (0x100 < unaff_s0[1]) {
    sStack00000050 = in_stack_00000048 - in_v0;
    uStack00000052 = (undefined2)(((unaff_s8 - unaff_s0[6]) * 0x1000) / unaff_s1);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_00000048 = sStack00000058 + unaff_s0[5];
    iVar5 = sStack0000005a * unaff_s1;
    if (iVar5 < 0) {
      iVar5 = iVar5 + 0xfff;
    }
    unaff_s8 = ((int)unaff_s0[6] + (iVar5 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
    sStack00000050 = in_stack_0000004c - unaff_s0[5];
    uStack00000052 = (undefined2)(((unaff_s7 - unaff_s0[6]) * 0x1000) / unaff_s1);
    in_stack_00000054 = 0;
    FUN_0001eb14(&stack0x00000060,&stack0x00000050,&stack0x00000058);
    in_stack_0000004c = sStack00000058 + unaff_s0[5];
    iVar5 = sStack0000005a * unaff_s1;
    if (iVar5 < 0) {
      iVar5 = iVar5 + 0xfff;
    }
    unaff_s7 = ((int)unaff_s0[6] + (iVar5 >> 0xc)) * 0x10000 >> 0x10;    // Q12_SHIFT Q12_PROD
  }
  iVar5 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
  if (iVar5 == 0) {
    uVar2 = 0;
  }
  else {
    *(undefined1 *)(iVar5 + 3) = 9;
    *(undefined1 *)(iVar5 + 7) = 0x2c;
    *(undefined2 *)(iVar5 + 8) = in_stack_0000003c;
    *(undefined2 *)(iVar5 + 10) = in_stack_00000040;
    *(undefined2 *)(iVar5 + 0x10) = unaff_s5;    // POS.z
    *(undefined2 *)(iVar5 + 0x12) = unaff_s4;
    *(undefined2 *)(iVar5 + 0x18) = in_stack_00000044;
    *(undefined2 *)(iVar5 + 0x1a) = unaff_s6;
    *(undefined2 *)(iVar5 + 0x20) = in_v1;    // ANG.yaw
    uVar3 = (undefined2)((uint)(((int)sVar1 + (iVar4 >> 0xc)) * 0x10000) >> 0x10);    // Q12_SHIFT Q12_PROD
    *(undefined2 *)(iVar5 + 0x22) = uVar3;    // ANG.pitch
    *(char *)(iVar5 + 0xc) = (char)unaff_s0[0x14];    // POS.y
    *(char *)(iVar5 + 0xd) = (char)unaff_s0[0x17];
    *(undefined1 *)(iVar5 + 0x14) = *(undefined1 *)((int)unaff_s0 + 0x29);
    *(undefined1 *)(iVar5 + 0x15) = *(undefined1 *)((int)unaff_s0 + 0x2f);
    *(char *)(iVar5 + 0x1c) = (char)unaff_s0[0x15];
    *(char *)(iVar5 + 0x1d) = (char)unaff_s0[0x18];
    *(undefined1 *)(iVar5 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2b);    // ANG.roll
    *(undefined1 *)(iVar5 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x31);
    *(char *)(iVar5 + 4) = (char)unaff_s0[0x1a];
    *(undefined1 *)(iVar5 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
    *(char *)(iVar5 + 6) = (char)unaff_s0[0x1b];
    *(short *)(iVar5 + 0xe) = unaff_s0[0x1e];
    *(short *)(iVar5 + 0x16) = unaff_s0[0x1c];
    FUN_0001c89c(iVar5,(int)unaff_s0[3]);
    FUN_0001c85c(*in_stack_00000084 + *unaff_s0 * 4,iVar5);
    FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    if (0x100 < unaff_s0[1]) {
      iVar4 = FUN_00036b44(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
      if (iVar4 == 0) {
        return 0;
      }
      *(undefined1 *)(iVar4 + 3) = 9;
      *(undefined1 *)(iVar4 + 7) = 0x2c;
      *(undefined2 *)(iVar4 + 8) = unaff_s5;
      *(undefined2 *)(iVar4 + 10) = unaff_s4;
      *(short *)(iVar4 + 0x10) = in_stack_00000048;    // POS.z
      *(short *)(iVar4 + 0x12) = (short)unaff_s8;
      *(undefined2 *)(iVar4 + 0x18) = in_v1;
      *(undefined2 *)(iVar4 + 0x1a) = uVar3;
      *(short *)(iVar4 + 0x20) = in_stack_0000004c;    // ANG.yaw
      *(short *)(iVar4 + 0x22) = (short)unaff_s7;    // ANG.pitch
      *(undefined1 *)(iVar4 + 0xc) = 0;    // POS.y
      *(undefined1 *)(iVar4 + 0xd) = *(undefined1 *)((int)unaff_s0 + 0x2f);
      *(char *)(iVar4 + 0x14) = (char)unaff_s0[0x16];
      *(char *)(iVar4 + 0x15) = (char)unaff_s0[0x19];
      *(undefined1 *)(iVar4 + 0x1c) = 0;
      *(undefined1 *)(iVar4 + 0x1d) = *(undefined1 *)((int)unaff_s0 + 0x31);
      *(undefined1 *)(iVar4 + 0x24) = *(undefined1 *)((int)unaff_s0 + 0x2d);    // ANG.roll
      *(undefined1 *)(iVar4 + 0x25) = *(undefined1 *)((int)unaff_s0 + 0x33);
      *(char *)(iVar4 + 4) = (char)unaff_s0[0x1a];
      *(undefined1 *)(iVar4 + 5) = *(undefined1 *)((int)unaff_s0 + 0x35);
      *(char *)(iVar4 + 6) = (char)unaff_s0[0x1b];
      *(short *)(iVar4 + 0xe) = unaff_s0[0x1e];
      *(short *)(iVar4 + 0x16) = unaff_s0[0x1d];
      FUN_0001c89c(iVar4,(int)unaff_s0[3]);
      FUN_0001c85c(*in_stack_00000084 + *unaff_s0 * 4,iVar4);
      FUN_00036d20(*(undefined4 *)(unaff_gp + -0x7df8),5,1);
    }
    uVar2 = 1;
  }
  return uVar2;
}


---

