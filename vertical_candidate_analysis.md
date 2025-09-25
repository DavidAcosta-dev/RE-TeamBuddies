# Vertical Candidate Function Decompilation (Annotated)

## FUN_00032c18 (ea=0x32c18, size=1124)


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
  
  param_1 = param_1 & 0xffff;    // MASK_0xFFF
  iVar2 = func_0x000f5b78(param_1,0);
  *(uint *)(iVar2 + 300) = param_1;
  *(undefined4 *)(iVar2 + 0x128) = *param_2;    // POTENTIAL_Y(0x128)
  uVar3 = func_0x000743a4(1,param_1);
  *(undefined4 *)(iVar2 + 0x134) = uVar3;    // POTENTIAL_Y(0x134)
  *(short *)(iVar2 + 0x138) = (short)((uint)param_2[4] >> 6);    // POTENTIAL_Y(0x138)
  *(short *)(iVar2 + 0x13a) = (short)((uint)param_2[5] >> 6);    // POTENTIAL_Y(0x13a)
  *(short *)(iVar2 + 0x13c) = (short)((uint)param_2[6] >> 6);    // POTENTIAL_Y(0x13c)
  sVar6 = (short)((uint)param_2[7] >> 6);
  *(short *)(iVar2 + 0x13e) = sVar6;    // POTENTIAL_Y(0x13e)
  sVar4 = (short)((uint)param_2[8] >> 0xc);    // SHIFT_Q12
  *(short *)(iVar2 + 0x140) = sVar4;    // POTENTIAL_Y(0x140)
  *(short *)(iVar2 + 0x142) = (short)((uint)-param_2[9] >> 6);    // POTENTIAL_Y(0x142)
  *(short *)(iVar2 + 0x144) = (short)((uint)param_2[10] >> 0xc);    // POTENTIAL_Y(0x144) SHIFT_Q12
  *(short *)(iVar2 + 0x146) = (short)((uint)param_2[0xb] >> 0xc);    // POTENTIAL_Y(0x146) SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x148) = *(undefined2 *)(param_2 + 0xd);    // POTENTIAL_Y(0x148)
  *(undefined2 *)(iVar2 + 0x14a) = *(undefined2 *)(param_2 + 0xe);    // POTENTIAL_Y(0x14a)
  *(undefined2 *)(iVar2 + 0x14c) = *(undefined2 *)(param_2 + 0x10);    // POTENTIAL_Y(0x14c)
  iVar8 = (int)sVar6;
  *(short *)(iVar2 + 0x14e) = (short)((uint)param_2[0x12] >> 6);    // POTENTIAL_Y(0x14e)
  if (iVar8 != 0) {
    if (iVar8 == 0) {
      trap(7);
    }
    *(short *)(iVar2 + 0x152) = (short)((sVar4 * 0x477) / iVar8);
  }
  *(undefined2 *)(iVar2 + 0x154) = *(undefined2 *)(param_2 + 0x18);
  *(short *)(iVar2 + 0x156) = (short)((uint)(param_2[0x18] * param_2[0x1b]) >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x15a) = *(undefined2 *)(param_2 + 0x19);
  *(undefined2 *)(iVar2 + 0x158) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar2 + 0x15c) = *(undefined2 *)(param_2 + 0x1c);
  *(undefined2 *)(iVar2 + 0x15e) = *(undefined2 *)(param_2 + 0x16);
  *(undefined2 *)(iVar2 + 0x150) = *(undefined2 *)(param_2 + 0x17);
  *(short *)(iVar2 + 0x160) = (short)((uint)param_2[0x1d] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x162) = *(undefined2 *)(param_2 + 0x21);
  *(short *)(iVar2 + 0x164) = (short)((uint)param_2[0x1f] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x166) = *(undefined2 *)(param_2 + 0x22);
  *(short *)(iVar2 + 0x168) = (short)((uint)param_2[0x1e] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x16a) = *(undefined2 *)(param_2 + 0x23);
  *(short *)(iVar2 + 0x16c) = (short)((uint)param_2[0x20] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x16e) = *(undefined2 *)(param_2 + 0x24);
  *(short *)(iVar2 + 0x170) = (short)((uint)param_2[0x15] >> 0xc);    // SHIFT_Q12
  sVar4 = (short)((uint)param_2[0x14] >> 6);
  *(short *)(iVar2 + 0x172) = sVar4;
  sVar6 = *(short *)(iVar2 + 0x128);    // POTENTIAL_Y(0x128)
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
  *(undefined4 *)(iVar2 + 0x130) = param_2[0x25];    // POTENTIAL_Y(0x130)
  puVar7 = (undefined2 *)(iVar2 + 0xca);
  *(undefined2 *)(iVar2 + 0x18a) = *(undefined2 *)(param_2 + 0x26);
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
      *(undefined2 *)(iVar2 + 0x11a) = 0;    // POTENTIAL_Y(0x11a)
      *(undefined2 *)(iVar2 + 0x11c) = 0xff60;    // POTENTIAL_Y(0x11c)
      *(undefined2 *)(iVar2 + 0x11e) = 0xfe8e;    // POTENTIAL_Y(0x11e)
      *(undefined2 *)(iVar2 + 0x120) = 0;    // POTENTIAL_Y(0x120)
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if (param_1 == 0x4c) {
      *(undefined2 *)(iVar2 + 0x11c) = 0xfe70;    // POTENTIAL_Y(0x11c)
      *(undefined2 *)(iVar2 + 0x11a) = 0;    // POTENTIAL_Y(0x11a)
      *(undefined2 *)(iVar2 + 0x11e) = 0;    // POTENTIAL_Y(0x11e)
      *(undefined2 *)(iVar2 + 0x120) = 1;    // POTENTIAL_Y(0x120)
    }
    if (sVar6 == 6) {
      if (*(short *)(iVar2 + 0x13e) == 0) {    // POTENTIAL_Y(0x13e)
        trap(7);
      }
      iVar8 = (int)_DAT_8011966e * (int)_DAT_8011966e;
      if (iVar8 == 0) {
        trap(7);
      }
      *(short *)(iVar2 + 0xb2) =
           (short)((((int)*(short *)(iVar2 + 0x138) * (int)*(short *)(iVar2 + 0x138)) /    // POTENTIAL_Y(0x138) POTENTIAL_Y(0x138)
                    (int)*(short *)(iVar2 + 0x13e) << 0x11) / iVar8);    // POTENTIAL_Y(0x13e)
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00044a14 (ea=0x44a14, size=1388)


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
     ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44))) {
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) | 4;
  }
  if (*(short *)(param_1 + 10) <= iVar2) {
    return;
  }
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 5) == '\x04') && (0 < *(int *)(param_1 + 0xbc))) {
    if ((*(short *)(param_1 + 0x34) != 0) || (*(short *)(param_1 + 0x38) != 0)) {
      *(undefined2 *)(param_1 + 0x36) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    uVar1 = 0xffff;
    if (*(short *)(param_1 + 0x36) == 0) {
      uVar1 = 0xfff6;
    }
    *(undefined2 *)(param_1 + 0x36) = uVar1;
    *(short *)(param_1 + 0x44) =
         (short)((int)*(short *)(param_1 + 0x3c) * (int)*(short *)(param_1 + 0x34) +
                 (int)*(short *)(param_1 + 0x3e) * (int)*(short *)(param_1 + 0x36) +
                 (int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc);    // SHIFT_Q12
    uVar1 = func_0x000ab4d0(param_1 + 8);
    *(undefined2 *)(param_1 + 10) = uVar1;
    iVar2 = func_0x000a9678((int)*(short *)(param_1 + 8),(int)*(short *)(param_1 + 0xc));
    if (iVar2 != 0) {
      *(undefined2 *)(param_1 + 0x44) = 0;
    }
    func_0x00109ff4(param_1);
    if (*(short *)(param_1 + 0x44) == 0) {
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // MASK_0xFFF
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
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x36)) >> 0xc),    // SHIFT_Q12
                        *(short *)(param_1 + 8) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x34)) >> 0xc));    // SHIFT_Q12
    local_1c = CONCAT22(local_1c._2_2_,
                        *(short *)(param_1 + 0xc) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x38)) >> 0xc));    // SHIFT_Q12
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
  *(undefined4 *)(param_1 + 0xc) = local_1c;
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
      uVar4 = uVar5 & 0xfffffff7;    // MASK_0xFFF
    }
    *(uint *)(param_1 + 0xd0) = uVar4;
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0) {
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
    *(short *)(param_1 + 0x36) = (short)((int)-((int)*(short *)(param_1 + 0x36) * uVar4) >> 0xc);    // SHIFT_Q12
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 1 & 1) != 0) {
      uVar5 = *(uint *)((*(ushort *)(param_1 + 200) & 0x7f) * 4 + -0x7ffeb164);
      uVar4 = uVar5 >> 0x10;
      setCopControlWord(2,0,uVar4);
      uVar5 = uVar5 & 0xffff;    // MASK_0xFFF
      setCopControlWord(2,0x2000,uVar4);
      setCopControlWord(2,0x800,uVar5);
      setCopControlWord(2,0x1000,0x1000);
      setCopControlWord(2,0x1800,-uVar5 & 0xffff);    // MASK_0xFFF
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x34));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x36));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x38));
      copFunction(2,0x49e012);
      uVar6 = getCopReg(2,0x4800);
      uVar7 = getCopReg(2,0x5000);
      uVar8 = getCopReg(2,0x5800);
      *(short *)(param_1 + 0x34) = (short)uVar6;
      *(short *)(param_1 + 0x36) = (short)uVar7;
      *(short *)(param_1 + 0x38) = (short)uVar8;
    }
    func_0x00109ff4(param_1);
    if ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44)) {
      uVar1 = (undefined2)
              ((int)*(short *)(param_1 + 0x34) * (int)*(short *)(param_1 + 0x3c) +
               (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +
               (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc);    // SHIFT_Q12
      *(undefined2 *)(param_1 + 0xc4) = uVar1;
      *(undefined2 *)(param_1 + 0x44) = uVar1;
    }
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffdff | 0x40;    // MASK_0xFFF
    func_0x00076790(param_1);
    uVar4 = (uint)(*(ushort *)(*(int *)(param_1 + 0xb8) + 8) >> 3);
    if (uVar4 < 3) {
      uVar4 = 3;
    }
    iVar2 = (int)*(short *)(param_1 + 0x36);
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    if (((iVar2 <= (int)uVar4) || ((int)*(short *)(param_1 + 0x44) <= (int)uVar4)) &&
       (func_0x0010a4f8(param_1), (*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0)) {
      *(undefined2 *)(param_1 + 0xc0) = 0;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 3;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  return;
}


---

## FUN_00044f80 (ea=0x44f80, size=1912)


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
    iVar12 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)
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
        uVar8 = *(uint *)(*(int *)(param_1 + 0xb8) + 0x20);
        if ((uVar8 >> 4 & 1) != 0) {
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);
          sVar3 = 0x80;
          if (0x80 < (int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1)) {
            sVar3 = *(short *)(param_1 + 0x44) - uVar1;
          }
          sVar6 = *(short *)(param_1 + 10);
          *(short *)(param_1 + 0x44) = sVar3;
          iVar12 = func_0x000ab4d0(param_1 + 8);
          if ((((int)sVar6 < iVar12 + -0x100) && (*(short *)(param_1 + 0x3e) < 1)) &&
             (iVar12 = -(int)*(short *)(param_1 + 0x3e), (*(uint *)(param_1 + 0x50) & 4) == 0)) {
            if (iVar12 < 0x20) {
              iVar12 = 0x20;
            }
            *(short *)(param_1 + 0x3e) = (short)iVar12;
            func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                            param_1 + 0x3c);
          }
          iVar12 = (int)*(short *)(param_1 + 0x44);
          *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);    // SHIFT_Q12
          *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);    // SHIFT_Q12
          *(short *)(param_1 + 0x38) = (short)(*(short *)(param_1 + 0x40) * iVar12 >> 0xc);    // SHIFT_Q12
          halt_baddata();
        }
        if ((uVar8 >> 3 & 1) == 0) {
          func_0x00109e70(param_1);
          func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                          param_1 + 0x3c);
          halt_baddata();
        }
        return;
      }
    }
    iVar11 = (int)(((uint)*(ushort *)(param_1 + 8) - (uint)*(ushort *)(iVar12 + 0x6c)) * 0x10000) >>
             0x10;
    iVar10 = (int)(((uint)*(ushort *)(param_1 + 10) - (uint)*(ushort *)(iVar12 + 0x6e)) * 0x10000)
             >> 0x10;
    iVar9 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)
            >> 0x10;
    uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
    if (uVar8 * uVar8 < (uint)(iVar11 * iVar11 + iVar10 * iVar10 + iVar9 * iVar9)) {
      local_50 = CONCAT22(*(short *)(iVar12 + 0x6e) - *(ushort *)(param_1 + 10),
                          *(short *)(iVar12 + 0x6c) - *(ushort *)(param_1 + 8));
      local_2c = CONCAT22(uStack_4a,*(short *)(iVar12 + 0x70) - *(ushort *)(param_1 + 0xc));
      local_30 = local_50;
      func_0x00109758(param_1,local_50,local_2c,&local_48);
      local_30 = CONCAT22(local_46 - *(short *)(param_1 + 0x3e),
                          local_48 - *(short *)(param_1 + 0x3c));
      local_2c = CONCAT22(local_2c._2_2_,local_44 - *(short *)(param_1 + 0x40));
      local_20 = local_30;
      local_1c = local_2c;
      func_0x00109758(param_1,local_30,local_2c,auStack_28);
      iVar12 = func_0x0010a95c(param_1,param_1 + 0x3c,&local_48,auStack_40);
      iVar9 = (int)*(short *)(param_1 + 0x3c) * (int)local_48 +
              (int)*(short *)(param_1 + 0x3e) * (int)local_46 +
              (int)*(short *)(param_1 + 0x40) * (int)local_44 >> 0xc;    // SHIFT_Q12
      func_0x0010a95c(param_1,auStack_40,param_1 + 0x3c,&local_38);
      local_20 = local_38;
      local_1c = local_34;
      func_0x00109758(param_1,local_38,local_34,&local_38);
      if (4000 < iVar9) {
        iVar11 = iVar12;
        if (iVar12 < 0) {
          iVar11 = -iVar12;
        }
        if (iVar11 < 1000) {
          if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {
            return;
          }
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
      if ((iVar12 == 0) && (iVar9 < 0)) {
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) != 0) {
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);
          sVar3 = *(short *)(param_1 + 0x44) - uVar1;
          if ((int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1) < 1) {
            sVar3 = 0;
          }
          *(short *)(param_1 + 0x44) = sVar3;
        }
        func_0x0010a6ec(param_1);
      }
      else {
        uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x12);
        bVar2 = iVar9 < *(short *)((uVar8 & 0xfff) * 4 + -0x7ffeb162);    // MASK_0xFFF
        if (bVar2) {
          if (iVar12 < 0) {
            uVar8 = 0x1000 - uVar8 & 0xfff;    // MASK_0xFFF
          }
          iVar9 = (uVar8 & 0xfff) * 4;    // MASK_0xFFF
          iVar12 = (int)*(short *)(iVar9 + -0x7ffeb164);
          iVar9 = (int)*(short *)(iVar9 + -0x7ffeb162);
        }
        iVar11 = (int)*(short *)(param_1 + 0x44);
        sVar7 = (short)(iVar9 * *(short *)(param_1 + 0x3c) + iVar12 * (short)local_38 >> 0xc);    // SHIFT_Q12
        sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc);    // SHIFT_Q12
        sVar6 = (short)(iVar9 * *(short *)(param_1 + 0x40) + iVar12 * (short)local_34 >> 0xc);    // SHIFT_Q12
        *(short *)(param_1 + 0x3c) = sVar7;
        *(short *)(param_1 + 0x3e) = sVar3;
        *(short *)(param_1 + 0x40) = sVar6;
        *(short *)(param_1 + 0x34) = (short)(sVar7 * iVar11 >> 0xc);    // SHIFT_Q12
        *(short *)(param_1 + 0x36) = (short)(sVar3 * iVar11 >> 0xc);    // SHIFT_Q12
        *(short *)(param_1 + 0x38) = (short)(sVar6 * iVar11 >> 0xc);    // SHIFT_Q12
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {
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
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // MASK_0xFFF
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_0001e750 (ea=0x1e750, size=100)


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
    local_40 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
    sStack_30 = sVar6 - param_1[5];
    uStack_2e = (undefined2)((((int)sVar5 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar6 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar5 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
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
    sVar7 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
    uStack_2e = (undefined2)((((int)sVar3 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar4 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar3 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
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
      sVar11 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
      sStack_30 = sStack_34 - param_1[5];
      uStack_2e = (undefined2)((((int)sVar8 - (int)param_1[6]) * 0x1000) / 0x780);
      uStack_2c = 0;
      FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
      sStack_34 = sStack_28 + param_1[5];
      iVar10 = sStack_26 * 0x780;
      if (iVar10 < 0) {
        iVar10 = iVar10 + 0xfff;
      }
      sVar8 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
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
    *(short *)(iVar10 + 0x10) = sVar6;
    *(short *)(iVar10 + 0x12) = sVar5;
    *(short *)(iVar10 + 0x18) = local_3c;
    *(short *)(iVar10 + 0x1a) = sVar7;
    *(short *)(iVar10 + 0x20) = sVar4;
    *(short *)(iVar10 + 0x22) = sVar3;
    *(char *)(iVar10 + 0xc) = (char)param_1[0x14];
    *(char *)(iVar10 + 0xd) = (char)param_1[0x17];
    *(undefined1 *)(iVar10 + 0x14) = *(undefined1 *)((int)param_1 + 0x29);
    *(undefined1 *)(iVar10 + 0x15) = *(undefined1 *)((int)param_1 + 0x2f);
    *(char *)(iVar10 + 0x1c) = (char)param_1[0x15];
    *(char *)(iVar10 + 0x1d) = (char)param_1[0x18];
    *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2b);
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
      *(short *)(iVar10 + 0x10) = local_38;
      *(short *)(iVar10 + 0x12) = sVar11;
      *(short *)(iVar10 + 0x18) = sVar4;
      *(short *)(iVar10 + 0x1a) = sVar3;
      *(short *)(iVar10 + 0x20) = sStack_34;
      *(short *)(iVar10 + 0x22) = sVar8;
      *(undefined1 *)(iVar10 + 0xc) = 0;
      *(undefined1 *)(iVar10 + 0xd) = *(undefined1 *)((int)param_1 + 0x2f);
      *(char *)(iVar10 + 0x14) = (char)param_1[0x16];
      *(char *)(iVar10 + 0x15) = (char)param_1[0x19];
      *(undefined1 *)(iVar10 + 0x1c) = 0;
      *(undefined1 *)(iVar10 + 0x1d) = *(undefined1 *)((int)param_1 + 0x31);
      *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2d);
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

## FUN_00032c18 (ea=0x32c18, size=1124)


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
  
  param_1 = param_1 & 0xffff;    // MASK_0xFFF
  iVar2 = func_0x000f5b78(param_1,0);
  *(uint *)(iVar2 + 300) = param_1;
  *(undefined4 *)(iVar2 + 0x128) = *param_2;    // POTENTIAL_Y(0x128)
  uVar3 = func_0x000743a4(1,param_1);
  *(undefined4 *)(iVar2 + 0x134) = uVar3;    // POTENTIAL_Y(0x134)
  *(short *)(iVar2 + 0x138) = (short)((uint)param_2[4] >> 6);    // POTENTIAL_Y(0x138)
  *(short *)(iVar2 + 0x13a) = (short)((uint)param_2[5] >> 6);    // POTENTIAL_Y(0x13a)
  *(short *)(iVar2 + 0x13c) = (short)((uint)param_2[6] >> 6);    // POTENTIAL_Y(0x13c)
  sVar6 = (short)((uint)param_2[7] >> 6);
  *(short *)(iVar2 + 0x13e) = sVar6;    // POTENTIAL_Y(0x13e)
  sVar4 = (short)((uint)param_2[8] >> 0xc);    // SHIFT_Q12
  *(short *)(iVar2 + 0x140) = sVar4;    // POTENTIAL_Y(0x140)
  *(short *)(iVar2 + 0x142) = (short)((uint)-param_2[9] >> 6);    // POTENTIAL_Y(0x142)
  *(short *)(iVar2 + 0x144) = (short)((uint)param_2[10] >> 0xc);    // POTENTIAL_Y(0x144) SHIFT_Q12
  *(short *)(iVar2 + 0x146) = (short)((uint)param_2[0xb] >> 0xc);    // POTENTIAL_Y(0x146) SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x148) = *(undefined2 *)(param_2 + 0xd);    // POTENTIAL_Y(0x148)
  *(undefined2 *)(iVar2 + 0x14a) = *(undefined2 *)(param_2 + 0xe);    // POTENTIAL_Y(0x14a)
  *(undefined2 *)(iVar2 + 0x14c) = *(undefined2 *)(param_2 + 0x10);    // POTENTIAL_Y(0x14c)
  iVar8 = (int)sVar6;
  *(short *)(iVar2 + 0x14e) = (short)((uint)param_2[0x12] >> 6);    // POTENTIAL_Y(0x14e)
  if (iVar8 != 0) {
    if (iVar8 == 0) {
      trap(7);
    }
    *(short *)(iVar2 + 0x152) = (short)((sVar4 * 0x477) / iVar8);
  }
  *(undefined2 *)(iVar2 + 0x154) = *(undefined2 *)(param_2 + 0x18);
  *(short *)(iVar2 + 0x156) = (short)((uint)(param_2[0x18] * param_2[0x1b]) >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x15a) = *(undefined2 *)(param_2 + 0x19);
  *(undefined2 *)(iVar2 + 0x158) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar2 + 0x15c) = *(undefined2 *)(param_2 + 0x1c);
  *(undefined2 *)(iVar2 + 0x15e) = *(undefined2 *)(param_2 + 0x16);
  *(undefined2 *)(iVar2 + 0x150) = *(undefined2 *)(param_2 + 0x17);
  *(short *)(iVar2 + 0x160) = (short)((uint)param_2[0x1d] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x162) = *(undefined2 *)(param_2 + 0x21);
  *(short *)(iVar2 + 0x164) = (short)((uint)param_2[0x1f] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x166) = *(undefined2 *)(param_2 + 0x22);
  *(short *)(iVar2 + 0x168) = (short)((uint)param_2[0x1e] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x16a) = *(undefined2 *)(param_2 + 0x23);
  *(short *)(iVar2 + 0x16c) = (short)((uint)param_2[0x20] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x16e) = *(undefined2 *)(param_2 + 0x24);
  *(short *)(iVar2 + 0x170) = (short)((uint)param_2[0x15] >> 0xc);    // SHIFT_Q12
  sVar4 = (short)((uint)param_2[0x14] >> 6);
  *(short *)(iVar2 + 0x172) = sVar4;
  sVar6 = *(short *)(iVar2 + 0x128);    // POTENTIAL_Y(0x128)
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
  *(undefined4 *)(iVar2 + 0x130) = param_2[0x25];    // POTENTIAL_Y(0x130)
  puVar7 = (undefined2 *)(iVar2 + 0xca);
  *(undefined2 *)(iVar2 + 0x18a) = *(undefined2 *)(param_2 + 0x26);
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
      *(undefined2 *)(iVar2 + 0x11a) = 0;    // POTENTIAL_Y(0x11a)
      *(undefined2 *)(iVar2 + 0x11c) = 0xff60;    // POTENTIAL_Y(0x11c)
      *(undefined2 *)(iVar2 + 0x11e) = 0xfe8e;    // POTENTIAL_Y(0x11e)
      *(undefined2 *)(iVar2 + 0x120) = 0;    // POTENTIAL_Y(0x120)
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if (param_1 == 0x4c) {
      *(undefined2 *)(iVar2 + 0x11c) = 0xfe70;    // POTENTIAL_Y(0x11c)
      *(undefined2 *)(iVar2 + 0x11a) = 0;    // POTENTIAL_Y(0x11a)
      *(undefined2 *)(iVar2 + 0x11e) = 0;    // POTENTIAL_Y(0x11e)
      *(undefined2 *)(iVar2 + 0x120) = 1;    // POTENTIAL_Y(0x120)
    }
    if (sVar6 == 6) {
      if (*(short *)(iVar2 + 0x13e) == 0) {    // POTENTIAL_Y(0x13e)
        trap(7);
      }
      iVar8 = (int)_DAT_8011966e * (int)_DAT_8011966e;
      if (iVar8 == 0) {
        trap(7);
      }
      *(short *)(iVar2 + 0xb2) =
           (short)((((int)*(short *)(iVar2 + 0x138) * (int)*(short *)(iVar2 + 0x138)) /    // POTENTIAL_Y(0x138) POTENTIAL_Y(0x138)
                    (int)*(short *)(iVar2 + 0x13e) << 0x11) / iVar8);    // POTENTIAL_Y(0x13e)
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00044a14 (ea=0x44a14, size=1388)


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
     ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44))) {
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) | 4;
  }
  if (*(short *)(param_1 + 10) <= iVar2) {
    return;
  }
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 5) == '\x04') && (0 < *(int *)(param_1 + 0xbc))) {
    if ((*(short *)(param_1 + 0x34) != 0) || (*(short *)(param_1 + 0x38) != 0)) {
      *(undefined2 *)(param_1 + 0x36) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    uVar1 = 0xffff;
    if (*(short *)(param_1 + 0x36) == 0) {
      uVar1 = 0xfff6;
    }
    *(undefined2 *)(param_1 + 0x36) = uVar1;
    *(short *)(param_1 + 0x44) =
         (short)((int)*(short *)(param_1 + 0x3c) * (int)*(short *)(param_1 + 0x34) +
                 (int)*(short *)(param_1 + 0x3e) * (int)*(short *)(param_1 + 0x36) +
                 (int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc);    // SHIFT_Q12
    uVar1 = func_0x000ab4d0(param_1 + 8);
    *(undefined2 *)(param_1 + 10) = uVar1;
    iVar2 = func_0x000a9678((int)*(short *)(param_1 + 8),(int)*(short *)(param_1 + 0xc));
    if (iVar2 != 0) {
      *(undefined2 *)(param_1 + 0x44) = 0;
    }
    func_0x00109ff4(param_1);
    if (*(short *)(param_1 + 0x44) == 0) {
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // MASK_0xFFF
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
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x36)) >> 0xc),    // SHIFT_Q12
                        *(short *)(param_1 + 8) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x34)) >> 0xc));    // SHIFT_Q12
    local_1c = CONCAT22(local_1c._2_2_,
                        *(short *)(param_1 + 0xc) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x38)) >> 0xc));    // SHIFT_Q12
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
  *(undefined4 *)(param_1 + 0xc) = local_1c;
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
      uVar4 = uVar5 & 0xfffffff7;    // MASK_0xFFF
    }
    *(uint *)(param_1 + 0xd0) = uVar4;
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0) {
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
    *(short *)(param_1 + 0x36) = (short)((int)-((int)*(short *)(param_1 + 0x36) * uVar4) >> 0xc);    // SHIFT_Q12
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 1 & 1) != 0) {
      uVar5 = *(uint *)((*(ushort *)(param_1 + 200) & 0x7f) * 4 + -0x7ffeb164);
      uVar4 = uVar5 >> 0x10;
      setCopControlWord(2,0,uVar4);
      uVar5 = uVar5 & 0xffff;    // MASK_0xFFF
      setCopControlWord(2,0x2000,uVar4);
      setCopControlWord(2,0x800,uVar5);
      setCopControlWord(2,0x1000,0x1000);
      setCopControlWord(2,0x1800,-uVar5 & 0xffff);    // MASK_0xFFF
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x34));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x36));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x38));
      copFunction(2,0x49e012);
      uVar6 = getCopReg(2,0x4800);
      uVar7 = getCopReg(2,0x5000);
      uVar8 = getCopReg(2,0x5800);
      *(short *)(param_1 + 0x34) = (short)uVar6;
      *(short *)(param_1 + 0x36) = (short)uVar7;
      *(short *)(param_1 + 0x38) = (short)uVar8;
    }
    func_0x00109ff4(param_1);
    if ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44)) {
      uVar1 = (undefined2)
              ((int)*(short *)(param_1 + 0x34) * (int)*(short *)(param_1 + 0x3c) +
               (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +
               (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc);    // SHIFT_Q12
      *(undefined2 *)(param_1 + 0xc4) = uVar1;
      *(undefined2 *)(param_1 + 0x44) = uVar1;
    }
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffdff | 0x40;    // MASK_0xFFF
    func_0x00076790(param_1);
    uVar4 = (uint)(*(ushort *)(*(int *)(param_1 + 0xb8) + 8) >> 3);
    if (uVar4 < 3) {
      uVar4 = 3;
    }
    iVar2 = (int)*(short *)(param_1 + 0x36);
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    if (((iVar2 <= (int)uVar4) || ((int)*(short *)(param_1 + 0x44) <= (int)uVar4)) &&
       (func_0x0010a4f8(param_1), (*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0)) {
      *(undefined2 *)(param_1 + 0xc0) = 0;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 3;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  return;
}


---

## FUN_00044f80 (ea=0x44f80, size=1912)


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
    iVar12 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)
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
        uVar8 = *(uint *)(*(int *)(param_1 + 0xb8) + 0x20);
        if ((uVar8 >> 4 & 1) != 0) {
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);
          sVar3 = 0x80;
          if (0x80 < (int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1)) {
            sVar3 = *(short *)(param_1 + 0x44) - uVar1;
          }
          sVar6 = *(short *)(param_1 + 10);
          *(short *)(param_1 + 0x44) = sVar3;
          iVar12 = func_0x000ab4d0(param_1 + 8);
          if ((((int)sVar6 < iVar12 + -0x100) && (*(short *)(param_1 + 0x3e) < 1)) &&
             (iVar12 = -(int)*(short *)(param_1 + 0x3e), (*(uint *)(param_1 + 0x50) & 4) == 0)) {
            if (iVar12 < 0x20) {
              iVar12 = 0x20;
            }
            *(short *)(param_1 + 0x3e) = (short)iVar12;
            func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                            param_1 + 0x3c);
          }
          iVar12 = (int)*(short *)(param_1 + 0x44);
          *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);    // SHIFT_Q12
          *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);    // SHIFT_Q12
          *(short *)(param_1 + 0x38) = (short)(*(short *)(param_1 + 0x40) * iVar12 >> 0xc);    // SHIFT_Q12
          halt_baddata();
        }
        if ((uVar8 >> 3 & 1) == 0) {
          func_0x00109e70(param_1);
          func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                          param_1 + 0x3c);
          halt_baddata();
        }
        return;
      }
    }
    iVar11 = (int)(((uint)*(ushort *)(param_1 + 8) - (uint)*(ushort *)(iVar12 + 0x6c)) * 0x10000) >>
             0x10;
    iVar10 = (int)(((uint)*(ushort *)(param_1 + 10) - (uint)*(ushort *)(iVar12 + 0x6e)) * 0x10000)
             >> 0x10;
    iVar9 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)
            >> 0x10;
    uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
    if (uVar8 * uVar8 < (uint)(iVar11 * iVar11 + iVar10 * iVar10 + iVar9 * iVar9)) {
      local_50 = CONCAT22(*(short *)(iVar12 + 0x6e) - *(ushort *)(param_1 + 10),
                          *(short *)(iVar12 + 0x6c) - *(ushort *)(param_1 + 8));
      local_2c = CONCAT22(uStack_4a,*(short *)(iVar12 + 0x70) - *(ushort *)(param_1 + 0xc));
      local_30 = local_50;
      func_0x00109758(param_1,local_50,local_2c,&local_48);
      local_30 = CONCAT22(local_46 - *(short *)(param_1 + 0x3e),
                          local_48 - *(short *)(param_1 + 0x3c));
      local_2c = CONCAT22(local_2c._2_2_,local_44 - *(short *)(param_1 + 0x40));
      local_20 = local_30;
      local_1c = local_2c;
      func_0x00109758(param_1,local_30,local_2c,auStack_28);
      iVar12 = func_0x0010a95c(param_1,param_1 + 0x3c,&local_48,auStack_40);
      iVar9 = (int)*(short *)(param_1 + 0x3c) * (int)local_48 +
              (int)*(short *)(param_1 + 0x3e) * (int)local_46 +
              (int)*(short *)(param_1 + 0x40) * (int)local_44 >> 0xc;    // SHIFT_Q12
      func_0x0010a95c(param_1,auStack_40,param_1 + 0x3c,&local_38);
      local_20 = local_38;
      local_1c = local_34;
      func_0x00109758(param_1,local_38,local_34,&local_38);
      if (4000 < iVar9) {
        iVar11 = iVar12;
        if (iVar12 < 0) {
          iVar11 = -iVar12;
        }
        if (iVar11 < 1000) {
          if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {
            return;
          }
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
      if ((iVar12 == 0) && (iVar9 < 0)) {
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) != 0) {
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);
          sVar3 = *(short *)(param_1 + 0x44) - uVar1;
          if ((int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1) < 1) {
            sVar3 = 0;
          }
          *(short *)(param_1 + 0x44) = sVar3;
        }
        func_0x0010a6ec(param_1);
      }
      else {
        uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x12);
        bVar2 = iVar9 < *(short *)((uVar8 & 0xfff) * 4 + -0x7ffeb162);    // MASK_0xFFF
        if (bVar2) {
          if (iVar12 < 0) {
            uVar8 = 0x1000 - uVar8 & 0xfff;    // MASK_0xFFF
          }
          iVar9 = (uVar8 & 0xfff) * 4;    // MASK_0xFFF
          iVar12 = (int)*(short *)(iVar9 + -0x7ffeb164);
          iVar9 = (int)*(short *)(iVar9 + -0x7ffeb162);
        }
        iVar11 = (int)*(short *)(param_1 + 0x44);
        sVar7 = (short)(iVar9 * *(short *)(param_1 + 0x3c) + iVar12 * (short)local_38 >> 0xc);    // SHIFT_Q12
        sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc);    // SHIFT_Q12
        sVar6 = (short)(iVar9 * *(short *)(param_1 + 0x40) + iVar12 * (short)local_34 >> 0xc);    // SHIFT_Q12
        *(short *)(param_1 + 0x3c) = sVar7;
        *(short *)(param_1 + 0x3e) = sVar3;
        *(short *)(param_1 + 0x40) = sVar6;
        *(short *)(param_1 + 0x34) = (short)(sVar7 * iVar11 >> 0xc);    // SHIFT_Q12
        *(short *)(param_1 + 0x36) = (short)(sVar3 * iVar11 >> 0xc);    // SHIFT_Q12
        *(short *)(param_1 + 0x38) = (short)(sVar6 * iVar11 >> 0xc);    // SHIFT_Q12
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {
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
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // MASK_0xFFF
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00032c18 (ea=0x32c18, size=1124)


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
  
  param_1 = param_1 & 0xffff;    // MASK_0xFFF
  iVar2 = func_0x000f5b78(param_1,0);
  *(uint *)(iVar2 + 300) = param_1;
  *(undefined4 *)(iVar2 + 0x128) = *param_2;    // POTENTIAL_Y(0x128)
  uVar3 = func_0x000743a4(1,param_1);
  *(undefined4 *)(iVar2 + 0x134) = uVar3;    // POTENTIAL_Y(0x134)
  *(short *)(iVar2 + 0x138) = (short)((uint)param_2[4] >> 6);    // POTENTIAL_Y(0x138)
  *(short *)(iVar2 + 0x13a) = (short)((uint)param_2[5] >> 6);    // POTENTIAL_Y(0x13a)
  *(short *)(iVar2 + 0x13c) = (short)((uint)param_2[6] >> 6);    // POTENTIAL_Y(0x13c)
  sVar6 = (short)((uint)param_2[7] >> 6);
  *(short *)(iVar2 + 0x13e) = sVar6;    // POTENTIAL_Y(0x13e)
  sVar4 = (short)((uint)param_2[8] >> 0xc);    // SHIFT_Q12
  *(short *)(iVar2 + 0x140) = sVar4;    // POTENTIAL_Y(0x140)
  *(short *)(iVar2 + 0x142) = (short)((uint)-param_2[9] >> 6);    // POTENTIAL_Y(0x142)
  *(short *)(iVar2 + 0x144) = (short)((uint)param_2[10] >> 0xc);    // POTENTIAL_Y(0x144) SHIFT_Q12
  *(short *)(iVar2 + 0x146) = (short)((uint)param_2[0xb] >> 0xc);    // POTENTIAL_Y(0x146) SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x148) = *(undefined2 *)(param_2 + 0xd);    // POTENTIAL_Y(0x148)
  *(undefined2 *)(iVar2 + 0x14a) = *(undefined2 *)(param_2 + 0xe);    // POTENTIAL_Y(0x14a)
  *(undefined2 *)(iVar2 + 0x14c) = *(undefined2 *)(param_2 + 0x10);    // POTENTIAL_Y(0x14c)
  iVar8 = (int)sVar6;
  *(short *)(iVar2 + 0x14e) = (short)((uint)param_2[0x12] >> 6);    // POTENTIAL_Y(0x14e)
  if (iVar8 != 0) {
    if (iVar8 == 0) {
      trap(7);
    }
    *(short *)(iVar2 + 0x152) = (short)((sVar4 * 0x477) / iVar8);
  }
  *(undefined2 *)(iVar2 + 0x154) = *(undefined2 *)(param_2 + 0x18);
  *(short *)(iVar2 + 0x156) = (short)((uint)(param_2[0x18] * param_2[0x1b]) >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x15a) = *(undefined2 *)(param_2 + 0x19);
  *(undefined2 *)(iVar2 + 0x158) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar2 + 0x15c) = *(undefined2 *)(param_2 + 0x1c);
  *(undefined2 *)(iVar2 + 0x15e) = *(undefined2 *)(param_2 + 0x16);
  *(undefined2 *)(iVar2 + 0x150) = *(undefined2 *)(param_2 + 0x17);
  *(short *)(iVar2 + 0x160) = (short)((uint)param_2[0x1d] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x162) = *(undefined2 *)(param_2 + 0x21);
  *(short *)(iVar2 + 0x164) = (short)((uint)param_2[0x1f] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x166) = *(undefined2 *)(param_2 + 0x22);
  *(short *)(iVar2 + 0x168) = (short)((uint)param_2[0x1e] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x16a) = *(undefined2 *)(param_2 + 0x23);
  *(short *)(iVar2 + 0x16c) = (short)((uint)param_2[0x20] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x16e) = *(undefined2 *)(param_2 + 0x24);
  *(short *)(iVar2 + 0x170) = (short)((uint)param_2[0x15] >> 0xc);    // SHIFT_Q12
  sVar4 = (short)((uint)param_2[0x14] >> 6);
  *(short *)(iVar2 + 0x172) = sVar4;
  sVar6 = *(short *)(iVar2 + 0x128);    // POTENTIAL_Y(0x128)
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
  *(undefined4 *)(iVar2 + 0x130) = param_2[0x25];    // POTENTIAL_Y(0x130)
  puVar7 = (undefined2 *)(iVar2 + 0xca);
  *(undefined2 *)(iVar2 + 0x18a) = *(undefined2 *)(param_2 + 0x26);
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
      *(undefined2 *)(iVar2 + 0x11a) = 0;    // POTENTIAL_Y(0x11a)
      *(undefined2 *)(iVar2 + 0x11c) = 0xff60;    // POTENTIAL_Y(0x11c)
      *(undefined2 *)(iVar2 + 0x11e) = 0xfe8e;    // POTENTIAL_Y(0x11e)
      *(undefined2 *)(iVar2 + 0x120) = 0;    // POTENTIAL_Y(0x120)
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if (param_1 == 0x4c) {
      *(undefined2 *)(iVar2 + 0x11c) = 0xfe70;    // POTENTIAL_Y(0x11c)
      *(undefined2 *)(iVar2 + 0x11a) = 0;    // POTENTIAL_Y(0x11a)
      *(undefined2 *)(iVar2 + 0x11e) = 0;    // POTENTIAL_Y(0x11e)
      *(undefined2 *)(iVar2 + 0x120) = 1;    // POTENTIAL_Y(0x120)
    }
    if (sVar6 == 6) {
      if (*(short *)(iVar2 + 0x13e) == 0) {    // POTENTIAL_Y(0x13e)
        trap(7);
      }
      iVar8 = (int)_DAT_8011966e * (int)_DAT_8011966e;
      if (iVar8 == 0) {
        trap(7);
      }
      *(short *)(iVar2 + 0xb2) =
           (short)((((int)*(short *)(iVar2 + 0x138) * (int)*(short *)(iVar2 + 0x138)) /    // POTENTIAL_Y(0x138) POTENTIAL_Y(0x138)
                    (int)*(short *)(iVar2 + 0x13e) << 0x11) / iVar8);    // POTENTIAL_Y(0x13e)
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00044a14 (ea=0x44a14, size=1388)


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
     ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44))) {
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) | 4;
  }
  if (*(short *)(param_1 + 10) <= iVar2) {
    return;
  }
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 5) == '\x04') && (0 < *(int *)(param_1 + 0xbc))) {
    if ((*(short *)(param_1 + 0x34) != 0) || (*(short *)(param_1 + 0x38) != 0)) {
      *(undefined2 *)(param_1 + 0x36) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    uVar1 = 0xffff;
    if (*(short *)(param_1 + 0x36) == 0) {
      uVar1 = 0xfff6;
    }
    *(undefined2 *)(param_1 + 0x36) = uVar1;
    *(short *)(param_1 + 0x44) =
         (short)((int)*(short *)(param_1 + 0x3c) * (int)*(short *)(param_1 + 0x34) +
                 (int)*(short *)(param_1 + 0x3e) * (int)*(short *)(param_1 + 0x36) +
                 (int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc);    // SHIFT_Q12
    uVar1 = func_0x000ab4d0(param_1 + 8);
    *(undefined2 *)(param_1 + 10) = uVar1;
    iVar2 = func_0x000a9678((int)*(short *)(param_1 + 8),(int)*(short *)(param_1 + 0xc));
    if (iVar2 != 0) {
      *(undefined2 *)(param_1 + 0x44) = 0;
    }
    func_0x00109ff4(param_1);
    if (*(short *)(param_1 + 0x44) == 0) {
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // MASK_0xFFF
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
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x36)) >> 0xc),    // SHIFT_Q12
                        *(short *)(param_1 + 8) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x34)) >> 0xc));    // SHIFT_Q12
    local_1c = CONCAT22(local_1c._2_2_,
                        *(short *)(param_1 + 0xc) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x38)) >> 0xc));    // SHIFT_Q12
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
  *(undefined4 *)(param_1 + 0xc) = local_1c;
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
      uVar4 = uVar5 & 0xfffffff7;    // MASK_0xFFF
    }
    *(uint *)(param_1 + 0xd0) = uVar4;
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0) {
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
    *(short *)(param_1 + 0x36) = (short)((int)-((int)*(short *)(param_1 + 0x36) * uVar4) >> 0xc);    // SHIFT_Q12
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 1 & 1) != 0) {
      uVar5 = *(uint *)((*(ushort *)(param_1 + 200) & 0x7f) * 4 + -0x7ffeb164);
      uVar4 = uVar5 >> 0x10;
      setCopControlWord(2,0,uVar4);
      uVar5 = uVar5 & 0xffff;    // MASK_0xFFF
      setCopControlWord(2,0x2000,uVar4);
      setCopControlWord(2,0x800,uVar5);
      setCopControlWord(2,0x1000,0x1000);
      setCopControlWord(2,0x1800,-uVar5 & 0xffff);    // MASK_0xFFF
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x34));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x36));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x38));
      copFunction(2,0x49e012);
      uVar6 = getCopReg(2,0x4800);
      uVar7 = getCopReg(2,0x5000);
      uVar8 = getCopReg(2,0x5800);
      *(short *)(param_1 + 0x34) = (short)uVar6;
      *(short *)(param_1 + 0x36) = (short)uVar7;
      *(short *)(param_1 + 0x38) = (short)uVar8;
    }
    func_0x00109ff4(param_1);
    if ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44)) {
      uVar1 = (undefined2)
              ((int)*(short *)(param_1 + 0x34) * (int)*(short *)(param_1 + 0x3c) +
               (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +
               (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc);    // SHIFT_Q12
      *(undefined2 *)(param_1 + 0xc4) = uVar1;
      *(undefined2 *)(param_1 + 0x44) = uVar1;
    }
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffdff | 0x40;    // MASK_0xFFF
    func_0x00076790(param_1);
    uVar4 = (uint)(*(ushort *)(*(int *)(param_1 + 0xb8) + 8) >> 3);
    if (uVar4 < 3) {
      uVar4 = 3;
    }
    iVar2 = (int)*(short *)(param_1 + 0x36);
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    if (((iVar2 <= (int)uVar4) || ((int)*(short *)(param_1 + 0x44) <= (int)uVar4)) &&
       (func_0x0010a4f8(param_1), (*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0)) {
      *(undefined2 *)(param_1 + 0xc0) = 0;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 3;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  return;
}


---

## FUN_00044f80 (ea=0x44f80, size=1912)


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
    iVar12 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)
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
        uVar8 = *(uint *)(*(int *)(param_1 + 0xb8) + 0x20);
        if ((uVar8 >> 4 & 1) != 0) {
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);
          sVar3 = 0x80;
          if (0x80 < (int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1)) {
            sVar3 = *(short *)(param_1 + 0x44) - uVar1;
          }
          sVar6 = *(short *)(param_1 + 10);
          *(short *)(param_1 + 0x44) = sVar3;
          iVar12 = func_0x000ab4d0(param_1 + 8);
          if ((((int)sVar6 < iVar12 + -0x100) && (*(short *)(param_1 + 0x3e) < 1)) &&
             (iVar12 = -(int)*(short *)(param_1 + 0x3e), (*(uint *)(param_1 + 0x50) & 4) == 0)) {
            if (iVar12 < 0x20) {
              iVar12 = 0x20;
            }
            *(short *)(param_1 + 0x3e) = (short)iVar12;
            func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                            param_1 + 0x3c);
          }
          iVar12 = (int)*(short *)(param_1 + 0x44);
          *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);    // SHIFT_Q12
          *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);    // SHIFT_Q12
          *(short *)(param_1 + 0x38) = (short)(*(short *)(param_1 + 0x40) * iVar12 >> 0xc);    // SHIFT_Q12
          halt_baddata();
        }
        if ((uVar8 >> 3 & 1) == 0) {
          func_0x00109e70(param_1);
          func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                          param_1 + 0x3c);
          halt_baddata();
        }
        return;
      }
    }
    iVar11 = (int)(((uint)*(ushort *)(param_1 + 8) - (uint)*(ushort *)(iVar12 + 0x6c)) * 0x10000) >>
             0x10;
    iVar10 = (int)(((uint)*(ushort *)(param_1 + 10) - (uint)*(ushort *)(iVar12 + 0x6e)) * 0x10000)
             >> 0x10;
    iVar9 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)
            >> 0x10;
    uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
    if (uVar8 * uVar8 < (uint)(iVar11 * iVar11 + iVar10 * iVar10 + iVar9 * iVar9)) {
      local_50 = CONCAT22(*(short *)(iVar12 + 0x6e) - *(ushort *)(param_1 + 10),
                          *(short *)(iVar12 + 0x6c) - *(ushort *)(param_1 + 8));
      local_2c = CONCAT22(uStack_4a,*(short *)(iVar12 + 0x70) - *(ushort *)(param_1 + 0xc));
      local_30 = local_50;
      func_0x00109758(param_1,local_50,local_2c,&local_48);
      local_30 = CONCAT22(local_46 - *(short *)(param_1 + 0x3e),
                          local_48 - *(short *)(param_1 + 0x3c));
      local_2c = CONCAT22(local_2c._2_2_,local_44 - *(short *)(param_1 + 0x40));
      local_20 = local_30;
      local_1c = local_2c;
      func_0x00109758(param_1,local_30,local_2c,auStack_28);
      iVar12 = func_0x0010a95c(param_1,param_1 + 0x3c,&local_48,auStack_40);
      iVar9 = (int)*(short *)(param_1 + 0x3c) * (int)local_48 +
              (int)*(short *)(param_1 + 0x3e) * (int)local_46 +
              (int)*(short *)(param_1 + 0x40) * (int)local_44 >> 0xc;    // SHIFT_Q12
      func_0x0010a95c(param_1,auStack_40,param_1 + 0x3c,&local_38);
      local_20 = local_38;
      local_1c = local_34;
      func_0x00109758(param_1,local_38,local_34,&local_38);
      if (4000 < iVar9) {
        iVar11 = iVar12;
        if (iVar12 < 0) {
          iVar11 = -iVar12;
        }
        if (iVar11 < 1000) {
          if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {
            return;
          }
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
      if ((iVar12 == 0) && (iVar9 < 0)) {
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) != 0) {
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);
          sVar3 = *(short *)(param_1 + 0x44) - uVar1;
          if ((int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1) < 1) {
            sVar3 = 0;
          }
          *(short *)(param_1 + 0x44) = sVar3;
        }
        func_0x0010a6ec(param_1);
      }
      else {
        uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x12);
        bVar2 = iVar9 < *(short *)((uVar8 & 0xfff) * 4 + -0x7ffeb162);    // MASK_0xFFF
        if (bVar2) {
          if (iVar12 < 0) {
            uVar8 = 0x1000 - uVar8 & 0xfff;    // MASK_0xFFF
          }
          iVar9 = (uVar8 & 0xfff) * 4;    // MASK_0xFFF
          iVar12 = (int)*(short *)(iVar9 + -0x7ffeb164);
          iVar9 = (int)*(short *)(iVar9 + -0x7ffeb162);
        }
        iVar11 = (int)*(short *)(param_1 + 0x44);
        sVar7 = (short)(iVar9 * *(short *)(param_1 + 0x3c) + iVar12 * (short)local_38 >> 0xc);    // SHIFT_Q12
        sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc);    // SHIFT_Q12
        sVar6 = (short)(iVar9 * *(short *)(param_1 + 0x40) + iVar12 * (short)local_34 >> 0xc);    // SHIFT_Q12
        *(short *)(param_1 + 0x3c) = sVar7;
        *(short *)(param_1 + 0x3e) = sVar3;
        *(short *)(param_1 + 0x40) = sVar6;
        *(short *)(param_1 + 0x34) = (short)(sVar7 * iVar11 >> 0xc);    // SHIFT_Q12
        *(short *)(param_1 + 0x36) = (short)(sVar3 * iVar11 >> 0xc);    // SHIFT_Q12
        *(short *)(param_1 + 0x38) = (short)(sVar6 * iVar11 >> 0xc);    // SHIFT_Q12
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {
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
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // MASK_0xFFF
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_0001e750 (ea=0x1e750, size=100)


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
    local_40 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
    sStack_30 = sVar6 - param_1[5];
    uStack_2e = (undefined2)((((int)sVar5 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar6 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar5 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
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
    sVar7 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
    uStack_2e = (undefined2)((((int)sVar3 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar4 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar3 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
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
      sVar11 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
      sStack_30 = sStack_34 - param_1[5];
      uStack_2e = (undefined2)((((int)sVar8 - (int)param_1[6]) * 0x1000) / 0x780);
      uStack_2c = 0;
      FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
      sStack_34 = sStack_28 + param_1[5];
      iVar10 = sStack_26 * 0x780;
      if (iVar10 < 0) {
        iVar10 = iVar10 + 0xfff;
      }
      sVar8 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
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
    *(short *)(iVar10 + 0x10) = sVar6;
    *(short *)(iVar10 + 0x12) = sVar5;
    *(short *)(iVar10 + 0x18) = local_3c;
    *(short *)(iVar10 + 0x1a) = sVar7;
    *(short *)(iVar10 + 0x20) = sVar4;
    *(short *)(iVar10 + 0x22) = sVar3;
    *(char *)(iVar10 + 0xc) = (char)param_1[0x14];
    *(char *)(iVar10 + 0xd) = (char)param_1[0x17];
    *(undefined1 *)(iVar10 + 0x14) = *(undefined1 *)((int)param_1 + 0x29);
    *(undefined1 *)(iVar10 + 0x15) = *(undefined1 *)((int)param_1 + 0x2f);
    *(char *)(iVar10 + 0x1c) = (char)param_1[0x15];
    *(char *)(iVar10 + 0x1d) = (char)param_1[0x18];
    *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2b);
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
      *(short *)(iVar10 + 0x10) = local_38;
      *(short *)(iVar10 + 0x12) = sVar11;
      *(short *)(iVar10 + 0x18) = sVar4;
      *(short *)(iVar10 + 0x1a) = sVar3;
      *(short *)(iVar10 + 0x20) = sStack_34;
      *(short *)(iVar10 + 0x22) = sVar8;
      *(undefined1 *)(iVar10 + 0xc) = 0;
      *(undefined1 *)(iVar10 + 0xd) = *(undefined1 *)((int)param_1 + 0x2f);
      *(char *)(iVar10 + 0x14) = (char)param_1[0x16];
      *(char *)(iVar10 + 0x15) = (char)param_1[0x19];
      *(undefined1 *)(iVar10 + 0x1c) = 0;
      *(undefined1 *)(iVar10 + 0x1d) = *(undefined1 *)((int)param_1 + 0x31);
      *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2d);
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

## FUN_00032c18 (ea=0x32c18, size=1124)


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
  
  param_1 = param_1 & 0xffff;    // MASK_0xFFF
  iVar2 = func_0x000f5b78(param_1,0);
  *(uint *)(iVar2 + 300) = param_1;
  *(undefined4 *)(iVar2 + 0x128) = *param_2;    // POTENTIAL_Y(0x128)
  uVar3 = func_0x000743a4(1,param_1);
  *(undefined4 *)(iVar2 + 0x134) = uVar3;    // POTENTIAL_Y(0x134)
  *(short *)(iVar2 + 0x138) = (short)((uint)param_2[4] >> 6);    // POTENTIAL_Y(0x138)
  *(short *)(iVar2 + 0x13a) = (short)((uint)param_2[5] >> 6);    // POTENTIAL_Y(0x13a)
  *(short *)(iVar2 + 0x13c) = (short)((uint)param_2[6] >> 6);    // POTENTIAL_Y(0x13c)
  sVar6 = (short)((uint)param_2[7] >> 6);
  *(short *)(iVar2 + 0x13e) = sVar6;    // POTENTIAL_Y(0x13e)
  sVar4 = (short)((uint)param_2[8] >> 0xc);    // SHIFT_Q12
  *(short *)(iVar2 + 0x140) = sVar4;    // POTENTIAL_Y(0x140)
  *(short *)(iVar2 + 0x142) = (short)((uint)-param_2[9] >> 6);    // POTENTIAL_Y(0x142)
  *(short *)(iVar2 + 0x144) = (short)((uint)param_2[10] >> 0xc);    // POTENTIAL_Y(0x144) SHIFT_Q12
  *(short *)(iVar2 + 0x146) = (short)((uint)param_2[0xb] >> 0xc);    // POTENTIAL_Y(0x146) SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x148) = *(undefined2 *)(param_2 + 0xd);    // POTENTIAL_Y(0x148)
  *(undefined2 *)(iVar2 + 0x14a) = *(undefined2 *)(param_2 + 0xe);    // POTENTIAL_Y(0x14a)
  *(undefined2 *)(iVar2 + 0x14c) = *(undefined2 *)(param_2 + 0x10);    // POTENTIAL_Y(0x14c)
  iVar8 = (int)sVar6;
  *(short *)(iVar2 + 0x14e) = (short)((uint)param_2[0x12] >> 6);    // POTENTIAL_Y(0x14e)
  if (iVar8 != 0) {
    if (iVar8 == 0) {
      trap(7);
    }
    *(short *)(iVar2 + 0x152) = (short)((sVar4 * 0x477) / iVar8);
  }
  *(undefined2 *)(iVar2 + 0x154) = *(undefined2 *)(param_2 + 0x18);
  *(short *)(iVar2 + 0x156) = (short)((uint)(param_2[0x18] * param_2[0x1b]) >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x15a) = *(undefined2 *)(param_2 + 0x19);
  *(undefined2 *)(iVar2 + 0x158) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar2 + 0x15c) = *(undefined2 *)(param_2 + 0x1c);
  *(undefined2 *)(iVar2 + 0x15e) = *(undefined2 *)(param_2 + 0x16);
  *(undefined2 *)(iVar2 + 0x150) = *(undefined2 *)(param_2 + 0x17);
  *(short *)(iVar2 + 0x160) = (short)((uint)param_2[0x1d] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x162) = *(undefined2 *)(param_2 + 0x21);
  *(short *)(iVar2 + 0x164) = (short)((uint)param_2[0x1f] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x166) = *(undefined2 *)(param_2 + 0x22);
  *(short *)(iVar2 + 0x168) = (short)((uint)param_2[0x1e] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x16a) = *(undefined2 *)(param_2 + 0x23);
  *(short *)(iVar2 + 0x16c) = (short)((uint)param_2[0x20] >> 0xc);    // SHIFT_Q12
  *(undefined2 *)(iVar2 + 0x16e) = *(undefined2 *)(param_2 + 0x24);
  *(short *)(iVar2 + 0x170) = (short)((uint)param_2[0x15] >> 0xc);    // SHIFT_Q12
  sVar4 = (short)((uint)param_2[0x14] >> 6);
  *(short *)(iVar2 + 0x172) = sVar4;
  sVar6 = *(short *)(iVar2 + 0x128);    // POTENTIAL_Y(0x128)
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
  *(undefined4 *)(iVar2 + 0x130) = param_2[0x25];    // POTENTIAL_Y(0x130)
  puVar7 = (undefined2 *)(iVar2 + 0xca);
  *(undefined2 *)(iVar2 + 0x18a) = *(undefined2 *)(param_2 + 0x26);
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
      *(undefined2 *)(iVar2 + 0x11a) = 0;    // POTENTIAL_Y(0x11a)
      *(undefined2 *)(iVar2 + 0x11c) = 0xff60;    // POTENTIAL_Y(0x11c)
      *(undefined2 *)(iVar2 + 0x11e) = 0xfe8e;    // POTENTIAL_Y(0x11e)
      *(undefined2 *)(iVar2 + 0x120) = 0;    // POTENTIAL_Y(0x120)
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if (param_1 == 0x4c) {
      *(undefined2 *)(iVar2 + 0x11c) = 0xfe70;    // POTENTIAL_Y(0x11c)
      *(undefined2 *)(iVar2 + 0x11a) = 0;    // POTENTIAL_Y(0x11a)
      *(undefined2 *)(iVar2 + 0x11e) = 0;    // POTENTIAL_Y(0x11e)
      *(undefined2 *)(iVar2 + 0x120) = 1;    // POTENTIAL_Y(0x120)
    }
    if (sVar6 == 6) {
      if (*(short *)(iVar2 + 0x13e) == 0) {    // POTENTIAL_Y(0x13e)
        trap(7);
      }
      iVar8 = (int)_DAT_8011966e * (int)_DAT_8011966e;
      if (iVar8 == 0) {
        trap(7);
      }
      *(short *)(iVar2 + 0xb2) =
           (short)((((int)*(short *)(iVar2 + 0x138) * (int)*(short *)(iVar2 + 0x138)) /    // POTENTIAL_Y(0x138) POTENTIAL_Y(0x138)
                    (int)*(short *)(iVar2 + 0x13e) << 0x11) / iVar8);    // POTENTIAL_Y(0x13e)
    }
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_00044a14 (ea=0x44a14, size=1388)


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
     ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44))) {
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) | 4;
  }
  if (*(short *)(param_1 + 10) <= iVar2) {
    return;
  }
  if ((*(char *)(*(int *)(param_1 + 0xb8) + 5) == '\x04') && (0 < *(int *)(param_1 + 0xbc))) {
    if ((*(short *)(param_1 + 0x34) != 0) || (*(short *)(param_1 + 0x38) != 0)) {
      *(undefined2 *)(param_1 + 0x36) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    uVar1 = 0xffff;
    if (*(short *)(param_1 + 0x36) == 0) {
      uVar1 = 0xfff6;
    }
    *(undefined2 *)(param_1 + 0x36) = uVar1;
    *(short *)(param_1 + 0x44) =
         (short)((int)*(short *)(param_1 + 0x3c) * (int)*(short *)(param_1 + 0x34) +
                 (int)*(short *)(param_1 + 0x3e) * (int)*(short *)(param_1 + 0x36) +
                 (int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc);    // SHIFT_Q12
    uVar1 = func_0x000ab4d0(param_1 + 8);
    *(undefined2 *)(param_1 + 10) = uVar1;
    iVar2 = func_0x000a9678((int)*(short *)(param_1 + 8),(int)*(short *)(param_1 + 0xc));
    if (iVar2 != 0) {
      *(undefined2 *)(param_1 + 0x44) = 0;
    }
    func_0x00109ff4(param_1);
    if (*(short *)(param_1 + 0x44) == 0) {
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // MASK_0xFFF
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
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x36)) >> 0xc),    // SHIFT_Q12
                        *(short *)(param_1 + 8) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x34)) >> 0xc));    // SHIFT_Q12
    local_1c = CONCAT22(local_1c._2_2_,
                        *(short *)(param_1 + 0xc) -
                        (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x38)) >> 0xc));    // SHIFT_Q12
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
  *(undefined4 *)(param_1 + 0xc) = local_1c;
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
      uVar4 = uVar5 & 0xfffffff7;    // MASK_0xFFF
    }
    *(uint *)(param_1 + 0xd0) = uVar4;
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0) {
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
    *(short *)(param_1 + 0x36) = (short)((int)-((int)*(short *)(param_1 + 0x36) * uVar4) >> 0xc);    // SHIFT_Q12
    if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 1 & 1) != 0) {
      uVar5 = *(uint *)((*(ushort *)(param_1 + 200) & 0x7f) * 4 + -0x7ffeb164);
      uVar4 = uVar5 >> 0x10;
      setCopControlWord(2,0,uVar4);
      uVar5 = uVar5 & 0xffff;    // MASK_0xFFF
      setCopControlWord(2,0x2000,uVar4);
      setCopControlWord(2,0x800,uVar5);
      setCopControlWord(2,0x1000,0x1000);
      setCopControlWord(2,0x1800,-uVar5 & 0xffff);    // MASK_0xFFF
      setCopReg(2,0x4800,(uint)*(ushort *)(param_1 + 0x34));
      setCopReg(2,0x5000,(uint)*(ushort *)(param_1 + 0x36));
      setCopReg(2,0x5800,(uint)*(ushort *)(param_1 + 0x38));
      copFunction(2,0x49e012);
      uVar6 = getCopReg(2,0x4800);
      uVar7 = getCopReg(2,0x5000);
      uVar8 = getCopReg(2,0x5800);
      *(short *)(param_1 + 0x34) = (short)uVar6;
      *(short *)(param_1 + 0x36) = (short)uVar7;
      *(short *)(param_1 + 0x38) = (short)uVar8;
    }
    func_0x00109ff4(param_1);
    if ((int)(uint)*(ushort *)(param_1 + 0xc4) <= (int)*(short *)(param_1 + 0x44)) {
      uVar1 = (undefined2)
              ((int)*(short *)(param_1 + 0x34) * (int)*(short *)(param_1 + 0x3c) +
               (int)*(short *)(param_1 + 0x36) * (int)*(short *)(param_1 + 0x3e) +
               (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc);    // SHIFT_Q12
      *(undefined2 *)(param_1 + 0xc4) = uVar1;
      *(undefined2 *)(param_1 + 0x44) = uVar1;
    }
    *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffdff | 0x40;    // MASK_0xFFF
    func_0x00076790(param_1);
    uVar4 = (uint)(*(ushort *)(*(int *)(param_1 + 0xb8) + 8) >> 3);
    if (uVar4 < 3) {
      uVar4 = 3;
    }
    iVar2 = (int)*(short *)(param_1 + 0x36);
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    if (((iVar2 <= (int)uVar4) || ((int)*(short *)(param_1 + 0x44) <= (int)uVar4)) &&
       (func_0x0010a4f8(param_1), (*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 2 & 1) != 0)) {
      *(undefined2 *)(param_1 + 0xc0) = 0;
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) | 3;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  return;
}


---

## FUN_00044f80 (ea=0x44f80, size=1912)


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
    iVar12 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)
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
        uVar8 = *(uint *)(*(int *)(param_1 + 0xb8) + 0x20);
        if ((uVar8 >> 4 & 1) != 0) {
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);
          sVar3 = 0x80;
          if (0x80 < (int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1)) {
            sVar3 = *(short *)(param_1 + 0x44) - uVar1;
          }
          sVar6 = *(short *)(param_1 + 10);
          *(short *)(param_1 + 0x44) = sVar3;
          iVar12 = func_0x000ab4d0(param_1 + 8);
          if ((((int)sVar6 < iVar12 + -0x100) && (*(short *)(param_1 + 0x3e) < 1)) &&
             (iVar12 = -(int)*(short *)(param_1 + 0x3e), (*(uint *)(param_1 + 0x50) & 4) == 0)) {
            if (iVar12 < 0x20) {
              iVar12 = 0x20;
            }
            *(short *)(param_1 + 0x3e) = (short)iVar12;
            func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                            param_1 + 0x3c);
          }
          iVar12 = (int)*(short *)(param_1 + 0x44);
          *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);    // SHIFT_Q12
          *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);    // SHIFT_Q12
          *(short *)(param_1 + 0x38) = (short)(*(short *)(param_1 + 0x40) * iVar12 >> 0xc);    // SHIFT_Q12
          halt_baddata();
        }
        if ((uVar8 >> 3 & 1) == 0) {
          func_0x00109e70(param_1);
          func_0x00109758(param_1,*(undefined4 *)(param_1 + 0x3c),*(undefined4 *)(param_1 + 0x40),
                          param_1 + 0x3c);
          halt_baddata();
        }
        return;
      }
    }
    iVar11 = (int)(((uint)*(ushort *)(param_1 + 8) - (uint)*(ushort *)(iVar12 + 0x6c)) * 0x10000) >>
             0x10;
    iVar10 = (int)(((uint)*(ushort *)(param_1 + 10) - (uint)*(ushort *)(iVar12 + 0x6e)) * 0x10000)
             >> 0x10;
    iVar9 = (int)(((uint)*(ushort *)(param_1 + 0xc) - (uint)*(ushort *)(iVar12 + 0x70)) * 0x10000)
            >> 0x10;
    uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x16);
    if (uVar8 * uVar8 < (uint)(iVar11 * iVar11 + iVar10 * iVar10 + iVar9 * iVar9)) {
      local_50 = CONCAT22(*(short *)(iVar12 + 0x6e) - *(ushort *)(param_1 + 10),
                          *(short *)(iVar12 + 0x6c) - *(ushort *)(param_1 + 8));
      local_2c = CONCAT22(uStack_4a,*(short *)(iVar12 + 0x70) - *(ushort *)(param_1 + 0xc));
      local_30 = local_50;
      func_0x00109758(param_1,local_50,local_2c,&local_48);
      local_30 = CONCAT22(local_46 - *(short *)(param_1 + 0x3e),
                          local_48 - *(short *)(param_1 + 0x3c));
      local_2c = CONCAT22(local_2c._2_2_,local_44 - *(short *)(param_1 + 0x40));
      local_20 = local_30;
      local_1c = local_2c;
      func_0x00109758(param_1,local_30,local_2c,auStack_28);
      iVar12 = func_0x0010a95c(param_1,param_1 + 0x3c,&local_48,auStack_40);
      iVar9 = (int)*(short *)(param_1 + 0x3c) * (int)local_48 +
              (int)*(short *)(param_1 + 0x3e) * (int)local_46 +
              (int)*(short *)(param_1 + 0x40) * (int)local_44 >> 0xc;    // SHIFT_Q12
      func_0x0010a95c(param_1,auStack_40,param_1 + 0x3c,&local_38);
      local_20 = local_38;
      local_1c = local_34;
      func_0x00109758(param_1,local_38,local_34,&local_38);
      if (4000 < iVar9) {
        iVar11 = iVar12;
        if (iVar12 < 0) {
          iVar11 = -iVar12;
        }
        if (iVar11 < 1000) {
          if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {
            return;
          }
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
      if ((iVar12 == 0) && (iVar9 < 0)) {
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) != 0) {
          uVar1 = *(ushort *)(*(int *)(param_1 + 0xb8) + 0x10);
          sVar3 = *(short *)(param_1 + 0x44) - uVar1;
          if ((int)((int)*(short *)(param_1 + 0x44) - (uint)uVar1) < 1) {
            sVar3 = 0;
          }
          *(short *)(param_1 + 0x44) = sVar3;
        }
        func_0x0010a6ec(param_1);
      }
      else {
        uVar8 = (uint)*(ushort *)(*(int *)(param_1 + 0xb8) + 0x12);
        bVar2 = iVar9 < *(short *)((uVar8 & 0xfff) * 4 + -0x7ffeb162);    // MASK_0xFFF
        if (bVar2) {
          if (iVar12 < 0) {
            uVar8 = 0x1000 - uVar8 & 0xfff;    // MASK_0xFFF
          }
          iVar9 = (uVar8 & 0xfff) * 4;    // MASK_0xFFF
          iVar12 = (int)*(short *)(iVar9 + -0x7ffeb164);
          iVar9 = (int)*(short *)(iVar9 + -0x7ffeb162);
        }
        iVar11 = (int)*(short *)(param_1 + 0x44);
        sVar7 = (short)(iVar9 * *(short *)(param_1 + 0x3c) + iVar12 * (short)local_38 >> 0xc);    // SHIFT_Q12
        sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc);    // SHIFT_Q12
        sVar6 = (short)(iVar9 * *(short *)(param_1 + 0x40) + iVar12 * (short)local_34 >> 0xc);    // SHIFT_Q12
        *(short *)(param_1 + 0x3c) = sVar7;
        *(short *)(param_1 + 0x3e) = sVar3;
        *(short *)(param_1 + 0x40) = sVar6;
        *(short *)(param_1 + 0x34) = (short)(sVar7 * iVar11 >> 0xc);    // SHIFT_Q12
        *(short *)(param_1 + 0x36) = (short)(sVar3 * iVar11 >> 0xc);    // SHIFT_Q12
        *(short *)(param_1 + 0x38) = (short)(sVar6 * iVar11 >> 0xc);    // SHIFT_Q12
        if ((*(uint *)(*(int *)(param_1 + 0xb8) + 0x20) >> 3 & 1) == 0) {
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
      *(uint *)(param_1 + 0xd0) = *(uint *)(param_1 + 0xd0) & 0xfffffff7;    // MASK_0xFFF
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


---

## FUN_0001e750 (ea=0x1e750, size=100)


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
    local_40 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
    sStack_30 = sVar6 - param_1[5];
    uStack_2e = (undefined2)((((int)sVar5 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar6 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar5 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
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
    sVar7 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
    uStack_2e = (undefined2)((((int)sVar3 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar4 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar3 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
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
      sVar11 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
      sStack_30 = sStack_34 - param_1[5];
      uStack_2e = (undefined2)((((int)sVar8 - (int)param_1[6]) * 0x1000) / 0x780);
      uStack_2c = 0;
      FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
      sStack_34 = sStack_28 + param_1[5];
      iVar10 = sStack_26 * 0x780;
      if (iVar10 < 0) {
        iVar10 = iVar10 + 0xfff;
      }
      sVar8 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
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
    *(short *)(iVar10 + 0x10) = sVar6;
    *(short *)(iVar10 + 0x12) = sVar5;
    *(short *)(iVar10 + 0x18) = local_3c;
    *(short *)(iVar10 + 0x1a) = sVar7;
    *(short *)(iVar10 + 0x20) = sVar4;
    *(short *)(iVar10 + 0x22) = sVar3;
    *(char *)(iVar10 + 0xc) = (char)param_1[0x14];
    *(char *)(iVar10 + 0xd) = (char)param_1[0x17];
    *(undefined1 *)(iVar10 + 0x14) = *(undefined1 *)((int)param_1 + 0x29);
    *(undefined1 *)(iVar10 + 0x15) = *(undefined1 *)((int)param_1 + 0x2f);
    *(char *)(iVar10 + 0x1c) = (char)param_1[0x15];
    *(char *)(iVar10 + 0x1d) = (char)param_1[0x18];
    *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2b);
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
      *(short *)(iVar10 + 0x10) = local_38;
      *(short *)(iVar10 + 0x12) = sVar11;
      *(short *)(iVar10 + 0x18) = sVar4;
      *(short *)(iVar10 + 0x1a) = sVar3;
      *(short *)(iVar10 + 0x20) = sStack_34;
      *(short *)(iVar10 + 0x22) = sVar8;
      *(undefined1 *)(iVar10 + 0xc) = 0;
      *(undefined1 *)(iVar10 + 0xd) = *(undefined1 *)((int)param_1 + 0x2f);
      *(char *)(iVar10 + 0x14) = (char)param_1[0x16];
      *(char *)(iVar10 + 0x15) = (char)param_1[0x19];
      *(undefined1 *)(iVar10 + 0x1c) = 0;
      *(undefined1 *)(iVar10 + 0x1d) = *(undefined1 *)((int)param_1 + 0x31);
      *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2d);
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

## FUN_0001e750 (ea=0x1e750, size=100)


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
    local_40 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
    sStack_30 = sVar6 - param_1[5];
    uStack_2e = (undefined2)((((int)sVar5 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar6 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar5 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
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
    sVar7 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
    uStack_2e = (undefined2)((((int)sVar3 - (int)param_1[6]) * 0x1000) / 0x780);
    uStack_2c = 0;
    FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
    sVar4 = sStack_28 + param_1[5];
    iVar10 = sStack_26 * 0x780;
    if (iVar10 < 0) {
      iVar10 = iVar10 + 0xfff;
    }
    sVar3 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
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
      sVar11 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
      sStack_30 = sStack_34 - param_1[5];
      uStack_2e = (undefined2)((((int)sVar8 - (int)param_1[6]) * 0x1000) / 0x780);
      uStack_2c = 0;
      FUN_0001eb14(auStack_20,&sStack_30,&sStack_28);
      sStack_34 = sStack_28 + param_1[5];
      iVar10 = sStack_26 * 0x780;
      if (iVar10 < 0) {
        iVar10 = iVar10 + 0xfff;
      }
      sVar8 = (short)((uint)(((int)param_1[6] + (iVar10 >> 0xc)) * 0x10000) >> 0x10);    // SHIFT_Q12
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
    *(short *)(iVar10 + 0x10) = sVar6;
    *(short *)(iVar10 + 0x12) = sVar5;
    *(short *)(iVar10 + 0x18) = local_3c;
    *(short *)(iVar10 + 0x1a) = sVar7;
    *(short *)(iVar10 + 0x20) = sVar4;
    *(short *)(iVar10 + 0x22) = sVar3;
    *(char *)(iVar10 + 0xc) = (char)param_1[0x14];
    *(char *)(iVar10 + 0xd) = (char)param_1[0x17];
    *(undefined1 *)(iVar10 + 0x14) = *(undefined1 *)((int)param_1 + 0x29);
    *(undefined1 *)(iVar10 + 0x15) = *(undefined1 *)((int)param_1 + 0x2f);
    *(char *)(iVar10 + 0x1c) = (char)param_1[0x15];
    *(char *)(iVar10 + 0x1d) = (char)param_1[0x18];
    *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2b);
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
      *(short *)(iVar10 + 0x10) = local_38;
      *(short *)(iVar10 + 0x12) = sVar11;
      *(short *)(iVar10 + 0x18) = sVar4;
      *(short *)(iVar10 + 0x1a) = sVar3;
      *(short *)(iVar10 + 0x20) = sStack_34;
      *(short *)(iVar10 + 0x22) = sVar8;
      *(undefined1 *)(iVar10 + 0xc) = 0;
      *(undefined1 *)(iVar10 + 0xd) = *(undefined1 *)((int)param_1 + 0x2f);
      *(char *)(iVar10 + 0x14) = (char)param_1[0x16];
      *(char *)(iVar10 + 0x15) = (char)param_1[0x19];
      *(undefined1 *)(iVar10 + 0x1c) = 0;
      *(undefined1 *)(iVar10 + 0x1d) = *(undefined1 *)((int)param_1 + 0x31);
      *(undefined1 *)(iVar10 + 0x24) = *(undefined1 *)((int)param_1 + 0x2d);
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

