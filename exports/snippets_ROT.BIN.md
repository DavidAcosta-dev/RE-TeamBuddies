# Snippets for ROT.BIN

## 1. phys_FUN_000006dc @ 0x000006dc  tags:physics  score:19

```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_000006dc(void)

{
  undefined4 *puVar1;
  int iVar2;
  
  func_0x0003dec4();
  iVar2 = func_0x00041614();
  puVar1 = _DAT_800ce760;
  if (((iVar2 != 0) && (_DAT_800cf8c4 != 4)) && (_DAT_800cf8c4 != 0)) {
    _DAT_800cf8c4 = 3;
  }
  *_DAT_800ce760 = _DAT_800ceb74;
  puVar1[1] = _DAT_800ceb78;
  puVar1 = _DAT_800ce760;
  _DAT_800ce760[2] = _DAT_800ceb7c;
  puVar1[3] = _DAT_800ceb80;
  func_0x000a1eb8(_DAT_800ce760,0);
  func_0x000acc7c(_DAT_800ce75c);
  setCopControlWord(2,0x4000,_DAT_800be5cc);
  setCopControlWord(2,0x4800,_DAT_800be5d0);
  setCopControlWord(2,0x5000,_DAT_800be5d4);
  setCopControlWord(2,0x5800,_DAT_800be5d8);
  setCopControlWord(2,0x6000,_DAT_800be5dc);
  setCopControlWord(2,0x8000,_DAT_800be5e4);
  setCopControlWord(2,0x8800,_DAT_800be5e8);
  setCopControlWord(2,0x9000,_DAT_800be5ec);
  setCopControlWord(2,0x9800,_DAT_800be5f0);
  setCopControlWord(2,0xa000,_DAT_800be5f4);
  setCopControlWord(2,0x6800,_DAT_800be5dc >> 0x10);
  setCopControlWord(2,0x7000,(int)(short)_DAT_800be5e0);
  setCopControlWord(2,0x7800,_DAT_800be5e0 >> 0x10);
  setCopControlWord(2,0xa800,_DAT_800be5f4 >> 0x10);
  setCopControlWord(2,0xb000,(int)(short)_DAT_800be5f8);
  setCopControlWord(2,0xb800,_DAT_800be5f8 >> 0x10);
  setCopControlWord(2,0x4000,_DAT_800be5cc);
  setCopControlWord(2,0x4800,_DAT_800be5d0);
  setCopControlWord(2,0x5000,_DAT_800be5d4);
  setCopControlWord(2,0x5800,_DAT_800be5d8);
  setCopControlWord(2,0x6000,_DAT_800be5dc);
  func_0x00043b60();
  if (5 < _DAT_800cf8c4) {
    func_0x000ace74(_DAT_800ce75c);
    func_0x00043b90(*(int *)(_DAT_80043cfc + 0x78) + 4);
    func_0x000ad154();
    func_0x0003cc50(7);
    return;
  }
                    /* WARNING: Could not emulate address calculation at 0x00000860 */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(_DAT_800cf8c4 * 4 + -0x7ff3bf9c))();
  return;
}


```

## 2. phys_FUN_000006dc @ 0x000006dc  tags:physics  score:19

```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_000006dc(void)

{
  undefined4 *puVar1;
  int iVar2;
  
  func_0x0003dec4();
  iVar2 = func_0x00041614();
  puVar1 = _DAT_800ce760;
  if (((iVar2 != 0) && (_DAT_800cf8c4 != 4)) && (_DAT_800cf8c4 != 0)) {
    _DAT_800cf8c4 = 3;
  }
  *_DAT_800ce760 = _DAT_800ceb74;
  puVar1[1] = _DAT_800ceb78;
  puVar1 = _DAT_800ce760;
  _DAT_800ce760[2] = _DAT_800ceb7c;
  puVar1[3] = _DAT_800ceb80;
  func_0x000a1eb8(_DAT_800ce760,0);
  func_0x000acc7c(_DAT_800ce75c);
  setCopControlWord(2,0x4000,_DAT_800be5cc);
  setCopControlWord(2,0x4800,_DAT_800be5d0);
  setCopControlWord(2,0x5000,_DAT_800be5d4);
  setCopControlWord(2,0x5800,_DAT_800be5d8);
  setCopControlWord(2,0x6000,_DAT_800be5dc);
  setCopControlWord(2,0x8000,_DAT_800be5e4);
  setCopControlWord(2,0x8800,_DAT_800be5e8);
  setCopControlWord(2,0x9000,_DAT_800be5ec);
  setCopControlWord(2,0x9800,_DAT_800be5f0);
  setCopControlWord(2,0xa000,_DAT_800be5f4);
  setCopControlWord(2,0x6800,_DAT_800be5dc >> 0x10);
  setCopControlWord(2,0x7000,(int)(short)_DAT_800be5e0);
  setCopControlWord(2,0x7800,_DAT_800be5e0 >> 0x10);
  setCopControlWord(2,0xa800,_DAT_800be5f4 >> 0x10);
  setCopControlWord(2,0xb000,(int)(short)_DAT_800be5f8);
  setCopControlWord(2,0xb800,_DAT_800be5f8 >> 0x10);
  setCopControlWord(2,0x4000,_DAT_800be5cc);
  setCopControlWord(2,0x4800,_DAT_800be5d0);
  setCopControlWord(2,0x5000,_DAT_800be5d4);
  setCopControlWord(2,0x5800,_DAT_800be5d8);
  setCopControlWord(2,0x6000,_DAT_800be5dc);
  func_0x00043b60();
  if (5 < _DAT_800cf8c4) {
    func_0x000ace74(_DAT_800ce75c);
    func_0x00043b90(*(int *)(_DAT_80043cfc + 0x78) + 4);
    func_0x000ad154();
    func_0x0003cc50(7);
    return;
  }
                    /* WARNING: Could not emulate address calculation at 0x00000860 */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(_DAT_800cf8c4 * 4 + -0x7ff3bf9c))();
  return;
}


```

## 3. phys_FUN_00001ad4 @ 0x00001ad4  tags:physics  score:19

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00001ad4(undefined2 *param_1,uint param_2,int param_3)

{
  ushort uVar1;
  ushort uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  
  if (_DAT_800cedb0 != param_1) {
    param_2 = 0;
  }
  if (*(uint *)(param_1 + 8) < 0xb) {
                    /* WARNING: Could not emulate address calculation at 0x00001b30 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(*(uint *)(param_1 + 8) * 4 + -0x7ff3bf64))();
    return;
  }
  if (param_3 != 0) {
    iVar4 = *(int *)((_DAT_800ceda4 & 0xfff) * 4 + -0x7ffeb164);
    iVar5 = iVar4 >> 0x10;
    iVar4 = (int)(short)iVar4;
    *param_1 = (short)(iVar5 * (short)param_1[4] + iVar4 * (short)param_1[6] >> 0xc);
    param_1[2] = (short)(-iVar4 * (int)(short)param_1[4] + iVar5 * (short)param_1[6] >> 0xc);
  }
  uVar1 = param_1[0x13];
  uVar2 = param_1[0x12];
  if ((uint)uVar1 != (uint)uVar2) {
    uVar6 = (uint)uVar1 - (uint)uVar2 & 0xfff;
    if (0x800 < uVar6) {
      uVar6 = uVar6 - 0x1000;
    }
    uVar3 = uVar6;
    if ((int)uVar6 < 0) {
      uVar3 = -uVar6;
    }
    if ((int)uVar3 < _DAT_800ceda8) {
      param_1[0x12] = uVar1;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    iVar4 = _DAT_800ceda8;
    if ((int)uVar6 < 1) {
      iVar4 = -_DAT_800ceda8;
    }
    param_1[0x12] = uVar2 + (short)iVar4;
    uVar1 = param_1[0x12];
    param_1[0x12] = uVar1 & 0xfff;
    if (((uVar1 & 0xfff) - param_1[0x13] & 0xfff) == 0) {
      param_1[0x12] = param_1[0x13];
    }
  }
  if (param_2 < 7) {
                    /* WARNING: Could not emulate address calculation at 0x00001d74 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(param_2 * 4 + -0x7ff3bf34))();
    return;
  }
  return;
}


```

## 4. phys_FUN_00001ad4 @ 0x00001ad4  tags:physics  score:19

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00001ad4(undefined2 *param_1,uint param_2,int param_3)

{
  ushort uVar1;
  ushort uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  
  if (_DAT_800cedb0 != param_1) {
    param_2 = 0;
  }
  if (*(uint *)(param_1 + 8) < 0xb) {
                    /* WARNING: Could not emulate address calculation at 0x00001b30 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(*(uint *)(param_1 + 8) * 4 + -0x7ff3bf64))();
    return;
  }
  if (param_3 != 0) {
    iVar4 = *(int *)((_DAT_800ceda4 & 0xfff) * 4 + -0x7ffeb164);
    iVar5 = iVar4 >> 0x10;
    iVar4 = (int)(short)iVar4;
    *param_1 = (short)(iVar5 * (short)param_1[4] + iVar4 * (short)param_1[6] >> 0xc);
    param_1[2] = (short)(-iVar4 * (int)(short)param_1[4] + iVar5 * (short)param_1[6] >> 0xc);
  }
  uVar1 = param_1[0x13];
  uVar2 = param_1[0x12];
  if ((uint)uVar1 != (uint)uVar2) {
    uVar6 = (uint)uVar1 - (uint)uVar2 & 0xfff;
    if (0x800 < uVar6) {
      uVar6 = uVar6 - 0x1000;
    }
    uVar3 = uVar6;
    if ((int)uVar6 < 0) {
      uVar3 = -uVar6;
    }
    if ((int)uVar3 < _DAT_800ceda8) {
      param_1[0x12] = uVar1;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    iVar4 = _DAT_800ceda8;
    if ((int)uVar6 < 1) {
      iVar4 = -_DAT_800ceda8;
    }
    param_1[0x12] = uVar2 + (short)iVar4;
    uVar1 = param_1[0x12];
    param_1[0x12] = uVar1 & 0xfff;
    if (((uVar1 & 0xfff) - param_1[0x13] & 0xfff) == 0) {
      param_1[0x12] = param_1[0x13];
    }
  }
  if (param_2 < 7) {
                    /* WARNING: Could not emulate address calculation at 0x00001d74 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(param_2 * 4 + -0x7ff3bf34))();
    return;
  }
  return;
}


```

## 5. phys_FUN_00007034 @ 0x00007034  tags:physics  score:18

```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00007034(int param_1)

{
  undefined2 *puVar1;
  uint *puVar2;
  uint uVar3;
  undefined2 *puVar4;
  uint uVar5;
  int iVar6;
  uint *puVar7;
  
  _DAT_800cfb34 = *(ushort *)(param_1 + 2);
  uVar5 = (uint)_DAT_800cfb34;
  puVar2 = (uint *)func_0x0003d44c(uVar5 << 5 | 8,0,0);
  puVar7 = puVar2 + 2;
  iVar6 = uVar5 - 1;
  *puVar2 = uVar5;
  puVar2 = puVar7;
  if (uVar5 != 0) {
    do {
      func_0x000cb01c(puVar2);
      iVar6 = iVar6 + -1;
      puVar2 = puVar2 + 8;
    } while (iVar6 != -1);
  }
  puVar4 = (undefined2 *)(param_1 + 4);
  uVar5 = 0;
  _DAT_800cfb30 = puVar7;
  if (_DAT_800cfb34 != 0) {
    do {
      puVar2 = _DAT_800cfb30 + uVar5 * 8;
      *(undefined2 *)(puVar2 + 2) = *puVar4;
      *(undefined2 *)((int)puVar2 + 0x12) = puVar4[1];
      *(undefined2 *)(puVar2 + 4) = puVar4[2];
      uVar3 = (int)(((ushort)puVar4[2] - 4) * 0x10000) >> 0x10;
      if (uVar3 < 0x1b) {
                    /* WARNING: Could not emulate address calculation at 0x00007128 */
                    /* WARNING: Treating indirect jump as call */
        (**(code **)(uVar3 * 4 + -0x7ff3be8c))();
        return;
      }
      *(undefined2 *)(puVar2 + 5) = 0;
      *(undefined2 *)((int)puVar2 + 0x16) = 1;
      *(undefined2 *)((int)puVar2 + 10) = puVar4[8];
      puVar2[3] = (int)(short)puVar4[10];
      *(undefined2 *)puVar2 = puVar4[0xb];
      uVar5 = uVar5 + 1 & 0xffff;
      *(undefined2 *)((int)puVar2 + 2) = puVar4[0xc];
      puVar1 = puVar4 + 0xd;
      uVar3 = (uint)_DAT_800cfb34;
      puVar4 = puVar4 + 0x10;
      *(undefined2 *)(puVar2 + 1) = *puVar1;
    } while (uVar5 < uVar3);
  }
  return;
}


```

## 6. phys_FUN_00007034 @ 0x00007034  tags:physics  score:18

```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00007034(int param_1)

{
  undefined2 *puVar1;
  uint *puVar2;
  uint uVar3;
  undefined2 *puVar4;
  uint uVar5;
  int iVar6;
  uint *puVar7;
  
  _DAT_800cfb34 = *(ushort *)(param_1 + 2);
  uVar5 = (uint)_DAT_800cfb34;
  puVar2 = (uint *)func_0x0003d44c(uVar5 << 5 | 8,0,0);
  puVar7 = puVar2 + 2;
  iVar6 = uVar5 - 1;
  *puVar2 = uVar5;
  puVar2 = puVar7;
  if (uVar5 != 0) {
    do {
      func_0x000cb01c(puVar2);
      iVar6 = iVar6 + -1;
      puVar2 = puVar2 + 8;
    } while (iVar6 != -1);
  }
  puVar4 = (undefined2 *)(param_1 + 4);
  uVar5 = 0;
  _DAT_800cfb30 = puVar7;
  if (_DAT_800cfb34 != 0) {
    do {
      puVar2 = _DAT_800cfb30 + uVar5 * 8;
      *(undefined2 *)(puVar2 + 2) = *puVar4;
      *(undefined2 *)((int)puVar2 + 0x12) = puVar4[1];
      *(undefined2 *)(puVar2 + 4) = puVar4[2];
      uVar3 = (int)(((ushort)puVar4[2] - 4) * 0x10000) >> 0x10;
      if (uVar3 < 0x1b) {
                    /* WARNING: Could not emulate address calculation at 0x00007128 */
                    /* WARNING: Treating indirect jump as call */
        (**(code **)(uVar3 * 4 + -0x7ff3be8c))();
        return;
      }
      *(undefined2 *)(puVar2 + 5) = 0;
      *(undefined2 *)((int)puVar2 + 0x16) = 1;
      *(undefined2 *)((int)puVar2 + 10) = puVar4[8];
      puVar2[3] = (int)(short)puVar4[10];
      *(undefined2 *)puVar2 = puVar4[0xb];
      uVar5 = uVar5 + 1 & 0xffff;
      *(undefined2 *)((int)puVar2 + 2) = puVar4[0xc];
      puVar1 = puVar4 + 0xd;
      uVar3 = (uint)_DAT_800cfb34;
      puVar4 = puVar4 + 0x10;
      *(undefined2 *)(puVar2 + 1) = *puVar1;
    } while (uVar5 < uVar3);
  }
  return;
}


```

## 7. phys_FUN_0000652c @ 0x0000652c  tags:physics  score:17

```c

/* WARNING: Control flow encountered bad instruction data */

uint FUN_0000652c(int param_1,int param_2)

{
  ushort uVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x44);
  if (*(int *)(iVar5 + 0xc) == 3) {
    bVar2 = false;
    if (*(short *)(iVar5 + 0x12) < 0) {
LAB_000065c4:
      bVar2 = true;
    }
    else {
      iVar3 = func_0x000431e4();
      if (0x1f < (uint)(int)*(short *)(iVar5 + 0x12)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      if ((*(uint *)(iVar3 + 0xc) & 1 << ((int)*(short *)(iVar5 + 0x12) & 0x1fU)) != 0)
      goto LAB_000065c4;
    }
    if (!bVar2) {
      *(undefined4 *)(*(int *)(param_1 + 0x44) + 0x1c) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  if (param_2 == 6) {
    uVar4 = *(uint *)(param_1 + 0x48);
    bVar2 = uVar4 < 8;
    if ((uVar4 == 5) || (uVar4 == 6)) goto LAB_00006618;
    func_0x000cad0c(param_1);
  }
  uVar4 = *(uint *)(param_1 + 0x48);
  bVar2 = uVar4 < 8;
LAB_00006618:
  if (bVar2) {
                    /* WARNING: Could not recover jumptable at 0x00006634. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    uVar4 = (**(code **)(uVar4 * 4 + -0x7ff3beac))();
    return uVar4;
  }
  iVar5 = *(int *)(*(int *)(param_1 + 0x44) + 0xc);
  uVar1 = *(ushort *)(*(int *)(param_1 + 0x4c) + 0x24);
  if ((int)*(short *)(param_1 + 0x12) != (uint)uVar1) {
    *(ushort *)(param_1 + 0x12) = uVar1;
    *(short *)(param_1 + 0xe) =
         *(short *)(*(int *)(param_1 + 0x44) + 10) + *(short *)(*(int *)(param_1 + 0x4c) + 0x24);
    func_0x000b0e20(param_1 + 0xc,param_1 + 0x14);
  }
  return (uint)(iVar5 != 0);
}


```

## 8. phys_FUN_0000652c @ 0x0000652c  tags:physics  score:17

```c

/* WARNING: Control flow encountered bad instruction data */

uint FUN_0000652c(int param_1,int param_2)

{
  ushort uVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x44);
  if (*(int *)(iVar5 + 0xc) == 3) {
    bVar2 = false;
    if (*(short *)(iVar5 + 0x12) < 0) {
LAB_000065c4:
      bVar2 = true;
    }
    else {
      iVar3 = func_0x000431e4();
      if (0x1f < (uint)(int)*(short *)(iVar5 + 0x12)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      if ((*(uint *)(iVar3 + 0xc) & 1 << ((int)*(short *)(iVar5 + 0x12) & 0x1fU)) != 0)
      goto LAB_000065c4;
    }
    if (!bVar2) {
      *(undefined4 *)(*(int *)(param_1 + 0x44) + 0x1c) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  if (param_2 == 6) {
    uVar4 = *(uint *)(param_1 + 0x48);
    bVar2 = uVar4 < 8;
    if ((uVar4 == 5) || (uVar4 == 6)) goto LAB_00006618;
    func_0x000cad0c(param_1);
  }
  uVar4 = *(uint *)(param_1 + 0x48);
  bVar2 = uVar4 < 8;
LAB_00006618:
  if (bVar2) {
                    /* WARNING: Could not recover jumptable at 0x00006634. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    uVar4 = (**(code **)(uVar4 * 4 + -0x7ff3beac))();
    return uVar4;
  }
  iVar5 = *(int *)(*(int *)(param_1 + 0x44) + 0xc);
  uVar1 = *(ushort *)(*(int *)(param_1 + 0x4c) + 0x24);
  if ((int)*(short *)(param_1 + 0x12) != (uint)uVar1) {
    *(ushort *)(param_1 + 0x12) = uVar1;
    *(short *)(param_1 + 0xe) =
         *(short *)(*(int *)(param_1 + 0x44) + 10) + *(short *)(*(int *)(param_1 + 0x4c) + 0x24);
    func_0x000b0e20(param_1 + 0xc,param_1 + 0x14);
  }
  return (uint)(iVar5 != 0);
}


```

## 9. phys_FUN_000053dc @ 0x000053dc  tags:physics  score:13

```c

undefined4 FUN_000053dc(int param_1)

{
  short sVar1;
  undefined4 uVar2;
  
  *(undefined2 *)(param_1 + 0x34) = **(undefined2 **)(param_1 + 0x48);
  *(undefined2 *)(param_1 + 0x38) = (*(undefined2 **)(param_1 + 0x48))[2];
  if (*(uint *)(param_1 + 0x44) < 5) {
                    /* WARNING: Could not emulate address calculation at 0x0000542c */
                    /* WARNING: Treating indirect jump as call */
    uVar2 = (**(code **)(*(uint *)(param_1 + 0x44) * 4 + -0x7ff3bec0))();
    return uVar2;
  }
  sVar1 = *(short *)(param_1 + 0x32) + *(short *)(param_1 + 0x30);
  *(short *)(param_1 + 0x32) = sVar1;
  *(short *)(param_1 + 0x36) = *(short *)(param_1 + 0x36) + (sVar1 >> 6);
  return 1;
}


```

## 10. phys_FUN_000053dc @ 0x000053dc  tags:physics  score:13

```c

undefined4 FUN_000053dc(int param_1)

{
  short sVar1;
  undefined4 uVar2;
  
  *(undefined2 *)(param_1 + 0x34) = **(undefined2 **)(param_1 + 0x48);
  *(undefined2 *)(param_1 + 0x38) = (*(undefined2 **)(param_1 + 0x48))[2];
  if (*(uint *)(param_1 + 0x44) < 5) {
                    /* WARNING: Could not emulate address calculation at 0x0000542c */
                    /* WARNING: Treating indirect jump as call */
    uVar2 = (**(code **)(*(uint *)(param_1 + 0x44) * 4 + -0x7ff3bec0))();
    return uVar2;
  }
  sVar1 = *(short *)(param_1 + 0x32) + *(short *)(param_1 + 0x30);
  *(short *)(param_1 + 0x32) = sVar1;
  *(short *)(param_1 + 0x36) = *(short *)(param_1 + 0x36) + (sVar1 >> 6);
  return 1;
}


```

## 11. phys_FUN_00000900 @ 0x00000900  tags:physics  score:11

```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_00000900(void)

{
  undefined4 uVar1;
  
  if (_DAT_800cfa50 < 7) {
                    /* WARNING: Could not emulate address calculation at 0x00000938 */
                    /* WARNING: Treating indirect jump as call */
    uVar1 = (**(code **)(_DAT_800cfa50 * 4 + -0x7ff3bf84))();
    return uVar1;
  }
  return 0;
}


```

## 12. phys_FUN_00000900 @ 0x00000900  tags:physics  score:11

```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_00000900(void)

{
  undefined4 uVar1;
  
  if (_DAT_800cfa50 < 7) {
                    /* WARNING: Could not emulate address calculation at 0x00000938 */
                    /* WARNING: Treating indirect jump as call */
    uVar1 = (**(code **)(_DAT_800cfa50 * 4 + -0x7ff3bf84))();
    return uVar1;
  }
  return 0;
}


```

