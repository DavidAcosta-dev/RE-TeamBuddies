# Vertical Function Focus

## FUN_0001cff0

```

undefined4 FUN_0001cff0(int param_1)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  ushort *puVar6;
  uint uVar7;
  int iVar8;
  
  iVar8 = *(int *)(*(int *)(param_1 + 0x24) + 8);
  iVar2 = func_0x00095d6c(*(undefined4 *)(*(int *)(iVar8 + 0x11c) + 0x40),
                          *(undefined2 *)(*(int *)(param_1 + 0x18) + 8),
                          *(undefined2 *)(*(int *)(param_1 + 0x18) + 10),0);
  uVar7 = 0;
  do {
    iVar3 = uVar7 * 4;
    iVar4 = uVar7 * 2;
    puVar6 = (ushort *)(iVar8 + 0x2c4 + iVar4);
    *(undefined4 *)(iVar8 + 0x2f8 + iVar3) = 0;
    *(int *)(iVar8 + 0x2f0 + iVar3) = iVar2;
    iVar5 = (int)(short)*puVar6;
    uVar1 = *(ushort *)(iVar2 + 2);
    if ((iVar5 < (int)(uint)uVar1) || ((int)(uint)*(ushort *)(iVar2 + 4) < iVar5)) {
      *(ushort *)(iVar8 + 0x2c8 + iVar4) = uVar1;
      *puVar6 = uVar1;
    }
    uVar7 = uVar7 + 1 & 0xffff;
    *(undefined2 *)(iVar8 + 0x2cc + iVar4) = *(undefined2 *)(iVar2 + 4);
    *(undefined4 *)(iVar8 + 0x2e0 + iVar3) = 0x10;
  } while (uVar7 < 2);
  return 1;
}

```

## FUN_0001d100

```

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_0001d100(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(*(int *)(param_1 + 0x24) + 8);
  iVar1 = func_0x00095d6c(*(undefined4 *)(*(int *)(iVar3 + 0x11c) + 0x40),
                          *(undefined2 *)(*(int *)(param_1 + 0x18) + 8),
                          *(undefined2 *)(*(int *)(param_1 + 0x18) + 10),0);
  if (iVar1 == *(int *)(iVar3 + 0x2f0)) {
    iVar2 = (uint)*(ushort *)(iVar1 + 4) - (int)*(short *)(iVar3 + 0x2c4);
    if (iVar2 < 0) {
      iVar2 = (int)*(short *)(iVar3 + 0x2c4) - (uint)*(ushort *)(iVar1 + 4);
    }
    if (iVar2 < 3) goto LAB_0001d18c;
  }
  if ((*(short *)(iVar3 + 0x34) == 0) && (*(short *)(iVar3 + 0x38) == 0)) {
    return 0;
  }
LAB_0001d18c:
  *(undefined4 *)(iVar3 + 0x290) = _DAT_800c02ac;
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}

```

## FUN_0001f558

```

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_0001f558(int param_1)

{
  undefined2 uVar1;
  int iVar2;
  short sVar3;
  
  if (-1 < *(short *)(*(int *)(param_1 + 0x11c) + 0x60)) {
    iVar2 = func_0x000e3554();
    uVar1 = **(undefined2 **)(param_1 + 0x11c);
    sVar3 = _DAT_800c02ac + (*(undefined2 **)(param_1 + 0x11c))[0x30];
    *(undefined2 *)(iVar2 + 6) = *(undefined2 *)(*(int *)(param_1 + 0x318) + 0x34);
    *(undefined2 *)(iVar2 + 2) = uVar1;
    *(short *)(iVar2 + 4) = sVar3;
    *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 0x10c);
    *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(param_1 + 0x110);
  }
  func_0x00074854(0x8010e514,(int)*(short *)(param_1 + 0x4a));
  return;
}

```

## FUN_0001f5ec

```

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_0001f5ec(int param_1)

{
  undefined2 uVar1;
  int iVar2;
  short sVar3;
  
  if (-1 < *(short *)(*(int *)(param_1 + 0x11c) + 0x60)) {
    iVar2 = func_0x000e3554();
    uVar1 = **(undefined2 **)(param_1 + 0x11c);
    sVar3 = _DAT_800c02ac + (*(undefined2 **)(param_1 + 0x11c))[0x30];
    *(undefined2 *)(iVar2 + 6) = *(undefined2 *)(*(int *)(param_1 + 0x318) + 0x34);
    *(undefined2 *)(iVar2 + 2) = uVar1;
    *(short *)(iVar2 + 4) = sVar3;
    *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 0x10c);
    *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(param_1 + 0x110);
  }
  func_0x00074854(0x8010e4fc,(int)*(short *)(param_1 + 0x4a));
  return;
}

```

