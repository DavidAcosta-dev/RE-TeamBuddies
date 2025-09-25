# Snippets for SYS.BIN

## 1. phys_FUN_00005c9c @ 0x00005c9c  tags:physics  score:45

```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00005c9c(void)

{
  bool bVar1;
  short sVar2;
  undefined1 *puVar3;
  int iVar4;
  uint uVar5;
  undefined2 *puVar6;
  uint uVar7;
  int *piVar8;
  uint uVar9;
  short *psVar10;
  short sVar11;
  
  uVar7 = 0;
  do {
    puVar3 = _DAT_80049c7c + uVar7;
    uVar7 = uVar7 + 1;
    *puVar3 = 0;
  } while (uVar7 < 0x47);
  uVar7 = 0;
  puVar6 = (undefined2 *)&DAT_8004862c;
  do {
    *puVar6 = 0xffff;
    uVar7 = uVar7 + 1;
    puVar6 = puVar6 + 1;
  } while (uVar7 < 0x46);
  uVar7 = 0;
  piVar8 = (int *)&DAT_80119920;
  do {
    *(undefined1 *)(_DAT_80049c78 + uVar7) = 0;
    if (*piVar8 != 0) {
      *(undefined1 *)(_DAT_80049c78 + uVar7) = 1;
    }
    uVar7 = uVar7 + 1;
    piVar8 = piVar8 + 1;
  } while (uVar7 < 0x3e);
  uVar9 = 0;
  uVar7 = 0;
  do {
    *(undefined1 *)(_DAT_80049c74 + uVar9) = 0;
    iVar4 = func_0x000f5b78(uVar7,1);
    if (iVar4 != 0) {
      *(undefined1 *)(_DAT_80049c74 + uVar9) = 1;
    }
    uVar9 = uVar9 + 1;
    uVar7 = uVar9 & 0xffff;
  } while (uVar9 < 0x54);
  uVar7 = 0;
  piVar8 = (int *)&DAT_8011a348;
  do {
    *(undefined1 *)(_DAT_80049c70 + uVar7) = 0;
    if (*piVar8 != 0) {
      *(undefined1 *)(_DAT_80049c70 + uVar7) = 1;
    }
    uVar7 = uVar7 + 1;
    piVar8 = piVar8 + 1;
  } while (uVar7 < 0x59);
  bVar1 = false;
  uVar7 = 0x11;
  iVar4 = 0x44;
  do {
    iVar4 = *(int *)(iVar4 + -0x7fee5eb8);
    if (((iVar4 != 0) && (*(int *)(iVar4 + 4) == 3)) && (*(int *)(iVar4 + 8) == 1)) {
      bVar1 = true;
    }
    uVar7 = uVar7 - 1 & 0xffff;
    iVar4 = uVar7 << 2;
  } while (uVar7 != 0xffff);
  if (!bVar1) {
    *(undefined1 *)(_DAT_80049c78 + 1) = 0;
  }
  uVar7 = 0;
  psVar10 = (short *)&DAT_8004862c;
  sVar11 = 0;
  do {
    sVar2 = sVar11;
    if ((*(char *)(_DAT_80049c78 + uVar7) != '\0') &&
       (((_DAT_8004d754 == 0 || (((5 < uVar7 && (uVar7 != 0x1f)) && (uVar7 != 0x21)))) &&
        (iVar4 = func_0x0003ec0c(uVar7 & 0xffff), iVar4 == 0)))) {
      sVar2 = sVar11 + 1;
      *psVar10 = sVar11;
    }
    uVar7 = uVar7 + 1;
    psVar10 = psVar10 + 1;
    sVar11 = sVar2;
  } while (uVar7 < 0x3e);
  if ((_DAT_8004d754 != 0) && (uVar7 = 0, _DAT_8004d6ec != 0)) {
    do {
      uVar9 = uVar7 & 0xffff;
      uVar7 = uVar7 + 1;
      iVar4 = func_0x0003ebf0(*(undefined2 *)(&DAT_8004d712 + uVar9 * 2));
      uVar9 = (uint)_DAT_8004d6ec;
      *(short *)(&DAT_8004862c + (iVar4 + 0x3e) * 2) = sVar2;
      sVar2 = sVar2 + 1;
    } while (uVar7 < uVar9);
  }
  uVar7 = 0;
  while ((*(char *)(_DAT_80049c70 + uVar7) == '\0' ||
         (uVar9 = func_0x0003f408(*(undefined4 *)(*(int *)(&DAT_8011a348 + uVar7 * 4) + 0x1c)),
         5 < uVar9))) {
    uVar7 = uVar7 + 1;
    if (0x58 < uVar7) {
      _DAT_80049c7c[0x2b] = 1;
      _DAT_80049c7c[0x2a] = 1;
      _DAT_80049c7c[0x21] = 1;
      _DAT_80049c7c[0x23] = 1;
      _DAT_80049c7c[0x24] = 1;
      _DAT_80049c7c[0x25] = 1;
      _DAT_80049c7c[0x26] = 1;
      _DAT_80049c7c[0x27] = 1;
      _DAT_80049c7c[0x28] = 1;
      _DAT_80049c7c[0x29] = 1;
      _DAT_80049c7c[0x37] = 1;
      _DAT_80049c7c[0x2f] = 1;
      _DAT_80049c7c[0x1f] = 1;
      _DAT_80049c7c[0x20] = 1;
      _DAT_80049c7c[0x34] = 1;
      _DAT_80049c7c[0x31] = 1;
      _DAT_80049c7c[0x22] = 1;
      _DAT_80049c7c[0x35] = 1;
      _DAT_80049c7c[0x36] = 1;
      _DAT_80049c7c[0x32] = 1;
      _DAT_80049c7c[0x33] = 1;
      _DAT_80049c7c[0x35] = 1;
      _DAT_80049c7c[0x36] = 1;
      _DAT_80049c7c[1] = 1;
      _DAT_80049c7c[2] = 1;
      _DAT_80049c7c[3] = 1;
      _DAT_80049c7c[4] = 1;
      *_DAT_80049c7c = 1;
      _DAT_80049c7c[0x15] = 1;
      _DAT_80049c7c[0x16] = 1;
      _DAT_80049c7c[0x17] = 1;
      _DAT_80049c7c[0x18] = 1;
      _DAT_80049c7c[0x19] = 1;
      _DAT_80049c7c[0x2c] = 1;
      _DAT_80049c7c[0x2d] = 1;
      _DAT_80049c7c[0x2e] = 1;
      _DAT_80049c7c[0x3d] = 1;
      _DAT_80049c7c[0x3e] = 1;
      _DAT_80049c7c[0x3f] = 1;
      _DAT_80049c7c[0x40] = 1;
      _DAT_80049c7c[0x41] = 1;
      _DAT_80049c7c[0x42] = 1;
      _DAT_80049c7c[0x43] = 1;
      _DAT_80049c7c[0x44] = 1;
      _DAT_80049c7c[0x45] = 1;
      _DAT_80049c7c[0x46] = 1;
      uVar9 = (uint)_DAT_8004d6ec;
      uVar7 = 0;
      if (uVar9 != 0) {
        uVar5 = 0;
        do {
          uVar7 = uVar7 + 1;
          iVar4 = func_0x0003ebf0(*(undefined2 *)(&DAT_8004d712 + uVar5 * 2));
          _DAT_80049c7c[iVar4 + 6] = 1;
          uVar5 = uVar7 & 0xffff;
        } while (uVar7 < uVar9);
      }
      _DAT_80049c7c[0x38] = 1;
      _DAT_80049c7c[0x39] = 1;
      _DAT_80049c7c[0x3a] = 1;
      _DAT_80049c7c[0x3b] = 1;
      _DAT_80049c7c[0x3c] = 1;
      if (_DAT_8004d6ee == 0x1e) {
        _DAT_80049c7c[0x21] = 0;
        _DAT_80049c7c[0x23] = 0;
        _DAT_80049c7c[0x24] = 0;
        _DAT_80049c7c[0x25] = 0;
        _DAT_80049c7c[0x26] = 0;
        _DAT_80049c7c[0x27] = 0;
        _DAT_80049c7c[0x16] = 0;
        _DAT_80049c7c[0x17] = 0;
        _DAT_80049c7c[0x37] = 0;
      }
      func_0x0003f4f0();
      func_0x0003f6bc();
      func_0x0003f844();
      func_0x0003f984();
      return;
    }
  }
                    /* WARNING: Could not emulate address calculation at 0x00005fe0 */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(uVar9 * 4 + -0x7ffc5d0c))();
  return;
}


```

## 2. phys_FUN_00005c9c @ 0x00005c9c  tags:physics  score:45

```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00005c9c(void)

{
  bool bVar1;
  short sVar2;
  undefined1 *puVar3;
  int iVar4;
  uint uVar5;
  undefined2 *puVar6;
  uint uVar7;
  int *piVar8;
  uint uVar9;
  short *psVar10;
  short sVar11;
  
  uVar7 = 0;
  do {
    puVar3 = _DAT_80049c7c + uVar7;
    uVar7 = uVar7 + 1;
    *puVar3 = 0;
  } while (uVar7 < 0x47);
  uVar7 = 0;
  puVar6 = (undefined2 *)&DAT_8004862c;
  do {
    *puVar6 = 0xffff;
    uVar7 = uVar7 + 1;
    puVar6 = puVar6 + 1;
  } while (uVar7 < 0x46);
  uVar7 = 0;
  piVar8 = (int *)&DAT_80119920;
  do {
    *(undefined1 *)(_DAT_80049c78 + uVar7) = 0;
    if (*piVar8 != 0) {
      *(undefined1 *)(_DAT_80049c78 + uVar7) = 1;
    }
    uVar7 = uVar7 + 1;
    piVar8 = piVar8 + 1;
  } while (uVar7 < 0x3e);
  uVar9 = 0;
  uVar7 = 0;
  do {
    *(undefined1 *)(_DAT_80049c74 + uVar9) = 0;
    iVar4 = func_0x000f5b78(uVar7,1);
    if (iVar4 != 0) {
      *(undefined1 *)(_DAT_80049c74 + uVar9) = 1;
    }
    uVar9 = uVar9 + 1;
    uVar7 = uVar9 & 0xffff;
  } while (uVar9 < 0x54);
  uVar7 = 0;
  piVar8 = (int *)&DAT_8011a348;
  do {
    *(undefined1 *)(_DAT_80049c70 + uVar7) = 0;
    if (*piVar8 != 0) {
      *(undefined1 *)(_DAT_80049c70 + uVar7) = 1;
    }
    uVar7 = uVar7 + 1;
    piVar8 = piVar8 + 1;
  } while (uVar7 < 0x59);
  bVar1 = false;
  uVar7 = 0x11;
  iVar4 = 0x44;
  do {
    iVar4 = *(int *)(iVar4 + -0x7fee5eb8);
    if (((iVar4 != 0) && (*(int *)(iVar4 + 4) == 3)) && (*(int *)(iVar4 + 8) == 1)) {
      bVar1 = true;
    }
    uVar7 = uVar7 - 1 & 0xffff;
    iVar4 = uVar7 << 2;
  } while (uVar7 != 0xffff);
  if (!bVar1) {
    *(undefined1 *)(_DAT_80049c78 + 1) = 0;
  }
  uVar7 = 0;
  psVar10 = (short *)&DAT_8004862c;
  sVar11 = 0;
  do {
    sVar2 = sVar11;
    if ((*(char *)(_DAT_80049c78 + uVar7) != '\0') &&
       (((_DAT_8004d754 == 0 || (((5 < uVar7 && (uVar7 != 0x1f)) && (uVar7 != 0x21)))) &&
        (iVar4 = func_0x0003ec0c(uVar7 & 0xffff), iVar4 == 0)))) {
      sVar2 = sVar11 + 1;
      *psVar10 = sVar11;
    }
    uVar7 = uVar7 + 1;
    psVar10 = psVar10 + 1;
    sVar11 = sVar2;
  } while (uVar7 < 0x3e);
  if ((_DAT_8004d754 != 0) && (uVar7 = 0, _DAT_8004d6ec != 0)) {
    do {
      uVar9 = uVar7 & 0xffff;
      uVar7 = uVar7 + 1;
      iVar4 = func_0x0003ebf0(*(undefined2 *)(&DAT_8004d712 + uVar9 * 2));
      uVar9 = (uint)_DAT_8004d6ec;
      *(short *)(&DAT_8004862c + (iVar4 + 0x3e) * 2) = sVar2;
      sVar2 = sVar2 + 1;
    } while (uVar7 < uVar9);
  }
  uVar7 = 0;
  while ((*(char *)(_DAT_80049c70 + uVar7) == '\0' ||
         (uVar9 = func_0x0003f408(*(undefined4 *)(*(int *)(&DAT_8011a348 + uVar7 * 4) + 0x1c)),
         5 < uVar9))) {
    uVar7 = uVar7 + 1;
    if (0x58 < uVar7) {
      _DAT_80049c7c[0x2b] = 1;
      _DAT_80049c7c[0x2a] = 1;
      _DAT_80049c7c[0x21] = 1;
      _DAT_80049c7c[0x23] = 1;
      _DAT_80049c7c[0x24] = 1;
      _DAT_80049c7c[0x25] = 1;
      _DAT_80049c7c[0x26] = 1;
      _DAT_80049c7c[0x27] = 1;
      _DAT_80049c7c[0x28] = 1;
      _DAT_80049c7c[0x29] = 1;
      _DAT_80049c7c[0x37] = 1;
      _DAT_80049c7c[0x2f] = 1;
      _DAT_80049c7c[0x1f] = 1;
      _DAT_80049c7c[0x20] = 1;
      _DAT_80049c7c[0x34] = 1;
      _DAT_80049c7c[0x31] = 1;
      _DAT_80049c7c[0x22] = 1;
      _DAT_80049c7c[0x35] = 1;
      _DAT_80049c7c[0x36] = 1;
      _DAT_80049c7c[0x32] = 1;
      _DAT_80049c7c[0x33] = 1;
      _DAT_80049c7c[0x35] = 1;
      _DAT_80049c7c[0x36] = 1;
      _DAT_80049c7c[1] = 1;
      _DAT_80049c7c[2] = 1;
      _DAT_80049c7c[3] = 1;
      _DAT_80049c7c[4] = 1;
      *_DAT_80049c7c = 1;
      _DAT_80049c7c[0x15] = 1;
      _DAT_80049c7c[0x16] = 1;
      _DAT_80049c7c[0x17] = 1;
      _DAT_80049c7c[0x18] = 1;
      _DAT_80049c7c[0x19] = 1;
      _DAT_80049c7c[0x2c] = 1;
      _DAT_80049c7c[0x2d] = 1;
      _DAT_80049c7c[0x2e] = 1;
      _DAT_80049c7c[0x3d] = 1;
      _DAT_80049c7c[0x3e] = 1;
      _DAT_80049c7c[0x3f] = 1;
      _DAT_80049c7c[0x40] = 1;
      _DAT_80049c7c[0x41] = 1;
      _DAT_80049c7c[0x42] = 1;
      _DAT_80049c7c[0x43] = 1;
      _DAT_80049c7c[0x44] = 1;
      _DAT_80049c7c[0x45] = 1;
      _DAT_80049c7c[0x46] = 1;
      uVar9 = (uint)_DAT_8004d6ec;
      uVar7 = 0;
      if (uVar9 != 0) {
        uVar5 = 0;
        do {
          uVar7 = uVar7 + 1;
          iVar4 = func_0x0003ebf0(*(undefined2 *)(&DAT_8004d712 + uVar5 * 2));
          _DAT_80049c7c[iVar4 + 6] = 1;
          uVar5 = uVar7 & 0xffff;
        } while (uVar7 < uVar9);
      }
      _DAT_80049c7c[0x38] = 1;
      _DAT_80049c7c[0x39] = 1;
      _DAT_80049c7c[0x3a] = 1;
      _DAT_80049c7c[0x3b] = 1;
      _DAT_80049c7c[0x3c] = 1;
      if (_DAT_8004d6ee == 0x1e) {
        _DAT_80049c7c[0x21] = 0;
        _DAT_80049c7c[0x23] = 0;
        _DAT_80049c7c[0x24] = 0;
        _DAT_80049c7c[0x25] = 0;
        _DAT_80049c7c[0x26] = 0;
        _DAT_80049c7c[0x27] = 0;
        _DAT_80049c7c[0x16] = 0;
        _DAT_80049c7c[0x17] = 0;
        _DAT_80049c7c[0x37] = 0;
      }
      func_0x0003f4f0();
      func_0x0003f6bc();
      func_0x0003f844();
      func_0x0003f984();
      return;
    }
  }
                    /* WARNING: Could not emulate address calculation at 0x00005fe0 */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(uVar9 * 4 + -0x7ffc5d0c))();
  return;
}


```

## 3. phys_FUN_00002b10 @ 0x00002b10  tags:physics  score:30

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00002b10(code *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  undefined1 auStack_38 [4];
  uint local_34;
  undefined1 auStack_30 [4];
  int local_2c;
  
LAB_00002b54:
  do {
    (*param_1)(*(undefined4 *)(_DAT_80048e68 + 100),_DAT_80048e68 + 0xb4,0,0);
    local_34 = 0;
    do {
      uVar1 = local_34;
      func_0x00020eac(0);
      func_0x00021f04(0,auStack_38,&local_34);
      _DAT_80048e78 = local_34;
      if ((local_34 == 0) || (local_34 == 3)) break;
    } while (local_34 != uVar1);
    iVar2 = 0;
    if (local_34 < 5) {
                    /* WARNING: Could not emulate address calculation at 0x00002bd0 */
                    /* WARNING: Treating indirect jump as call */
      (**(code **)(local_34 * 4 + -0x7ffc7034))();
      return;
    }
    func_0x00021f04(0,auStack_38,auStack_30);
    local_34 = func_0x000211bc(0,_DAT_80043c68,1);
    if ((local_34 == 0) && (param_2 != 0)) {
      iVar2 = func_0x0003d44c(0xa00,1,0);
      local_2c = func_0x00021388(iVar2,0x100,0xa00);
      func_0x00021f04(0,auStack_38,&local_2c);
      func_0x00021344();
      func_0x00021f04(0,auStack_38,auStack_30);
      if (local_2c == 0) {
        _DAT_80043c6c = (char *)(_DAT_8004d728 * 0x30c + iVar2 + 0xc6);
        func_0x0003d5c4(iVar2,1);
        if (*_DAT_80043c6c == '\0') {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        local_34 = (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0xa8),_DAT_80048e68 + 0xb8,2,0);
        if (local_34 == 0) {
          return;
        }
        if (local_34 == 1) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
      goto LAB_00002b54;
    }
    func_0x00021344();
    func_0x00021f04(0,auStack_38,auStack_30);
    if (local_34 == 0) {
      local_34 = (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x7c),_DAT_80048e68 + 0xb8,2,0);
      if (local_34 == 0) {
        return;
      }
      if (local_34 != 1) goto LAB_00002b54;
      if (param_2 != 0) {
        halt_baddata();
      }
    }
    else {
      if (local_34 != 5) goto LAB_00002b54;
      local_34 = (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x78),_DAT_80048e68 + 0xb8,2,0);
      if (local_34 == 0) {
        return;
      }
      if (local_34 != 1) goto LAB_00002b54;
      iVar2 = 1;
    }
    local_34 = 1;
    if (iVar2 == 0) goto LAB_00002f28;
    func_0x00021f04(0,auStack_38,auStack_30);
    (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x8c),_DAT_80048e68 + 0xb4,0,0);
    local_34 = func_0x00022020(0,_DAT_80043c68,1);
    if ((local_34 == 7) && (local_34 = func_0x00022020(0,_DAT_80043c68,1), local_34 == 7)) {
      iVar2 = (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x90),_DAT_80048e68 + 0xc0,1,0);
      if (iVar2 == 0) {
        return;
      }
      halt_baddata();
    }
    if (local_34 == 0) {
LAB_00002f28:
      (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x84),_DAT_80048e68 + 0xb4,0,0);
      local_34 = func_0x0003c030(1,iVar2,param_2);
      if (local_34 == 0) {
        (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0xa0),_DAT_80048e68 + 0xc4,1,1);
      }
      else {
        iVar2 = (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x94),_DAT_80048e68 + 0xb4,2,1);
        if (iVar2 != 1) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
      return;
    }
  } while( true );
}


```

## 4. phys_FUN_00002b10 @ 0x00002b10  tags:physics  score:30

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00002b10(code *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  undefined1 auStack_38 [4];
  uint local_34;
  undefined1 auStack_30 [4];
  int local_2c;
  
LAB_00002b54:
  do {
    (*param_1)(*(undefined4 *)(_DAT_80048e68 + 100),_DAT_80048e68 + 0xb4,0,0);
    local_34 = 0;
    do {
      uVar1 = local_34;
      func_0x00020eac(0);
      func_0x00021f04(0,auStack_38,&local_34);
      _DAT_80048e78 = local_34;
      if ((local_34 == 0) || (local_34 == 3)) break;
    } while (local_34 != uVar1);
    iVar2 = 0;
    if (local_34 < 5) {
                    /* WARNING: Could not emulate address calculation at 0x00002bd0 */
                    /* WARNING: Treating indirect jump as call */
      (**(code **)(local_34 * 4 + -0x7ffc7034))();
      return;
    }
    func_0x00021f04(0,auStack_38,auStack_30);
    local_34 = func_0x000211bc(0,_DAT_80043c68,1);
    if ((local_34 == 0) && (param_2 != 0)) {
      iVar2 = func_0x0003d44c(0xa00,1,0);
      local_2c = func_0x00021388(iVar2,0x100,0xa00);
      func_0x00021f04(0,auStack_38,&local_2c);
      func_0x00021344();
      func_0x00021f04(0,auStack_38,auStack_30);
      if (local_2c == 0) {
        _DAT_80043c6c = (char *)(_DAT_8004d728 * 0x30c + iVar2 + 0xc6);
        func_0x0003d5c4(iVar2,1);
        if (*_DAT_80043c6c == '\0') {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        local_34 = (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0xa8),_DAT_80048e68 + 0xb8,2,0);
        if (local_34 == 0) {
          return;
        }
        if (local_34 == 1) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
      goto LAB_00002b54;
    }
    func_0x00021344();
    func_0x00021f04(0,auStack_38,auStack_30);
    if (local_34 == 0) {
      local_34 = (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x7c),_DAT_80048e68 + 0xb8,2,0);
      if (local_34 == 0) {
        return;
      }
      if (local_34 != 1) goto LAB_00002b54;
      if (param_2 != 0) {
        halt_baddata();
      }
    }
    else {
      if (local_34 != 5) goto LAB_00002b54;
      local_34 = (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x78),_DAT_80048e68 + 0xb8,2,0);
      if (local_34 == 0) {
        return;
      }
      if (local_34 != 1) goto LAB_00002b54;
      iVar2 = 1;
    }
    local_34 = 1;
    if (iVar2 == 0) goto LAB_00002f28;
    func_0x00021f04(0,auStack_38,auStack_30);
    (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x8c),_DAT_80048e68 + 0xb4,0,0);
    local_34 = func_0x00022020(0,_DAT_80043c68,1);
    if ((local_34 == 7) && (local_34 = func_0x00022020(0,_DAT_80043c68,1), local_34 == 7)) {
      iVar2 = (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x90),_DAT_80048e68 + 0xc0,1,0);
      if (iVar2 == 0) {
        return;
      }
      halt_baddata();
    }
    if (local_34 == 0) {
LAB_00002f28:
      (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x84),_DAT_80048e68 + 0xb4,0,0);
      local_34 = func_0x0003c030(1,iVar2,param_2);
      if (local_34 == 0) {
        (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0xa0),_DAT_80048e68 + 0xc4,1,1);
      }
      else {
        iVar2 = (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x94),_DAT_80048e68 + 0xb4,2,1);
        if (iVar2 != 1) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
      return;
    }
  } while( true );
}


```

## 5. phys_FUN_0000377c @ 0x0000377c  tags:physics  score:22

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Removing unreachable block (ram,0x00003890) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_0000377c(uint param_1)

{
  int unaff_s2;
  undefined4 uVar1;
  
  func_0x0001bc08(0);
  func_0x000205ac(0);
  if ((param_1 & 0xf) < 5) {
                    /* WARNING: Could not emulate address calculation at 0x000037cc */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)((param_1 & 0xf) * 4 + -0x7ffc7008))();
    return;
  }
  if ((param_1 & 0x40) == 0) {
    func_0x000207bc(0x80048eb0,0,0);
    func_0x000207bc(0x80048f2c,0,0x100);
    func_0x00023cd8(0x80048ec4,0,0x100);
    uVar1 = 0x100;
    func_0x00023cd8(0x80048f40,0,0);
    _DAT_80048f3a = 0x100;
    _DAT_80048ebe = 0x100;
    DAT_80048f3c = 0;
    DAT_80048ec0 = 0;
    _DAT_80048e82 = 0x100;
    _DAT_80048e80 = (undefined2)unaff_s2;
    _DAT_80048f34 = _DAT_80048e7c;
    _DAT_80048eb8 = _DAT_80048e7c;
    _DAT_80048f36 = _DAT_80048e7e;
    _DAT_80048eba = _DAT_80048e7e;
    func_0x0003cd48(0,0,(unaff_s2 + 1) * 0x10000 >> 0x10,0x101,uVar1);
    DAT_80048edc = 1;
    DAT_80048f58 = 1;
    DAT_80048eda = 1;
    DAT_80048f56 = 1;
    DAT_80048edd = 0;
    DAT_80048ede = 0;
    DAT_80048edf = 0;
    DAT_80048f59 = 0;
    DAT_80048f5a = 0;
    DAT_80048f5b = 0;
    _DAT_80048f54 = 0;
    _DAT_80048ed8 = 0;
    DAT_80048edb = 0;
    DAT_80048f57 = 0;
    _DAT_80048ed0 = 0;
    _DAT_80048ed2 = 0;
    _DAT_80048ed4 = 0xff;
    _DAT_80048ed6 = 0xff;
    _DAT_80048f4c = 0;
    _DAT_80048f4e = 0;
    _DAT_80048f50 = 0xff;
    _DAT_80048f52 = 0xff;
    DAT_80048e90 = 0;
    DAT_80048e84 = (char)param_1;
    func_0x000205ac(0);
    func_0x0001c438(0x80048eb0);
    func_0x0001c26c(0x80048ec4);
    func_0x0001ca54(&DAT_80048ee0,0x80048ec4);
    func_0x0001ca54(&DAT_80048f5c,0x80048f40);
    _DAT_80043cfc = &DAT_80048ea8 + (uint)DAT_80048e90 * 0x7c;
    func_0x0003cbc8();
    func_0x0003cc00();
    func_0x0003ce14(0);
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


```

## 6. phys_FUN_0000377c @ 0x0000377c  tags:physics  score:22

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Removing unreachable block (ram,0x00003890) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_0000377c(uint param_1)

{
  int unaff_s2;
  undefined4 uVar1;
  
  func_0x0001bc08(0);
  func_0x000205ac(0);
  if ((param_1 & 0xf) < 5) {
                    /* WARNING: Could not emulate address calculation at 0x000037cc */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)((param_1 & 0xf) * 4 + -0x7ffc7008))();
    return;
  }
  if ((param_1 & 0x40) == 0) {
    func_0x000207bc(0x80048eb0,0,0);
    func_0x000207bc(0x80048f2c,0,0x100);
    func_0x00023cd8(0x80048ec4,0,0x100);
    uVar1 = 0x100;
    func_0x00023cd8(0x80048f40,0,0);
    _DAT_80048f3a = 0x100;
    _DAT_80048ebe = 0x100;
    DAT_80048f3c = 0;
    DAT_80048ec0 = 0;
    _DAT_80048e82 = 0x100;
    _DAT_80048e80 = (undefined2)unaff_s2;
    _DAT_80048f34 = _DAT_80048e7c;
    _DAT_80048eb8 = _DAT_80048e7c;
    _DAT_80048f36 = _DAT_80048e7e;
    _DAT_80048eba = _DAT_80048e7e;
    func_0x0003cd48(0,0,(unaff_s2 + 1) * 0x10000 >> 0x10,0x101,uVar1);
    DAT_80048edc = 1;
    DAT_80048f58 = 1;
    DAT_80048eda = 1;
    DAT_80048f56 = 1;
    DAT_80048edd = 0;
    DAT_80048ede = 0;
    DAT_80048edf = 0;
    DAT_80048f59 = 0;
    DAT_80048f5a = 0;
    DAT_80048f5b = 0;
    _DAT_80048f54 = 0;
    _DAT_80048ed8 = 0;
    DAT_80048edb = 0;
    DAT_80048f57 = 0;
    _DAT_80048ed0 = 0;
    _DAT_80048ed2 = 0;
    _DAT_80048ed4 = 0xff;
    _DAT_80048ed6 = 0xff;
    _DAT_80048f4c = 0;
    _DAT_80048f4e = 0;
    _DAT_80048f50 = 0xff;
    _DAT_80048f52 = 0xff;
    DAT_80048e90 = 0;
    DAT_80048e84 = (char)param_1;
    func_0x000205ac(0);
    func_0x0001c438(0x80048eb0);
    func_0x0001c26c(0x80048ec4);
    func_0x0001ca54(&DAT_80048ee0,0x80048ec4);
    func_0x0001ca54(&DAT_80048f5c,0x80048f40);
    _DAT_80043cfc = &DAT_80048ea8 + (uint)DAT_80048e90 * 0x7c;
    func_0x0003cbc8();
    func_0x0003cc00();
    func_0x0003ce14(0);
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


```

## 7. phys_FUN_0000276c @ 0x0000276c  tags:physics  score:18

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_0000276c(code *param_1)

{
  uint uVar1;
  undefined4 uVar2;
  undefined1 auStack_30 [4];
  uint local_2c [3];
  
  do {
    (*param_1)(*(undefined4 *)(_DAT_80048e68 + 100),_DAT_80048e68 + 0xb4,0,0);
    local_2c[0] = 0;
    do {
      uVar1 = local_2c[0];
      func_0x00020eac(0);
      func_0x00021f04(0,auStack_30,local_2c);
      _DAT_80048e78 = local_2c[0];
      if ((local_2c[0] == 0) || (local_2c[0] == 3)) break;
    } while (local_2c[0] != uVar1);
    if (local_2c[0] < 5) {
                    /* WARNING: Could not emulate address calculation at 0x00002820 */
                    /* WARNING: Treating indirect jump as call */
      uVar2 = (**(code **)(local_2c[0] * 4 + -0x7ffc704c))();
      return uVar2;
    }
    (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x6c),_DAT_80048e68 + 0xb4,0,0);
    local_2c[0] = func_0x0003c030(0,0,0);
    if (local_2c[0] == 0) {
      (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0xa4),_DAT_80048e68 + 0xc4,1,1);
      halt_baddata();
    }
    if (local_2c[0] == 5) {
      (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x9c),_DAT_80048e68 + 0xc0,1,0);
      return 0;
    }
    local_2c[0] = (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x70),_DAT_80048e68 + 0xb4,2,1);
    if (local_2c[0] == 1) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  } while( true );
}


```

## 8. phys_FUN_0000276c @ 0x0000276c  tags:physics  score:18

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_0000276c(code *param_1)

{
  uint uVar1;
  undefined4 uVar2;
  undefined1 auStack_30 [4];
  uint local_2c [3];
  
  do {
    (*param_1)(*(undefined4 *)(_DAT_80048e68 + 100),_DAT_80048e68 + 0xb4,0,0);
    local_2c[0] = 0;
    do {
      uVar1 = local_2c[0];
      func_0x00020eac(0);
      func_0x00021f04(0,auStack_30,local_2c);
      _DAT_80048e78 = local_2c[0];
      if ((local_2c[0] == 0) || (local_2c[0] == 3)) break;
    } while (local_2c[0] != uVar1);
    if (local_2c[0] < 5) {
                    /* WARNING: Could not emulate address calculation at 0x00002820 */
                    /* WARNING: Treating indirect jump as call */
      uVar2 = (**(code **)(local_2c[0] * 4 + -0x7ffc704c))();
      return uVar2;
    }
    (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x6c),_DAT_80048e68 + 0xb4,0,0);
    local_2c[0] = func_0x0003c030(0,0,0);
    if (local_2c[0] == 0) {
      (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0xa4),_DAT_80048e68 + 0xc4,1,1);
      halt_baddata();
    }
    if (local_2c[0] == 5) {
      (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x9c),_DAT_80048e68 + 0xc0,1,0);
      return 0;
    }
    local_2c[0] = (*param_1)(*(undefined4 *)(_DAT_80048e68 + 0x70),_DAT_80048e68 + 0xb4,2,1);
    if (local_2c[0] == 1) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  } while( true );
}


```

