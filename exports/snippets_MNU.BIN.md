# Snippets for MNU.BIN

## 1. phys_FUN_00007420 @ 0x00007420  tags:physics  score:83

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00007420(int param_1)

{
  ushort *puVar1;
  bool bVar2;
  undefined2 uVar3;
  short sVar4;
  int iVar5;
  uint *puVar6;
  uint uVar7;
  uint uVar8;
  undefined2 *puVar9;
  uint uVar10;
  ushort *puVar11;
  short *psVar12;
  undefined4 local_48;
  undefined4 local_44;
  undefined2 local_40;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  
  uVar8 = _DAT_8004cc58;
  if (param_1 != 0) {
    _DAT_800d16d4 = 2;
    _DAT_8004d704 = 0;
    if (_DAT_8004d754 != 0) {
      _DAT_800d16a6 = _DAT_8004d74e;
      _DAT_800cf4ec = _DAT_8004d74c;
      _DAT_800d16ac = _DAT_8004d750;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    _DAT_800d16a6 = 0;
    _DAT_800cf4ec = 0;
    _DAT_800d16ac = 0;
    _DAT_800d16a4 = 1;
    _DAT_800d16aa = (short)_DAT_8004cdc0;
    _DAT_800d16ae = (short)_DAT_8004d734;
    func_0x000ced20();
    _DAT_800d16a8 = _DAT_8004d752;
    if (_DAT_8004d752 == 0) {
      _DAT_800d16a8 = 1;
    }
    if (_DAT_800d16a6 == 0) {
      _DAT_800d16a6 = 0x2d;
      iVar5 = func_0x000ce46c(0x2d,*(undefined4 *)(&DAT_800cf4cc + _DAT_800cf4ec * 4),
                              (int)_DAT_800d16a0 + (int)_DAT_800d16a2);
      _DAT_800d16a6 = (short)iVar5;
      if (_DAT_800d16a6 == -1) {
        _DAT_800cf4ec = 0;
        _DAT_800d16a6 = (short)(iVar5 + -1);
        _DAT_800d16a6 =
             func_0x000ce46c((iVar5 + -1) * 0x10000 >> 0x10,_DAT_800cf4cc,
                             (int)_DAT_800d16a0 + (int)_DAT_800d16a2);
      }
      _DAT_800cf86c = 0xffff;
      func_0x000cb3dc();
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  sVar4 = _DAT_800cf86c + -1;
  if (_DAT_800cf86c < 1) {
    if ((_DAT_800cf4ec == 0) && (3 < _DAT_800d16a8)) {
      _DAT_800d16a8 = 1;
    }
    uVar10 = 0;
    if (_DAT_800d16a0 != 0) {
      uVar7 = 0;
      do {
        iVar5 = func_0x00041ba8(*(undefined1 *)(uVar7 * 0x13c + -0x7ff4357a));
        uVar10 = uVar10 + 1;
        if (iVar5 == 0) {
          func_0x000c99b4(1);
          halt_baddata();
        }
        uVar7 = uVar10 & 0xff;
      } while (uVar10 < (uint)(int)_DAT_800d16a0);
    }
    if ((uVar8 & 0x10000000) != 0) {
      _DAT_8004d752 = _DAT_800d16a8;
      func_0x000cd4f4(1);
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if ((uVar8 & 0x40080000) != 0) {
      iVar5 = 2;
      if (0 < _DAT_800cf4ec) {
        func_0x000cd4f4(3);
        iVar5 = func_0x000c4268(_DAT_800d16a6);
      }
      if (iVar5 == 1) {
        func_0x000cb3dc();
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      if (iVar5 == 2) {
        func_0x000cd4f4(3);
        func_0x000ced20();
        _DAT_8004d6e8 = _DAT_800d16a0;
        _DAT_8004d6ee = _DAT_800d16a6;
        for (uVar8 = (int)_DAT_800d16a0 + (int)_DAT_800d16a2; _DAT_800d16a0 = _DAT_8004d6e8,
            _DAT_800d16a6 = _DAT_8004d6ee, uVar8 < 4; uVar8 = uVar8 + 1) {
          *(undefined2 *)(&DAT_8004d712 + (uVar8 & 0xffff) * 2) = 3;
          _DAT_8004d6e8 = _DAT_800d16a0;
          _DAT_8004d6ee = _DAT_800d16a6;
        }
        _DAT_8004d6ec = _DAT_800d16a2 + _DAT_8004d6e8;
        _DAT_8004d6f4 = _DAT_800d16ac + 0x29;
        _DAT_8004d6ea = _DAT_8004d6e8;
        iVar5 = func_0x000ce408(_DAT_8004d6ee,*(undefined4 *)(&DAT_800cf4cc + _DAT_800cf4ec * 4));
        _DAT_8004d6f8 = *(undefined2 *)(iVar5 + 2);
        _DAT_8004d6fa = (ushort)*(byte *)(iVar5 + 1);
        if (_DAT_800cf4ec != 0) {
          _DAT_8004cdc0 = 0;
          _DAT_8004d734 = (int)_DAT_800d16ae;
          if (6 < (uint)(int)_DAT_800d16a8) {
            uVar8 = 0;
            puVar9 = (undefined2 *)&DAT_800d1642;
            _DAT_8004d754 = 1;
            _DAT_8004d752 = _DAT_800d16a8;
            _DAT_8004d74c = _DAT_800cf4ec;
            _DAT_8004d74e = _DAT_800d16a6;
            _DAT_8004d750 = _DAT_800d16ac;
            do {
              uVar3 = *puVar9;
              puVar9 = puVar9 + 0xc;
              uVar10 = uVar8 & 0xffff;
              uVar8 = uVar8 + 1;
              *(char *)(uVar10 + 0x8004d758) = (char)uVar3;
            } while (uVar8 < 4);
            _DAT_800cf86c = 10;
            halt_baddata();
          }
                    /* WARNING: Could not emulate address calculation at 0x0000784c */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)(_DAT_800d16a8 * 4 + -0x7ff3bdd0))();
          return;
        }
        _DAT_8004cdc0 = (int)_DAT_800d16aa;
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
    }
    if ((uVar8 & 0x100000) != 0) {
      func_0x000cd4f4(0);
      _DAT_800d16a4 = _DAT_800d16a4 + -1;
      puVar6 = (uint *)func_0x000431e4();
      if ((((((*puVar6 & 0x40000000) == 0) || (_DAT_800cf4ec != 0)) || (_DAT_800d16a0 < 2)) ||
          ((int)_DAT_800d16a0 + (int)_DAT_800d16a2 < 3)) && (_DAT_800d16a4 == 4)) {
        _DAT_800d16a4 = _DAT_800d16a4 + -1;
      }
      iVar5 = func_0x000cece4();
      if ((iVar5 == 0) && (_DAT_800d16a4 == 3)) {
        _DAT_800d16a4 = 2;
      }
      if (_DAT_800d16a4 < 0) {
        _DAT_800d16a4 = 5;
      }
    }
    if ((uVar8 & 0x400000) != 0) {
      func_0x000cd4f4(0);
      _DAT_800d16a4 = _DAT_800d16a4 + 1;
      iVar5 = func_0x000cece4();
      if ((iVar5 == 0) && (_DAT_800d16a4 == 3)) {
        _DAT_800d16a4 = _DAT_800d16a4 + 1;
      }
      puVar6 = (uint *)func_0x000431e4();
      if ((((((*puVar6 & 0x40000000) == 0) || (_DAT_800cf4ec != 0)) || (_DAT_800d16a0 < 2)) ||
          ((int)_DAT_800d16a0 + (int)_DAT_800d16a2 < 3)) && (_DAT_800d16a4 == 4)) {
        _DAT_800d16a4 = 5;
      }
      if (5 < _DAT_800d16a4) {
        _DAT_800d16a4 = 0;
      }
    }
    psVar12 = (short *)&local_38;
    if ((uint)(int)_DAT_800d16a4 < 6) {
                    /* WARNING: Could not emulate address calculation at 0x00007b2c */
                    /* WARNING: Treating indirect jump as call */
      (**(code **)(_DAT_800d16a4 * 4 + -0x7ff3bdb0))();
      return;
    }
    func_0x000ce0fc();
    func_0x000cce8c(0xf2,0,0x18,0x10,0x808080,0,0,0);
    func_0x000cd7cc(_DAT_800d16bc,0xf8,0x10,*(undefined4 *)(_DAT_80048e68 + 0x26c),2,0x8080);
    func_0x000cce8c(_DAT_800cf4ec + 10,0,0xb0,0x18,0x808080,0,0,0);
    func_0x000cd7cc(_DAT_800d16bc,0xf8,0x38,*(undefined4 *)(_DAT_80048e68 + 0x318),2,0x8080);
    func_0x000ccf80((int)*(short *)(_DAT_800d16a6 * 2 + -0x7ff30b90),0,0xb0,0x40,0x808080);
    func_0x000cd7cc(_DAT_800d16bc,0xf8,0x80,*(undefined4 *)(_DAT_80048e68 + 0x270),2,0x8080);
    iVar5 = (int)_DAT_800d16a8;
    if (iVar5 < 4) {
      func_0x000cd7cc(_DAT_800d16c4,0xf8,0x8c,*(undefined4 *)(iVar5 * 4 + _DAT_80048e68 + 0x280),2,
                      0x808080);
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    func_0x000222ec(0x800cf72c,0x800c420c,
                    (int)*(short *)((_DAT_800cf4ec * 3 + iVar5 + -4) * 2 + -0x7ff30b10),
                    *(undefined4 *)(_DAT_80048e68 + 0x290));
    func_0x000cd7cc(_DAT_800d16c4,0xf8,0x8c,0x800cf72c,2,0x808080);
    iVar5 = func_0x000cece4();
    if (iVar5 != 0) {
      func_0x000cd7cc(_DAT_800d16bc,0xf8,0xa0,*(undefined4 *)(_DAT_80048e68 + 0x328),2,0x8080);
      func_0x000cd7cc(_DAT_800d16c4,0xf8,0xb0,
                      *(undefined4 *)(_DAT_800d16ae * 4 + _DAT_80048e68 + 0x32c),2,0x808080);
    }
    puVar6 = (uint *)func_0x000431e4();
    if ((((*puVar6 & 0x40000000) != 0) && (_DAT_800cf4ec == 0)) &&
       ((1 < _DAT_800d16a0 && (2 < (int)_DAT_800d16a0 + (int)_DAT_800d16a2)))) {
      func_0x000cd7cc(_DAT_800d16bc,0xf8,0xc0,*(undefined4 *)(_DAT_80048e68 + 0x278),2,0x8080);
      if (_DAT_800d16aa == 0) {
        func_0x000cd7cc(_DAT_800d16c4,0xf8,0xcc,*(undefined4 *)(_DAT_80048e68 + 0x24c),2,0x808080);
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      uVar8 = 0;
      if (_DAT_800d16aa != 0) {
        sVar4 = 200;
        do {
          func_0x000cce8c(0x115,0,sVar4,0xcc,0x808080,0,0,0);
          uVar8 = uVar8 + 1;
          sVar4 = sVar4 + 0x20;
        } while (uVar8 < (uint)(int)_DAT_800d16aa);
      }
    }
    uVar8 = 0;
    func_0x000cd7cc(_DAT_800d16bc,0x200,0x10,*(undefined4 *)(_DAT_80048e68 + 0x274),2,0x8080);
    func_0x000cce8c(0x38,0,0x1d8,0x30,0x808080,0,0,0);
    local_48 = _DAT_800c4214;
    local_44 = _DAT_800c4218;
    local_40 = _DAT_800c421c;
    do {
      if (((uVar8 != 3) || (iVar5 = func_0x000cece4(), iVar5 != 0)) &&
         ((uVar8 != 4 ||
          ((((puVar6 = (uint *)func_0x000431e4(0xfe), (*puVar6 & 0x40000000) != 0 &&
             (_DAT_800cf4ec == 0)) && (1 < _DAT_800d16a0)) &&
           (2 < (int)_DAT_800d16a0 + (int)_DAT_800d16a2)))))) {
        puVar9 = (undefined2 *)((int)&local_48 + uVar8 * 2);
        func_0x000cce8c(0xfe,1,0x88,*puVar9,0x808080,0,0,0);
        func_0x000cce8c(0xff,1,0x148,*puVar9,0x808080,0,0,0);
        if (uVar8 == (int)_DAT_800d16a4) {
          func_0x000cce8c(0x100,0,0x88,*puVar9,_DAT_800d1624,0,0,0);
          func_0x000cce8c(0x101,0,0x148,*puVar9,_DAT_800d1624,0,0,0);
        }
      }
      uVar8 = uVar8 + 1;
    } while (uVar8 < 5);
    func_0x000cce8c(0xfe,1,0x188,0x18,0x808080,0,0,0);
    func_0x000cce8c(0xff,1,600,0x18,0x808080,0,0,0);
    if (_DAT_800d16a4 == 5) {
      func_0x000cce8c(0x100,0,0x188,0x18,_DAT_800d1624,0,0,0);
      func_0x000cce8c(0x101,0,600,0x18,_DAT_800d1624,0,0,0);
    }
    uVar8 = 0;
    func_0x000cd7cc(_DAT_800d16c4,0x200,0x1c,
                    *(undefined4 *)(_DAT_800d16ac * 4 + _DAT_80048e68 + 0x294),2,0x808080);
    func_0x000cce8c(0xf6,0,0x30,0xa0,0x808080,0,0,0);
    func_0x000cd7cc(_DAT_800d16bc,0x40,0xb0,*(undefined4 *)(_DAT_80048e68 + 0x30c),2,0x808080);
    func_0x000cce8c(0xf9,0,0x30,0xc2,0x808080,0,0,0);
    func_0x000cd7cc(_DAT_800d16bc,0x40,0xd2,*(undefined4 *)(_DAT_80048e68 + 0x268),2,0x808080);
    local_38 = _DAT_800c4220;
    local_34 = _DAT_800c4224;
    local_30 = _DAT_800c4228;
    puVar11 = *(ushort **)(&DAT_800d1584 + _DAT_800d16ac * 4);
    do {
      uVar8 = uVar8 + 1;
      func_0x000cce8c(*puVar11 + 0x39,0,0x1b8,*psVar12 + 0x30,0x808080,0,0,1);
      sVar4 = *psVar12;
      psVar12 = psVar12 + 1;
      puVar1 = puVar11 + 1;
      puVar11 = puVar11 + 2;
      func_0x000cce8c(*puVar1 + 0x39,0,0x248,sVar4 + 0x30,0x808080,0,0,1);
    } while (uVar8 < 6);
  }
  else {
    bVar2 = _DAT_800cf86c == 1;
    _DAT_800cf86c = sVar4;
    if (bVar2) {
      func_0x0003cc50(7);
      func_0x0003cc50(7);
      _DAT_800d16d0 = 2;
      halt_baddata();
    }
  }
  return;
}


```

## 2. phys_FUN_00007420 @ 0x00007420  tags:physics  score:83

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00007420(int param_1)

{
  ushort *puVar1;
  bool bVar2;
  undefined2 uVar3;
  short sVar4;
  int iVar5;
  uint *puVar6;
  uint uVar7;
  uint uVar8;
  undefined2 *puVar9;
  uint uVar10;
  ushort *puVar11;
  short *psVar12;
  undefined4 local_48;
  undefined4 local_44;
  undefined2 local_40;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  
  uVar8 = _DAT_8004cc58;
  if (param_1 != 0) {
    _DAT_800d16d4 = 2;
    _DAT_8004d704 = 0;
    if (_DAT_8004d754 != 0) {
      _DAT_800d16a6 = _DAT_8004d74e;
      _DAT_800cf4ec = _DAT_8004d74c;
      _DAT_800d16ac = _DAT_8004d750;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    _DAT_800d16a6 = 0;
    _DAT_800cf4ec = 0;
    _DAT_800d16ac = 0;
    _DAT_800d16a4 = 1;
    _DAT_800d16aa = (short)_DAT_8004cdc0;
    _DAT_800d16ae = (short)_DAT_8004d734;
    func_0x000ced20();
    _DAT_800d16a8 = _DAT_8004d752;
    if (_DAT_8004d752 == 0) {
      _DAT_800d16a8 = 1;
    }
    if (_DAT_800d16a6 == 0) {
      _DAT_800d16a6 = 0x2d;
      iVar5 = func_0x000ce46c(0x2d,*(undefined4 *)(&DAT_800cf4cc + _DAT_800cf4ec * 4),
                              (int)_DAT_800d16a0 + (int)_DAT_800d16a2);
      _DAT_800d16a6 = (short)iVar5;
      if (_DAT_800d16a6 == -1) {
        _DAT_800cf4ec = 0;
        _DAT_800d16a6 = (short)(iVar5 + -1);
        _DAT_800d16a6 =
             func_0x000ce46c((iVar5 + -1) * 0x10000 >> 0x10,_DAT_800cf4cc,
                             (int)_DAT_800d16a0 + (int)_DAT_800d16a2);
      }
      _DAT_800cf86c = 0xffff;
      func_0x000cb3dc();
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  sVar4 = _DAT_800cf86c + -1;
  if (_DAT_800cf86c < 1) {
    if ((_DAT_800cf4ec == 0) && (3 < _DAT_800d16a8)) {
      _DAT_800d16a8 = 1;
    }
    uVar10 = 0;
    if (_DAT_800d16a0 != 0) {
      uVar7 = 0;
      do {
        iVar5 = func_0x00041ba8(*(undefined1 *)(uVar7 * 0x13c + -0x7ff4357a));
        uVar10 = uVar10 + 1;
        if (iVar5 == 0) {
          func_0x000c99b4(1);
          halt_baddata();
        }
        uVar7 = uVar10 & 0xff;
      } while (uVar10 < (uint)(int)_DAT_800d16a0);
    }
    if ((uVar8 & 0x10000000) != 0) {
      _DAT_8004d752 = _DAT_800d16a8;
      func_0x000cd4f4(1);
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if ((uVar8 & 0x40080000) != 0) {
      iVar5 = 2;
      if (0 < _DAT_800cf4ec) {
        func_0x000cd4f4(3);
        iVar5 = func_0x000c4268(_DAT_800d16a6);
      }
      if (iVar5 == 1) {
        func_0x000cb3dc();
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      if (iVar5 == 2) {
        func_0x000cd4f4(3);
        func_0x000ced20();
        _DAT_8004d6e8 = _DAT_800d16a0;
        _DAT_8004d6ee = _DAT_800d16a6;
        for (uVar8 = (int)_DAT_800d16a0 + (int)_DAT_800d16a2; _DAT_800d16a0 = _DAT_8004d6e8,
            _DAT_800d16a6 = _DAT_8004d6ee, uVar8 < 4; uVar8 = uVar8 + 1) {
          *(undefined2 *)(&DAT_8004d712 + (uVar8 & 0xffff) * 2) = 3;
          _DAT_8004d6e8 = _DAT_800d16a0;
          _DAT_8004d6ee = _DAT_800d16a6;
        }
        _DAT_8004d6ec = _DAT_800d16a2 + _DAT_8004d6e8;
        _DAT_8004d6f4 = _DAT_800d16ac + 0x29;
        _DAT_8004d6ea = _DAT_8004d6e8;
        iVar5 = func_0x000ce408(_DAT_8004d6ee,*(undefined4 *)(&DAT_800cf4cc + _DAT_800cf4ec * 4));
        _DAT_8004d6f8 = *(undefined2 *)(iVar5 + 2);
        _DAT_8004d6fa = (ushort)*(byte *)(iVar5 + 1);
        if (_DAT_800cf4ec != 0) {
          _DAT_8004cdc0 = 0;
          _DAT_8004d734 = (int)_DAT_800d16ae;
          if (6 < (uint)(int)_DAT_800d16a8) {
            uVar8 = 0;
            puVar9 = (undefined2 *)&DAT_800d1642;
            _DAT_8004d754 = 1;
            _DAT_8004d752 = _DAT_800d16a8;
            _DAT_8004d74c = _DAT_800cf4ec;
            _DAT_8004d74e = _DAT_800d16a6;
            _DAT_8004d750 = _DAT_800d16ac;
            do {
              uVar3 = *puVar9;
              puVar9 = puVar9 + 0xc;
              uVar10 = uVar8 & 0xffff;
              uVar8 = uVar8 + 1;
              *(char *)(uVar10 + 0x8004d758) = (char)uVar3;
            } while (uVar8 < 4);
            _DAT_800cf86c = 10;
            halt_baddata();
          }
                    /* WARNING: Could not emulate address calculation at 0x0000784c */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)(_DAT_800d16a8 * 4 + -0x7ff3bdd0))();
          return;
        }
        _DAT_8004cdc0 = (int)_DAT_800d16aa;
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
    }
    if ((uVar8 & 0x100000) != 0) {
      func_0x000cd4f4(0);
      _DAT_800d16a4 = _DAT_800d16a4 + -1;
      puVar6 = (uint *)func_0x000431e4();
      if ((((((*puVar6 & 0x40000000) == 0) || (_DAT_800cf4ec != 0)) || (_DAT_800d16a0 < 2)) ||
          ((int)_DAT_800d16a0 + (int)_DAT_800d16a2 < 3)) && (_DAT_800d16a4 == 4)) {
        _DAT_800d16a4 = _DAT_800d16a4 + -1;
      }
      iVar5 = func_0x000cece4();
      if ((iVar5 == 0) && (_DAT_800d16a4 == 3)) {
        _DAT_800d16a4 = 2;
      }
      if (_DAT_800d16a4 < 0) {
        _DAT_800d16a4 = 5;
      }
    }
    if ((uVar8 & 0x400000) != 0) {
      func_0x000cd4f4(0);
      _DAT_800d16a4 = _DAT_800d16a4 + 1;
      iVar5 = func_0x000cece4();
      if ((iVar5 == 0) && (_DAT_800d16a4 == 3)) {
        _DAT_800d16a4 = _DAT_800d16a4 + 1;
      }
      puVar6 = (uint *)func_0x000431e4();
      if ((((((*puVar6 & 0x40000000) == 0) || (_DAT_800cf4ec != 0)) || (_DAT_800d16a0 < 2)) ||
          ((int)_DAT_800d16a0 + (int)_DAT_800d16a2 < 3)) && (_DAT_800d16a4 == 4)) {
        _DAT_800d16a4 = 5;
      }
      if (5 < _DAT_800d16a4) {
        _DAT_800d16a4 = 0;
      }
    }
    psVar12 = (short *)&local_38;
    if ((uint)(int)_DAT_800d16a4 < 6) {
                    /* WARNING: Could not emulate address calculation at 0x00007b2c */
                    /* WARNING: Treating indirect jump as call */
      (**(code **)(_DAT_800d16a4 * 4 + -0x7ff3bdb0))();
      return;
    }
    func_0x000ce0fc();
    func_0x000cce8c(0xf2,0,0x18,0x10,0x808080,0,0,0);
    func_0x000cd7cc(_DAT_800d16bc,0xf8,0x10,*(undefined4 *)(_DAT_80048e68 + 0x26c),2,0x8080);
    func_0x000cce8c(_DAT_800cf4ec + 10,0,0xb0,0x18,0x808080,0,0,0);
    func_0x000cd7cc(_DAT_800d16bc,0xf8,0x38,*(undefined4 *)(_DAT_80048e68 + 0x318),2,0x8080);
    func_0x000ccf80((int)*(short *)(_DAT_800d16a6 * 2 + -0x7ff30b90),0,0xb0,0x40,0x808080);
    func_0x000cd7cc(_DAT_800d16bc,0xf8,0x80,*(undefined4 *)(_DAT_80048e68 + 0x270),2,0x8080);
    iVar5 = (int)_DAT_800d16a8;
    if (iVar5 < 4) {
      func_0x000cd7cc(_DAT_800d16c4,0xf8,0x8c,*(undefined4 *)(iVar5 * 4 + _DAT_80048e68 + 0x280),2,
                      0x808080);
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    func_0x000222ec(0x800cf72c,0x800c420c,
                    (int)*(short *)((_DAT_800cf4ec * 3 + iVar5 + -4) * 2 + -0x7ff30b10),
                    *(undefined4 *)(_DAT_80048e68 + 0x290));
    func_0x000cd7cc(_DAT_800d16c4,0xf8,0x8c,0x800cf72c,2,0x808080);
    iVar5 = func_0x000cece4();
    if (iVar5 != 0) {
      func_0x000cd7cc(_DAT_800d16bc,0xf8,0xa0,*(undefined4 *)(_DAT_80048e68 + 0x328),2,0x8080);
      func_0x000cd7cc(_DAT_800d16c4,0xf8,0xb0,
                      *(undefined4 *)(_DAT_800d16ae * 4 + _DAT_80048e68 + 0x32c),2,0x808080);
    }
    puVar6 = (uint *)func_0x000431e4();
    if ((((*puVar6 & 0x40000000) != 0) && (_DAT_800cf4ec == 0)) &&
       ((1 < _DAT_800d16a0 && (2 < (int)_DAT_800d16a0 + (int)_DAT_800d16a2)))) {
      func_0x000cd7cc(_DAT_800d16bc,0xf8,0xc0,*(undefined4 *)(_DAT_80048e68 + 0x278),2,0x8080);
      if (_DAT_800d16aa == 0) {
        func_0x000cd7cc(_DAT_800d16c4,0xf8,0xcc,*(undefined4 *)(_DAT_80048e68 + 0x24c),2,0x808080);
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      uVar8 = 0;
      if (_DAT_800d16aa != 0) {
        sVar4 = 200;
        do {
          func_0x000cce8c(0x115,0,sVar4,0xcc,0x808080,0,0,0);
          uVar8 = uVar8 + 1;
          sVar4 = sVar4 + 0x20;
        } while (uVar8 < (uint)(int)_DAT_800d16aa);
      }
    }
    uVar8 = 0;
    func_0x000cd7cc(_DAT_800d16bc,0x200,0x10,*(undefined4 *)(_DAT_80048e68 + 0x274),2,0x8080);
    func_0x000cce8c(0x38,0,0x1d8,0x30,0x808080,0,0,0);
    local_48 = _DAT_800c4214;
    local_44 = _DAT_800c4218;
    local_40 = _DAT_800c421c;
    do {
      if (((uVar8 != 3) || (iVar5 = func_0x000cece4(), iVar5 != 0)) &&
         ((uVar8 != 4 ||
          ((((puVar6 = (uint *)func_0x000431e4(0xfe), (*puVar6 & 0x40000000) != 0 &&
             (_DAT_800cf4ec == 0)) && (1 < _DAT_800d16a0)) &&
           (2 < (int)_DAT_800d16a0 + (int)_DAT_800d16a2)))))) {
        puVar9 = (undefined2 *)((int)&local_48 + uVar8 * 2);
        func_0x000cce8c(0xfe,1,0x88,*puVar9,0x808080,0,0,0);
        func_0x000cce8c(0xff,1,0x148,*puVar9,0x808080,0,0,0);
        if (uVar8 == (int)_DAT_800d16a4) {
          func_0x000cce8c(0x100,0,0x88,*puVar9,_DAT_800d1624,0,0,0);
          func_0x000cce8c(0x101,0,0x148,*puVar9,_DAT_800d1624,0,0,0);
        }
      }
      uVar8 = uVar8 + 1;
    } while (uVar8 < 5);
    func_0x000cce8c(0xfe,1,0x188,0x18,0x808080,0,0,0);
    func_0x000cce8c(0xff,1,600,0x18,0x808080,0,0,0);
    if (_DAT_800d16a4 == 5) {
      func_0x000cce8c(0x100,0,0x188,0x18,_DAT_800d1624,0,0,0);
      func_0x000cce8c(0x101,0,600,0x18,_DAT_800d1624,0,0,0);
    }
    uVar8 = 0;
    func_0x000cd7cc(_DAT_800d16c4,0x200,0x1c,
                    *(undefined4 *)(_DAT_800d16ac * 4 + _DAT_80048e68 + 0x294),2,0x808080);
    func_0x000cce8c(0xf6,0,0x30,0xa0,0x808080,0,0,0);
    func_0x000cd7cc(_DAT_800d16bc,0x40,0xb0,*(undefined4 *)(_DAT_80048e68 + 0x30c),2,0x808080);
    func_0x000cce8c(0xf9,0,0x30,0xc2,0x808080,0,0,0);
    func_0x000cd7cc(_DAT_800d16bc,0x40,0xd2,*(undefined4 *)(_DAT_80048e68 + 0x268),2,0x808080);
    local_38 = _DAT_800c4220;
    local_34 = _DAT_800c4224;
    local_30 = _DAT_800c4228;
    puVar11 = *(ushort **)(&DAT_800d1584 + _DAT_800d16ac * 4);
    do {
      uVar8 = uVar8 + 1;
      func_0x000cce8c(*puVar11 + 0x39,0,0x1b8,*psVar12 + 0x30,0x808080,0,0,1);
      sVar4 = *psVar12;
      psVar12 = psVar12 + 1;
      puVar1 = puVar11 + 1;
      puVar11 = puVar11 + 2;
      func_0x000cce8c(*puVar1 + 0x39,0,0x248,sVar4 + 0x30,0x808080,0,0,1);
    } while (uVar8 < 6);
  }
  else {
    bVar2 = _DAT_800cf86c == 1;
    _DAT_800cf86c = sVar4;
    if (bVar2) {
      func_0x0003cc50(7);
      func_0x0003cc50(7);
      _DAT_800d16d0 = 2;
      halt_baddata();
    }
  }
  return;
}


```

## 3. phys_FUN_000031d8 @ 0x000031d8  tags:physics  score:59

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_000031d8(int param_1)

{
  int iVar1;
  short *psVar2;
  undefined4 *puVar3;
  uint uVar4;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined2 local_48;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined2 local_30;
  
  uVar4 = _DAT_8004cc58;
  if (param_1 == 0) {
    if (_DAT_800cf85c == 1) {
      _DAT_800cf85c = 2;
    }
    else if (_DAT_800cf85c == 2) {
      _DAT_8004cd76 = _DAT_800d161a;
      _DAT_8004cd78 = _DAT_800d161e;
      _DAT_8004cd7c = _DAT_800d1620;
      _DAT_8004cd1c = _DAT_80048e7c;
      _DAT_8004cd1e = _DAT_80048e7e;
      func_0x000c5bc8(1);
    }
    else {
      if (((_DAT_8004cc58 & 0x200) != 0) && (_DAT_800cf85a == 3)) {
        if ((_DAT_8004cc58 & 0x80) == 0) {
          if (((_DAT_8004cc58 & 0x20) != 0) && (_DAT_80048e7c < 0x41)) {
            _DAT_80048e7c = _DAT_80048e7c + 1;
          }
        }
        else if (-0x1b < _DAT_80048e7c) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        if ((_DAT_8004cc58 & 0x10) == 0) {
          if (((_DAT_8004cc58 & 0x40) != 0) && (_DAT_80048e7e < 0x28)) {
            _DAT_80048e7e = _DAT_80048e7e + 1;
          }
        }
        else if (0 < _DAT_80048e7e) {
          _DAT_80048e7e = _DAT_80048e7e + -1;
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        func_0x000c94a8(0x808080);
        if ((uint)(int)_DAT_800cf85a < 8) {
                    /* WARNING: Could not emulate address calculation at 0x00003504 */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)(_DAT_800cf85a * 4 + -0x7ff3be98))();
          return;
        }
        uVar4 = 0;
        func_0x000ce0fc();
        local_58 = _DAT_800c413c;
        local_54 = _DAT_800c4140;
        local_50 = _DAT_800c4144;
        local_4c = _DAT_800c4148;
        local_48 = _DAT_800c414c;
        local_40 = _DAT_800c4150;
        local_3c = _DAT_800c4154;
        local_38 = _DAT_800c4158;
        local_34 = _DAT_800c415c;
        local_30 = _DAT_800c4160;
        iVar1 = func_0x000ce068(_DAT_800d16c0,*(undefined4 *)(_DAT_80048e68 + 0x2f8));
        local_50 = CONCAT22(local_50._2_2_,(short)(iVar1 / 2) + 0x20);
        iVar1 = func_0x000ce068(_DAT_800d16c0,*(undefined4 *)(_DAT_80048e68 + 0x34c));
        local_50 = CONCAT22((short)(iVar1 / 2) + 0x20,(undefined2)local_50);
        iVar1 = func_0x000ce068(_DAT_800d16c0,*(undefined4 *)(_DAT_80048e68 + 0x350));
        local_4c = CONCAT22(local_4c._2_2_,(short)(iVar1 / 2) + 0x20);
        iVar1 = func_0x000ce068(_DAT_800d16c0,*(undefined4 *)(_DAT_80048e68 + 0x354));
        puVar3 = &local_40;
        psVar2 = (short *)&local_58;
        local_4c = CONCAT22((short)(iVar1 / 2) + 0x20,(undefined2)local_4c);
        do {
          if (uVar4 < 3) {
            func_0x000cce8c(0xfe,1,0x130 - *psVar2,*(undefined2 *)puVar3,0x808080,0,0,0);
            func_0x000cce8c(0xff,1,*psVar2 + 0x130,*(undefined2 *)puVar3,0x808080,0,0,0);
            if (uVar4 == (int)_DAT_800cf85a) {
              func_0x000cce8c(0x100,0,0x130 - *psVar2,*(undefined2 *)puVar3,_DAT_800d1624,0,0,0);
              func_0x000cce8c(0x101,0,*psVar2 + 0x130,*(undefined2 *)puVar3,_DAT_800d1624,0,0,0);
            }
          }
          else {
            func_0x000cce8c(0xfe,1,*psVar2 + 0x130,*(undefined2 *)puVar3,0x808080,0,0,0);
            func_0x000cce8c(0xff,1,0x130 - *psVar2,*(undefined2 *)puVar3,0x808080,0,0,0);
            if (uVar4 == (int)_DAT_800cf85a) {
              func_0x000cce8c(0x100,0,*psVar2 + 0x130,*(undefined2 *)puVar3,_DAT_800d1624,0,0,0);
              func_0x000cce8c(0x101,0,0x130 - *psVar2,*(undefined2 *)puVar3,_DAT_800d1624,0,0,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
          }
          puVar3 = (undefined4 *)((int)puVar3 + 2);
          uVar4 = uVar4 + 1;
          psVar2 = psVar2 + 1;
        } while (uVar4 < 8);
        func_0x000cce8c(0xef,0,0x18,0x10,0x808080,0,0,0);
        func_0x000cce8c(0xf6,0,0x40,0xa0,0x808080,0,0,0);
        func_0x000cd7cc(_DAT_800d16bc,0x50,0xb0,*(undefined4 *)(_DAT_80048e68 + 0x264),2,0x808080);
        func_0x000cce8c(0xf9,0,0x40,0xc2,0x808080,0,0,0);
        func_0x000cd7cc(_DAT_800d16bc,0x50,0xd2,*(undefined4 *)(_DAT_80048e68 + 800),2,0x808080);
        if (_DAT_800cf85a == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        func_0x000cd7cc(_DAT_800d16c0,0x1c0,0x18,*(undefined4 *)(_DAT_80048e68 + 0x254),0,0x808080);
        if (_DAT_800cf85a == 1) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        func_0x000cd7cc(_DAT_800d16c0,0x1c0,0x30,*(undefined4 *)(_DAT_80048e68 + 600),0,0x808080);
        if (_DAT_800cf85a == 2) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        func_0x000cd7cc(_DAT_800d16c0,0x1c0,0x48,*(undefined4 *)(_DAT_80048e68 + 0x25c),0,0x808080);
        if (_DAT_800cf85a == 3) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        func_0x000cd7cc(_DAT_800d16c4,0x1c0,0x5c,*(undefined4 *)(_DAT_80048e68 + 0x260),0,0x808080);
        func_0x000cd7cc(_DAT_800d16c0,0x140,0x5e,*(undefined4 *)(_DAT_80048e68 + 0x250),2,0x808080);
        if (_DAT_800cf85a != 4) {
          func_0x000cd7cc(_DAT_800d16c0,0x140,0x78,*(undefined4 *)(_DAT_80048e68 + 0x2f8),2,0x808080
                         );
          if (_DAT_800cf85a == 5) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          func_0x000cd7cc(_DAT_800d16c0,0x140,0x90,*(undefined4 *)(_DAT_80048e68 + 0x34c),2,0x808080
                         );
          if (_DAT_800cf85a != 6) {
            func_0x000cd7cc(_DAT_800d16c0,0x140,0xa4,*(undefined4 *)(_DAT_80048e68 + 0x350),2,
                            0x808080);
            if (_DAT_800cf85a != 7) {
              func_0x000cd7cc(_DAT_800d16c0,0x140,0xb8,*(undefined4 *)(_DAT_80048e68 + 0x354),2,
                              0x808080);
              func_0x000c9758(0x100,0x18,_DAT_800d161a);
              func_0x000c9758(0x100,0x30,_DAT_8004cd74);
              func_0x000c9758(0x100,0x48,_DAT_800d161e);
              return;
            }
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      if ((_DAT_8004cc58 & 0x10000000) == 0) {
        if ((_DAT_8004cc58 & 0x100000) != 0) {
          func_0x000cd4f4(0);
          if (0 < _DAT_800cf85a) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          _DAT_800cf85a = 7;
        }
        if ((uVar4 & 0x400000) != 0) {
          func_0x000cd4f4(0);
          if (_DAT_800cf85a < 7) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          _DAT_800cf85a = 0;
        }
        func_0x000c94a8(0);
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      func_0x000cd4f4(1);
      _DAT_8004cd74 = _DAT_800d161c;
      _DAT_80048e7c = _DAT_8004cd1c;
      _DAT_80048e7e = _DAT_8004cd1e;
      func_0x000c5bc8(1);
    }
  }
  else {
    _DAT_800cf85a = 0;
    _DAT_800d16d4 = 9;
    _DAT_800d15f0 = 0;
    _DAT_800cf85c = 0;
    if (_DAT_800cf64c != 0) {
      _DAT_800cf64c = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    _DAT_800d161a = _DAT_8004cd76;
    _DAT_800d161c = _DAT_8004cd74;
    _DAT_800d161e = _DAT_8004cd78;
    _DAT_800d1620 = _DAT_8004cd7c;
    func_0x000cd2d8();
    func_0x000cd100(0x2c,1);
    func_0x000cd100(0x2d,1);
    func_0x000cd100(0x2e,1);
    func_0x000cd2fc();
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


```

## 4. phys_FUN_000031d8 @ 0x000031d8  tags:physics  score:59

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_000031d8(int param_1)

{
  int iVar1;
  short *psVar2;
  undefined4 *puVar3;
  uint uVar4;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined2 local_48;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined2 local_30;
  
  uVar4 = _DAT_8004cc58;
  if (param_1 == 0) {
    if (_DAT_800cf85c == 1) {
      _DAT_800cf85c = 2;
    }
    else if (_DAT_800cf85c == 2) {
      _DAT_8004cd76 = _DAT_800d161a;
      _DAT_8004cd78 = _DAT_800d161e;
      _DAT_8004cd7c = _DAT_800d1620;
      _DAT_8004cd1c = _DAT_80048e7c;
      _DAT_8004cd1e = _DAT_80048e7e;
      func_0x000c5bc8(1);
    }
    else {
      if (((_DAT_8004cc58 & 0x200) != 0) && (_DAT_800cf85a == 3)) {
        if ((_DAT_8004cc58 & 0x80) == 0) {
          if (((_DAT_8004cc58 & 0x20) != 0) && (_DAT_80048e7c < 0x41)) {
            _DAT_80048e7c = _DAT_80048e7c + 1;
          }
        }
        else if (-0x1b < _DAT_80048e7c) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        if ((_DAT_8004cc58 & 0x10) == 0) {
          if (((_DAT_8004cc58 & 0x40) != 0) && (_DAT_80048e7e < 0x28)) {
            _DAT_80048e7e = _DAT_80048e7e + 1;
          }
        }
        else if (0 < _DAT_80048e7e) {
          _DAT_80048e7e = _DAT_80048e7e + -1;
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        func_0x000c94a8(0x808080);
        if ((uint)(int)_DAT_800cf85a < 8) {
                    /* WARNING: Could not emulate address calculation at 0x00003504 */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)(_DAT_800cf85a * 4 + -0x7ff3be98))();
          return;
        }
        uVar4 = 0;
        func_0x000ce0fc();
        local_58 = _DAT_800c413c;
        local_54 = _DAT_800c4140;
        local_50 = _DAT_800c4144;
        local_4c = _DAT_800c4148;
        local_48 = _DAT_800c414c;
        local_40 = _DAT_800c4150;
        local_3c = _DAT_800c4154;
        local_38 = _DAT_800c4158;
        local_34 = _DAT_800c415c;
        local_30 = _DAT_800c4160;
        iVar1 = func_0x000ce068(_DAT_800d16c0,*(undefined4 *)(_DAT_80048e68 + 0x2f8));
        local_50 = CONCAT22(local_50._2_2_,(short)(iVar1 / 2) + 0x20);
        iVar1 = func_0x000ce068(_DAT_800d16c0,*(undefined4 *)(_DAT_80048e68 + 0x34c));
        local_50 = CONCAT22((short)(iVar1 / 2) + 0x20,(undefined2)local_50);
        iVar1 = func_0x000ce068(_DAT_800d16c0,*(undefined4 *)(_DAT_80048e68 + 0x350));
        local_4c = CONCAT22(local_4c._2_2_,(short)(iVar1 / 2) + 0x20);
        iVar1 = func_0x000ce068(_DAT_800d16c0,*(undefined4 *)(_DAT_80048e68 + 0x354));
        puVar3 = &local_40;
        psVar2 = (short *)&local_58;
        local_4c = CONCAT22((short)(iVar1 / 2) + 0x20,(undefined2)local_4c);
        do {
          if (uVar4 < 3) {
            func_0x000cce8c(0xfe,1,0x130 - *psVar2,*(undefined2 *)puVar3,0x808080,0,0,0);
            func_0x000cce8c(0xff,1,*psVar2 + 0x130,*(undefined2 *)puVar3,0x808080,0,0,0);
            if (uVar4 == (int)_DAT_800cf85a) {
              func_0x000cce8c(0x100,0,0x130 - *psVar2,*(undefined2 *)puVar3,_DAT_800d1624,0,0,0);
              func_0x000cce8c(0x101,0,*psVar2 + 0x130,*(undefined2 *)puVar3,_DAT_800d1624,0,0,0);
            }
          }
          else {
            func_0x000cce8c(0xfe,1,*psVar2 + 0x130,*(undefined2 *)puVar3,0x808080,0,0,0);
            func_0x000cce8c(0xff,1,0x130 - *psVar2,*(undefined2 *)puVar3,0x808080,0,0,0);
            if (uVar4 == (int)_DAT_800cf85a) {
              func_0x000cce8c(0x100,0,*psVar2 + 0x130,*(undefined2 *)puVar3,_DAT_800d1624,0,0,0);
              func_0x000cce8c(0x101,0,0x130 - *psVar2,*(undefined2 *)puVar3,_DAT_800d1624,0,0,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
          }
          puVar3 = (undefined4 *)((int)puVar3 + 2);
          uVar4 = uVar4 + 1;
          psVar2 = psVar2 + 1;
        } while (uVar4 < 8);
        func_0x000cce8c(0xef,0,0x18,0x10,0x808080,0,0,0);
        func_0x000cce8c(0xf6,0,0x40,0xa0,0x808080,0,0,0);
        func_0x000cd7cc(_DAT_800d16bc,0x50,0xb0,*(undefined4 *)(_DAT_80048e68 + 0x264),2,0x808080);
        func_0x000cce8c(0xf9,0,0x40,0xc2,0x808080,0,0,0);
        func_0x000cd7cc(_DAT_800d16bc,0x50,0xd2,*(undefined4 *)(_DAT_80048e68 + 800),2,0x808080);
        if (_DAT_800cf85a == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        func_0x000cd7cc(_DAT_800d16c0,0x1c0,0x18,*(undefined4 *)(_DAT_80048e68 + 0x254),0,0x808080);
        if (_DAT_800cf85a == 1) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        func_0x000cd7cc(_DAT_800d16c0,0x1c0,0x30,*(undefined4 *)(_DAT_80048e68 + 600),0,0x808080);
        if (_DAT_800cf85a == 2) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        func_0x000cd7cc(_DAT_800d16c0,0x1c0,0x48,*(undefined4 *)(_DAT_80048e68 + 0x25c),0,0x808080);
        if (_DAT_800cf85a == 3) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        func_0x000cd7cc(_DAT_800d16c4,0x1c0,0x5c,*(undefined4 *)(_DAT_80048e68 + 0x260),0,0x808080);
        func_0x000cd7cc(_DAT_800d16c0,0x140,0x5e,*(undefined4 *)(_DAT_80048e68 + 0x250),2,0x808080);
        if (_DAT_800cf85a != 4) {
          func_0x000cd7cc(_DAT_800d16c0,0x140,0x78,*(undefined4 *)(_DAT_80048e68 + 0x2f8),2,0x808080
                         );
          if (_DAT_800cf85a == 5) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          func_0x000cd7cc(_DAT_800d16c0,0x140,0x90,*(undefined4 *)(_DAT_80048e68 + 0x34c),2,0x808080
                         );
          if (_DAT_800cf85a != 6) {
            func_0x000cd7cc(_DAT_800d16c0,0x140,0xa4,*(undefined4 *)(_DAT_80048e68 + 0x350),2,
                            0x808080);
            if (_DAT_800cf85a != 7) {
              func_0x000cd7cc(_DAT_800d16c0,0x140,0xb8,*(undefined4 *)(_DAT_80048e68 + 0x354),2,
                              0x808080);
              func_0x000c9758(0x100,0x18,_DAT_800d161a);
              func_0x000c9758(0x100,0x30,_DAT_8004cd74);
              func_0x000c9758(0x100,0x48,_DAT_800d161e);
              return;
            }
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      if ((_DAT_8004cc58 & 0x10000000) == 0) {
        if ((_DAT_8004cc58 & 0x100000) != 0) {
          func_0x000cd4f4(0);
          if (0 < _DAT_800cf85a) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          _DAT_800cf85a = 7;
        }
        if ((uVar4 & 0x400000) != 0) {
          func_0x000cd4f4(0);
          if (_DAT_800cf85a < 7) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          _DAT_800cf85a = 0;
        }
        func_0x000c94a8(0);
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      func_0x000cd4f4(1);
      _DAT_8004cd74 = _DAT_800d161c;
      _DAT_80048e7c = _DAT_8004cd1c;
      _DAT_80048e7e = _DAT_8004cd1e;
      func_0x000c5bc8(1);
    }
  }
  else {
    _DAT_800cf85a = 0;
    _DAT_800d16d4 = 9;
    _DAT_800d15f0 = 0;
    _DAT_800cf85c = 0;
    if (_DAT_800cf64c != 0) {
      _DAT_800cf64c = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    _DAT_800d161a = _DAT_8004cd76;
    _DAT_800d161c = _DAT_8004cd74;
    _DAT_800d161e = _DAT_8004cd78;
    _DAT_800d1620 = _DAT_8004cd7c;
    func_0x000cd2d8();
    func_0x000cd100(0x2c,1);
    func_0x000cd100(0x2d,1);
    func_0x000cd100(0x2e,1);
    func_0x000cd2fc();
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


```

## 5. phys_FUN_00001948 @ 0x00001948  tags:physics  score:16

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00001948(void)

{
  undefined1 *puVar1;
  undefined1 *puVar2;
  uint uVar3;
  
  _DAT_800d16cc = _DAT_800d16cc + 1;
  func_0x0003dec4();
  func_0x00041614();
  uVar3 = 0;
  _DAT_800d1570 = _DAT_800d1568;
  do {
    puVar2 = (undefined1 *)(uVar3 + 0x800d1574);
    puVar1 = &DAT_800d156c + uVar3;
    uVar3 = uVar3 + 1;
    *puVar2 = *puVar1;
  } while (uVar3 < 4);
  _DAT_800d1568 = func_0x00041b3c(4,&DAT_800d156c);
  func_0x000c535c();
  if (((_DAT_800d1568 == 0) || (DAT_800d156c != '\0')) && (_DAT_8004d770 != 0)) {
    func_0x000ced9c();
  }
  func_0x00043b60();
  if (_DAT_800d16d4 < 0xd) {
                    /* WARNING: Could not emulate address calculation at 0x00001a30 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(_DAT_800d16d4 * 4 + -0x7ff3bf08))();
    return;
  }
  func_0x00043b90(*(int *)(_DAT_80043cfc + 0x78) + 4);
  if (_DAT_800d16d4 == 3) {
    func_0x0003cc50(3);
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  func_0x0003cc50(7);
  func_0x0001bc08(0);
  return;
}


```

## 6. phys_FUN_00001948 @ 0x00001948  tags:physics  score:16

```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00001948(void)

{
  undefined1 *puVar1;
  undefined1 *puVar2;
  uint uVar3;
  
  _DAT_800d16cc = _DAT_800d16cc + 1;
  func_0x0003dec4();
  func_0x00041614();
  uVar3 = 0;
  _DAT_800d1570 = _DAT_800d1568;
  do {
    puVar2 = (undefined1 *)(uVar3 + 0x800d1574);
    puVar1 = &DAT_800d156c + uVar3;
    uVar3 = uVar3 + 1;
    *puVar2 = *puVar1;
  } while (uVar3 < 4);
  _DAT_800d1568 = func_0x00041b3c(4,&DAT_800d156c);
  func_0x000c535c();
  if (((_DAT_800d1568 == 0) || (DAT_800d156c != '\0')) && (_DAT_8004d770 != 0)) {
    func_0x000ced9c();
  }
  func_0x00043b60();
  if (_DAT_800d16d4 < 0xd) {
                    /* WARNING: Could not emulate address calculation at 0x00001a30 */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(_DAT_800d16d4 * 4 + -0x7ff3bf08))();
    return;
  }
  func_0x00043b90(*(int *)(_DAT_80043cfc + 0x78) + 4);
  if (_DAT_800d16d4 == 3) {
    func_0x0003cc50(3);
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  func_0x0003cc50(7);
  func_0x0001bc08(0);
  return;
}


```

## 7. phys_FUN_00001868 @ 0x00001868  tags:physics  score:11

```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_00001868(void)

{
  undefined4 uVar1;
  
  if (_DAT_800d16d0 < 8) {
                    /* WARNING: Could not emulate address calculation at 0x000018a0 */
                    /* WARNING: Treating indirect jump as call */
    uVar1 = (**(code **)(_DAT_800d16d0 * 4 + -0x7ff3bf28))();
    return uVar1;
  }
  return 0;
}


```

## 8. phys_FUN_00001868 @ 0x00001868  tags:physics  score:11

```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_00001868(void)

{
  undefined4 uVar1;
  
  if (_DAT_800d16d0 < 8) {
                    /* WARNING: Could not emulate address calculation at 0x000018a0 */
                    /* WARNING: Treating indirect jump as call */
    uVar1 = (**(code **)(_DAT_800d16d0 * 4 + -0x7ff3bf28))();
    return uVar1;
  }
  return 0;
}


```

