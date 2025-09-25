# Vertical Writer Function Dossier

## FUN_00001c84 @ 0x1c84

```c
/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Removing unreachable block (ram,0x00001f74) */
/* WARNING: Removing unreachable block (ram,0x00001f88) */
/* WARNING: Removing unreachable block (ram,0x00001fd0) */
/* WARNING: Removing unreachable block (ram,0x00002008) */
/* WARNING: Removing unreachable block (ram,0x0000201c) */
/* WARNING: Removing unreachable block (ram,0x00001fe4) */
/* WARNING: Removing unreachable block (ram,0x00001ffc) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00001c84(int param_1)

{
  int *piVar1;
  bool bVar2;
  int *piVar3;
  short sVar4;
  undefined4 in_zero;
  undefined4 in_at;
  undefined2 uVar5;
  short sVar6;
  ushort uVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  undefined4 uVar11;
  uint uVar12;
  uint uVar13;
  short sVar14;
  uint *puVar15;
  uint uVar16;
  uint uVar17;
  int iVar18;
  undefined2 *puVar19;
  short *psVar20;
  int iVar21;
  int local_58 [4];
  int local_48 [4];
  uint local_38;
  int local_34;
  int local_30;
  
  iVar10 = _DAT_800bca78;
  _DAT_800be634 = 2;
  if ((_DAT_800bca78 != 0) &&
     (iVar8 = (**(code **)(*(int *)(_DAT_800bca78 + 4) + 0x1c))
                        (_DAT_800bca78 + *(short *)(*(int *)(_DAT_800bca78 + 4) + 0x18)),
     uVar16 = _DAT_8010e4ec, iVar8 == 0)) {
    for (; uVar16 != 0xffff; uVar16 = (uint)*(ushort *)(uVar16 * 2 + _DAT_8010e4f0)) {
      iVar8 = uVar16 * 0x3a4;
      if (*(int *)(iVar8 + -0x7feed9dc) == *(int *)(iVar10 + 0x318)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      *(uint *)(iVar8 + -0x7feedbec) = *(uint *)(iVar8 + -0x7feedbec) & 0xfdffffff;
    }
    local_30 = 0;
    if ((param_1 == 0) && (0 < _DAT_8011e278)) {
      _DAT_8011e278 = _DAT_8011e278 + -1;
    }
    iVar8 = 1;
    local_34 = param_1;
    if (0 < _DAT_8011e1f0) {
      iVar8 = func_0x000423ac(_DAT_800c0270,*(undefined4 *)(_DAT_8011e1f0 * 4 + _DAT_800c02a8),0x230
                             );
      iVar8 = iVar8 + 1;
    }
    if ((param_1 != 0) || (_DAT_8011e1f0 < 1)) {
      func_0x00093b34(0x800bca94,0,
                      (int)(((_DAT_1f8003f6 + -8) - (uint)_DAT_800bcaae) * 0x10000) >> 0x10,3);
      func_0x00093b34(0x800bcad4,0,
                      (int)(((_DAT_1f8003f6 + -8) - (uint)_DAT_800bcaee) * 0x10000) >> 0x10,3);
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    iVar18 = (iVar8 + 1) * -0xc;
    iVar21 = iVar18 + 0x100;
    func_0x00093b34(0x800bca94,0,(int)(((iVar18 + 0xf4) - (uint)_DAT_800bcaae) * 0x10000) >> 0x10,3)
    ;
    func_0x00093b34(0x800bcad4,0,(int)(((iVar18 + 0xf4) - (uint)_DAT_800bcaee) * 0x10000) >> 0x10,3)
    ;
    if (0 < _DAT_8011e1f0) {
      iVar8 = iVar8 * 0xc;
      func_0x00042490(_DAT_800c0270,0x28,iVar21 * 0x10000 >> 0x10,
                      *(undefined4 *)(_DAT_8011e1f0 * 4 + _DAT_800c02a8),0,0x100,1,0x808080);
    }
    uVar16 = 0;
    if (0 < _DAT_8011e1f0) {
      iVar18 = iVar18 + 0xf8;
      uVar17 = iVar21 * 0x10000;
      uVar12 = (iVar18 + iVar8 + 0x10) * 0x10000;
      uVar9 = (iVar21 + iVar8) * 0x10000;
      do {
        piVar3 = _DAT_80043cfc;
        puVar15 = (uint *)*_DAT_80043cfc;
        piVar1 = _DAT_80043cfc + 1;
        *_DAT_80043cfc = (int)(puVar15 + 9);
        piVar3[1] = *piVar1 + 1;
        puVar15[1] = 0x3affffff;
        puVar15[3] = 0xffffff;
        puVar15[5] = 0;
        puVar15[7] = 0;
        if ((int)uVar16 < 2) {
          puVar15[2] = iVar18 * 0x10000 | 0x18;
          puVar15[6] = uVar17 | 0x28;
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        puVar15[2] = uVar12 | 0x268;
        puVar15[6] = uVar9 | 600;
        if ((uVar16 & 1) != 0) {
          puVar15[4] = iVar18 * 0x10000 | 0x268;
          puVar15[8] = uVar17 | 600;
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        puVar15[4] = uVar12 | 0x18;
        puVar15[8] = uVar9 | 0x28;
        uVar13 = *(uint *)_DAT_80043cfc[0x1e];
        uVar16 = uVar16 + 1;
        *puVar15 = uVar13 & 0xffffff | 0x8000000;
        *(uint *)_DAT_80043cfc[0x1e] = uVar13 & 0xff000000 | (uint)puVar15;
        piVar1 = _DAT_80043cfc;
      } while ((int)uVar16 < 4);
      puVar15 = (uint *)*_DAT_80043cfc;
      _DAT_80043cfc[1] = _DAT_80043cfc[1] + 1;
      *piVar1 = (int)(puVar15 + 5);
      puVar15[2] = 0x62000000;
      puVar15[3] = uVar17 | 0x28;
      puVar15[4] = iVar8 << 0x10 | 0x230;
      piVar1 = _DAT_80043cfc;
      puVar15[1] = 0xe1000200;
      uVar16 = *(uint *)piVar1[0x1e];
      *puVar15 = uVar16 & 0xffffff | 0x4000000;
      *(uint *)_DAT_80043cfc[0x1e] = uVar16 & 0xff000000 | (uint)puVar15;
      piVar1 = _DAT_80043cfc;
      puVar15 = (uint *)*_DAT_80043cfc;
      _DAT_80043cfc[1] = _DAT_80043cfc[1] + 1;
      *piVar1 = (int)(puVar15 + 5);
      puVar15[2] = 0x62000000;
      puVar15[3] = iVar18 * 0x10000 | 0x18;
      puVar15[4] = (iVar8 + 0x10) * 0x10000 | 0x250;
      piVar1 = _DAT_80043cfc;
      puVar15[1] = 0xe1000200;
      uVar16 = *(uint *)piVar1[0x1e];
      *puVar15 = uVar16 & 0xffffff | 0x4000000;
      *(uint *)_DAT_80043cfc[0x1e] = uVar16 & 0xff000000 | (uint)puVar15;
    }
    iVar8 = 0x46;
    if ((_DAT_8011e28c != 0) || (iVar18 = local_34, _DAT_8011e284 != 0)) {
      iVar18 = 0;
      uVar16 = _DAT_8011e27c;
      uVar9 = _DAT_8011e280;
      if (_DAT_8011e28c != 0) {
        iVar18 = 0xff;
        if (((((_DAT_8011e28c == 1) || (_DAT_8011e28c == 2)) || (_DAT_8011e28c == 3)) ||
            ((_DAT_8011e28c == 4 || (_DAT_8011e28c == 7)))) || (_DAT_8011e28c == 6)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        if (_DAT_8011e28c == 5) {
          iVar8 = 200;
          setCopControlWord(2,0,_DAT_1f800384);
          setCopControlWord(2,0x800,_DAT_1f800388);
          setCopControlWord(2,0x1000,_DAT_1f80038c);
          setCopControlWord(2,0x1800,_DAT_1f800390);
          setCopControlWord(2,0x2000,_DAT_1f800394);
          setCopControlWord(2,0x2800,_DAT_1f800398);
          setCopControlWord(2,0x3000,_DAT_1f80039c);
          setCopControlWord(2,0x3800,_DAT_1f8003a0);
          iVar21 = *(int *)(*(int *)(*(int *)(iVar10 + 0x318) + 0xd8) + 0x138);
          if (iVar21 == 0) {
            iVar8 = 0x32;
            iVar21 = iVar10;
          }
          setCopReg(2,in_zero,*(undefined4 *)(iVar21 + 0x6c));
          setCopReg(2,in_at,*(undefined4 *)(iVar21 + 0x70));
          copFunction(2,0x180001);
          local_38 = getCopReg(2,0xe);
          uVar16 = local_38 & 0xffff;
          uVar9 = local_38 >> 0x10;
        }
      }
      _DAT_8011e284 = _DAT_8011e284 + iVar18 >> 1;
      uVar12 = _DAT_8011e284 * 0xb0 >> 8;
      uVar17 = uVar12 | uVar12 << 8 | uVar12 << 0x10;
      _DAT_8011e288 = _DAT_8011e288 + iVar8 >> 1;
      uVar12 = (_DAT_8011e284 << 4) >> 8;
      _DAT_8011e27c = (int)(_DAT_8011e27c + uVar16) >> 1;
      _DAT_8011e280 = (int)(_DAT_8011e280 + uVar9) >> 1;
      func_0x0008ab98(_DAT_8011e288,_DAT_8011e288 + 0x1e,uVar12 | uVar12 << 8 | uVar12 << 0x10,
                      uVar17,0,2,_DAT_8011e27c,_DAT_8011e280);
      func_0x0008ab98(300,_DAT_8011e288 + 0x1e,uVar17,uVar17,0,2,_DAT_8011e27c,_DAT_8011e280);
      func_0x0008ab98(300,0x226,uVar17,uVar17,0,2,_DAT_8011e27c,_DAT_8011e280);
      func_0x0008ab98(800,0x226,uVar17,uVar17,0,2,_DAT_8011e27c,_DAT_8011e280);
      iVar18 = local_34;
    }
    do {
      if (iVar18 != 0) break;
      iVar8 = func_0x0011a930(0x8011a7ec,&DAT_8011e204,0xffffffff);
      if (iVar8 != 0) {
        func_0x000ab08c((int)(short)_DAT_8011e264,(int)(short)_DAT_8011e266,(int)_DAT_8011e268,
                        (int)_DAT_8011e26a);
        sVar6 = _DAT_80119a20;
        sVar14 = *(short *)(iVar10 + 8);
        if (*(short *)(iVar10 + 8) < _DAT_80119a18) {
          sVar14 = _DAT_80119a18;
        }
        bVar2 = _DAT_80119a20 < sVar14;
        *(short *)(iVar10 + 8) = sVar14;
        sVar4 = _DAT_80119a1c;
        if (bVar2) {
          sVar14 = sVar6;
        }
        bVar2 = *(short *)(iVar10 + 0xc) < _DAT_80119a1c;
        *(short *)(iVar10 + 8) = sVar14;
        sVar6 = _DAT_80119a24;
        sVar14 = *(short *)(iVar10 + 0xc);
        if (bVar2) {
          sVar14 = sVar4;
        }
        bVar2 = _DAT_80119a24 < sVar14;
        *(short *)(iVar10 + 0xc) = sVar14;
        if (bVar2) {
          sVar14 = sVar6;
        }
        *(short *)(iVar10 + 0xc) = sVar14;
        halt_baddata();
      }
      iVar8 = func_0x0011a930(0x8011a7f4,&DAT_8011e204,0xffffffff);
      if (((iVar8 != 0) && (_DAT_8011e274 == 1)) && (0 < (short)_DAT_8011e264)) {
        _DAT_8011e1f0 = (short)_DAT_8011e264 + -1;
        halt_baddata();
      }
      iVar8 = func_0x0011a930(0x8011a7f8,&DAT_8011e204,0xffffffff);
      if (((iVar8 == 0) || (_DAT_8011e274 == 0)) || ((short)_DAT_8011e264 < 1)) {
        iVar8 = func_0x0011a930(0x8011a7fc,&DAT_8011e204,4);
        if (iVar8 == 0) {
          iVar8 = func_0x0011a930(0x8011a80c,&DAT_8011e204,2);
          if (iVar8 == 0) {
            iVar8 = func_0x0011a930(0x8011a818,&DAT_8011e204,4);
            if (iVar8 == 0) {
              iVar8 = func_0x0011a930(0x8011a820,&DAT_8011e204,0xffffffff);
              if (iVar8 != 0) {
                _DAT_800bcf90 = 0;
                _DAT_800bd074 = 0;
                halt_baddata();
              }
              iVar8 = func_0x0011a930(0x8011a82c,&DAT_8011e204,4);
              if (iVar8 != 0) {
                func_0x0011af14(0x8011e209);
                halt_baddata();
              }
              iVar8 = func_0x0011a930(0x8011a834,&DAT_8011e204,4);
              if (iVar8 != 0) {
                if ((_DAT_8011e274 != 0) && (_DAT_8011e264 == 0)) {
                  _DAT_8004d724 = _DAT_8004d724 & 0xdfffffff;
                  halt_baddata();
                }
                _DAT_8004d724 = _DAT_8004d724 | 0x20000000;
                halt_baddata();
              }
              iVar8 = func_0x0011a930(0x8011a83c,&DAT_8011e204,0xffffffff);
              if ((iVar8 != 0) && (1 < _DAT_8011e274)) {
                *(ushort *)((short)_DAT_8011e264 * 0xa4 + _DAT_8011a19c + 0x14) = _DAT_8011e266;
                halt_baddata();
              }
              iVar8 = func_0x0011a930(0x8011a84c,&DAT_8011e204,0xffffffff);
              if ((iVar8 != 0) && (_DAT_8011e274 != 0)) {
                if (_DAT_8011e274 < 2) {
                  _DAT_8011e266 = (ushort)(_DAT_8011e264 == 0);
                }
                func_0x0011dd74((int)(short)_DAT_8011e264,(int)(short)_DAT_8011e266);
                func_0x00078918(0x800bd050,1);
                func_0x00078918(0x800bcf6c,0);
                *(undefined2 *)(iVar10 + 8) =
                     *(undefined2 *)(*(int *)(*(int *)(iVar10 + 0x318) + 0xd8) + 8);
                *(undefined2 *)(iVar10 + 0xc) =
                     *(undefined2 *)(*(int *)(*(int *)(iVar10 + 0x318) + 0xd8) + 0xc);
                halt_baddata();
              }
              iVar8 = func_0x0011a930(0x8011a854,&DAT_8011e204,0xffffffff);
              if (iVar8 != 0) {
                local_34 = 0;
                func_0x0011ab78();
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
              iVar8 = func_0x0011a930(0x8011a85c,&DAT_8011e204,0xffffffff);
              if ((iVar8 != 0) && (_DAT_8011e274 == 1)) {
                if (_DAT_8011e264 == 0) {
                  func_0x000e472c(0,0);
                  func_0x00079ae0(*(undefined4 *)(iVar10 + 0x318),0);
                  iVar10 = *(int *)(iVar10 + 0x318);
                  *(undefined4 *)(iVar10 + 8) = 0;
                  *(undefined4 *)(iVar10 + 4) = 0;
                }
                func_0x0011aa0c((int)(short)_DAT_8011e264,0);
                halt_baddata();
              }
              iVar8 = func_0x0011a930(0x8011a864,&DAT_8011e204,0xffffffff);
              if (iVar8 != 0) {
                func_0x0011aa0c(0,99);
                halt_baddata();
              }
              iVar8 = func_0x0011a930(0x8011a870,&DAT_8011e204,0xffffffff);
              if ((iVar8 != 0) && (_DAT_8011e274 == 1)) {
                _DAT_8011e278 = (int)(short)_DAT_8011e264;
                halt_baddata();
              }
              iVar8 = func_0x0011a930(0x8011a648,&DAT_8011e204,0xffffffff);
              if ((iVar8 == 0) || (_DAT_8011e274 == 0)) {
                iVar8 = func_0x0011a930(0x8011a878,&DAT_8011e204,0xffffffff);
                if ((iVar8 == 0) || (_DAT_8011e274 != 1)) {
                  iVar8 = func_0x0011a930(0x8011a884,&DAT_8011e204,0xffffffff);
                  if ((iVar8 != 0) && (_DAT_8011e274 == 1)) {
                    func_0x00075df0(iVar10,9999);
                    iVar8 = ((int)(((uint)*(ushort *)(iVar10 + 0xb0) -
                                   (uint)*(ushort *)(iVar10 + 0xb2)) * 0x10000) >> 0x10) -
                            (int)(short)_DAT_8011e264;
                    if (iVar8 < 0) {
                      iVar8 = 0;
                    }
                    (**(code **)(*(int *)(iVar10 + 4) + 0x4c))
                              (iVar10 + *(short *)(*(int *)(iVar10 + 4) + 0x48),iVar8);
                    halt_baddata();
                  }
                  iVar8 = func_0x0011a930(0x8011a88c,&DAT_8011e204,0xffffffff);
                  if (iVar8 != 0) {
                    if ((_DAT_8011e274 != 0) && (_DAT_8011e264 == 0)) {
                      *(uint *)(iVar10 + 0x108) = *(uint *)(iVar10 + 0x108) & 0xfdffffff;
                      halt_baddata();
                    }
                    *(uint *)(iVar10 + 0x108) = *(uint *)(iVar10 + 0x108) | 0x2000000;
                    halt_baddata();
                  }
                  iVar8 = func_0x0011a930(0x8011a898,&DAT_8011e204,0xffffffff);
                  if (iVar8 == 0) {
                    iVar8 = func_0x0011a930(0x8011a8a4,&DAT_8011e204,0xffffffff);
                    uVar16 = _DAT_8011e274;
                    uVar7 = _DAT_8011e264;
                    if (iVar8 == 0) {
                      iVar8 = func_0x0011a930(0x8011a8b0,&DAT_8011e204,0xffffffff);
                      if ((iVar8 != 0) && (_DAT_8011e274 != 0)) {
                        iVar10 = (int)(short)_DAT_8011e264;
                        func_0x00023000(local_48,0,0x10);
                        local_58[0] = 1;
                        if (1 < _DAT_8011e274) {
                          local_58[0] = (int)(short)_DAT_8011e266;
                        }
                        local_48[1] = 0xffffffff;
                        local_48[2] = 0xffffffff;
                        local_58[1] = 0xffffffff;
                        local_58[2] = 0xffffffff;
                        local_58[3] = local_48[3];
                        local_48[0] = local_58[0];
                        func_0x00070790(local_58,_DAT_8011e264,
                                        *(undefined2 *)(iVar10 * 0xe4 + -0x7ff43040));
                        halt_baddata();
                      }
                      iVar8 = func_0x0011a930(0x8011a8bc,&DAT_8011e204,0xffffffff);
                      if ((iVar8 != 0) && (_DAT_8011e274 != 0)) {
                        *(short *)(iVar10 + 0xc) = *(short *)(iVar10 + 0xc) + -0x800;
                        func_0x000f2214((int)(short)_DAT_8011e266,iVar10 + 8);
                        *(short *)(iVar10 + 0xc) = *(short *)(iVar10 + 0xc) + 0x800;
                        halt_baddata();
                      }
                      iVar8 = func_0x0011a930(0x8011a8cc,&DAT_8011e204,0xffffffff);
                      if (iVar8 == 0) {
                        iVar8 = func_0x0011a930(0x8011a8d8,&DAT_8011e204,0xffffffff);
                        if (iVar8 == 0) {
                          iVar8 = func_0x0011a930(0x8011a8e4,&DAT_8011e204,0xffffffff);
                          if (iVar8 == 0) {
                            iVar8 = func_0x0011a930(0x8011a8f0,&DAT_8011e204,0xffffffff);
                            if ((iVar8 != 0) && (_DAT_8011e274 == 1)) {
                              func_0x000e4e2c(*(undefined4 *)(*(int *)(iVar10 + 0x318) + 0xd8),
                                              (int)(short)_DAT_8011e264,0);
                              halt_baddata();
                            }
                            iVar8 = func_0x0011a930(0x8011a8fc,&DAT_8011e204,0xffffffff);
                            if (iVar8 != 0) {
                              iVar8 = 999;
                              if (_DAT_8011e274 != 0) {
                                iVar8 = (int)(short)_DAT_8011e264;
                              }
                              func_0x00075df0(iVar10,iVar8);
                              halt_baddata();
                            }
                            iVar8 = func_0x0011a930(0x8011a908,&DAT_8011e204,0xffffffff);
                            if ((iVar8 != 0) && (1 < _DAT_8011e274)) {
                              iVar8 = (int)_DAT_80119a1c;
                              *(short *)(iVar10 + 8) =
                                   _DAT_80119a18 +
                                   (short)((int)(short)_DAT_8011e264 *
                                           ((int)_DAT_80119a20 - (int)_DAT_80119a18) >> 0xc);
                              *(short *)(iVar10 + 0xc) =
                                   _DAT_80119a1c +
                                   (short)((int)(short)_DAT_8011e266 * (_DAT_80119a24 - iVar8) >>
                                          0xc);
                              uVar5 = func_0x000ab4d0(iVar10 + 8);
                              *(undefined2 *)(iVar10 + 10) = uVar5;
                              halt_baddata();
                            }
                            iVar8 = func_0x0011a930(0x8011a914,&DAT_8011e204,0xffffffff);
                            if (iVar8 == 0) {
                              iVar8 = func_0x0011a930(0x8011a924,&DAT_8011e204,0xffffffff);
                              if (iVar8 != 0) {
                                iVar8 = func_0x00071260(0x32);
                                iVar10 = _DAT_801199e8;
                                *(int *)(iVar8 + 0x11c) = _DAT_801199e8;
                                *(undefined2 *)(iVar8 + 0xb0) = *(undefined2 *)(iVar10 + 0x20);
                                *(undefined2 *)(iVar10 + 0x4c) = 30000;
                                uVar16 = 0;
                                (**(code **)(*(int *)(iVar8 + 4) + 0x8c))
                                          (iVar8 + *(short *)(*(int *)(iVar8 + 4) + 0x88));
                                func_0x0005b2b0(iVar8);
                                iVar10 = **(int **)(iVar8 + 0x11c);
                                *(short *)(iVar8 + 0x226) = (short)iVar10;
                                *(undefined4 *)(iVar8 + 0x228) =
                                     *(undefined4 *)(iVar10 * 4 + -0x7fee6878);
                                func_0x000544bc(iVar8,0x800bd050);
                                iVar10 = (int)_DAT_80119a1c;
                                iVar18 = (int)_DAT_80119a24;
                                *(short *)(iVar8 + 8) =
                                     (short)(_DAT_80119a18 * 3 + (int)_DAT_80119a20 >> 2);
                                *(short *)(iVar8 + 0xc) = (short)(iVar10 + iVar18 >> 1);
                                uVar5 = func_0x000ab4d0(iVar8 + 8);
                                *(undefined2 *)(iVar8 + 10) = uVar5;
                                func_0x00078b54(0x800bd050,iVar8);
                                func_0x00057dd4(iVar8,2,0);
                                *(undefined2 *)(iVar8 + 0x48) = 0;
                                uVar11 = func_0x00081ea8(iVar8 + 8);
                                *(undefined4 *)(iVar8 + 0x310) = uVar11;
                                *(undefined2 *)(iVar8 + 0x314) = 0;
                                *(undefined2 *)(iVar8 + 0x348) = 0xf100;
                                *(undefined2 *)(iVar8 + 0x34e) = 0;
                                do {
                                  func_0x000209dc();
                                  uVar9 = func_0x000209dc();
                                  if ((uVar9 & 1) != 0) {
                                    func_0x000209dc();
                    /* WARNING: Bad instruction - Truncating control flow here */
                                    halt_baddata();
                                  }
                                  uVar9 = func_0x000209dc();
                                  uVar9 = (uVar9 & 0x7f) << 0x10;
                                  uVar11 = func_0x00084134();
                                  uVar12 = func_0x000209dc();
                                  iVar10 = func_0x00086048(uVar11,iVar8 + 8,0,6,
                                                           (uVar12 & 0x3f) + 0x78,3,uVar9 | 0x80b0b0
                                                           ,(uVar9 & 0xfcfcfc | 0x80b0b0) >> 2);
                                  if (iVar10 != 0) {
                                    uVar7 = func_0x000209dc();
                                    *(ushort *)(iVar10 + 2) =
                                         *(short *)(iVar10 + 2) - (uVar7 & 0x1ff);
                                  }
                                  uVar16 = uVar16 + 1;
                                } while (uVar16 < 8);
                                halt_baddata();
                              }
                              if (DAT_8011e204 != ':') {
                                iVar10 = func_0x0011a930(0x8011a604,&DAT_8011e204,0xffffffff);
                                if (iVar10 != 0) {
                                  _DAT_8011e254 = _DAT_8011e1fc;
                                  func_0x0011ab78();
                                  _DAT_8004d6fa = 0;
                                  _DAT_800c02a0 = 3;
                                  _DAT_800c02cc = 0;
                                  halt_baddata();
                                }
                                func_0x0011ab78();
                                halt_baddata();
                              }
                            }
                            else {
                              iVar18 = _DAT_800c0314 + -1;
                              iVar8 = _DAT_800bd720;
                              if (iVar18 != -1) {
                                do {
                                  bVar2 = false;
                                  if (((_DAT_800c031c < *(short *)(iVar8 + 8)) &&
                                      (_DAT_800c0324 < *(short *)(iVar8 + 0xc))) &&
                                     (*(short *)(iVar8 + 8) < _DAT_800c0330)) {
                                    bVar2 = *(short *)(iVar8 + 0xc) < _DAT_800c0338;
                                  }
                                  if (((bVar2) &&
                                      ((((_DAT_800bd68c != 3 || (5 < (short)_DAT_8011e264)) ||
                                        (*(short *)(iVar8 + 0xc) != 0xb40)) &&
                                       (((*(uint *)(iVar8 + 0xb8) & 0x10) != 0 ||
                                        ((*(uint *)(iVar8 + 0xb8) & 0xb0) == 0)))))) &&
                                     (*(int *)(iVar8 + 0x54) == 0)) {
                                    func_0x000757b4(iVar8,0);
                                    func_0x00081a08(iVar8);
                                    if (_DAT_8011e274 < 2) {
                                      sVar6 = func_0x000ab4d0(iVar8 + 8);
                                      *(short *)(iVar8 + 10) = sVar6 + -5000;
                                    }
                                    if ((_DAT_8011e274 == 0) ||
                                       (_DAT_8011e264 = _DAT_8011e264 - 1,
                                       (int)((uint)_DAT_8011e264 << 0x10) < 1)) break;
                                  }
                                  iVar18 = iVar18 + -1;
                                  iVar8 = iVar8 + 0xf4;
                                  if (iVar18 == -1) {
                                    halt_baddata();
                                  }
                                } while( true );
                              }
                            }
                          }
                          else {
                            uVar16 = 0;
                            if (_DAT_8011e274 != 0) {
                              psVar20 = (short *)&DAT_8011e264;
                              do {
                                if (*psVar20 < 0) {
                                  _DAT_8011e1f8 = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
                                  halt_baddata();
                                }
                                func_0x0011a9ac(*psVar20);
                                uVar16 = uVar16 + 1;
                                psVar20 = psVar20 + 1;
                              } while (uVar16 < _DAT_8011e274);
                              halt_baddata();
                            }
                          }
                        }
                        else {
                          uVar16 = 0;
                          if (_DAT_8011e274 != 0) {
                            psVar20 = (short *)&DAT_8011e264;
                            do {
                              if (*psVar20 < 0) {
                                _DAT_8011e1f8 = 1;
                    /* WARNING: Bad instruction - Truncating control flow here */
                                halt_baddata();
                              }
                              func_0x0011a990(*psVar20);
                              uVar16 = uVar16 + 1;
                              psVar20 = psVar20 + 1;
                            } while (uVar16 < _DAT_8011e274);
                            halt_baddata();
                          }
                        }
                      }
                      else {
                        uVar16 = 0;
                        _DAT_8011e1f4 = 0x10;
                        if (_DAT_8011e274 != 0) {
                          puVar19 = (undefined2 *)&DAT_8011e264;
                          do {
                            uVar5 = *puVar19;
                            puVar19 = puVar19 + 1;
                            func_0x0011a990(uVar5);
                            uVar16 = uVar16 + 1;
                          } while (uVar16 < _DAT_8011e274);
                          halt_baddata();
                        }
                      }
                    }
                    else {
                      uVar9 = _DAT_8010e4ec;
                      if (_DAT_8010e4ec != 0xffff) {
                        while ((uVar16 != 0 && (uVar7 == 0))) {
                          *(uint *)(uVar9 * 0x3a4 + -0x7feedbec) =
                               *(uint *)(uVar9 * 0x3a4 + -0x7feedbec) & 0xefffffff;
                          uVar9 = (uint)*(ushort *)(uVar9 * 2 + _DAT_8010e4f0);
                          if (uVar9 == 0xffff) {
                    /* WARNING: Bad instruction - Truncating control flow here */
                            halt_baddata();
                          }
                        }
                    /* WARNING: Bad instruction - Truncating control flow here */
                        halt_baddata();
                      }
                    }
                  }
                  else {
                    if ((_DAT_8011e274 == 0) || (_DAT_8011e264 != 0)) {
                      *(uint *)(iVar10 + 0x108) = *(uint *)(iVar10 + 0x108) | 0x10000000;
                    /* WARNING: Bad instruction - Truncating control flow here */
                      halt_baddata();
                    }
                    *(uint *)(iVar10 + 0x108) = *(uint *)(iVar10 + 0x108) & 0xefffffff;
                    if (1 < _DAT_8011e274) {
                      if (_DAT_8011e266 != 0) {
                        *(uint *)(iVar10 + 0x50) = *(uint *)(iVar10 + 0x50) & 0xffffffef;
                        halt_baddata();
                      }
                      *(uint *)(iVar10 + 0x50) = *(uint *)(iVar10 + 0x50) | 0x10;
                      halt_baddata();
                    }
                  }
                }
                else {
                  iVar18 = _DAT_800c0314 + -1;
                  iVar8 = _DAT_800bd720;
                  if (iVar18 != -1) {
                    do {
                      iVar10 = *(int *)(iVar8 + 0xe0);
                      if (*(uint *)(iVar10 + 4) < 100) {
                        if (_DAT_8011e264 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
                          halt_baddata();
                        }
                        *(uint *)(iVar10 + 8) = *(uint *)(iVar10 + 8) & 0xffffffdf;
                      }
                      iVar18 = iVar18 + -1;
                      iVar8 = iVar8 + 0xf4;
                    } while (iVar18 != -1);
                    halt_baddata();
                  }
                }
              }
              else {
                if (_DAT_8011e274 < 2) {
                  (**(code **)(*(int *)(iVar10 + 4) + 0x5c))
                            (iVar10 + *(short *)(*(int *)(iVar10 + 4) + 0x58),
                             *(undefined2 *)(iVar10 + 0xb8));
                  func_0x000779f4(iVar10,_DAT_8011e264);
                  halt_baddata();
                }
                uVar16 = _DAT_8010e4ec;
                if (_DAT_8010e4ec != 0xffff) {
                  do {
                    iVar8 = uVar16 * 0x3a4;
                    iVar18 = iVar8 + -0x7feedcf4;
                    if (iVar18 != iVar10) {
                      (**(code **)(*(int *)(iVar8 + -0x7feedcf0) + 0x5c))
                                (iVar18 + *(short *)(*(int *)(iVar8 + -0x7feedcf0) + 0x58),
                                 *(undefined2 *)(iVar8 + -0x7feedc3c));
                      func_0x000779f4(iVar18,_DAT_8011e264);
                    }
                    uVar16 = (uint)*(ushort *)(uVar16 * 2 + _DAT_8010e4f0);
                  } while (uVar16 != 0xffff);
                  halt_baddata();
                }
              }
            }
            else {
              iVar8 = func_0x000e374c();
              if (iVar8 != 0) {
                func_0x00075df0(iVar8,999);
                halt_baddata();
              }
            }
          }
          else {
            iVar8 = func_0x0011a930(0x8011a810,&DAT_8011e204,5);
            if (iVar8 != 0) {
              func_0x0011b6bc(0x8011e20a,iVar10);
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
            iVar8 = func_0x0011b6bc(0x8011e207,iVar10);
            if (iVar8 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
          }
        }
        else {
          local_34 = 0;
          local_30 = 0;
          iVar8 = func_0x0011a930(0x8011a804,&DAT_8011e204,7);
          if (iVar8 != 0) {
            func_0x0011b6bc(0x8011e20c,iVar10);
            halt_baddata();
          }
          iVar8 = func_0x0011b6bc(0x8011e209,iVar10);
          if (iVar8 == 0) {
            halt_baddata();
          }
        }
      }
      else if ((_DAT_8011e274 < 3) || ((_DAT_8011e290 & 1 << ((int)_DAT_8011e268 & 0x1fU)) == 0)) {
        if (1 < _DAT_8011e274) {
          _DAT_8011e290 = _DAT_8011e290 | 1 << ((int)_DAT_8011e268 & 0x1fU);
        }
        _DAT_8011e1f0 = (short)_DAT_8011e264 + -1;
        local_34 = 1;
        if (1 < _DAT_8011e274) {
          _DAT_8011e28c = (int)(short)_DAT_8011e266;
          halt_baddata();
        }
      }
      if (local_30 == 0) {
        func_0x0011ab78();
      }
      iVar18 = local_30;
    } while (local_34 == 0);
    if (local_34 != 0) {
      if (local_34 != 0) {
        func_0x0011afdc();
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      func_0x0011b01c();
    }
  }
  return;
}
```

## FUN_0001a320 @ 0x1a320

```c
void FUN_0001a320(int param_1)

{
  int iVar1;
  int iVar2;
  undefined2 uVar3;
  
  iVar1 = 0;
  for (iVar2 = 0; iVar2 < 8; iVar2 = iVar2 + 1) {
    if (*(int *)(iVar1 + param_1 + 100) != 0) {
      FUN_0001f5e8();
      *(undefined4 *)(iVar1 + param_1 + 100) = 0;
    }
    iVar1 = iVar1 + 4;
  }
  *(undefined4 *)(param_1 + 0x40) = 0;
  *(undefined4 *)(param_1 + 0x3c) = 0;
  *(undefined4 *)(param_1 + 0x38) = 0;
  *(undefined4 *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x1c) = 0;
  *(undefined4 *)(param_1 + 0x34) = 0;
  *(undefined4 *)(param_1 + 0x44) = 3;
  *(undefined2 *)(param_1 + 0x54) = 0;
  *(undefined2 *)(param_1 + 0x4c) = 0;
  iVar1 = *(int *)(param_1 + 0x44) * 0x140;
  uVar3 = (undefined2)(iVar1 >> 1);
  if (iVar1 < 0) {
    uVar3 = (undefined2)(iVar1 + 1 >> 1);
  }
  *(undefined2 *)(param_1 + 0x58) = uVar3;
  *(undefined2 *)(param_1 + 0x50) = uVar3;
  *(undefined2 *)(param_1 + 0x5a) = 0xf0;
  *(undefined2 *)(param_1 + 0x52) = 0xf0;
  *(undefined2 *)(param_1 + 0x4e) = 0;
  *(undefined2 *)(param_1 + 0x56) = 0xf0;
  *(undefined2 *)(param_1 + 0x5e) = 0;
  *(undefined2 *)(param_1 + 0x5c) = 0;
  *(undefined2 *)(param_1 + 0x62) = 0xf0;
  iVar1 = *(int *)(param_1 + 0x44) * 0x10;
  uVar3 = (undefined2)(iVar1 >> 1);
  if (iVar1 < 0) {
    uVar3 = (undefined2)(iVar1 + 1 >> 1);
  }
  *(undefined2 *)(param_1 + 0x60) = uVar3;
  *(undefined4 *)(param_1 + 0x20) = 0;
  *(undefined4 *)(param_1 + 0x30) = 0;
  *(undefined4 *)(param_1 + 0x24) = 0;
  iVar1 = *(int *)(param_1 + 0x44) * 0x140;
  if (iVar1 < 0) {
    iVar1 = iVar1 + 1;
  }
  *(int *)(param_1 + 0x28) = iVar1 >> 1;
  *(undefined4 *)(param_1 + 0x2c) = 0xf0;
  *(undefined4 *)(param_1 + 0x88) = 0;
  *(undefined4 *)(param_1 + 0x8c) = 1;
  *(undefined4 *)(param_1 + 0x84) = 1;
  *(undefined4 *)(param_1 + 0x90) = 0;
  return;
}
```

## FUN_0001a348 @ 0x1a348

```c
void FUN_0001a348(void)

{
  int in_v0;
  int iVar1;
  int unaff_s0;
  int unaff_s1;
  int unaff_s2;
  undefined2 uVar2;
  
  while( true ) {
    if (*(int *)(in_v0 + 100) != 0) {
      FUN_0001f5e8();
      *(undefined4 *)(unaff_s1 + unaff_s0 + 100) = 0;
    }
    unaff_s2 = unaff_s2 + 1;
    unaff_s1 = unaff_s1 + 4;
    if (7 < unaff_s2) break;
    in_v0 = unaff_s1 + unaff_s0;
  }
  *(undefined4 *)(unaff_s0 + 0x40) = 0;
  *(undefined4 *)(unaff_s0 + 0x3c) = 0;
  *(undefined4 *)(unaff_s0 + 0x38) = 0;
  *(undefined4 *)(unaff_s0 + 0x18) = 0;
  *(undefined4 *)(unaff_s0 + 0x1c) = 0;
  *(undefined4 *)(unaff_s0 + 0x34) = 0;
  *(undefined4 *)(unaff_s0 + 0x44) = 3;
  *(undefined2 *)(unaff_s0 + 0x54) = 0;
  *(undefined2 *)(unaff_s0 + 0x4c) = 0;
  iVar1 = *(int *)(unaff_s0 + 0x44) * 0x140;
  uVar2 = (undefined2)(iVar1 >> 1);
  if (iVar1 < 0) {
    uVar2 = (undefined2)(iVar1 + 1 >> 1);
  }
  *(undefined2 *)(unaff_s0 + 0x58) = uVar2;
  *(undefined2 *)(unaff_s0 + 0x50) = uVar2;
  *(undefined2 *)(unaff_s0 + 0x5a) = 0xf0;
  *(undefined2 *)(unaff_s0 + 0x52) = 0xf0;
  *(undefined2 *)(unaff_s0 + 0x4e) = 0;
  *(undefined2 *)(unaff_s0 + 0x56) = 0xf0;
  *(undefined2 *)(unaff_s0 + 0x5e) = 0;
  *(undefined2 *)(unaff_s0 + 0x5c) = 0;
  *(undefined2 *)(unaff_s0 + 0x62) = 0xf0;
  iVar1 = *(int *)(unaff_s0 + 0x44) * 0x10;
  uVar2 = (undefined2)(iVar1 >> 1);
  if (iVar1 < 0) {
    uVar2 = (undefined2)(iVar1 + 1 >> 1);
  }
  *(undefined2 *)(unaff_s0 + 0x60) = uVar2;
  *(undefined4 *)(unaff_s0 + 0x20) = 0;
  *(undefined4 *)(unaff_s0 + 0x30) = 0;
  *(undefined4 *)(unaff_s0 + 0x24) = 0;
  iVar1 = *(int *)(unaff_s0 + 0x44) * 0x140;
  if (iVar1 < 0) {
    iVar1 = iVar1 + 1;
  }
  *(int *)(unaff_s0 + 0x28) = iVar1 >> 1;
  *(undefined4 *)(unaff_s0 + 0x2c) = 0xf0;
  *(undefined4 *)(unaff_s0 + 0x88) = 0;
  *(undefined4 *)(unaff_s0 + 0x8c) = 1;
  *(undefined4 *)(unaff_s0 + 0x84) = 1;
  *(undefined4 *)(unaff_s0 + 0x90) = 0;
  return;
}
```

## FUN_0001a3b0 @ 0x1a3b0

```c
void FUN_0001a3b0(void)

{
  int in_v0;
  int iVar1;
  int in_v1;
  int unaff_s0;
  undefined2 uVar2;
  
  iVar1 = (in_v0 + in_v1) * 0x40;
  uVar2 = (undefined2)(iVar1 >> 1);
  if (iVar1 < 0) {
    uVar2 = (undefined2)(iVar1 + 1 >> 1);
  }
  *(undefined2 *)(unaff_s0 + 0x58) = uVar2;
  *(undefined2 *)(unaff_s0 + 0x50) = uVar2;
  *(undefined2 *)(unaff_s0 + 0x5a) = 0xf0;
  *(undefined2 *)(unaff_s0 + 0x52) = 0xf0;
  *(undefined2 *)(unaff_s0 + 0x4e) = 0;
  *(undefined2 *)(unaff_s0 + 0x56) = 0xf0;
  *(undefined2 *)(unaff_s0 + 0x5e) = 0;
  *(undefined2 *)(unaff_s0 + 0x5c) = 0;
  *(undefined2 *)(unaff_s0 + 0x62) = 0xf0;
  iVar1 = *(int *)(unaff_s0 + 0x44) * 0x10;
  uVar2 = (undefined2)(iVar1 >> 1);
  if (iVar1 < 0) {
    uVar2 = (undefined2)(iVar1 + 1 >> 1);
  }
  *(undefined2 *)(unaff_s0 + 0x60) = uVar2;
  *(undefined4 *)(unaff_s0 + 0x20) = 0;
  *(undefined4 *)(unaff_s0 + 0x30) = 0;
  *(undefined4 *)(unaff_s0 + 0x24) = 0;
  iVar1 = *(int *)(unaff_s0 + 0x44) * 0x140;
  if (iVar1 < 0) {
    iVar1 = iVar1 + 1;
  }
  *(int *)(unaff_s0 + 0x28) = iVar1 >> 1;
  *(undefined4 *)(unaff_s0 + 0x2c) = 0xf0;
  *(undefined4 *)(unaff_s0 + 0x88) = 0;
  *(undefined4 *)(unaff_s0 + 0x8c) = 1;
  *(undefined4 *)(unaff_s0 + 0x84) = 1;
  *(undefined4 *)(unaff_s0 + 0x90) = 0;
  return;
}
```

## FUN_0001a528 @ 0x1a528

```c
undefined4 FUN_0001a528(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  if (*(int *)(param_1 + 0x88) == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    FUN_00031e14();
    if ((*(int *)(param_1 + 0x24) == 0) || (*(int *)(param_1 + 0x8c) != 0)) {
      FUN_0002d1a4(*(undefined4 *)(param_1 + *(int *)(param_1 + 0x38) * 4 + 4),
                   *(undefined4 *)(param_1 + 0x44));
      *(uint *)(param_1 + 0x38) = *(uint *)(param_1 + 0x38) ^ 1;
      iVar2 = (int)*(short *)(param_1 + 0x60) * (int)*(short *)(param_1 + 0x62);
      if (iVar2 < 0) {
        iVar2 = iVar2 + 1;
      }
      FUN_0002d220(*(undefined4 *)(param_1 + *(int *)(param_1 + 0x3c) * 4 + 0xc),iVar2 >> 1);
      *(uint *)(param_1 + 0x3c) = *(uint *)(param_1 + 0x3c) ^ 1;
      uVar1 = 1;
    }
    else {
      FUN_00031cd0(param_1);
      uVar1 = 0;
    }
  }
  return uVar1;
}
```

## FUN_0001a558 @ 0x1a558

```c
undefined4 FUN_0001a558(void)

{
  undefined4 uVar1;
  int unaff_s0;
  int iVar2;
  
  if ((*(int *)(unaff_s0 + 0x24) == 0) || (*(int *)(unaff_s0 + 0x8c) != 0)) {
    FUN_0002d1a4(*(undefined4 *)(unaff_s0 + *(int *)(unaff_s0 + 0x38) * 4 + 4),
                 *(undefined4 *)(unaff_s0 + 0x44));
    *(uint *)(unaff_s0 + 0x38) = *(uint *)(unaff_s0 + 0x38) ^ 1;
    iVar2 = (int)*(short *)(unaff_s0 + 0x60) * (int)*(short *)(unaff_s0 + 0x62);
    if (iVar2 < 0) {
      iVar2 = iVar2 + 1;
    }
    FUN_0002d220(*(undefined4 *)(unaff_s0 + *(int *)(unaff_s0 + 0x3c) * 4 + 0xc),iVar2 >> 1);
    *(uint *)(unaff_s0 + 0x3c) = *(uint *)(unaff_s0 + 0x3c) ^ 1;
    uVar1 = 1;
  }
  else {
    FUN_00031cd0();
    uVar1 = 0;
  }
  return uVar1;
}
```

## FUN_0001a614 @ 0x1a614

```c
undefined4 FUN_0001a614(int param_1)

{
  undefined2 uVar1;
  int iVar2;
  int iVar3;
  int local_8;
  undefined4 uStack_4;
  
  iVar3 = 0x200000;
  do {
    iVar2 = FUN_00030d08(&uStack_4,&local_8);
    if (iVar2 == 0) {
      if ((*(uint *)(param_1 + 0x18) <= *(uint *)(local_8 + 8)) ||
         (((*(uint *)(local_8 + 8) < *(uint *)(param_1 + 0x1c) && (*(int *)(param_1 + 0x20) == 0))
          || ((int)*(uint *)(param_1 + 0x18) < *(int *)(param_1 + 0x34))))) {
        *(undefined4 *)(param_1 + 0x24) = 1;
      }
      if ((*(uint *)(param_1 + 0x28) != (uint)*(ushort *)(local_8 + 0x10)) ||
         (*(uint *)(param_1 + 0x2c) != (uint)*(ushort *)(local_8 + 0x12))) {
        *(uint *)(param_1 + 0x28) = (uint)*(ushort *)(local_8 + 0x10);
        *(uint *)(param_1 + 0x2c) = (uint)*(ushort *)(local_8 + 0x12);
        uVar1 = (undefined2)(*(int *)(param_1 + 0x28) * *(int *)(param_1 + 0x44) >> 1);
        *(undefined2 *)(param_1 + 0x58) = uVar1;
        *(undefined2 *)(param_1 + 0x50) = uVar1;
        uVar1 = (undefined2)*(undefined4 *)(param_1 + 0x2c);
        *(undefined2 *)(param_1 + 0x62) = uVar1;
        *(undefined2 *)(param_1 + 0x5a) = uVar1;
        *(undefined2 *)(param_1 + 0x52) = uVar1;
      }
      *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(local_8 + 8);
      FUN_0002d2dc(uStack_4,*(undefined4 *)(param_1 + *(int *)(param_1 + 0x38) * 4 + 4));
      FUN_00030c18(uStack_4);
      *(int *)(param_1 + 0x34) = *(int *)(param_1 + 0x34) + 1;
      return 1;
    }
    iVar3 = iVar3 + -1;
  } while (0 < iVar3);
  return 0;
}
```

## FUN_0001abfc @ 0x1abfc

```c
void FUN_0001abfc(int param_1)

{
  int iVar1;
  
  FUN_0001a440(param_1 + 0x5c,*(undefined4 *)(param_1 + (1 - *(int *)(param_1 + 0x3c)) * 4 + 0xc));
  *(short *)(param_1 + 0x5c) = *(short *)(param_1 + 0x5c) + *(short *)(param_1 + 0x60);
  iVar1 = *(int *)(param_1 + 0x40) * 8 + param_1;
  if ((int)*(short *)(param_1 + 0x5c) <
      (int)*(short *)(iVar1 + 0x4c) + (int)*(short *)(iVar1 + 0x50)) {
    iVar1 = (int)*(short *)(param_1 + 0x60) * (int)*(short *)(param_1 + 0x62);
    if (iVar1 < 0) {
      iVar1 = iVar1 + 1;
    }
    FUN_0002d220(*(undefined4 *)(param_1 + *(int *)(param_1 + 0x3c) * 4 + 0xc),iVar1 >> 1);
    *(uint *)(param_1 + 0x3c) = *(uint *)(param_1 + 0x3c) ^ 1;
  }
  else {
    *(undefined4 *)(param_1 + 0x30) = 1;
    *(undefined2 *)(param_1 + 0x5c) = *(undefined2 *)(*(int *)(param_1 + 0x40) * 8 + param_1 + 0x4c)
    ;
    *(undefined2 *)(param_1 + 0x5e) = *(undefined2 *)(*(int *)(param_1 + 0x40) * 8 + param_1 + 0x4e)
    ;
    *(uint *)(param_1 + 0x40) = *(uint *)(param_1 + 0x40) ^ 1;
  }
  return;
}
```

## FUN_0002a8c8 @ 0x2a8c8

```c
/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_0002a8c8(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  ushort *puVar5;
  int iVar6;
  int iVar7;
  ushort *puVar8;
  int iVar9;
  int iVar10;
  ushort *puVar11;
  ushort uVar12;
  
  uVar4 = 0;
  if (*(char *)(param_1 + 0xd2) != '\0') {
    iVar3 = 0;
    do {
      uVar12 = 0;
      puVar8 = (ushort *)(param_1 + 0x72 + iVar3);
      if (*puVar8 != 0) {
        puVar11 = (ushort *)(param_1 + 0x70 + iVar3);
        do {
          iVar9 = *(int *)((uint)*(ushort *)(param_1 + 0x70 + iVar3) * 4 + -0x7fee66e0);
          iVar10 = 0;
          uVar12 = uVar12 + 1;
          if (3 < *(int *)(&DAT_800bcfc0 + (uint)*(ushort *)(iVar9 + 0xa6) * 0xe4)) {
            puVar5 = (ushort *)(iVar9 + 0xa6);
            do {
              puVar5 = puVar5 + 1;
              iVar10 = iVar10 + 1;
            } while (3 < *(int *)(&DAT_800bcfc0 + (uint)*puVar5 * 0xe4));
          }
          iVar1 = func_0x00071260(*puVar11);
          iVar6 = *(int *)((uint)*puVar11 * 4 + -0x7fee66e0);
          *(int *)(iVar1 + 0x11c) = iVar6;
          *(undefined2 *)(iVar1 + 0xb0) = *(undefined2 *)(iVar6 + 0x20);
          func_0x000e301c(iVar1,*(undefined2 *)(iVar9 + iVar10 * 2 + 0xa6));
          uVar2 = func_0x00081ea8(iVar1 + 8);
          *(undefined4 *)(iVar1 + 0x310) = uVar2;
          *(undefined2 *)(iVar1 + 0x314) = 0;
        } while (uVar12 < *puVar8);
      }
      uVar4 = uVar4 + 1 & 0xffff;
      iVar3 = uVar4 << 2;
    } while (uVar4 < *(byte *)(param_1 + 0xd2));
  }
  uVar4 = 0;
  if (*(char *)(param_1 + 0xcd) != '\0') {
    iVar3 = 0;
    do {
      iVar9 = (iVar3 + uVar4) * 4;
      uVar12 = 0;
      if (*(short *)(param_1 + 0x1a + iVar9) != 0) {
        puVar8 = (ushort *)(param_1 + 0x18 + iVar9);
        do {
          iVar1 = 0;
          iVar10 = *(int *)((uint)*(ushort *)(param_1 + 0x18 + (iVar3 + uVar4) * 4) * 4 +
                           -0x7fee66e0);
          uVar12 = uVar12 + 1;
          if (3 < *(int *)(&DAT_800bcfc0 + (uint)*(ushort *)(iVar10 + 0xa6) * 0xe4)) {
            puVar11 = (ushort *)(iVar10 + 0xa6);
            do {
              puVar11 = puVar11 + 1;
              iVar1 = iVar1 + 1;
            } while (3 < *(int *)(&DAT_800bcfc0 + (uint)*puVar11 * 0xe4));
          }
          iVar6 = func_0x00071260(*puVar8);
          iVar7 = *(int *)((uint)*puVar8 * 4 + -0x7fee66e0);
          *(int *)(iVar6 + 0x11c) = iVar7;
          *(undefined2 *)(iVar6 + 0xb0) = *(undefined2 *)(iVar7 + 0x20);
          func_0x000e301c(iVar6,*(undefined2 *)(iVar10 + iVar1 * 2 + 0xa6));
          *(undefined4 *)(iVar6 + 8) = *(undefined4 *)(iVar9 + param_1 + 0x1c);
          *(undefined4 *)(iVar6 + 0xc) = *(undefined4 *)(iVar9 + param_1 + 0x20);
          if (_DAT_8004d6ee == 0x17) {
            uVar2 = func_0x00081e74(3);
            *(undefined4 *)(iVar6 + 0x310) = uVar2;
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          uVar2 = func_0x00081ea8(iVar6 + 8);
          *(undefined4 *)(iVar6 + 0x310) = uVar2;
          *(undefined2 *)(iVar6 + 0x314) = 0;
          if (_DAT_8004d6ee == 4) {
            func_0x000efabc(param_1,iVar6);
          }
        } while (uVar12 < *(ushort *)(param_1 + 0x1a + (iVar3 + uVar4) * 4));
      }
      uVar4 = uVar4 + 1 & 0xffff;
      iVar3 = uVar4 << 1;
    } while (uVar4 < *(byte *)(param_1 + 0xcd));
  }
  return;
}
```

