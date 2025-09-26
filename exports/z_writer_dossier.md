# Direct-Z Writer Dossier

## FUN_00001c84

- Integrator: no; axes=-; directPos=0

> iVar18 = iVar18 + 0xf8; uVar17 = iVar21 * 0x10000; uVar12 = (iVar18 + iVar8 + 0x10) * 0x10000; uVar9 = (iVar21 + iVar8) * 0x10000; do {
> puVar15[2] = 0x62000000; puVar15[3] = iVar18 * 0x10000 | 0x18; puVar15[4] = (iVar8 + 0x10) * 0x10000 | 0x250; piVar1 = _DAT_80043cfc; puVar15[1] = 0xe1000200;
> sVar14 = sVar6; } bVar2 = *(short *)(iVar10 + 0xc) < _DAT_80119a1c; *(short *)(iVar10 + 8) = sVar14; sVar6 = _DAT_80119a24;
> *(short *)(iVar10 + 8) = sVar14; sVar6 = _DAT_80119a24; sVar14 = *(short *)(iVar10 + 0xc); if (bVar2) { sVar14 = sVar4;
> } bVar2 = _DAT_80119a24 < sVar14; *(short *)(iVar10 + 0xc) = sVar14; if (bVar2) { sVar14 = sVar6;

## FUN_00008528

- Integrator: no; axes=-; directPos=0

> FUN_000240a0(param_1); iVar2 = FUN_0001cba8(*(int *)(*(int *)(param_1 + 0x7c) + 4) + **(int **)(*(int *)(param_1 + 0x7c) + 0xc) * 0x58,unaff_gp + -0x7fe4,3); if (iVar2 == 0) { FUN_00024400(*(undefined4 *)(unaff_gp + -0x7e14));
> **(undefined1 **)(unaff_gp + -0x7e44) = 1; } iVar2 = FUN_00021424(*(int *)(param_1 + 0x7c),**(undefined4 **)(*(int *)(param_1 + 0x7c) + 0xc)); if (iVar2 == 0) { FUN_00024400(*(undefined4 *)(unaff_gp + -0x7e14));
> } **(undefined1 **)(unaff_gp + -0x7e44) = 1; iVar2 = *(int *)(*(int *)(param_1 + 0x7c) + 4) + **(int **)(*(int *)(param_1 + 0x7c) + 0xc) * 0x58 ; if (-1 < *(int *)(iVar2 + 0x44)) {
> iVar4 = iVar4 + 1; } **(undefined2 **)(iVar3 + 0xc) = (short)(iVar4 >> 1); *(short *)(*(int *)(iVar3 + 0xc) + 2) = (short)*(undefined4 *)(iVar2 + 0x54); iVar4 = thunk_FUN_0001f5d4(0x10);
> } **(undefined2 **)(iVar3 + 0xc) = (short)(iVar4 >> 1); *(short *)(*(int *)(iVar3 + 0xc) + 2) = (short)*(undefined4 *)(iVar2 + 0x54); iVar4 = thunk_FUN_0001f5d4(0x10); if (iVar4 != 0) {

## FUN_0000af3c

- Integrator: no; axes=-; directPos=0

> *(undefined1 *)(iVar3 + 6) = *(undefined1 *)(iVar7 + -0x7ffaa522); iVar8 = uVar12 * 4; *(undefined1 *)(iVar3 + 0x10) = *(undefined1 *)(iVar8 + -0x7ffaa524); *(undefined1 *)(iVar3 + 0x11) = *(undefined1 *)(iVar8 + -0x7ffaa523); *(undefined1 *)(iVar3 + 0x12) = *(undefined1 *)(iVar8 + -0x7ffaa522);
> *(undefined2 *)(iVar3 + 0x20) = *(undefined2 *)(iVar1 + iVar5); *(undefined2 *)(iVar3 + 0x22) = ((undefined2 *)(iVar1 + iVar5))[1]; *(byte *)(iVar3 + 0xc) = pbVar9[4]; *(byte *)(iVar3 + 0xd) = pbVar9[8]; *(byte *)(iVar3 + 0x18) = pbVar9[5];
> *(undefined2 *)(iVar3 + 10) = puVar6[1]; puVar6 = (undefined2 *)(iVar1 + uVar12 * 4); *(undefined2 *)(iVar3 + 0x10) = *puVar6; *(undefined2 *)(iVar3 + 0x12) = puVar6[1]; puVar6 = (undefined2 *)(iVar1 + uVar2 * 4);
> *(undefined2 *)(iVar3 + 0x18) = *puVar6; *(undefined2 *)(iVar3 + 0x1a) = puVar6[1]; *(byte *)(iVar3 + 0xc) = pbVar9[4]; *(byte *)(iVar3 + 0xd) = pbVar9[8]; *(byte *)(iVar3 + 0x14) = pbVar9[5];
> *(undefined1 *)(iVar3 + 5) = *(undefined1 *)(iVar7 + -0x7ffaa523); *(undefined1 *)(iVar3 + 6) = *(undefined1 *)(iVar7 + -0x7ffaa522); *(undefined1 *)(iVar3 + 0x10) = *(undefined1 *)(iVar5 + -0x7ffaa524); *(undefined1 *)(iVar3 + 0x11) = *(undefined1 *)(iVar5 + -0x7ffaa523); *(undefined1 *)(iVar3 + 0x12) = *(undefined1 *)(iVar5 + -0x7ffaa522);

## FUN_00022dc8

- Integrator: yes; axes=Z; directPos=1

> iVar4 = *(int *)(*(int *)(param_1 + 0xec) + (uVar3 - 1) * 4 + 0x184); uVar5 = *(uint *)(iVar4 + 8); uStack_4c = *(uint *)(iVar4 + 0xc); uStack_50._2_2_ = (short)(uVar5 >> 0x10); iVar6 = (uint)*(ushort *)(param_1 + 0xc) - (uStack_4c & 0xffff);
> uStack_4c = *(uint *)(iVar4 + 0xc); uStack_50._2_2_ = (short)(uVar5 >> 0x10); iVar6 = (uint)*(ushort *)(param_1 + 0xc) - (uStack_4c & 0xffff); iVar4 = (uint)*(ushort *)(param_1 + 8) - (uVar5 & 0xffff); sStack_48 = (short)iVar4;
> *(short *)(param_1 + 0x38) = sVar1; *(short *)(param_1 + 10) = *(short *)(param_1 + 10) + sVar7; *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + sVar1; iVar4 = func_0x000ab4d0(param_1 + 8); if (iVar4 < *(short *)(param_1 + 10)) {
> sStack_48 = (short)iVar9; sStack_46 = *(short *)(param_1 + 10) - uStack_58._2_2_; iVar10 = (uint)*(ushort *)(param_1 + 0xc) - (local_54 & 0xffff); sStack_44 = (short)iVar10; iVar4 = (*(ushort *)(*(int *)(param_1 + 0xec) + 0x12) & 0xfff) * 4;
> *(short *)(param_1 + 0x38) = (short)(-iVar6 >> 7); *(ushort *)(param_1 + 8) = *(ushort *)(param_1 + 8) - (short)(-(iVar4 * iVar8) >> 0xc); *(ushort *)(param_1 + 0xc) = *(ushort *)(param_1 + 0xc) - (short)(-(iVar4 * iVar6) >> 0xc); } iVar4 = *(int *)(param_1 + 0xec);

## FUN_00022e5c

- Integrator: yes; axes=Z; directPos=1

>  setCopControlWord(2,0x1000,in_t4); setCopControlWord(2,0x1800,*(undefined4 *)(in_v1 + 0xc)); setCopControlWord(2,0x2000,*(undefined4 *)(in_v1 + 0x10)); iVar10 = (int)*(short *)(param_1 + 0x152);
> setCopControlWord(2,0x1000,in_t4); setCopControlWord(2,0x1800,*(undefined4 *)(in_v1 + 0xc)); setCopControlWord(2,0x2000,*(undefined4 *)(in_v1 + 0x10)); iVar10 = (int)*(short *)(param_1 + 0x152); iVar11 = (int)*(short *)(param_1 + 0x154);
> iVar5 = *(int *)(*(int *)(unaff_s2 + 0xec) + (unaff_s5 - 1) * 4 + 0x184); uVar7 = *(uint *)(iVar5 + 8); uStack0000001c = *(uint *)(iVar5 + 0xc); uStack00000018._2_2_ = (short)(uVar7 >> 0x10); iVar8 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uStack0000001c & 0xffff);
> uStack0000001c = *(uint *)(iVar5 + 0xc); uStack00000018._2_2_ = (short)(uVar7 >> 0x10); iVar8 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uStack0000001c & 0xffff); iVar5 = (uint)*(ushort *)(unaff_s2 + 8) - (uVar7 & 0xffff); sStack00000020 = (short)iVar5;
> *(short *)(unaff_s2 + 0x38) = sVar3; *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + sVar9; *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar3; iVar10 = func_0x000ab4d0(unaff_s2 + 8); if (iVar10 < *(short *)(unaff_s2 + 10)) {

## FUN_00023000

- Integrator: yes; axes=Z; directPos=1

> *(short *)(unaff_s2 + 0x38) = sVar1; *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + sVar5; *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar1; iVar3 = func_0x000ab4d0(unaff_s2 + 8); if (iVar3 < *(short *)(unaff_s2 + 10)) {
> iVar4 = (int)*(short *)(iVar3 + -0x7ffeb162); iVar3 = -((int)(((uint)*(ushort *)(unaff_s2 + 8) - (uint)param_5) * 0x10000) >> 0x10) * iVar6 - ((int)(((uint)*(ushort *)(unaff_s2 + 0xc) - (uint)param_6) * 0x10000) >> 0x10) * iVar4 >> 0xc; if (iVar3 < 0) {
> *(short *)(unaff_s2 + 0x38) = (short)(-iVar4 >> 7); *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar3 * iVar6) >> 0xc); *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar3 * iVar4) >> 0xc); } iVar3 = *(int *)(unaff_s2 + 0xec);
> } uVar2 = 0xc100; if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) { *(undefined2 *)(unaff_s2 + 0xc) = uVar2;
> uVar2 = 0xc100; if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) { *(undefined2 *)(unaff_s2 + 0xc) = uVar2; }

## FUN_00023110

- Integrator: yes; axes=Z; directPos=1

> *(short *)(unaff_s2 + 0x38) = sVar1; *(short *)(unaff_s2 + 10) = *(short *)(unaff_s2 + 10) + param_4; *(short *)(unaff_s2 + 0xc) = *(short *)(unaff_s2 + 0xc) + sVar1; iVar3 = func_0x000ab4d0(); if (iVar3 < *(short *)(unaff_s2 + 10)) {
> iVar4 = (int)*(short *)(iVar3 + -0x7ffeb162); iVar3 = -((int)(((uint)*(ushort *)(unaff_s2 + 8) - (param_5 & 0xffff)) * 0x10000) >> 0x10) * iVar5 - ((int)(((uint)*(ushort *)(unaff_s2 + 0xc) - (uint)param_6) * 0x10000) >> 0x10) * iVar4 >> 0xc; if (iVar3 < 0) {
> *(short *)(unaff_s2 + 0x38) = (short)(-iVar4 >> 7); *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar3 * iVar5) >> 0xc); *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar3 * iVar4) >> 0xc); } iVar3 = *(int *)(unaff_s2 + 0xec);
> } uVar2 = 0xc100; if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) { *(undefined2 *)(unaff_s2 + 0xc) = uVar2;
> uVar2 = 0xc100; if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) || (uVar2 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) { *(undefined2 *)(unaff_s2 + 0xc) = uVar2; }

## FUN_00023180

- Integrator: yes; axes=Z; directPos=1

>  *(undefined2 *)(unaff_s2 + 10) = in_v0; *(undefined4 *)(in_a3 + 0x10) = 1; iVar3 = (uint)*(ushort *)(unaff_s2 + 8) - (in_stack_00000010 & 0xffff); uStack00000020 = (undefined2)iVar3;
> uStack00000020 = (undefined2)iVar3; sStack00000022 = *(short *)(unaff_s2 + 10) - in_stack_00000010._2_2_; iVar4 = (uint)*(ushort *)(unaff_s2 + 0xc) - (uint)in_stack_00000014; uStack00000024 = (undefined2)iVar4; iVar2 = (*(ushort *)(*(int *)(unaff_s2 + 0xec) + 0x12) & 0xfff) * 4;
> *(short *)(unaff_s2 + 0x38) = (short)(-iVar5 >> 7); *(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar2 * iVar6) >> 0xc); *(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar2 * iVar5) >> 0xc); } iVar2 = *(int *)(unaff_s2 + 0xec);
> } while (uVar7 < *(ushort *)(iVar2 + 0x182)); } *(undefined4 *)(in_a3 + 0x10) = 4; uVar1 = 0xc100; if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
> } uVar1 = 0xc100; if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) || (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) { *(undefined2 *)(unaff_s2 + 0xc) = uVar1;

## FUN_00023210

- Integrator: yes; axes=Z; directPos=1

> *(short *)(unaff_s2 + 0x38) = (short)(-param_3 >> 7); *(short *)(unaff_s2 + 8) = in_t2 - (short)(-((in_v1 + -10) * in_t0) >> 0xc); *(short *)(unaff_s2 + 0xc) = in_t1 - (short)(-((in_v1 + -10) * param_3) >> 0xc); iVar2 = *(int *)(unaff_s2 + 0xec); uVar3 = 0;
> } while (uVar3 < *(ushort *)(iVar2 + 0x182)); } *(undefined4 *)(param_4 + 0x10) = 4; uVar1 = 0xc100; if ((*(short *)(unaff_s2 + 8) < -0x3f00) || (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 8))) {
> } uVar1 = 0xc100; if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) || (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) { *(undefined2 *)(unaff_s2 + 0xc) = uVar1;
> uVar1 = 0xc100; if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) || (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) { *(undefined2 *)(unaff_s2 + 0xc) = uVar1; }
> if ((*(short *)(unaff_s2 + 0xc) < -0x3f00) || (uVar1 = 0x3f00, 0x3f00 < *(short *)(unaff_s2 + 0xc))) { *(undefined2 *)(unaff_s2 + 0xc) = uVar1; } return;

## FUN_0002380c

- Integrator: no; axes=-; directPos=0

>  *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(param_1 + 8); *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0xc); if ((*(uint *)(param_1 + 0xb8) & 2) != 0) { *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) | 4;
> } if ((*(uint *)(param_1 + 0xb8) & 0x10) != 0) { *(ushort *)(param_1 + 0x10) = *(short *)(param_1 + 0x10) + 0x78U & 0xfff; *(ushort *)(param_1 + 0x12) = *(short *)(param_1 + 0x12) + 0xf0U & 0xfff; }
> if ((uVar5 & 8) != 0) { uVar9 = *(undefined4 *)(*(int *)(param_1 + 0xe8) + 8); uVar10 = *(undefined4 *)(*(int *)(param_1 + 0xe8) + 0xc); _DAT_8011a138 = (short)uVar9; _DAT_8011a13a = (short)((uint)uVar9 >> 0x10);
> } uVar3 = 0xc100; if ((*(short *)(param_1 + 0xc) < -0x3f00) || (uVar3 = 0x3f00, 0x3f00 < *(short *)(param_1 + 0xc))) { *(undefined2 *)(param_1 + 0xc) = uVar3;
> uVar3 = 0xc100; if ((*(short *)(param_1 + 0xc) < -0x3f00) || (uVar3 = 0x3f00, 0x3f00 < *(short *)(param_1 + 0xc))) { *(undefined2 *)(param_1 + 0xc) = uVar3; }

## FUN_00035cc0

- Integrator: yes; axes=Z; directPos=0

> int local_2c;  *(undefined2 *)(param_1 + 0x10) = 0; sVar1 = FUN_00022e5c((int)*(short *)(param_1 + 0x24),(int)*(short *)(param_1 + 0x28)); *(short *)(param_1 + 0x12) = -sVar1;
> *(short *)(param_1 + 0x12) = -sVar1; *(undefined2 *)(param_1 + 0x14) = 0; func_0x00081afc(param_1,param_1 + 0x10); func_0x000755a8(param_1,0); uVar3 = func_0x0006d03c(0x183,param_1 + 0x68,local_f8,local_178,3);
> unaff_s3 = *piVar9; unaff_s5 = *piVar10; unaff_s2 = *(int *)(unaff_s3 + 0xc); local_3c = FUN_00022e5c((int)*(short *)(unaff_s5 + 4) - (int)*(short *)(unaff_s3 + 4), (int)*(short *)(unaff_s5 + 8) - (int)*(short *)(unaff_s3 + 8));
> func_0x000e6ad4(unaff_s2,0); if (unaff_s2 != 0) { (**(code **)(*(int *)(unaff_s2 + 4) + 0xc)) (unaff_s2 + *(short *)(*(int *)(unaff_s2 + 4) + 8),3); /* WARNING: Bad instruction - Truncating control flow here */
> } uVar2 = FUN_00022e5c((int)*(short *)(unaff_s3 + 4) - (int)*(short *)(param_1 + 8), (int)*(short *)(unaff_s3 + 8) - (int)*(short *)(param_1 + 0xc)); (**(code **)(*(int *)(unaff_s2 + 4) + 100)) (unaff_s2 + *(short *)(*(int *)(unaff_s2 + 4) + 0x60),uVar2,
