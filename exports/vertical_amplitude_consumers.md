# Potential amplitude field consumers (reads/writes outside core writers)

| Function | EA | Line | Class | Code |
|----------|----|------|-------|------|
| FUN_00005e14 | 0x5e14 | 7 | read | `uVar1 = func_0x0006ea78(*(undefined4 *)(*(int *)(param_2 + 8) + 0x54),1);` |
| FUN_00005e50 | 0x5e50 | 15 | read | `uVar1 = func_0x0006c768(*(undefined4 *)(*(int *)(param_2 + 8) + 0x54),local_40);` |
| FUN_00006240 | 0x6240 | 5 | read | `func_0x000c994c(param_1,*(undefined4 *)(*(int *)(*(int *)(param_2 + 8) + 0x318) + 0x54));` |
| FUN_00006f90 | 0x6f90 | 11 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_00007084 | 0x7084 | 11 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_000071ec | 0x71ec | 12 | read | `(((((*(uint *)(iVar2 + 0xb8) & 8) == 0 && ((*(uint *)(iVar2 + 0x50) & 4) == 0)) &&` |
| FUN_00007710 | 0x7710 | 17 | read | `uVar2 = *(undefined2 *)(*(int *)(iVar1 + 0xc0) + 0x50);` |
| FUN_00007784 | 0x7784 | 17 | read | `uVar3 = *(undefined4 *)(*(int *)(iVar1 + 0xc0) + 0x54);` |
| FUN_00007a74 | 0x7a74 | 7 | read | `uVar1 = func_0x0006e55c(*(undefined4 *)(*(int *)(param_2 + 8) + 0x54));` |
| FUN_00007f10 | 0x7f10 | 17 | read | `} while ((*(int *)(aiStack_18[uVar2] + 0x54) != 6) \|\|` |
| FUN_0000852c | 0x852c | 16 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_00008610 | 0x8610 | 16 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_00008704 | 0x8704 | 15 | read | `uVar4 = *(uint *)(iVar5 + 0x58);` |
| FUN_00008704 | 0x8704 | 25 | read | `if (*(uint *)(iVar5 + 0x54) == 0) {` |
| FUN_00008704 | 0x8704 | 28 | read | `return uVar1 / *(uint *)(iVar5 + 0x54);` |
| FUN_0000888c | 0x888c | 12 | read | `if ((*(int *)(iVar2 + 0x300) == 2) && ((*(uint *)(iVar2 + 0x50) & 0x20a00) == 0)) {` |
| FUN_0000888c | 0x888c | 33 | read | `(iVar2 = (**(code **)(*(int *)(iVar1 + 0x10) + 0x4c))` |
| FUN_00009274 | 0x9274 | 8 | read | `(**(code **)(iVar1 + 0x54))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar1 + 0x50),0);` |
| FUN_000092cc | 0x92cc | 8 | read | `(**(code **)(iVar1 + 0x54))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar1 + 0x50),0);` |
| FUN_00009638 | 0x9638 | 8 | read | `(**(code **)(iVar1 + 0x54))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar1 + 0x50));` |
| FUN_0000c020 | 0xc020 | 27 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0000c020 | 0xc020 | 28 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0000c10c | 0xc10c | 18 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0000c10c | 0xc10c | 19 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0000c910 | 0xc910 | 18 | read | `if (((*(uint *)(param_2 + 0x50) & 1) == 0) \|\|` |
| FUN_0000c9fc | 0xc9fc | 22 | read | `if (((*(uint *)(param_2 + 0x50) & 1) == 0) \|\|` |
| FUN_0000d090 | 0xd090 | 22 | read | `(**(code **)(*(int *)(iVar1 + 0x10) + 0x54))` |
| FUN_0000d090 | 0xd090 | 23 | read | `(iVar1 + *(short *)(*(int *)(iVar1 + 0x10) + 0x50),0);` |
| FUN_0000d090 | 0xd090 | 36 | read | `(**(code **)(*(int *)(iVar3 + 0x10) + 0x54))` |
| FUN_0000d090 | 0xd090 | 37 | read | `(iVar3 + *(short *)(*(int *)(iVar3 + 0x10) + 0x50),0);` |
| FUN_0000d090 | 0xd090 | 38 | read | `(**(code **)(*(int *)(iVar1 + 0x10) + 0x54))` |
| FUN_0000d090 | 0xd090 | 39 | read | `(iVar1 + *(short *)(*(int *)(iVar1 + 0x10) + 0x50),0);` |
| FUN_0000d090 | 0xd090 | 43 | read | `(**(code **)(*(int *)(iVar3 + 0x10) + 0x54))(iVar3 + *(short *)(*(int *)(iVar3 + 0x10) + 0x50));` |
| FUN_0000d398 | 0xd398 | 44 | read | `for (iVar3 = *(int *)(iVar6 + iVar5 * 4 + 4); iVar3 != 0; iVar3 = *(int *)(iVar3 + 0x58))` |
| FUN_0000dbb4 | 0xdbb4 | 21 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0000dbb4 | 0xdbb4 | 22 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00010c1c | 0x10c1c | 30 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00010c1c | 0x10c1c | 31 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00010c1c | 0x10c1c | 59 | read | `if ((*(uint *)(iVar4 + 0x50) & 1) == 0) goto LAB_00010ea0;` |
| FUN_00010c1c | 0x10c1c | 71 | read | `if ((*(uint *)(iVar4 + 0x50) & 1) == 0) {` |
| FUN_0001150c | 0x1150c | 36 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001150c | 0x1150c | 37 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00011714 | 0x11714 | 44 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00011714 | 0x11714 | 45 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000119cc | 0x119cc | 47 | read | `uVar1 = *(ushort *)(iVar2 + 0x54);` |
| FUN_000119cc | 0x119cc | 66 | read | `iVar3 = func_0x0006c768(*(undefined4 *)(param_2 + 0x54),aiStack_58);` |
| FUN_000119cc | 0x119cc | 71 | read | `iVar9 = *(int *)(iVar9 + 0x58)) {` |
| FUN_000119cc | 0x119cc | 73 | read | `uVar7 = *(uint *)(iVar9 + 0x50);` |
| FUN_000122ec | 0x122ec | 58 | read | `if ((*(uint *)(iVar5 + 0x50) & 1) != 0) {` |
| FUN_000122ec | 0x122ec | 78 | read | `(**(code **)(iVar3 + 0x54))(*param_1 + (int)*(short *)(iVar3 + 0x50),1);` |
| FUN_0001301c | 0x1301c | 63 | read | `if ((*(uint *)(iVar4 + 0x50) & 5) != 0) {` |
| FUN_000138c4 | 0x138c4 | 27 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_000138c4 | 0x138c4 | 28 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00013dec | 0x13dec | 21 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00013dec | 0x13dec | 22 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000146c0 | 0x146c0 | 31 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_000146c0 | 0x146c0 | 32 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001528c | 0x1528c | 34 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001528c | 0x1528c | 35 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001543c | 0x1543c | 14 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001543c | 0x1543c | 15 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015508 | 0x15508 | 5 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015508 | 0x15508 | 6 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015668 | 0x15668 | 17 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015668 | 0x15668 | 18 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000158f0 | 0x158f0 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_000158f0 | 0x158f0 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015990 | 0x15990 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015990 | 0x15990 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000159e0 | 0x159e0 | 13 | read | `uVar5 = *(uint *)(iVar4 + 0x58);` |
| FUN_00015ba4 | 0x15ba4 | 7 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015ba4 | 0x15ba4 | 8 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015c4c | 0x15c4c | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015c4c | 0x15c4c | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001655c | 0x1655c | 35 | read | `(**(code **)(iVar3 + 0x54))(*(int *)*param_1 + (int)*(short *)(iVar3 + 0x50),1);` |
| FUN_0001655c | 0x1655c | 87 | read | `(**(code **)(*(int *)(iVar4 + 0x10) + 0x54))` |
| FUN_0001655c | 0x1655c | 88 | read | `(iVar4 + *(short *)(*(int *)(iVar4 + 0x10) + 0x50),1);` |
| FUN_0001a688 | 0x1a688 | 11 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001a688 | 0x1a688 | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001a754 | 0x1a754 | 11 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001a754 | 0x1a754 | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001a834 | 0x1a834 | 46 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001a834 | 0x1a834 | 47 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001a958 | 0x1a958 | 9 | read | `uVar3 = *(uint *)(*(int *)(*(int *)(*(int *)(param_1 + 0x24) + 8) + 0x318) + 0x58);` |
| FUN_0001aa78 | 0x1aa78 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001aa78 | 0x1aa78 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ab10 | 0x1ab10 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ab10 | 0x1ab10 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001aba8 | 0x1aba8 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001aba8 | 0x1aba8 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ac40 | 0x1ac40 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ac40 | 0x1ac40 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001acd8 | 0x1acd8 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001acd8 | 0x1acd8 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ad70 | 0x1ad70 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ad70 | 0x1ad70 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001adb8 | 0x1adb8 | 18 | read | `uVar5 = *(undefined4 *)(iVar4 + 0x54);` |
| FUN_0001aea4 | 0x1aea4 | 15 | read | `uVar3 = *(undefined4 *)(iVar2 + 0x54);` |
| FUN_0001b198 | 0x1b198 | 41 | read | `func_0x0007a3e0(iVar3,iVar4 + 0x38,iVar4 + 0x50,local_10);` |
| FUN_0001b198 | 0x1b198 | 71 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001b198 | 0x1b198 | 72 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001b544 | 0x1b544 | 43 | read | `func_0x0007a3e0(iVar5,iVar2 + 0x38,iVar2 + 0x50,local_18);` |
| FUN_0001b544 | 0x1b544 | 80 | read | `func_0x0007a3e0(iVar5,iVar4 + 0x38,iVar4 + 0x50,local_18);` |
| FUN_0001b544 | 0x1b544 | 142 | read | `uVar3 = (**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001b544 | 0x1b544 | 143 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001bf94 | 0x1bf94 | 43 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001bf94 | 0x1bf94 | 44 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c3ec | 0x1c3ec | 11 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c3ec | 0x1c3ec | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c5c4 | 0x1c5c4 | 50 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c5c4 | 0x1c5c4 | 51 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c7c4 | 0x1c7c4 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c7c4 | 0x1c7c4 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c8d8 | 0x1c8d8 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c8d8 | 0x1c8d8 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c9cc | 0x1c9cc | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c9cc | 0x1c9cc | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001cac0 | 0x1cac0 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001cac0 | 0x1cac0 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001cbb4 | 0x1cbb4 | 46 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001cbb4 | 0x1cbb4 | 47 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ce00 | 0x1ce00 | 40 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ce00 | 0x1ce00 | 41 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001d200 | 0x1d200 | 7 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001d200 | 0x1d200 | 8 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001e80c | 0x1e80c | 19 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001e80c | 0x1e80c | 20 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001e8dc | 0x1e8dc | 14 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001e8dc | 0x1e8dc | 15 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ec7c | 0x1ec7c | 55 | read | `*(ushort *)((int)piVar6 + 0x4e) = uVar4;` |
| FUN_000207a8 | 0x207a8 | 53 | read | `iVar2 = iVar2 + 0x4c;` |
| FUN_000209dc | 0x209dc | 9 | read | `param_1 = *(int *)(param_1 + 0x58);` |
| FUN_00020b88 | 0x20b88 | 33 | read | `iVar4 = iVar4 + 0x4c;` |
| FUN_00020dcc | 0x20dcc | 60 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) \| 4;` |
| FUN_000226c4 | 0x226c4 | 11 | read | `(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58),param_2);` |
| FUN_000226c4 | 0x226c4 | 23 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffffb \| 8;` |
| FUN_00022790 | 0x22790 | 19 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x5c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58),0);` |
| FUN_00022790 | 0x22790 | 39 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffff7;` |
| FUN_00022790 | 0x22790 | 52 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffff7 \| 4;` |
| FUN_00022924 | 0x22924 | 30 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffffb \| 0x1000;` |
| FUN_00022a18 | 0x22a18 | 13 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffefff \| 4;` |
| FUN_00023698 | 0x23698 | 20 | write | `*(ushort *)(param_1 + 0xd4) = *(ushort *)(param_1 + 0xd4) + 0x50;` |
| FUN_00023698 | 0x23698 | 30 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00023698 | 0x23698 | 35 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 0x80;` |
| FUN_0002380c | 0x2380c | 26 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_0002380c | 0x2380c | 108 | read | `uVar5 = *(uint *)(param_1 + 0x50);` |
| FUN_0002380c | 0x2380c | 199 | read | `if ((*(uint *)(param_1 + 0x50) & 0x40) != 0) {` |
| FUN_00024454 | 0x24454 | 5 | read | `if ((*(uint *)(param_1 + 0x50) & 0x1000) == 0) {` |
| FUN_00024454 | 0x24454 | 10 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00024454 | 0x24454 | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58),0);` |
| FUN_00024454 | 0x24454 | 13 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffff7 \| 0x80;` |
| FUN_00024558 | 0x24558 | 22 | read | `if ((*(uint *)(param_1 + 0x50) & 8) == 0) {` |
| FUN_000249e4 | 0x249e4 | 68 | write | `*(undefined4 *)(iVar6 + 0x50) = *(undefined4 *)(param_1 + 0x50);` |
| FUN_00025048 | 0x25048 | 30 | write | `*(undefined4 *)(param_1 + 0x54) = 0;` |
| FUN_00025c18 | 0x25c18 | 40 | read | `*(uint *)(iVar2 + 0x50) = *(uint *)(iVar2 + 0x50) \| 4;` |
| FUN_00026768 | 0x26768 | 23 | read | `*(uint *)(iVar2 + 0x50) = *(uint *)(iVar2 + 0x50) \| 4;` |
| FUN_0002685c | 0x2685c | 66 | read | `*(uint *)(iVar9 + 0x50) = *(uint *)(iVar9 + 0x50) \| 4;` |
| FUN_00026c68 | 0x26c68 | 20 | read | `((*(uint *)(param_1 + 0x50) & 4) == 0)) {` |
| FUN_00026e4c | 0x26e4c | 9 | read | `if ((*(uint *)(param_1 + 0x50) & 8) == 0) {` |
| FUN_00026e4c | 0x26e4c | 13 | read | `if ((*(int *)(iVar2 + 0x54) == 6) && (*(int *)(param_1 + 0xf4) != 0)) {` |
| FUN_00027a44 | 0x27a44 | 12 | read | `if (*(int *)(iVar1 + 0x54) != param_2) {` |
| FUN_000280a0 | 0x280a0 | 16 | read | `iVar3 = *(int *)(param_1 + 0x54);` |
| FUN_000280a0 | 0x280a0 | 28 | read | `iVar3 = *(int *)(param_1 + 0x58);` |
| FUN_000283f8 | 0x283f8 | 58 | write | `*(ushort *)(param_1 + 0x4c + uVar4 * 2) = *puVar7;` |
| FUN_000283f8 | 0x283f8 | 69 | write | `*(ushort *)(param_1 + 0x50 + iVar5) = *puVar7;` |
| FUN_00028724 | 0x28724 | 24 | read | `if (*(int *)(param_1 + 0x54) == 6) {` |
| FUN_00028724 | 0x28724 | 28 | read | `if ((*(uint *)(param_2 + 0x50) & 4) != 0) {` |
| FUN_00028724 | 0x28724 | 31 | read | `if ((*(uint *)(param_2 + 0x50) & 1) != 0) {` |
| FUN_00028724 | 0x28724 | 38 | read | `if ((*(int *)(param_1 + 0x58) == 3) && (*(int *)(param_2 + 0x300) != 1)) {` |
| FUN_00028724 | 0x28724 | 61 | read | `if (*(uint *)(param_1 + 0x58) < 2) {` |
| FUN_00028724 | 0x28724 | 66 | read | `else if ((*(int *)(param_1 + 0x58) == 2) \|\| (*(int *)(param_1 + 0x58) == 0)) {` |
| FUN_00028724 | 0x28724 | 78 | read | `iVar6 = *(int *)(param_1 + 0x54);` |
| FUN_00028724 | 0x28724 | 86 | read | `else if (*(int *)(param_1 + 0x54) != 1) {` |
| FUN_00028c60 | 0x28c60 | 26 | read | `*(undefined4 *)(iVar3 + 0x54) = 0;` |
| FUN_00028c60 | 0x28c60 | 27 | read | `*(undefined4 *)(iVar3 + 0x58) = 0;` |
| FUN_00028d10 | 0x28d10 | 19 | read | `*(undefined4 *)(iVar1 + 0x54) = 5;` |
| FUN_00028e58 | 0x28e58 | 9 | read | `if (*(int *)(param_1 + 0x54) == 2) {` |
| FUN_00028e58 | 0x28e58 | 13 | read | `if (*(int *)(param_1 + 0x54) != 3) {` |
| FUN_00028ef4 | 0x28ef4 | 11 | read | `if ((iVar2 != -1) && (*(int *)(param_1 + 0x54) != 6)) {` |
| FUN_00028fc4 | 0x28fc4 | 56 | read | `if (((_DAT_8004d6fa == 2) && (*(int *)(param_1 + 0x54) == 6)) &&` |
| FUN_000296e8 | 0x296e8 | 22 | read | `piVar6 = (int *)(iVar3 + 0x58);` |
| FUN_00029910 | 0x29910 | 24 | read | `iVar4 = *(int *)(uVar2 * 4 + iVar3 + 0x58);` |
| FUN_00029c24 | 0x29c24 | 77 | write | `*(uint *)(param_1 + 0x58 + uVar7 * 4) = iVar3 + (uint)*puVar9 * 0x18;` |
| FUN_0002a2d0 | 0x2a2d0 | 52 | read | `iVar6 = iVar6 + 0x4c;` |
| FUN_0002a498 | 0x2a498 | 45 | read | `iVar1 = func_0x00072348(*(undefined4 *)(param_1 + 0x58 + iVar1));` |
| FUN_0002a5f4 | 0x2a5f4 | 18 | read | `func_0x000725a8(*(undefined4 *)(param_1 + 0x58 + iVar1));` |
| FUN_0002ad60 | 0x2ad60 | 19 | read | `iVar4 = *(int *)(*(int *)(param_1 + iVar2 + 0x58) + 4);` |
| FUN_0002ad60 | 0x2ad60 | 20 | read | `iVar2 = *(int *)(iVar4 + 0x54);` |
| FUN_0002b2b8 | 0x2b2b8 | 80 | read | `piVar7 = (int *)(uVar6 * 4 + 0x58 + param_1);` |
| FUN_0002b7d0 | 0x2b7d0 | 29 | read | `if (*(int *)(*(int *)(*(int *)(param_1 + 0x58) + 4) + 0x54) == 5) {` |
| FUN_0002b7d0 | 0x2b7d0 | 38 | read | `iVar7 = *(int *)(*(int *)(param_1 + 0x58 + uVar3 * 4) + 4);` |
| FUN_0002b7d0 | 0x2b7d0 | 40 | read | `} while (*(int *)(iVar7 + 0x54) != 5);` |
| FUN_0002c4b0 | 0x2c4b0 | 30 | write | `*(undefined4 *)(param_1 + 0x50) = param_2[3];` |
| FUN_0002c4b0 | 0x2c4b0 | 75 | read | `if (*(int *)(param_1 + 0x50) != 0) {` |
| FUN_0002c4b0 | 0x2c4b0 | 81 | read | `} while (uVar8 < *(uint *)(param_1 + 0x50));` |
| FUN_0002c964 | 0x2c964 | 116 | read | `if ((((uVar4 & 1) != 0) && (*(int *)(iVar7 + 0x54) != 0)) && (*(int *)(iVar7 + 0x10) == 0)) {` |
| FUN_0002da08 | 0x2da08 | 27 | read | `if (*(int *)(param_1 + 0x50) == 0) {` |
| FUN_0002dbc0 | 0x2dbc0 | 87 | read | `uVar7 = *(uint *)(param_1 + 0x50);` |
| FUN_0002f988 | 0x2f988 | 72 | write | `*(short *)(param_1 + 0x584) = (short)uVar5 + *(short *)(param_1 + 8);` |
| FUN_0002f988 | 0x2f988 | 73 | write | `*(short *)(param_1 + 0x586) = (short)uVar6 + *(short *)(param_1 + 10);` |
| FUN_0002f988 | 0x2f988 | 74 | write | `*(short *)(param_1 + 0x588) = (short)uVar7 + *(short *)(param_1 + 0xc);` |
| FUN_0002f988 | 0x2f988 | 96 | write | `*(short *)(param_1 + 0x58c) = (short)uVar5 + *(short *)(param_1 + 8);` |
| FUN_0002f988 | 0x2f988 | 97 | write | `*(short *)(param_1 + 0x58e) = (short)uVar6 + *(short *)(param_1 + 10);` |
| FUN_0002ffac | 0x2ffac | 185 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) & 0xffffffef;` |
| FUN_0002ffac | 0x2ffac | 194 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) \| 0x10;` |
| FUN_0002ffac | 0x2ffac | 201 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) \| 0x10;` |
| FUN_00030be8 | 0x30be8 | 42 | read | `((*(uint *)(iVar2 + 0x50) & 0x20000) != 0)) {` |
| FUN_00031048 | 0x31048 | 32 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x4c))` |
| FUN_00031048 | 0x31048 | 50 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x4c))` |
| FUN_00031048 | 0x31048 | 76 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x4c))` |
| FUN_00031480 | 0x31480 | 10 | read | `(((*(uint *)(param_2 + 0x50) & 4) == 0 &&` |
| FUN_00031b38 | 0x31b38 | 64 | read | `iVar7 = iVar2 + 0x54;` |
| FUN_00031b38 | 0x31b38 | 96 | read | `iVar11 = FUN_00023358(iVar2 + 0x5a);` |
| FUN_00031b38 | 0x31b38 | 106 | read | `iVar2 = FUN_00023358(iVar2 + 0x5a);` |
| FUN_00035cc0 | 0x35cc0 | 134 | read | `if ((*(uint *)(unaff_s2 + 0x50) & 0x20000) == 0) {` |
| FUN_00035cc0 | 0x35cc0 | 136 | read | `*(uint *)(unaff_s2 + 0x50) = *(uint *)(unaff_s2 + 0x50) \| 0x20000;` |
| FUN_00036c34 | 0x36c34 | 60 | read | `iVar12 = *(int *)(iVar12 + 0x58)) {` |
| FUN_00039dac | 0x39dac | 14 | write | `*(undefined4 *)(param_1 + 0x520) = 0;` |
| FUN_00039dac | 0x39dac | 28 | write | `*(undefined4 *)(param_1 + 0x5ac) = 0;` |
| FUN_00039dac | 0x39dac | 31 | write | `*(int *)(param_1 + 0x5a8) = param_1;` |
| FUN_0003a25c | 0x3a25c | 19 | read | `puVar2 = (undefined4 *)(param_1 + 0x544);` |
| FUN_0003a25c | 0x3a25c | 35 | write | `*(undefined4 *)(param_1 + 0x524) = *(undefined4 *)(param_1 + 0x39c);` |
| FUN_0003a25c | 0x3a25c | 36 | write | `*(undefined4 *)(param_1 + 0x528) = *(undefined4 *)(param_1 + 0x3a0);` |
| FUN_0003a25c | 0x3a25c | 37 | write | `*(undefined4 *)(param_1 + 0x52c) = *(undefined4 *)(param_1 + 0x3a4);` |
| FUN_0003a25c | 0x3a25c | 42 | write | `*(undefined4 *)(param_1 + 0x540) = *(undefined4 *)(param_1 + 0x3b8);` |
| FUN_0003a7d0 | 0x3a7d0 | 19 | read | `iVar1 = *(int *)(param_1 + 0x520);` |
| FUN_0003b264 | 0x3b264 | 142 | read | `if (((*(uint *)(iVar10 + 0x50) & 4) != 0) \|\| ((*(uint *)(iVar10 + 0x50) & 1) != 0)) {` |
| FUN_0003cdf0 | 0x3cdf0 | 15 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003cdf0 | 0x3cdf0 | 16 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) & 0xfffffffe;` |
| FUN_0003cdf0 | 0x3cdf0 | 18 | read | `*(uint *)(iVar1 + 0x50) = *(uint *)(iVar1 + 0x50) & 0xfffffdff;` |
| FUN_0003cdf0 | 0x3cdf0 | 20 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) = *(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x10` |
| FUN_0003cee4 | 0x3cee4 | 45 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) & 0xffffffef;` |
| FUN_0003d0e8 | 0x3d0e8 | 45 | read | `(iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x58),*(undefined2 *)(iVar6 + 0xb8))` |
| FUN_0003d0e8 | 0x3d0e8 | 48 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) \| 0x10;` |
| FUN_0003dd3c | 0x3dd3c | 47 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 1;` |
| FUN_0003df28 | 0x3df28 | 55 | read | `*(uint *)(iVar8 + 0x50) = *(uint *)(iVar8 + 0x50) & 0xffffffef;` |
| FUN_0003df28 | 0x3df28 | 56 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003df28 | 0x3df28 | 57 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x200;` |
| FUN_0003df28 | 0x3df28 | 97 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffffe;` |
| FUN_0003df28 | 0x3df28 | 104 | read | `*(uint *)(iVar8 + 0x50) = *(uint *)(iVar8 + 0x50) & 0xffffffef;` |
| FUN_0003df28 | 0x3df28 | 105 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003df28 | 0x3df28 | 106 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x200;` |
| FUN_0003e810 | 0x3e810 | 16 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) \| 1;` |
| FUN_0003e810 | 0x3e810 | 43 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) & 0xfffffdff;` |
| FUN_0003e810 | 0x3e810 | 45 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003e810 | 0x3e810 | 46 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x10;` |
| FUN_0003e810 | 0x3e810 | 47 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003e810 | 0x3e810 | 48 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) & 0xfffffffe;` |
| FUN_0003e838 | 0x3e838 | 19 | read | `*(uint *)(in_v1 + 0x50) = in_v0 \| 1;` |
| FUN_0003e838 | 0x3e838 | 48 | read | `*(uint *)(iVar1 + 0x50) = *(uint *)(iVar1 + 0x50) & 0xfffffdff;` |
| FUN_0003e838 | 0x3e838 | 50 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) =` |
| FUN_0003e838 | 0x3e838 | 51 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) \| 0x10;` |
| FUN_0003e838 | 0x3e838 | 52 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) =` |
| FUN_0003e838 | 0x3e838 | 53 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) & 0xfffffffe;` |
| FUN_0003f1dc | 0x3f1dc | 21 | read | `((uVar3 == 0x57 \|\| (*(int *)(iVar2 + 0x58) == 0))))));` |
| FUN_0003f1dc | 0x3f1dc | 28 | read | `*(short *)(*(int *)(iVar2 + 0x48) + 6) = *(short *)(iVar2 + 0x4e) + (short)_DAT_800bc944;` |
| FUN_0003f1dc | 0x3f1dc | 34 | read | `} while (0xd < *(ushort *)(iVar2 + 0x4e));` |
| FUN_0003f1dc | 0x3f1dc | 37 | read | `(**(code **)((uint)*(ushort *)(iVar2 + 0x4e) * 4 + -0x7ff38cec))();` |
| FUN_0003fbb0 | 0x3fbb0 | 179 | read | `*(undefined4 *)(_DAT_8011a3dc + 0x58) = 0;` |
| FUN_0003fbb0 | 0x3fbb0 | 183 | read | `*(undefined4 *)(_DAT_8011a3e8 + 0x58) = 0;` |
| FUN_0003fbb0 | 0x3fbb0 | 188 | read | `*(undefined4 *)(*piVar8 + 0x58) = 0;` |
| FUN_000401ec | 0x401ec | 11 | read | `*(undefined4 *)(_DAT_8011a3dc + 0x58) = 0;` |
| FUN_000401ec | 0x401ec | 15 | read | `*(undefined4 *)(_DAT_8011a3e8 + 0x58) = 0;` |
| FUN_000401ec | 0x401ec | 20 | read | `*(undefined4 *)(*piVar1 + 0x58) = 0;` |
| FUN_000402e0 | 0x402e0 | 34 | read | `*(undefined2 *)(param_3 + 0x3c) = *(undefined2 *)(param_4 + 0x4c);` |
| FUN_000402e0 | 0x402e0 | 35 | read | `*(undefined2 *)(param_3 + 0x3e) = *(undefined2 *)(param_4 + 0x50);` |
| FUN_000402e0 | 0x402e0 | 37 | read | `if (*(int *)(param_4 + 0x54) != 0) {` |
| FUN_000402e0 | 0x402e0 | 41 | read | `*(short *)(param_3 + 0x40) = *(short *)(param_4 + 0x58) << 6;` |
| FUN_000402e0 | 0x402e0 | 42 | read | `*(undefined2 *)(param_3 + 0x50) = *(undefined2 *)(param_4 + 0x5c);` |
| FUN_000402e0 | 0x402e0 | 43 | read | `*(undefined4 *)(param_3 + 0x54) = *(undefined4 *)(param_4 + 0x60);` |
| FUN_0004033c | 0x4033c | 25 | read | `*(undefined2 *)(param_3 + 0x3c) = *(undefined2 *)(param_4 + 0x4c);` |
| FUN_0004033c | 0x4033c | 26 | read | `*(undefined2 *)(param_3 + 0x3e) = *(undefined2 *)(param_4 + 0x50);` |
| FUN_0004033c | 0x4033c | 28 | read | `if (*(int *)(param_4 + 0x54) != 0) {` |
| FUN_0004033c | 0x4033c | 32 | read | `*(short *)(param_3 + 0x40) = *(short *)(param_4 + 0x58) << 6;` |
| FUN_0004033c | 0x4033c | 33 | read | `*(undefined2 *)(param_3 + 0x50) = *(undefined2 *)(param_4 + 0x5c);` |
| FUN_0004033c | 0x4033c | 34 | read | `*(undefined4 *)(param_3 + 0x54) = *(undefined4 *)(param_4 + 0x60);` |
| FUN_0004050c | 0x4050c | 19 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 0x18;` |
| FUN_00040a4c | 0x40a4c | 93 | read | `(iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x58),uVar3);` |
| FUN_00040a4c | 0x40a4c | 98 | read | `(**(code **)(iVar6 + 0x5c))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar6 + 0x58),uVar3);` |
| FUN_00040a4c | 0x40a4c | 111 | read | `(**(code **)(iVar6 + 0x4c))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar6 + 0x48),999);` |
| FUN_00040a98 | 0x40a98 | 86 | read | `(iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x58),uVar3);` |
| FUN_00040a98 | 0x40a98 | 96 | read | `(*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x58),uVar3);` |
| FUN_00040a98 | 0x40a98 | 109 | read | `(**(code **)(iVar6 + 0x4c))` |
| FUN_000412d8 | 0x412d8 | 16 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 0x10;` |
| FUN_000412d8 | 0x412d8 | 89 | read | `*(short *)(*(int *)(param_1 + 0xc0) + 0x4c);` |
| FUN_000412d8 | 0x412d8 | 100 | read | `(int)*(short *)(*(int *)(param_1 + 0xc0) + 0x4c))) {` |
| FUN_000412d8 | 0x412d8 | 125 | read | `if ((*(uint *)(*(int *)(param_1 + 0xd4) + 0x50) & 0x400) != 0) {` |
| FUN_000412d8 | 0x412d8 | 150 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;` |
| FUN_00041a48 | 0x41a48 | 21 | read | `iVar4 = iVar2 + 0x54;` |
| FUN_00041ba4 | 0x41ba4 | 44 | read | `iVar3 = FUN_00023210(0x800c7840,iVar5 + 0x54,6);` |
| FUN_00041ba4 | 0x41ba4 | 71 | read | `iVar3 = FUN_00023210(0x800c7848,iVar5 + 0x54,6);` |
| FUN_00041ba4 | 0x41ba4 | 100 | read | `iVar4 = FUN_00023210(0x800c7850,iVar10 + 0x54,4);` |
| FUN_00041ba4 | 0x41ba4 | 108 | read | `iVar4 = FUN_00023210(0x800c7858,iVar10 + 0x54,4);` |
| FUN_00041edc | 0x41edc | 18 | read | `iVar3 = FUN_00023110(0x800c7860,iVar4 + 0x54);` |
| FUN_00041edc | 0x41edc | 24 | read | `iVar3 = FUN_00023110(0x800c786c,iVar4 + 0x54);` |
| FUN_00043748 | 0x43748 | 40 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 53 | read | `if (((cVar1 == '\x06') && ((*(uint *)(param_1 + 0x50) & 4) != 0)) &&` |
| FUN_000438fc | 0x438fc | 69 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 96 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 101 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 122 | read | `(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58));` |
| FUN_000438fc | 0x438fc | 142 | read | `if ((*(uint *)(param_1 + 0x50) & 4) == 0) {` |
| FUN_000438fc | 0x438fc | 161 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 284 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;` |
| FUN_00043a94 | 0x43a94 | 9 | read | `*(uint *)(unaff_s3 + 0x50) = *(uint *)(unaff_s3 + 0x50) & 0xffffffef;` |
| FUN_000443b8 | 0x443b8 | 82 | read | `param_2 = *(int *)(param_2 + 0x58);` |
| FUN_00044a14 | 0x44a14 | 21 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00044a14 | 0x44a14 | 148 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffdff \| 0x40;` |
| FUN_00044f80 | 0x44f80 | 56 | read | `if ((*(uint *)(param_1 + 0x50) & 4) != 0) {` |
| FUN_00044f80 | 0x44f80 | 59 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00044f80 | 0x44f80 | 85 | read | `(iVar12 = -(int)*(short *)(param_1 + 0x3e), (*(uint *)(param_1 + 0x50) & 4) == 0)) {` |
| FUN_00045a00 | 0x45a00 | 14 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00045a80 | 0x45a80 | 33 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00045a80 | 0x45a80 | 52 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046024 | 0x46024 | 38 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046024 | 0x46024 | 40 | read | `if (((*(uint *)(param_1 + 0x50) & 4) == 0) &&` |
| FUN_00046024 | 0x46024 | 43 | read | `if ((*(uint *)(param_1 + 0x50) & 0x20) != 0) {` |
| FUN_00046024 | 0x46024 | 144 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046498 | 0x46498 | 10 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046498 | 0x46498 | 13 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000475dc | 0x475dc | 159 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;` |
| FUN_0004a058 | 0x4a058 | 22 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000153a0 | 0x153a0 | 70 | read | `if ((*(char *)(param_1 + 0x50) != '\0') && (uVar6 = 0, *(char *)(param_1 + 0x37) == '\0')) {` |
| FUN_00017510 | 0x17510 | 31 | write | `*(undefined1 *)(param_1 + 0x58) = 1;` |
| FUN_00017a6c | 0x17a6c | 75 | read | `(*(char *)(param_1 + 0x50) == '\0')) \|\| (*(char *)(param_1 + 0xe8) != cVar1)) {` |
| FUN_00017e54 | 0x17e54 | 62 | write | `*(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1;` |
| FUN_00002f34 | 0x2f34 | 96 | read | `(iVar9,uVar11 + *(int *)(uVar11 + 0x40) * 8 + 0x4c);` |
| FUN_00003a64 | 0x3a64 | 69 | read | `if ((*(char *)(iVar3 + 0x50) != '\0') && (iVar4 = 0, *(char *)(iVar3 + 0x36) == '\0')) {` |
| FUN_00008528 | 0x8528 | 129 | read | `iVar4 = *(int *)(iVar2 + 0x50) * 3;` |
| FUN_00008528 | 0x8528 | 134 | read | `*(short *)(*(int *)(iVar3 + 0xc) + 2) = (short)*(undefined4 *)(iVar2 + 0x54);` |
| FUN_00008528 | 0x8528 | 137 | read | `FUN_00031978(iVar4,iVar3,*(undefined4 *)(iVar2 + 0x48),*(undefined4 *)(iVar2 + 0x4c));` |
| FUN_000090e0 | 0x90e0 | 58 | read | `iVar5 = *(int *)(iVar4 + 0x50) * 3;` |
| FUN_000090e0 | 0x90e0 | 63 | read | `*(short *)(*(int *)(iVar3 + 0xc) + 2) = (short)*(undefined4 *)(iVar4 + 0x54);` |
| FUN_000090e0 | 0x90e0 | 66 | read | `FUN_00031978(iVar5,iVar3,*(undefined4 *)(iVar4 + 0x48),*(undefined4 *)(iVar4 + 0x4c));` |
| FUN_00009b18 | 0x9b18 | 16 | read | `iVar3 = iVar3 + 0x58;` |
| FUN_0000a234 | 0xa234 | 24 | read | `iVar3 = *param_1 + 0x4c;` |
| FUN_0000af3c | 0xaf3c | 28 | read | `FUN_0001e7b4(param_3 + 0x54,param_2,auStack_20);` |
| FUN_0000d7d8 | 0xd7d8 | 11 | read | `iVar2 = iVar1 - *(short *)(iVar3 + 0x54);` |
| FUN_0000d7d8 | 0xd7d8 | 13 | read | `if (iVar1 <= *(short *)(iVar3 + 0x54)) {` |
| FUN_0000d7d8 | 0xd7d8 | 19 | read | `} while (iVar1 < *(short *)(iVar3 + 0x54));` |
| FUN_0000d7d8 | 0xd7d8 | 20 | read | `*(int *)(iVar3 + 0x90) = iVar1 - *(short *)(iVar3 + 0x54);` |
| FUN_0000d7d8 | 0xd7d8 | 24 | read | `if (0 < *(short *)(iVar3 + 0x52)) {` |
| FUN_0000d7d8 | 0xd7d8 | 25 | read | `*(short *)(iVar3 + 0x52) = *(short *)(iVar3 + 0x52) + -1;` |
| FUN_0000d7d8 | 0xd7d8 | 29 | read | `if (*(short *)(iVar3 + 0x52) == 0) {` |
| FUN_0000d7d8 | 0xd7d8 | 30 | read | `*(undefined2 *)(iVar3 + 0x52) = *(undefined2 *)(iVar3 + 0x54);` |
| FUN_0000e5f0 | 0xe5f0 | 23 | read | `*(undefined2 *)((int)puVar1 + 0x5a),1);` |
| FUN_0000eb10 | 0xeb10 | 38 | read | `*(undefined2 *)(puVar4 + 0x15) = *(undefined2 *)((int)puVar4 + 0x56);` |
| FUN_0000ef68 | 0xef68 | 11 | read | `*(undefined2 *)(iVar1 + 0x58) = param_3;` |
| FUN_0000ef68 | 0xef68 | 12 | read | `*(undefined2 *)(iVar1 + 0x5a) = param_4;` |
| FUN_0000eff8 | 0xeff8 | 11 | read | `*(undefined2 *)(iVar1 + 0x58) = param_2;` |
| FUN_0000eff8 | 0xeff8 | 12 | read | `*(undefined2 *)(iVar1 + 0x5a) = param_3;` |
| FUN_0000f060 | 0xf060 | 11 | read | `*(undefined2 *)(iVar1 + 0x58) = param_3;` |
| FUN_0000f060 | 0xf060 | 12 | read | `*(undefined2 *)(iVar1 + 0x5a) = param_4;` |
| FUN_00010944 | 0x10944 | 23 | read | `uVar7 = (uVar6 * *(ushort *)(iVar5 + 0x58)) / 0x7f;` |
| FUN_00010944 | 0x10944 | 24 | read | `uVar6 = (uVar6 * *(ushort *)(iVar5 + 0x5a)) / 0x7f;` |
| FUN_000114a4 | 0x114a4 | 19 | read | `*(undefined2 *)(iVar8 + 0x58) = param_2;` |
| FUN_000114a4 | 0x114a4 | 20 | read | `*(undefined2 *)(iVar8 + 0x5a) = param_3;` |
| FUN_000114a4 | 0x114a4 | 21 | read | `if (0x7e < *(ushort *)(iVar8 + 0x58)) {` |
| FUN_000114a4 | 0x114a4 | 22 | read | `*(undefined2 *)(iVar8 + 0x58) = 0x7f;` |
| FUN_000114a4 | 0x114a4 | 24 | read | `if (0x7e < *(ushort *)(iVar8 + 0x5a)) {` |
| FUN_000114a4 | 0x114a4 | 25 | read | `*(undefined2 *)(iVar8 + 0x5a) = 0x7f;` |
| FUN_000114a4 | 0x114a4 | 43 | read | `uVar5 = (uVar6 * *(ushort *)(iVar8 + 0x58)) / 0x7f;` |
| FUN_000114a4 | 0x114a4 | 45 | read | `uVar6 = (uVar6 * *(ushort *)(iVar8 + 0x5a)) / 0x7f;` |
| FUN_0001a348 | 0x1a348 | 29 | read | `*(undefined2 *)(unaff_s0 + 0x54) = 0;` |
| FUN_0001a348 | 0x1a348 | 30 | read | `*(undefined2 *)(unaff_s0 + 0x4c) = 0;` |
| FUN_0001a348 | 0x1a348 | 36 | read | `*(undefined2 *)(unaff_s0 + 0x58) = uVar2;` |
| FUN_0001a348 | 0x1a348 | 37 | read | `*(undefined2 *)(unaff_s0 + 0x50) = uVar2;` |
| FUN_0001a348 | 0x1a348 | 38 | read | `*(undefined2 *)(unaff_s0 + 0x5a) = 0xf0;` |
| FUN_0001a348 | 0x1a348 | 39 | read | `*(undefined2 *)(unaff_s0 + 0x52) = 0xf0;` |
| FUN_0001a348 | 0x1a348 | 40 | read | `*(undefined2 *)(unaff_s0 + 0x4e) = 0;` |
| FUN_0001a348 | 0x1a348 | 41 | read | `*(undefined2 *)(unaff_s0 + 0x56) = 0xf0;` |
| FUN_0001a3b0 | 0x1a3b0 | 16 | read | `*(undefined2 *)(unaff_s0 + 0x58) = uVar2;` |
| FUN_0001a3b0 | 0x1a3b0 | 17 | read | `*(undefined2 *)(unaff_s0 + 0x50) = uVar2;` |
| FUN_0001a3b0 | 0x1a3b0 | 18 | read | `*(undefined2 *)(unaff_s0 + 0x5a) = 0xf0;` |
| FUN_0001a3b0 | 0x1a3b0 | 19 | read | `*(undefined2 *)(unaff_s0 + 0x52) = 0xf0;` |
| FUN_0001a3b0 | 0x1a3b0 | 20 | read | `*(undefined2 *)(unaff_s0 + 0x4e) = 0;` |
| FUN_0001a3b0 | 0x1a3b0 | 21 | read | `*(undefined2 *)(unaff_s0 + 0x56) = 0xf0;` |
| FUN_0001a674 | 0x1a674 | 20 | read | `*(undefined2 *)(unaff_s0 + 0x58) = uVar1;` |
| FUN_0001a674 | 0x1a674 | 21 | read | `*(undefined2 *)(unaff_s0 + 0x50) = uVar1;` |
| FUN_0001a674 | 0x1a674 | 24 | read | `*(undefined2 *)(unaff_s0 + 0x5a) = uVar1;` |
| FUN_0001a674 | 0x1a674 | 25 | read | `*(undefined2 *)(unaff_s0 + 0x52) = uVar1;` |
| FUN_0001a804 | 0x1a804 | 28 | read | `(iVar3,param_1 + *(int *)(param_1 + 0x40) * 8 + 0x4c);` |
| FUN_0001a804 | 0x1a804 | 33 | read | `FUN_00018878(auStack_14,(int)*(short *)(iVar4 + 0x4c),(int)*(short *)(iVar4 + 0x4e),` |
| FUN_0001aaec | 0x1aaec | 14 | read | `*(undefined2 *)((int)unaff_s0 + (param_1 - unaff_s0[0x10]) * 8 + 0x4e);` |
| FUN_0001abfc | 0x1abfc | 11 | read | `(int)*(short *)(iVar1 + 0x4c) + (int)*(short *)(iVar1 + 0x50)) {` |
| FUN_0001b220 | 0x1b220 | 69 | read | `if ((*(char *)(param_1 + 0x50) != '\0') && (uVar6 = 0, *(char *)(param_1 + 0x36) == '\0')) {` |
| FUN_0001b264 | 0x1b264 | 61 | read | `if ((*(char *)(unaff_s0 + 0x50) != '\0') && (uVar4 = 0, *(char *)(unaff_s0 + 0x36) == '\0')) {` |
| FUN_0001b364 | 0x1b364 | 36 | read | `if ((*(char *)(unaff_s0 + 0x50) != '\0') && (uVar3 = 0, *(char *)(unaff_s0 + 0x36) == '\0')) {` |
| FUN_0001c2b4 | 0x1c2b4 | 15 | write | `*(undefined1 *)(param_1 + 0x52) = param_3;` |
| FUN_0001cfcc | 0x1cfcc | 29 | write | `*(undefined1 *)(param_1 + 0x58) = 1;` |
| FUN_0001d504 | 0x1d504 | 32 | read | `(*(char *)(param_1 + 0x50) == '\0')))) \|\|` |
| FUN_0001d7b8 | 0x1d7b8 | 10 | write | `*(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1;` |
| FUN_00021974 | 0x21974 | 13 | read | `*(undefined4 *)(unaff_s0 + 0x50) = 0;` |
| FUN_00021974 | 0x21974 | 14 | read | `*(undefined4 *)(unaff_s0 + 0x4c) = 0;` |
| FUN_00021b4c | 0x21b4c | 9 | read | `*(undefined4 *)(unaff_s0 + 0x50) = in_v0;` |
| FUN_000233dc | 0x233dc | 9 | read | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x8c),param_2 + 0x5464);` |
| FUN_00023d74 | 0x23d74 | 36 | read | `FUN_0001a4a0(&local_8,0x23a,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 48 | read | `FUN_0001a4a0(&local_8,0x251,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 60 | read | `FUN_0001a4a0(&local_8,0x25d,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 72 | read | `FUN_0001a4a0(&local_8,0x26f,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 84 | read | `FUN_0001a4a0(&local_8,0x27b,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 96 | read | `FUN_0001a4a0(&local_8,0x28c,iVar1 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 21 | read | `FUN_0001a4a0(param_1,0x25d,in_hi * 2 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 34 | read | `FUN_0001a4a0(&stack0x00000020,0x26f,iVar1 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 46 | read | `FUN_0001a4a0(&stack0x00000020,0x27b,iVar1 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 58 | read | `FUN_0001a4a0(&stack0x00000020,0x28c,iVar1 + 0x58);` |
| FUN_000240a0 | 0x240a0 | 24 | read | `FUN_0001a4a0(&stack0x00000020,0x28c,iVar1 + 0x58);` |
| FUN_00000a2c | 0xa2c | 28 | read | `func_0x0002080c(iVar1 + *(int *)(iVar1 + 0x50));` |
| FUN_00001f4c | 0x1f4c | 28 | read | `func_0x000cce8c(0x106,0,sVar1 + 0xc0,sVar2 + 0x50,iVar3,0,0,0);` |
| FUN_00001f4c | 0x1f4c | 29 | read | `func_0x000cce8c(0x108,0,sVar5,sVar2 + 0x50,iVar3,0,0,0);` |
| FUN_00001f4c | 0x1f4c | 34 | read | `func_0x000cce8c(0x107,0,sVar4,sVar2 + 0x50,iVar3,0,0,0);` |
| FUN_00004328 | 0x4328 | 313 | read | `func_0x000cce8c(0x2b,0,iVar22 + 200U & 0xffff,iVar7 + 0x54U & 0xffff,0x808080,0,0,0);` |
| FUN_00005954 | 0x5954 | 405 | read | `func_0x000cce8c(0xfe,1,*psVar21 + -0x38,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,0x808080,0,0,` |
| FUN_00005954 | 0x5954 | 407 | read | `func_0x000cce8c(0xff,1,*psVar21 + 0x88,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,0x808080,0,0,0` |
| FUN_00005954 | 0x5954 | 409 | read | `func_0x000cce8c(0x100,0,*psVar21 + -0x38,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,` |
| FUN_00005954 | 0x5954 | 411 | read | `func_0x000cce8c(0x101,0,*psVar21 + 0x88,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,0x808080,0,0,` |
| FUN_00006f28 | 0x6f28 | 13 | read | `,(int)((*(ushort *)(&DAT_800cf4de + iVar1) + 0x50) * 0x10000) >> 0x10,` |
| FUN_00002724 | 0x2724 | 68 | read | `if ((((iVar9 == 0) \|\| (*(int *)(iVar9 + 0x48) != 3)) \|\| (*(int *)(iVar9 + 0x50) != 0)) \|\|` |
| FUN_00003f60 | 0x3f60 | 28 | read | `func_0x000c9b8c(iVar2 + *(int *)(iVar2 + 0x50));` |
| FUN_00004fcc | 0x4fcc | 13 | write | `*(undefined2 **)(param_1 + 0x4c) = param_2;` |
| FUN_00004fcc | 0x4fcc | 42 | write | `*(undefined4 *)(param_1 + 0x50) = 0;` |
| FUN_00004fcc | 0x4fcc | 43 | read | `iVar4 = *(int *)((uint)**(ushort **)(param_1 + 0x4c) * 4 + -0x7ff30500);` |
| FUN_000056dc | 0x56dc | 11 | read | `*(short *)(*(int *)(param_1 + 0x4c) + 2),(undefined2)local_10[0]) &` |
| FUN_000057cc | 0x57cc | 26 | read | `(*(ushort **)(param_1 + 0x4c))[1],(undefined2)local_30) & 0xfffffff;` |
| FUN_000057cc | 0x57cc | 31 | read | `(*(int *)((uint)**(ushort **)(param_1 + 0x4c) * 4 + -0x7ff30500) != 0)) {` |
| FUN_000059f4 | 0x59f4 | 19 | read | `iVar3 = iVar3 + 0x54;` |
| FUN_00005de4 | 0x5de4 | 7 | read | `puVar1 = *(undefined4 **)(param_1 + 0x50);` |
| FUN_00005de4 | 0x5de4 | 16 | write | `*(undefined4 *)(param_1 + 0x50) = 0;` |
| FUN_00005e70 | 0x5e70 | 27 | write | `*(int *)(param_1 + 0x4c) = param_2;` |
| FUN_00005e70 | 0x5e70 | 49 | write | `*(undefined4 *)(param_1 + 0x50) = 0;` |
| FUN_00005e70 | 0x5e70 | 58 | write | `*(undefined4 *)(param_1 + 0x54) = uVar4;` |
| FUN_00005e70 | 0x5e70 | 82 | write | `*(undefined4 *)(param_1 + 0x54) = uVar4;` |
| FUN_000063c4 | 0x63c4 | 17 | read | `psVar1 = *(short **)(param_1 + 0x4c);` |
| FUN_000063c4 | 0x63c4 | 45 | read | `if (*(int **)(param_1 + 0x50) != (int *)0x0) {` |
| FUN_000063c4 | 0x63c4 | 46 | read | `func_0x00098a7c(*(undefined4 *)(**(int **)(param_1 + 0x50) + 0x24),puVar3,0,2,` |
| FUN_000063c4 | 0x63c4 | 51 | read | `func_0x0009af10(puVar3,param_1 + 0x38,*(undefined4 *)(param_1 + 0x54));` |
| FUN_0000652c | 0x652c | 51 | read | `uVar1 = *(ushort *)(*(int *)(param_1 + 0x4c) + 0x24);` |
| FUN_0000652c | 0x652c | 55 | read | `*(short *)(*(int *)(param_1 + 0x44) + 10) + *(short *)(*(int *)(param_1 + 0x4c) + 0x24);` |
| FUN_00006ec4 | 0x6ec4 | 19 | read | `iVar3 = iVar3 + 0x58;` |
| FUN_000072b4 | 0x72b4 | 40 | read | `*(undefined2 *)((uint)*(ushort *)(param_1 + 0x1fe) * 0x2c + param_1 + 0x5a);` |
| FUN_00008198 | 0x8198 | 71 | read | `if (*(short *)(iVar1 * 0x10 + uVar5 * 0xc + param_1 + 0x5a) != *(short *)(param_1 + 0x202)) {` |
| FUN_00008198 | 0x8198 | 83 | read | `if (*(short *)(uVar2 * 0x2c + param_1 + 0x5a) != *(short *)(param_1 + 0x202)) {` |
| FUN_00008198 | 0x8198 | 92 | read | `} while (*(short *)(uVar2 * 0x2c + param_1 + 0x5a) != *(short *)(param_1 + 0x202));` |
| FUN_00009dfc | 0x9dfc | 28 | read | `func_0x0002080c(iVar1 + *(int *)(iVar1 + 0x50));` |
| FUN_00001998 | 0x1998 | 40 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) \| 0x10;` |
| FUN_00001998 | 0x1998 | 77 | read | `*(uint *)(_DAT_800bca78 + 0x50) = *(uint *)(_DAT_800bca78 + 0x50) & 0xffffffef;` |
| FUN_000010b8 | 0x10b8 | 143 | read | `iVar4 = *(int *)(iVar7 + 0x54);` |
| FUN_000010b8 | 0x10b8 | 150 | read | `iVar4 = *(int *)(iVar7 + 0x54);` |
| FUN_000010b8 | 0x10b8 | 184 | read | `if (((*(int *)(iVar3 + 0x54) != 0) && ((*(uint *)(iVar3 + 0xb8) & 0xb0) == 0)) &&` |
| FUN_00001c84 | 0x1c84 | 325 | read | `(**(code **)(*(int *)(iVar10 + 4) + 0x4c))` |
| FUN_00001c84 | 0x1c84 | 413 | read | `*(undefined2 *)(iVar10 + 0x4c) = 30000;` |
| FUN_00001c84 | 0x1c84 | 492 | read | `(*(int *)(iVar8 + 0x54) == 0)) {` |
| FUN_00001c84 | 0x1c84 | 589 | read | `*(uint *)(iVar10 + 0x50) = *(uint *)(iVar10 + 0x50) & 0xffffffef;` |
| FUN_00001c84 | 0x1c84 | 592 | read | `*(uint *)(iVar10 + 0x50) = *(uint *)(iVar10 + 0x50) \| 0x10;` |
| FUN_00001c84 | 0x1c84 | 620 | read | `(iVar10 + *(short *)(*(int *)(iVar10 + 4) + 0x58),` |
| FUN_00001c84 | 0x1c84 | 632 | read | `(iVar18 + *(short *)(*(int *)(iVar8 + -0x7feedcf0) + 0x58),` |
| FUN_00005e14 | 0x5e14 | 7 | read | `uVar1 = func_0x0006ea78(*(undefined4 *)(*(int *)(param_2 + 8) + 0x54),1);` |
| FUN_00005e50 | 0x5e50 | 15 | read | `uVar1 = func_0x0006c768(*(undefined4 *)(*(int *)(param_2 + 8) + 0x54),local_40);` |
| FUN_00006240 | 0x6240 | 5 | read | `func_0x000c994c(param_1,*(undefined4 *)(*(int *)(*(int *)(param_2 + 8) + 0x318) + 0x54));` |
| FUN_00006f90 | 0x6f90 | 11 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_00007084 | 0x7084 | 11 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_000071ec | 0x71ec | 12 | read | `(((((*(uint *)(iVar2 + 0xb8) & 8) == 0 && ((*(uint *)(iVar2 + 0x50) & 4) == 0)) &&` |
| FUN_00007710 | 0x7710 | 17 | read | `uVar2 = *(undefined2 *)(*(int *)(iVar1 + 0xc0) + 0x50);` |
| FUN_00007784 | 0x7784 | 17 | read | `uVar3 = *(undefined4 *)(*(int *)(iVar1 + 0xc0) + 0x54);` |
| FUN_00007a74 | 0x7a74 | 7 | read | `uVar1 = func_0x0006e55c(*(undefined4 *)(*(int *)(param_2 + 8) + 0x54));` |
| FUN_00007f10 | 0x7f10 | 17 | read | `} while ((*(int *)(aiStack_18[uVar2] + 0x54) != 6) \|\|` |
| FUN_0000852c | 0x852c | 16 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_00008610 | 0x8610 | 16 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_00008704 | 0x8704 | 15 | read | `uVar4 = *(uint *)(iVar5 + 0x58);` |
| FUN_00008704 | 0x8704 | 25 | read | `if (*(uint *)(iVar5 + 0x54) == 0) {` |
| FUN_00008704 | 0x8704 | 28 | read | `return uVar1 / *(uint *)(iVar5 + 0x54);` |
| FUN_0000888c | 0x888c | 12 | read | `if ((*(int *)(iVar2 + 0x300) == 2) && ((*(uint *)(iVar2 + 0x50) & 0x20a00) == 0)) {` |
| FUN_0000888c | 0x888c | 33 | read | `(iVar2 = (**(code **)(*(int *)(iVar1 + 0x10) + 0x4c))` |
| FUN_00009274 | 0x9274 | 8 | read | `(**(code **)(iVar1 + 0x54))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar1 + 0x50),0);` |
| FUN_000092cc | 0x92cc | 8 | read | `(**(code **)(iVar1 + 0x54))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar1 + 0x50),0);` |
| FUN_00009638 | 0x9638 | 8 | read | `(**(code **)(iVar1 + 0x54))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar1 + 0x50));` |
| FUN_0000c020 | 0xc020 | 27 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0000c020 | 0xc020 | 28 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0000c10c | 0xc10c | 18 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0000c10c | 0xc10c | 19 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0000c910 | 0xc910 | 18 | read | `if (((*(uint *)(param_2 + 0x50) & 1) == 0) \|\|` |
| FUN_0000c9fc | 0xc9fc | 22 | read | `if (((*(uint *)(param_2 + 0x50) & 1) == 0) \|\|` |
| FUN_0000d090 | 0xd090 | 22 | read | `(**(code **)(*(int *)(iVar1 + 0x10) + 0x54))` |
| FUN_0000d090 | 0xd090 | 23 | read | `(iVar1 + *(short *)(*(int *)(iVar1 + 0x10) + 0x50),0);` |
| FUN_0000d090 | 0xd090 | 36 | read | `(**(code **)(*(int *)(iVar3 + 0x10) + 0x54))` |
| FUN_0000d090 | 0xd090 | 37 | read | `(iVar3 + *(short *)(*(int *)(iVar3 + 0x10) + 0x50),0);` |
| FUN_0000d090 | 0xd090 | 38 | read | `(**(code **)(*(int *)(iVar1 + 0x10) + 0x54))` |
| FUN_0000d090 | 0xd090 | 39 | read | `(iVar1 + *(short *)(*(int *)(iVar1 + 0x10) + 0x50),0);` |
| FUN_0000d090 | 0xd090 | 43 | read | `(**(code **)(*(int *)(iVar3 + 0x10) + 0x54))(iVar3 + *(short *)(*(int *)(iVar3 + 0x10) + 0x50));` |
| FUN_0000d398 | 0xd398 | 44 | read | `for (iVar3 = *(int *)(iVar6 + iVar5 * 4 + 4); iVar3 != 0; iVar3 = *(int *)(iVar3 + 0x58))` |
| FUN_0000dbb4 | 0xdbb4 | 21 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0000dbb4 | 0xdbb4 | 22 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00010c1c | 0x10c1c | 30 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00010c1c | 0x10c1c | 31 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00010c1c | 0x10c1c | 59 | read | `if ((*(uint *)(iVar4 + 0x50) & 1) == 0) goto LAB_00010ea0;` |
| FUN_00010c1c | 0x10c1c | 71 | read | `if ((*(uint *)(iVar4 + 0x50) & 1) == 0) {` |
| FUN_0001150c | 0x1150c | 36 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001150c | 0x1150c | 37 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00011714 | 0x11714 | 44 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00011714 | 0x11714 | 45 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000119cc | 0x119cc | 47 | read | `uVar1 = *(ushort *)(iVar2 + 0x54);` |
| FUN_000119cc | 0x119cc | 66 | read | `iVar3 = func_0x0006c768(*(undefined4 *)(param_2 + 0x54),aiStack_58);` |
| FUN_000119cc | 0x119cc | 71 | read | `iVar9 = *(int *)(iVar9 + 0x58)) {` |
| FUN_000119cc | 0x119cc | 73 | read | `uVar7 = *(uint *)(iVar9 + 0x50);` |
| FUN_000122ec | 0x122ec | 58 | read | `if ((*(uint *)(iVar5 + 0x50) & 1) != 0) {` |
| FUN_000122ec | 0x122ec | 78 | read | `(**(code **)(iVar3 + 0x54))(*param_1 + (int)*(short *)(iVar3 + 0x50),1);` |
| FUN_0001301c | 0x1301c | 63 | read | `if ((*(uint *)(iVar4 + 0x50) & 5) != 0) {` |
| FUN_000138c4 | 0x138c4 | 27 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_000138c4 | 0x138c4 | 28 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00013dec | 0x13dec | 21 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00013dec | 0x13dec | 22 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000146c0 | 0x146c0 | 31 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_000146c0 | 0x146c0 | 32 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001528c | 0x1528c | 34 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001528c | 0x1528c | 35 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001543c | 0x1543c | 14 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001543c | 0x1543c | 15 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015508 | 0x15508 | 5 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015508 | 0x15508 | 6 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015668 | 0x15668 | 17 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015668 | 0x15668 | 18 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000158f0 | 0x158f0 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_000158f0 | 0x158f0 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015990 | 0x15990 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015990 | 0x15990 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000159e0 | 0x159e0 | 13 | read | `uVar5 = *(uint *)(iVar4 + 0x58);` |
| FUN_00015ba4 | 0x15ba4 | 7 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015ba4 | 0x15ba4 | 8 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015c4c | 0x15c4c | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015c4c | 0x15c4c | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001655c | 0x1655c | 35 | read | `(**(code **)(iVar3 + 0x54))(*(int *)*param_1 + (int)*(short *)(iVar3 + 0x50),1);` |
| FUN_0001655c | 0x1655c | 87 | read | `(**(code **)(*(int *)(iVar4 + 0x10) + 0x54))` |
| FUN_0001655c | 0x1655c | 88 | read | `(iVar4 + *(short *)(*(int *)(iVar4 + 0x10) + 0x50),1);` |
| FUN_0001a688 | 0x1a688 | 11 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001a688 | 0x1a688 | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001a754 | 0x1a754 | 11 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001a754 | 0x1a754 | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001a834 | 0x1a834 | 46 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001a834 | 0x1a834 | 47 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001a958 | 0x1a958 | 9 | read | `uVar3 = *(uint *)(*(int *)(*(int *)(*(int *)(param_1 + 0x24) + 8) + 0x318) + 0x58);` |
| FUN_0001aa78 | 0x1aa78 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001aa78 | 0x1aa78 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ab10 | 0x1ab10 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ab10 | 0x1ab10 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001aba8 | 0x1aba8 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001aba8 | 0x1aba8 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ac40 | 0x1ac40 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ac40 | 0x1ac40 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001acd8 | 0x1acd8 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001acd8 | 0x1acd8 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ad70 | 0x1ad70 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ad70 | 0x1ad70 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001adb8 | 0x1adb8 | 18 | read | `uVar5 = *(undefined4 *)(iVar4 + 0x54);` |
| FUN_0001aea4 | 0x1aea4 | 15 | read | `uVar3 = *(undefined4 *)(iVar2 + 0x54);` |
| FUN_0001b198 | 0x1b198 | 41 | read | `func_0x0007a3e0(iVar3,iVar4 + 0x38,iVar4 + 0x50,local_10);` |
| FUN_0001b198 | 0x1b198 | 71 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001b198 | 0x1b198 | 72 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001b544 | 0x1b544 | 43 | read | `func_0x0007a3e0(iVar5,iVar2 + 0x38,iVar2 + 0x50,local_18);` |
| FUN_0001b544 | 0x1b544 | 80 | read | `func_0x0007a3e0(iVar5,iVar4 + 0x38,iVar4 + 0x50,local_18);` |
| FUN_0001b544 | 0x1b544 | 142 | read | `uVar3 = (**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001b544 | 0x1b544 | 143 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001bf94 | 0x1bf94 | 43 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001bf94 | 0x1bf94 | 44 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c3ec | 0x1c3ec | 11 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c3ec | 0x1c3ec | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c5c4 | 0x1c5c4 | 50 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c5c4 | 0x1c5c4 | 51 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c7c4 | 0x1c7c4 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c7c4 | 0x1c7c4 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c8d8 | 0x1c8d8 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c8d8 | 0x1c8d8 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c9cc | 0x1c9cc | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c9cc | 0x1c9cc | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001cac0 | 0x1cac0 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001cac0 | 0x1cac0 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001cbb4 | 0x1cbb4 | 46 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001cbb4 | 0x1cbb4 | 47 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ce00 | 0x1ce00 | 40 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ce00 | 0x1ce00 | 41 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001d200 | 0x1d200 | 7 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001d200 | 0x1d200 | 8 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001e80c | 0x1e80c | 19 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001e80c | 0x1e80c | 20 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001e8dc | 0x1e8dc | 14 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001e8dc | 0x1e8dc | 15 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ec7c | 0x1ec7c | 55 | read | `*(ushort *)((int)piVar6 + 0x4e) = uVar4;` |
| FUN_000207a8 | 0x207a8 | 53 | read | `iVar2 = iVar2 + 0x4c;` |
| FUN_000209dc | 0x209dc | 9 | read | `param_1 = *(int *)(param_1 + 0x58);` |
| FUN_00020b88 | 0x20b88 | 33 | read | `iVar4 = iVar4 + 0x4c;` |
| FUN_00020dcc | 0x20dcc | 60 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) \| 4;` |
| FUN_000226c4 | 0x226c4 | 11 | read | `(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58),param_2);` |
| FUN_000226c4 | 0x226c4 | 23 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffffb \| 8;` |
| FUN_00022790 | 0x22790 | 19 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x5c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58),0);` |
| FUN_00022790 | 0x22790 | 39 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffff7;` |
| FUN_00022790 | 0x22790 | 52 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffff7 \| 4;` |
| FUN_00022924 | 0x22924 | 30 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffffb \| 0x1000;` |
| FUN_00022a18 | 0x22a18 | 13 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffefff \| 4;` |
| FUN_00023698 | 0x23698 | 20 | write | `*(ushort *)(param_1 + 0xd4) = *(ushort *)(param_1 + 0xd4) + 0x50;` |
| FUN_00023698 | 0x23698 | 30 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00023698 | 0x23698 | 35 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 0x80;` |
| FUN_0002380c | 0x2380c | 26 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_0002380c | 0x2380c | 108 | read | `uVar5 = *(uint *)(param_1 + 0x50);` |
| FUN_0002380c | 0x2380c | 199 | read | `if ((*(uint *)(param_1 + 0x50) & 0x40) != 0) {` |
| FUN_00024454 | 0x24454 | 5 | read | `if ((*(uint *)(param_1 + 0x50) & 0x1000) == 0) {` |
| FUN_00024454 | 0x24454 | 10 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00024454 | 0x24454 | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58),0);` |
| FUN_00024454 | 0x24454 | 13 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffff7 \| 0x80;` |
| FUN_00024558 | 0x24558 | 22 | read | `if ((*(uint *)(param_1 + 0x50) & 8) == 0) {` |
| FUN_000249e4 | 0x249e4 | 68 | write | `*(undefined4 *)(iVar6 + 0x50) = *(undefined4 *)(param_1 + 0x50);` |
| FUN_00025048 | 0x25048 | 30 | write | `*(undefined4 *)(param_1 + 0x54) = 0;` |
| FUN_00025c18 | 0x25c18 | 40 | read | `*(uint *)(iVar2 + 0x50) = *(uint *)(iVar2 + 0x50) \| 4;` |
| FUN_00026768 | 0x26768 | 23 | read | `*(uint *)(iVar2 + 0x50) = *(uint *)(iVar2 + 0x50) \| 4;` |
| FUN_0002685c | 0x2685c | 66 | read | `*(uint *)(iVar9 + 0x50) = *(uint *)(iVar9 + 0x50) \| 4;` |
| FUN_00026c68 | 0x26c68 | 20 | read | `((*(uint *)(param_1 + 0x50) & 4) == 0)) {` |
| FUN_00026e4c | 0x26e4c | 9 | read | `if ((*(uint *)(param_1 + 0x50) & 8) == 0) {` |
| FUN_00026e4c | 0x26e4c | 13 | read | `if ((*(int *)(iVar2 + 0x54) == 6) && (*(int *)(param_1 + 0xf4) != 0)) {` |
| FUN_00027a44 | 0x27a44 | 12 | read | `if (*(int *)(iVar1 + 0x54) != param_2) {` |
| FUN_000280a0 | 0x280a0 | 16 | read | `iVar3 = *(int *)(param_1 + 0x54);` |
| FUN_000280a0 | 0x280a0 | 28 | read | `iVar3 = *(int *)(param_1 + 0x58);` |
| FUN_000283f8 | 0x283f8 | 58 | write | `*(ushort *)(param_1 + 0x4c + uVar4 * 2) = *puVar7;` |
| FUN_000283f8 | 0x283f8 | 69 | write | `*(ushort *)(param_1 + 0x50 + iVar5) = *puVar7;` |
| FUN_00028724 | 0x28724 | 24 | read | `if (*(int *)(param_1 + 0x54) == 6) {` |
| FUN_00028724 | 0x28724 | 28 | read | `if ((*(uint *)(param_2 + 0x50) & 4) != 0) {` |
| FUN_00028724 | 0x28724 | 31 | read | `if ((*(uint *)(param_2 + 0x50) & 1) != 0) {` |
| FUN_00028724 | 0x28724 | 38 | read | `if ((*(int *)(param_1 + 0x58) == 3) && (*(int *)(param_2 + 0x300) != 1)) {` |
| FUN_00028724 | 0x28724 | 61 | read | `if (*(uint *)(param_1 + 0x58) < 2) {` |
| FUN_00028724 | 0x28724 | 66 | read | `else if ((*(int *)(param_1 + 0x58) == 2) \|\| (*(int *)(param_1 + 0x58) == 0)) {` |
| FUN_00028724 | 0x28724 | 78 | read | `iVar6 = *(int *)(param_1 + 0x54);` |
| FUN_00028724 | 0x28724 | 86 | read | `else if (*(int *)(param_1 + 0x54) != 1) {` |
| FUN_00028c60 | 0x28c60 | 26 | read | `*(undefined4 *)(iVar3 + 0x54) = 0;` |
| FUN_00028c60 | 0x28c60 | 27 | read | `*(undefined4 *)(iVar3 + 0x58) = 0;` |
| FUN_00028d10 | 0x28d10 | 19 | read | `*(undefined4 *)(iVar1 + 0x54) = 5;` |
| FUN_00028e58 | 0x28e58 | 9 | read | `if (*(int *)(param_1 + 0x54) == 2) {` |
| FUN_00028e58 | 0x28e58 | 13 | read | `if (*(int *)(param_1 + 0x54) != 3) {` |
| FUN_00028ef4 | 0x28ef4 | 11 | read | `if ((iVar2 != -1) && (*(int *)(param_1 + 0x54) != 6)) {` |
| FUN_00028fc4 | 0x28fc4 | 56 | read | `if (((_DAT_8004d6fa == 2) && (*(int *)(param_1 + 0x54) == 6)) &&` |
| FUN_000296e8 | 0x296e8 | 22 | read | `piVar6 = (int *)(iVar3 + 0x58);` |
| FUN_00029910 | 0x29910 | 24 | read | `iVar4 = *(int *)(uVar2 * 4 + iVar3 + 0x58);` |
| FUN_00029c24 | 0x29c24 | 77 | write | `*(uint *)(param_1 + 0x58 + uVar7 * 4) = iVar3 + (uint)*puVar9 * 0x18;` |
| FUN_0002a2d0 | 0x2a2d0 | 52 | read | `iVar6 = iVar6 + 0x4c;` |
| FUN_0002a498 | 0x2a498 | 45 | read | `iVar1 = func_0x00072348(*(undefined4 *)(param_1 + 0x58 + iVar1));` |
| FUN_0002a5f4 | 0x2a5f4 | 18 | read | `func_0x000725a8(*(undefined4 *)(param_1 + 0x58 + iVar1));` |
| FUN_0002ad60 | 0x2ad60 | 19 | read | `iVar4 = *(int *)(*(int *)(param_1 + iVar2 + 0x58) + 4);` |
| FUN_0002ad60 | 0x2ad60 | 20 | read | `iVar2 = *(int *)(iVar4 + 0x54);` |
| FUN_0002b2b8 | 0x2b2b8 | 80 | read | `piVar7 = (int *)(uVar6 * 4 + 0x58 + param_1);` |
| FUN_0002b7d0 | 0x2b7d0 | 29 | read | `if (*(int *)(*(int *)(*(int *)(param_1 + 0x58) + 4) + 0x54) == 5) {` |
| FUN_0002b7d0 | 0x2b7d0 | 38 | read | `iVar7 = *(int *)(*(int *)(param_1 + 0x58 + uVar3 * 4) + 4);` |
| FUN_0002b7d0 | 0x2b7d0 | 40 | read | `} while (*(int *)(iVar7 + 0x54) != 5);` |
| FUN_0002c4b0 | 0x2c4b0 | 30 | write | `*(undefined4 *)(param_1 + 0x50) = param_2[3];` |
| FUN_0002c4b0 | 0x2c4b0 | 75 | read | `if (*(int *)(param_1 + 0x50) != 0) {` |
| FUN_0002c4b0 | 0x2c4b0 | 81 | read | `} while (uVar8 < *(uint *)(param_1 + 0x50));` |
| FUN_0002c964 | 0x2c964 | 116 | read | `if ((((uVar4 & 1) != 0) && (*(int *)(iVar7 + 0x54) != 0)) && (*(int *)(iVar7 + 0x10) == 0)) {` |
| FUN_0002da08 | 0x2da08 | 27 | read | `if (*(int *)(param_1 + 0x50) == 0) {` |
| FUN_0002dbc0 | 0x2dbc0 | 87 | read | `uVar7 = *(uint *)(param_1 + 0x50);` |
| FUN_0002f988 | 0x2f988 | 72 | write | `*(short *)(param_1 + 0x584) = (short)uVar5 + *(short *)(param_1 + 8);` |
| FUN_0002f988 | 0x2f988 | 73 | write | `*(short *)(param_1 + 0x586) = (short)uVar6 + *(short *)(param_1 + 10);` |
| FUN_0002f988 | 0x2f988 | 74 | write | `*(short *)(param_1 + 0x588) = (short)uVar7 + *(short *)(param_1 + 0xc);` |
| FUN_0002f988 | 0x2f988 | 96 | write | `*(short *)(param_1 + 0x58c) = (short)uVar5 + *(short *)(param_1 + 8);` |
| FUN_0002f988 | 0x2f988 | 97 | write | `*(short *)(param_1 + 0x58e) = (short)uVar6 + *(short *)(param_1 + 10);` |
| FUN_0002ffac | 0x2ffac | 185 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) & 0xffffffef;` |
| FUN_0002ffac | 0x2ffac | 194 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) \| 0x10;` |
| FUN_0002ffac | 0x2ffac | 201 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) \| 0x10;` |
| FUN_00030be8 | 0x30be8 | 42 | read | `((*(uint *)(iVar2 + 0x50) & 0x20000) != 0)) {` |
| FUN_00031048 | 0x31048 | 32 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x4c))` |
| FUN_00031048 | 0x31048 | 50 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x4c))` |
| FUN_00031048 | 0x31048 | 76 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x4c))` |
| FUN_00031480 | 0x31480 | 10 | read | `(((*(uint *)(param_2 + 0x50) & 4) == 0 &&` |
| FUN_00031b38 | 0x31b38 | 64 | read | `iVar7 = iVar2 + 0x54;` |
| FUN_00031b38 | 0x31b38 | 96 | read | `iVar11 = FUN_00023358(iVar2 + 0x5a);` |
| FUN_00031b38 | 0x31b38 | 106 | read | `iVar2 = FUN_00023358(iVar2 + 0x5a);` |
| FUN_00035cc0 | 0x35cc0 | 134 | read | `if ((*(uint *)(unaff_s2 + 0x50) & 0x20000) == 0) {` |
| FUN_00035cc0 | 0x35cc0 | 136 | read | `*(uint *)(unaff_s2 + 0x50) = *(uint *)(unaff_s2 + 0x50) \| 0x20000;` |
| FUN_00036c34 | 0x36c34 | 60 | read | `iVar12 = *(int *)(iVar12 + 0x58)) {` |
| FUN_00039dac | 0x39dac | 14 | write | `*(undefined4 *)(param_1 + 0x520) = 0;` |
| FUN_00039dac | 0x39dac | 28 | write | `*(undefined4 *)(param_1 + 0x5ac) = 0;` |
| FUN_00039dac | 0x39dac | 31 | write | `*(int *)(param_1 + 0x5a8) = param_1;` |
| FUN_0003a25c | 0x3a25c | 19 | read | `puVar2 = (undefined4 *)(param_1 + 0x544);` |
| FUN_0003a25c | 0x3a25c | 35 | write | `*(undefined4 *)(param_1 + 0x524) = *(undefined4 *)(param_1 + 0x39c);` |
| FUN_0003a25c | 0x3a25c | 36 | write | `*(undefined4 *)(param_1 + 0x528) = *(undefined4 *)(param_1 + 0x3a0);` |
| FUN_0003a25c | 0x3a25c | 37 | write | `*(undefined4 *)(param_1 + 0x52c) = *(undefined4 *)(param_1 + 0x3a4);` |
| FUN_0003a25c | 0x3a25c | 42 | write | `*(undefined4 *)(param_1 + 0x540) = *(undefined4 *)(param_1 + 0x3b8);` |
| FUN_0003a7d0 | 0x3a7d0 | 19 | read | `iVar1 = *(int *)(param_1 + 0x520);` |
| FUN_0003b264 | 0x3b264 | 142 | read | `if (((*(uint *)(iVar10 + 0x50) & 4) != 0) \|\| ((*(uint *)(iVar10 + 0x50) & 1) != 0)) {` |
| FUN_0003cdf0 | 0x3cdf0 | 15 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003cdf0 | 0x3cdf0 | 16 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) & 0xfffffffe;` |
| FUN_0003cdf0 | 0x3cdf0 | 18 | read | `*(uint *)(iVar1 + 0x50) = *(uint *)(iVar1 + 0x50) & 0xfffffdff;` |
| FUN_0003cdf0 | 0x3cdf0 | 20 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) = *(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x10` |
| FUN_0003cee4 | 0x3cee4 | 45 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) & 0xffffffef;` |
| FUN_0003d0e8 | 0x3d0e8 | 45 | read | `(iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x58),*(undefined2 *)(iVar6 + 0xb8))` |
| FUN_0003d0e8 | 0x3d0e8 | 48 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) \| 0x10;` |
| FUN_0003dd3c | 0x3dd3c | 47 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 1;` |
| FUN_0003df28 | 0x3df28 | 55 | read | `*(uint *)(iVar8 + 0x50) = *(uint *)(iVar8 + 0x50) & 0xffffffef;` |
| FUN_0003df28 | 0x3df28 | 56 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003df28 | 0x3df28 | 57 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x200;` |
| FUN_0003df28 | 0x3df28 | 97 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffffe;` |
| FUN_0003df28 | 0x3df28 | 104 | read | `*(uint *)(iVar8 + 0x50) = *(uint *)(iVar8 + 0x50) & 0xffffffef;` |
| FUN_0003df28 | 0x3df28 | 105 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003df28 | 0x3df28 | 106 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x200;` |
| FUN_0003e810 | 0x3e810 | 16 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) \| 1;` |
| FUN_0003e810 | 0x3e810 | 43 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) & 0xfffffdff;` |
| FUN_0003e810 | 0x3e810 | 45 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003e810 | 0x3e810 | 46 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x10;` |
| FUN_0003e810 | 0x3e810 | 47 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003e810 | 0x3e810 | 48 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) & 0xfffffffe;` |
| FUN_0003e838 | 0x3e838 | 19 | read | `*(uint *)(in_v1 + 0x50) = in_v0 \| 1;` |
| FUN_0003e838 | 0x3e838 | 48 | read | `*(uint *)(iVar1 + 0x50) = *(uint *)(iVar1 + 0x50) & 0xfffffdff;` |
| FUN_0003e838 | 0x3e838 | 50 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) =` |
| FUN_0003e838 | 0x3e838 | 51 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) \| 0x10;` |
| FUN_0003e838 | 0x3e838 | 52 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) =` |
| FUN_0003e838 | 0x3e838 | 53 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) & 0xfffffffe;` |
| FUN_0003f1dc | 0x3f1dc | 21 | read | `((uVar3 == 0x57 \|\| (*(int *)(iVar2 + 0x58) == 0))))));` |
| FUN_0003f1dc | 0x3f1dc | 28 | read | `*(short *)(*(int *)(iVar2 + 0x48) + 6) = *(short *)(iVar2 + 0x4e) + (short)_DAT_800bc944;` |
| FUN_0003f1dc | 0x3f1dc | 34 | read | `} while (0xd < *(ushort *)(iVar2 + 0x4e));` |
| FUN_0003f1dc | 0x3f1dc | 37 | read | `(**(code **)((uint)*(ushort *)(iVar2 + 0x4e) * 4 + -0x7ff38cec))();` |
| FUN_0003fbb0 | 0x3fbb0 | 179 | read | `*(undefined4 *)(_DAT_8011a3dc + 0x58) = 0;` |
| FUN_0003fbb0 | 0x3fbb0 | 183 | read | `*(undefined4 *)(_DAT_8011a3e8 + 0x58) = 0;` |
| FUN_0003fbb0 | 0x3fbb0 | 188 | read | `*(undefined4 *)(*piVar8 + 0x58) = 0;` |
| FUN_000401ec | 0x401ec | 11 | read | `*(undefined4 *)(_DAT_8011a3dc + 0x58) = 0;` |
| FUN_000401ec | 0x401ec | 15 | read | `*(undefined4 *)(_DAT_8011a3e8 + 0x58) = 0;` |
| FUN_000401ec | 0x401ec | 20 | read | `*(undefined4 *)(*piVar1 + 0x58) = 0;` |
| FUN_000402e0 | 0x402e0 | 34 | read | `*(undefined2 *)(param_3 + 0x3c) = *(undefined2 *)(param_4 + 0x4c);` |
| FUN_000402e0 | 0x402e0 | 35 | read | `*(undefined2 *)(param_3 + 0x3e) = *(undefined2 *)(param_4 + 0x50);` |
| FUN_000402e0 | 0x402e0 | 37 | read | `if (*(int *)(param_4 + 0x54) != 0) {` |
| FUN_000402e0 | 0x402e0 | 41 | read | `*(short *)(param_3 + 0x40) = *(short *)(param_4 + 0x58) << 6;` |
| FUN_000402e0 | 0x402e0 | 42 | read | `*(undefined2 *)(param_3 + 0x50) = *(undefined2 *)(param_4 + 0x5c);` |
| FUN_000402e0 | 0x402e0 | 43 | read | `*(undefined4 *)(param_3 + 0x54) = *(undefined4 *)(param_4 + 0x60);` |
| FUN_0004033c | 0x4033c | 25 | read | `*(undefined2 *)(param_3 + 0x3c) = *(undefined2 *)(param_4 + 0x4c);` |
| FUN_0004033c | 0x4033c | 26 | read | `*(undefined2 *)(param_3 + 0x3e) = *(undefined2 *)(param_4 + 0x50);` |
| FUN_0004033c | 0x4033c | 28 | read | `if (*(int *)(param_4 + 0x54) != 0) {` |
| FUN_0004033c | 0x4033c | 32 | read | `*(short *)(param_3 + 0x40) = *(short *)(param_4 + 0x58) << 6;` |
| FUN_0004033c | 0x4033c | 33 | read | `*(undefined2 *)(param_3 + 0x50) = *(undefined2 *)(param_4 + 0x5c);` |
| FUN_0004033c | 0x4033c | 34 | read | `*(undefined4 *)(param_3 + 0x54) = *(undefined4 *)(param_4 + 0x60);` |
| FUN_0004050c | 0x4050c | 19 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 0x18;` |
| FUN_00040a4c | 0x40a4c | 93 | read | `(iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x58),uVar3);` |
| FUN_00040a4c | 0x40a4c | 98 | read | `(**(code **)(iVar6 + 0x5c))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar6 + 0x58),uVar3);` |
| FUN_00040a4c | 0x40a4c | 111 | read | `(**(code **)(iVar6 + 0x4c))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar6 + 0x48),999);` |
| FUN_00040a98 | 0x40a98 | 86 | read | `(iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x58),uVar3);` |
| FUN_00040a98 | 0x40a98 | 96 | read | `(*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x58),uVar3);` |
| FUN_00040a98 | 0x40a98 | 109 | read | `(**(code **)(iVar6 + 0x4c))` |
| FUN_000412d8 | 0x412d8 | 16 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 0x10;` |
| FUN_000412d8 | 0x412d8 | 89 | read | `*(short *)(*(int *)(param_1 + 0xc0) + 0x4c);` |
| FUN_000412d8 | 0x412d8 | 100 | read | `(int)*(short *)(*(int *)(param_1 + 0xc0) + 0x4c))) {` |
| FUN_000412d8 | 0x412d8 | 125 | read | `if ((*(uint *)(*(int *)(param_1 + 0xd4) + 0x50) & 0x400) != 0) {` |
| FUN_000412d8 | 0x412d8 | 150 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;` |
| FUN_00041a48 | 0x41a48 | 21 | read | `iVar4 = iVar2 + 0x54;` |
| FUN_00041ba4 | 0x41ba4 | 44 | read | `iVar3 = FUN_00023210(0x800c7840,iVar5 + 0x54,6);` |
| FUN_00041ba4 | 0x41ba4 | 71 | read | `iVar3 = FUN_00023210(0x800c7848,iVar5 + 0x54,6);` |
| FUN_00041ba4 | 0x41ba4 | 100 | read | `iVar4 = FUN_00023210(0x800c7850,iVar10 + 0x54,4);` |
| FUN_00041ba4 | 0x41ba4 | 108 | read | `iVar4 = FUN_00023210(0x800c7858,iVar10 + 0x54,4);` |
| FUN_00041edc | 0x41edc | 18 | read | `iVar3 = FUN_00023110(0x800c7860,iVar4 + 0x54);` |
| FUN_00041edc | 0x41edc | 24 | read | `iVar3 = FUN_00023110(0x800c786c,iVar4 + 0x54);` |
| FUN_00043748 | 0x43748 | 40 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 53 | read | `if (((cVar1 == '\x06') && ((*(uint *)(param_1 + 0x50) & 4) != 0)) &&` |
| FUN_000438fc | 0x438fc | 69 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 96 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 101 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 122 | read | `(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58));` |
| FUN_000438fc | 0x438fc | 142 | read | `if ((*(uint *)(param_1 + 0x50) & 4) == 0) {` |
| FUN_000438fc | 0x438fc | 161 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 284 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;` |
| FUN_00043a94 | 0x43a94 | 9 | read | `*(uint *)(unaff_s3 + 0x50) = *(uint *)(unaff_s3 + 0x50) & 0xffffffef;` |
| FUN_000443b8 | 0x443b8 | 82 | read | `param_2 = *(int *)(param_2 + 0x58);` |
| FUN_00044a14 | 0x44a14 | 21 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00044a14 | 0x44a14 | 148 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffdff \| 0x40;` |
| FUN_00044f80 | 0x44f80 | 56 | read | `if ((*(uint *)(param_1 + 0x50) & 4) != 0) {` |
| FUN_00044f80 | 0x44f80 | 59 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00044f80 | 0x44f80 | 85 | read | `(iVar12 = -(int)*(short *)(param_1 + 0x3e), (*(uint *)(param_1 + 0x50) & 4) == 0)) {` |
| FUN_00045a00 | 0x45a00 | 14 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00045a80 | 0x45a80 | 33 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00045a80 | 0x45a80 | 52 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046024 | 0x46024 | 38 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046024 | 0x46024 | 40 | read | `if (((*(uint *)(param_1 + 0x50) & 4) == 0) &&` |
| FUN_00046024 | 0x46024 | 43 | read | `if ((*(uint *)(param_1 + 0x50) & 0x20) != 0) {` |
| FUN_00046024 | 0x46024 | 144 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046498 | 0x46498 | 10 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046498 | 0x46498 | 13 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000475dc | 0x475dc | 159 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;` |
| FUN_0004a058 | 0x4a058 | 22 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00005e14 | 0x5e14 | 7 | read | `uVar1 = func_0x0006ea78(*(undefined4 *)(*(int *)(param_2 + 8) + 0x54),1);` |
| FUN_00005e50 | 0x5e50 | 15 | read | `uVar1 = func_0x0006c768(*(undefined4 *)(*(int *)(param_2 + 8) + 0x54),local_40);` |
| FUN_00006240 | 0x6240 | 5 | read | `func_0x000c994c(param_1,*(undefined4 *)(*(int *)(*(int *)(param_2 + 8) + 0x318) + 0x54));` |
| FUN_00006f90 | 0x6f90 | 11 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_00007084 | 0x7084 | 11 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_000071ec | 0x71ec | 12 | read | `(((((*(uint *)(iVar2 + 0xb8) & 8) == 0 && ((*(uint *)(iVar2 + 0x50) & 4) == 0)) &&` |
| FUN_00007710 | 0x7710 | 17 | read | `uVar2 = *(undefined2 *)(*(int *)(iVar1 + 0xc0) + 0x50);` |
| FUN_00007784 | 0x7784 | 17 | read | `uVar3 = *(undefined4 *)(*(int *)(iVar1 + 0xc0) + 0x54);` |
| FUN_00007a74 | 0x7a74 | 7 | read | `uVar1 = func_0x0006e55c(*(undefined4 *)(*(int *)(param_2 + 8) + 0x54));` |
| FUN_00007f10 | 0x7f10 | 17 | read | `} while ((*(int *)(aiStack_18[uVar2] + 0x54) != 6) \|\|` |
| FUN_0000852c | 0x852c | 16 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_00008610 | 0x8610 | 16 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_00008704 | 0x8704 | 15 | read | `uVar4 = *(uint *)(iVar5 + 0x58);` |
| FUN_00008704 | 0x8704 | 25 | read | `if (*(uint *)(iVar5 + 0x54) == 0) {` |
| FUN_00008704 | 0x8704 | 28 | read | `return uVar1 / *(uint *)(iVar5 + 0x54);` |
| FUN_0000888c | 0x888c | 12 | read | `if ((*(int *)(iVar2 + 0x300) == 2) && ((*(uint *)(iVar2 + 0x50) & 0x20a00) == 0)) {` |
| FUN_0000888c | 0x888c | 33 | read | `(iVar2 = (**(code **)(*(int *)(iVar1 + 0x10) + 0x4c))` |
| FUN_00009274 | 0x9274 | 8 | read | `(**(code **)(iVar1 + 0x54))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar1 + 0x50),0);` |
| FUN_000092cc | 0x92cc | 8 | read | `(**(code **)(iVar1 + 0x54))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar1 + 0x50),0);` |
| FUN_00009638 | 0x9638 | 8 | read | `(**(code **)(iVar1 + 0x54))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar1 + 0x50));` |
| FUN_0000c020 | 0xc020 | 27 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0000c020 | 0xc020 | 28 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0000c10c | 0xc10c | 18 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0000c10c | 0xc10c | 19 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0000c910 | 0xc910 | 18 | read | `if (((*(uint *)(param_2 + 0x50) & 1) == 0) \|\|` |
| FUN_0000c9fc | 0xc9fc | 22 | read | `if (((*(uint *)(param_2 + 0x50) & 1) == 0) \|\|` |
| FUN_0000d090 | 0xd090 | 22 | read | `(**(code **)(*(int *)(iVar1 + 0x10) + 0x54))` |
| FUN_0000d090 | 0xd090 | 23 | read | `(iVar1 + *(short *)(*(int *)(iVar1 + 0x10) + 0x50),0);` |
| FUN_0000d090 | 0xd090 | 36 | read | `(**(code **)(*(int *)(iVar3 + 0x10) + 0x54))` |
| FUN_0000d090 | 0xd090 | 37 | read | `(iVar3 + *(short *)(*(int *)(iVar3 + 0x10) + 0x50),0);` |
| FUN_0000d090 | 0xd090 | 38 | read | `(**(code **)(*(int *)(iVar1 + 0x10) + 0x54))` |
| FUN_0000d090 | 0xd090 | 39 | read | `(iVar1 + *(short *)(*(int *)(iVar1 + 0x10) + 0x50),0);` |
| FUN_0000d090 | 0xd090 | 43 | read | `(**(code **)(*(int *)(iVar3 + 0x10) + 0x54))(iVar3 + *(short *)(*(int *)(iVar3 + 0x10) + 0x50));` |
| FUN_0000d398 | 0xd398 | 44 | read | `for (iVar3 = *(int *)(iVar6 + iVar5 * 4 + 4); iVar3 != 0; iVar3 = *(int *)(iVar3 + 0x58))` |
| FUN_0000dbb4 | 0xdbb4 | 21 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0000dbb4 | 0xdbb4 | 22 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00010c1c | 0x10c1c | 30 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00010c1c | 0x10c1c | 31 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00010c1c | 0x10c1c | 59 | read | `if ((*(uint *)(iVar4 + 0x50) & 1) == 0) goto LAB_00010ea0;` |
| FUN_00010c1c | 0x10c1c | 71 | read | `if ((*(uint *)(iVar4 + 0x50) & 1) == 0) {` |
| FUN_0001150c | 0x1150c | 36 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001150c | 0x1150c | 37 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00011714 | 0x11714 | 44 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00011714 | 0x11714 | 45 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000119cc | 0x119cc | 47 | read | `uVar1 = *(ushort *)(iVar2 + 0x54);` |
| FUN_000119cc | 0x119cc | 66 | read | `iVar3 = func_0x0006c768(*(undefined4 *)(param_2 + 0x54),aiStack_58);` |
| FUN_000119cc | 0x119cc | 71 | read | `iVar9 = *(int *)(iVar9 + 0x58)) {` |
| FUN_000119cc | 0x119cc | 73 | read | `uVar7 = *(uint *)(iVar9 + 0x50);` |
| FUN_000122ec | 0x122ec | 58 | read | `if ((*(uint *)(iVar5 + 0x50) & 1) != 0) {` |
| FUN_000122ec | 0x122ec | 78 | read | `(**(code **)(iVar3 + 0x54))(*param_1 + (int)*(short *)(iVar3 + 0x50),1);` |
| FUN_0001301c | 0x1301c | 63 | read | `if ((*(uint *)(iVar4 + 0x50) & 5) != 0) {` |
| FUN_000138c4 | 0x138c4 | 27 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_000138c4 | 0x138c4 | 28 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00013dec | 0x13dec | 21 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00013dec | 0x13dec | 22 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000146c0 | 0x146c0 | 31 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_000146c0 | 0x146c0 | 32 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001528c | 0x1528c | 34 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001528c | 0x1528c | 35 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001543c | 0x1543c | 14 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001543c | 0x1543c | 15 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015508 | 0x15508 | 5 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015508 | 0x15508 | 6 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015668 | 0x15668 | 17 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015668 | 0x15668 | 18 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000158f0 | 0x158f0 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_000158f0 | 0x158f0 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015990 | 0x15990 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015990 | 0x15990 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000159e0 | 0x159e0 | 13 | read | `uVar5 = *(uint *)(iVar4 + 0x58);` |
| FUN_00015ba4 | 0x15ba4 | 7 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015ba4 | 0x15ba4 | 8 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015c4c | 0x15c4c | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015c4c | 0x15c4c | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001655c | 0x1655c | 35 | read | `(**(code **)(iVar3 + 0x54))(*(int *)*param_1 + (int)*(short *)(iVar3 + 0x50),1);` |
| FUN_0001655c | 0x1655c | 87 | read | `(**(code **)(*(int *)(iVar4 + 0x10) + 0x54))` |
| FUN_0001655c | 0x1655c | 88 | read | `(iVar4 + *(short *)(*(int *)(iVar4 + 0x10) + 0x50),1);` |
| FUN_0001a688 | 0x1a688 | 11 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001a688 | 0x1a688 | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001a754 | 0x1a754 | 11 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001a754 | 0x1a754 | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001a834 | 0x1a834 | 46 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001a834 | 0x1a834 | 47 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001a958 | 0x1a958 | 9 | read | `uVar3 = *(uint *)(*(int *)(*(int *)(*(int *)(param_1 + 0x24) + 8) + 0x318) + 0x58);` |
| FUN_0001aa78 | 0x1aa78 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001aa78 | 0x1aa78 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ab10 | 0x1ab10 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ab10 | 0x1ab10 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001aba8 | 0x1aba8 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001aba8 | 0x1aba8 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ac40 | 0x1ac40 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ac40 | 0x1ac40 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001acd8 | 0x1acd8 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001acd8 | 0x1acd8 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ad70 | 0x1ad70 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ad70 | 0x1ad70 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001adb8 | 0x1adb8 | 18 | read | `uVar5 = *(undefined4 *)(iVar4 + 0x54);` |
| FUN_0001aea4 | 0x1aea4 | 15 | read | `uVar3 = *(undefined4 *)(iVar2 + 0x54);` |
| FUN_0001b198 | 0x1b198 | 41 | read | `func_0x0007a3e0(iVar3,iVar4 + 0x38,iVar4 + 0x50,local_10);` |
| FUN_0001b198 | 0x1b198 | 71 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001b198 | 0x1b198 | 72 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001b544 | 0x1b544 | 43 | read | `func_0x0007a3e0(iVar5,iVar2 + 0x38,iVar2 + 0x50,local_18);` |
| FUN_0001b544 | 0x1b544 | 80 | read | `func_0x0007a3e0(iVar5,iVar4 + 0x38,iVar4 + 0x50,local_18);` |
| FUN_0001b544 | 0x1b544 | 142 | read | `uVar3 = (**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001b544 | 0x1b544 | 143 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001bf94 | 0x1bf94 | 43 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001bf94 | 0x1bf94 | 44 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c3ec | 0x1c3ec | 11 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c3ec | 0x1c3ec | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c5c4 | 0x1c5c4 | 50 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c5c4 | 0x1c5c4 | 51 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c7c4 | 0x1c7c4 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c7c4 | 0x1c7c4 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c8d8 | 0x1c8d8 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c8d8 | 0x1c8d8 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c9cc | 0x1c9cc | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c9cc | 0x1c9cc | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001cac0 | 0x1cac0 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001cac0 | 0x1cac0 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001cbb4 | 0x1cbb4 | 46 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001cbb4 | 0x1cbb4 | 47 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ce00 | 0x1ce00 | 40 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ce00 | 0x1ce00 | 41 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001d200 | 0x1d200 | 7 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001d200 | 0x1d200 | 8 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001e80c | 0x1e80c | 19 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001e80c | 0x1e80c | 20 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001e8dc | 0x1e8dc | 14 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001e8dc | 0x1e8dc | 15 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ec7c | 0x1ec7c | 55 | read | `*(ushort *)((int)piVar6 + 0x4e) = uVar4;` |
| FUN_000207a8 | 0x207a8 | 53 | read | `iVar2 = iVar2 + 0x4c;` |
| FUN_000209dc | 0x209dc | 9 | read | `param_1 = *(int *)(param_1 + 0x58);` |
| FUN_00020b88 | 0x20b88 | 33 | read | `iVar4 = iVar4 + 0x4c;` |
| FUN_00020dcc | 0x20dcc | 60 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) \| 4;` |
| FUN_000226c4 | 0x226c4 | 11 | read | `(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58),param_2);` |
| FUN_000226c4 | 0x226c4 | 23 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffffb \| 8;` |
| FUN_00022790 | 0x22790 | 19 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x5c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58),0);` |
| FUN_00022790 | 0x22790 | 39 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffff7;` |
| FUN_00022790 | 0x22790 | 52 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffff7 \| 4;` |
| FUN_00022924 | 0x22924 | 30 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffffb \| 0x1000;` |
| FUN_00022a18 | 0x22a18 | 13 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffefff \| 4;` |
| FUN_00023698 | 0x23698 | 20 | write | `*(ushort *)(param_1 + 0xd4) = *(ushort *)(param_1 + 0xd4) + 0x50;` |
| FUN_00023698 | 0x23698 | 30 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00023698 | 0x23698 | 35 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 0x80;` |
| FUN_0002380c | 0x2380c | 26 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_0002380c | 0x2380c | 108 | read | `uVar5 = *(uint *)(param_1 + 0x50);` |
| FUN_0002380c | 0x2380c | 199 | read | `if ((*(uint *)(param_1 + 0x50) & 0x40) != 0) {` |
| FUN_00024454 | 0x24454 | 5 | read | `if ((*(uint *)(param_1 + 0x50) & 0x1000) == 0) {` |
| FUN_00024454 | 0x24454 | 10 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00024454 | 0x24454 | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58),0);` |
| FUN_00024454 | 0x24454 | 13 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffff7 \| 0x80;` |
| FUN_00024558 | 0x24558 | 22 | read | `if ((*(uint *)(param_1 + 0x50) & 8) == 0) {` |
| FUN_000249e4 | 0x249e4 | 68 | write | `*(undefined4 *)(iVar6 + 0x50) = *(undefined4 *)(param_1 + 0x50);` |
| FUN_00025048 | 0x25048 | 30 | write | `*(undefined4 *)(param_1 + 0x54) = 0;` |
| FUN_00025c18 | 0x25c18 | 40 | read | `*(uint *)(iVar2 + 0x50) = *(uint *)(iVar2 + 0x50) \| 4;` |
| FUN_00026768 | 0x26768 | 23 | read | `*(uint *)(iVar2 + 0x50) = *(uint *)(iVar2 + 0x50) \| 4;` |
| FUN_0002685c | 0x2685c | 66 | read | `*(uint *)(iVar9 + 0x50) = *(uint *)(iVar9 + 0x50) \| 4;` |
| FUN_00026c68 | 0x26c68 | 20 | read | `((*(uint *)(param_1 + 0x50) & 4) == 0)) {` |
| FUN_00026e4c | 0x26e4c | 9 | read | `if ((*(uint *)(param_1 + 0x50) & 8) == 0) {` |
| FUN_00026e4c | 0x26e4c | 13 | read | `if ((*(int *)(iVar2 + 0x54) == 6) && (*(int *)(param_1 + 0xf4) != 0)) {` |
| FUN_00027a44 | 0x27a44 | 12 | read | `if (*(int *)(iVar1 + 0x54) != param_2) {` |
| FUN_000280a0 | 0x280a0 | 16 | read | `iVar3 = *(int *)(param_1 + 0x54);` |
| FUN_000280a0 | 0x280a0 | 28 | read | `iVar3 = *(int *)(param_1 + 0x58);` |
| FUN_000283f8 | 0x283f8 | 58 | write | `*(ushort *)(param_1 + 0x4c + uVar4 * 2) = *puVar7;` |
| FUN_000283f8 | 0x283f8 | 69 | write | `*(ushort *)(param_1 + 0x50 + iVar5) = *puVar7;` |
| FUN_00028724 | 0x28724 | 24 | read | `if (*(int *)(param_1 + 0x54) == 6) {` |
| FUN_00028724 | 0x28724 | 28 | read | `if ((*(uint *)(param_2 + 0x50) & 4) != 0) {` |
| FUN_00028724 | 0x28724 | 31 | read | `if ((*(uint *)(param_2 + 0x50) & 1) != 0) {` |
| FUN_00028724 | 0x28724 | 38 | read | `if ((*(int *)(param_1 + 0x58) == 3) && (*(int *)(param_2 + 0x300) != 1)) {` |
| FUN_00028724 | 0x28724 | 61 | read | `if (*(uint *)(param_1 + 0x58) < 2) {` |
| FUN_00028724 | 0x28724 | 66 | read | `else if ((*(int *)(param_1 + 0x58) == 2) \|\| (*(int *)(param_1 + 0x58) == 0)) {` |
| FUN_00028724 | 0x28724 | 78 | read | `iVar6 = *(int *)(param_1 + 0x54);` |
| FUN_00028724 | 0x28724 | 86 | read | `else if (*(int *)(param_1 + 0x54) != 1) {` |
| FUN_00028c60 | 0x28c60 | 26 | read | `*(undefined4 *)(iVar3 + 0x54) = 0;` |
| FUN_00028c60 | 0x28c60 | 27 | read | `*(undefined4 *)(iVar3 + 0x58) = 0;` |
| FUN_00028d10 | 0x28d10 | 19 | read | `*(undefined4 *)(iVar1 + 0x54) = 5;` |
| FUN_00028e58 | 0x28e58 | 9 | read | `if (*(int *)(param_1 + 0x54) == 2) {` |
| FUN_00028e58 | 0x28e58 | 13 | read | `if (*(int *)(param_1 + 0x54) != 3) {` |
| FUN_00028ef4 | 0x28ef4 | 11 | read | `if ((iVar2 != -1) && (*(int *)(param_1 + 0x54) != 6)) {` |
| FUN_00028fc4 | 0x28fc4 | 56 | read | `if (((_DAT_8004d6fa == 2) && (*(int *)(param_1 + 0x54) == 6)) &&` |
| FUN_000296e8 | 0x296e8 | 22 | read | `piVar6 = (int *)(iVar3 + 0x58);` |
| FUN_00029910 | 0x29910 | 24 | read | `iVar4 = *(int *)(uVar2 * 4 + iVar3 + 0x58);` |
| FUN_00029c24 | 0x29c24 | 77 | write | `*(uint *)(param_1 + 0x58 + uVar7 * 4) = iVar3 + (uint)*puVar9 * 0x18;` |
| FUN_0002a2d0 | 0x2a2d0 | 52 | read | `iVar6 = iVar6 + 0x4c;` |
| FUN_0002a498 | 0x2a498 | 45 | read | `iVar1 = func_0x00072348(*(undefined4 *)(param_1 + 0x58 + iVar1));` |
| FUN_0002a5f4 | 0x2a5f4 | 18 | read | `func_0x000725a8(*(undefined4 *)(param_1 + 0x58 + iVar1));` |
| FUN_0002ad60 | 0x2ad60 | 19 | read | `iVar4 = *(int *)(*(int *)(param_1 + iVar2 + 0x58) + 4);` |
| FUN_0002ad60 | 0x2ad60 | 20 | read | `iVar2 = *(int *)(iVar4 + 0x54);` |
| FUN_0002b2b8 | 0x2b2b8 | 80 | read | `piVar7 = (int *)(uVar6 * 4 + 0x58 + param_1);` |
| FUN_0002b7d0 | 0x2b7d0 | 29 | read | `if (*(int *)(*(int *)(*(int *)(param_1 + 0x58) + 4) + 0x54) == 5) {` |
| FUN_0002b7d0 | 0x2b7d0 | 38 | read | `iVar7 = *(int *)(*(int *)(param_1 + 0x58 + uVar3 * 4) + 4);` |
| FUN_0002b7d0 | 0x2b7d0 | 40 | read | `} while (*(int *)(iVar7 + 0x54) != 5);` |
| FUN_0002c4b0 | 0x2c4b0 | 30 | write | `*(undefined4 *)(param_1 + 0x50) = param_2[3];` |
| FUN_0002c4b0 | 0x2c4b0 | 75 | read | `if (*(int *)(param_1 + 0x50) != 0) {` |
| FUN_0002c4b0 | 0x2c4b0 | 81 | read | `} while (uVar8 < *(uint *)(param_1 + 0x50));` |
| FUN_0002c964 | 0x2c964 | 116 | read | `if ((((uVar4 & 1) != 0) && (*(int *)(iVar7 + 0x54) != 0)) && (*(int *)(iVar7 + 0x10) == 0)) {` |
| FUN_0002da08 | 0x2da08 | 27 | read | `if (*(int *)(param_1 + 0x50) == 0) {` |
| FUN_0002dbc0 | 0x2dbc0 | 87 | read | `uVar7 = *(uint *)(param_1 + 0x50);` |
| FUN_0002f988 | 0x2f988 | 72 | write | `*(short *)(param_1 + 0x584) = (short)uVar5 + *(short *)(param_1 + 8);` |
| FUN_0002f988 | 0x2f988 | 73 | write | `*(short *)(param_1 + 0x586) = (short)uVar6 + *(short *)(param_1 + 10);` |
| FUN_0002f988 | 0x2f988 | 74 | write | `*(short *)(param_1 + 0x588) = (short)uVar7 + *(short *)(param_1 + 0xc);` |
| FUN_0002f988 | 0x2f988 | 96 | write | `*(short *)(param_1 + 0x58c) = (short)uVar5 + *(short *)(param_1 + 8);` |
| FUN_0002f988 | 0x2f988 | 97 | write | `*(short *)(param_1 + 0x58e) = (short)uVar6 + *(short *)(param_1 + 10);` |
| FUN_0002ffac | 0x2ffac | 185 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) & 0xffffffef;` |
| FUN_0002ffac | 0x2ffac | 194 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) \| 0x10;` |
| FUN_0002ffac | 0x2ffac | 201 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) \| 0x10;` |
| FUN_00030be8 | 0x30be8 | 42 | read | `((*(uint *)(iVar2 + 0x50) & 0x20000) != 0)) {` |
| FUN_00031048 | 0x31048 | 32 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x4c))` |
| FUN_00031048 | 0x31048 | 50 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x4c))` |
| FUN_00031048 | 0x31048 | 76 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x4c))` |
| FUN_00031480 | 0x31480 | 10 | read | `(((*(uint *)(param_2 + 0x50) & 4) == 0 &&` |
| FUN_00031b38 | 0x31b38 | 64 | read | `iVar7 = iVar2 + 0x54;` |
| FUN_00031b38 | 0x31b38 | 96 | read | `iVar11 = FUN_00023358(iVar2 + 0x5a);` |
| FUN_00031b38 | 0x31b38 | 106 | read | `iVar2 = FUN_00023358(iVar2 + 0x5a);` |
| FUN_00035cc0 | 0x35cc0 | 134 | read | `if ((*(uint *)(unaff_s2 + 0x50) & 0x20000) == 0) {` |
| FUN_00035cc0 | 0x35cc0 | 136 | read | `*(uint *)(unaff_s2 + 0x50) = *(uint *)(unaff_s2 + 0x50) \| 0x20000;` |
| FUN_00036c34 | 0x36c34 | 60 | read | `iVar12 = *(int *)(iVar12 + 0x58)) {` |
| FUN_00039dac | 0x39dac | 14 | write | `*(undefined4 *)(param_1 + 0x520) = 0;` |
| FUN_00039dac | 0x39dac | 28 | write | `*(undefined4 *)(param_1 + 0x5ac) = 0;` |
| FUN_00039dac | 0x39dac | 31 | write | `*(int *)(param_1 + 0x5a8) = param_1;` |
| FUN_0003a25c | 0x3a25c | 19 | read | `puVar2 = (undefined4 *)(param_1 + 0x544);` |
| FUN_0003a25c | 0x3a25c | 35 | write | `*(undefined4 *)(param_1 + 0x524) = *(undefined4 *)(param_1 + 0x39c);` |
| FUN_0003a25c | 0x3a25c | 36 | write | `*(undefined4 *)(param_1 + 0x528) = *(undefined4 *)(param_1 + 0x3a0);` |
| FUN_0003a25c | 0x3a25c | 37 | write | `*(undefined4 *)(param_1 + 0x52c) = *(undefined4 *)(param_1 + 0x3a4);` |
| FUN_0003a25c | 0x3a25c | 42 | write | `*(undefined4 *)(param_1 + 0x540) = *(undefined4 *)(param_1 + 0x3b8);` |
| FUN_0003a7d0 | 0x3a7d0 | 19 | read | `iVar1 = *(int *)(param_1 + 0x520);` |
| FUN_0003b264 | 0x3b264 | 142 | read | `if (((*(uint *)(iVar10 + 0x50) & 4) != 0) \|\| ((*(uint *)(iVar10 + 0x50) & 1) != 0)) {` |
| FUN_0003cdf0 | 0x3cdf0 | 15 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003cdf0 | 0x3cdf0 | 16 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) & 0xfffffffe;` |
| FUN_0003cdf0 | 0x3cdf0 | 18 | read | `*(uint *)(iVar1 + 0x50) = *(uint *)(iVar1 + 0x50) & 0xfffffdff;` |
| FUN_0003cdf0 | 0x3cdf0 | 20 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) = *(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x10` |
| FUN_0003cee4 | 0x3cee4 | 45 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) & 0xffffffef;` |
| FUN_0003d0e8 | 0x3d0e8 | 45 | read | `(iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x58),*(undefined2 *)(iVar6 + 0xb8))` |
| FUN_0003d0e8 | 0x3d0e8 | 48 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) \| 0x10;` |
| FUN_0003dd3c | 0x3dd3c | 47 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 1;` |
| FUN_0003df28 | 0x3df28 | 55 | read | `*(uint *)(iVar8 + 0x50) = *(uint *)(iVar8 + 0x50) & 0xffffffef;` |
| FUN_0003df28 | 0x3df28 | 56 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003df28 | 0x3df28 | 57 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x200;` |
| FUN_0003df28 | 0x3df28 | 97 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffffe;` |
| FUN_0003df28 | 0x3df28 | 104 | read | `*(uint *)(iVar8 + 0x50) = *(uint *)(iVar8 + 0x50) & 0xffffffef;` |
| FUN_0003df28 | 0x3df28 | 105 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003df28 | 0x3df28 | 106 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x200;` |
| FUN_0003e810 | 0x3e810 | 16 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) \| 1;` |
| FUN_0003e810 | 0x3e810 | 43 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) & 0xfffffdff;` |
| FUN_0003e810 | 0x3e810 | 45 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003e810 | 0x3e810 | 46 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x10;` |
| FUN_0003e810 | 0x3e810 | 47 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003e810 | 0x3e810 | 48 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) & 0xfffffffe;` |
| FUN_0003e838 | 0x3e838 | 19 | read | `*(uint *)(in_v1 + 0x50) = in_v0 \| 1;` |
| FUN_0003e838 | 0x3e838 | 48 | read | `*(uint *)(iVar1 + 0x50) = *(uint *)(iVar1 + 0x50) & 0xfffffdff;` |
| FUN_0003e838 | 0x3e838 | 50 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) =` |
| FUN_0003e838 | 0x3e838 | 51 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) \| 0x10;` |
| FUN_0003e838 | 0x3e838 | 52 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) =` |
| FUN_0003e838 | 0x3e838 | 53 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) & 0xfffffffe;` |
| FUN_0003f1dc | 0x3f1dc | 21 | read | `((uVar3 == 0x57 \|\| (*(int *)(iVar2 + 0x58) == 0))))));` |
| FUN_0003f1dc | 0x3f1dc | 28 | read | `*(short *)(*(int *)(iVar2 + 0x48) + 6) = *(short *)(iVar2 + 0x4e) + (short)_DAT_800bc944;` |
| FUN_0003f1dc | 0x3f1dc | 34 | read | `} while (0xd < *(ushort *)(iVar2 + 0x4e));` |
| FUN_0003f1dc | 0x3f1dc | 37 | read | `(**(code **)((uint)*(ushort *)(iVar2 + 0x4e) * 4 + -0x7ff38cec))();` |
| FUN_0003fbb0 | 0x3fbb0 | 179 | read | `*(undefined4 *)(_DAT_8011a3dc + 0x58) = 0;` |
| FUN_0003fbb0 | 0x3fbb0 | 183 | read | `*(undefined4 *)(_DAT_8011a3e8 + 0x58) = 0;` |
| FUN_0003fbb0 | 0x3fbb0 | 188 | read | `*(undefined4 *)(*piVar8 + 0x58) = 0;` |
| FUN_000401ec | 0x401ec | 11 | read | `*(undefined4 *)(_DAT_8011a3dc + 0x58) = 0;` |
| FUN_000401ec | 0x401ec | 15 | read | `*(undefined4 *)(_DAT_8011a3e8 + 0x58) = 0;` |
| FUN_000401ec | 0x401ec | 20 | read | `*(undefined4 *)(*piVar1 + 0x58) = 0;` |
| FUN_000402e0 | 0x402e0 | 34 | read | `*(undefined2 *)(param_3 + 0x3c) = *(undefined2 *)(param_4 + 0x4c);` |
| FUN_000402e0 | 0x402e0 | 35 | read | `*(undefined2 *)(param_3 + 0x3e) = *(undefined2 *)(param_4 + 0x50);` |
| FUN_000402e0 | 0x402e0 | 37 | read | `if (*(int *)(param_4 + 0x54) != 0) {` |
| FUN_000402e0 | 0x402e0 | 41 | read | `*(short *)(param_3 + 0x40) = *(short *)(param_4 + 0x58) << 6;` |
| FUN_000402e0 | 0x402e0 | 42 | read | `*(undefined2 *)(param_3 + 0x50) = *(undefined2 *)(param_4 + 0x5c);` |
| FUN_000402e0 | 0x402e0 | 43 | read | `*(undefined4 *)(param_3 + 0x54) = *(undefined4 *)(param_4 + 0x60);` |
| FUN_0004033c | 0x4033c | 25 | read | `*(undefined2 *)(param_3 + 0x3c) = *(undefined2 *)(param_4 + 0x4c);` |
| FUN_0004033c | 0x4033c | 26 | read | `*(undefined2 *)(param_3 + 0x3e) = *(undefined2 *)(param_4 + 0x50);` |
| FUN_0004033c | 0x4033c | 28 | read | `if (*(int *)(param_4 + 0x54) != 0) {` |
| FUN_0004033c | 0x4033c | 32 | read | `*(short *)(param_3 + 0x40) = *(short *)(param_4 + 0x58) << 6;` |
| FUN_0004033c | 0x4033c | 33 | read | `*(undefined2 *)(param_3 + 0x50) = *(undefined2 *)(param_4 + 0x5c);` |
| FUN_0004033c | 0x4033c | 34 | read | `*(undefined4 *)(param_3 + 0x54) = *(undefined4 *)(param_4 + 0x60);` |
| FUN_0004050c | 0x4050c | 19 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 0x18;` |
| FUN_00040a4c | 0x40a4c | 93 | read | `(iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x58),uVar3);` |
| FUN_00040a4c | 0x40a4c | 98 | read | `(**(code **)(iVar6 + 0x5c))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar6 + 0x58),uVar3);` |
| FUN_00040a4c | 0x40a4c | 111 | read | `(**(code **)(iVar6 + 0x4c))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar6 + 0x48),999);` |
| FUN_00040a98 | 0x40a98 | 86 | read | `(iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x58),uVar3);` |
| FUN_00040a98 | 0x40a98 | 96 | read | `(*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x58),uVar3);` |
| FUN_00040a98 | 0x40a98 | 109 | read | `(**(code **)(iVar6 + 0x4c))` |
| FUN_000412d8 | 0x412d8 | 16 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 0x10;` |
| FUN_000412d8 | 0x412d8 | 89 | read | `*(short *)(*(int *)(param_1 + 0xc0) + 0x4c);` |
| FUN_000412d8 | 0x412d8 | 100 | read | `(int)*(short *)(*(int *)(param_1 + 0xc0) + 0x4c))) {` |
| FUN_000412d8 | 0x412d8 | 125 | read | `if ((*(uint *)(*(int *)(param_1 + 0xd4) + 0x50) & 0x400) != 0) {` |
| FUN_000412d8 | 0x412d8 | 150 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;` |
| FUN_00041a48 | 0x41a48 | 21 | read | `iVar4 = iVar2 + 0x54;` |
| FUN_00041ba4 | 0x41ba4 | 44 | read | `iVar3 = FUN_00023210(0x800c7840,iVar5 + 0x54,6);` |
| FUN_00041ba4 | 0x41ba4 | 71 | read | `iVar3 = FUN_00023210(0x800c7848,iVar5 + 0x54,6);` |
| FUN_00041ba4 | 0x41ba4 | 100 | read | `iVar4 = FUN_00023210(0x800c7850,iVar10 + 0x54,4);` |
| FUN_00041ba4 | 0x41ba4 | 108 | read | `iVar4 = FUN_00023210(0x800c7858,iVar10 + 0x54,4);` |
| FUN_00041edc | 0x41edc | 18 | read | `iVar3 = FUN_00023110(0x800c7860,iVar4 + 0x54);` |
| FUN_00041edc | 0x41edc | 24 | read | `iVar3 = FUN_00023110(0x800c786c,iVar4 + 0x54);` |
| FUN_00043748 | 0x43748 | 40 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 53 | read | `if (((cVar1 == '\x06') && ((*(uint *)(param_1 + 0x50) & 4) != 0)) &&` |
| FUN_000438fc | 0x438fc | 69 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 96 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 101 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 122 | read | `(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58));` |
| FUN_000438fc | 0x438fc | 142 | read | `if ((*(uint *)(param_1 + 0x50) & 4) == 0) {` |
| FUN_000438fc | 0x438fc | 161 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 284 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;` |
| FUN_00043a94 | 0x43a94 | 9 | read | `*(uint *)(unaff_s3 + 0x50) = *(uint *)(unaff_s3 + 0x50) & 0xffffffef;` |
| FUN_000443b8 | 0x443b8 | 82 | read | `param_2 = *(int *)(param_2 + 0x58);` |
| FUN_00044a14 | 0x44a14 | 21 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00044a14 | 0x44a14 | 148 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffdff \| 0x40;` |
| FUN_00044f80 | 0x44f80 | 56 | read | `if ((*(uint *)(param_1 + 0x50) & 4) != 0) {` |
| FUN_00044f80 | 0x44f80 | 59 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00044f80 | 0x44f80 | 85 | read | `(iVar12 = -(int)*(short *)(param_1 + 0x3e), (*(uint *)(param_1 + 0x50) & 4) == 0)) {` |
| FUN_00045a00 | 0x45a00 | 14 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00045a80 | 0x45a80 | 33 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00045a80 | 0x45a80 | 52 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046024 | 0x46024 | 38 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046024 | 0x46024 | 40 | read | `if (((*(uint *)(param_1 + 0x50) & 4) == 0) &&` |
| FUN_00046024 | 0x46024 | 43 | read | `if ((*(uint *)(param_1 + 0x50) & 0x20) != 0) {` |
| FUN_00046024 | 0x46024 | 144 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046498 | 0x46498 | 10 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046498 | 0x46498 | 13 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000475dc | 0x475dc | 159 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;` |
| FUN_0004a058 | 0x4a058 | 22 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000153a0 | 0x153a0 | 70 | read | `if ((*(char *)(param_1 + 0x50) != '\0') && (uVar6 = 0, *(char *)(param_1 + 0x37) == '\0')) {` |
| FUN_00017510 | 0x17510 | 31 | write | `*(undefined1 *)(param_1 + 0x58) = 1;` |
| FUN_00017a6c | 0x17a6c | 75 | read | `(*(char *)(param_1 + 0x50) == '\0')) \|\| (*(char *)(param_1 + 0xe8) != cVar1)) {` |
| FUN_00017e54 | 0x17e54 | 62 | write | `*(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1;` |
| FUN_00002f34 | 0x2f34 | 96 | read | `(iVar9,uVar11 + *(int *)(uVar11 + 0x40) * 8 + 0x4c);` |
| FUN_00003a64 | 0x3a64 | 69 | read | `if ((*(char *)(iVar3 + 0x50) != '\0') && (iVar4 = 0, *(char *)(iVar3 + 0x36) == '\0')) {` |
| FUN_00008528 | 0x8528 | 129 | read | `iVar4 = *(int *)(iVar2 + 0x50) * 3;` |
| FUN_00008528 | 0x8528 | 134 | read | `*(short *)(*(int *)(iVar3 + 0xc) + 2) = (short)*(undefined4 *)(iVar2 + 0x54);` |
| FUN_00008528 | 0x8528 | 137 | read | `FUN_00031978(iVar4,iVar3,*(undefined4 *)(iVar2 + 0x48),*(undefined4 *)(iVar2 + 0x4c));` |
| FUN_000090e0 | 0x90e0 | 58 | read | `iVar5 = *(int *)(iVar4 + 0x50) * 3;` |
| FUN_000090e0 | 0x90e0 | 63 | read | `*(short *)(*(int *)(iVar3 + 0xc) + 2) = (short)*(undefined4 *)(iVar4 + 0x54);` |
| FUN_000090e0 | 0x90e0 | 66 | read | `FUN_00031978(iVar5,iVar3,*(undefined4 *)(iVar4 + 0x48),*(undefined4 *)(iVar4 + 0x4c));` |
| FUN_00009b18 | 0x9b18 | 16 | read | `iVar3 = iVar3 + 0x58;` |
| FUN_0000a234 | 0xa234 | 24 | read | `iVar3 = *param_1 + 0x4c;` |
| FUN_0000af3c | 0xaf3c | 28 | read | `FUN_0001e7b4(param_3 + 0x54,param_2,auStack_20);` |
| FUN_0000d7d8 | 0xd7d8 | 11 | read | `iVar2 = iVar1 - *(short *)(iVar3 + 0x54);` |
| FUN_0000d7d8 | 0xd7d8 | 13 | read | `if (iVar1 <= *(short *)(iVar3 + 0x54)) {` |
| FUN_0000d7d8 | 0xd7d8 | 19 | read | `} while (iVar1 < *(short *)(iVar3 + 0x54));` |
| FUN_0000d7d8 | 0xd7d8 | 20 | read | `*(int *)(iVar3 + 0x90) = iVar1 - *(short *)(iVar3 + 0x54);` |
| FUN_0000d7d8 | 0xd7d8 | 24 | read | `if (0 < *(short *)(iVar3 + 0x52)) {` |
| FUN_0000d7d8 | 0xd7d8 | 25 | read | `*(short *)(iVar3 + 0x52) = *(short *)(iVar3 + 0x52) + -1;` |
| FUN_0000d7d8 | 0xd7d8 | 29 | read | `if (*(short *)(iVar3 + 0x52) == 0) {` |
| FUN_0000d7d8 | 0xd7d8 | 30 | read | `*(undefined2 *)(iVar3 + 0x52) = *(undefined2 *)(iVar3 + 0x54);` |
| FUN_0000e5f0 | 0xe5f0 | 23 | read | `*(undefined2 *)((int)puVar1 + 0x5a),1);` |
| FUN_0000eb10 | 0xeb10 | 38 | read | `*(undefined2 *)(puVar4 + 0x15) = *(undefined2 *)((int)puVar4 + 0x56);` |
| FUN_0000ef68 | 0xef68 | 11 | read | `*(undefined2 *)(iVar1 + 0x58) = param_3;` |
| FUN_0000ef68 | 0xef68 | 12 | read | `*(undefined2 *)(iVar1 + 0x5a) = param_4;` |
| FUN_0000eff8 | 0xeff8 | 11 | read | `*(undefined2 *)(iVar1 + 0x58) = param_2;` |
| FUN_0000eff8 | 0xeff8 | 12 | read | `*(undefined2 *)(iVar1 + 0x5a) = param_3;` |
| FUN_0000f060 | 0xf060 | 11 | read | `*(undefined2 *)(iVar1 + 0x58) = param_3;` |
| FUN_0000f060 | 0xf060 | 12 | read | `*(undefined2 *)(iVar1 + 0x5a) = param_4;` |
| FUN_00010944 | 0x10944 | 23 | read | `uVar7 = (uVar6 * *(ushort *)(iVar5 + 0x58)) / 0x7f;` |
| FUN_00010944 | 0x10944 | 24 | read | `uVar6 = (uVar6 * *(ushort *)(iVar5 + 0x5a)) / 0x7f;` |
| FUN_000114a4 | 0x114a4 | 19 | read | `*(undefined2 *)(iVar8 + 0x58) = param_2;` |
| FUN_000114a4 | 0x114a4 | 20 | read | `*(undefined2 *)(iVar8 + 0x5a) = param_3;` |
| FUN_000114a4 | 0x114a4 | 21 | read | `if (0x7e < *(ushort *)(iVar8 + 0x58)) {` |
| FUN_000114a4 | 0x114a4 | 22 | read | `*(undefined2 *)(iVar8 + 0x58) = 0x7f;` |
| FUN_000114a4 | 0x114a4 | 24 | read | `if (0x7e < *(ushort *)(iVar8 + 0x5a)) {` |
| FUN_000114a4 | 0x114a4 | 25 | read | `*(undefined2 *)(iVar8 + 0x5a) = 0x7f;` |
| FUN_000114a4 | 0x114a4 | 43 | read | `uVar5 = (uVar6 * *(ushort *)(iVar8 + 0x58)) / 0x7f;` |
| FUN_000114a4 | 0x114a4 | 45 | read | `uVar6 = (uVar6 * *(ushort *)(iVar8 + 0x5a)) / 0x7f;` |
| FUN_0001a348 | 0x1a348 | 29 | read | `*(undefined2 *)(unaff_s0 + 0x54) = 0;` |
| FUN_0001a348 | 0x1a348 | 30 | read | `*(undefined2 *)(unaff_s0 + 0x4c) = 0;` |
| FUN_0001a348 | 0x1a348 | 36 | read | `*(undefined2 *)(unaff_s0 + 0x58) = uVar2;` |
| FUN_0001a348 | 0x1a348 | 37 | read | `*(undefined2 *)(unaff_s0 + 0x50) = uVar2;` |
| FUN_0001a348 | 0x1a348 | 38 | read | `*(undefined2 *)(unaff_s0 + 0x5a) = 0xf0;` |
| FUN_0001a348 | 0x1a348 | 39 | read | `*(undefined2 *)(unaff_s0 + 0x52) = 0xf0;` |
| FUN_0001a348 | 0x1a348 | 40 | read | `*(undefined2 *)(unaff_s0 + 0x4e) = 0;` |
| FUN_0001a348 | 0x1a348 | 41 | read | `*(undefined2 *)(unaff_s0 + 0x56) = 0xf0;` |
| FUN_0001a3b0 | 0x1a3b0 | 16 | read | `*(undefined2 *)(unaff_s0 + 0x58) = uVar2;` |
| FUN_0001a3b0 | 0x1a3b0 | 17 | read | `*(undefined2 *)(unaff_s0 + 0x50) = uVar2;` |
| FUN_0001a3b0 | 0x1a3b0 | 18 | read | `*(undefined2 *)(unaff_s0 + 0x5a) = 0xf0;` |
| FUN_0001a3b0 | 0x1a3b0 | 19 | read | `*(undefined2 *)(unaff_s0 + 0x52) = 0xf0;` |
| FUN_0001a3b0 | 0x1a3b0 | 20 | read | `*(undefined2 *)(unaff_s0 + 0x4e) = 0;` |
| FUN_0001a3b0 | 0x1a3b0 | 21 | read | `*(undefined2 *)(unaff_s0 + 0x56) = 0xf0;` |
| FUN_0001a674 | 0x1a674 | 20 | read | `*(undefined2 *)(unaff_s0 + 0x58) = uVar1;` |
| FUN_0001a674 | 0x1a674 | 21 | read | `*(undefined2 *)(unaff_s0 + 0x50) = uVar1;` |
| FUN_0001a674 | 0x1a674 | 24 | read | `*(undefined2 *)(unaff_s0 + 0x5a) = uVar1;` |
| FUN_0001a674 | 0x1a674 | 25 | read | `*(undefined2 *)(unaff_s0 + 0x52) = uVar1;` |
| FUN_0001a804 | 0x1a804 | 28 | read | `(iVar3,param_1 + *(int *)(param_1 + 0x40) * 8 + 0x4c);` |
| FUN_0001a804 | 0x1a804 | 33 | read | `FUN_00018878(auStack_14,(int)*(short *)(iVar4 + 0x4c),(int)*(short *)(iVar4 + 0x4e),` |
| FUN_0001aaec | 0x1aaec | 14 | read | `*(undefined2 *)((int)unaff_s0 + (param_1 - unaff_s0[0x10]) * 8 + 0x4e);` |
| FUN_0001abfc | 0x1abfc | 11 | read | `(int)*(short *)(iVar1 + 0x4c) + (int)*(short *)(iVar1 + 0x50)) {` |
| FUN_0001b220 | 0x1b220 | 69 | read | `if ((*(char *)(param_1 + 0x50) != '\0') && (uVar6 = 0, *(char *)(param_1 + 0x36) == '\0')) {` |
| FUN_0001b264 | 0x1b264 | 61 | read | `if ((*(char *)(unaff_s0 + 0x50) != '\0') && (uVar4 = 0, *(char *)(unaff_s0 + 0x36) == '\0')) {` |
| FUN_0001b364 | 0x1b364 | 36 | read | `if ((*(char *)(unaff_s0 + 0x50) != '\0') && (uVar3 = 0, *(char *)(unaff_s0 + 0x36) == '\0')) {` |
| FUN_0001c2b4 | 0x1c2b4 | 15 | write | `*(undefined1 *)(param_1 + 0x52) = param_3;` |
| FUN_0001cfcc | 0x1cfcc | 29 | write | `*(undefined1 *)(param_1 + 0x58) = 1;` |
| FUN_0001d504 | 0x1d504 | 32 | read | `(*(char *)(param_1 + 0x50) == '\0')))) \|\|` |
| FUN_0001d7b8 | 0x1d7b8 | 10 | write | `*(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1;` |
| FUN_00021974 | 0x21974 | 13 | read | `*(undefined4 *)(unaff_s0 + 0x50) = 0;` |
| FUN_00021974 | 0x21974 | 14 | read | `*(undefined4 *)(unaff_s0 + 0x4c) = 0;` |
| FUN_00021b4c | 0x21b4c | 9 | read | `*(undefined4 *)(unaff_s0 + 0x50) = in_v0;` |
| FUN_000233dc | 0x233dc | 9 | read | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x8c),param_2 + 0x5464);` |
| FUN_00023d74 | 0x23d74 | 36 | read | `FUN_0001a4a0(&local_8,0x23a,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 48 | read | `FUN_0001a4a0(&local_8,0x251,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 60 | read | `FUN_0001a4a0(&local_8,0x25d,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 72 | read | `FUN_0001a4a0(&local_8,0x26f,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 84 | read | `FUN_0001a4a0(&local_8,0x27b,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 96 | read | `FUN_0001a4a0(&local_8,0x28c,iVar1 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 21 | read | `FUN_0001a4a0(param_1,0x25d,in_hi * 2 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 34 | read | `FUN_0001a4a0(&stack0x00000020,0x26f,iVar1 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 46 | read | `FUN_0001a4a0(&stack0x00000020,0x27b,iVar1 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 58 | read | `FUN_0001a4a0(&stack0x00000020,0x28c,iVar1 + 0x58);` |
| FUN_000240a0 | 0x240a0 | 24 | read | `FUN_0001a4a0(&stack0x00000020,0x28c,iVar1 + 0x58);` |
| FUN_00000a2c | 0xa2c | 28 | read | `func_0x0002080c(iVar1 + *(int *)(iVar1 + 0x50));` |
| FUN_00001f4c | 0x1f4c | 28 | read | `func_0x000cce8c(0x106,0,sVar1 + 0xc0,sVar2 + 0x50,iVar3,0,0,0);` |
| FUN_00001f4c | 0x1f4c | 29 | read | `func_0x000cce8c(0x108,0,sVar5,sVar2 + 0x50,iVar3,0,0,0);` |
| FUN_00001f4c | 0x1f4c | 34 | read | `func_0x000cce8c(0x107,0,sVar4,sVar2 + 0x50,iVar3,0,0,0);` |
| FUN_00004328 | 0x4328 | 313 | read | `func_0x000cce8c(0x2b,0,iVar22 + 200U & 0xffff,iVar7 + 0x54U & 0xffff,0x808080,0,0,0);` |
| FUN_00005954 | 0x5954 | 405 | read | `func_0x000cce8c(0xfe,1,*psVar21 + -0x38,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,0x808080,0,0,` |
| FUN_00005954 | 0x5954 | 407 | read | `func_0x000cce8c(0xff,1,*psVar21 + 0x88,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,0x808080,0,0,0` |
| FUN_00005954 | 0x5954 | 409 | read | `func_0x000cce8c(0x100,0,*psVar21 + -0x38,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,` |
| FUN_00005954 | 0x5954 | 411 | read | `func_0x000cce8c(0x101,0,*psVar21 + 0x88,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,0x808080,0,0,` |
| FUN_00006f28 | 0x6f28 | 13 | read | `,(int)((*(ushort *)(&DAT_800cf4de + iVar1) + 0x50) * 0x10000) >> 0x10,` |
| FUN_00002724 | 0x2724 | 68 | read | `if ((((iVar9 == 0) \|\| (*(int *)(iVar9 + 0x48) != 3)) \|\| (*(int *)(iVar9 + 0x50) != 0)) \|\|` |
| FUN_00003f60 | 0x3f60 | 28 | read | `func_0x000c9b8c(iVar2 + *(int *)(iVar2 + 0x50));` |
| FUN_00004fcc | 0x4fcc | 13 | write | `*(undefined2 **)(param_1 + 0x4c) = param_2;` |
| FUN_00004fcc | 0x4fcc | 42 | write | `*(undefined4 *)(param_1 + 0x50) = 0;` |
| FUN_00004fcc | 0x4fcc | 43 | read | `iVar4 = *(int *)((uint)**(ushort **)(param_1 + 0x4c) * 4 + -0x7ff30500);` |
| FUN_000056dc | 0x56dc | 11 | read | `*(short *)(*(int *)(param_1 + 0x4c) + 2),(undefined2)local_10[0]) &` |
| FUN_000057cc | 0x57cc | 26 | read | `(*(ushort **)(param_1 + 0x4c))[1],(undefined2)local_30) & 0xfffffff;` |
| FUN_000057cc | 0x57cc | 31 | read | `(*(int *)((uint)**(ushort **)(param_1 + 0x4c) * 4 + -0x7ff30500) != 0)) {` |
| FUN_000059f4 | 0x59f4 | 19 | read | `iVar3 = iVar3 + 0x54;` |
| FUN_00005de4 | 0x5de4 | 7 | read | `puVar1 = *(undefined4 **)(param_1 + 0x50);` |
| FUN_00005de4 | 0x5de4 | 16 | write | `*(undefined4 *)(param_1 + 0x50) = 0;` |
| FUN_00005e70 | 0x5e70 | 27 | write | `*(int *)(param_1 + 0x4c) = param_2;` |
| FUN_00005e70 | 0x5e70 | 49 | write | `*(undefined4 *)(param_1 + 0x50) = 0;` |
| FUN_00005e70 | 0x5e70 | 58 | write | `*(undefined4 *)(param_1 + 0x54) = uVar4;` |
| FUN_00005e70 | 0x5e70 | 82 | write | `*(undefined4 *)(param_1 + 0x54) = uVar4;` |
| FUN_000063c4 | 0x63c4 | 17 | read | `psVar1 = *(short **)(param_1 + 0x4c);` |
| FUN_000063c4 | 0x63c4 | 45 | read | `if (*(int **)(param_1 + 0x50) != (int *)0x0) {` |
| FUN_000063c4 | 0x63c4 | 46 | read | `func_0x00098a7c(*(undefined4 *)(**(int **)(param_1 + 0x50) + 0x24),puVar3,0,2,` |
| FUN_000063c4 | 0x63c4 | 51 | read | `func_0x0009af10(puVar3,param_1 + 0x38,*(undefined4 *)(param_1 + 0x54));` |
| FUN_0000652c | 0x652c | 51 | read | `uVar1 = *(ushort *)(*(int *)(param_1 + 0x4c) + 0x24);` |
| FUN_0000652c | 0x652c | 55 | read | `*(short *)(*(int *)(param_1 + 0x44) + 10) + *(short *)(*(int *)(param_1 + 0x4c) + 0x24);` |
| FUN_00006ec4 | 0x6ec4 | 19 | read | `iVar3 = iVar3 + 0x58;` |
| FUN_000072b4 | 0x72b4 | 40 | read | `*(undefined2 *)((uint)*(ushort *)(param_1 + 0x1fe) * 0x2c + param_1 + 0x5a);` |
| FUN_00008198 | 0x8198 | 71 | read | `if (*(short *)(iVar1 * 0x10 + uVar5 * 0xc + param_1 + 0x5a) != *(short *)(param_1 + 0x202)) {` |
| FUN_00008198 | 0x8198 | 83 | read | `if (*(short *)(uVar2 * 0x2c + param_1 + 0x5a) != *(short *)(param_1 + 0x202)) {` |
| FUN_00008198 | 0x8198 | 92 | read | `} while (*(short *)(uVar2 * 0x2c + param_1 + 0x5a) != *(short *)(param_1 + 0x202));` |
| FUN_00009dfc | 0x9dfc | 28 | read | `func_0x0002080c(iVar1 + *(int *)(iVar1 + 0x50));` |
| FUN_00001998 | 0x1998 | 40 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) \| 0x10;` |
| FUN_00001998 | 0x1998 | 77 | read | `*(uint *)(_DAT_800bca78 + 0x50) = *(uint *)(_DAT_800bca78 + 0x50) & 0xffffffef;` |
| FUN_000010b8 | 0x10b8 | 143 | read | `iVar4 = *(int *)(iVar7 + 0x54);` |
| FUN_000010b8 | 0x10b8 | 150 | read | `iVar4 = *(int *)(iVar7 + 0x54);` |
| FUN_000010b8 | 0x10b8 | 184 | read | `if (((*(int *)(iVar3 + 0x54) != 0) && ((*(uint *)(iVar3 + 0xb8) & 0xb0) == 0)) &&` |
| FUN_00001c84 | 0x1c84 | 325 | read | `(**(code **)(*(int *)(iVar10 + 4) + 0x4c))` |
| FUN_00001c84 | 0x1c84 | 413 | read | `*(undefined2 *)(iVar10 + 0x4c) = 30000;` |
| FUN_00001c84 | 0x1c84 | 492 | read | `(*(int *)(iVar8 + 0x54) == 0)) {` |
| FUN_00001c84 | 0x1c84 | 589 | read | `*(uint *)(iVar10 + 0x50) = *(uint *)(iVar10 + 0x50) & 0xffffffef;` |
| FUN_00001c84 | 0x1c84 | 592 | read | `*(uint *)(iVar10 + 0x50) = *(uint *)(iVar10 + 0x50) \| 0x10;` |
| FUN_00001c84 | 0x1c84 | 620 | read | `(iVar10 + *(short *)(*(int *)(iVar10 + 4) + 0x58),` |
| FUN_00001c84 | 0x1c84 | 632 | read | `(iVar18 + *(short *)(*(int *)(iVar8 + -0x7feedcf0) + 0x58),` |
| FUN_00005e14 | 0x5e14 | 7 | read | `uVar1 = func_0x0006ea78(*(undefined4 *)(*(int *)(param_2 + 8) + 0x54),1);` |
| FUN_00005e50 | 0x5e50 | 15 | read | `uVar1 = func_0x0006c768(*(undefined4 *)(*(int *)(param_2 + 8) + 0x54),local_40);` |
| FUN_00006240 | 0x6240 | 5 | read | `func_0x000c994c(param_1,*(undefined4 *)(*(int *)(*(int *)(param_2 + 8) + 0x318) + 0x54));` |
| FUN_00006f90 | 0x6f90 | 11 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_00007084 | 0x7084 | 11 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_000071ec | 0x71ec | 12 | read | `(((((*(uint *)(iVar2 + 0xb8) & 8) == 0 && ((*(uint *)(iVar2 + 0x50) & 4) == 0)) &&` |
| FUN_00007710 | 0x7710 | 17 | read | `uVar2 = *(undefined2 *)(*(int *)(iVar1 + 0xc0) + 0x50);` |
| FUN_00007784 | 0x7784 | 17 | read | `uVar3 = *(undefined4 *)(*(int *)(iVar1 + 0xc0) + 0x54);` |
| FUN_00007a74 | 0x7a74 | 7 | read | `uVar1 = func_0x0006e55c(*(undefined4 *)(*(int *)(param_2 + 8) + 0x54));` |
| FUN_00007f10 | 0x7f10 | 17 | read | `} while ((*(int *)(aiStack_18[uVar2] + 0x54) != 6) \|\|` |
| FUN_0000852c | 0x852c | 16 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_00008610 | 0x8610 | 16 | read | `uVar3 = *(uint *)(iVar1 + 0x58);` |
| FUN_00008704 | 0x8704 | 15 | read | `uVar4 = *(uint *)(iVar5 + 0x58);` |
| FUN_00008704 | 0x8704 | 25 | read | `if (*(uint *)(iVar5 + 0x54) == 0) {` |
| FUN_00008704 | 0x8704 | 28 | read | `return uVar1 / *(uint *)(iVar5 + 0x54);` |
| FUN_0000888c | 0x888c | 12 | read | `if ((*(int *)(iVar2 + 0x300) == 2) && ((*(uint *)(iVar2 + 0x50) & 0x20a00) == 0)) {` |
| FUN_0000888c | 0x888c | 33 | read | `(iVar2 = (**(code **)(*(int *)(iVar1 + 0x10) + 0x4c))` |
| FUN_00009274 | 0x9274 | 8 | read | `(**(code **)(iVar1 + 0x54))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar1 + 0x50),0);` |
| FUN_000092cc | 0x92cc | 8 | read | `(**(code **)(iVar1 + 0x54))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar1 + 0x50),0);` |
| FUN_00009638 | 0x9638 | 8 | read | `(**(code **)(iVar1 + 0x54))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar1 + 0x50));` |
| FUN_0000c020 | 0xc020 | 27 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0000c020 | 0xc020 | 28 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0000c10c | 0xc10c | 18 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0000c10c | 0xc10c | 19 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0000c910 | 0xc910 | 18 | read | `if (((*(uint *)(param_2 + 0x50) & 1) == 0) \|\|` |
| FUN_0000c9fc | 0xc9fc | 22 | read | `if (((*(uint *)(param_2 + 0x50) & 1) == 0) \|\|` |
| FUN_0000d090 | 0xd090 | 22 | read | `(**(code **)(*(int *)(iVar1 + 0x10) + 0x54))` |
| FUN_0000d090 | 0xd090 | 23 | read | `(iVar1 + *(short *)(*(int *)(iVar1 + 0x10) + 0x50),0);` |
| FUN_0000d090 | 0xd090 | 36 | read | `(**(code **)(*(int *)(iVar3 + 0x10) + 0x54))` |
| FUN_0000d090 | 0xd090 | 37 | read | `(iVar3 + *(short *)(*(int *)(iVar3 + 0x10) + 0x50),0);` |
| FUN_0000d090 | 0xd090 | 38 | read | `(**(code **)(*(int *)(iVar1 + 0x10) + 0x54))` |
| FUN_0000d090 | 0xd090 | 39 | read | `(iVar1 + *(short *)(*(int *)(iVar1 + 0x10) + 0x50),0);` |
| FUN_0000d090 | 0xd090 | 43 | read | `(**(code **)(*(int *)(iVar3 + 0x10) + 0x54))(iVar3 + *(short *)(*(int *)(iVar3 + 0x10) + 0x50));` |
| FUN_0000d398 | 0xd398 | 44 | read | `for (iVar3 = *(int *)(iVar6 + iVar5 * 4 + 4); iVar3 != 0; iVar3 = *(int *)(iVar3 + 0x58))` |
| FUN_0000dbb4 | 0xdbb4 | 21 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0000dbb4 | 0xdbb4 | 22 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00010c1c | 0x10c1c | 30 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00010c1c | 0x10c1c | 31 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00010c1c | 0x10c1c | 59 | read | `if ((*(uint *)(iVar4 + 0x50) & 1) == 0) goto LAB_00010ea0;` |
| FUN_00010c1c | 0x10c1c | 71 | read | `if ((*(uint *)(iVar4 + 0x50) & 1) == 0) {` |
| FUN_0001150c | 0x1150c | 36 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001150c | 0x1150c | 37 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00011714 | 0x11714 | 44 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00011714 | 0x11714 | 45 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000119cc | 0x119cc | 47 | read | `uVar1 = *(ushort *)(iVar2 + 0x54);` |
| FUN_000119cc | 0x119cc | 66 | read | `iVar3 = func_0x0006c768(*(undefined4 *)(param_2 + 0x54),aiStack_58);` |
| FUN_000119cc | 0x119cc | 71 | read | `iVar9 = *(int *)(iVar9 + 0x58)) {` |
| FUN_000119cc | 0x119cc | 73 | read | `uVar7 = *(uint *)(iVar9 + 0x50);` |
| FUN_000122ec | 0x122ec | 58 | read | `if ((*(uint *)(iVar5 + 0x50) & 1) != 0) {` |
| FUN_000122ec | 0x122ec | 78 | read | `(**(code **)(iVar3 + 0x54))(*param_1 + (int)*(short *)(iVar3 + 0x50),1);` |
| FUN_0001301c | 0x1301c | 63 | read | `if ((*(uint *)(iVar4 + 0x50) & 5) != 0) {` |
| FUN_000138c4 | 0x138c4 | 27 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_000138c4 | 0x138c4 | 28 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00013dec | 0x13dec | 21 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00013dec | 0x13dec | 22 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000146c0 | 0x146c0 | 31 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_000146c0 | 0x146c0 | 32 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001528c | 0x1528c | 34 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001528c | 0x1528c | 35 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001543c | 0x1543c | 14 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001543c | 0x1543c | 15 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015508 | 0x15508 | 5 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015508 | 0x15508 | 6 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015668 | 0x15668 | 17 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015668 | 0x15668 | 18 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000158f0 | 0x158f0 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_000158f0 | 0x158f0 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015990 | 0x15990 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015990 | 0x15990 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_000159e0 | 0x159e0 | 13 | read | `uVar5 = *(uint *)(iVar4 + 0x58);` |
| FUN_00015ba4 | 0x15ba4 | 7 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015ba4 | 0x15ba4 | 8 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_00015c4c | 0x15c4c | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_00015c4c | 0x15c4c | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001655c | 0x1655c | 35 | read | `(**(code **)(iVar3 + 0x54))(*(int *)*param_1 + (int)*(short *)(iVar3 + 0x50),1);` |
| FUN_0001655c | 0x1655c | 87 | read | `(**(code **)(*(int *)(iVar4 + 0x10) + 0x54))` |
| FUN_0001655c | 0x1655c | 88 | read | `(iVar4 + *(short *)(*(int *)(iVar4 + 0x10) + 0x50),1);` |
| FUN_0001a688 | 0x1a688 | 11 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001a688 | 0x1a688 | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001a754 | 0x1a754 | 11 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001a754 | 0x1a754 | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001a834 | 0x1a834 | 46 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001a834 | 0x1a834 | 47 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001a958 | 0x1a958 | 9 | read | `uVar3 = *(uint *)(*(int *)(*(int *)(*(int *)(param_1 + 0x24) + 8) + 0x318) + 0x58);` |
| FUN_0001aa78 | 0x1aa78 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001aa78 | 0x1aa78 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ab10 | 0x1ab10 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ab10 | 0x1ab10 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001aba8 | 0x1aba8 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001aba8 | 0x1aba8 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ac40 | 0x1ac40 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ac40 | 0x1ac40 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001acd8 | 0x1acd8 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001acd8 | 0x1acd8 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ad70 | 0x1ad70 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ad70 | 0x1ad70 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001adb8 | 0x1adb8 | 18 | read | `uVar5 = *(undefined4 *)(iVar4 + 0x54);` |
| FUN_0001aea4 | 0x1aea4 | 15 | read | `uVar3 = *(undefined4 *)(iVar2 + 0x54);` |
| FUN_0001b198 | 0x1b198 | 41 | read | `func_0x0007a3e0(iVar3,iVar4 + 0x38,iVar4 + 0x50,local_10);` |
| FUN_0001b198 | 0x1b198 | 71 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001b198 | 0x1b198 | 72 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001b544 | 0x1b544 | 43 | read | `func_0x0007a3e0(iVar5,iVar2 + 0x38,iVar2 + 0x50,local_18);` |
| FUN_0001b544 | 0x1b544 | 80 | read | `func_0x0007a3e0(iVar5,iVar4 + 0x38,iVar4 + 0x50,local_18);` |
| FUN_0001b544 | 0x1b544 | 142 | read | `uVar3 = (**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001b544 | 0x1b544 | 143 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001bf94 | 0x1bf94 | 43 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001bf94 | 0x1bf94 | 44 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c3ec | 0x1c3ec | 11 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c3ec | 0x1c3ec | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c5c4 | 0x1c5c4 | 50 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c5c4 | 0x1c5c4 | 51 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c7c4 | 0x1c7c4 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c7c4 | 0x1c7c4 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c8d8 | 0x1c8d8 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c8d8 | 0x1c8d8 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001c9cc | 0x1c9cc | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001c9cc | 0x1c9cc | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001cac0 | 0x1cac0 | 6 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001cac0 | 0x1cac0 | 7 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001cbb4 | 0x1cbb4 | 46 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001cbb4 | 0x1cbb4 | 47 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ce00 | 0x1ce00 | 40 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001ce00 | 0x1ce00 | 41 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001d200 | 0x1d200 | 7 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001d200 | 0x1d200 | 8 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001e80c | 0x1e80c | 19 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001e80c | 0x1e80c | 20 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001e8dc | 0x1e8dc | 14 | read | `(**(code **)(*(int *)(param_1 + 0x10) + 0x54))` |
| FUN_0001e8dc | 0x1e8dc | 15 | read | `(param_1 + *(short *)(*(int *)(param_1 + 0x10) + 0x50),1);` |
| FUN_0001ec7c | 0x1ec7c | 55 | read | `*(ushort *)((int)piVar6 + 0x4e) = uVar4;` |
| FUN_000207a8 | 0x207a8 | 53 | read | `iVar2 = iVar2 + 0x4c;` |
| FUN_000209dc | 0x209dc | 9 | read | `param_1 = *(int *)(param_1 + 0x58);` |
| FUN_00020b88 | 0x20b88 | 33 | read | `iVar4 = iVar4 + 0x4c;` |
| FUN_00020dcc | 0x20dcc | 60 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) \| 4;` |
| FUN_000226c4 | 0x226c4 | 11 | read | `(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58),param_2);` |
| FUN_000226c4 | 0x226c4 | 23 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffffb \| 8;` |
| FUN_00022790 | 0x22790 | 19 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x5c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58),0);` |
| FUN_00022790 | 0x22790 | 39 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffff7;` |
| FUN_00022790 | 0x22790 | 52 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffff7 \| 4;` |
| FUN_00022924 | 0x22924 | 30 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffffb \| 0x1000;` |
| FUN_00022a18 | 0x22a18 | 13 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffefff \| 4;` |
| FUN_00023698 | 0x23698 | 20 | write | `*(ushort *)(param_1 + 0xd4) = *(ushort *)(param_1 + 0xd4) + 0x50;` |
| FUN_00023698 | 0x23698 | 30 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00023698 | 0x23698 | 35 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 0x80;` |
| FUN_0002380c | 0x2380c | 26 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_0002380c | 0x2380c | 108 | read | `uVar5 = *(uint *)(param_1 + 0x50);` |
| FUN_0002380c | 0x2380c | 199 | read | `if ((*(uint *)(param_1 + 0x50) & 0x40) != 0) {` |
| FUN_00024454 | 0x24454 | 5 | read | `if ((*(uint *)(param_1 + 0x50) & 0x1000) == 0) {` |
| FUN_00024454 | 0x24454 | 10 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00024454 | 0x24454 | 12 | read | `(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58),0);` |
| FUN_00024454 | 0x24454 | 13 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffff7 \| 0x80;` |
| FUN_00024558 | 0x24558 | 22 | read | `if ((*(uint *)(param_1 + 0x50) & 8) == 0) {` |
| FUN_000249e4 | 0x249e4 | 68 | write | `*(undefined4 *)(iVar6 + 0x50) = *(undefined4 *)(param_1 + 0x50);` |
| FUN_00025048 | 0x25048 | 30 | write | `*(undefined4 *)(param_1 + 0x54) = 0;` |
| FUN_00025c18 | 0x25c18 | 40 | read | `*(uint *)(iVar2 + 0x50) = *(uint *)(iVar2 + 0x50) \| 4;` |
| FUN_00026768 | 0x26768 | 23 | read | `*(uint *)(iVar2 + 0x50) = *(uint *)(iVar2 + 0x50) \| 4;` |
| FUN_0002685c | 0x2685c | 66 | read | `*(uint *)(iVar9 + 0x50) = *(uint *)(iVar9 + 0x50) \| 4;` |
| FUN_00026c68 | 0x26c68 | 20 | read | `((*(uint *)(param_1 + 0x50) & 4) == 0)) {` |
| FUN_00026e4c | 0x26e4c | 9 | read | `if ((*(uint *)(param_1 + 0x50) & 8) == 0) {` |
| FUN_00026e4c | 0x26e4c | 13 | read | `if ((*(int *)(iVar2 + 0x54) == 6) && (*(int *)(param_1 + 0xf4) != 0)) {` |
| FUN_00027a44 | 0x27a44 | 12 | read | `if (*(int *)(iVar1 + 0x54) != param_2) {` |
| FUN_000280a0 | 0x280a0 | 16 | read | `iVar3 = *(int *)(param_1 + 0x54);` |
| FUN_000280a0 | 0x280a0 | 28 | read | `iVar3 = *(int *)(param_1 + 0x58);` |
| FUN_000283f8 | 0x283f8 | 58 | write | `*(ushort *)(param_1 + 0x4c + uVar4 * 2) = *puVar7;` |
| FUN_000283f8 | 0x283f8 | 69 | write | `*(ushort *)(param_1 + 0x50 + iVar5) = *puVar7;` |
| FUN_00028724 | 0x28724 | 24 | read | `if (*(int *)(param_1 + 0x54) == 6) {` |
| FUN_00028724 | 0x28724 | 28 | read | `if ((*(uint *)(param_2 + 0x50) & 4) != 0) {` |
| FUN_00028724 | 0x28724 | 31 | read | `if ((*(uint *)(param_2 + 0x50) & 1) != 0) {` |
| FUN_00028724 | 0x28724 | 38 | read | `if ((*(int *)(param_1 + 0x58) == 3) && (*(int *)(param_2 + 0x300) != 1)) {` |
| FUN_00028724 | 0x28724 | 61 | read | `if (*(uint *)(param_1 + 0x58) < 2) {` |
| FUN_00028724 | 0x28724 | 66 | read | `else if ((*(int *)(param_1 + 0x58) == 2) \|\| (*(int *)(param_1 + 0x58) == 0)) {` |
| FUN_00028724 | 0x28724 | 78 | read | `iVar6 = *(int *)(param_1 + 0x54);` |
| FUN_00028724 | 0x28724 | 86 | read | `else if (*(int *)(param_1 + 0x54) != 1) {` |
| FUN_00028c60 | 0x28c60 | 26 | read | `*(undefined4 *)(iVar3 + 0x54) = 0;` |
| FUN_00028c60 | 0x28c60 | 27 | read | `*(undefined4 *)(iVar3 + 0x58) = 0;` |
| FUN_00028d10 | 0x28d10 | 19 | read | `*(undefined4 *)(iVar1 + 0x54) = 5;` |
| FUN_00028e58 | 0x28e58 | 9 | read | `if (*(int *)(param_1 + 0x54) == 2) {` |
| FUN_00028e58 | 0x28e58 | 13 | read | `if (*(int *)(param_1 + 0x54) != 3) {` |
| FUN_00028ef4 | 0x28ef4 | 11 | read | `if ((iVar2 != -1) && (*(int *)(param_1 + 0x54) != 6)) {` |
| FUN_00028fc4 | 0x28fc4 | 56 | read | `if (((_DAT_8004d6fa == 2) && (*(int *)(param_1 + 0x54) == 6)) &&` |
| FUN_000296e8 | 0x296e8 | 22 | read | `piVar6 = (int *)(iVar3 + 0x58);` |
| FUN_00029910 | 0x29910 | 24 | read | `iVar4 = *(int *)(uVar2 * 4 + iVar3 + 0x58);` |
| FUN_00029c24 | 0x29c24 | 77 | write | `*(uint *)(param_1 + 0x58 + uVar7 * 4) = iVar3 + (uint)*puVar9 * 0x18;` |
| FUN_0002a2d0 | 0x2a2d0 | 52 | read | `iVar6 = iVar6 + 0x4c;` |
| FUN_0002a498 | 0x2a498 | 45 | read | `iVar1 = func_0x00072348(*(undefined4 *)(param_1 + 0x58 + iVar1));` |
| FUN_0002a5f4 | 0x2a5f4 | 18 | read | `func_0x000725a8(*(undefined4 *)(param_1 + 0x58 + iVar1));` |
| FUN_0002ad60 | 0x2ad60 | 19 | read | `iVar4 = *(int *)(*(int *)(param_1 + iVar2 + 0x58) + 4);` |
| FUN_0002ad60 | 0x2ad60 | 20 | read | `iVar2 = *(int *)(iVar4 + 0x54);` |
| FUN_0002b2b8 | 0x2b2b8 | 80 | read | `piVar7 = (int *)(uVar6 * 4 + 0x58 + param_1);` |
| FUN_0002b7d0 | 0x2b7d0 | 29 | read | `if (*(int *)(*(int *)(*(int *)(param_1 + 0x58) + 4) + 0x54) == 5) {` |
| FUN_0002b7d0 | 0x2b7d0 | 38 | read | `iVar7 = *(int *)(*(int *)(param_1 + 0x58 + uVar3 * 4) + 4);` |
| FUN_0002b7d0 | 0x2b7d0 | 40 | read | `} while (*(int *)(iVar7 + 0x54) != 5);` |
| FUN_0002c4b0 | 0x2c4b0 | 30 | write | `*(undefined4 *)(param_1 + 0x50) = param_2[3];` |
| FUN_0002c4b0 | 0x2c4b0 | 75 | read | `if (*(int *)(param_1 + 0x50) != 0) {` |
| FUN_0002c4b0 | 0x2c4b0 | 81 | read | `} while (uVar8 < *(uint *)(param_1 + 0x50));` |
| FUN_0002c964 | 0x2c964 | 116 | read | `if ((((uVar4 & 1) != 0) && (*(int *)(iVar7 + 0x54) != 0)) && (*(int *)(iVar7 + 0x10) == 0)) {` |
| FUN_0002da08 | 0x2da08 | 27 | read | `if (*(int *)(param_1 + 0x50) == 0) {` |
| FUN_0002dbc0 | 0x2dbc0 | 87 | read | `uVar7 = *(uint *)(param_1 + 0x50);` |
| FUN_0002f988 | 0x2f988 | 72 | write | `*(short *)(param_1 + 0x584) = (short)uVar5 + *(short *)(param_1 + 8);` |
| FUN_0002f988 | 0x2f988 | 73 | write | `*(short *)(param_1 + 0x586) = (short)uVar6 + *(short *)(param_1 + 10);` |
| FUN_0002f988 | 0x2f988 | 74 | write | `*(short *)(param_1 + 0x588) = (short)uVar7 + *(short *)(param_1 + 0xc);` |
| FUN_0002f988 | 0x2f988 | 96 | write | `*(short *)(param_1 + 0x58c) = (short)uVar5 + *(short *)(param_1 + 8);` |
| FUN_0002f988 | 0x2f988 | 97 | write | `*(short *)(param_1 + 0x58e) = (short)uVar6 + *(short *)(param_1 + 10);` |
| FUN_0002ffac | 0x2ffac | 185 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) & 0xffffffef;` |
| FUN_0002ffac | 0x2ffac | 194 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) \| 0x10;` |
| FUN_0002ffac | 0x2ffac | 201 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) \| 0x10;` |
| FUN_00030be8 | 0x30be8 | 42 | read | `((*(uint *)(iVar2 + 0x50) & 0x20000) != 0)) {` |
| FUN_00031048 | 0x31048 | 32 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x4c))` |
| FUN_00031048 | 0x31048 | 50 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x4c))` |
| FUN_00031048 | 0x31048 | 76 | read | `(**(code **)(*(int *)(param_1 + 4) + 0x4c))` |
| FUN_00031480 | 0x31480 | 10 | read | `(((*(uint *)(param_2 + 0x50) & 4) == 0 &&` |
| FUN_00031b38 | 0x31b38 | 64 | read | `iVar7 = iVar2 + 0x54;` |
| FUN_00031b38 | 0x31b38 | 96 | read | `iVar11 = FUN_00023358(iVar2 + 0x5a);` |
| FUN_00031b38 | 0x31b38 | 106 | read | `iVar2 = FUN_00023358(iVar2 + 0x5a);` |
| FUN_00035cc0 | 0x35cc0 | 134 | read | `if ((*(uint *)(unaff_s2 + 0x50) & 0x20000) == 0) {` |
| FUN_00035cc0 | 0x35cc0 | 136 | read | `*(uint *)(unaff_s2 + 0x50) = *(uint *)(unaff_s2 + 0x50) \| 0x20000;` |
| FUN_00036c34 | 0x36c34 | 60 | read | `iVar12 = *(int *)(iVar12 + 0x58)) {` |
| FUN_00039dac | 0x39dac | 14 | write | `*(undefined4 *)(param_1 + 0x520) = 0;` |
| FUN_00039dac | 0x39dac | 28 | write | `*(undefined4 *)(param_1 + 0x5ac) = 0;` |
| FUN_00039dac | 0x39dac | 31 | write | `*(int *)(param_1 + 0x5a8) = param_1;` |
| FUN_0003a25c | 0x3a25c | 19 | read | `puVar2 = (undefined4 *)(param_1 + 0x544);` |
| FUN_0003a25c | 0x3a25c | 35 | write | `*(undefined4 *)(param_1 + 0x524) = *(undefined4 *)(param_1 + 0x39c);` |
| FUN_0003a25c | 0x3a25c | 36 | write | `*(undefined4 *)(param_1 + 0x528) = *(undefined4 *)(param_1 + 0x3a0);` |
| FUN_0003a25c | 0x3a25c | 37 | write | `*(undefined4 *)(param_1 + 0x52c) = *(undefined4 *)(param_1 + 0x3a4);` |
| FUN_0003a25c | 0x3a25c | 42 | write | `*(undefined4 *)(param_1 + 0x540) = *(undefined4 *)(param_1 + 0x3b8);` |
| FUN_0003a7d0 | 0x3a7d0 | 19 | read | `iVar1 = *(int *)(param_1 + 0x520);` |
| FUN_0003b264 | 0x3b264 | 142 | read | `if (((*(uint *)(iVar10 + 0x50) & 4) != 0) \|\| ((*(uint *)(iVar10 + 0x50) & 1) != 0)) {` |
| FUN_0003cdf0 | 0x3cdf0 | 15 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003cdf0 | 0x3cdf0 | 16 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) & 0xfffffffe;` |
| FUN_0003cdf0 | 0x3cdf0 | 18 | read | `*(uint *)(iVar1 + 0x50) = *(uint *)(iVar1 + 0x50) & 0xfffffdff;` |
| FUN_0003cdf0 | 0x3cdf0 | 20 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) = *(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x10` |
| FUN_0003cee4 | 0x3cee4 | 45 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) & 0xffffffef;` |
| FUN_0003d0e8 | 0x3d0e8 | 45 | read | `(iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x58),*(undefined2 *)(iVar6 + 0xb8))` |
| FUN_0003d0e8 | 0x3d0e8 | 48 | read | `*(uint *)(iVar6 + 0x50) = *(uint *)(iVar6 + 0x50) \| 0x10;` |
| FUN_0003dd3c | 0x3dd3c | 47 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 1;` |
| FUN_0003df28 | 0x3df28 | 55 | read | `*(uint *)(iVar8 + 0x50) = *(uint *)(iVar8 + 0x50) & 0xffffffef;` |
| FUN_0003df28 | 0x3df28 | 56 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003df28 | 0x3df28 | 57 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x200;` |
| FUN_0003df28 | 0x3df28 | 97 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffffe;` |
| FUN_0003df28 | 0x3df28 | 104 | read | `*(uint *)(iVar8 + 0x50) = *(uint *)(iVar8 + 0x50) & 0xffffffef;` |
| FUN_0003df28 | 0x3df28 | 105 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003df28 | 0x3df28 | 106 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x200;` |
| FUN_0003e810 | 0x3e810 | 16 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) \| 1;` |
| FUN_0003e810 | 0x3e810 | 43 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) & 0xfffffdff;` |
| FUN_0003e810 | 0x3e810 | 45 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003e810 | 0x3e810 | 46 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) \| 0x10;` |
| FUN_0003e810 | 0x3e810 | 47 | write | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) =` |
| FUN_0003e810 | 0x3e810 | 48 | read | `*(uint *)(*(int *)(param_1 + 0x71c) + 0x50) & 0xfffffffe;` |
| FUN_0003e838 | 0x3e838 | 19 | read | `*(uint *)(in_v1 + 0x50) = in_v0 \| 1;` |
| FUN_0003e838 | 0x3e838 | 48 | read | `*(uint *)(iVar1 + 0x50) = *(uint *)(iVar1 + 0x50) & 0xfffffdff;` |
| FUN_0003e838 | 0x3e838 | 50 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) =` |
| FUN_0003e838 | 0x3e838 | 51 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) \| 0x10;` |
| FUN_0003e838 | 0x3e838 | 52 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) =` |
| FUN_0003e838 | 0x3e838 | 53 | read | `*(uint *)(*(int *)(unaff_s0 + 0x71c) + 0x50) & 0xfffffffe;` |
| FUN_0003f1dc | 0x3f1dc | 21 | read | `((uVar3 == 0x57 \|\| (*(int *)(iVar2 + 0x58) == 0))))));` |
| FUN_0003f1dc | 0x3f1dc | 28 | read | `*(short *)(*(int *)(iVar2 + 0x48) + 6) = *(short *)(iVar2 + 0x4e) + (short)_DAT_800bc944;` |
| FUN_0003f1dc | 0x3f1dc | 34 | read | `} while (0xd < *(ushort *)(iVar2 + 0x4e));` |
| FUN_0003f1dc | 0x3f1dc | 37 | read | `(**(code **)((uint)*(ushort *)(iVar2 + 0x4e) * 4 + -0x7ff38cec))();` |
| FUN_0003fbb0 | 0x3fbb0 | 179 | read | `*(undefined4 *)(_DAT_8011a3dc + 0x58) = 0;` |
| FUN_0003fbb0 | 0x3fbb0 | 183 | read | `*(undefined4 *)(_DAT_8011a3e8 + 0x58) = 0;` |
| FUN_0003fbb0 | 0x3fbb0 | 188 | read | `*(undefined4 *)(*piVar8 + 0x58) = 0;` |
| FUN_000401ec | 0x401ec | 11 | read | `*(undefined4 *)(_DAT_8011a3dc + 0x58) = 0;` |
| FUN_000401ec | 0x401ec | 15 | read | `*(undefined4 *)(_DAT_8011a3e8 + 0x58) = 0;` |
| FUN_000401ec | 0x401ec | 20 | read | `*(undefined4 *)(*piVar1 + 0x58) = 0;` |
| FUN_000402e0 | 0x402e0 | 34 | read | `*(undefined2 *)(param_3 + 0x3c) = *(undefined2 *)(param_4 + 0x4c);` |
| FUN_000402e0 | 0x402e0 | 35 | read | `*(undefined2 *)(param_3 + 0x3e) = *(undefined2 *)(param_4 + 0x50);` |
| FUN_000402e0 | 0x402e0 | 37 | read | `if (*(int *)(param_4 + 0x54) != 0) {` |
| FUN_000402e0 | 0x402e0 | 41 | read | `*(short *)(param_3 + 0x40) = *(short *)(param_4 + 0x58) << 6;` |
| FUN_000402e0 | 0x402e0 | 42 | read | `*(undefined2 *)(param_3 + 0x50) = *(undefined2 *)(param_4 + 0x5c);` |
| FUN_000402e0 | 0x402e0 | 43 | read | `*(undefined4 *)(param_3 + 0x54) = *(undefined4 *)(param_4 + 0x60);` |
| FUN_0004033c | 0x4033c | 25 | read | `*(undefined2 *)(param_3 + 0x3c) = *(undefined2 *)(param_4 + 0x4c);` |
| FUN_0004033c | 0x4033c | 26 | read | `*(undefined2 *)(param_3 + 0x3e) = *(undefined2 *)(param_4 + 0x50);` |
| FUN_0004033c | 0x4033c | 28 | read | `if (*(int *)(param_4 + 0x54) != 0) {` |
| FUN_0004033c | 0x4033c | 32 | read | `*(short *)(param_3 + 0x40) = *(short *)(param_4 + 0x58) << 6;` |
| FUN_0004033c | 0x4033c | 33 | read | `*(undefined2 *)(param_3 + 0x50) = *(undefined2 *)(param_4 + 0x5c);` |
| FUN_0004033c | 0x4033c | 34 | read | `*(undefined4 *)(param_3 + 0x54) = *(undefined4 *)(param_4 + 0x60);` |
| FUN_0004050c | 0x4050c | 19 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 0x18;` |
| FUN_00040a4c | 0x40a4c | 93 | read | `(iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x58),uVar3);` |
| FUN_00040a4c | 0x40a4c | 98 | read | `(**(code **)(iVar6 + 0x5c))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar6 + 0x58),uVar3);` |
| FUN_00040a4c | 0x40a4c | 111 | read | `(**(code **)(iVar6 + 0x4c))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar6 + 0x48),999);` |
| FUN_00040a98 | 0x40a98 | 86 | read | `(iVar6 + *(short *)(*(int *)(iVar6 + 4) + 0x58),uVar3);` |
| FUN_00040a98 | 0x40a98 | 96 | read | `(*(int *)(unaff_s1 + 0xd4) + (int)*(short *)(iVar6 + 0x58),uVar3);` |
| FUN_00040a98 | 0x40a98 | 109 | read | `(**(code **)(iVar6 + 0x4c))` |
| FUN_000412d8 | 0x412d8 | 16 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 0x10;` |
| FUN_000412d8 | 0x412d8 | 89 | read | `*(short *)(*(int *)(param_1 + 0xc0) + 0x4c);` |
| FUN_000412d8 | 0x412d8 | 100 | read | `(int)*(short *)(*(int *)(param_1 + 0xc0) + 0x4c))) {` |
| FUN_000412d8 | 0x412d8 | 125 | read | `if ((*(uint *)(*(int *)(param_1 + 0xd4) + 0x50) & 0x400) != 0) {` |
| FUN_000412d8 | 0x412d8 | 150 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;` |
| FUN_00041a48 | 0x41a48 | 21 | read | `iVar4 = iVar2 + 0x54;` |
| FUN_00041ba4 | 0x41ba4 | 44 | read | `iVar3 = FUN_00023210(0x800c7840,iVar5 + 0x54,6);` |
| FUN_00041ba4 | 0x41ba4 | 71 | read | `iVar3 = FUN_00023210(0x800c7848,iVar5 + 0x54,6);` |
| FUN_00041ba4 | 0x41ba4 | 100 | read | `iVar4 = FUN_00023210(0x800c7850,iVar10 + 0x54,4);` |
| FUN_00041ba4 | 0x41ba4 | 108 | read | `iVar4 = FUN_00023210(0x800c7858,iVar10 + 0x54,4);` |
| FUN_00041edc | 0x41edc | 18 | read | `iVar3 = FUN_00023110(0x800c7860,iVar4 + 0x54);` |
| FUN_00041edc | 0x41edc | 24 | read | `iVar3 = FUN_00023110(0x800c786c,iVar4 + 0x54);` |
| FUN_00043748 | 0x43748 | 40 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 53 | read | `if (((cVar1 == '\x06') && ((*(uint *)(param_1 + 0x50) & 4) != 0)) &&` |
| FUN_000438fc | 0x438fc | 69 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 96 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 101 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 122 | read | `(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58));` |
| FUN_000438fc | 0x438fc | 142 | read | `if ((*(uint *)(param_1 + 0x50) & 4) == 0) {` |
| FUN_000438fc | 0x438fc | 161 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000438fc | 0x438fc | 284 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;` |
| FUN_00043a94 | 0x43a94 | 9 | read | `*(uint *)(unaff_s3 + 0x50) = *(uint *)(unaff_s3 + 0x50) & 0xffffffef;` |
| FUN_000443b8 | 0x443b8 | 82 | read | `param_2 = *(int *)(param_2 + 0x58);` |
| FUN_00044a14 | 0x44a14 | 21 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00044a14 | 0x44a14 | 148 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffdff \| 0x40;` |
| FUN_00044f80 | 0x44f80 | 56 | read | `if ((*(uint *)(param_1 + 0x50) & 4) != 0) {` |
| FUN_00044f80 | 0x44f80 | 59 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00044f80 | 0x44f80 | 85 | read | `(iVar12 = -(int)*(short *)(param_1 + 0x3e), (*(uint *)(param_1 + 0x50) & 4) == 0)) {` |
| FUN_00045a00 | 0x45a00 | 14 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00045a80 | 0x45a80 | 33 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00045a80 | 0x45a80 | 52 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046024 | 0x46024 | 38 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046024 | 0x46024 | 40 | read | `if (((*(uint *)(param_1 + 0x50) & 4) == 0) &&` |
| FUN_00046024 | 0x46024 | 43 | read | `if ((*(uint *)(param_1 + 0x50) & 0x20) != 0) {` |
| FUN_00046024 | 0x46024 | 144 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046498 | 0x46498 | 10 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_00046498 | 0x46498 | 13 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000475dc | 0x475dc | 159 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xffffffef;` |
| FUN_0004a058 | 0x4a058 | 22 | write | `*(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) \| 4;` |
| FUN_000153a0 | 0x153a0 | 70 | read | `if ((*(char *)(param_1 + 0x50) != '\0') && (uVar6 = 0, *(char *)(param_1 + 0x37) == '\0')) {` |
| FUN_00017510 | 0x17510 | 31 | write | `*(undefined1 *)(param_1 + 0x58) = 1;` |
| FUN_00017a6c | 0x17a6c | 75 | read | `(*(char *)(param_1 + 0x50) == '\0')) \|\| (*(char *)(param_1 + 0xe8) != cVar1)) {` |
| FUN_00017e54 | 0x17e54 | 62 | write | `*(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1;` |
| FUN_00002f34 | 0x2f34 | 96 | read | `(iVar9,uVar11 + *(int *)(uVar11 + 0x40) * 8 + 0x4c);` |
| FUN_00003a64 | 0x3a64 | 69 | read | `if ((*(char *)(iVar3 + 0x50) != '\0') && (iVar4 = 0, *(char *)(iVar3 + 0x36) == '\0')) {` |
| FUN_00008528 | 0x8528 | 129 | read | `iVar4 = *(int *)(iVar2 + 0x50) * 3;` |
| FUN_00008528 | 0x8528 | 134 | read | `*(short *)(*(int *)(iVar3 + 0xc) + 2) = (short)*(undefined4 *)(iVar2 + 0x54);` |
| FUN_00008528 | 0x8528 | 137 | read | `FUN_00031978(iVar4,iVar3,*(undefined4 *)(iVar2 + 0x48),*(undefined4 *)(iVar2 + 0x4c));` |
| FUN_000090e0 | 0x90e0 | 58 | read | `iVar5 = *(int *)(iVar4 + 0x50) * 3;` |
| FUN_000090e0 | 0x90e0 | 63 | read | `*(short *)(*(int *)(iVar3 + 0xc) + 2) = (short)*(undefined4 *)(iVar4 + 0x54);` |
| FUN_000090e0 | 0x90e0 | 66 | read | `FUN_00031978(iVar5,iVar3,*(undefined4 *)(iVar4 + 0x48),*(undefined4 *)(iVar4 + 0x4c));` |
| FUN_00009b18 | 0x9b18 | 16 | read | `iVar3 = iVar3 + 0x58;` |
| FUN_0000a234 | 0xa234 | 24 | read | `iVar3 = *param_1 + 0x4c;` |
| FUN_0000af3c | 0xaf3c | 28 | read | `FUN_0001e7b4(param_3 + 0x54,param_2,auStack_20);` |
| FUN_0000d7d8 | 0xd7d8 | 11 | read | `iVar2 = iVar1 - *(short *)(iVar3 + 0x54);` |
| FUN_0000d7d8 | 0xd7d8 | 13 | read | `if (iVar1 <= *(short *)(iVar3 + 0x54)) {` |
| FUN_0000d7d8 | 0xd7d8 | 19 | read | `} while (iVar1 < *(short *)(iVar3 + 0x54));` |
| FUN_0000d7d8 | 0xd7d8 | 20 | read | `*(int *)(iVar3 + 0x90) = iVar1 - *(short *)(iVar3 + 0x54);` |
| FUN_0000d7d8 | 0xd7d8 | 24 | read | `if (0 < *(short *)(iVar3 + 0x52)) {` |
| FUN_0000d7d8 | 0xd7d8 | 25 | read | `*(short *)(iVar3 + 0x52) = *(short *)(iVar3 + 0x52) + -1;` |
| FUN_0000d7d8 | 0xd7d8 | 29 | read | `if (*(short *)(iVar3 + 0x52) == 0) {` |
| FUN_0000d7d8 | 0xd7d8 | 30 | read | `*(undefined2 *)(iVar3 + 0x52) = *(undefined2 *)(iVar3 + 0x54);` |
| FUN_0000e5f0 | 0xe5f0 | 23 | read | `*(undefined2 *)((int)puVar1 + 0x5a),1);` |
| FUN_0000eb10 | 0xeb10 | 38 | read | `*(undefined2 *)(puVar4 + 0x15) = *(undefined2 *)((int)puVar4 + 0x56);` |
| FUN_0000ef68 | 0xef68 | 11 | read | `*(undefined2 *)(iVar1 + 0x58) = param_3;` |
| FUN_0000ef68 | 0xef68 | 12 | read | `*(undefined2 *)(iVar1 + 0x5a) = param_4;` |
| FUN_0000eff8 | 0xeff8 | 11 | read | `*(undefined2 *)(iVar1 + 0x58) = param_2;` |
| FUN_0000eff8 | 0xeff8 | 12 | read | `*(undefined2 *)(iVar1 + 0x5a) = param_3;` |
| FUN_0000f060 | 0xf060 | 11 | read | `*(undefined2 *)(iVar1 + 0x58) = param_3;` |
| FUN_0000f060 | 0xf060 | 12 | read | `*(undefined2 *)(iVar1 + 0x5a) = param_4;` |
| FUN_00010944 | 0x10944 | 23 | read | `uVar7 = (uVar6 * *(ushort *)(iVar5 + 0x58)) / 0x7f;` |
| FUN_00010944 | 0x10944 | 24 | read | `uVar6 = (uVar6 * *(ushort *)(iVar5 + 0x5a)) / 0x7f;` |
| FUN_000114a4 | 0x114a4 | 19 | read | `*(undefined2 *)(iVar8 + 0x58) = param_2;` |
| FUN_000114a4 | 0x114a4 | 20 | read | `*(undefined2 *)(iVar8 + 0x5a) = param_3;` |
| FUN_000114a4 | 0x114a4 | 21 | read | `if (0x7e < *(ushort *)(iVar8 + 0x58)) {` |
| FUN_000114a4 | 0x114a4 | 22 | read | `*(undefined2 *)(iVar8 + 0x58) = 0x7f;` |
| FUN_000114a4 | 0x114a4 | 24 | read | `if (0x7e < *(ushort *)(iVar8 + 0x5a)) {` |
| FUN_000114a4 | 0x114a4 | 25 | read | `*(undefined2 *)(iVar8 + 0x5a) = 0x7f;` |
| FUN_000114a4 | 0x114a4 | 43 | read | `uVar5 = (uVar6 * *(ushort *)(iVar8 + 0x58)) / 0x7f;` |
| FUN_000114a4 | 0x114a4 | 45 | read | `uVar6 = (uVar6 * *(ushort *)(iVar8 + 0x5a)) / 0x7f;` |
| FUN_0001a348 | 0x1a348 | 29 | read | `*(undefined2 *)(unaff_s0 + 0x54) = 0;` |
| FUN_0001a348 | 0x1a348 | 30 | read | `*(undefined2 *)(unaff_s0 + 0x4c) = 0;` |
| FUN_0001a348 | 0x1a348 | 36 | read | `*(undefined2 *)(unaff_s0 + 0x58) = uVar2;` |
| FUN_0001a348 | 0x1a348 | 37 | read | `*(undefined2 *)(unaff_s0 + 0x50) = uVar2;` |
| FUN_0001a348 | 0x1a348 | 38 | read | `*(undefined2 *)(unaff_s0 + 0x5a) = 0xf0;` |
| FUN_0001a348 | 0x1a348 | 39 | read | `*(undefined2 *)(unaff_s0 + 0x52) = 0xf0;` |
| FUN_0001a348 | 0x1a348 | 40 | read | `*(undefined2 *)(unaff_s0 + 0x4e) = 0;` |
| FUN_0001a348 | 0x1a348 | 41 | read | `*(undefined2 *)(unaff_s0 + 0x56) = 0xf0;` |
| FUN_0001a3b0 | 0x1a3b0 | 16 | read | `*(undefined2 *)(unaff_s0 + 0x58) = uVar2;` |
| FUN_0001a3b0 | 0x1a3b0 | 17 | read | `*(undefined2 *)(unaff_s0 + 0x50) = uVar2;` |
| FUN_0001a3b0 | 0x1a3b0 | 18 | read | `*(undefined2 *)(unaff_s0 + 0x5a) = 0xf0;` |
| FUN_0001a3b0 | 0x1a3b0 | 19 | read | `*(undefined2 *)(unaff_s0 + 0x52) = 0xf0;` |
| FUN_0001a3b0 | 0x1a3b0 | 20 | read | `*(undefined2 *)(unaff_s0 + 0x4e) = 0;` |
| FUN_0001a3b0 | 0x1a3b0 | 21 | read | `*(undefined2 *)(unaff_s0 + 0x56) = 0xf0;` |
| FUN_0001a674 | 0x1a674 | 20 | read | `*(undefined2 *)(unaff_s0 + 0x58) = uVar1;` |
| FUN_0001a674 | 0x1a674 | 21 | read | `*(undefined2 *)(unaff_s0 + 0x50) = uVar1;` |
| FUN_0001a674 | 0x1a674 | 24 | read | `*(undefined2 *)(unaff_s0 + 0x5a) = uVar1;` |
| FUN_0001a674 | 0x1a674 | 25 | read | `*(undefined2 *)(unaff_s0 + 0x52) = uVar1;` |
| FUN_0001a804 | 0x1a804 | 28 | read | `(iVar3,param_1 + *(int *)(param_1 + 0x40) * 8 + 0x4c);` |
| FUN_0001a804 | 0x1a804 | 33 | read | `FUN_00018878(auStack_14,(int)*(short *)(iVar4 + 0x4c),(int)*(short *)(iVar4 + 0x4e),` |
| FUN_0001aaec | 0x1aaec | 14 | read | `*(undefined2 *)((int)unaff_s0 + (param_1 - unaff_s0[0x10]) * 8 + 0x4e);` |
| FUN_0001abfc | 0x1abfc | 11 | read | `(int)*(short *)(iVar1 + 0x4c) + (int)*(short *)(iVar1 + 0x50)) {` |
| FUN_0001b220 | 0x1b220 | 69 | read | `if ((*(char *)(param_1 + 0x50) != '\0') && (uVar6 = 0, *(char *)(param_1 + 0x36) == '\0')) {` |
| FUN_0001b264 | 0x1b264 | 61 | read | `if ((*(char *)(unaff_s0 + 0x50) != '\0') && (uVar4 = 0, *(char *)(unaff_s0 + 0x36) == '\0')) {` |
| FUN_0001b364 | 0x1b364 | 36 | read | `if ((*(char *)(unaff_s0 + 0x50) != '\0') && (uVar3 = 0, *(char *)(unaff_s0 + 0x36) == '\0')) {` |
| FUN_0001c2b4 | 0x1c2b4 | 15 | write | `*(undefined1 *)(param_1 + 0x52) = param_3;` |
| FUN_0001cfcc | 0x1cfcc | 29 | write | `*(undefined1 *)(param_1 + 0x58) = 1;` |
| FUN_0001d504 | 0x1d504 | 32 | read | `(*(char *)(param_1 + 0x50) == '\0')))) \|\|` |
| FUN_0001d7b8 | 0x1d7b8 | 10 | write | `*(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1;` |
| FUN_00021974 | 0x21974 | 13 | read | `*(undefined4 *)(unaff_s0 + 0x50) = 0;` |
| FUN_00021974 | 0x21974 | 14 | read | `*(undefined4 *)(unaff_s0 + 0x4c) = 0;` |
| FUN_00021b4c | 0x21b4c | 9 | read | `*(undefined4 *)(unaff_s0 + 0x50) = in_v0;` |
| FUN_000233dc | 0x233dc | 9 | read | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x8c),param_2 + 0x5464);` |
| FUN_00023d74 | 0x23d74 | 36 | read | `FUN_0001a4a0(&local_8,0x23a,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 48 | read | `FUN_0001a4a0(&local_8,0x251,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 60 | read | `FUN_0001a4a0(&local_8,0x25d,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 72 | read | `FUN_0001a4a0(&local_8,0x26f,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 84 | read | `FUN_0001a4a0(&local_8,0x27b,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 96 | read | `FUN_0001a4a0(&local_8,0x28c,iVar1 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 21 | read | `FUN_0001a4a0(param_1,0x25d,in_hi * 2 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 34 | read | `FUN_0001a4a0(&stack0x00000020,0x26f,iVar1 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 46 | read | `FUN_0001a4a0(&stack0x00000020,0x27b,iVar1 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 58 | read | `FUN_0001a4a0(&stack0x00000020,0x28c,iVar1 + 0x58);` |
| FUN_000240a0 | 0x240a0 | 24 | read | `FUN_0001a4a0(&stack0x00000020,0x28c,iVar1 + 0x58);` |
| FUN_00000a2c | 0xa2c | 28 | read | `func_0x0002080c(iVar1 + *(int *)(iVar1 + 0x50));` |
| FUN_00001f4c | 0x1f4c | 28 | read | `func_0x000cce8c(0x106,0,sVar1 + 0xc0,sVar2 + 0x50,iVar3,0,0,0);` |
| FUN_00001f4c | 0x1f4c | 29 | read | `func_0x000cce8c(0x108,0,sVar5,sVar2 + 0x50,iVar3,0,0,0);` |
| FUN_00001f4c | 0x1f4c | 34 | read | `func_0x000cce8c(0x107,0,sVar4,sVar2 + 0x50,iVar3,0,0,0);` |
| FUN_00004328 | 0x4328 | 313 | read | `func_0x000cce8c(0x2b,0,iVar22 + 200U & 0xffff,iVar7 + 0x54U & 0xffff,0x808080,0,0,0);` |
| FUN_00005954 | 0x5954 | 405 | read | `func_0x000cce8c(0xfe,1,*psVar21 + -0x38,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,0x808080,0,0,` |
| FUN_00005954 | 0x5954 | 407 | read | `func_0x000cce8c(0xff,1,*psVar21 + 0x88,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,0x808080,0,0,0` |
| FUN_00005954 | 0x5954 | 409 | read | `func_0x000cce8c(0x100,0,*psVar21 + -0x38,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,` |
| FUN_00005954 | 0x5954 | 411 | read | `func_0x000cce8c(0x101,0,*psVar21 + 0x88,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,0x808080,0,0,` |
| FUN_00006f28 | 0x6f28 | 13 | read | `,(int)((*(ushort *)(&DAT_800cf4de + iVar1) + 0x50) * 0x10000) >> 0x10,` |
| FUN_00002724 | 0x2724 | 68 | read | `if ((((iVar9 == 0) \|\| (*(int *)(iVar9 + 0x48) != 3)) \|\| (*(int *)(iVar9 + 0x50) != 0)) \|\|` |
| FUN_00003f60 | 0x3f60 | 28 | read | `func_0x000c9b8c(iVar2 + *(int *)(iVar2 + 0x50));` |
| FUN_00004fcc | 0x4fcc | 13 | write | `*(undefined2 **)(param_1 + 0x4c) = param_2;` |
| FUN_00004fcc | 0x4fcc | 42 | write | `*(undefined4 *)(param_1 + 0x50) = 0;` |
| FUN_00004fcc | 0x4fcc | 43 | read | `iVar4 = *(int *)((uint)**(ushort **)(param_1 + 0x4c) * 4 + -0x7ff30500);` |
| FUN_000056dc | 0x56dc | 11 | read | `*(short *)(*(int *)(param_1 + 0x4c) + 2),(undefined2)local_10[0]) &` |
| FUN_000057cc | 0x57cc | 26 | read | `(*(ushort **)(param_1 + 0x4c))[1],(undefined2)local_30) & 0xfffffff;` |
| FUN_000057cc | 0x57cc | 31 | read | `(*(int *)((uint)**(ushort **)(param_1 + 0x4c) * 4 + -0x7ff30500) != 0)) {` |
| FUN_000059f4 | 0x59f4 | 19 | read | `iVar3 = iVar3 + 0x54;` |
| FUN_00005de4 | 0x5de4 | 7 | read | `puVar1 = *(undefined4 **)(param_1 + 0x50);` |
| FUN_00005de4 | 0x5de4 | 16 | write | `*(undefined4 *)(param_1 + 0x50) = 0;` |
| FUN_00005e70 | 0x5e70 | 27 | write | `*(int *)(param_1 + 0x4c) = param_2;` |
| FUN_00005e70 | 0x5e70 | 49 | write | `*(undefined4 *)(param_1 + 0x50) = 0;` |
| FUN_00005e70 | 0x5e70 | 58 | write | `*(undefined4 *)(param_1 + 0x54) = uVar4;` |
| FUN_00005e70 | 0x5e70 | 82 | write | `*(undefined4 *)(param_1 + 0x54) = uVar4;` |
| FUN_000063c4 | 0x63c4 | 17 | read | `psVar1 = *(short **)(param_1 + 0x4c);` |
| FUN_000063c4 | 0x63c4 | 45 | read | `if (*(int **)(param_1 + 0x50) != (int *)0x0) {` |
| FUN_000063c4 | 0x63c4 | 46 | read | `func_0x00098a7c(*(undefined4 *)(**(int **)(param_1 + 0x50) + 0x24),puVar3,0,2,` |
| FUN_000063c4 | 0x63c4 | 51 | read | `func_0x0009af10(puVar3,param_1 + 0x38,*(undefined4 *)(param_1 + 0x54));` |
| FUN_0000652c | 0x652c | 51 | read | `uVar1 = *(ushort *)(*(int *)(param_1 + 0x4c) + 0x24);` |
| FUN_0000652c | 0x652c | 55 | read | `*(short *)(*(int *)(param_1 + 0x44) + 10) + *(short *)(*(int *)(param_1 + 0x4c) + 0x24);` |
| FUN_00006ec4 | 0x6ec4 | 19 | read | `iVar3 = iVar3 + 0x58;` |
| FUN_000072b4 | 0x72b4 | 40 | read | `*(undefined2 *)((uint)*(ushort *)(param_1 + 0x1fe) * 0x2c + param_1 + 0x5a);` |
| FUN_00008198 | 0x8198 | 71 | read | `if (*(short *)(iVar1 * 0x10 + uVar5 * 0xc + param_1 + 0x5a) != *(short *)(param_1 + 0x202)) {` |
| FUN_00008198 | 0x8198 | 83 | read | `if (*(short *)(uVar2 * 0x2c + param_1 + 0x5a) != *(short *)(param_1 + 0x202)) {` |
| FUN_00008198 | 0x8198 | 92 | read | `} while (*(short *)(uVar2 * 0x2c + param_1 + 0x5a) != *(short *)(param_1 + 0x202));` |
| FUN_00009dfc | 0x9dfc | 28 | read | `func_0x0002080c(iVar1 + *(int *)(iVar1 + 0x50));` |
| FUN_00001998 | 0x1998 | 40 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) \| 0x10;` |
| FUN_00001998 | 0x1998 | 77 | read | `*(uint *)(_DAT_800bca78 + 0x50) = *(uint *)(_DAT_800bca78 + 0x50) & 0xffffffef;` |
| FUN_000010b8 | 0x10b8 | 143 | read | `iVar4 = *(int *)(iVar7 + 0x54);` |
| FUN_000010b8 | 0x10b8 | 150 | read | `iVar4 = *(int *)(iVar7 + 0x54);` |
| FUN_000010b8 | 0x10b8 | 184 | read | `if (((*(int *)(iVar3 + 0x54) != 0) && ((*(uint *)(iVar3 + 0xb8) & 0xb0) == 0)) &&` |
| FUN_00001c84 | 0x1c84 | 325 | read | `(**(code **)(*(int *)(iVar10 + 4) + 0x4c))` |
| FUN_00001c84 | 0x1c84 | 413 | read | `*(undefined2 *)(iVar10 + 0x4c) = 30000;` |
| FUN_00001c84 | 0x1c84 | 492 | read | `(*(int *)(iVar8 + 0x54) == 0)) {` |
| FUN_00001c84 | 0x1c84 | 589 | read | `*(uint *)(iVar10 + 0x50) = *(uint *)(iVar10 + 0x50) & 0xffffffef;` |
| FUN_00001c84 | 0x1c84 | 592 | read | `*(uint *)(iVar10 + 0x50) = *(uint *)(iVar10 + 0x50) \| 0x10;` |
| FUN_00001c84 | 0x1c84 | 620 | read | `(iVar10 + *(short *)(*(int *)(iVar10 + 4) + 0x58),` |
| FUN_00001c84 | 0x1c84 | 632 | read | `(iVar18 + *(short *)(*(int *)(iVar8 + -0x7feedcf0) + 0x58),` |
| FUN_000153a0 | 0x153a0 | 70 | read | `if ((*(char *)(param_1 + 0x50) != '\0') && (uVar6 = 0, *(char *)(param_1 + 0x37) == '\0')) {` |
| FUN_00017510 | 0x17510 | 31 | write | `*(undefined1 *)(param_1 + 0x58) = 1;` |
| FUN_00017a6c | 0x17a6c | 75 | read | `(*(char *)(param_1 + 0x50) == '\0')) \|\| (*(char *)(param_1 + 0xe8) != cVar1)) {` |
| FUN_00017e54 | 0x17e54 | 62 | write | `*(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1;` |
| FUN_00002f34 | 0x2f34 | 96 | read | `(iVar9,uVar11 + *(int *)(uVar11 + 0x40) * 8 + 0x4c);` |
| FUN_00003a64 | 0x3a64 | 69 | read | `if ((*(char *)(iVar3 + 0x50) != '\0') && (iVar4 = 0, *(char *)(iVar3 + 0x36) == '\0')) {` |
| FUN_00008528 | 0x8528 | 129 | read | `iVar4 = *(int *)(iVar2 + 0x50) * 3;` |
| FUN_00008528 | 0x8528 | 134 | read | `*(short *)(*(int *)(iVar3 + 0xc) + 2) = (short)*(undefined4 *)(iVar2 + 0x54);` |
| FUN_00008528 | 0x8528 | 137 | read | `FUN_00031978(iVar4,iVar3,*(undefined4 *)(iVar2 + 0x48),*(undefined4 *)(iVar2 + 0x4c));` |
| FUN_000090e0 | 0x90e0 | 58 | read | `iVar5 = *(int *)(iVar4 + 0x50) * 3;` |
| FUN_000090e0 | 0x90e0 | 63 | read | `*(short *)(*(int *)(iVar3 + 0xc) + 2) = (short)*(undefined4 *)(iVar4 + 0x54);` |
| FUN_000090e0 | 0x90e0 | 66 | read | `FUN_00031978(iVar5,iVar3,*(undefined4 *)(iVar4 + 0x48),*(undefined4 *)(iVar4 + 0x4c));` |
| FUN_00009b18 | 0x9b18 | 16 | read | `iVar3 = iVar3 + 0x58;` |
| FUN_0000a234 | 0xa234 | 24 | read | `iVar3 = *param_1 + 0x4c;` |
| FUN_0000af3c | 0xaf3c | 28 | read | `FUN_0001e7b4(param_3 + 0x54,param_2,auStack_20);` |
| FUN_0000d7d8 | 0xd7d8 | 11 | read | `iVar2 = iVar1 - *(short *)(iVar3 + 0x54);` |
| FUN_0000d7d8 | 0xd7d8 | 13 | read | `if (iVar1 <= *(short *)(iVar3 + 0x54)) {` |
| FUN_0000d7d8 | 0xd7d8 | 19 | read | `} while (iVar1 < *(short *)(iVar3 + 0x54));` |
| FUN_0000d7d8 | 0xd7d8 | 20 | read | `*(int *)(iVar3 + 0x90) = iVar1 - *(short *)(iVar3 + 0x54);` |
| FUN_0000d7d8 | 0xd7d8 | 24 | read | `if (0 < *(short *)(iVar3 + 0x52)) {` |
| FUN_0000d7d8 | 0xd7d8 | 25 | read | `*(short *)(iVar3 + 0x52) = *(short *)(iVar3 + 0x52) + -1;` |
| FUN_0000d7d8 | 0xd7d8 | 29 | read | `if (*(short *)(iVar3 + 0x52) == 0) {` |
| FUN_0000d7d8 | 0xd7d8 | 30 | read | `*(undefined2 *)(iVar3 + 0x52) = *(undefined2 *)(iVar3 + 0x54);` |
| FUN_0000e5f0 | 0xe5f0 | 23 | read | `*(undefined2 *)((int)puVar1 + 0x5a),1);` |
| FUN_0000eb10 | 0xeb10 | 38 | read | `*(undefined2 *)(puVar4 + 0x15) = *(undefined2 *)((int)puVar4 + 0x56);` |
| FUN_0000ef68 | 0xef68 | 11 | read | `*(undefined2 *)(iVar1 + 0x58) = param_3;` |
| FUN_0000ef68 | 0xef68 | 12 | read | `*(undefined2 *)(iVar1 + 0x5a) = param_4;` |
| FUN_0000eff8 | 0xeff8 | 11 | read | `*(undefined2 *)(iVar1 + 0x58) = param_2;` |
| FUN_0000eff8 | 0xeff8 | 12 | read | `*(undefined2 *)(iVar1 + 0x5a) = param_3;` |
| FUN_0000f060 | 0xf060 | 11 | read | `*(undefined2 *)(iVar1 + 0x58) = param_3;` |
| FUN_0000f060 | 0xf060 | 12 | read | `*(undefined2 *)(iVar1 + 0x5a) = param_4;` |
| FUN_00010944 | 0x10944 | 23 | read | `uVar7 = (uVar6 * *(ushort *)(iVar5 + 0x58)) / 0x7f;` |
| FUN_00010944 | 0x10944 | 24 | read | `uVar6 = (uVar6 * *(ushort *)(iVar5 + 0x5a)) / 0x7f;` |
| FUN_000114a4 | 0x114a4 | 19 | read | `*(undefined2 *)(iVar8 + 0x58) = param_2;` |
| FUN_000114a4 | 0x114a4 | 20 | read | `*(undefined2 *)(iVar8 + 0x5a) = param_3;` |
| FUN_000114a4 | 0x114a4 | 21 | read | `if (0x7e < *(ushort *)(iVar8 + 0x58)) {` |
| FUN_000114a4 | 0x114a4 | 22 | read | `*(undefined2 *)(iVar8 + 0x58) = 0x7f;` |
| FUN_000114a4 | 0x114a4 | 24 | read | `if (0x7e < *(ushort *)(iVar8 + 0x5a)) {` |
| FUN_000114a4 | 0x114a4 | 25 | read | `*(undefined2 *)(iVar8 + 0x5a) = 0x7f;` |
| FUN_000114a4 | 0x114a4 | 43 | read | `uVar5 = (uVar6 * *(ushort *)(iVar8 + 0x58)) / 0x7f;` |
| FUN_000114a4 | 0x114a4 | 45 | read | `uVar6 = (uVar6 * *(ushort *)(iVar8 + 0x5a)) / 0x7f;` |
| FUN_0001a348 | 0x1a348 | 29 | read | `*(undefined2 *)(unaff_s0 + 0x54) = 0;` |
| FUN_0001a348 | 0x1a348 | 30 | read | `*(undefined2 *)(unaff_s0 + 0x4c) = 0;` |
| FUN_0001a348 | 0x1a348 | 36 | read | `*(undefined2 *)(unaff_s0 + 0x58) = uVar2;` |
| FUN_0001a348 | 0x1a348 | 37 | read | `*(undefined2 *)(unaff_s0 + 0x50) = uVar2;` |
| FUN_0001a348 | 0x1a348 | 38 | read | `*(undefined2 *)(unaff_s0 + 0x5a) = 0xf0;` |
| FUN_0001a348 | 0x1a348 | 39 | read | `*(undefined2 *)(unaff_s0 + 0x52) = 0xf0;` |
| FUN_0001a348 | 0x1a348 | 40 | read | `*(undefined2 *)(unaff_s0 + 0x4e) = 0;` |
| FUN_0001a348 | 0x1a348 | 41 | read | `*(undefined2 *)(unaff_s0 + 0x56) = 0xf0;` |
| FUN_0001a3b0 | 0x1a3b0 | 16 | read | `*(undefined2 *)(unaff_s0 + 0x58) = uVar2;` |
| FUN_0001a3b0 | 0x1a3b0 | 17 | read | `*(undefined2 *)(unaff_s0 + 0x50) = uVar2;` |
| FUN_0001a3b0 | 0x1a3b0 | 18 | read | `*(undefined2 *)(unaff_s0 + 0x5a) = 0xf0;` |
| FUN_0001a3b0 | 0x1a3b0 | 19 | read | `*(undefined2 *)(unaff_s0 + 0x52) = 0xf0;` |
| FUN_0001a3b0 | 0x1a3b0 | 20 | read | `*(undefined2 *)(unaff_s0 + 0x4e) = 0;` |
| FUN_0001a3b0 | 0x1a3b0 | 21 | read | `*(undefined2 *)(unaff_s0 + 0x56) = 0xf0;` |
| FUN_0001a674 | 0x1a674 | 20 | read | `*(undefined2 *)(unaff_s0 + 0x58) = uVar1;` |
| FUN_0001a674 | 0x1a674 | 21 | read | `*(undefined2 *)(unaff_s0 + 0x50) = uVar1;` |
| FUN_0001a674 | 0x1a674 | 24 | read | `*(undefined2 *)(unaff_s0 + 0x5a) = uVar1;` |
| FUN_0001a674 | 0x1a674 | 25 | read | `*(undefined2 *)(unaff_s0 + 0x52) = uVar1;` |
| FUN_0001a804 | 0x1a804 | 28 | read | `(iVar3,param_1 + *(int *)(param_1 + 0x40) * 8 + 0x4c);` |
| FUN_0001a804 | 0x1a804 | 33 | read | `FUN_00018878(auStack_14,(int)*(short *)(iVar4 + 0x4c),(int)*(short *)(iVar4 + 0x4e),` |
| FUN_0001aaec | 0x1aaec | 14 | read | `*(undefined2 *)((int)unaff_s0 + (param_1 - unaff_s0[0x10]) * 8 + 0x4e);` |
| FUN_0001abfc | 0x1abfc | 11 | read | `(int)*(short *)(iVar1 + 0x4c) + (int)*(short *)(iVar1 + 0x50)) {` |
| FUN_0001b220 | 0x1b220 | 69 | read | `if ((*(char *)(param_1 + 0x50) != '\0') && (uVar6 = 0, *(char *)(param_1 + 0x36) == '\0')) {` |
| FUN_0001b264 | 0x1b264 | 61 | read | `if ((*(char *)(unaff_s0 + 0x50) != '\0') && (uVar4 = 0, *(char *)(unaff_s0 + 0x36) == '\0')) {` |
| FUN_0001b364 | 0x1b364 | 36 | read | `if ((*(char *)(unaff_s0 + 0x50) != '\0') && (uVar3 = 0, *(char *)(unaff_s0 + 0x36) == '\0')) {` |
| FUN_0001c2b4 | 0x1c2b4 | 15 | write | `*(undefined1 *)(param_1 + 0x52) = param_3;` |
| FUN_0001cfcc | 0x1cfcc | 29 | write | `*(undefined1 *)(param_1 + 0x58) = 1;` |
| FUN_0001d504 | 0x1d504 | 32 | read | `(*(char *)(param_1 + 0x50) == '\0')))) \|\|` |
| FUN_0001d7b8 | 0x1d7b8 | 10 | write | `*(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1;` |
| FUN_00021974 | 0x21974 | 13 | read | `*(undefined4 *)(unaff_s0 + 0x50) = 0;` |
| FUN_00021974 | 0x21974 | 14 | read | `*(undefined4 *)(unaff_s0 + 0x4c) = 0;` |
| FUN_00021b4c | 0x21b4c | 9 | read | `*(undefined4 *)(unaff_s0 + 0x50) = in_v0;` |
| FUN_000233dc | 0x233dc | 9 | read | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x8c),param_2 + 0x5464);` |
| FUN_00023d74 | 0x23d74 | 36 | read | `FUN_0001a4a0(&local_8,0x23a,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 48 | read | `FUN_0001a4a0(&local_8,0x251,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 60 | read | `FUN_0001a4a0(&local_8,0x25d,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 72 | read | `FUN_0001a4a0(&local_8,0x26f,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 84 | read | `FUN_0001a4a0(&local_8,0x27b,iVar1 + 0x58);` |
| FUN_00023d74 | 0x23d74 | 96 | read | `FUN_0001a4a0(&local_8,0x28c,iVar1 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 21 | read | `FUN_0001a4a0(param_1,0x25d,in_hi * 2 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 34 | read | `FUN_0001a4a0(&stack0x00000020,0x26f,iVar1 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 46 | read | `FUN_0001a4a0(&stack0x00000020,0x27b,iVar1 + 0x58);` |
| FUN_00023f50 | 0x23f50 | 58 | read | `FUN_0001a4a0(&stack0x00000020,0x28c,iVar1 + 0x58);` |
| FUN_000240a0 | 0x240a0 | 24 | read | `FUN_0001a4a0(&stack0x00000020,0x28c,iVar1 + 0x58);` |
| FUN_00000a2c | 0xa2c | 28 | read | `func_0x0002080c(iVar1 + *(int *)(iVar1 + 0x50));` |
| FUN_00001f4c | 0x1f4c | 28 | read | `func_0x000cce8c(0x106,0,sVar1 + 0xc0,sVar2 + 0x50,iVar3,0,0,0);` |
| FUN_00001f4c | 0x1f4c | 29 | read | `func_0x000cce8c(0x108,0,sVar5,sVar2 + 0x50,iVar3,0,0,0);` |
| FUN_00001f4c | 0x1f4c | 34 | read | `func_0x000cce8c(0x107,0,sVar4,sVar2 + 0x50,iVar3,0,0,0);` |
| FUN_00004328 | 0x4328 | 313 | read | `func_0x000cce8c(0x2b,0,iVar22 + 200U & 0xffff,iVar7 + 0x54U & 0xffff,0x808080,0,0,0);` |
| FUN_00005954 | 0x5954 | 405 | read | `func_0x000cce8c(0xfe,1,*psVar21 + -0x38,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,0x808080,0,0,` |
| FUN_00005954 | 0x5954 | 407 | read | `func_0x000cce8c(0xff,1,*psVar21 + 0x88,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,0x808080,0,0,0` |
| FUN_00005954 | 0x5954 | 409 | read | `func_0x000cce8c(0x100,0,*psVar21 + -0x38,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,` |
| FUN_00005954 | 0x5954 | 411 | read | `func_0x000cce8c(0x101,0,*psVar21 + 0x88,*(short *)(iVar9 + -0x7ff2e9ca) + 0x50,0x808080,0,0,` |
| FUN_00006f28 | 0x6f28 | 13 | read | `,(int)((*(ushort *)(&DAT_800cf4de + iVar1) + 0x50) * 0x10000) >> 0x10,` |
| FUN_00002724 | 0x2724 | 68 | read | `if ((((iVar9 == 0) \|\| (*(int *)(iVar9 + 0x48) != 3)) \|\| (*(int *)(iVar9 + 0x50) != 0)) \|\|` |
| FUN_00003f60 | 0x3f60 | 28 | read | `func_0x000c9b8c(iVar2 + *(int *)(iVar2 + 0x50));` |
| FUN_00004fcc | 0x4fcc | 13 | write | `*(undefined2 **)(param_1 + 0x4c) = param_2;` |
| FUN_00004fcc | 0x4fcc | 42 | write | `*(undefined4 *)(param_1 + 0x50) = 0;` |
| FUN_00004fcc | 0x4fcc | 43 | read | `iVar4 = *(int *)((uint)**(ushort **)(param_1 + 0x4c) * 4 + -0x7ff30500);` |
| FUN_000056dc | 0x56dc | 11 | read | `*(short *)(*(int *)(param_1 + 0x4c) + 2),(undefined2)local_10[0]) &` |
| FUN_000057cc | 0x57cc | 26 | read | `(*(ushort **)(param_1 + 0x4c))[1],(undefined2)local_30) & 0xfffffff;` |
| FUN_000057cc | 0x57cc | 31 | read | `(*(int *)((uint)**(ushort **)(param_1 + 0x4c) * 4 + -0x7ff30500) != 0)) {` |
| FUN_000059f4 | 0x59f4 | 19 | read | `iVar3 = iVar3 + 0x54;` |
| FUN_00005de4 | 0x5de4 | 7 | read | `puVar1 = *(undefined4 **)(param_1 + 0x50);` |
| FUN_00005de4 | 0x5de4 | 16 | write | `*(undefined4 *)(param_1 + 0x50) = 0;` |
| FUN_00005e70 | 0x5e70 | 27 | write | `*(int *)(param_1 + 0x4c) = param_2;` |
| FUN_00005e70 | 0x5e70 | 49 | write | `*(undefined4 *)(param_1 + 0x50) = 0;` |
| FUN_00005e70 | 0x5e70 | 58 | write | `*(undefined4 *)(param_1 + 0x54) = uVar4;` |
| FUN_00005e70 | 0x5e70 | 82 | write | `*(undefined4 *)(param_1 + 0x54) = uVar4;` |
| FUN_000063c4 | 0x63c4 | 17 | read | `psVar1 = *(short **)(param_1 + 0x4c);` |
| FUN_000063c4 | 0x63c4 | 45 | read | `if (*(int **)(param_1 + 0x50) != (int *)0x0) {` |
| FUN_000063c4 | 0x63c4 | 46 | read | `func_0x00098a7c(*(undefined4 *)(**(int **)(param_1 + 0x50) + 0x24),puVar3,0,2,` |
| FUN_000063c4 | 0x63c4 | 51 | read | `func_0x0009af10(puVar3,param_1 + 0x38,*(undefined4 *)(param_1 + 0x54));` |
| FUN_0000652c | 0x652c | 51 | read | `uVar1 = *(ushort *)(*(int *)(param_1 + 0x4c) + 0x24);` |
| FUN_0000652c | 0x652c | 55 | read | `*(short *)(*(int *)(param_1 + 0x44) + 10) + *(short *)(*(int *)(param_1 + 0x4c) + 0x24);` |
| FUN_00006ec4 | 0x6ec4 | 19 | read | `iVar3 = iVar3 + 0x58;` |
| FUN_000072b4 | 0x72b4 | 40 | read | `*(undefined2 *)((uint)*(ushort *)(param_1 + 0x1fe) * 0x2c + param_1 + 0x5a);` |
| FUN_00008198 | 0x8198 | 71 | read | `if (*(short *)(iVar1 * 0x10 + uVar5 * 0xc + param_1 + 0x5a) != *(short *)(param_1 + 0x202)) {` |
| FUN_00008198 | 0x8198 | 83 | read | `if (*(short *)(uVar2 * 0x2c + param_1 + 0x5a) != *(short *)(param_1 + 0x202)) {` |
| FUN_00008198 | 0x8198 | 92 | read | `} while (*(short *)(uVar2 * 0x2c + param_1 + 0x5a) != *(short *)(param_1 + 0x202));` |
| FUN_00009dfc | 0x9dfc | 28 | read | `func_0x0002080c(iVar1 + *(int *)(iVar1 + 0x50));` |
| FUN_00001998 | 0x1998 | 40 | read | `*(uint *)(iVar3 + 0x50) = *(uint *)(iVar3 + 0x50) \| 0x10;` |
| FUN_00001998 | 0x1998 | 77 | read | `*(uint *)(_DAT_800bca78 + 0x50) = *(uint *)(_DAT_800bca78 + 0x50) & 0xffffffef;` |
| FUN_000010b8 | 0x10b8 | 143 | read | `iVar4 = *(int *)(iVar7 + 0x54);` |
| FUN_000010b8 | 0x10b8 | 150 | read | `iVar4 = *(int *)(iVar7 + 0x54);` |
| FUN_000010b8 | 0x10b8 | 184 | read | `if (((*(int *)(iVar3 + 0x54) != 0) && ((*(uint *)(iVar3 + 0xb8) & 0xb0) == 0)) &&` |
| FUN_00001c84 | 0x1c84 | 325 | read | `(**(code **)(*(int *)(iVar10 + 4) + 0x4c))` |
| FUN_00001c84 | 0x1c84 | 413 | read | `*(undefined2 *)(iVar10 + 0x4c) = 30000;` |
| FUN_00001c84 | 0x1c84 | 492 | read | `(*(int *)(iVar8 + 0x54) == 0)) {` |
| FUN_00001c84 | 0x1c84 | 589 | read | `*(uint *)(iVar10 + 0x50) = *(uint *)(iVar10 + 0x50) & 0xffffffef;` |
| FUN_00001c84 | 0x1c84 | 592 | read | `*(uint *)(iVar10 + 0x50) = *(uint *)(iVar10 + 0x50) \| 0x10;` |
| FUN_00001c84 | 0x1c84 | 620 | read | `(iVar10 + *(short *)(*(int *)(iVar10 + 4) + 0x58),` |
| FUN_00001c84 | 0x1c84 | 632 | read | `(iVar18 + *(short *)(*(int *)(iVar8 + -0x7feedcf0) + 0x58),` |
