# Usage of offset +0x88 in secondary vertical context

| Function | EA | Line | Class | Code |
|----------|----|------|-------|------|
| FUN_00007680 | 0x7680 | 20 | unknown | `bVar1 = iVar2 == *(short *)(*(int *)(iVar4 + 0x1a8) + 0x88);` |
| FUN_00018aa4 | 0x18aa4 | 26 | unknown | `bVar2 = iVar4 == *(short *)(*(int *)(iVar5 + 0x1a8) + 0x88);` |
| FUN_0001efbc | 0x1efbc | 14 | unknown | `(**(code **)(*(int *)(param_1 + 4) + 0x8c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x88));` |
| FUN_0002e8f4 | 0x2e8f4 | 123 | unknown | `((undefined2 *)(param_1 + 0x1e0))[*(short *)(*(int *)(param_1 + 0x1a8) + 0x88)] = 0x800;` |
| FUN_0002f6d4 | 0x2f6d4 | 44 | unknown | `else if (param_3 == *(short *)(*(int *)(param_1 + 0x1a8) + 0x88)) {` |
| FUN_0002ffac | 0x2ffac | 36 | unknown | `(((int)*(short *)(iVar6 + 0x88) == uVar14 \|\| (iVar12 != *(int *)(param_1 + 0x1b4))))) {` |
| FUN_0002ffac | 0x2ffac | 113 | unknown | `uVar14 == (int)*(short *)(*(int *)(param_1 + 0x1a8) + 0x88))) {` |
| FUN_0002ffac | 0x2ffac | 206 | unknown | `if ((int)*(short *)(*(int *)(param_1 + 0x1a8) + 0x88) == uVar14) {` |
| FUN_00030850 | 0x30850 | 19 | unknown | `uVar3 = (uint)*(ushort *)(*(int *)(param_1 + 0x1a8) + 0x88);` |
| FUN_00030b38 | 0x30b38 | 11 | unknown | `(**(code **)(*(int *)(param_1 + 4) + 0x8c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x88));` |
| FUN_00031b38 | 0x31b38 | 53 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 0xffff;` |
| FUN_00031b38 | 0x31b38 | 74 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 0;` |
| FUN_00031b38 | 0x31b38 | 80 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 1;` |
| FUN_00031b38 | 0x31b38 | 164 | unknown | `if (*(short *)(iVar1 + 0x88) < 0) {` |
| FUN_00031b38 | 0x31b38 | 165 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 0;` |
| FUN_0003360c | 0x3360c | 58 | unknown | `(**(code **)(*(int *)(param_1 + 4) + 0x8c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x88));` |
| FUN_00037114 | 0x37114 | 20 | unknown | `piVar1 = (int *)(((int)*(short *)(param_1 + *(short *)(*(int *)(param_1 + 0x1a8) + 0x88) * 2 +` |
| FUN_00008158 | 0x8158 | 34 | unknown | `FUN_0003539c(*(undefined4 *)(param_1 + 0x10),*(undefined4 *)(param_1 + 0x88),0);` |
| FUN_000083ac | 0x83ac | 10 | write | `*(undefined4 *)(param_1 + 0x88) = 0;` |
| FUN_00008528 | 0x8528 | 64 | unknown | `FUN_000204e4(param_1,*(int *)(param_1 + 0x88) + 1);` |
| FUN_00008528 | 0x8528 | 80 | unknown | `FUN_000204e4(param_1,*(int *)(param_1 + 0x88) + -1);` |
| FUN_00008528 | 0x8528 | 155 | unknown | `*(int *)(*(int *)(param_1 + 0x84) + 0x88) = unaff_gp + -0x7fc8;` |
| FUN_00008528 | 0x8528 | 173 | unknown | `*(int *)(*(int *)(param_1 + 0x84) + 0x88) = unaff_gp + -0x7fa8;` |
| FUN_00008ce4 | 0x8ce4 | 25 | write | `*(int *)(param_1 + 0x88) = param_2;` |
| FUN_0001a320 | 0x1a320 | 55 | write | `*(undefined4 *)(param_1 + 0x88) = 0;` |
| FUN_0001a348 | 0x1a348 | 60 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 0;` |
| FUN_0001a3b0 | 0x1a3b0 | 40 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 0;` |
| FUN_0001a440 | 0x1a440 | 10 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 0;` |
| FUN_0001a4d0 | 0x1a4d0 | 5 | unknown | `if (*(int *)(param_1 + 0x88) != 0) {` |
| FUN_0001a528 | 0x1a528 | 8 | write | `if (*(int *)(param_1 + 0x88) == 0) {` |
| FUN_0001ab7c | 0x1ab7c | 16 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 1;` |
| FUN_0001ab94 | 0x1ab94 | 13 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 1;` |
| FUN_0001f734 | 0x1f734 | 31 | unknown | `*(undefined1 *)(iVar4 + 0x88) = 0;` |
| FUN_0001f7cc | 0x1f7cc | 35 | unknown | `*(undefined1 *)(param_2 + 0x88) = 0;` |
| FUN_0002273c | 0x2273c | 27 | unknown | `*(undefined4 *)(unaff_s1 + 0x88) = uVar1;` |
| FUN_0002273c | 0x2273c | 40 | unknown | `FUN_000356b4(unaff_gp + -0x7ef0,1,*(undefined4 *)(unaff_s1 + 0x88));` |
| FUN_0002336c | 0x2336c | 13 | unknown | `FUN_0001f7cc(*(undefined4 *)(param_1 + 0x88),0x80035464);` |
| FUN_00023390 | 0x23390 | 15 | unknown | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x88),0x80035464);` |
| FUN_000233a0 | 0x233a0 | 14 | unknown | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x88),0x80035464);` |
| FUN_000233dc | 0x233dc | 10 | unknown | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x88),0x80035464);` |
| FUN_00023d74 | 0x23d74 | 24 | unknown | `FUN_00035554(*(undefined4 *)(param_1 + 0x88));` |
| FUN_00001c84 | 0x1c84 | 416 | unknown | `(iVar8 + *(short *)(*(int *)(iVar8 + 4) + 0x88));` |
| FUN_00007680 | 0x7680 | 20 | unknown | `bVar1 = iVar2 == *(short *)(*(int *)(iVar4 + 0x1a8) + 0x88);` |
| FUN_00018aa4 | 0x18aa4 | 26 | unknown | `bVar2 = iVar4 == *(short *)(*(int *)(iVar5 + 0x1a8) + 0x88);` |
| FUN_0001efbc | 0x1efbc | 14 | unknown | `(**(code **)(*(int *)(param_1 + 4) + 0x8c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x88));` |
| FUN_0002e8f4 | 0x2e8f4 | 123 | unknown | `((undefined2 *)(param_1 + 0x1e0))[*(short *)(*(int *)(param_1 + 0x1a8) + 0x88)] = 0x800;` |
| FUN_0002f6d4 | 0x2f6d4 | 44 | unknown | `else if (param_3 == *(short *)(*(int *)(param_1 + 0x1a8) + 0x88)) {` |
| FUN_0002ffac | 0x2ffac | 36 | unknown | `(((int)*(short *)(iVar6 + 0x88) == uVar14 \|\| (iVar12 != *(int *)(param_1 + 0x1b4))))) {` |
| FUN_0002ffac | 0x2ffac | 113 | unknown | `uVar14 == (int)*(short *)(*(int *)(param_1 + 0x1a8) + 0x88))) {` |
| FUN_0002ffac | 0x2ffac | 206 | unknown | `if ((int)*(short *)(*(int *)(param_1 + 0x1a8) + 0x88) == uVar14) {` |
| FUN_00030850 | 0x30850 | 19 | unknown | `uVar3 = (uint)*(ushort *)(*(int *)(param_1 + 0x1a8) + 0x88);` |
| FUN_00030b38 | 0x30b38 | 11 | unknown | `(**(code **)(*(int *)(param_1 + 4) + 0x8c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x88));` |
| FUN_00031b38 | 0x31b38 | 53 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 0xffff;` |
| FUN_00031b38 | 0x31b38 | 74 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 0;` |
| FUN_00031b38 | 0x31b38 | 80 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 1;` |
| FUN_00031b38 | 0x31b38 | 164 | unknown | `if (*(short *)(iVar1 + 0x88) < 0) {` |
| FUN_00031b38 | 0x31b38 | 165 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 0;` |
| FUN_0003360c | 0x3360c | 58 | unknown | `(**(code **)(*(int *)(param_1 + 4) + 0x8c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x88));` |
| FUN_00037114 | 0x37114 | 20 | unknown | `piVar1 = (int *)(((int)*(short *)(param_1 + *(short *)(*(int *)(param_1 + 0x1a8) + 0x88) * 2 +` |
| FUN_00007680 | 0x7680 | 20 | unknown | `bVar1 = iVar2 == *(short *)(*(int *)(iVar4 + 0x1a8) + 0x88);` |
| FUN_00018aa4 | 0x18aa4 | 26 | unknown | `bVar2 = iVar4 == *(short *)(*(int *)(iVar5 + 0x1a8) + 0x88);` |
| FUN_0001efbc | 0x1efbc | 14 | unknown | `(**(code **)(*(int *)(param_1 + 4) + 0x8c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x88));` |
| FUN_0002e8f4 | 0x2e8f4 | 123 | unknown | `((undefined2 *)(param_1 + 0x1e0))[*(short *)(*(int *)(param_1 + 0x1a8) + 0x88)] = 0x800;` |
| FUN_0002f6d4 | 0x2f6d4 | 44 | unknown | `else if (param_3 == *(short *)(*(int *)(param_1 + 0x1a8) + 0x88)) {` |
| FUN_0002ffac | 0x2ffac | 36 | unknown | `(((int)*(short *)(iVar6 + 0x88) == uVar14 \|\| (iVar12 != *(int *)(param_1 + 0x1b4))))) {` |
| FUN_0002ffac | 0x2ffac | 113 | unknown | `uVar14 == (int)*(short *)(*(int *)(param_1 + 0x1a8) + 0x88))) {` |
| FUN_0002ffac | 0x2ffac | 206 | unknown | `if ((int)*(short *)(*(int *)(param_1 + 0x1a8) + 0x88) == uVar14) {` |
| FUN_00030850 | 0x30850 | 19 | unknown | `uVar3 = (uint)*(ushort *)(*(int *)(param_1 + 0x1a8) + 0x88);` |
| FUN_00030b38 | 0x30b38 | 11 | unknown | `(**(code **)(*(int *)(param_1 + 4) + 0x8c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x88));` |
| FUN_00031b38 | 0x31b38 | 53 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 0xffff;` |
| FUN_00031b38 | 0x31b38 | 74 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 0;` |
| FUN_00031b38 | 0x31b38 | 80 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 1;` |
| FUN_00031b38 | 0x31b38 | 164 | unknown | `if (*(short *)(iVar1 + 0x88) < 0) {` |
| FUN_00031b38 | 0x31b38 | 165 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 0;` |
| FUN_0003360c | 0x3360c | 58 | unknown | `(**(code **)(*(int *)(param_1 + 4) + 0x8c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x88));` |
| FUN_00037114 | 0x37114 | 20 | unknown | `piVar1 = (int *)(((int)*(short *)(param_1 + *(short *)(*(int *)(param_1 + 0x1a8) + 0x88) * 2 +` |
| FUN_00008158 | 0x8158 | 34 | unknown | `FUN_0003539c(*(undefined4 *)(param_1 + 0x10),*(undefined4 *)(param_1 + 0x88),0);` |
| FUN_000083ac | 0x83ac | 10 | write | `*(undefined4 *)(param_1 + 0x88) = 0;` |
| FUN_00008528 | 0x8528 | 64 | unknown | `FUN_000204e4(param_1,*(int *)(param_1 + 0x88) + 1);` |
| FUN_00008528 | 0x8528 | 80 | unknown | `FUN_000204e4(param_1,*(int *)(param_1 + 0x88) + -1);` |
| FUN_00008528 | 0x8528 | 155 | unknown | `*(int *)(*(int *)(param_1 + 0x84) + 0x88) = unaff_gp + -0x7fc8;` |
| FUN_00008528 | 0x8528 | 173 | unknown | `*(int *)(*(int *)(param_1 + 0x84) + 0x88) = unaff_gp + -0x7fa8;` |
| FUN_00008ce4 | 0x8ce4 | 25 | write | `*(int *)(param_1 + 0x88) = param_2;` |
| FUN_0001a320 | 0x1a320 | 55 | write | `*(undefined4 *)(param_1 + 0x88) = 0;` |
| FUN_0001a348 | 0x1a348 | 60 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 0;` |
| FUN_0001a3b0 | 0x1a3b0 | 40 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 0;` |
| FUN_0001a440 | 0x1a440 | 10 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 0;` |
| FUN_0001a4d0 | 0x1a4d0 | 5 | unknown | `if (*(int *)(param_1 + 0x88) != 0) {` |
| FUN_0001a528 | 0x1a528 | 8 | write | `if (*(int *)(param_1 + 0x88) == 0) {` |
| FUN_0001ab7c | 0x1ab7c | 16 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 1;` |
| FUN_0001ab94 | 0x1ab94 | 13 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 1;` |
| FUN_0001f734 | 0x1f734 | 31 | unknown | `*(undefined1 *)(iVar4 + 0x88) = 0;` |
| FUN_0001f7cc | 0x1f7cc | 35 | unknown | `*(undefined1 *)(param_2 + 0x88) = 0;` |
| FUN_0002273c | 0x2273c | 27 | unknown | `*(undefined4 *)(unaff_s1 + 0x88) = uVar1;` |
| FUN_0002273c | 0x2273c | 40 | unknown | `FUN_000356b4(unaff_gp + -0x7ef0,1,*(undefined4 *)(unaff_s1 + 0x88));` |
| FUN_0002336c | 0x2336c | 13 | unknown | `FUN_0001f7cc(*(undefined4 *)(param_1 + 0x88),0x80035464);` |
| FUN_00023390 | 0x23390 | 15 | unknown | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x88),0x80035464);` |
| FUN_000233a0 | 0x233a0 | 14 | unknown | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x88),0x80035464);` |
| FUN_000233dc | 0x233dc | 10 | unknown | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x88),0x80035464);` |
| FUN_00023d74 | 0x23d74 | 24 | unknown | `FUN_00035554(*(undefined4 *)(param_1 + 0x88));` |
| FUN_00001c84 | 0x1c84 | 416 | unknown | `(iVar8 + *(short *)(*(int *)(iVar8 + 4) + 0x88));` |
| FUN_00007680 | 0x7680 | 20 | unknown | `bVar1 = iVar2 == *(short *)(*(int *)(iVar4 + 0x1a8) + 0x88);` |
| FUN_00018aa4 | 0x18aa4 | 26 | unknown | `bVar2 = iVar4 == *(short *)(*(int *)(iVar5 + 0x1a8) + 0x88);` |
| FUN_0001efbc | 0x1efbc | 14 | unknown | `(**(code **)(*(int *)(param_1 + 4) + 0x8c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x88));` |
| FUN_0002e8f4 | 0x2e8f4 | 123 | unknown | `((undefined2 *)(param_1 + 0x1e0))[*(short *)(*(int *)(param_1 + 0x1a8) + 0x88)] = 0x800;` |
| FUN_0002f6d4 | 0x2f6d4 | 44 | unknown | `else if (param_3 == *(short *)(*(int *)(param_1 + 0x1a8) + 0x88)) {` |
| FUN_0002ffac | 0x2ffac | 36 | unknown | `(((int)*(short *)(iVar6 + 0x88) == uVar14 \|\| (iVar12 != *(int *)(param_1 + 0x1b4))))) {` |
| FUN_0002ffac | 0x2ffac | 113 | unknown | `uVar14 == (int)*(short *)(*(int *)(param_1 + 0x1a8) + 0x88))) {` |
| FUN_0002ffac | 0x2ffac | 206 | unknown | `if ((int)*(short *)(*(int *)(param_1 + 0x1a8) + 0x88) == uVar14) {` |
| FUN_00030850 | 0x30850 | 19 | unknown | `uVar3 = (uint)*(ushort *)(*(int *)(param_1 + 0x1a8) + 0x88);` |
| FUN_00030b38 | 0x30b38 | 11 | unknown | `(**(code **)(*(int *)(param_1 + 4) + 0x8c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x88));` |
| FUN_00031b38 | 0x31b38 | 53 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 0xffff;` |
| FUN_00031b38 | 0x31b38 | 74 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 0;` |
| FUN_00031b38 | 0x31b38 | 80 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 1;` |
| FUN_00031b38 | 0x31b38 | 164 | unknown | `if (*(short *)(iVar1 + 0x88) < 0) {` |
| FUN_00031b38 | 0x31b38 | 165 | unknown | `*(undefined2 *)(iVar1 + 0x88) = 0;` |
| FUN_0003360c | 0x3360c | 58 | unknown | `(**(code **)(*(int *)(param_1 + 4) + 0x8c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x88));` |
| FUN_00037114 | 0x37114 | 20 | unknown | `piVar1 = (int *)(((int)*(short *)(param_1 + *(short *)(*(int *)(param_1 + 0x1a8) + 0x88) * 2 +` |
| FUN_00008158 | 0x8158 | 34 | unknown | `FUN_0003539c(*(undefined4 *)(param_1 + 0x10),*(undefined4 *)(param_1 + 0x88),0);` |
| FUN_000083ac | 0x83ac | 10 | write | `*(undefined4 *)(param_1 + 0x88) = 0;` |
| FUN_00008528 | 0x8528 | 64 | unknown | `FUN_000204e4(param_1,*(int *)(param_1 + 0x88) + 1);` |
| FUN_00008528 | 0x8528 | 80 | unknown | `FUN_000204e4(param_1,*(int *)(param_1 + 0x88) + -1);` |
| FUN_00008528 | 0x8528 | 155 | unknown | `*(int *)(*(int *)(param_1 + 0x84) + 0x88) = unaff_gp + -0x7fc8;` |
| FUN_00008528 | 0x8528 | 173 | unknown | `*(int *)(*(int *)(param_1 + 0x84) + 0x88) = unaff_gp + -0x7fa8;` |
| FUN_00008ce4 | 0x8ce4 | 25 | write | `*(int *)(param_1 + 0x88) = param_2;` |
| FUN_0001a320 | 0x1a320 | 55 | write | `*(undefined4 *)(param_1 + 0x88) = 0;` |
| FUN_0001a348 | 0x1a348 | 60 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 0;` |
| FUN_0001a3b0 | 0x1a3b0 | 40 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 0;` |
| FUN_0001a440 | 0x1a440 | 10 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 0;` |
| FUN_0001a4d0 | 0x1a4d0 | 5 | unknown | `if (*(int *)(param_1 + 0x88) != 0) {` |
| FUN_0001a528 | 0x1a528 | 8 | write | `if (*(int *)(param_1 + 0x88) == 0) {` |
| FUN_0001ab7c | 0x1ab7c | 16 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 1;` |
| FUN_0001ab94 | 0x1ab94 | 13 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 1;` |
| FUN_0001f734 | 0x1f734 | 31 | unknown | `*(undefined1 *)(iVar4 + 0x88) = 0;` |
| FUN_0001f7cc | 0x1f7cc | 35 | unknown | `*(undefined1 *)(param_2 + 0x88) = 0;` |
| FUN_0002273c | 0x2273c | 27 | unknown | `*(undefined4 *)(unaff_s1 + 0x88) = uVar1;` |
| FUN_0002273c | 0x2273c | 40 | unknown | `FUN_000356b4(unaff_gp + -0x7ef0,1,*(undefined4 *)(unaff_s1 + 0x88));` |
| FUN_0002336c | 0x2336c | 13 | unknown | `FUN_0001f7cc(*(undefined4 *)(param_1 + 0x88),0x80035464);` |
| FUN_00023390 | 0x23390 | 15 | unknown | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x88),0x80035464);` |
| FUN_000233a0 | 0x233a0 | 14 | unknown | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x88),0x80035464);` |
| FUN_000233dc | 0x233dc | 10 | unknown | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x88),0x80035464);` |
| FUN_00023d74 | 0x23d74 | 24 | unknown | `FUN_00035554(*(undefined4 *)(param_1 + 0x88));` |
| FUN_00001c84 | 0x1c84 | 416 | unknown | `(iVar8 + *(short *)(*(int *)(iVar8 + 4) + 0x88));` |
| FUN_00008158 | 0x8158 | 34 | unknown | `FUN_0003539c(*(undefined4 *)(param_1 + 0x10),*(undefined4 *)(param_1 + 0x88),0);` |
| FUN_000083ac | 0x83ac | 10 | write | `*(undefined4 *)(param_1 + 0x88) = 0;` |
| FUN_00008528 | 0x8528 | 64 | unknown | `FUN_000204e4(param_1,*(int *)(param_1 + 0x88) + 1);` |
| FUN_00008528 | 0x8528 | 80 | unknown | `FUN_000204e4(param_1,*(int *)(param_1 + 0x88) + -1);` |
| FUN_00008528 | 0x8528 | 155 | unknown | `*(int *)(*(int *)(param_1 + 0x84) + 0x88) = unaff_gp + -0x7fc8;` |
| FUN_00008528 | 0x8528 | 173 | unknown | `*(int *)(*(int *)(param_1 + 0x84) + 0x88) = unaff_gp + -0x7fa8;` |
| FUN_00008ce4 | 0x8ce4 | 25 | write | `*(int *)(param_1 + 0x88) = param_2;` |
| FUN_0001a320 | 0x1a320 | 55 | write | `*(undefined4 *)(param_1 + 0x88) = 0;` |
| FUN_0001a348 | 0x1a348 | 60 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 0;` |
| FUN_0001a3b0 | 0x1a3b0 | 40 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 0;` |
| FUN_0001a440 | 0x1a440 | 10 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 0;` |
| FUN_0001a4d0 | 0x1a4d0 | 5 | unknown | `if (*(int *)(param_1 + 0x88) != 0) {` |
| FUN_0001a528 | 0x1a528 | 8 | write | `if (*(int *)(param_1 + 0x88) == 0) {` |
| FUN_0001ab7c | 0x1ab7c | 16 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 1;` |
| FUN_0001ab94 | 0x1ab94 | 13 | unknown | `*(undefined4 *)(unaff_s0 + 0x88) = 1;` |
| FUN_0001f734 | 0x1f734 | 31 | unknown | `*(undefined1 *)(iVar4 + 0x88) = 0;` |
| FUN_0001f7cc | 0x1f7cc | 35 | unknown | `*(undefined1 *)(param_2 + 0x88) = 0;` |
| FUN_0002273c | 0x2273c | 27 | unknown | `*(undefined4 *)(unaff_s1 + 0x88) = uVar1;` |
| FUN_0002273c | 0x2273c | 40 | unknown | `FUN_000356b4(unaff_gp + -0x7ef0,1,*(undefined4 *)(unaff_s1 + 0x88));` |
| FUN_0002336c | 0x2336c | 13 | unknown | `FUN_0001f7cc(*(undefined4 *)(param_1 + 0x88),0x80035464);` |
| FUN_00023390 | 0x23390 | 15 | unknown | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x88),0x80035464);` |
| FUN_000233a0 | 0x233a0 | 14 | unknown | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x88),0x80035464);` |
| FUN_000233dc | 0x233dc | 10 | unknown | `FUN_0001f7cc(*(undefined4 *)(unaff_s0 + 0x88),0x80035464);` |
| FUN_00023d74 | 0x23d74 | 24 | unknown | `FUN_00035554(*(undefined4 *)(param_1 + 0x88));` |
| FUN_00001c84 | 0x1c84 | 416 | unknown | `(iVar8 + *(short *)(*(int *)(iVar8 + 4) + 0x88));` |
