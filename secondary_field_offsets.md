# Secondary Field Offsets via +0x11C Pointer

| Off | Read | Write | ShiftLocal | ShiftNear | Funcs |
|-----|------|-------|------------|-----------|-------|
| 0x40 | 0 | 8 | 0 | 0 | 2 |
| 0x60 | 8 | 0 | 0 | 0 | 2 |
| 0x22 | 4 | 0 | 0 | 0 | 1 |
| 0x1e | 4 | 0 | 0 | 0 | 1 |
| 0xa4 | 0 | 4 | 0 | 0 | 1 |
| 0x2c | 4 | 0 | 0 | 0 | 1 |

## Context Samples

### Offset 0x40
- `iVar2 = func_0x00095d6c(*(undefined4 *)(*(int *)(iVar8 + 0x11c) + 0x40),`
- `iVar1 = func_0x00095d6c(*(undefined4 *)(*(int *)(iVar3 + 0x11c) + 0x40),`
- `iVar2 = func_0x00095d6c(*(undefined4 *)(*(int *)(iVar8 + 0x11c) + 0x40),`

### Offset 0x60
- `if (-1 < *(short *)(*(int *)(param_1 + 0x11c) + 0x60)) {`
- `if (-1 < *(short *)(*(int *)(param_1 + 0x11c) + 0x60)) {`
- `if (-1 < *(short *)(*(int *)(param_1 + 0x11c) + 0x60)) {`

### Offset 0x22
- `func_0x000c994c(param_1,(uint)*(ushort *)(*(int *)(*(int *)(param_2 + 8) + 0x11c) + 0x22) * 3);`
- `func_0x000c994c(param_1,(uint)*(ushort *)(*(int *)(*(int *)(param_2 + 8) + 0x11c) + 0x22) * 3);`
- `func_0x000c994c(param_1,(uint)*(ushort *)(*(int *)(*(int *)(param_2 + 8) + 0x11c) + 0x22) * 3);`

### Offset 0x1e
- `if (*(ushort *)(*(int *)(iVar4 + 0x11c) + 0x1e) < 0xf87) {`
- `if (*(ushort *)(*(int *)(iVar4 + 0x11c) + 0x1e) < 0xf87) {`
- `if (*(ushort *)(*(int *)(iVar4 + 0x11c) + 0x1e) < 0xf87) {`
