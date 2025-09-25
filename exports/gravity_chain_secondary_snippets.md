# Secondary Chain Candidate Snippets


## FUN_00022790  | score=7.3 overlap=2 overlap2=0 vref=5 shifts=0

```c
  (**(code **)(*(int *)(param_1 + 4) + 0x5c))(param_1 + *(short *)(*(int *)(param_1 + 4) + 0x58),0);
  *(undefined4 *)(param_1 + 8) = *param_2;
  iVar5 = *(short *)(param_1 + 8) + 0x4000;
  *(undefined4 *)(param_1 + 0xc) = param_2[1];
  if (iVar5 < 0) {
```
```c
  *(undefined4 *)(param_1 + 0xc) = param_2[1];
  if (iVar5 < 0) {
    iVar5 = *(short *)(param_1 + 8) + 0x40ff;
  }
  iVar6 = *(short *)(param_1 + 0xc) + 0x4000;
```
```c
    iVar5 = *(short *)(param_1 + 8) + 0x40ff;
  }
  iVar6 = *(short *)(param_1 + 0xc) + 0x4000;
  if (iVar6 < 0) {
    iVar6 = *(short *)(param_1 + 0xc) + 0x40ff;
```
```c
  iVar6 = *(short *)(param_1 + 0xc) + 0x4000;
  if (iVar6 < 0) {
    iVar6 = *(short *)(param_1 + 0xc) + 0x40ff;
  }
  iVar5 = func_0x000829a8(iVar5 >> 8 & 0xffff,iVar6 >> 8 & 0xffff,0);
```
```c
        return uVar4;
      }
      *(undefined2 *)(param_1 + 0x36) = 0;
      *(uint *)(param_1 + 0x50) = *(uint *)(param_1 + 0x50) & 0xfffffff7 | 4;
    }
```

## FUN_0002f200  | score=6.75 overlap=2 overlap2=0 vref=5 shifts=0

```c
  
  uVar8 = 0;
  *(undefined4 *)(param_1 + 0x34) = 0;
  *(undefined4 *)(param_1 + 0x38) = 0;
  *(undefined4 *)(param_1 + 0x100) = 0;
```
```c
  uVar8 = 0;
  *(undefined4 *)(param_1 + 0x34) = 0;
  *(undefined4 *)(param_1 + 0x38) = 0;
  *(undefined4 *)(param_1 + 0x100) = 0;
  *(undefined4 *)(param_1 + 0x104) = 0;
```
```c
    *(undefined4 *)(iVar3 + 0x10) = 0;
    uVar1 = *(ushort *)(*(int *)(param_1 + 0x1a8) + 0x186);
    *(ushort *)(iVar3 + 0x34) = uVar1;
    *(uint *)(iVar3 + 0x30) = (uint)uVar1 * (uint)uVar1;
    func_0x00080d14(iVar3,iVar5);
```
```c
        iVar5 = *(int *)(iVar4 + 4);
        uVar6 = uVar6 + 1;
        (**(code **)(iVar5 + 0x3c))(iVar4 + *(short *)(iVar5 + 0x38),param_1);
      } while (uVar6 < uVar8);
    }
```

## FUN_00046a34  | score=6.75 overlap=2 overlap2=0 vref=3 shifts=2

```c
        iVar8 = (uint)*(ushort *)(param_1 + 8) +
                ((uint)((int)*(short *)((*(ushort *)(*(int *)(param_1 + 0xd8) + 0x12) & 0xfff) * 4 +
                                       -0x7ffeb164) << 10) >> 0xc);
        sVar4 = *(short *)(param_1 + 0xc) +
                (short)((uint)((int)*(short *)((*(ushort *)(*(int *)(param_1 + 0xd8) + 0x12) & 0xfff
```
```c
        sVar4 = *(short *)(param_1 + 0xc) +
                (short)((uint)((int)*(short *)((*(ushort *)(*(int *)(param_1 + 0xd8) + 0x12) & 0xfff
                                               ) * 4 + -0x7ffeb162) << 10) >> 0xc);
        iVar7 = iVar8 * 0x10000 >> 0x10;
        if (((iVar7 < -0x4000) || (uVar6 = 0x4000, iVar7 < 0x4001)) &&
```
```c
    func_0x00087394(uVar10,param_1 + 8,*(int *)(param_1 + 0xd4) + 0x6c,iVar8 + 0x32,uVar9,0);
    iVar8 = *(int *)(*(int *)(param_1 + 0xd4) + 4);
    (**(code **)(iVar8 + 0x3c))(*(int *)(param_1 + 0xd4) + (int)*(short *)(iVar8 + 0x38),param_1);
    uVar2 = **(ushort **)(param_1 + 0xb8);
    if (uVar2 != 0x44) {
```
```c
    local_28 = local_30;
    local_24 = local_2c;
    func_0x00109758(param_1,local_30,local_2c,param_1 + 0x3c);
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*(int *)(param_1 + 0xd4) + 0x6c);
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*(int *)(param_1 + 0xd4) + 0x70);
```

## FUN_00023488  | score=6.7 overlap=2 overlap2=0 vref=4 shifts=0

```c
    }
    *(undefined4 *)(unaff_s0 + 0x10) = 1;
    *(undefined2 *)(unaff_s0 + 0x34) = 0x80;
    *(undefined4 *)(unaff_s0 + 0x30) = 0x4000;
    *(undefined2 *)(unaff_s0 + 0x36) = 0x100;
```
```c
    *(undefined2 *)(unaff_s0 + 0x34) = 0x80;
    *(undefined4 *)(unaff_s0 + 0x30) = 0x4000;
    *(undefined2 *)(unaff_s0 + 0x36) = 0x100;
    func_0x00080d2c();
  }
```
```c
    *(undefined2 *)(unaff_s1 + 0xc0) = 0x2a;
    *(undefined4 *)(unaff_s0 + 0x10) = 1;
    *(undefined2 *)(unaff_s0 + 0x34) = 0x100;
    *(undefined4 *)(unaff_s0 + 0x30) = 0x10000;
    *(undefined2 *)(unaff_s0 + 0x36) = 0x200;
```
```c
    *(undefined2 *)(unaff_s0 + 0x34) = 0x100;
    *(undefined4 *)(unaff_s0 + 0x30) = 0x10000;
    *(undefined2 *)(unaff_s0 + 0x36) = 0x200;
    func_0x00080d2c();
  }
```

## FUN_000249e4  | score=5.5 overlap=2 overlap2=0 vref=2 shifts=0

```c
                if (iVar5 != 0) {
                  uVar2 = FUN_000209dc();
                  *(ushort *)(iVar5 + 0x3e) = uVar2 & 0xfff;
                  *(undefined2 *)(iVar5 + 0x44) = 0x28;
                  *(undefined2 *)(iVar5 + 0x36) = 0xed40;
```
```c
                  uVar2 = FUN_000209dc();
                  *(ushort *)(iVar5 + 0x3e) = uVar2 & 0xfff;
                  *(undefined2 *)(iVar5 + 0x44) = 0x28;
                  *(undefined2 *)(iVar5 + 0x36) = 0xed40;
                }
```
```c
                  *(ushort *)(iVar5 + 0x3e) = uVar2 & 0xfff;
                  *(undefined2 *)(iVar5 + 0x44) = 0x28;
                  *(undefined2 *)(iVar5 + 0x36) = 0xed40;
                }
              }
```

## FUN_00023364  | score=5.25 overlap=2 overlap2=0 vref=1 shifts=0

```c
  *(uint *)(param_1 + 0xb8) = *(uint *)(param_1 + 0xb8) & 0xfffffffd;
  if (param_2 != 0) {
    iVar3 = (*(ushort *)(param_1 + 0x3e) & 0xfff) * 4;
    iVar4 = (int)*(short *)(iVar3 + -0x7ffeb164);
    if (iVar4 < 0) {
```
```c
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined2 *)(param_1 + 0x44) = 0;
  *(uint *)(param_1 + 0xb8) = *(uint *)(param_1 + 0xb8) & 0xffffffe7;
  func_0x000e58f4(param_1,0);
```

## FUN_0001d3a4  | score=4.8 overlap=2 overlap2=0 vref=0 shifts=0

_No relevant lines found._


## FUN_000412d8  | score=4.2 overlap=2 overlap2=0 vref=0 shifts=0

_No relevant lines found._
