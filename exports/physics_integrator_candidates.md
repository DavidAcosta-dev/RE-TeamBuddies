# Physics Integrator Candidates

## FUN_00022dc8 @ 0x22dc8

- Base: `param_1`
- Axes: Z
- Direct pos write: yes

```c
*(ushort *)(param_1 + 0xc) = *(ushort *)(param_1 + 0xc) - (short)(-(iVar4 * iVar6) >> 0xc);
iVar4 = -(iVar9 * 0x10000 >> 0x10) * iVar8 - (iVar10 * 0x10000 >> 0x10) * iVar6 >> 0xc;
*(ushort *)(param_1 + 8) = *(ushort *)(param_1 + 8) - (short)(-(iVar4 * iVar8) >> 0xc);
```

## FUN_00022e5c @ 0x22e5c

- Base: `unaff_s2`
- Axes: Z
- Direct pos write: yes

```c
*(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar10 * iVar8) >> 0xc);
iVar10 = -(iVar11 * 0x10000 >> 0x10) * iVar6 - (iVar5 * 0x10000 >> 0x10) * iVar8 >> 0xc;
*(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar10 * iVar6) >> 0xc);
```

## FUN_00023000 @ 0x23000

- Base: `unaff_s2`
- Axes: Z
- Direct pos write: yes

```c
*(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar3 * iVar4) >> 0xc);
*(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar3 * iVar6) >> 0xc);
```

## FUN_00023110 @ 0x23110

- Base: `unaff_s2`
- Axes: Z
- Direct pos write: yes

```c
*(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar3 * iVar4) >> 0xc);
>> 0xc;
*(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar3 * iVar5) >> 0xc);
```

## FUN_00023180 @ 0x23180

- Base: `unaff_s2`
- Axes: Z
- Direct pos write: yes

```c
*(ushort *)(unaff_s2 + 0xc) = *(ushort *)(unaff_s2 + 0xc) - (short)(-(iVar2 * iVar5) >> 0xc);
iVar2 = -(iVar3 * 0x10000 >> 0x10) * iVar6 - (iVar4 * 0x10000 >> 0x10) * iVar5 >> 0xc;
*(ushort *)(unaff_s2 + 8) = *(ushort *)(unaff_s2 + 8) - (short)(-(iVar2 * iVar6) >> 0xc);
```

## FUN_00023210 @ 0x23210

- Base: `unaff_s2`
- Axes: Z
- Direct pos write: yes

```c
*(short *)(unaff_s2 + 0xc) = in_t1 - (short)(-((in_v1 + -10) * param_3) >> 0xc);
*(short *)(unaff_s2 + 8) = in_t2 - (short)(-((in_v1 + -10) * in_t0) >> 0xc);
```

## FUN_00023698 @ 0x23698

- Base: `param_1`
- Axes: Z
- Direct pos write: no

```c
uVar4 = (int)((uint)*(ushort *)(param_1 + 0xd6) * (int)*(short *)(iVar5 + -0x7ffeb164)) >> 0xc;
uVar3 = (int)((uint)*(ushort *)(param_1 + 0xd6) * (int)*(short *)(iVar5 + -0x7ffeb162)) >> 0xc;
```

## FUN_00025c18 @ 0x25c18

- Base: `iVar2`
- Axes: Z
- Direct pos write: no

```c
*puVar6 = (ushort)((int)((uint)*puVar6 * 0x1333) >> 0xc);
```

## FUN_00035cc0 @ 0x35cc0

- Base: `param_1`
- Axes: Z
- Direct pos write: no

```c
>> 0xc;
local_44 >> 0xc;
```

## FUN_00044a14 @ 0x44a14

- Base: `param_1`
- Axes: Z
- Direct pos write: no

```c
(int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc);
(short)((int)(uVar4 * (int)*(short *)(param_1 + 0x36)) >> 0xc),
(short)((int)(uVar4 * (int)*(short *)(param_1 + 0x34)) >> 0xc));
```

## FUN_00044f80 @ 0x44f80

- Base: `param_1`
- Axes: Z
- Direct pos write: no

```c
*(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);
*(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);
*(short *)(param_1 + 0x38) = (short)(*(short *)(param_1 + 0x40) * iVar12 >> 0xc);
```

## FUN_00046024 @ 0x46024

- Base: `param_1`
- Axes: Z
- Direct pos write: no

```c
local_40 = CONCAT22(0x1000 - (short)(iVar2 * iVar2 >> 0xc),
-(short)(iVar2 * *(short *)(param_1 + 0x3c) >> 0xc));
local_3c = CONCAT22(local_3c._2_2_,-(short)(iVar2 * *(short *)(param_1 + 0x40) >> 0xc));
```

