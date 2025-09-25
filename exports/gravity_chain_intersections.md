# Gravity Chain Intersection Inference

Integrator count (union): 18  | Integrator callee union: 8

Thresholds: MIN_CALLEE_INTERSECT=3, MIN_CALLEE_INTERSECT2=2, MIN_VERTICAL_REFS=4, MIN_SHIFTS=2

Candidates ranked (top 10):

| Function | Score | DirInt | Overlap | Overlap2 | VertRefs | Shifts | Reasons | TopOverlap | TopOverlap2 |
|----------|------:|-------:|--------:|---------:|---------:|-------:|---------|-----------|------------|
| FUN_0003b264 | 17.80 | 0 | 3 | 0 | 22 | 0 | overlap>=3 | FUN_000209dc,FUN_00022e5c,FUN_00023180 |  |
| FUN_00022dc8 | 14.00 | 0 | 3 | 1 | 8 | 3 | overlap>=3+vertical+shifts | FUN_00022e5c,FUN_00023000,FUN_00023180 | FUN_00022bac |
| FUN_00035cc0 | 11.80 | 0 | 2 | 0 | 12 | 2 | vertical+shifts | FUN_00022e5c,FUN_000402e0 |  |
| FUN_00022e5c | 11.50 | 0 | 2 | 1 | 8 | 3 | vertical+shifts | FUN_00022e5c,FUN_00023180 | FUN_00022bac |
| FUN_00023000 | 9.75 | 0 | 2 | 0 | 8 | 2 | vertical+shifts | FUN_00023000,FUN_00023180 |  |
| FUN_0004a058 | 8.00 | 0 | 1 | 0 | 9 | 3 | vertical+shifts | FUN_000209dc |  |
| FUN_00042518 | 6.70 | 0 | 3 | 0 | 0 | 0 | overlap>=3 | FUN_00023000,FUN_0003e4b4,FUN_0004033c |  |
| FUN_0001f218 | 6.50 | 1 | 0 | 0 | 3 | 0 | direct_integrator_call |  |  |
| FUN_00035088 | 4.50 | 0 | 0 | 0 | 6 | 3 | vertical+shifts |  |  |
| FUN_00023110 | 3.50 | 0 | 0 | 0 | 4 | 3 | vertical+shifts |  |  |

## Potential New Caller→Integrator Edges

| Caller | Integrator |
|--------|------------|
| FUN_0001f218 | FUN_00040a98 |

### Bridge Paths (Depth <= 4)

_No bridge paths discovered._

### Reverse Bridge Paths (Depth <= 4)

_No reverse bridge paths discovered._

## Secondary Candidates (Relaxed Overlap)

Relaxed thresholds: overlap>=2 or overlap2>=2 (other gates unchanged). Top 8 shown.

| Function | Score | DirInt | Overlap | Overlap2 | VertRefs | Shifts | Reasons | TopOverlap | TopOverlap2 |
|----------|------:|-------:|--------:|---------:|---------:|-------:|---------|-----------|------------|
| FUN_00022790 | 7.30 | 0 | 2 | 0 | 5 | 0 |  | FUN_00022e5c,FUN_000402e0 |  |
| FUN_0002f200 | 6.75 | 0 | 2 | 0 | 5 | 0 |  | FUN_000209dc,FUN_000402e0 |  |
| FUN_00046a34 | 6.75 | 0 | 2 | 0 | 3 | 2 |  | FUN_000209dc,FUN_00023180 |  |
| FUN_00023488 | 6.70 | 0 | 2 | 0 | 4 | 0 |  | FUN_00023000,FUN_00023488 |  |
| FUN_000249e4 | 5.50 | 0 | 2 | 0 | 2 | 0 |  | FUN_000209dc,FUN_00023000 |  |
| FUN_00023364 | 5.25 | 0 | 2 | 0 | 1 | 0 |  | FUN_00023000,FUN_000402e0 |  |
| FUN_0001d3a4 | 4.80 | 0 | 2 | 0 | 0 | 0 |  | FUN_00022e5c,FUN_00023180 |  |
| FUN_000412d8 | 4.20 | 0 | 2 | 0 | 0 | 0 |  | FUN_0003e4b4,FUN_0004033c |  |

## Top Overlap Neighbor Snippets

### FUN_0003b264  (showing up to 3 neighbors)

- FUN_000209dc

_No relevant lines found._

- FUN_00022e5c

```c
                          (int)sStack00000024 * (int)sStack00000024);
    iVar10 = (iVar10 + -300) * 0x10000 >> 0x10;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar10 * (iVar5 >> uVar7) >> 0xf))
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x34) = sVar3;
```

- FUN_00023180

```c
  iVar6 = (int)*(short *)(iVar2 + -0x7ffeb164);
  iVar5 = (int)*(short *)(iVar2 + -0x7ffeb162);
  iVar2 = -(iVar3 * 0x10000 >> 0x10) * iVar6 - (iVar4 * 0x10000 >> 0x10) * iVar5 >> 0xc;
  if (iVar2 < 0) {
    iVar2 = iVar2 + -10;
```

### FUN_00022dc8  (showing up to 3 neighbors)

- FUN_00022e5c

```c
                          (int)sStack00000024 * (int)sStack00000024);
    iVar10 = (iVar10 + -300) * 0x10000 >> 0x10;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar10 * (iVar5 >> uVar7) >> 0xf))
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x34) = sVar3;
```

- FUN_00023000

```c
                       (int)param_9._2_2_ * (int)param_9._2_2_ + (int)param_10 * (int)param_10);
  iVar3 = (iVar3 + -300) * 0x10000 >> 0x10;
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar3 * param_11 >> 0xf)) * 0x10000)
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x34) = sVar1;
```

- FUN_00023180

```c
  iVar6 = (int)*(short *)(iVar2 + -0x7ffeb164);
  iVar5 = (int)*(short *)(iVar2 + -0x7ffeb162);
  iVar2 = -(iVar3 * 0x10000 >> 0x10) * iVar6 - (iVar4 * 0x10000 >> 0x10) * iVar5 >> 0xc;
  if (iVar2 < 0) {
    iVar2 = iVar2 + -10;
```

### FUN_00035cc0  (showing up to 3 neighbors)

- FUN_00022e5c

```c
                          (int)sStack00000024 * (int)sStack00000024);
    iVar10 = (iVar10 + -300) * 0x10000 >> 0x10;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar10 * (iVar5 >> uVar7) >> 0xf))
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x34) = sVar3;
```

- FUN_000402e0

```c
    iVar3 = uVar4 * 4;
    uVar4 = uVar4 + 1 & 0xffff;
    *(undefined4 *)(param_3 + 0x24 + iVar3) = *(undefined4 *)(param_4 + 0x38 + iVar3);
  } while (uVar4 < 5);
  uVar2 = *(ushort *)(param_3 + 0x42);
```

### FUN_00022e5c  (showing up to 3 neighbors)

- FUN_00022e5c

```c
                          (int)sStack00000024 * (int)sStack00000024);
    iVar10 = (iVar10 + -300) * 0x10000 >> 0x10;
    sVar3 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar10 * (iVar5 >> uVar7) >> 0xf))
                          * 0x10000) >> 0x10) * 0x1a9 >> 9);
    *(short *)(unaff_s2 + 0x34) = sVar3;
```

- FUN_00023180

```c
  iVar6 = (int)*(short *)(iVar2 + -0x7ffeb164);
  iVar5 = (int)*(short *)(iVar2 + -0x7ffeb162);
  iVar2 = -(iVar3 * 0x10000 >> 0x10) * iVar6 - (iVar4 * 0x10000 >> 0x10) * iVar5 >> 0xc;
  if (iVar2 < 0) {
    iVar2 = iVar2 + -10;
```

- FUN_00022bac

_No relevant lines found._

### FUN_00023000  (showing up to 3 neighbors)

- FUN_00023000

```c
                       (int)param_9._2_2_ * (int)param_9._2_2_ + (int)param_10 * (int)param_10);
  iVar3 = (iVar3 + -300) * 0x10000 >> 0x10;
  sVar1 = (short)(((int)(((uint)*(ushort *)(unaff_s2 + 0x34) - (iVar3 * param_11 >> 0xf)) * 0x10000)
                  >> 0x10) * 0x1a9 >> 9);
  *(short *)(unaff_s2 + 0x34) = sVar1;
```

- FUN_00023180

```c
  iVar6 = (int)*(short *)(iVar2 + -0x7ffeb164);
  iVar5 = (int)*(short *)(iVar2 + -0x7ffeb162);
  iVar2 = -(iVar3 * 0x10000 >> 0x10) * iVar6 - (iVar4 * 0x10000 >> 0x10) * iVar5 >> 0xc;
  if (iVar2 < 0) {
    iVar2 = iVar2 + -10;
```


_Heuristic: high overlap without direct call may indicate intermediate aggregation layer; forward/reverse bridge paths (<= 4) and 2-hop overlap highlight plausible composition chains._
