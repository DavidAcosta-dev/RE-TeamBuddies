# Fixed-Point Integrator Lines (>> 0xC sweep)

Total lines containing >> 0xC: 568

| Offset | Count | Known? | Sample 1 | Sample 2 | Sample 3 |
|--------|-------|--------|----------|----------|----------|
| 0x40 | 48 |  | 0x443b8 FUN_000443b8 :: (int)local_2c * (int)*(short *)(param_1 + 0x40) >> 0xc; | 0x44754 FUN_00044754 :: (int)local_1c * (int)*(short *)(param_1 + 0x40) >> 0xc < | 0x44a14 FUN_00044a14 :: (int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc); |
| 0x38 | 44 |  | 0x26c68 FUN_00026c68 :: iVar5 * *(short *)(param_1 + 0x38) >> 0xc); | 0x26c68 FUN_00026c68 :: (short)(((int)sVar2 + (int)*(short *)(param_1 + 0x38)) * iVar5 >> 0xc); | 0x438fc FUN_000438fc :: -(short)((int)(uVar8 * (int)*(short *)(param_1 + 0x38)) >> 0xc); |
| 0x36 | 28 |  | 0x26c68 FUN_00026c68 :: *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x36) * -0x400 >> 0xc); | 0x44a14 FUN_00044a14 :: (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x36)) >> 0xc), | 0x44a14 FUN_00044a14 :: *(short *)(param_1 + 0x36) = (short)((int)-((int)*(short *)(param_1 + 0x36) * uVar4) >> 0xc); |
| 0x34 | 24 |  | 0x438fc FUN_000438fc :: -(short)((int)(uVar8 * (int)*(short *)(param_1 + 0x34)) >> 0xc); | 0x44a14 FUN_00044a14 :: (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x34)) >> 0xc)); | 0x44f80 FUN_00044f80 :: *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc); |
| 0x3c | 20 |  | 0x44f80 FUN_00044f80 :: *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc); | 0x44f80 FUN_00044f80 :: sVar7 = (short)(iVar9 * *(short *)(param_1 + 0x3c) + iVar12 * (short)local_38 >> 0xc); | 0x46024 FUN_00046024 :: -(short)(iVar2 * *(short *)(param_1 + 0x3c) >> 0xc)); |
| 0x3e | 16 |  | 0x44f80 FUN_00044f80 :: *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc); | 0x44f80 FUN_00044f80 :: sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc); | 0x48150 FUN_00048150 :: local_38._2_2_ = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x3e)) >> 0xc); |
| 0xd6 | 8 |  | 0x23698 FUN_00023698 :: uVar4 = (int)((uint)*(ushort *)(param_1 + 0xd6) * (int)*(short *)(iVar5 + -0x7ffeb164)) >> 0xc; | 0x23698 FUN_00023698 :: uVar3 = (int)((uint)*(ushort *)(param_1 + 0xd6) * (int)*(short *)(iVar5 + -0x7ffeb162)) >> 0xc; | 0x23698 FUN_00023698 :: uVar4 = (int)((uint)*(ushort *)(param_1 + 0xd6) * (int)*(short *)(iVar5 + -0x7ffeb164)) >> 0xc; |
| 0x100 | 8 | velX | 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // velX | 0x40a98 FUN_00040a98 :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // velX | 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // velX |
| 0x114 | 8 | posX | 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // posX | 0x40a98 FUN_00040a98 :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // posX | 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // posX |
| 0x102 | 8 | velZ | 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // velZ | 0x40a98 FUN_00040a98 :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // velZ | 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // velZ |
| 0x118 | 8 | posZ | 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // posZ | 0x40a98 FUN_00040a98 :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // posZ | 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // posZ |
| 0xce | 4 |  | 0x6dd0 FUN_00006dd0 :: func_0x000c994c(param_1,(int)((uint)*(ushort *)(iVar2 + 0xce) * 0x64000) / 0x78 >> 0xc); | 0x6dd0 FUN_00006dd0 :: func_0x000c994c(param_1,(int)((uint)*(ushort *)(iVar2 + 0xce) * 0x64000) / 0x78 >> 0xc); | 0x6dd0 FUN_00006dd0 :: func_0x000c994c(param_1,(int)((uint)*(ushort *)(iVar2 + 0xce) * 0x64000) / 0x78 >> 0xc); |
| 0x13 | 4 |  | 0x1ec7c FUN_0001ec7c :: piVar6[0x14] = (int)(((uint)*(ushort *)(piVar6 + 0x13) << 0xc) / (uint)uVar4) >> 0xc; | 0x1ec7c FUN_0001ec7c :: piVar6[0x14] = (int)(((uint)*(ushort *)(piVar6 + 0x13) << 0xc) / (uint)uVar4) >> 0xc; | 0x1ec7c FUN_0001ec7c :: piVar6[0x14] = (int)(((uint)*(ushort *)(piVar6 + 0x13) << 0xc) / (uint)uVar4) >> 0xc; |
| 0x144 | 4 |  | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x144) = (short)((uint)param_2[10] >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x144) = (short)((uint)param_2[10] >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x144) = (short)((uint)param_2[10] >> 0xc); |
| 0x146 | 4 |  | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x146) = (short)((uint)param_2[0xb] >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x146) = (short)((uint)param_2[0xb] >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x146) = (short)((uint)param_2[0xb] >> 0xc); |
| 0x156 | 4 |  | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x156) = (short)((uint)(param_2[0x18] * param_2[0x1b]) >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x156) = (short)((uint)(param_2[0x18] * param_2[0x1b]) >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x156) = (short)((uint)(param_2[0x18] * param_2[0x1b]) >> 0xc); |
| 0x160 | 4 |  | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x160) = (short)((uint)param_2[0x1d] >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x160) = (short)((uint)param_2[0x1d] >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x160) = (short)((uint)param_2[0x1d] >> 0xc); |
| 0x164 | 4 |  | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x164) = (short)((uint)param_2[0x1f] >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x164) = (short)((uint)param_2[0x1f] >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x164) = (short)((uint)param_2[0x1f] >> 0xc); |
| 0x168 | 4 |  | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x168) = (short)((uint)param_2[0x1e] >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x168) = (short)((uint)param_2[0x1e] >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x168) = (short)((uint)param_2[0x1e] >> 0xc); |
| 0x16c | 4 |  | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x16c) = (short)((uint)param_2[0x20] >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x16c) = (short)((uint)param_2[0x20] >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x16c) = (short)((uint)param_2[0x20] >> 0xc); |
| 0x170 | 4 |  | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x170) = (short)((uint)param_2[0x15] >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x170) = (short)((uint)param_2[0x15] >> 0xc); | 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x170) = (short)((uint)param_2[0x15] >> 0xc); |
| 0xcc | 4 |  | 0x45a80 FUN_00045a80 :: *psVar5 = (short)((0x1000 - *(int *)(param_1 + 0xcc)) * (int)*psVar5 >> 0xc); | 0x45a80 FUN_00045a80 :: *psVar5 = (short)((0x1000 - *(int *)(param_1 + 0xcc)) * (int)*psVar5 >> 0xc); | 0x45a80 FUN_00045a80 :: *psVar5 = (short)((0x1000 - *(int *)(param_1 + 0xcc)) * (int)*psVar5 >> 0xc); |
| 0x22 | 4 |  | 0x1eb14 FUN_0001eb14 :: *(short *)(iVar2 + 0x22) = (short)((uint)(((int)sVar1 + (iVar4 >> 0xc)) * 0x10000) >> 0x10); | 0x1eb14 FUN_0001eb14 :: *(short *)(iVar2 + 0x22) = (short)((uint)(((int)sVar1 + (iVar4 >> 0xc)) * 0x10000) >> 0x10); | 0x1eb14 FUN_0001eb14 :: *(short *)(iVar2 + 0x22) = (short)((uint)(((int)sVar1 + (iVar4 >> 0xc)) * 0x10000) >> 0x10); |

---

## Detailed Samples

### Offset 0x40

- 0x443b8 FUN_000443b8 :: (int)local_2c * (int)*(short *)(param_1 + 0x40) >> 0xc;
- 0x44754 FUN_00044754 :: (int)local_1c * (int)*(short *)(param_1 + 0x40) >> 0xc <
- 0x44a14 FUN_00044a14 :: (int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc);
- 0x44a14 FUN_00044a14 :: (int)*(short *)(param_1 + 0x38) * (int)*(short *)(param_1 + 0x40) >> 0xc);
- 0x44f80 FUN_00044f80 :: *(short *)(param_1 + 0x38) = (short)(*(short *)(param_1 + 0x40) * iVar12 >> 0xc);

### Offset 0x38

- 0x26c68 FUN_00026c68 :: iVar5 * *(short *)(param_1 + 0x38) >> 0xc);
- 0x26c68 FUN_00026c68 :: (short)(((int)sVar2 + (int)*(short *)(param_1 + 0x38)) * iVar5 >> 0xc);
- 0x438fc FUN_000438fc :: -(short)((int)(uVar8 * (int)*(short *)(param_1 + 0x38)) >> 0xc);
- 0x44a14 FUN_00044a14 :: (int)*(short *)(param_1 + 0x40) * (int)*(short *)(param_1 + 0x38) >> 0xc);
- 0x44a14 FUN_00044a14 :: (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x38)) >> 0xc));

### Offset 0x36

- 0x26c68 FUN_00026c68 :: *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x36) * -0x400 >> 0xc);
- 0x44a14 FUN_00044a14 :: (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x36)) >> 0xc),
- 0x44a14 FUN_00044a14 :: *(short *)(param_1 + 0x36) = (short)((int)-((int)*(short *)(param_1 + 0x36) * uVar4) >> 0xc);
- 0x44f80 FUN_00044f80 :: *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);
- 0x44f80 FUN_00044f80 :: *(short *)(param_1 + 0x36) = (short)(sVar3 * iVar11 >> 0xc);

### Offset 0x34

- 0x438fc FUN_000438fc :: -(short)((int)(uVar8 * (int)*(short *)(param_1 + 0x34)) >> 0xc);
- 0x44a14 FUN_00044a14 :: (short)((int)(uVar4 * (int)*(short *)(param_1 + 0x34)) >> 0xc));
- 0x44f80 FUN_00044f80 :: *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);
- 0x44f80 FUN_00044f80 :: *(short *)(param_1 + 0x34) = (short)(sVar7 * iVar11 >> 0xc);
- 0x475dc FUN_000475dc :: *(short *)(param_1 + 0x34) = (short)(local_30 >> 0xc);

### Offset 0x3c

- 0x44f80 FUN_00044f80 :: *(short *)(param_1 + 0x34) = (short)(*(short *)(param_1 + 0x3c) * iVar12 >> 0xc);
- 0x44f80 FUN_00044f80 :: sVar7 = (short)(iVar9 * *(short *)(param_1 + 0x3c) + iVar12 * (short)local_38 >> 0xc);
- 0x46024 FUN_00046024 :: -(short)(iVar2 * *(short *)(param_1 + 0x3c) >> 0xc));
- 0x48150 FUN_00048150 :: local_38._0_2_ = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x3c)) >> 0xc);
- 0x489a8 FUN_000489a8 :: *(short *)(iVar3 + 0x34) = (short)((int)((int)*(short *)(iVar3 + 0x3c) * uVar15) >> 0xc)

### Offset 0x3e

- 0x44f80 FUN_00044f80 :: *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);
- 0x44f80 FUN_00044f80 :: sVar3 = (short)(iVar9 * *(short *)(param_1 + 0x3e) + iVar12 * local_38._2_2_ >> 0xc);
- 0x48150 FUN_00048150 :: local_38._2_2_ = (short)((int)(uVar9 * (int)*(short *)(param_1 + 0x3e)) >> 0xc);
- 0x489a8 FUN_000489a8 :: *(short *)(iVar3 + 0x36) = (short)((int)((int)*(short *)(iVar3 + 0x3e) * uVar15) >> 0xc)
- 0x44f80 FUN_00044f80 :: *(short *)(param_1 + 0x36) = (short)(*(short *)(param_1 + 0x3e) * iVar12 >> 0xc);

### Offset 0xd6

- 0x23698 FUN_00023698 :: uVar4 = (int)((uint)*(ushort *)(param_1 + 0xd6) * (int)*(short *)(iVar5 + -0x7ffeb164)) >> 0xc;
- 0x23698 FUN_00023698 :: uVar3 = (int)((uint)*(ushort *)(param_1 + 0xd6) * (int)*(short *)(iVar5 + -0x7ffeb162)) >> 0xc;
- 0x23698 FUN_00023698 :: uVar4 = (int)((uint)*(ushort *)(param_1 + 0xd6) * (int)*(short *)(iVar5 + -0x7ffeb164)) >> 0xc;
- 0x23698 FUN_00023698 :: uVar3 = (int)((uint)*(ushort *)(param_1 + 0xd6) * (int)*(short *)(iVar5 + -0x7ffeb162)) >> 0xc;
- 0x23698 FUN_00023698 :: uVar4 = (int)((uint)*(ushort *)(param_1 + 0xd6) * (int)*(short *)(iVar5 + -0x7ffeb164)) >> 0xc;

### Offset 0x100 (velX)

- 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // velX
- 0x40a98 FUN_00040a98 :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // velX
- 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // velX
- 0x40a98 FUN_00040a98 :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // velX
- 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // velX

### Offset 0x114 (posX)

- 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // posX
- 0x40a98 FUN_00040a98 :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // posX
- 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // posX
- 0x40a98 FUN_00040a98 :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // posX
- 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x114) - (short)(*(short *)(iVar6 + 0x100) * iVar10 >> 0xc);  // posX

### Offset 0x102 (velZ)

- 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // velZ
- 0x40a98 FUN_00040a98 :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // velZ
- 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // velZ
- 0x40a98 FUN_00040a98 :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // velZ
- 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // velZ

### Offset 0x118 (posZ)

- 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // posZ
- 0x40a98 FUN_00040a98 :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // posZ
- 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // posZ
- 0x40a98 FUN_00040a98 :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // posZ
- 0x40a4c FUN_00040a4c :: *(short *)(iVar6 + 0x118) - (short)(*(short *)(iVar6 + 0x102) * iVar10 >> 0xc);  // posZ

### Offset 0xce

- 0x6dd0 FUN_00006dd0 :: func_0x000c994c(param_1,(int)((uint)*(ushort *)(iVar2 + 0xce) * 0x64000) / 0x78 >> 0xc);
- 0x6dd0 FUN_00006dd0 :: func_0x000c994c(param_1,(int)((uint)*(ushort *)(iVar2 + 0xce) * 0x64000) / 0x78 >> 0xc);
- 0x6dd0 FUN_00006dd0 :: func_0x000c994c(param_1,(int)((uint)*(ushort *)(iVar2 + 0xce) * 0x64000) / 0x78 >> 0xc);
- 0x6dd0 FUN_00006dd0 :: func_0x000c994c(param_1,(int)((uint)*(ushort *)(iVar2 + 0xce) * 0x64000) / 0x78 >> 0xc);

### Offset 0x13

- 0x1ec7c FUN_0001ec7c :: piVar6[0x14] = (int)(((uint)*(ushort *)(piVar6 + 0x13) << 0xc) / (uint)uVar4) >> 0xc;
- 0x1ec7c FUN_0001ec7c :: piVar6[0x14] = (int)(((uint)*(ushort *)(piVar6 + 0x13) << 0xc) / (uint)uVar4) >> 0xc;
- 0x1ec7c FUN_0001ec7c :: piVar6[0x14] = (int)(((uint)*(ushort *)(piVar6 + 0x13) << 0xc) / (uint)uVar4) >> 0xc;
- 0x1ec7c FUN_0001ec7c :: piVar6[0x14] = (int)(((uint)*(ushort *)(piVar6 + 0x13) << 0xc) / (uint)uVar4) >> 0xc;

### Offset 0x144

- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x144) = (short)((uint)param_2[10] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x144) = (short)((uint)param_2[10] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x144) = (short)((uint)param_2[10] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x144) = (short)((uint)param_2[10] >> 0xc);

### Offset 0x146

- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x146) = (short)((uint)param_2[0xb] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x146) = (short)((uint)param_2[0xb] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x146) = (short)((uint)param_2[0xb] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x146) = (short)((uint)param_2[0xb] >> 0xc);

### Offset 0x156

- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x156) = (short)((uint)(param_2[0x18] * param_2[0x1b]) >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x156) = (short)((uint)(param_2[0x18] * param_2[0x1b]) >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x156) = (short)((uint)(param_2[0x18] * param_2[0x1b]) >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x156) = (short)((uint)(param_2[0x18] * param_2[0x1b]) >> 0xc);

### Offset 0x160

- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x160) = (short)((uint)param_2[0x1d] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x160) = (short)((uint)param_2[0x1d] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x160) = (short)((uint)param_2[0x1d] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x160) = (short)((uint)param_2[0x1d] >> 0xc);

### Offset 0x164

- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x164) = (short)((uint)param_2[0x1f] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x164) = (short)((uint)param_2[0x1f] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x164) = (short)((uint)param_2[0x1f] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x164) = (short)((uint)param_2[0x1f] >> 0xc);

### Offset 0x168

- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x168) = (short)((uint)param_2[0x1e] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x168) = (short)((uint)param_2[0x1e] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x168) = (short)((uint)param_2[0x1e] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x168) = (short)((uint)param_2[0x1e] >> 0xc);

### Offset 0x16c

- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x16c) = (short)((uint)param_2[0x20] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x16c) = (short)((uint)param_2[0x20] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x16c) = (short)((uint)param_2[0x20] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x16c) = (short)((uint)param_2[0x20] >> 0xc);

### Offset 0x170

- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x170) = (short)((uint)param_2[0x15] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x170) = (short)((uint)param_2[0x15] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x170) = (short)((uint)param_2[0x15] >> 0xc);
- 0x32c18 FUN_00032c18 :: *(short *)(iVar2 + 0x170) = (short)((uint)param_2[0x15] >> 0xc);

### Offset 0xcc

- 0x45a80 FUN_00045a80 :: *psVar5 = (short)((0x1000 - *(int *)(param_1 + 0xcc)) * (int)*psVar5 >> 0xc);
- 0x45a80 FUN_00045a80 :: *psVar5 = (short)((0x1000 - *(int *)(param_1 + 0xcc)) * (int)*psVar5 >> 0xc);
- 0x45a80 FUN_00045a80 :: *psVar5 = (short)((0x1000 - *(int *)(param_1 + 0xcc)) * (int)*psVar5 >> 0xc);
- 0x45a80 FUN_00045a80 :: *psVar5 = (short)((0x1000 - *(int *)(param_1 + 0xcc)) * (int)*psVar5 >> 0xc);

### Offset 0x22

- 0x1eb14 FUN_0001eb14 :: *(short *)(iVar2 + 0x22) = (short)((uint)(((int)sVar1 + (iVar4 >> 0xc)) * 0x10000) >> 0x10);
- 0x1eb14 FUN_0001eb14 :: *(short *)(iVar2 + 0x22) = (short)((uint)(((int)sVar1 + (iVar4 >> 0xc)) * 0x10000) >> 0x10);
- 0x1eb14 FUN_0001eb14 :: *(short *)(iVar2 + 0x22) = (short)((uint)(((int)sVar1 + (iVar4 >> 0xc)) * 0x10000) >> 0x10);
- 0x1eb14 FUN_0001eb14 :: *(short *)(iVar2 + 0x22) = (short)((uint)(((int)sVar1 + (iVar4 >> 0xc)) * 0x10000) >> 0x10);

