# Broad Gravity Candidate Self-Mutating Offsets

| Offset | Hits | Funcs | NegMut | PosMut | Types | Sample 1 | Sample 2 |
|--------|------|-------|--------|--------|-------|----------|----------|
| 0x34 | 12 | 3 | 0 | 12 | int | 0x1a614 FUN_0001a614 :: *(int *)(param_1 + 0x34) = *(int *)(param_1 + 0x34) + 1; | 0x1a674 FUN_0001a674 :: *(int *)(unaff_s0 + 0x34) = *(int *)(unaff_s0 + 0x34) + 1; |
| 0x4c | 8 | 2 | 0 | 8 | int | 0x17e54 FUN_00017e54 :: *(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1; | 0x1d7b8 FUN_0001d7b8 :: *(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1; |
| 0x1b0 | 4 | 1 | 0 | 4 | int | 0x2f6d4 FUN_0002f6d4 :: *(int *)(param_1 + 0x1b0) = *(int *)(param_1 + 0x1b0) + 1; | 0x2f6d4 FUN_0002f6d4 :: *(int *)(param_1 + 0x1b0) = *(int *)(param_1 + 0x1b0) + 1; |
| 0x230 | 4 | 1 | 0 | 4 | int | 0x3360c FUN_0003360c :: *(int *)(param_1 + 0x230) = *(int *)(param_1 + 0x230) + 1; | 0x3360c FUN_0003360c :: *(int *)(param_1 + 0x230) = *(int *)(param_1 + 0x230) + 1; |
| 0x8c | 4 | 1 | 0 | 4 | int | 0x8528 FUN_00008528 :: *(int *)(param_1 + 0x8c) = *(int *)(param_1 + 0x8c) + 1; | 0x8528 FUN_00008528 :: *(int *)(param_1 + 0x8c) = *(int *)(param_1 + 0x8c) + 1; |
| 0xb8 | 4 | 1 | 0 | 4 | int | 0x1fdb4 FUN_0001fdb4 :: *(int *)(param_1 + 0xb8) = *(int *)(param_1 + 0xb8) + 0xf; | 0x1fdb4 FUN_0001fdb4 :: *(int *)(param_1 + 0xb8) = *(int *)(param_1 + 0xb8) + 0xf; |

---

## Detailed Samples

### Offset 0x34

- 0x1a614 FUN_0001a614 :: *(int *)(param_1 + 0x34) = *(int *)(param_1 + 0x34) + 1;
- 0x1a674 FUN_0001a674 :: *(int *)(unaff_s0 + 0x34) = *(int *)(unaff_s0 + 0x34) + 1;
- 0x1a734 FUN_0001a734 :: *(int *)(unaff_s0 + 0x34) = *(int *)(unaff_s0 + 0x34) + 1;
- 0x1a614 FUN_0001a614 :: *(int *)(param_1 + 0x34) = *(int *)(param_1 + 0x34) + 1;
- 0x1a674 FUN_0001a674 :: *(int *)(unaff_s0 + 0x34) = *(int *)(unaff_s0 + 0x34) + 1;
- 0x1a734 FUN_0001a734 :: *(int *)(unaff_s0 + 0x34) = *(int *)(unaff_s0 + 0x34) + 1;

### Offset 0x4c

- 0x17e54 FUN_00017e54 :: *(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1;
- 0x1d7b8 FUN_0001d7b8 :: *(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1;
- 0x17e54 FUN_00017e54 :: *(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1;
- 0x1d7b8 FUN_0001d7b8 :: *(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1;
- 0x17e54 FUN_00017e54 :: *(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1;
- 0x1d7b8 FUN_0001d7b8 :: *(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + 1;

### Offset 0x1b0

- 0x2f6d4 FUN_0002f6d4 :: *(int *)(param_1 + 0x1b0) = *(int *)(param_1 + 0x1b0) + 1;
- 0x2f6d4 FUN_0002f6d4 :: *(int *)(param_1 + 0x1b0) = *(int *)(param_1 + 0x1b0) + 1;
- 0x2f6d4 FUN_0002f6d4 :: *(int *)(param_1 + 0x1b0) = *(int *)(param_1 + 0x1b0) + 1;
- 0x2f6d4 FUN_0002f6d4 :: *(int *)(param_1 + 0x1b0) = *(int *)(param_1 + 0x1b0) + 1;

### Offset 0x230

- 0x3360c FUN_0003360c :: *(int *)(param_1 + 0x230) = *(int *)(param_1 + 0x230) + 1;
- 0x3360c FUN_0003360c :: *(int *)(param_1 + 0x230) = *(int *)(param_1 + 0x230) + 1;
- 0x3360c FUN_0003360c :: *(int *)(param_1 + 0x230) = *(int *)(param_1 + 0x230) + 1;
- 0x3360c FUN_0003360c :: *(int *)(param_1 + 0x230) = *(int *)(param_1 + 0x230) + 1;

### Offset 0x8c

- 0x8528 FUN_00008528 :: *(int *)(param_1 + 0x8c) = *(int *)(param_1 + 0x8c) + 1;
- 0x8528 FUN_00008528 :: *(int *)(param_1 + 0x8c) = *(int *)(param_1 + 0x8c) + 1;
- 0x8528 FUN_00008528 :: *(int *)(param_1 + 0x8c) = *(int *)(param_1 + 0x8c) + 1;
- 0x8528 FUN_00008528 :: *(int *)(param_1 + 0x8c) = *(int *)(param_1 + 0x8c) + 1;

### Offset 0xb8

- 0x1fdb4 FUN_0001fdb4 :: *(int *)(param_1 + 0xb8) = *(int *)(param_1 + 0xb8) + 0xf;
- 0x1fdb4 FUN_0001fdb4 :: *(int *)(param_1 + 0xb8) = *(int *)(param_1 + 0xb8) + 0xf;
- 0x1fdb4 FUN_0001fdb4 :: *(int *)(param_1 + 0xb8) = *(int *)(param_1 + 0xb8) + 0xf;
- 0x1fdb4 FUN_0001fdb4 :: *(int *)(param_1 + 0xb8) = *(int *)(param_1 + 0xb8) + 0xf;

