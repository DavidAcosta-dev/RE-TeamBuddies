# Primary +0x11C (secondary pointer) writes

| File | Function | EA | BaseExpr | RHS |
|------|----------|----|----------|-----|
| bundle_all_plus_demo.jsonl | FUN_0002a8c8 | 174280 | `iVar1` | `iVar6` |
| bundle_all_plus_demo.jsonl | FUN_0002a8c8 | 174280 | `iVar6` | `iVar7` |
| bundle_all_plus_demo.jsonl | FUN_00001c84 | 7300 | `iVar8` | `_DAT_801199e8` |
| bundle_GAME.BIN.jsonl | FUN_0002a8c8 | 174280 | `iVar1` | `iVar6` |
| bundle_GAME.BIN.jsonl | FUN_0002a8c8 | 174280 | `iVar6` | `iVar7` |
| bundle_ghidra.jsonl | FUN_0002a8c8 | 174280 | `iVar1` | `iVar6` |
| bundle_ghidra.jsonl | FUN_0002a8c8 | 174280 | `iVar6` | `iVar7` |
| bundle_ghidra.jsonl | FUN_00001c84 | 7300 | `iVar8` | `_DAT_801199e8` |
| bundle_ghidra.jsonl | FUN_0002a8c8 | 174280 | `iVar1` | `iVar6` |
| bundle_ghidra.jsonl | FUN_0002a8c8 | 174280 | `iVar6` | `iVar7` |
| bundle_ghidra.jsonl | FUN_00001c84 | 7300 | `iVar8` | `_DAT_801199e8` |
| bundle_TUTO.BIN.jsonl | FUN_00001c84 | 7300 | `iVar8` | `_DAT_801199e8` |


## Snippets

### FUN_0002a8c8 @ 174280 (bundle_all_plus_demo.jsonl)

```c
*(int *)(iVar1 + 0x11c) = iVar6;
```

### FUN_0002a8c8 @ 174280 (bundle_all_plus_demo.jsonl)

```c
*(int *)(iVar6 + 0x11c) = iVar7;
```

### FUN_00001c84 @ 7300 (bundle_all_plus_demo.jsonl)

```c
*(int *)(iVar8 + 0x11c) = _DAT_801199e8;
```

### FUN_0002a8c8 @ 174280 (bundle_GAME.BIN.jsonl)

```c
*(int *)(iVar1 + 0x11c) = iVar6;
```

### FUN_0002a8c8 @ 174280 (bundle_GAME.BIN.jsonl)

```c
*(int *)(iVar6 + 0x11c) = iVar7;
```

### FUN_0002a8c8 @ 174280 (bundle_ghidra.jsonl)

```c
*(int *)(iVar1 + 0x11c) = iVar6;
```

### FUN_0002a8c8 @ 174280 (bundle_ghidra.jsonl)

```c
*(int *)(iVar6 + 0x11c) = iVar7;
```

### FUN_00001c84 @ 7300 (bundle_ghidra.jsonl)

```c
*(int *)(iVar8 + 0x11c) = _DAT_801199e8;
```

### FUN_0002a8c8 @ 174280 (bundle_ghidra.jsonl)

```c
*(int *)(iVar1 + 0x11c) = iVar6;
```

### FUN_0002a8c8 @ 174280 (bundle_ghidra.jsonl)

```c
*(int *)(iVar6 + 0x11c) = iVar7;
```

### FUN_00001c84 @ 7300 (bundle_ghidra.jsonl)

```c
*(int *)(iVar8 + 0x11c) = _DAT_801199e8;
```

### FUN_00001c84 @ 7300 (bundle_TUTO.BIN.jsonl)

```c
*(int *)(iVar8 + 0x11c) = _DAT_801199e8;
```

