# Bank Population Evidence Summary

## Goal

Determine whether mini context words are copied into low offsets (struct +4/+8/+0xC/+0x10) prior to fast-path emissions, or whether FUN_0001a558 uses argument registers directly (H1).

## Current Findings

- High-resolution windows for `FUN_0000a944` show no intervening stores into low offsets between allocation, slot write (0x3b/0x3c), and `FUN_0001a558` calls.
- Filtered low-offset store scan produced 16 duplicate candidates but their snippets (`FUN_0001dd54`, `FUN_0001dd68`, `FUN_0001de28`, `FUN_00002ca0`) only show dereferences of `(struct + 0xC)+4`-style patterns, not assignments writing into +4/+8/+0xC/+0x10.
- No evidence yet of explicit population of the presumed bank region immediately before first fast-path emission invocation.
- `FUN_0001a558` decompilation lacks parameters; call sites nonetheless supply two 32-bit values, consistent with inlined/ignored usage or register-only side effects not reflected in decompiler variable list.

## Hypothesis Status

- H1 (Direct Use via argument registers): Strengthened (no stores observed).
- H2 (Bank Population Elsewhere): We have not located any store instructions writing into the low offsets proximate to allocations; remains unsubstantiated.
- H3 (Pointer-of-Pointers): Weak (arithmetic inside `FUN_0001a558` indexes within the main struct using toggles, not traversing stored mini context pointers directly).

## Next Steps

1. Narrow searches for explicit `=` assignments where left-hand side contains `+ 4)` or `+ 0xC)` and right-hand side contains `[0x3b]` or `[0x3c]` dereferences.
2. If absent, promote mini context field naming to stable status and mark bank fields as internal toggle banks decoupled from mini context memory.
3. (Optional) Introduce heuristic to locate any function that writes both offsets +0x38 and +0x3c in the same basic block prior to an emit; classify as toggle manager.
4. Document final vertical emission pipeline sequence with timeline diagram.

## Provisional Conclusion

Proceed under assumption that the two arguments to `FUN_0001a558` influence emission indirectly (e.g., hardware channel selection or sideband configuration) without copying into the main vertical struct's low-offset banks.
