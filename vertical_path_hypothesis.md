# Vertical Path / Gravity & Orientation Hypothesis

Date: 2025-09-24

## Established Facts

1. Horizontal integrator confirmed: velX(+0x100), velZ(+0x102) -> posX(+0x114), posZ(+0x118) using Q12 shift (>>0xC).
2. Orientation hashing through `FUN_00022e5c` with `(angle & 0xFFF)` feeding a table of 4096 entries (pairs still undumped; base unresolved).
3. Candidate vertical-related direct offsets (+0x11A,+0x11C,+0x11E,+0x120,+0x128) show repeated initialization / mutation patterns but no literal gravity decrement.
4. +0x11C is heavily used as a pointer: `*(int *)(param + 0x11c)` frequently dereferenced, suggesting a secondary per-actor or per-state struct.
5. Secondary struct offset 0xA4 appears in function `FUN_0001efbc` via nested pointer: `*(undefined1 *)(*(int *)(param_1 + 0x11c) + 0xa4)`.
6. Fuzzy gravity scans (literal & non-literal) plus broad negative mutation scans yielded no stable self-subtraction on candidate direct offsets.
7. Gravity helper candidate scan surfaced clustered small functions (`FUN_0001f5d4` family and `FUN_0001c8cc`) with repeated small decrements or conditional branches near pointer usage, but not definitive gravity math.

## Working Hypothesis

Vertical velocity and position are stored inside the secondary struct pointed to by *(param + 0x11C). The actual Y integrator likely:

1. Loads secondary struct pointer (P = *(param + 0x11C)).
2. Applies gravity via a compact helper (possibly updating a 16-bit or 32-bit field at P + offYVel).
3. Updates a position-like quantity via Q12 shift in a separate function or inline code that we have not captured because it operates on P+off rather than base+0x11A..0x120.

The absence of direct negative immediates on base object vertical offsets (contrasting with horizontal integrator) indicates design partitioning (optimization / modular state separation).

## Evidence Mapping

| Clue | Supports | Notes |
|------|----------|-------|
| Repeated pointer derefs *(param + 0x11c) | Secondary struct presence | Common across high-scoring fuzzy candidates |
| Secondary offset 0xA4 access | Internal field of secondary struct | Could be anim state or sub-pointer (needs neighborhood scan) |
| No direct gravity self-sub on +0x11A..+0x120 | Gravity not stored in base block | Aligns with pointer indirection design |
| Helper candidates with small decrements & multiple callers | Dedicated gravity or timer helper | Need callsite correlation with pointer deref sites |

## Next Investigations

1. Secondary Neighborhood Scan: Enumerate offsets (0x90–0xB0) around 0xA4 to detect clusters of small signed short fields; look for paired updates.
2. Inline Shift Correlation: Re-scan for `>> 0xC` where source address pattern matches `*(short *)(*(int *)(param + 0x11C) + off)`.
3. Helper Call Graph: Build call graph slices for top gravity helper candidates; retain only paths that also dereference *(param + 0x11C).
4. Temporal Coupling: If frame-step ordering is known, check if helper executes each frame before or after horizontal integrator; infer integrator staging.
5. Trig Table Extraction: Failure of pair/probe heuristics implies table may be (a) compressed, (b) separate sin[] & cos[] in non-adjacent memory, or (c) 32-bit values. Add heuristic for: two disjoint 8KB regions each passed through index-shift operations within orientation function.

## Potential Script Additions

- `scan_secondary_neighborhood.py`: gather distribution of accesses to P+off for off in range.
- `scan_shift_secondary.py`: isolate shifts involving secondary struct fields.
- `callgraph_helpers_filter.py`: given list of helper candidates, emit only those reachable from crate / physics update roots.
- `trig_multi_segment_probe.py`: attempt to align two candidate 8KB blocks by correlation of angle progression.

## Success Criteria

| Goal | Metric |
|------|--------|
| Identify velY field | Consistent per-frame monotonic decrease until ground event resets |
| Identify posY field | Observed integrator / shift sequence from velY |
| Extract trig table | 4096 lines with stable radial magnitude & smooth angular delta |
| Classify helper | Distinct function whose removal (simulated) halts vertical acceleration |

## Blocking Unknowns

- Without raw disassembly around `FUN_00022e5c` memory loads we lack direct base constant references; constant addresses in report may include reloc data not actual table base.
- Secondary struct layout largely unexplored; need systematic enumeration.

## Immediate Plan (Automatable)

1. Implement neighborhood & shift-secondary scanners.
2. Expand helper scan to include small add AND subtract of 0x40–0x120 range constants (typical PS1 gravity increments in Q12/Q10).
3. Run multi-segment trig probe.

---
Generated automatically for iterative RE tracking.
