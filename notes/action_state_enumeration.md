# Action State Enumeration (WIP)

Identified switch/jump bounds referencing 0x4B (75) total action state slots:

Occurrences:

- `if (iVar6 - 2U < 0x4b)` (range check variant: states 2..76 exclusive upper) in `snippets_GAME.BIN` lines near 370 & 584.
- `if (uVar7 < 0x4b)` simple bound checks (lines ~1304, ~1489).
- Calls to `func_0x0006df40(0x4b, &local_48, &local_38, iVar5)` (lines ~1694, ~1699, ~1822, ~1827) suggest iterator/dispatcher over 0x4B entries.

## Pointer Table Base Candidates

- Table address pattern in physics init (`(unaff_s2 - 0x25U) * 4 + -0x7ff38ab4`) may define a separate range (0x33 count) likely unrelated but similar derivation.
- Another indirect jump: `local_34 * 4 + -0x7ff39a9c` for range `< 0x45` (69 entries) — possibly a different subsystem (object/primitive builders or animation phases).

## Preliminary Hypotheses

- 0x4B action states: composite of global player/AI behavior states including idle, move, pickup, throw, build, attack, stunned, etc.
- The `func_0x0006df40` calls likely perform validation or transformation across all action slots (e.g., mass update, culling, or scheduling step) given repeated invocation pattern within loops.

## Next Extraction Steps

1. Locate definition of `func_0x0006df40` to analyze its inner loop (expects count param first: 0x4b) — pattern match on function prologue reading first argument then looping.
2. Build an address list of indirect call targets captured from instrumentation around the dispatcher; correlate with usage counts.
3. Cross-reference input bitmask gating (0x40 pickup, 0x10 throw, 0x8000/0x2000 directional) to identify which action IDs handle these transitions.
4. Scan for constant stores of small IDs (<=0x4b) to actor state fields; frequency analysis to cluster semantic roles.

## Planned Artifacts

- `exports/action_state_map.csv` (columns: id, address, provisional_name, evidence_notes)
- `exports/action_state_transitions.md` (graph of observed transitions through state field writes)

## Open Questions

- Are states densely packed 0..0x4A or do sentinel offsets (subtract 2) imply reserved headers (e.g., 0/1 for system/meta)?
- Is gravity / Y integrator gated by particular action states (e.g., only active in throw/airborne)?

## Changelog

- (Init) Created enumeration file with initial occurrence catalog from snippets.
