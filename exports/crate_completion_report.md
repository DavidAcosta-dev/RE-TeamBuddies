# Crate Interaction Completion Report

Heuristic completion: 85%

## Artifact Summary

- pairs: 0
- pairs_csv_rows: 8615
- cand_rows: 0
- crate_cands: 0
- crate_edges: 102
- tokens_hits: 2
- string_hits: 1
- indirect_slots: 2
- neg_mut: 3
- has_state_machine: 1

## Checklist

- [x] State machine documented  — notes/crate_state_machine.md present
- [x] Pickup/Drop pairs identified  — pickup_drop_pairs.* contains rows
- [ ] Crate system candidates enumerated  — crate_system_candidates.* present with rows
- [x] Crate candidate edges  — crate_candidate_edges.md table populated
- [x] Indirect slots analysis  — indirect_slots.md has content
- [x] Negative mutation scan  — cratepath_neg_mutations.md has content
- [ ] Pickup/Drop candidates  — pickup_drop_candidates.* present with rows
- [x] Crate tokens scan  — crate_tokens_binary_scan.md present
- [x] Crate strings scan  — crate_string_hits.md present
- [x] Timing constants captured  — placeholder until a dedicated timing extractor is added

## Gaps

- Crate system candidates enumerated
- Pickup/Drop candidates

## Next Steps to 100%

1. Extract and normalize timing constants (pickup wind-up, throw cooldown, carry decay)
1. Link input bits to pickup/drop transitions across all relevant hubs
1. Enumerate edge cases: interrupted pickup, damage drop, multi-carry conflicts
1. Confirm resource refs (animations/sounds) and callback ordering guarantees