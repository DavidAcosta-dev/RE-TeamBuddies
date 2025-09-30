# PSYQ focus report (2025-09-30)
Derived from crate domain pivots and psyq_trace_targets.csv.
Run `scripts/summarize_psyq_focus.py` after refreshing pivots/targets to regenerate this file.
## AI / libgte vectors
| Crate | Label | Priority | Score | Domain hits | Crossrefs | Focus hint |
|-------|-------|----------|-------|-------------|-----------|------------|
| 28 | INDEX_28 | watch | 48.3 | 11 hits | 391 | libgte vector routines + state-machine scheduler |
| 34 | INDEX_34 | watch | 60.8 | 10 hits | 1628 | libgte vector routines + libgpu geometry + libgte transforms |
| 31 | INDEX_31 | watch | 46.3 | 10 hits | 260 | libgte vector routines + state-machine scheduler |
| 29 | INDEX_29 | watch | 45.8 | 10 hits | 253 | libgte vector routines + state-machine scheduler |
| 4 | ICE_AREA | high | 102.3 | 9 hits | 3095 | libgpu geometry + libgte transforms + libgte/libgpu combat loops |
| 32 | INDEX_32 | second | 76.8 | 9 hits | 2603 | libgte vector routines + state-machine scheduler |
| 0 | PARK_AREA | second | 69.9 | 9 hits | 2083 | libgte vector routines + state-machine scheduler |
| 1 | PLAINS_AREA | second | 69.9 | 9 hits | 2083 | libgte vector routines + state-machine scheduler |

## Combat FX (libgte/libgpu)
| Crate | Label | Priority | Score | Domain hits | Crossrefs | Focus hint |
|-------|-------|----------|-------|-------------|-----------|------------|
| 6 | JUNGLE_AREA | high | 96.0 | 34 hits | 712 | libgte/libgpu combat loops + libspu/libpad support systems |
| 3 | WOODS_AREA | high | 90.3 | 34 hits | 408 | libgte/libgpu combat loops + libspu/libpad support systems |
| 5 | ORIENTAL_AREA | high | 98.3 | 33 hits | 571 | libgte/libgpu combat loops + libspu/libpad support systems |
| 14 | ALL_HEAVY_WEAPONS_1 | high | 76.9 | 28 hits | 604 | libgte/libgpu combat loops + state-machine scheduler |
| 8 | INDEX_08 | watch | 50.3 | 12 hits | 593 | libgte/libgpu combat loops + libgte vector routines |
| 9 | INDEX_09 | watch | 50.0 | 12 hits | 263 | libgte/libgpu combat loops + libgte vector routines |
| 10 | ALL_FLAME_WEAPONS | watch | 45.5 | 12 hits | 339 | libgte/libgpu combat loops + state-machine scheduler |
| 4 | ICE_AREA | high | 102.3 | 11 hits | 3095 | libgpu geometry + libgte transforms + libgte/libgpu combat loops |

## State machine core
| Crate | Label | Priority | Score | Domain hits | Crossrefs | Focus hint |
|-------|-------|----------|-------|-------------|-----------|------------|
| 30 | INDEX_30 | watch | 47.0 | 9 hits | 363 | state-machine scheduler + libgte vector routines |
| 14 | ALL_HEAVY_WEAPONS_1 | high | 76.9 | 8 hits | 604 | libgte/libgpu combat loops + state-machine scheduler |
| 22 | FLYING_4 | watch | 39.0 | 7 hits | 260 | state-machine scheduler + libgte/libgpu combat loops |
| 29 | INDEX_29 | watch | 45.8 | 6 hits | 253 | libgte vector routines + state-machine scheduler |
| 10 | ALL_FLAME_WEAPONS | watch | 45.5 | 6 hits | 339 | libgte/libgpu combat loops + state-machine scheduler |
| 28 | INDEX_28 | watch | 48.3 | 5 hits | 391 | libgte vector routines + state-machine scheduler |
| 31 | INDEX_31 | watch | 46.3 | 5 hits | 260 | libgte vector routines + state-machine scheduler |
| 26 | BIKES | watch | 45.9 | 5 hits | 204 | libgte/libgpu combat loops + libgte vector routines |

## Rendering (libgpu/libgte)
| Crate | Label | Priority | Score | Domain hits | Crossrefs | Focus hint |
|-------|-------|----------|-------|-------------|-----------|------------|
| 4 | ICE_AREA | high | 102.3 | 11 hits | 3095 | libgpu geometry + libgte transforms + libgte/libgpu combat loops |
| 16 | ALL_ROCKET_WEAPONS | watch | 57.3 | 9 hits | 526 | libgpu geometry + libgte transforms + libgte vector routines |
| 17 | ALL_MISSILE_WEAPONS | watch | 54.3 | 9 hits | 346 | libgpu geometry + libgte transforms + libgte vector routines |
| 15 | ALL_HEAVY_WEAPONS_2 | watch | 54.3 | 9 hits | 345 | libgpu geometry + libgte transforms + libgte vector routines |
| 18 | ALL_SPECIAL_WEAPONS | watch | 55.8 | 8 hits | 440 | libgpu geometry + libgte transforms + libgte vector routines |
| 31 | INDEX_31 | watch | 46.3 | 4 hits | 260 | libgte vector routines + state-machine scheduler |
| 34 | INDEX_34 | watch | 60.8 | 3 hits | 1628 | libgte vector routines + libgpu geometry + libgte transforms |
| 28 | INDEX_28 | watch | 48.3 | 3 hits | 391 | libgte vector routines + state-machine scheduler |

## Support systems (libspu/libpad)
| Crate | Label | Priority | Score | Domain hits | Crossrefs | Focus hint |
|-------|-------|----------|-------|-------------|-----------|------------|
| 5 | ORIENTAL_AREA | high | 98.3 | 11 hits | 571 | libgte/libgpu combat loops + libspu/libpad support systems |
| 6 | JUNGLE_AREA | high | 96.0 | 11 hits | 712 | libgte/libgpu combat loops + libspu/libpad support systems |
| 3 | WOODS_AREA | high | 90.3 | 11 hits | 408 | libgte/libgpu combat loops + libspu/libpad support systems |

---
Focus ranking favours crates with high domain counts, breaking ties by priority score and crossref density.
