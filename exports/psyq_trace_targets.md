# PSYQ crate trace targets (auto-generated 2025-09-30)
These rankings are derived from domain pivot counts and cross-reference density.
Run `scripts/prioritize_psyq_trace_targets.py` after refreshing the matrix/pivot to regenerate this file.
## High priority
| Crate | Label | Score | Highlights | PSYQ focus |
|-------|-------|-------|------------|------------|
| 4 | ICE_AREA | 102.3 | combat:11, render:11, ai:9, engine:3 | libgpu geometry + libgte transforms + libgte/libgpu combat loops |
| 5 | ORIENTAL_AREA | 98.3 | combat:33, support:11, ai:8, engine:1 | libgte/libgpu combat loops + libspu/libpad support systems |
| 6 | JUNGLE_AREA | 96.0 | combat:34, support:11, ai:8, render:1 | libgte/libgpu combat loops + libspu/libpad support systems |
| 3 | WOODS_AREA | 90.4 | combat:34, support:11, ai:7, engine:2 | libgte/libgpu combat loops + libspu/libpad support systems |
| 14 | ALL_HEAVY_WEAPONS_1 | 76.9 | combat:28, engine:8, ai:3, render:1 | libgte/libgpu combat loops + state-machine scheduler |

## Second wave
| Crate | Label | Score | Highlights | PSYQ focus |
|-------|-------|-------|------------|------------|
| 32 | INDEX_32 | 76.8 | ai:9, engine:3, combat:1, render:1 | libgte vector routines + state-machine scheduler |
| 0 | PARK_AREA | 69.9 | ai:9, engine:3, combat:1, render:1 | libgte vector routines + state-machine scheduler |
| 1 | PLAINS_AREA | 69.9 | ai:9, engine:3, combat:1, render:1 | libgte vector routines + state-machine scheduler |
| 33 | INDEX_33 | 69.9 | ai:9, engine:3, combat:1, render:1 | libgte vector routines + state-machine scheduler |
| 35 | INDEX_35 | 69.9 | ai:9, engine:3, combat:1, render:1 | libgte vector routines + state-machine scheduler |

## Watch list
| Crate | Label | Score | Highlights | PSYQ focus |
|-------|-------|-------|------------|------------|
| 36 | INDEX_36 | 69.9 | ai:9, engine:3, combat:1, render:1 | libgte vector routines + state-machine scheduler |
| 37 | INDEX_37 | 69.9 | ai:9, engine:3, combat:1, render:1 | libgte vector routines + state-machine scheduler |
| 38 | INDEX_38 | 69.9 | ai:9, engine:3, combat:1, render:1 | libgte vector routines + state-machine scheduler |
| 39 | INDEX_39 | 69.9 | ai:9, engine:3, combat:1, render:1 | libgte vector routines + state-machine scheduler |
| 40 | INDEX_40 | 69.9 | ai:9, engine:3, combat:1, render:1 | libgte vector routines + state-machine scheduler |
| 34 | INDEX_34 | 60.8 | ai:10, combat:3, render:3 | libgte vector routines + libgpu geometry + libgte transforms |
| 16 | ALL_ROCKET_WEAPONS | 57.3 | render:9, ai:8, combat:5, engine:2 | libgpu geometry + libgte transforms + libgte vector routines |
| 18 | ALL_SPECIAL_WEAPONS | 55.8 | ai:8, render:8, combat:6, engine:2 | libgpu geometry + libgte transforms + libgte vector routines |
| 17 | ALL_MISSILE_WEAPONS | 54.3 | render:9, ai:8, combat:5, engine:2 | libgpu geometry + libgte transforms + libgte vector routines |
| 15 | ALL_HEAVY_WEAPONS_2 | 54.3 | render:9, ai:8, combat:5, engine:2 | libgpu geometry + libgte transforms + libgte vector routines |

---
Scores blend domain coverage with crossref totals. Domain weights emphasise render/combat-heavy crates for PSYQ instrumentation.
