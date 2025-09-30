# FieldTruth Coverage Summary – Crates 4–6 (High Priority Slots)

This note captures the ten recurring function hits surfaced by the 18-slot
FieldTruth sweep across crates 4–6 (ICE_AREA → JUNGLE_AREA) and the single
fallback memory sample. Every slot returned the same call-map driven matches,
signalising a tightly shared gameplay subsystem—likely the core physics/GPU
loop that underpins combat encounters.

## Core Matches

| Function | Address | Stub Path | Primary Mapping Context | Tags | Size (bytes) |
| --- | --- | --- | --- | --- | --- |
| `FUN_000006dc` | `0x000006dc` | `reconstructed_src/field_truth/000006dc_fun_000006dc.c` | `exports/mapping_ROT.BIN.md` · Top hubs | `physics, gpu` | 476 |
| `FUN_00000900` | `0x00000900` | `reconstructed_src/field_truth/00000900_fun_00000900.c` | `exports/mapping_ROT.BIN.md` · Seed neighborhoods (2 hops) | `physics, gpu` | 96 |
| `FUN_00001868` | `0x00001868` | `reconstructed_src/field_truth/00001868_fun_00001868.c` | `exports/mapping_MNU.BIN.md` · Seed neighborhoods (2 hops) | `physics, gpu` | 96 |
| `FUN_00001948` | `0x00001948` | `reconstructed_src/field_truth/00001948_fun_00001948.c` | `exports/mapping_MNU.BIN.md` · Top hubs | `physics, gpu` | 344 |
| `FUN_00001ad4` | `0x00001ad4` | `reconstructed_src/field_truth/00001ad4_fun_00001ad4.c` | `exports/mapping_ROT.BIN.md` · Top hubs | `physics, gpu` | 460 |
| `FUN_0000276c` | `0x0000276c` | `reconstructed_src/field_truth/0000276c_fun_0000276c.c` | `exports/mapping_SYS.BIN.md` · Top hubs | `physics, gpu` | 400 |
| `FUN_00002b10` | `0x00002b10` | `reconstructed_src/field_truth/00002b10_fun_00002b10.c` | `exports/mapping_SYS.BIN.md` · Top hubs | `physics, gpu` | 1004 |
| `FUN_000031d8` | `0x000031d8` | `reconstructed_src/field_truth/000031d8_fun_000031d8.c` | `exports/mapping_MNU.BIN.md` · Top hubs | `physics, gpu` | 2492 |
| `FUN_0000377c` | `0x0000377c` | `reconstructed_src/field_truth/0000377c_fun_0000377c.c` | `exports/mapping_SYS.BIN.md` · Top hubs | `physics, gpu` | 616 |
| `FUN_000053dc` | `0x000053dc` | `reconstructed_src/field_truth/000053dc_fun_000053dc.c` | `exports/mapping_ROT.BIN.md` · Seed neighborhoods (2 hops) | `physics, gpu` | 156 |

_All ten hits share identical provenance across every log. Focus tokens (“libgte/libgpu combat loops”) correlate with the physics/GPU tag cluster shown in the call-map exports above._

## Fallback Sample

| Symbol | Address | Stub Path | Origin |
| --- | --- | --- | --- |
| `ram__00000000_` | `0x00000000` | `reconstructed_src/field_truth/00000000_ram__00000000_.c` | Memory block sample captured when keyword search produced zero direct matches. |

## Suggested Next Moves

- **Decompile the hubs first**: tackle `FUN_000031d8` and `FUN_00002b10`—they are the largest routines in the cluster and likely orchestrate the shared combat/physics loop for these crates.
- **Correlate with vertical dossiers**: `FUN_000031d8` already appears in `vertical_block_map.md`; cross-link its block-motion offsets with gameplay observations from the ICE/ORIENTAL/JUNGLE encounters.
- **Adjust focus tokens if differentiation is needed**: since all slots converge on the same set, add environment-specific tokens (e.g., “oriental boss”, “jungle spawn scripts”) before the next FieldTruth sweep to tease out crate-unique behaviours.
- **Promote promising stubs into manual reconstruction**: migrate the most critical functions into the primary reverse-engineering tree once disassembly confirms their combat role.
