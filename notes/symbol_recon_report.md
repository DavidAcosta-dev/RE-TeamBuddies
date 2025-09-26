# PSYQ Symbol Recon Report

Automated snapshot derived from the PSYQ SDK MAP exports. Use it to prioritise
interface work and bulk rename passes inside Ghidra.

## Category Overview

| Category | Symbols | Share (%) |
|---|---:|---:|
| module | 1010 | 19.53 |
| ui | 1010 | 19.53 |
| graphics | 927 | 17.93 |
| audio | 885 | 17.11 |
| cdrom | 551 | 10.66 |
| io | 478 | 9.24 |
| unknown | 310 | 5.99 |

## Category Highlights

### Module (1010 symbols, 19.53% share)

- `main` @ 0x80100DD0 — obs=8, distinct_addrs=17, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `_96_remove` @ 0x80017A40 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `_ramsize` @ 0x8001E90C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `_stacksize` @ 0x8001E908 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `ChangeClearPAD` @ 0x8001712C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `ChangeClearRCnt` @ 0x80017320 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `CheckCallback` @ 0x80017484 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `DMACallback` @ 0x80017390 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `EnterCriticalSection` @ 0x8001703C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `ExitCriticalSection` @ 0x8001704C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- … 916 more entries.

### Ui (1010 symbols, 19.53% share)

- `main` @ 0x80100DD0 — obs=8, distinct_addrs=17, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `_96_remove` @ 0x80017A40 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `_ramsize` @ 0x8001E90C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `_stacksize` @ 0x8001E908 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `ChangeClearPAD` @ 0x8001712C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `ChangeClearRCnt` @ 0x80017320 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `CheckCallback` @ 0x80017484 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `DMACallback` @ 0x80017390 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `EnterCriticalSection` @ 0x8001703C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `ExitCriticalSection` @ 0x8001704C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- … 916 more entries.

### Graphics (927 symbols, 17.93% share)

- `main` @ 0x80100DD0 — obs=8, distinct_addrs=17, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `m_sin` @ 0x80100D30 — obs=8, distinct_addrs=1, maps=8; e.g. `assets/psyq_sdk/psyq/psx/sample/graphics/texaddr/wave/main.map`
- `_96_remove` @ 0x80017A40 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `_ramsize` @ 0x8001E90C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `_stacksize` @ 0x8001E908 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `ChangeClearPAD` @ 0x8001712C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `ChangeClearRCnt` @ 0x80017320 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `CheckCallback` @ 0x80017484 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `DMACallback` @ 0x80017390 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `EnterCriticalSection` @ 0x8001703C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- … 803 more entries.

### Audio (885 symbols, 17.11% share)

- `main` @ 0x80100DD0 — obs=8, distinct_addrs=17, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `_96_remove` @ 0x80017A40 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `_ramsize` @ 0x8001E90C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `_stacksize` @ 0x8001E908 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `ChangeClearPAD` @ 0x8001712C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `ChangeClearRCnt` @ 0x80017320 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `CheckCallback` @ 0x80017484 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `DMACallback` @ 0x80017390 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `EnterCriticalSection` @ 0x8001703C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `ExitCriticalSection` @ 0x8001704C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- … 765 more entries.

### Cdrom (551 symbols, 10.66% share)

- `main` @ 0x80100DD0 — obs=8, distinct_addrs=17, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `_96_remove` @ 0x80017A40 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `_ramsize` @ 0x8001E90C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `_stacksize` @ 0x8001E908 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `ChangeClearPAD` @ 0x8001712C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `ChangeClearRCnt` @ 0x80017320 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `CheckCallback` @ 0x80017484 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `DMACallback` @ 0x80017390 — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `EnterCriticalSection` @ 0x8001703C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `ExitCriticalSection` @ 0x8001704C — obs=4, distinct_addrs=19, maps=42; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- … 484 more entries.

### Io (478 symbols, 9.24% share)

- `_LC` @ 0x801A4018 — obs=4, distinct_addrs=8, maps=18; e.g. `assets/psyq_sdk/psyq/addons/module/overmenu/menu.map`
- `HWD0` @ 0x801A4054 — obs=4, distinct_addrs=8, maps=18; e.g. `assets/psyq_sdk/psyq/addons/module/overmenu/menu.map`
- `VWD0` @ 0x801A4060 — obs=4, distinct_addrs=8, maps=18; e.g. `assets/psyq_sdk/psyq/addons/module/overmenu/menu.map`
- `_96_REMOVE` @ 0x80011A1C — obs=2, distinct_addrs=5, maps=10; e.g. `assets/psyq_sdk/psyq/addons/scee/etc/cardconf/main.map`
- `_QIN` @ 0x800167B4 — obs=2, distinct_addrs=5, maps=10; e.g. `assets/psyq_sdk/psyq/addons/scee/etc/cardconf/main.map`
- `_QOUT` @ 0x800167B8 — obs=2, distinct_addrs=5, maps=10; e.g. `assets/psyq_sdk/psyq/addons/scee/etc/cardconf/main.map`
- `_QUE` @ 0x80024790 — obs=2, distinct_addrs=5, maps=10; e.g. `assets/psyq_sdk/psyq/addons/scee/etc/cardconf/main.map`
- `_RAMSIZE` @ 0x80015554 — obs=2, distinct_addrs=5, maps=10; e.g. `assets/psyq_sdk/psyq/addons/scee/etc/cardconf/main.map`
- `_STACKSIZE` @ 0x80015550 — obs=2, distinct_addrs=5, maps=10; e.g. `assets/psyq_sdk/psyq/addons/scee/etc/cardconf/main.map`
- `ADDPRIM` @ 0x8001210C — obs=2, distinct_addrs=5, maps=10; e.g. `assets/psyq_sdk/psyq/addons/scee/etc/cardconf/main.map`
- … 457 more entries.

### Unknown (310 symbols, 5.99% share)

- `icon` @ 0x80010000 — obs=4, distinct_addrs=1, maps=4; e.g. `assets/psyq_sdk/psyq/addons/scee/demodisc/demo/bs/bs.map`
- `SpadStock` @ 0x80010000 — obs=4, distinct_addrs=1, maps=4; e.g. `assets/psyq_sdk/psyq/addons/cmplr/scratch/main.map`
- `Exec` @ 0x8001140C — obs=2, distinct_addrs=4, maps=8; e.g. `assets/psyq_sdk/psyq/addons/scee/demodisc/demo/bs/bs.map`
- `GoProg` @ 0x800106AC — obs=2, distinct_addrs=4, maps=8; e.g. `assets/psyq_sdk/psyq/addons/scee/demodisc/demo/bs/bs.map`
- `head` @ 0x800152E8 — obs=2, distinct_addrs=4, maps=8; e.g. `assets/psyq_sdk/psyq/addons/scee/demodisc/demo/bs/bs.map`
- `LoadProg` @ 0x80010460 — obs=2, distinct_addrs=4, maps=8; e.g. `assets/psyq_sdk/psyq/addons/scee/demodisc/demo/bs/bs.map`
- `rambase` @ 0x80014E40 — obs=2, distinct_addrs=4, maps=8; e.g. `assets/psyq_sdk/psyq/addons/scee/demodisc/demo/bs/bs.map`
- `timer` @ 0x800107D4 — obs=2, distinct_addrs=4, maps=8; e.g. `assets/psyq_sdk/psyq/addons/scee/demodisc/demo/bs/bs.map`
- `_boot` @ 0x80011DBC — obs=2, distinct_addrs=2, maps=4; e.g. `assets/psyq_sdk/psyq/addons/scee/demodisc/demo/bs/bs.map`
- `AppArgs` @ 0x800152D8 — obs=2, distinct_addrs=2, maps=4; e.g. `assets/psyq_sdk/psyq/opm/launcher/launch.map`
- … 291 more entries.

## Suggested Next Steps

- Feed category-specific labels into subsystem headers (graphics, audio, etc.).
- Run `ghidra_scripts/ApplySdkSymbols.py include_categories=graphics` (or other sets) to splash the 864 canonical labels across the game binary in focused passes.
- Start with the dominant categories when carving interface contracts (graphics + UI together represent ~40% of the dataset).
- Reference `notes/symbol_dossiers/` for ready-made shortlists tied to graphics/audio/cdrom workflows.
