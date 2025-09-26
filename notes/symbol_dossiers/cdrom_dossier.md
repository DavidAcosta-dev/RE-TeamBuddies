# Cdrom Symbol Dossier

Auto-generated summary from `sdk_symbol_labels.json`. Focused on high-confidence symbols within the "cdrom" category to guide subsystem reverse engineering.

## Top Symbols

| Symbol | Address | Observations | Distinct Addrs | Map Samples |
|---|---|---:|---:|---|
| `srand` | 0x80012318 | 4 | 1 | assets/PSYQ_SDK/psyq/addons/sound/STREAM/TUTO1.MAP<br/>assets/PSYQ_SDK/psyq/psx/sample/sound/STREAM/TUTO1.MAP |
| `CheckControllers` | 0x8001A130 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `DsStartCallback` | 0x800204E0 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/sound/STREAM/TUTO2.MAP |
| `InitControllers` | 0x8001A0B8 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `MDEC_vlc` | 0x80023EE8 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `MDEC_vlc2` | 0x8002421C | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `MDEC_vlc_brk` | 0x80023EB8 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `PlayStream` | 0x80019440 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `Pressed` | 0x8001A21C | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `SpuGetCommonAttr` | 0x80025978 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `SpuWrite0` | 0x80025620 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `SsGetSerialVol` | 0x800258A4 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `SsSetSerialAttr` | 0x80025D94 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `SsSetSerialVol` | 0x80027918 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `StopControllers` | 0x8001A108 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `bs_curt` | 0x80045F14 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `dc_cb` | 0x8004822C | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `dc_cr` | 0x80045764 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `dc_type` | 0x80045F04 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `dc_y` | 0x800460F4 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `dec_pt` | 0x80045D28 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `dec_used` | 0x80045F28 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `fIdA` | 0x8003EC9C | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |
| `ivlc_dct_dc_size` | 0x800245F8 | 2 | 1 | assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP |

## Frequent MAP Sources

| MAP Path | Count |
|---|---:|
| `assets/PSYQ_SDK/psyq/psx/sample/scee/CD/MOVIE2/MAIN.MAP` | 22 |
| `assets/PSYQ_SDK/psyq/addons/sound/STREAM/TUTO1.MAP` | 1 |
| `assets/PSYQ_SDK/psyq/psx/sample/sound/STREAM/TUTO1.MAP` | 1 |
| `assets/PSYQ_SDK/psyq/psx/sample/sound/STREAM/TUTO2.MAP` | 1 |

## Next Steps

- Cross-check these addresses against Team Buddies binaries to confirm function parity.
- Capture calling conventions in shared headers (e.g., `include/graphics.h`).
- Use `ApplySdkSymbols.py include_categories=cdrom` during Ghidra sessions for targeted labelling.
