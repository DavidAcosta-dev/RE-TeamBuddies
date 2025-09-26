# Crate Signature Candidate Triage Report

Generated: 2025-09-25T20:36:19+00:00 UTC

## Snapshot

- Total CSV rows: 9220
- Unique functions: 2267
- Candidate type counts: other=2207, pickup_or_throw_logic=50, per_frame_cb=8, secondary_cb=2
- Sources scanned: exports\bundle_GAME.BIN.jsonl, exports\bundle_LEGGIT.EXE.jsonl, exports\bundle_MAIN.EXE.jsonl, exports\bundle_MNU.BIN.jsonl, exports\bundle_MPLR.BIN.jsonl, exports\bundle_PSX.EXE.jsonl, exports\bundle_ROT.BIN.jsonl, exports\bundle_SYS.BIN.jsonl, exports\bundle_TUTO.BIN.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl
- Functions with pickup masks and full tri-slot coverage: 37

## Score Distribution

| Score | Functions | Tier |
| --- | ---: | --- |
| 7 | 6 | score_6_7 |
| 5 | 32 | score_4_5 |
| 4 | 18 | score_4_5 |
| 3 | 55 | score_below_4 |
| 2 | 217 | score_below_4 |
| 1 | 78 | score_below_4 |
| 0 | 1861 | score_below_4 |

## Top Candidates (score ≥ 6)

| Function | EA | Score | Type | Tri Hits | Masks | Polarity | Effects | Sources |
| --- | --- | ---: | --- | ---: | :---: | :---: | :---: | ---: |
| FUN_00038748 | 0x038748 | 7 | pickup_or_throw_logic | 7 | ✅ | ✅ |  | 3 |
| FUN_0003baf8 | 0x03baf8 | 7 | pickup_or_throw_logic | 7 | ✅ | ✅ |  | 3 |
| FUN_000090e0 | 0x0090e0 | 7 | pickup_or_throw_logic | 6 | ✅ |  | ✅ | 3 |
| FUN_00008528 | 0x008528 | 7 | pickup_or_throw_logic | 4 | ✅ |  | ✅ | 3 |
| FUN_00009708 | 0x009708 | 7 | pickup_or_throw_logic | 3 | ✅ |  | ✅ | 3 |
| FUN_0001a348 | 0x01a348 | 7 | pickup_or_throw_logic | 3 | ✅ |  | ✅ | 3 |

## Source Coverage

| Source | Rows | Unique functions | High-score funcs | Max score | Key types |
| --- | ---: | ---: | ---: | ---: | --- |
| exports\bundle_GAME.BIN.jsonl | 872 | 872 | 2 | 7 | other:833, pickup_or_throw_logic:34, per_frame_cb:5 |
| exports\bundle_LEGGIT.EXE.jsonl | 198 | 198 | 0 | 5 | other:196, pickup_or_throw_logic:1, per_frame_cb:1 |
| exports\bundle_MAIN.EXE.jsonl | 907 | 907 | 4 | 7 | other:891, pickup_or_throw_logic:13, secondary_cb:2, per_frame_cb:1 |
| exports\bundle_MNU.BIN.jsonl | 46 | 46 | 0 | 3 | other:46 |
| exports\bundle_MPLR.BIN.jsonl | 7 | 7 | 0 | 2 | other:7 |
| exports\bundle_PSX.EXE.jsonl | 45 | 45 | 0 | 1 | other:45 |
| exports\bundle_ROT.BIN.jsonl | 108 | 108 | 0 | 5 | other:105, pickup_or_throw_logic:2, per_frame_cb:1 |
| exports\bundle_SYS.BIN.jsonl | 112 | 112 | 0 | 3 | other:112 |
| exports\bundle_TUTO.BIN.jsonl | 10 | 10 | 0 | 3 | other:10 |
| exports\bundle_all_plus_demo.jsonl | 2305 | 2267 | 6 | 7 | other:2246, pickup_or_throw_logic:50, per_frame_cb:9 |
| exports\bundle_ghidra.jsonl | 4610 | 2267 | 6 | 7 | other:4491, pickup_or_throw_logic:100, per_frame_cb:17, secondary_cb:2 |

## Type Highlights

### pickup_or_throw_logic

| Function | EA | Score | Tri Hits | Masks | Polarity | Effects | Sources |
| --- | --- | ---: | ---: | :---: | :---: | :---: | ---: |
| FUN_00038748 | 0x038748 | 7 | 7 | ✅ | ✅ |  | 3 |
| FUN_0003baf8 | 0x03baf8 | 7 | 7 | ✅ | ✅ |  | 3 |
| FUN_000090e0 | 0x0090e0 | 7 | 6 | ✅ |  | ✅ | 3 |
| FUN_00008528 | 0x008528 | 7 | 4 | ✅ |  | ✅ | 3 |
| FUN_00009708 | 0x009708 | 7 | 3 | ✅ |  | ✅ | 3 |

### secondary_cb

| Function | EA | Score | Tri Hits | Masks | Polarity | Effects | Sources |
| --- | --- | ---: | ---: | :---: | :---: | :---: | ---: |
| FUN_0001a804 | 0x01a804 | 5 | 3 |  |  | ✅ | 3 |
| FUN_0001eec8 | 0x01eec8 | 4 | 2 |  |  | ✅ | 3 |

### other

| Function | EA | Score | Tri Hits | Masks | Polarity | Effects | Sources |
| --- | --- | ---: | ---: | :---: | :---: | :---: | ---: |
| FUN_000026f4 | 0x0026f4 | 4 | 0 | ✅ |  | ✅ | 3 |
| FUN_00008158 | 0x008158 | 4 | 0 | ✅ |  | ✅ | 4 |
| FUN_00019614 | 0x019614 | 4 | 0 | ✅ |  | ✅ | 3 |
| FUN_0001fab8 | 0x01fab8 | 4 | 0 | ✅ |  | ✅ | 3 |
| FUN_0003b264 | 0x03b264 | 3 | 11 |  |  |  | 3 |

### per_frame_cb

| Function | EA | Score | Tri Hits | Masks | Polarity | Effects | Sources |
| --- | --- | ---: | ---: | :---: | :---: | :---: | ---: |
| FUN_000057cc | 0x0057cc | 3 | 3 |  |  |  | 3 |
| FUN_00016a1c | 0x016a1c | 3 | 3 |  |  |  | 3 |
| FUN_0001b554 | 0x01b554 | 3 | 3 |  |  |  | 3 |
| FUN_00022dc8 | 0x022dc8 | 3 | 3 |  |  |  | 3 |
| FUN_00022e5c | 0x022e5c | 3 | 3 |  |  |  | 3 |

## Follow-up Leads

1. Validate pickup/throw state transitions for the highest scoring `pickup_or_throw_logic` entries.
2. Map secondary callbacks with strong effects calls to their animation/audio resources.
3. Confirm polarity helper routines tie into crate ownership checks before installing names.
4. Feed the top candidates into Ghidra symbol import to accelerate naming passes.