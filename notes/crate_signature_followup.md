# Crate Signature Follow-up

Generated: 2025-09-25T20:36:19+00:00 UTC

## High-confidence pickup/throw leads

- `FUN_00038748` @ 0x038748 — score 7, tri 7. Masks: yes, Polarity: yes, Effects: no. Sources: exports\bundle_GAME.BIN.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl
- `FUN_0003baf8` @ 0x03baf8 — score 7, tri 7. Masks: yes, Polarity: yes, Effects: no. Sources: exports\bundle_GAME.BIN.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl
- `FUN_000090e0` @ 0x0090e0 — score 7, tri 6. Masks: yes, Polarity: no, Effects: yes. Sources: exports\bundle_MAIN.EXE.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl
- `FUN_00008528` @ 0x008528 — score 7, tri 4. Masks: yes, Polarity: no, Effects: yes. Sources: exports\bundle_MAIN.EXE.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl
- `FUN_00009708` @ 0x009708 — score 7, tri 3. Masks: yes, Polarity: no, Effects: yes. Sources: exports\bundle_MAIN.EXE.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl
- `FUN_0001a348` @ 0x01a348 — score 7, tri 3. Masks: yes, Polarity: no, Effects: yes. Sources: exports\bundle_MAIN.EXE.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl
- `FUN_00044f80` @ 0x044f80 — score 5, tri 20. Masks: yes, Polarity: no, Effects: no. Sources: exports\bundle_GAME.BIN.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl
- `FUN_000475dc` @ 0x0475dc — score 5, tri 17. Masks: yes, Polarity: no, Effects: no. Sources: exports\bundle_GAME.BIN.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl
- `FUN_00046024` @ 0x046024 — score 5, tri 11. Masks: yes, Polarity: no, Effects: no. Sources: exports\bundle_GAME.BIN.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl
- `FUN_00044a14` @ 0x044a14 — score 5, tri 10. Masks: yes, Polarity: no, Effects: no. Sources: exports\bundle_GAME.BIN.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl

## Secondary callback prospects

- `FUN_0001a804` @ 0x01a804 — score 5, tri 3. Masks: no, Polarity: no, Effects: yes. Sources: exports\bundle_MAIN.EXE.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl
- `FUN_0001eec8` @ 0x01eec8 — score 4, tri 2. Masks: no, Polarity: no, Effects: yes. Sources: exports\bundle_MAIN.EXE.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl

## Polarity helpers to verify

- None captured.

## Per-frame handlers worth diffing

- `FUN_000057cc` @ 0x0057cc — score 3, tri 3. Masks: no, Polarity: no, Effects: no. Sources: exports\bundle_ROT.BIN.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl
- `FUN_00016a1c` @ 0x016a1c — score 3, tri 3. Masks: no, Polarity: no, Effects: no. Sources: exports\bundle_LEGGIT.EXE.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl
- `FUN_0001b554` @ 0x01b554 — score 3, tri 3. Masks: no, Polarity: no, Effects: no. Sources: exports\bundle_MAIN.EXE.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl
- `FUN_00022dc8` @ 0x022dc8 — score 3, tri 3. Masks: no, Polarity: no, Effects: no. Sources: exports\bundle_GAME.BIN.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl
- `FUN_00022e5c` @ 0x022e5c — score 3, tri 3. Masks: no, Polarity: no, Effects: no. Sources: exports\bundle_GAME.BIN.jsonl, exports\bundle_all_plus_demo.jsonl, exports\bundle_ghidra.jsonl

## Immediate tasks

1. Diff the pickup/throw integrator calls between MAIN.EXE and overlays for the top 5 leads.
2. Trace secondary callback install sites for high-scoring entries to map animation/audio assets.
3. Validate polarity helper usage paths before assigning final names.
4. Feed confirmed matches back into the SDK label pipeline and Ghidra import script.