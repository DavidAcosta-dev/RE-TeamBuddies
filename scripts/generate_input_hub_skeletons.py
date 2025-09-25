#!/usr/bin/env python3
"""Generate per-input-hub annotation skeletons.

Reads exports/input_hubs.md and creates (if absent) an annotation file:
  exports/input_hubs/<FUN_xxxxxxxx>.md
Prepopulates with section headings for manual semantic notes (pad bits, state transitions, linked crate/vertical calls).
"""
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
HUB_FILE = EXPORTS / 'input_hubs.md'
OUT_DIR = EXPORTS / 'input_hubs'
OUT_DIR.mkdir(exist_ok=True)

if not HUB_FILE.exists():
    print('input_hubs.md missing; run extract_input_hubs.py first')
    raise SystemExit(1)

funcs = []
for ln in HUB_FILE.read_text(encoding='utf-8', errors='ignore').splitlines():
    if ln.startswith('- FUN_'):
        funcs.append(ln.split(':',1)[0].strip('- ').strip())

TEMPLATE = """# {name} Input Hub Annotation

## High-Level Role
// Describe orchestrator role (e.g., consolidates crate + input + pickup logic)

## Pad Bit Consumption
// List pad bits (e.g., 0x10 throw, 0x40 pickup) and gating conditions

## State / Scheduler Interactions
// Functions called that enqueue state changes (list FUN_xxx or named symbols)

## Crate / Pickup Paths
// Summarize calls branching into crate/pickup pathways

## Vertical / Movement Links
// Any calls into vertical_core/consumer or gravity-tagged functions

## Additional Notes
// Edge cases, timing constants, TODOs
"""

created = 0
for f in funcs:
    path = OUT_DIR / f'{f}.md'
    if path.exists():
        continue
    path.write_text(TEMPLATE.format(name=f))
    created += 1

print(f'Generated {created} new skeleton annotation files in {OUT_DIR}')
