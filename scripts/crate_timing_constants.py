#!/usr/bin/env python3
from __future__ import annotations
"""
Extract coarse timing constants from pickup_drop_pairs.csv into a compact report.

Outputs:
  exports/crate_timing_constants.md
"""
import csv, re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
PAIRS = EXPORTS / 'pickup_drop_pairs.csv'
OUT = EXPORTS / 'crate_timing_constants.md'

if not PAIRS.exists():
    raise SystemExit('Missing pickup_drop_pairs.csv')

durations = Counter()
frame_consts = Counter()

with PAIRS.open('r', encoding='utf-8', errors='ignore') as f:
    rd = csv.reader(f)
    header = next(rd, None)
    for row in rd:
        line = ' '.join(row)
        # naive capture of small integer constants likely to be frame counts
        for m in re.finditer(r'\b(1[0-9]|[2-9])\b', line):
            frame_consts[m.group(0)] += 1
        # capture hex 0x.. under 0x200
        for m in re.finditer(r'0x([0-1]?[0-9a-f]{1,2})\b', line, flags=re.I):
            frame_consts[m.group(0).lower()] += 1
        # look for phrases like delay=, cool, frame
        if 'frame' in line.lower() or 'cool' in line.lower() or 'delay' in line.lower():
            durations['hinted'] += 1

top_frames = frame_consts.most_common(20)

lines = []
lines.append('# Crate Timing Constants (coarse)')
lines.append('')
lines.append('Top small-constant frequencies (likely frame counts or fixed increments):')
lines.append('')
for val, cnt in top_frames:
    lines.append(f'- {val}: {cnt}')
lines.append('')
lines.append(f'Hints with words (frame/cool/delay): {durations["hinted"]}')

OUT.write_text('\n'.join(lines), encoding='utf-8')
print(f'Wrote {OUT}')
