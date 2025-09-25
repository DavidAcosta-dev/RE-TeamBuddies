#!/usr/bin/env python3
"""Deep scan integrator callees for vertical + shift rich functions to extend gravity chain.

Looks at functions listed in gravity_neighborhood_extend.md callee table and identifies those with
 strong vertical pattern: verticalHits >=4 and shifts >=1 (or verticalHits >=2 and shifts >=2).
Outputs prioritized list for manual review.

Outputs:
  - exports/gravity_deep_callees.md
"""
from __future__ import annotations
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
EXT_MD = EXPORTS / 'gravity_neighborhood_extend.md'
OUT = EXPORTS / 'gravity_deep_callees.md'

if not EXT_MD.exists():
    raise SystemExit('gravity_neighborhood_extend.md missing.')

text = EXT_MD.read_text(encoding='utf-8')
lines = text.splitlines()
in_callee = False
rows = []
for ln in lines:
    if ln.startswith('## Callee Metrics'):
        in_callee = True
        continue
    if in_callee:
        if not ln.strip():
            continue
        if ln.startswith('| Integrator | Callee'):
            continue
        if ln.startswith('|------------'):
            continue
        if ln.startswith('###'):
            break
        if ln.startswith('|'):
            parts = [p.strip() for p in ln.strip().strip('|').split('|')]
            if len(parts) >= 5:
                integ, callee, c_spatial, c_vert, c_shifts = parts
                try:
                    c_spatial = int(c_spatial)
                    c_vert = int(c_vert)
                    c_shifts = int(c_shifts)
                except ValueError:
                    continue
                priority = 0
                if (c_vert >= 4 and c_shifts >= 1) or (c_vert >=2 and c_shifts >=2):
                    priority = c_vert * 2 + c_shifts * 3
                if priority:
                    rows.append({
                        'integrator': integ,
                        'callee': callee,
                        'vert': c_vert,
                        'shifts': c_shifts,
                        'spatial': c_spatial,
                        'priority': priority,
                    })

rows.sort(key=lambda r: (-r['priority'], -r['vert'], -r['shifts']))

with OUT.open('w', encoding='utf-8') as fh:
    fh.write('# Gravity Deep Callee Scan\n\n')
    if not rows:
        fh.write('_No high-priority vertical+shift callees found._\n')
    else:
        fh.write('| Priority | Callee | Integrator | Vert | Shifts | Spatial |\n')
        fh.write('|---------:|--------|------------|-----:|-------:|--------:|\n')
        for r in rows:
            fh.write(f"| {r['priority']} | {r['callee']} | {r['integrator']} | {r['vert']} | {r['shifts']} | {r['spatial']} |\n")
        fh.write('\nHeuristic: High vertical + shift density suggests Y accumulation or fixed-point normalization pieces.\n')

print(f'Wrote {OUT} with {len(rows)} high-priority callees')
