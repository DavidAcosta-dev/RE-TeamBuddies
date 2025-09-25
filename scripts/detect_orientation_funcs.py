#!/usr/bin/env python3
"""Detect orientation-related functions.

Heuristic:
  - Search snippet export files (snippets_*.md) for lines containing '& 0xFFF' or '&0xFFF'
  - Also look for references to known trig table base addresses (0x26800, 0x27800) as hex literals.
  - Collect function names (FUN_XXXXXXXX) appearing in those lines or the nearest preceding header line containing a function name.
Output:
  exports/orientation_candidates.md
"""
from __future__ import annotations
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
OUT = EXPORTS / 'orientation_candidates.md'

FUNC_RE = re.compile(r'FUN_[0-9a-fA-F]{8}')
TRIG_PAT = re.compile(r'&\s*0x?FFF', re.IGNORECASE)
ADDR_PAT = re.compile(r'0x(26800|27800)')

orientation_funcs = set()

for f in EXPORTS.glob('snippets_*.md'):
    lines = f.read_text(encoding='utf-8', errors='ignore').splitlines()
    last_func = None
    for ln in lines:
        # Track function context
        fmatch = FUNC_RE.search(ln)
        if fmatch:
            last_func = fmatch.group(0)
        if TRIG_PAT.search(ln) or ADDR_PAT.search(ln):
            if fmatch:
                orientation_funcs.add(fmatch.group(0))
            elif last_func:
                orientation_funcs.add(last_func)

if orientation_funcs:
    with OUT.open('w', encoding='utf-8') as fh:
        fh.write('# Orientation Candidate Functions\n\n')
        fh.write(f'Detected {len(orientation_funcs)} functions via trig mask / table heuristic.\n\n')
        for fn in sorted(orientation_funcs):
            fh.write(f'- {fn}\n')
    print(f'Wrote {OUT} ({len(orientation_funcs)} functions)')
else:
    print('No orientation candidates found (heuristic may need adjustment)')
