#!/usr/bin/env python3
"""Annotate orientation candidates with coarse roles.

Roles:
  - trig_source: contains &0xFFF mask AND references both 0x26800 and 0x27800
  - angle_normalize: contains &0xFFF but only one table ref
  - orientation_consumer: references a trig table address but no mask (&0xFFF) (likely uses precomputed angle)
  - ambiguous: none of the above heuristics

Output: exports/orientation_candidates_annotated.md
"""
from __future__ import annotations
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
BASE_FILE = EXPORTS / 'orientation_candidates.md'
OUT = EXPORTS / 'orientation_candidates_annotated.md'

if not BASE_FILE.exists():
    print('orientation_candidates.md missing; run detector first')
    raise SystemExit(1)

functions = [ln.strip('- ').strip() for ln in BASE_FILE.read_text().splitlines() if ln.startswith('- FUN_')]
FUNC_SET = set(functions)

FUNC_RE = re.compile(r'FUN_[0-9a-fA-F]{8}')

info = {f:{'mask':False,'sintab':False,'costab':False} for f in functions}

for snippet in EXPORTS.glob('snippets_*.md'):
    lines = snippet.read_text(encoding='utf-8', errors='ignore').splitlines()
    current = None
    for ln in lines:
        m = FUNC_RE.search(ln)
        if m:
            current = m.group(0)
        if current not in FUNC_SET:
            continue
        if '& 0xFFF' in ln or '&0xFFF' in ln:
            info[current]['mask'] = True
        if '0x26800' in ln:
            info[current]['sintab'] = True
        if '0x27800' in ln:
            info[current]['costab'] = True

def classify(d):
    if d['mask'] and d['sintab'] and d['costab']:
        return 'trig_source'
    if d['mask'] and (d['sintab'] ^ d['costab']):
        return 'angle_normalize'
    if (d['sintab'] or d['costab']) and not d['mask']:
        return 'orientation_consumer'
    return 'ambiguous'

with OUT.open('w', encoding='utf-8') as fh:
    fh.write('# Annotated Orientation Candidates\n\n')
    fh.write('| Function | Mask (&0xFFF) | SinRef | CosRef | Role |\n')
    fh.write('|----------|--------------:|-------:|-------:|------|\n')
    for fn in sorted(functions):
        d = info[fn]
        role = classify(d)
        fh.write(f'| {fn} | {int(d['mask'])} | {int(d['sintab'])} | {int(d['costab'])} | {role} |\n')
print(f'Wrote {OUT}')
