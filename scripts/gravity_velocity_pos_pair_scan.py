#!/usr/bin/env python3
"""Gravity heuristic v3: broaden integrator search.

Instead of requiring all four offsets, look for functions referencing ANY 3 of the 4 core spatial offsets
(0x100,0x102,0x114,0x118) plus at least one >>0xc shift, OR referencing any 2 core offsets and one from the extended set
(0x104,0x106,0x108,0x10a,0x10c,0x10e,0x110,0x11c) with >=2 shifts.

Output: exports/gravity_velocity_pos_pair_scan.md
"""
from __future__ import annotations
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
OUT = EXPORTS / 'gravity_velocity_pos_pair_scan.md'

FUNC_RE = re.compile(r'FUN_[0-9a-fA-F]{8}')
SHIFT_RE = re.compile(r'>>\s*0xc')

core = ['+0x100','+0x102','+0x114','+0x118']
ext = ['+0x104','+0x106','+0x108','+0x10a','+0x10c','+0x10e','+0x110','+0x11c']

candidates = {}

def consider(name, text):
    core_hits = [o for o in core if o in text]
    ext_hits = [o for o in ext if o in text]
    shifts = SHIFT_RE.findall(text)
    cond1 = len(core_hits) >= 3 and len(shifts) >= 1
    cond2 = len(core_hits) >= 2 and len(ext_hits) >= 1 and len(shifts) >= 2
    if cond1 or cond2:
        candidates[name] = {
            'core': core_hits,
            'ext': ext_hits,
            'shifts': len(shifts),
            'mode': 'core3+' if cond1 else 'core2+ext'
        }

for snip in EXPORTS.glob('snippets_*.md'):
    content = snip.read_text(encoding='utf-8', errors='ignore')
    # naive split by function markers
    parts = re.split(r'(FUN_[0-9a-fA-F]{8})', content)
    # parts pattern: '', name, rest, name, rest...
    for i in range(1, len(parts), 2):
        name = parts[i]
        body = parts[i+1]
        consider(name, body)

with OUT.open('w', encoding='utf-8') as fh:
    fh.write('# Gravity Velocity/Position Pair Scan (v3)\n\n')
    fh.write('Heuristic: core>=3 with >=1 shift OR core>=2 + ext>=1 with >=2 shifts.\n\n')
    if not candidates:
        fh.write('_No candidates under broadened velocity/position heuristic._\n')
    else:
        fh.write('| Function | Mode | CoreHits | ExtHits | ShiftCount |\n')
        fh.write('|----------|------|----------|---------|-----------:|\n')
        for fn,meta in sorted(candidates.items()):
            fh.write(f"| {fn} | {meta['mode']} | {','.join(meta['core'])} | {','.join(meta['ext'])} | {meta['shifts']} |\n")
        fh.write(f"\nTotal: {len(candidates)} candidates\n")

print(f'Wrote {OUT} with {len(candidates)} gravity velocity/position candidates')
