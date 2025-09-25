#!/usr/bin/env python3
"""Detect integrator / spatial update clusters.

Heuristic: functions whose snippet lines contain all of:
  - velocities: +0x100 and +0x102 (velX, velZ assumed from integrator_lines.md naming comments)
  - positions: +0x114 and +0x118 (posX, posZ)
  - at least two '>> 0xc' shift operations in same function body.

Also capture any occurrences of +0x104 / +0x10a / +0x10c / +0x110 / +0x11c to surface potential Y components or adjacent fields.

Output: exports/gravity_integrator_cluster.md
"""
from __future__ import annotations
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
OUT = EXPORTS / 'gravity_integrator_cluster.md'

FUNC_RE = re.compile(r'FUN_[0-9a-fA-F]{8}')
SHIFT_RE = re.compile(r'>>\s*0xc')

needed = ['+0x100','+0x102','+0x114','+0x118']
optional = ['+0x104','+0x106','+0x108','+0x10a','+0x10c','+0x10e','+0x110','+0x11c']

hits = {}

for snip in EXPORTS.glob('snippets_*.md'):
    lines = snip.read_text(encoding='utf-8', errors='ignore').splitlines()
    current = None
    bucket = []
    for ln in lines:
        m = FUNC_RE.search(ln)
        if m:
            if current and bucket:
                text = '\n'.join(bucket)
                if all(n in text for n in needed) and len(SHIFT_RE.findall(text)) >= 2:
                    hits[current] = {
                        'file': snip.name,
                        'optional': [o for o in optional if o in text]
                    }
            current = m.group(0)
            bucket = [ln]
        else:
            if current:
                bucket.append(ln)
    # flush last function
    if current and bucket:
        text = '\n'.join(bucket)
        if all(n in text for n in needed) and len(SHIFT_RE.findall(text)) >= 2:
            hits[current] = {
                'file': snip.name,
                'optional': [o for o in optional if o in text]
            }

with OUT.open('w', encoding='utf-8') as fh:
    fh.write('# Gravity / Integrator Cluster Detection\n\n')
    fh.write(f'Requirements: {", ".join(needed)} + >=2 shift(>>0xc).\n\n')
    if not hits:
        fh.write('_No functions met integrator cluster heuristic._\n')
    else:
        fh.write('| Function | Source Snippet File | Optional Offsets Present |\n')
        fh.write('|----------|--------------------|---------------------------|\n')
        for fn,meta in sorted(hits.items()):
            opt = ','.join(meta['optional']) if meta['optional'] else ''
            fh.write(f"| {fn} | {meta['file']} | {opt} |\n")
        fh.write('\n## Notes\n\n')
        fh.write('Optional offsets hint at Y-axis or extended spatial fields if present.\n')

print(f'Wrote {OUT} with {len(hits)} integrator cluster candidates')
