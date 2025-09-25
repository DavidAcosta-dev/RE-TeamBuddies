#!/usr/bin/env python3
"""Enhanced gravity pointer chase (v2).

Improvements over v1:
 - Broaden candidate secondary pointer offsets: 0x118,0x11A,0x11C,0x11E,0x120,0x124
 - Accept lowercase/uppercase hex and decimal forms (e.g., 284 for 0x11C)
 - Rudimentary register flow heuristic: if a line loads from *(base + off) into a register (e.g., v0=, a1=, t0=)
   then subsequent lines within a small window referencing that register plus vertical field offsets count as linkage.
 - Scores:
     pointer_load = 2
     vertical_field_direct = 1 (line with +0x5C..+0x62 or amplitude offset) 
     linked_register_usage = +1 each time register appears in vertical line.

Outputs: exports/gravity_pointer_chase_v2.md
"""
from __future__ import annotations
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
OUT = EXPORTS / 'gravity_pointer_chase_v2.md'

FUNC_RE = re.compile(r'FUN_[0-9a-fA-F]{8}')
PTR_OFFS = ['0x118','0x11a','0x11c','0x11e','0x120','0x124']
PTR_DEC = {str(int(o,16)) for o in PTR_OFFS}  # decimal strings
VERT_FIELDS = ['+0x50','+0x52','+0x54','+0x56','+0x58','+0x5a','+0x5A','+0x5C','+0x5c','+0x5E','+0x5e','+0x60','+0x62']
LOAD_RE = re.compile(r'(?P<reg>[avst][0-9])\s*=.*(0x11[89aA-cC-eE]|0x120|0x124|\b28[048]\b)')

class Rec:
    __slots__ = ('func','score','ptr_loads','vert_lines','reg_links')
    def __init__(self, func):
        self.func = func
        self.score = 0
        self.ptr_loads = 0
        self.vert_lines = 0
        self.reg_links = 0

records = {}

def get(func):
    if func not in records:
        records[func] = Rec(func)
    return records[func]

for snip in EXPORTS.glob('snippets_*.md'):
    lines = snip.read_text(encoding='utf-8', errors='ignore').splitlines()
    current = None
    recent_regs = []  # (reg, ttl)
    for ln in lines:
        fm = FUNC_RE.search(ln)
        if fm:
            current = fm.group(0)
            recent_regs.clear()
        if not current:
            continue
        rec = get(current)
        # Decay TTL
        recent_regs = [(r,ttl-1) for r,ttl in recent_regs if ttl>1]
        # Detect pointer loads
        if any(off in ln for off in PTR_OFFS) or any(d in ln for d in PTR_DEC):
            m = LOAD_RE.search(ln)
            if m:
                reg = m.group('reg')
                recent_regs.append((reg,5))  # track for next few lines
            rec.ptr_loads += 1
            rec.score += 2
        # Vertical field usage
        if any(vf in ln for vf in VERT_FIELDS):
            rec.vert_lines += 1
            rec.score += 1
            # register linkage
            for reg,_ttl in recent_regs:
                if reg in ln:
                    rec.reg_links += 1
                    rec.score += 1

ranked = [r for r in records.values() if r.ptr_loads and r.vert_lines]
ranked.sort(key=lambda r: r.score, reverse=True)

with OUT.open('w', encoding='utf-8') as fh:
    fh.write('# Gravity Pointer-Chase v2\n\n')
    fh.write('Enhanced heuristic: broader offsets, register linkage scoring.\n\n')
    if not ranked:
        fh.write('_No candidates with both pointer loads and vertical field lines under v2 heuristic._\n')
    else:
        fh.write('| Function | Score | PtrLoads | VertLines | RegLinks |\n')
        fh.write('|----------|------:|---------:|----------:|---------:|\n')
        for r in ranked:
            fh.write(f'| {r.func} | {r.score} | {r.ptr_loads} | {r.vert_lines} | {r.reg_links} |\n')
print(f'Wrote {OUT} with {len(ranked)} ranked functions')
