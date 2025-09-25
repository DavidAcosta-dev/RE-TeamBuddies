#!/usr/bin/env python3
"""
secondary_index_neighborhood.py

Capture array-index style secondary struct usage:
  (*(type **)(param_X + 0x11c))[index]
We aggregate index frequencies and note if nearby a >>0xC shift occurs.

Outputs:
  secondary_index_neighborhood.md
"""
from __future__ import annotations
import re,json
from pathlib import Path
from collections import defaultdict

BUNDLE_GLOB='exports/bundle_*.jsonl'
ARR_IDX=re.compile(r'\(\*\([^)]*\*\)\(param_\d+ \+ 0x11c\)\)\[(0x[0-9a-fA-F]+|\d+)\]')
SHIFT=re.compile(r'>>\s*0xc',re.IGNORECASE)
WINDOW=8

def iter_funcs():
    for p in Path('.').glob(BUNDLE_GLOB):
        with p.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip();
                if not line: continue
                try:
                    obj=json.loads(line)
                except json.JSONDecodeError:
                    continue
                if 'function' in obj:
                    yield obj

def parse_idx(tok:str)->int:
    return int(tok,16) if tok.startswith('0x') else int(tok)

def main():
    idx_stats=defaultdict(lambda:{'freq':0,'shiftNear':0,'funcs':set()})
    for fn in iter_funcs():
        dec=fn.get('decompilation') or ''
        if '+ 0x11c)' not in dec: continue
        lines=dec.splitlines()
        shift_lines=[i for i,l in enumerate(lines) if SHIFT.search(l)]
        for i,l in enumerate(lines):
            for m in ARR_IDX.finditer(l):
                try:
                    idx=parse_idx(m.group(1))
                except ValueError:
                    continue
                st=idx_stats[idx]
                st['freq']+=1
                st['funcs'].add(fn['function']['name'])
                # shift proximity
                for s in shift_lines:
                    if abs(s-i)<=WINDOW:
                        st['shiftNear']+=1
                        break
    with open('secondary_index_neighborhood.md','w',encoding='utf-8') as f:
        f.write('# Secondary Array Index Neighborhood (via +0x11C pointer)\n\n')
        if not idx_stats:
            f.write('_No array index patterns detected._')
            return
        f.write('| Index | Freq | ShiftNear | Funcs |\n|-------|------|-----------|-------|\n')
        for idx,st in sorted(idx_stats.items(), key=lambda x:-x[1]['freq']):
            f.write(f"| 0x{idx:x} | {st['freq']} | {st['shiftNear']} | {len(st['funcs'])} |\n")
    print('Wrote secondary_index_neighborhood.md with',len(idx_stats),'indices')

if __name__=='__main__':
    main()
