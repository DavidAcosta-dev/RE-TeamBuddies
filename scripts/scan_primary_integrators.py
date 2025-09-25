#!/usr/bin/env python3
"""
scan_primary_integrators.py

Search for classic fixed-point integrator patterns in the primary object struct:
   *(int *)(param_X + POS) = *(int *)(param_X + POS) + ((int)*(short *)(param_X + VEL) >> 0xc)

We know existing horizontal pairs:
   velX=0x100 -> posX=0x114
   velZ=0x102 -> posZ=0x118

Goal: find any OTHER (VEL,POS) pairs using same >>0xC shift, excluding known ones.
Produces: primary_integrator_candidates.md
"""
from __future__ import annotations
import re,json
from pathlib import Path
from collections import defaultdict

BUNDLE_GLOB='exports/bundle_*.jsonl'

# Regex fragments capturing offsets inside (param_N + 0xXYZ)
ASSIGN_LINE=re.compile(r'\*\(int \*\)\(param_\d+ \+ 0x([0-9a-fA-F]{2,3})\)\s*=.*>>\s*0xc')
VEL_IN_EXPR=re.compile(r'\(short \*\)\(param_\d+ \+ 0x([0-9a-fA-F]{2,3})\)\)\s*>?>?\s*0xc')
# Broader: any short load feeding a shift inside an addition assigned to an int field
PAIR_LINE=re.compile(r'\*\(int \*\)\(param_\d+ \+ 0x([0-9a-fA-F]{2,3})\)\s*=\s*\*\(int \*\)\(param_\d+ \+ 0x([0-9a-fA-F]{2,3})\) \+ \(\(int\)\*(?:short|undefined2) \*\)\(param_\d+ \+ 0x([0-9a-fA-F]{2,3})\)\s*>>\s*0xc')

KNOWN={ (0x100,0x114), (0x102,0x118) } # (vel,pos)

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

def main():
    hits=[]
    for fn in iter_funcs():
        dec=fn.get('decompilation') or ''
        if '>> 0xc' not in dec:
            continue
        for m in PAIR_LINE.finditer(dec):
            pos_lhs=int(m.group(1),16)
            pos_read=int(m.group(2),16)
            vel=int(m.group(3),16)
            # ensure pos_lhs==pos_read, integrator form
            if pos_lhs!=pos_read: continue
            pair=(vel,pos_lhs)
            if pair in KNOWN: continue
            hits.append({
                'func':fn['function']['name'],
                'ea':fn['function']['ea'],
                'vel':vel,
                'pos':pos_lhs
            })
    with open('primary_integrator_candidates.md','w',encoding='utf-8') as f:
        f.write('# Primary Integrator Candidates (excluding known X/Z)\n\n')
        if not hits:
            f.write('_No additional integrator patterns found._')
        else:
            f.write('| VelOff | PosOff | Function | EA |\n|--------|--------|----------|----|\n')
            for h in hits:
                f.write(f"| 0x{h['vel']:03x} | 0x{h['pos']:03x} | {h['func']} | 0x{h['ea']:x} |\n")
    print('Wrote primary_integrator_candidates.md with',len(hits),'rows')

if __name__=='__main__':
    main()
