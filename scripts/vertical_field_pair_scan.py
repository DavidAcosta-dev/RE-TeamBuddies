#!/usr/bin/env python3
"""
vertical_field_pair_scan.py

Identify functions that touch combinations of secondary struct field offsets,
highlighting likely (velY,posY) pairs. Uses results from secondary_field_offsets.md.

Currently seeds candidate set with all discovered offsets, but ranks higher when:
  - Function touches both a write-heavy and read-heavy offset (e.g., 0x40 write, 0x60 read)
  - Both appear multiple times
  - Presence of any shift (generic) lines nearby (even if not tied directly)

Output: vertical_field_pair_candidates.md
"""
from __future__ import annotations
import re,json
from pathlib import Path
from collections import defaultdict

BUNDLE_GLOB='exports/bundle_*.jsonl'
OFFSETS_CAND={0x40,0x60,0xa4,0x1e,0x22,0x2c}
PAT_OFF=re.compile(r'\+ 0x11c\) \+ 0x([0-9a-fA-F]{1,3})\b')
SHIFT_ANY=re.compile(r'>>\s*0x[0-9a-fA-F]+|>>\s*\d+')

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
    rows=[]
    for fn in iter_funcs():
        dec=fn.get('decompilation') or ''
        if '+ 0x11c)' not in dec:
            continue
        lines=dec.splitlines()
        touched=defaultdict(int)
        shifts=0
        for l in lines:
            if SHIFT_ANY.search(l):
                shifts+=1
            if '+ 0x11c)' not in l:
                continue
            for m in PAT_OFF.finditer(l):
                off=int(m.group(1),16)
                if off in OFFSETS_CAND:
                    touched[off]+=1
        if len(touched)>=2:
            # score: weight 0x40 & 0x60 synergy highest
            score=0
            if 0x40 in touched and 0x60 in touched:
                score+=20
            score+=sum(min(v,5) for v in touched.values())
            score+=min(shifts,3)
            rows.append({
                'name':fn['function']['name'],
                'ea':fn['function']['ea'],
                'touched':dict(touched),
                'shifts':shifts,
                'score':score
            })
    rows.sort(key=lambda r:r['score'], reverse=True)
    with open('vertical_field_pair_candidates.md','w',encoding='utf-8') as f:
        f.write('# Vertical Field Pair Candidates\n\n')
        if not rows:
            f.write('_No multi-field candidate functions found._')
            return
        f.write('| Rank | Function | Score | Fields | Shifts | EA |\n|------|----------|-------|--------|--------|----|\n')
        for i,r in enumerate(rows,1):
            fields=';'.join(f'0x{k:02x}:{v}' for k,v in sorted(r['touched'].items()))
            f.write(f"| {i} | {r['name']} | {r['score']} | {fields} | {r['shifts']} | 0x{r['ea']:x} |\n")
    print('Wrote vertical_field_pair_candidates.md with',len(rows),'rows')

if __name__=='__main__':
    main()
