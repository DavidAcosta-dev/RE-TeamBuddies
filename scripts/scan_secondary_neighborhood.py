#!/usr/bin/env python3
"""
scan_secondary_neighborhood.py

Enumerate secondary struct offsets accessed via *(int *)(param_X + 0x11c) dereferences.
Collect:
  - Frequency of each secondary offset
  - Counts of negative immediate writes (0xFFxx)
  - Arithmetic +/- usage lines
  - Nearby shift >> 0xC occurrences (within window) to hint at integrator
Also cluster offsets: simple clustering where offsets within <=4 bytes of a neighbor belong to same cluster.

Outputs:
  secondary_neighborhood.md (markdown summary)
  secondary_neighborhood.csv (offset,freq,negWrites,arith,shiftNear,clusterId)
"""
from __future__ import annotations
import re,json
from pathlib import Path
from collections import defaultdict

BUNDLE_GLOB='exports/bundle_*.jsonl'
SEC_OFF_PAT=re.compile(r'\*\(int \*\)\(\*\(int \*\)\(param_\d+ \+ 0x11c\) \+ 0x([0-9a-fA-F]{2,3})\)')
SEC_SHORT_PAT=re.compile(r'\*(?:short|undefined2) \*\)\(\*\(int \*\)\(param_\d+ \+ 0x11c\) \+ 0x([0-9a-fA-F]{2,3})\)')
NEG_IMM=re.compile(r'=\s*0xff[0-9a-fA-F]{2}')
ARITH=re.compile(r'[+\-]=|=\s*[^;]*[+\-]\s*(0x[0-9a-fA-F]+|\d+)')
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

def main():
    stats=defaultdict(lambda:{'freq':0,'neg':0,'arith':0,'shiftNear':0})
    for fn in iter_funcs():
        dec=fn.get('decompilation') or ''
        lines=dec.splitlines()
        if '+ 0x11c)' not in dec:
            continue
        shift_lines=[i for i,l in enumerate(lines) if SHIFT.search(l)]
        for idx,l in enumerate(lines):
            offs=[]
            for pat in (SEC_OFF_PAT,SEC_SHORT_PAT):
                for m in pat.finditer(l):
                    offs.append(int(m.group(1),16))
            if not offs: continue
            for off in offs:
                st=stats[off]
                st['freq']+=1
                if NEG_IMM.search(l): st['neg']+=1
                if ARITH.search(l): st['arith']+=1
                # shift proximity
                for s in shift_lines:
                    if abs(s-idx)<=WINDOW:
                        st['shiftNear']+=1
                        break
    # Clustering
    sorted_offs=sorted(stats.keys())
    cluster_id=0
    clusters={}
    prev=None
    for o in sorted_offs:
        if prev is None or o - prev > 4:
            cluster_id+=1
        clusters[o]=cluster_id
        prev=o
    # Write CSV
    with open('secondary_neighborhood.csv','w',encoding='utf-8') as f:
        f.write('offset,freq,negWrites,arith,shiftNear,clusterId\n')
        for o in sorted_offs:
            st=stats[o]
            f.write(f"0x{o:x},{st['freq']},{st['neg']},{st['arith']},{st['shiftNear']},{clusters[o]}\n")
    # Markdown summary
    with open('secondary_neighborhood.md','w',encoding='utf-8') as f:
        f.write('# Secondary Struct Neighborhood (via +0x11C pointer)\n\n')
        f.write('| Offset | Freq | Neg | Arith | ShiftNear | Cluster |\n|--------|------|-----|-------|-----------|---------|\n')
        for o in sorted_offs:
            st=stats[o]
            f.write(f"| 0x{o:x} | {st['freq']} | {st['neg']} | {st['arith']} | {st['shiftNear']} | {clusters[o]} |\n")
        f.write('\nCluster count: ' + str(cluster_id) + '\n')
    print('Wrote secondary_neighborhood.{md,csv}')

if __name__=='__main__':
    main()
