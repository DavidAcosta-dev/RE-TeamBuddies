#!/usr/bin/env python3
"""
scan_gravity_helpers.py

Hypothesis: gravity may be applied via a small helper function that subtracts a
constant from a velocity field (possibly via pointer indirection) and returns.

Heuristic:
 1. Identify small functions (decomp < ~40 lines) containing a single subtraction
    of a small constant (<= 0x1200) or add of a negative constant.
 2. Count how many callers occur in functions that also dereference (param + 0x11C).
 3. Score by (#gravity-like sub patterns) * (#qualified callers).

Outputs:
  gravity_helper_candidates.md
"""
from __future__ import annotations
import json,re
from pathlib import Path
from collections import defaultdict

BUNDLE_GLOB='exports/bundle_*.jsonl'
SUB_PAT=re.compile(r'-\s*(0x[0-9a-fA-F]+|\d+)')
ADD_NEG_PAT=re.compile(r'\+\s*0xff[0-9a-fA-F]{2}')
PTR11C_PAT=re.compile(r'\+ 0x11c\)')

def load_funcs():
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
                    obj['_bundle']=p
                    yield obj

def parse_int(tok:str)->int:
    return int(tok,16) if tok.startswith('0x') else int(tok)

def main():
    funcs=list(load_funcs())
    meta={}
    for fn in funcs:
        dec=fn.get('decompilation') or ''
        lines=[l for l in dec.splitlines() if l.strip()]
        if len(lines)>40: 
            continue
        subs=[]
        for l in lines:
            for m in SUB_PAT.finditer(l):
                val=parse_int(m.group(1))
                if val<=0x1200:
                    subs.append((l,val))
            if ADD_NEG_PAT.search(l):
                # treat negative add as subtraction of small magnitude (approx)
                subs.append((l,0x100))
        if not subs:
            continue
        meta[fn['function']['name']]={'ea':fn['function']['ea'],'subs':subs,'callers':0}
    # Build naive caller counts by scanning others for function names
    for fn in funcs:
        dec=fn.get('decompilation') or ''
        if not PTR11C_PAT.search(dec):
            continue
        for name in meta.keys():
            if name in dec:
                meta[name]['callers']+=1
    # Score and output
    lines_out=['# Gravity Helper Candidates','']
    scored=[]
    for name,info in meta.items():
        score=len(info['subs'])*(info['callers'] or 0)
        if score==0: continue
        scored.append((score,name,info))
    scored.sort(reverse=True)
    for score,name,info in scored[:100]:
        lines_out.append(f"## {name} (ea=0x{info['ea']:x}) score={score} callers={info['callers']} subPatterns={len(info['subs'])}")
        for l,v in info['subs'][:6]:
            lines_out.append(f"- {l.strip()}")
        lines_out.append('')
    if not scored:
        lines_out.append('_No helper candidates found matching heuristic._')
    with open('gravity_helper_candidates.md','w',encoding='utf-8') as f:
        f.write('\n'.join(lines_out))
    print('Wrote gravity_helper_candidates.md with',len(scored),'scored candidate(s)')

if __name__=='__main__':
    main()
