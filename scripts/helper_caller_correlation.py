#!/usr/bin/env python3
"""
helper_caller_correlation.py

Correlate previously identified small helper candidates (gravity helpers) with
functions that perform secondary (+0x11C) array-index accesses and >>0xC shifts.

Heuristic:
  1. Load helper candidate names from gravity_helper_candidates.md (table form)
     expecting a list like: | Rank | Name | Score | ...
  2. For each function in bundle jsonl exports, detect:
        - calls to helper candidates
        - presence of +0x11c pointer array index patterns
        - presence of >>0xC shifts
  3. Produce correlation score: helpers_called * (array_refs + shift_refs)
  4. Output markdown report helper_caller_correlation.md
"""
from __future__ import annotations
import re,json
from pathlib import Path
from collections import defaultdict

BUNDLE_GLOB='exports/bundle_*.jsonl'
HELPER_MD='gravity_helper_candidates.md'

CALL=re.compile(r'FUN_[0-9a-fA-F]{7,}')
ARR_IDX=re.compile(r'\(\*\([^)]*\*\)\(param_\d+ \+ 0x11c\)\)\[(0x[0-9a-fA-F]+|\d+)\]')
SHIFT=re.compile(r'>>\s*0xc',re.IGNORECASE)

def load_helpers():
    helpers=set()
    p=Path(HELPER_MD)
    if not p.exists():
        return helpers
    for line in p.read_text(encoding='utf-8',errors='ignore').splitlines():
        # Headings like: ## FUN_0001c8cc (...)
        if line.startswith('## '):
            seg=line[3:].strip().split()
            if seg:
                name=seg[0]
                if name.startswith('FUN_') or name.startswith('thunk_FUN_'):
                    helpers.add(name)
    return helpers

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
    helpers=load_helpers()
    if not helpers:
        print('No helpers loaded; aborting.')
        return
    seen=set()
    rows=[]
    for fn in iter_funcs():
        name=fn['function']['name']
        dec=fn.get('decompilation') or ''
        calls=[c for c in CALL.findall(dec) if c in helpers]
        if not calls: # skip fast if no helper calls
            continue
        key=name
        if key in seen:
            continue
        seen.add(key)
        arr_refs=len(ARR_IDX.findall(dec))
        shifts=len(SHIFT.findall(dec))
        uniq_helpers=len(set(calls))
        score=uniq_helpers*2 + arr_refs*3 + shifts*5
        rows.append({
            'name':name,
            'helpers_called':sorted(set(calls)),
            'arr_refs':arr_refs,
            'shifts':shifts,
            'score':score
        })
    rows.sort(key=lambda r:r['score'], reverse=True)
    with open('helper_caller_correlation.md','w',encoding='utf-8') as f:
        f.write('# Helper Caller Correlation\n\n')
        if not rows:
            f.write('_No caller functions involving helpers & secondary patterns found._')
            return
        f.write('| Rank | Function | Score | Helpers | ArrayIdxRefs | Shift>>0xC |\n|------|----------|-------|---------|--------------|-----------|\n')
        for i,r in enumerate(rows,1):
            f.write(f"| {i} | {r['name']} | {r['score']} | {','.join(r['helpers_called'])} | {r['arr_refs']} | {r['shifts']} |\n")
    print('Wrote helper_caller_correlation.md with',len(rows),'rows')

if __name__=='__main__':
    main()
