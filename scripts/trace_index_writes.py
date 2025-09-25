#!/usr/bin/env python3
"""
trace_index_writes.py

Attempt to find write origins for secondary array index 0x30.
Pattern: (*(type **)(param + 0x11c))[0x30] = ...

Output: index30_writes.md
"""
from __future__ import annotations
import re,json
from pathlib import Path

BUNDLE_GLOB='exports/bundle_*.jsonl'
WRITE_PAT=re.compile(r'\(\*\([^)]*\*\)\(param_\d+ \+ 0x11c\)\)\[0x30\]\s*=')

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
        if '0x30]' not in dec:
            continue
        for line in dec.splitlines():
            if WRITE_PAT.search(line):
                rows.append((fn['function']['name'],fn['function']['ea'],line.strip()))
    with open('index30_writes.md','w',encoding='utf-8') as f:
        f.write('# Index 0x30 Write Sites\n\n')
        if not rows:
            f.write('_No explicit write patterns to index 0x30 found._')
            return
        f.write('| Function | EA | Line |\n|----------|----|------|\n')
        for name,ea,line in rows:
            esc=line.replace('|','\|')
            f.write(f"| {name} | 0x{ea:x} | `{esc}` |\n")
    print('Wrote index30_writes.md with',len(rows),'rows')

if __name__=='__main__':
    main()
