#!/usr/bin/env python3
"""
scan_secondary_writes.py

Find explicit writes to secondary struct fields (+0x11c pointer base):
  - *(...)(param + 0x11c) = ...  (pointer rebinding)
  - *(...)(*(int *)(param + 0x11c) + 0x60) = ...
  - *(...)(*(int *)(param + 0x11c) + 0x40) = ...

Output: secondary_write_sites.md
"""
from __future__ import annotations
import re,json
from pathlib import Path

BUNDLE_GLOB='exports/bundle_*.jsonl'
ASSIGN_BASE = re.compile(r'\*\([^)]*\)\(param_\d+ \+ 0x11c\)\s*=')
# capture writes like: *(short *)(*(int *)(param + 0x11c) + 0x60) = ...
ASSIGN_OFF_60 = re.compile(r'\*\((?:short|ushort|undefined2|int|uint|undefined4) \*\)\(\*(?:int|undefined4) \*\)\(param_\d+ \+ 0x11c\) \+ 0x60\)\s*=')
ASSIGN_OFF_40 = re.compile(r'\*\((?:short|ushort|undefined2|int|uint|undefined4) \*\)\(\*(?:int|undefined4) \*\)\(param_\d+ \+ 0x11c\) \+ 0x40\)\s*=')
ASSIGN_IDX30 = re.compile(r'\(\*\(undefined\d+ \*\)\(\*(?:int|undefined4) \*\)\(param_\d+ \+ 0x11c\)\)\[0x30\]\s*=')

def iter_funcs():
    for p in Path('exports').glob('bundle_*.jsonl'):
        with p.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip()
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
        for l in dec.splitlines():
            if ASSIGN_BASE.search(l) or ASSIGN_OFF_60.search(l) or ASSIGN_OFF_40.search(l) or ASSIGN_IDX30.search(l):
                rows.append((fn['function']['name'],fn['function']['ea'],l.strip()))
    with open('secondary_write_sites.md','w',encoding='utf-8') as f:
        f.write('# Secondary Write Sites\n\n')
        if not rows:
            f.write('_No secondary writes found._')
            return
        f.write('| Function | EA | Line |\n|----------|----|------|\n')
        for name,ea,line in rows:
            esc=line.replace('|','\\|')
            f.write(f"| {name} | 0x{ea:x} | `{esc}` |\n")
    print('Wrote secondary_write_sites.md with',len(rows),'rows')

if __name__=='__main__':
    main()
