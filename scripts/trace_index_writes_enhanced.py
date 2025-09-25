#!/usr/bin/env python3
"""
trace_index_writes_enhanced.py

Find writes to the secondary pointer array element [0x30] even when accessed via a
local alias pointer (e.g., p = *(T **)(param+0x11c); p[0x30] = ...).

Output: index30_writes_enhanced.md
"""
from __future__ import annotations
import re,json
from pathlib import Path

BUNDLE_GLOB='exports/bundle_*.jsonl'

# Capture local alias assignment: <type> *<var> = *(... **)(param_X + 0x11c)
ALIAS=re.compile(r'\*\)\s*\(param_\d+ \+ 0x11c\)\s*;?')
IDENT=r'[A-Za-z_]\w*'
DECL_ALIAS=re.compile(rf'(?:undefined\w*\s*\*\s*|ushort\s*\*\s*|short\s*\*\s*|int\s*\*\s*|uint\s*\*\s*)?(\w+)\s*=\s*\*\([^)]*\*\)\({IDENT} \+ 0x11c\)\s*;')
DECL_DBL=re.compile(rf'(\w+)\s*=\s*\(.*\*\*\)\({IDENT} \+ 0x11c\)')

# Direct write patterns without aliasing
DIRECT_IDX30 = re.compile(rf'\(\*\([^)]*\*\)\([^)]*\({IDENT} \+ 0x11c\)\)\)\[0x30\]\s*=')
DIRECT_IDX30_SIMPLE = re.compile(rf'\(\*\([^)]*\)\({IDENT} \+ 0x11c\)\)\[0x30\]\s*=')

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
        if '+ 0x11c)' not in dec or '[0x30]' not in dec:
            continue
        lines=dec.splitlines()
        aliases=set()
        for l in lines:
            m=DECL_ALIAS.search(l)
            if m:
                aliases.add(m.group(1))
        # Also consider double-pointer aliases: **pp = (T **)(param+0x11c)
        for l in lines:
            m=DECL_DBL.search(l)
            if m:
                aliases.add(m.group(1))
        # Find writes like alias[0x30] = ...
        for l in lines:
            for a in list(aliases):
                if f'{a}[0x30]' in l and '=' in l and '==' not in l:
                    rows.append((fn['function']['name'],fn['function']['ea'],l.strip()))
                # Also detect *(type *)(a + 0x60) = ...
                if '+ 0x60)' in l and '=' in l and '==' not in l:
                    # Tolerant pointer-offset write to the 0x30th element (0x30 * 2 == 0x60 for shorts)
                    if re.search(rf'\*\([^)]*\)\({a} \+ 0x60\)\s*=', l):
                        rows.append((fn['function']['name'],fn['function']['ea'],l.strip()))
        # Direct writes without aliasing
        for l in lines:
            if DIRECT_IDX30.search(l) or DIRECT_IDX30_SIMPLE.search(l):
                rows.append((fn['function']['name'],fn['function']['ea'],l.strip()))
    with open('index30_writes_enhanced.md','w',encoding='utf-8') as f:
        f.write('# Index 0x30 Write Sites (Enhanced Alias Detection)\n\n')
        if not rows:
            f.write('_No alias-based writes to index 0x30 found._')
            return
        f.write('| Function | EA | Line |\n|----------|----|------|\n')
        for name,ea,line in rows:
            esc=line.replace('|','\\|')
            f.write(f"| {name} | 0x{ea:x} | `{esc}` |\n")
    print('Wrote index30_writes_enhanced.md with',len(rows),'rows')

if __name__=='__main__':
    main()
