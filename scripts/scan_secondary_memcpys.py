#!/usr/bin/env python3
"""
scan_secondary_memcpys.py

Heuristically find bulk writes into the secondary buffer (*(int*)(param+0x11c)) that could
populate index 0x30, including:
- memcpy/memmove-like calls where destination is *(...)(param+0x11c)
- for/while loops writing *(type *)(dest + k) where dest aliases *(...)(param+0x11c),
  especially ranges that include +0x60 for 16-bit elements

Output: secondary_memcpy_candidates.md
"""
from __future__ import annotations
import re,json
from pathlib import Path

BUNDLE_GLOB='exports/bundle_*.jsonl'

# Simple signatures for memcpy/memmove wrappers often seen in decomp: func_0x********(dst, src, size)
CALL_3ARGS=re.compile(r'func_0x[0-9a-f]{8}\([^,]+,\s*[^,]+,\s*[^\)]\)')

# Destination expression patterns
IDENT=r'[A-Za-z_]\w*'
DST_PARAM_11C=re.compile(rf'\(\*\([^)]*\*\)\({IDENT} \+ 0x11c\)\)')

def iter_funcs():
    for p in Path('exports').glob(BUNDLE_GLOB):
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
        lines=dec.splitlines()
        # Collect alias names for destination
        aliases=set()
        decl_alias=re.compile(rf'(\w+)\s*=\s*\*\([^)]*\*\)\({IDENT} \+ 0x11c\)\s*;')
        for l in lines:
            m=decl_alias.search(l)
            if m:
                aliases.add(m.group(1))
        # 1) memcpy-like: look for 3-arg calls where first arg is dest alias or direct *(param+0x11c)
        for l in lines:
            if '(' not in l or ')' not in l: continue
            if CALL_3ARGS.search(l):
                if DST_PARAM_11C.search(l) or any((a + ',') in l for a in aliases):
                    rows.append((fn['function']['name'],fn['function']['ea'],'memcpy-like',l.strip()))
        # 2) looped stores: detect writes to *(type *)(alias + <expr>) = ...
        store_ptr=re.compile(r'\*\([^)]*\)\(\w+ \+ (0x[0-9a-f]+|\w+)\)\s*=')
        for l in lines:
            m=store_ptr.search(l)
            if not m:
                continue
            var=m.group(1)
            if var in aliases:
                off=m.group(2)
                rows.append((fn['function']['name'],fn['function']['ea'],f'store@{off}',l.strip()))
        # 3) direct dest with offset
        direct_store=re.compile(rf'\*\([^)]*\)\(\*\([^)]*\*\)\({IDENT} \+ 0x11c\) \+ (0x[0-9a-f]+|\w+)\)\s*=')
        for l in lines:
            m=direct_store.search(l)
            if m:
                rows.append((fn['function']['name'],fn['function']['ea'],f'direct@{m.group(1)}',l.strip()))
    with open('secondary_memcpy_candidates.md','w',encoding='utf-8') as f:
        f.write('# Secondary memcpy/memset candidates affecting sec[0x30] region\n\n')
        if not rows:
            f.write('_No candidates found._')
            return
        f.write('| Function | EA | Kind | Line |\n|----------|----|------|------|\n')
        for name,ea,kind,line in rows:
            esc=line.replace('|','\\|')
            f.write(f"| {name} | 0x{ea:x} | {kind} | `{esc}` |\n")
    print('Wrote secondary_memcpy_candidates.md with',len(rows),'rows')

if __name__=='__main__':
    main()
