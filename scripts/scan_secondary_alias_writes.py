#!/usr/bin/env python3
"""
scan_secondary_alias_writes.py

Alias-aware sweep for writes to the secondary struct's index 0x30 (offset +0x60 as short),
including via local aliases bound to *(...)(param_X + 0x11c).

Finds:
 - alias declarations like: <T>* a = *(<T> **)(param_k + 0x11c);
 - writes: a[0x30] = ..., *(<T>*)(a + 0x60) = ...
 - direct writes without alias: (*( <T>* )(*(int *)(param_k + 0x11c) + 0x60)) = ...
                                 ((*( <T>* ) (param_k + 0x11c)))[0x30] = ...

Outputs: secondary_alias_writes.md
"""
from __future__ import annotations
import re, json
from pathlib import Path

BUNDLE_GLOB='exports/bundle_*.jsonl'
IDENT=r'[A-Za-z_]\w*'

# alias from secondary pointer deref
DECL_ALIAS = re.compile(rf'(?:undefined\w*\s*\*\s*|ushort\s*\*\s*|short\s*\*\s*|int\s*\*\s*|uint\s*\*\s*)({IDENT})\s*=\s*\*\([^)]*\*\)\({IDENT}\s*\+\s*0x11c\)\s*;')
# double-pointer variant
DECL_DBL   = re.compile(rf'({IDENT})\s*=\s*\([^)]*\*\*\)\({IDENT}\s*\+\s*0x11c\)\s*;')

# direct writes via alias
ALIAS_IDX30 = lambda a: re.compile(rf'\b{re.escape(a)}\s*\[\s*0x30\s*\]\s*=')
ALIAS_OFF60 = lambda a: re.compile(rf'\*\s*\([^)]*\)\s*\(\s*{re.escape(a)}\s*\+\s*0x60\s*\)\s*=')

# direct writes via param deref
DIRECT_OFF60 = re.compile(r'\*\([^)]*\)\(\*\([^)]*\)\({IDENT}\s*\+\s*0x11c\)\s*\+\s*0x60\)\s*=' )
DIRECT_IDX30 = re.compile(r'\(\*\([^)]*\)\(\*\([^)]*\)\({IDENT}\s*\+\s*0x11c\)\)\)\s*\[\s*0x30\s*\]\s*=')


def iter_functions():
    for p in Path('.').glob(BUNDLE_GLOB):
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
    for fn in iter_functions():
        dec=fn.get('decompilation') or ''
        if '+ 0x11c)' not in dec:
            continue
        lines=dec.splitlines()
        aliases=set()
        for l in lines:
            m=DECL_ALIAS.search(l) or DECL_DBL.search(l)
            if m:
                aliases.add(m.group(1))
        # scan writes via aliases
        for l in lines:
            for a in list(aliases):
                if ALIAS_IDX30(a).search(l) or ALIAS_OFF60(a).search(l):
                    rows.append((fn['function']['name'],fn['function']['ea'],l.strip()))
        # scan direct forms
        for l in lines:
            if DIRECT_OFF60.search(l) or DIRECT_IDX30.search(l):
                rows.append((fn['function']['name'],fn['function']['ea'],l.strip()))
    with open('secondary_alias_writes.md','w',encoding='utf-8') as f:
        f.write('# Secondary Alias Writes (index 0x30 / +0x60)\n\n')
        if not rows:
            f.write('_No alias or direct writes to secondary[0x30] found._')
            return
        f.write('| Function | EA | Line |\n|----------|----|------|\n')
        for name,ea,line in rows:
            esc=line.replace('|','\\|')
            f.write(f"| {name} | 0x{int(ea):x} | `{esc}` |\n")
    print('Wrote secondary_alias_writes.md with',len(rows),'rows')

if __name__=='__main__':
    main()
