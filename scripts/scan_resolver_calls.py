#!/usr/bin/env python3
"""
scan_resolver_calls.py

Heuristic search for the unknown resolver (func_0x00095d6c):
 - Looks for calls where one argument is *(...)(param + 0x11c) + 0x40
 - Captures callee name and surrounding context lines

Output: resolver_call_sites.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

PAT_ARG_40 = re.compile(r'\(\*\(undefined\d+ \*\)\(param_\d+ \+ 0x11c\) \+ 0x40\)')
CALL_PAT = re.compile(r'(FUN_[0-9a-fA-Fx]+|func_0x[0-9a-fA-F]+)\(')

def iter_funcs():
    for p in Path('exports').glob('bundle_*.jsonl'):
        with p.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    o = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if 'function' in o:
                    yield o

def main():
    rows=[]
    for fn in iter_funcs():
        d = fn.get('decompilation') or ''
        if '+ 0x11c' not in d or '+ 0x40' not in d:
            continue
        lines = d.splitlines()
        for i,l in enumerate(lines):
            if PAT_ARG_40.search(l) and '(' in l and ')' in l and ' = ' in l or 'call' in l:
                # find callee on same line
                m = CALL_PAT.search(l)
                callee = m.group(1) if m else 'unknown'
                ctx = '\n'.join(lines[max(0,i-2):min(len(lines),i+3)])
                rows.append((fn['function']['name'], f"0x{fn['function']['ea']:x}", callee, ctx))
                break
    with open('resolver_call_sites.md','w',encoding='utf-8') as f:
        f.write('# Resolver call sites (heuristic)\n\n')
        if not rows:
            f.write('_No candidates found._\n')
        else:
            for name,ea,callee,ctx in rows:
                f.write(f"## {name} @ {ea}\ncallee: {callee}\n\n")
                f.write('`````\n')
                f.write(ctx)
                f.write('\n`````\n\n')
    print('Wrote resolver_call_sites.md with',len(rows),'candidates')

if __name__ == '__main__':
    main()
