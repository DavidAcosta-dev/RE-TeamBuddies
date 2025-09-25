#!/usr/bin/env python3
"""
scan_index30_backtrace.py

Hunt for writes to secondary[0x30] including alias/copy flows.
Strategy:
 - Find functions that read secondary[0x30]
 - Within those, collect registers/temps assigned from that read
 - Look backwards/forwards for assignments to the same lvalues pointing to [0x30]

This is heuristic, using decomp text regex windows.

Output: index30_backtrace.md
"""
from __future__ import annotations
import re,json
from pathlib import Path

READ_IDX30 = re.compile(r'\(\*\(undefined2 \*\)\(\*(?:int|undefined4) \*\)\(param_\d+ \+ 0x11c\)\)\[0x30\]')
ASSIGN_LHS = re.compile(r'^(\w+)\s*=\s*(.+);')

def iter_funcs():
    for p in Path('exports').glob('bundle_*.jsonl'):
        with p.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip()
                if not line:
                    continue
                try:
                    o=json.loads(line)
                except json.JSONDecodeError:
                    continue
                if 'function' in o:
                    yield o

def main():
    hits=[]
    for fn in iter_funcs():
        d = fn.get('decompilation') or ''
        if '[0x30]' not in d or '+ 0x11c' not in d:
            continue
        lines = d.splitlines()
        for i,l in enumerate(lines):
            if READ_IDX30.search(l):
                # capture the LHS temp if any
                m = ASSIGN_LHS.match(l.strip())
                lhs = m.group(1) if m else None
                ctx = '\n'.join(lines[max(0,i-5):min(len(lines),i+8)])
                hits.append((fn['function']['name'], f"0x{fn['function']['ea']:x}", lhs or '-', ctx))
                break
    with open('index30_backtrace.md','w',encoding='utf-8') as f:
        f.write('# index 0x30 read sites with local context\n\n')
        if not hits:
            f.write('_No read sites found._\n')
        else:
            for name,ea,lhs,ctx in hits:
                f.write(f"## {name} @ {ea} (lhs: {lhs})\n\n")
                f.write('`````\n')
                f.write(ctx)
                f.write('\n`````\n\n')
    print('Wrote index30_backtrace.md with',len(hits),'sites')

if __name__=='__main__':
    main()
