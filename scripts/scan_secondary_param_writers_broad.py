#!/usr/bin/env python3
"""
scan_secondary_param_writers_broad.py

Broader two-pass scan for callees that may receive the secondary struct pointer (*(X+0x11c))
as an argument, by simply flagging any call line that contains "+ 0x11c)" in its argument list.
Then scan those callees for direct writes to param_k + 0x60 or [0x30].

Output: secondary_param_writers_broad.md
"""
from __future__ import annotations
import re,json
from pathlib import Path
from typing import Set, List, Tuple

BUNDLE_GLOB='exports/bundle_*.jsonl'
CALL_ANY = re.compile(r'func_0x([0-9a-fA-F]{6,8})\s*\(([^)]*\+\s*0x11c[^)]*)\)')
WRITE_PARAM_PLUS_60 = re.compile(r'\*\([^)]*\)\(param_\d+\s*\+\s*0x60\)\s*=')
WRITE_PARAM_IDX_30  = re.compile(r'\(\([^)]*\*\)\s*param_\d+\)\s*\[\s*0x30\s*\]\s*=')


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


def pass1_collect_callees() -> Set[int]:
    s:set[int]=set()
    for fn in iter_functions():
        dec=fn.get('decompilation') or ''
        for m in CALL_ANY.finditer(dec):
            try:
                s.add(int(m.group(1),16))
            except ValueError:
                pass
    return s


def pass2_scan(callees:Set[int]) -> List[Tuple[str,int,str]]:
    rows=[]
    for fn in iter_functions():
        ea=int(fn['function']['ea'])
        if ea not in callees:
            continue
        dec=fn.get('decompilation') or ''
        for l in dec.splitlines():
            if WRITE_PARAM_PLUS_60.search(l) or WRITE_PARAM_IDX_30.search(l):
                rows.append((fn['function']['name'],ea,l.strip()))
    return rows


def main():
    cals=pass1_collect_callees()
    rows=pass2_scan(cals)
    with open('secondary_param_writers_broad.md','w',encoding='utf-8') as f:
        f.write('# Secondary Param Writers (broad callsite seed)\n\n')
        f.write(f'- candidate callees from pass1: {len(cals)}\n')
        if not rows:
            f.write('\n_No direct param+0x60 or [0x30] writes found in candidate callees._\n')
        else:
            f.write('\n| Callee | EA | Evidence |\n|--------|----|----------|\n')
            for name,ea,line in rows:
                esc=line.replace('|','\\|')
                f.write(f"| {name} | 0x{ea:x} | `{esc}` |\n")
    print('Wrote secondary_param_writers_broad.md with',len(rows),'rows; pass1 candidates:',len(cals))

if __name__=='__main__':
    main()
