#!/usr/bin/env python3
"""
vertical_function_focus.py

Extract and summarize decompilation snippets for target functions involved in
suspected vertical pathway plus the helper callee func_0x00095d6c.

Outputs: vertical_function_focus.md
"""
from __future__ import annotations
import json
from pathlib import Path

TARGETS={
    'FUN_0001cff0',
    'FUN_0001d100',
    'FUN_0001f558',
    'FUN_0001f5ec',
    'func_0x00095d6c', # probable callee returning vertical delta / resource
}

BUNDLE_GLOB='exports/bundle_*.jsonl'
MAX_LINES=2200

def iter_funcs():
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
    collected={}
    for fn in iter_funcs():
        name=fn['function']['name']
        dec=fn.get('decompilation') or ''
        lower=dec.lower()
        if name in TARGETS:
            collected.setdefault(name, dec[:MAX_LINES])
        # also collect definition of func_0x00095d6c if appears as name variant e.g. FUN_... alias
        if 'func_0x00095d6c' in lower and 'func_0x00095d6c' in TARGETS:
            # ensure we have the full function containing the symbol if its own name not equal
            if name not in collected:
                collected[name]=dec[:MAX_LINES]
    with open('vertical_function_focus.md','w',encoding='utf-8') as f:
        f.write('# Vertical Function Focus\n\n')
        if not collected:
            f.write('_No target functions found._')
            return
        for k,v in collected.items():
            f.write(f'## {k}\n\n')
            # Light trimming: show first 120 lines
            lines=v.splitlines()[:120]
            f.write('``'+'`\n')
            for l in lines:
                f.write(l+'\n')
            f.write('``'+'`\n\n')
    print('Wrote vertical_function_focus.md with',len(collected),'functions')

if __name__=='__main__':
    main()
