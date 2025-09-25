#!/usr/bin/env python3
"""
scan_block_offsets.py

Enumerate functions that access the suspected per-object block offsets observed in vertical path:
  iVar8 + 0x2c4, 0x2c8, 0x2cc  (shorts)
  iVar8 + 0x2f0, 0x2f8         (pointers/ints)
  iVar8 + 0x2e0                (control byte/word 0x10)

We look for "+ 0x2c4", "+ 0x2f0", etc and collect access types and sample lines.

Output: vertical_block_map.md
"""
from __future__ import annotations
import re,json
from pathlib import Path
from collections import defaultdict

BUNDLE_GLOB='exports/bundle_*.jsonl'
OFFS=[0x2c4,0x2c8,0x2cc,0x2e0,0x2f0,0x2f8]
PAT=re.compile(r'\+ 0x(2c4|2c8|2cc|2e0|2f0|2f8)\b', re.IGNORECASE)

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
    func_hits=[]
    for fn in iter_funcs():
        dec=fn.get('decompilation') or ''
        if not any(f"+ 0x{off:x}" in dec for off in OFFS):
            continue
        lines=[l.strip() for l in dec.splitlines() if any(f"+ 0x{off:x}" in l for off in OFFS)]
        func_hits.append({
            'name':fn['function']['name'],
            'ea':fn['function']['ea'],
            'lines':lines[:12]
        })
    with open('vertical_block_map.md','w',encoding='utf-8') as f:
        f.write('# Vertical Block Map (iVar8 + offsets)\n\n')
        if not func_hits:
            f.write('_No functions touching block offsets found._')
            return
        for h in func_hits:
            f.write(f"## {h['name']} (0x{h['ea']:x})\n\n")
            for l in h['lines']:
                esc=l.replace('|','\\|')
                f.write(f"- `{esc}`\n")
            f.write('\n')
    print('Wrote vertical_block_map.md with',len(func_hits),'functions')

if __name__=='__main__':
    main()
