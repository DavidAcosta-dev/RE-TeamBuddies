#!/usr/bin/env python3
"""
packed_field_scan.py

Detect potential packed 32-bit fields in secondary struct where the same 32-bit
offset is accessed via both int/word and short/halfword forms (suggesting high/low
parts might store different subfields like pos/vel).

Heuristic:
  - For each +0x11c path, record offset and access size pattern:
       *(int *)(*(int *)(base+0x11c) + 0x40)
       *(short *)(*(int *)(base+0x11c) + 0x40)
  - If both occur for same offset, mark packed candidate.
  - Also record if any AND/shift masking occurs in nearby lines.

Output: secondary_packed_candidates.md
"""
from __future__ import annotations
import re,json
from pathlib import Path
from collections import defaultdict

BUNDLE_GLOB='exports/bundle_*.jsonl'
INT_ACCESS=re.compile(r'\*\(int \*\)\(\*(?:int|undefined4) \*\)\(param_\d+ \+ 0x11c\) \+ 0x([0-9a-fA-F]{1,3})\)')
SHORT_ACCESS=re.compile(r'\*(?:short|undefined2) \*\)\(\*(?:int|undefined4) \*\)\(param_\d+ \+ 0x11c\) \+ 0x([0-9a-fA-F]{1,3})\)')
MASK_HINT=re.compile(r'&\s*0x[0-9a-fA-F]+')
SHIFT_HINT=re.compile(r'>>\s*0x[0-9a-fA-F]+|<<\s*0x[0-9a-fA-F]+')
WINDOW=4

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
    per_offset=defaultdict(lambda:{'int':0,'short':0,'mask':0,'shift':0,'funcs':set()})
    for fn in iter_funcs():
        dec=fn.get('decompilation') or ''
        if '+ 0x11c)' not in dec:
            continue
        lines=dec.splitlines()
        for i,l in enumerate(lines):
            if '+ 0x11c)' not in l:
                continue
            for m in INT_ACCESS.finditer(l):
                off=int(m.group(1),16)
                s=per_offset[off]
                s['int']+=1; s['funcs'].add(fn['function']['name'])
            for m in SHORT_ACCESS.finditer(l):
                off=int(m.group(1),16)
                s=per_offset[off]
                s['short']+=1; s['funcs'].add(fn['function']['name'])
            # Nearby mask/shift context
            if MASK_HINT.search(l):
                for m in INT_ACCESS.finditer(l):
                    per_offset[int(m.group(1),16)]['mask']+=1
                for m in SHORT_ACCESS.finditer(l):
                    per_offset[int(m.group(1),16)]['mask']+=1
            if SHIFT_HINT.search(l):
                for m in INT_ACCESS.finditer(l):
                    per_offset[int(m.group(1),16)]['shift']+=1
                for m in SHORT_ACCESS.finditer(l):
                    per_offset[int(m.group(1),16)]['shift']+=1
    with open('secondary_packed_candidates.md','w',encoding='utf-8') as f:
        f.write('# Secondary Packed Field Candidates\n\n')
        if not per_offset:
            f.write('_No accesses found._')
            return
        f.write('| Off | IntCnt | ShortCnt | MaskHints | ShiftHints | Funcs | Packed? |\n|-----|--------|----------|-----------|------------|-------|---------|\n')
        for off,data in sorted(per_offset.items() , key=lambda x:-(x[1]['int']+x[1]['short'])):
            packed = 'Y' if data['int']>0 and data['short']>0 else ''
            f.write(f"| 0x{off:02x} | {data['int']} | {data['short']} | {data['mask']} | {data['shift']} | {len(data['funcs'])} | {packed} |\n")
    print('Wrote secondary_packed_candidates.md with',len(per_offset),'offsets')

if __name__=='__main__':
    main()
