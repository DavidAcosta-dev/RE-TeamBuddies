#!/usr/bin/env python3
"""
secondary_field_offsets.py

Scan for constant field offsets accessed via the secondary struct pointer:
   *(short *)(*(int *)(param_X + 0x11c) + 0x60)

Heuristics collected:
  - read count (occurrences not considered writes)
  - write count (line has '=' assigning into that deref pattern)
  - shiftLocal: same line has >>0xC
  - shiftNear: within +/- 6 lines of a >>0xC

Output: secondary_field_offsets.md
"""
from __future__ import annotations
import re,json
from pathlib import Path
from collections import defaultdict

BUNDLE_GLOB='exports/bundle_*.jsonl'

PAT_OFF=re.compile(r'\+ 0x11c\) \+ 0x([0-9a-fA-F]{1,3})\b')
SHIFT=re.compile(r'>>\s*0xc',re.IGNORECASE)
WINDOW=6

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
    stats=defaultdict(lambda:{'read':0,'write':0,'shiftLocal':0,'shiftNear':0,'funcs':set()})
    for fn in iter_funcs():
        dec=fn.get('decompilation') or ''
        if '+ 0x11c)' not in dec:
            continue
        lines=dec.splitlines()
        shift_lines=[i for i,l in enumerate(lines) if SHIFT.search(l)]
        for i,l in enumerate(lines):
            if '+ 0x11c)' not in l:
                continue
            for m in PAT_OFF.finditer(l):
                off=int(m.group(1),16)
                st=stats[off]
                is_write=('=' in l.split(';')[0] and '==' not in l and '!=' not in l and '<=' not in l and '>=' not in l)
                if is_write:
                    st['write']+=1
                else:
                    st['read']+=1
                if SHIFT.search(l):
                    st['shiftLocal']+=1
                else:
                    for s in shift_lines:
                        if abs(s-i)<=WINDOW:
                            st['shiftNear']+=1
                            break
                st['funcs'].add(fn['function']['name'])
    # Capture context lines for top accessed offsets (by total count)
    top_context={}
    # Re-iterate to gather up to 3 representative lines per top offset later
    top_offsets=[o for o,_ in sorted(((o,st['read']+st['write']) for o,st in stats.items()), key=lambda x:-x[1])[:4]]
    if top_offsets:
        for fn in iter_funcs():
            dec=fn.get('decompilation') or ''
            if '+ 0x11c)' not in dec: continue
            lines=dec.splitlines()
            for l in lines:
                if '+ 0x11c)' not in l: continue
                m=PAT_OFF.search(l)
                if not m: continue
                off=int(m.group(1),16)
                if off not in top_offsets: continue
                bucket=top_context.setdefault(off,[])
                if len(bucket)<3:
                    bucket.append(l.strip())

    with open('secondary_field_offsets.md','w',encoding='utf-8') as f:
        f.write('# Secondary Field Offsets via +0x11C Pointer\n\n')
        if not stats:
            f.write('_No field offsets detected._')
            return
        f.write('| Off | Read | Write | ShiftLocal | ShiftNear | Funcs |\n|-----|------|-------|------------|-----------|-------|\n')
        ordered=sorted(stats.items(), key=lambda x:-(x[1]['read']+x[1]['write']))
        for off,st in ordered:
            f.write(f"| 0x{off:02x} | {st['read']} | {st['write']} | {st['shiftLocal']} | {st['shiftNear']} | {len(st['funcs'])} |\n")
        f.write('\n## Context Samples\n')
        if not top_context:
            f.write('\n_No context collected._')
        else:
            for off in ordered:
                o=off[0]
                if o not in top_context: continue
                f.write(f"\n### Offset 0x{o:02x}\n")
                for line in top_context[o]:
                    f.write(f"- `{line}`\n")
    print('Wrote secondary_field_offsets.md with',len(stats),'offsets')

if __name__=='__main__':
    main()
