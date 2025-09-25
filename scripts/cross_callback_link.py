#!/usr/bin/env python3
"""
cross_callback_link.py

Find call graph relationships among functions that touch key secondary offsets (0x40 write, 0x60 read).
We approximate call graph edges by scanning decompilation text for literal callee names.

Outputs: vertical_cross_links.md
"""
from __future__ import annotations
import re,json
from pathlib import Path
from collections import defaultdict

BUNDLE_GLOB='exports/bundle_*.jsonl'
OFF_WRITE=0x40
OFF_READ=0x60
PAT_OFF_WRITE=re.compile(r'\+ 0x11c\) \+ 0x40\b')
PAT_OFF_READ=re.compile(r'\+ 0x11c\) \+ 0x60\b')
CALL_PATTERN=re.compile(r'FUN_[0-9a-fA-F]{5,}')

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
    funcs_map={}
    for fn in iter_funcs():
        dec=fn.get('decompilation') or ''
        touchesW = bool(PAT_OFF_WRITE.search(dec))
        touchesR = bool(PAT_OFF_READ.search(dec))
        if not (touchesW or touchesR):
            continue
        calls=set(CALL_PATTERN.findall(dec))
        entry=funcs_map.get(fn['function']['name'])
        if entry:
            entry['w'] = entry['w'] or touchesW
            entry['r'] = entry['r'] or touchesR
            entry['calls'].update(calls)
        else:
            funcs_map[fn['function']['name']]={
                'name':fn['function']['name'],
                'ea':fn['function']['ea'],
                'w':touchesW,
                'r':touchesR,
                'calls':set(calls)
            }
    funcs=list(funcs_map.values())
    name_to = {f['name']:f for f in funcs}
    edges=[]
    for f in funcs:
        for c in f['calls']:
            if c in name_to:
                edges.append((f['name'],c))
    with open('vertical_cross_links.md','w',encoding='utf-8') as f:
        f.write('# Vertical Cross Links (Offsets 0x40 / 0x60)\n\n')
        if not funcs:
            f.write('_No functions touching 0x40/0x60 found._')
            return
        f.write('## Functions\n\n')
        f.write('| Function | EA | Writes40 | Reads60 | OutCallsIntoSet |\n|----------|----|----------|---------|-----------------|\n')
        for fn in funcs:
            out_edges=sum(1 for e in edges if e[0]==fn['name'])
            f.write(f"| {fn['name']} | 0x{fn['ea']:x} | {int(fn['w'])} | {int(fn['r'])} | {out_edges} |\n")
        f.write('\n## Edges (caller -> callee within 40/60 set)\n\n')
        if not edges:
            f.write('_No internal edges._')
        else:
            for a,b in edges:
                f.write(f"- {a} -> {b}\n")
    print('Wrote vertical_cross_links.md with',len(funcs),'func nodes')

if __name__=='__main__':
    main()
