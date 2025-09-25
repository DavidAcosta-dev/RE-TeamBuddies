#!/usr/bin/env python3
"""
array_index_usage_scan.py

Enumerate all secondary pointer array index usages: (*(type **)(param_X + 0x11c))[index]
Track read vs write (assignment LHS) and gather candidate vertical displacement index (0x30) context.

Output: secondary_array_indices.md
"""
from __future__ import annotations
import re,json
from pathlib import Path
from collections import defaultdict

BUNDLE_GLOB='exports/bundle_*.jsonl'
PAT_INDEX=re.compile(r'\(\*\(.*?\*\)\(param_\d+ \+ 0x11c\)\)\[(0x[0-9a-fA-F]+|\d+)\]')

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

def parse_idx(tok:str)->int:
    return int(tok,16) if tok.startswith('0x') else int(tok)

def main():
    stats=defaultdict(lambda:{'read':0,'write':0,'funcs':set(),'samples':[]})
    for fn in iter_funcs():
        dec=fn.get('decompilation') or ''
        if '+ 0x11c)' not in dec or '[' not in dec:
            continue
        for line in dec.splitlines():
            if '+ 0x11c)' not in line or '[' not in line:
                continue
            for m in PAT_INDEX.finditer(line):
                try:
                    idx=parse_idx(m.group(1))
                except ValueError:
                    continue
                bucket=stats[idx]
                is_write=('=' in line.split(';')[0] and '==' not in line)
                if is_write:
                    bucket['write']+=1
                else:
                    bucket['read']+=1
                bucket['funcs'].add(fn['function']['name'])
                if len(bucket['samples'])<3:
                    bucket['samples'].append(line.strip())
    with open('secondary_array_indices.md','w',encoding='utf-8') as f:
        f.write('# Secondary Array Index Usage\n\n')
        if not stats:
            f.write('_No array indices found._')
            return
        f.write('| Index | Reads | Writes | Funcs |\n|-------|-------|--------|-------|\n')
        for idx,data in sorted(stats.items(), key=lambda x:-(x[1]['read']+x[1]['write'])):
            f.write(f"| 0x{idx:x} | {data['read']} | {data['write']} | {len(data['funcs'])} |\n")
        f.write('\n## Samples\n')
        for idx,data in sorted(stats.items(), key=lambda x:-(x[1]['read']+x[1]['write'])):
            f.write(f"\n### Index 0x{idx:x}\n")
            for s in data['samples']:
                f.write(f"- `{s}`\n")
    print('Wrote secondary_array_indices.md with',len(stats),'indices')

if __name__=='__main__':
    main()
