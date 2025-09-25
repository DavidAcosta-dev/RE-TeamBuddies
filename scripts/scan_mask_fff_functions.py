#!/usr/bin/env python3
"""
scan_mask_fff_functions.py

List functions using '& 0xfff' (orientation hashing and possibly neighbors) to help locate trig table base.
Outputs mask_fff_functions.md with size, EA, and a snippet of each occurrence line.
"""
from __future__ import annotations
import json,re
from pathlib import Path

MASK_RE = re.compile(r"&\s*0xfff", re.IGNORECASE)
BUNDLE_GLOB = 'exports/bundle_*.jsonl'


def main():
    rows=[]
    for p in Path('.').glob(BUNDLE_GLOB):
        with p.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip();
                if not line: continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                fn = obj.get('function') or {}
                name = fn.get('name')
                decomp = obj.get('decompilation') or ''
                if '& 0xfff' not in decomp.lower():
                    continue
                hits=[]
                for l in decomp.splitlines():
                    if MASK_RE.search(l):
                        hits.append(l.strip())
                rows.append((name, fn.get('ea'), fn.get('size'), hits[:6]))
    rows.sort(key=lambda r: (-len(r[3]), r[2] or 0, r[0]))
    with open('mask_fff_functions.md','w',encoding='utf-8') as f:
        f.write('# Functions with & 0xFFF Mask Usage\n\n')
        for name,ea,size,hits in rows:
            f.write(f"## {name} (ea=0x{ea:x}, size={size})\n")
            for h in hits:
                f.write(f"  {h}\n")
            f.write('\n')
    print('Wrote mask_fff_functions.md with', len(rows), 'functions')

if __name__ == '__main__':
    main()
