"""
scan_param_struct_writers.py

Scan functions for writes to parameter-based structures at offsets relevant to vertical state:
  - *(short *)(param_X + 0x60) = ...
  - param_X[0x30] = ...
  - Cluster offsets 0x5c..0x64

Output: exports/param_struct_writers.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'param_struct_writers.md'

PARAM_NAMES = [f'param_{i}' for i in range(1,6)]  # heuristic range

def iter_functions():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except Exception: continue
                if 'function' in obj:
                    yield obj

def build_patterns(p):
    p60 = re.compile(rf"\*\([^)]*short[^)]*\)\(\s*(?:\(int\)\s*)?{p} \+ 0x60\)\s*=")
    pIdx = re.compile(rf"\b{p}\s*\[0x30\]\s*=")
    cluster = [re.compile(rf"{p} \+ 0x{off:x}\)\s*=") for off in range(0x5c,0x65)]
    return p60,pIdx,cluster

def scan_fn(obj):
    dec = obj.get('decompilation') or ''
    lines = dec.splitlines()
    hits = []
    for p in PARAM_NAMES:
        if p not in dec:
            continue
        p60,pIdx,cluster = build_patterns(p)
        for idx,l in enumerate(lines, start=1):
            if p60.search(l):
                hits.append((p,idx,'write_+0x60',l.strip()))
            if pIdx.search(l):
                hits.append((p,idx,'write_[0x30]',l.strip()))
            if any(c.search(l) for c in cluster):
                hits.append((p,idx,'cluster_near_0x60',l.strip()))
    return hits

def main():
    rows=[]
    for fn in iter_functions():
        h = scan_fn(fn)
        if h:
            name=fn['function']['name']; ea=fn['function']['ea']
            for (p,ln,kind,line) in h:
                rows.append((name,ea,p,ln,kind,line))
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Parameter-based struct writer scan\n\n')
        if not rows:
            out.write('No parameter-based writes to +0x60 / [0x30] detected.\n')
            return
        out.write('| Function | EA | Param | Line | Kind | Source |\n')
        out.write('|----------|----|-------|------|------|--------|\n')
        for name,ea,p,ln,kind,line in rows:
            out.write(f"| {name} | 0x{ea:x} | {p} | {ln} | {kind} | `{line.replace('|','\\|')}` |\n")
    print('Wrote', OUT.name, 'with', len(rows), 'rows')

if __name__ == '__main__':
    main()
