"""
scan_returning_struct_inits.py

Heuristic: Identify functions that build a struct in a local pointer (e.g., pVar, iVar6)
by performing multiple field writes, then return that pointer. We flag those
that touch offsets relevant to the vertical secondary slot (0x60 for +0x60 short,
and index 0x30 for 16-bit elements) or nearby cluster 0x5c..0x64.

Output: exports/returning_struct_inits.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'returning_struct_inits.md'

RET_PTR_RE = re.compile(r"return\s+([A-Za-z_]\w*)\s*;")
LOCAL_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*func_0x[0-9a-f]{8}\(.*\);")
FIELD_WRITE_BASE = r"\*\([^)]*\)\(\s*(?:\(int\)\s*)?{var}\s*\+\s*(0x[0-9a-fA-F]+)\s*\)\s*="
ARRAY_WRITE_BASE = r"{var}\s*\[(0x[0-9a-fA-F]+)\]\s*="

TARGET_OFFSETS = {0x60}
NEAR_CLUSTER = list(range(0x5c,0x65))  # inclusive range around 0x60

def iter_functions():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except Exception: continue
                if 'function' in obj:
                    yield obj

def scan_fn(obj):
    dec = obj.get('decompilation') or ''
    if 'return' not in dec:
        return None
    lines = dec.splitlines()
    ret_vars = set()
    for l in lines:
        m = RET_PTR_RE.search(l)
        if m:
            ret_vars.add(m.group(1))
    if not ret_vars:
        return None
    candidates = []
    for rv in ret_vars:
        # Collect writes referencing rv
        writes = []
        field_re = re.compile(FIELD_WRITE_BASE.format(var=rv))
        arr_re = re.compile(ARRAY_WRITE_BASE.format(var=rv))
        for idx,l in enumerate(lines, start=1):
            fm = field_re.search(l)
            if fm:
                off = int(fm.group(1),16)
                writes.append((idx,'field',off,l.strip()))
            am = arr_re.search(l)
            if am:
                off_idx = int(am.group(1),16)
                # index 0x30 -> byte offset 0x60 if element size is 2
                writes.append((idx,'array_index',off_idx,l.strip()))
        if not writes:
            continue
        # Determine if any interesting offsets present
        interesting = []
        for w in writes:
            kind_off = w[2]
            if w[1] == 'array_index' and kind_off == 0x30:
                interesting.append(w)
            elif w[1] == 'field' and (kind_off in TARGET_OFFSETS or kind_off in NEAR_CLUSTER):
                interesting.append(w)
        if interesting:
            candidates.append((rv,writes,interesting))
    if not candidates:
        return None
    return candidates

def main():
    rows = []
    for fn in iter_functions():
        res = scan_fn(fn)
        if res:
            name = fn['function']['name']
            ea = fn['function']['ea']
            rows.append((name,ea,res))
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Returning struct initializers touching vertical-related offsets\n\n')
        if not rows:
            out.write('No returning struct initializers with +0x60 / index0x30 activity found.\n')
            return
        for name,ea,data in rows:
            out.write(f'## {name} @ 0x{ea:x}\n\n')
            for (rv, all_writes, interesting) in data:
                out.write(f'- Return var: {rv}\n')
                out.write('  - Interesting writes:\n')
                for iw in interesting:
                    out.write(f'    - L{iw[0]} {iw[1]} off=0x{iw[2]:x}: `{iw[3]}`\n')
                out.write('  - Total writes count: ' + str(len(all_writes)) + '\n\n')
    print('Wrote', OUT.name)

if __name__ == '__main__':
    main()
