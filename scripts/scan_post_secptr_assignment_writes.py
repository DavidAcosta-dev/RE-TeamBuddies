"""
scan_post_secptr_assignment_writes.py

Strategy: In any function that assigns *(int *)(X + 0x11c) = <ptrVar> (or uint), capture <ptrVar>
and then scan subsequent lines ONLY for potential writes to:
   - *(short *)(<ptrVar> + 0x60)
   - <ptrVar>[0x30]
   - *(short *)((int)<ptrVar> + 0x60)
   - Clustered offsets in 0x5c..0x64 (struct packing bursts)

Output: exports/post_secptr_assignment_writes.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'post_secptr_assignment_writes.md'

ASSIGN_RE = re.compile(r"\*\((?:int|uint) \*\)\([^)]*\+ 0x11c\)\s*=\s*([A-Za-z_]\w*)\s*;")
WRITE_OFF60_TMPL = lambda v: re.compile(rf"\*\([^)]*short[^)]*\)\(\s*(?:\(int\)\s*)?{re.escape(v)}\s*\+\s*0x60\s*\)\s*=")
WRITE_IDX30_TMPL = lambda v: re.compile(rf"\b{re.escape(v)}\s*\[0x30\]\s*=")
CLUSTER_TMPLS = lambda v: [re.compile(rf"{re.escape(v)}\s*\+\s*0x{off:x}\)\s*=") for off in range(0x5c,0x65)]

def iter_functions():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except Exception: continue
                if 'function' in obj: yield obj

def scan_fn(obj):
    dec = obj.get('decompilation') or ''
    if '+ 0x11c' not in dec:
        return []
    lines = dec.splitlines()
    ptr_vars = []  # (var, first_line_index)
    events = []
    for idx, line in enumerate(lines):
        m = ASSIGN_RE.search(line)
        if m:
            ptr_vars.append((m.group(1), idx))
    if not ptr_vars:
        return []
    for var, start_idx in ptr_vars:
        w60 = WRITE_OFF60_TMPL(var)
        w30 = WRITE_IDX30_TMPL(var)
        clusters = CLUSTER_TMPLS(var)
        for i in range(start_idx+1, len(lines)):
            l = lines[i]
            if w60.search(l):
                events.append((var, i+1, 'write_+0x60', l.strip()))
            if w30.search(l):
                events.append((var, i+1, 'write_[0x30]', l.strip()))
            if any(c.search(l) for c in clusters):
                events.append((var, i+1, 'cluster_near_0x60', l.strip()))
    return events

def main():
    rows = []
    for fn in iter_functions():
        ev = scan_fn(fn)
        if ev:
            name = fn['function']['name']; ea = fn['function']['ea']
            for (var, line_no, kind, text) in ev:
                rows.append((name, ea, var, line_no, kind, text))
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Post secondary-pointer-assignment writer scan\n\n')
        if not rows:
            out.write('No post-assignment writes to +0x60 / [0x30] detected.\n')
            return
        out.write('| Function | EA | PtrVar | Line | Kind | Source |\n')
        out.write('|----------|----|--------|------|------|--------|\n')
        for name, ea, var, line_no, kind, text in rows:
            out.write(f"| {name} | 0x{ea:x} | {var} | {line_no} | {kind} | `{text.replace('|','\\|')}` |\n")
    print('Wrote', OUT.name, 'with', len(rows), 'rows')

if __name__ == '__main__':
    main()
