"""
scan_param_struct_vertical_reads.py

Scan for functions that READ (vs write) the vertical struct short fields when the struct
pointer is passed as the first parameter (param_1). We look for param_1 + 0x5c/0x5e/0x60/0x62
and classify lines as read if the expression appears on the RHS or inside a comparison, not
as the LHS of a simple assignment. (Heuristic; may include noise.)

Output: exports/param_struct_vertical_reads.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'param_struct_vertical_reads.md'

OFFSETS = [0x5c,0x5e,0x60,0x62]
PTR_PATTERNS = [re.compile(rf"\*\(short \*\)\(param_1 \+ 0x{off:x}\)") for off in OFFSETS]

def is_write(line: str, pattern: str) -> bool:
    # treat as write if pattern appears before a single '=' and not part of comparison
    idx = line.find(pattern)
    if idx == -1:
        return False
    after = line[idx+len(pattern):]
    # '=' before semicolon and not '==' etc.
    m = re.search(r"=", after)
    if m:
        # ensure not comparison
        comp = re.search(r"==|!=|<=|>=", after)
        if comp and comp.start() < m.start():
            return False
        # if '=' followed by another '=' immediately => comparison
        if after.strip().startswith('=='):
            return False
        return True
    return False

def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except Exception: continue
                if 'function' in obj: yield obj

def main():
    rows = []
    for fn in iter_funcs():
        dec = fn.get('decompilation') or ''
        name = fn['function']['name']
        fea = fn['function']['ea']
        lines = dec.splitlines()
        for ln, line in enumerate(lines, start=1):
            for off, pat in zip(OFFSETS, PTR_PATTERNS):
                if pat.search(line):
                    expr = f"*(short *)(param_1 + 0x{off:x})"
                    if is_write(line, expr):
                        continue
                    rows.append({"fn":name,"ea":fea,"line":ln,"offset":off,"src":line.strip()[:240]})
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Param struct vertical field READ candidates (param_1 based)\n\n')
        if not rows:
            out.write('No param_1 vertical field reads detected.\n')
            return
        out.write('| Function | EA | Line | Offset | Source |\n')
        out.write('|----------|----|------|--------|--------|\n')
        for r in rows:
            out.write(f"| {r['fn']} | 0x{r['ea']:x} | {r['line']} | 0x{r['offset']:02x} | `{r['src'].replace('|','\\|')}` |\n")
    print('Wrote', OUT.name, 'with', len(rows), 'rows')

if __name__ == '__main__':
    main()
