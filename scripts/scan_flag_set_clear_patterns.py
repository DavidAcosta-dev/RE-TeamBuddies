"""
scan_flag_set_clear_patterns.py

Derive value patterns written to (param_1 + 0x24) and (param_1 + 0x8c) to
understand semantics (e.g., set to 1, cleared to 0, toggled, copied from other fields).

Output: exports/vertical_flag_set_clear_patterns.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_flag_set_clear_patterns.md'

WRITE_LINE = re.compile(r"\(param_1 \+ 0x(24|8c)\)\s*=")
VALUE_CAPTURE = re.compile(r"\(param_1 \+ 0x(24|8c)\)\s*=\s*([^;]+);")

def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except Exception: continue
                if 'function' in obj: yield obj

def classify_value(expr: str) -> str:
    e = expr.strip()
    if e in ('0','0x0'): return 'clear_0'
    if e in ('1','0x1'): return 'set_1'
    if '^ 1' in e: return 'toggle'
    if 'param_1 + ' in e: return 'copy_from_struct'
    if e.startswith('*(undefined4 *') or e.startswith('*(int *'): return 'indirect_copy'
    return 'other'

def main():
    rows=[]
    for fn in iter_funcs():
        dec=fn.get('decompilation') or ''
        if '+ 0x24' not in dec and '+ 0x8c' not in dec: continue
        name=fn['function']['name']; ea=fn['function']['ea']
        for ln,line in enumerate(dec.splitlines(), start=1):
            if WRITE_LINE.search(line):
                m = VALUE_CAPTURE.search(line)
                if not m: continue
                off = m.group(1)
                val = m.group(2)
                cls = classify_value(val)
                rows.append({"fn":name,"ea":ea,"line":ln,"offset":"0x"+off,"class":cls,"value":val.strip()[:200]})
    # Aggregate stats
    stats={}
    for r in rows:
        stats.setdefault((r['offset'],r['class']),0)
        stats[(r['offset'],r['class'])]+=1
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Flag set/clear pattern analysis (+0x24 / +0x8c)\n\n')
        if not rows:
            out.write('No flag writes detected.\n'); return
        out.write('## Summary Counts\n\n')
        for (off,cls),cnt in sorted(stats.items()):
            out.write(f'- {off} {cls}: {cnt}\n')
        out.write('\n## Detailed Writes\n\n')
        out.write('| Function | EA | Line | Offset | Class | ValueExpr |\n|----------|----|------|--------|-------|-----------|\n')
        for r in rows:
            out.write(f"| {r['fn']} | 0x{r['ea']:x} | {r['line']} | {r['offset']} | {r['class']} | `{r['value'].replace('|','\\|')}` |\n")
    print('Wrote', OUT.name, 'with', len(rows), 'writes')

if __name__ == '__main__':
    main()
