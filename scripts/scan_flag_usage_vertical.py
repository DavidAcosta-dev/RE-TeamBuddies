"""
scan_flag_usage_vertical.py

Map usage of the gating flags at +0x24 and +0x8c in any function referencing them,
classifying read vs write patterns.

Output: exports/vertical_flag_usage.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_flag_usage.md'

WRITE_PAT = re.compile(r"\(param_1 \+ 0x(24|8c)\)\s*=")
READ_PAT = re.compile(r"\(param_1 \+ 0x(24|8c)\)")

def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except Exception: continue
                if 'function' in obj: yield obj

def main():
    rows=[]
    for fn in iter_funcs():
        dec=fn.get('decompilation') or ''
        if '+ 0x24' not in dec and '+ 0x8c' not in dec: continue
        name=fn['function']['name']; ea=fn['function']['ea']
        for ln,line in enumerate(dec.splitlines(), start=1):
            if '(param_1 + 0x24)' in line or '(param_1 + 0x8c)' in line:
                kind='write' if WRITE_PAT.search(line) else 'read'
                rows.append({"fn":name,"ea":ea,"line":ln,"kind":kind,"src":line.strip()[:240]})
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Vertical flag (+0x24 / +0x8c) usage\n\n')
        if not rows:
            out.write('No flag usages found.\n'); return
        out.write('| Function | EA | Line | Kind | Source |\n|----------|----|------|------|--------|\n')
        for r in rows:
            out.write(f"| {r['fn']} | 0x{r['ea']:x} | {r['line']} | {r['kind']} | `{r['src'].replace('|','\\|')}` |\n")
    print('Wrote', OUT.name, 'with', len(rows), 'events')

if __name__ == '__main__':
    main()
