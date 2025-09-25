"""
scan_address_literal_references.py

Search all bundle_*.jsonl exports for decompilation lines containing raw hex
addresses of the vertical writer functions (to catch indirect dispatch / tables).

Output: exports/vertical_address_refs.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_address_refs.md'

WRITER_EAS = [0x1a320,0x1a348,0x1a3b0,0x1a614,0x1abfc]
ADDR_PATTERNS = [re.compile(fr"0x{ea:x}") for ea in WRITER_EAS]

def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except Exception: continue
                if 'function' in obj:
                    yield obj

def main():
    rows = []
    for fn in iter_funcs():
        dec = fn.get('decompilation') or ''
        name = fn['function']['name']
        ea = fn['function']['ea']
        if not any(p.search(dec) for p in ADDR_PATTERNS):
            continue
        for idx,line in enumerate(dec.splitlines(), start=1):
            hits = [f"0x{WRITER_EAS[i]:x}" for i,p in enumerate(ADDR_PATTERNS) if p.search(line)]
            if hits:
                rows.append({"fn":name,"fea":ea,"line":idx,"hits":hits,"src":line.strip()[:240]})
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Vertical writer address literal references\n\n')
        if not rows:
            out.write('No address literal references found.\n')
            return
        out.write('| Function | EA | Line | Addresses | Source |\n')
        out.write('|----------|----|------|-----------|--------|\n')
        for r in rows:
            out.write(f"| {r['fn']} | 0x{r['fea']:x} | {r['line']} | {','.join(r['hits'])} | `{r['src'].replace('|','\\|')}` |\n")
    print('Wrote', OUT.name, 'with', len(rows), 'rows')

if __name__ == '__main__':
    main()
