"""
fingerprint_vertical_scaled_product.py

Identify all functions containing the characteristic velocity*scale pattern:
  (int)*(short *)(X + 0x60) * (int)*(short *)(X + 0x62)
Allow loose spacing and either param_1 or any register/temp leading expression.

Output: exports/vertical_scaled_product_fingerprint.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_scaled_product_fingerprint.md'

PAT = re.compile(r"\(int\)\*\(short \*\)\([^)]*\+ 0x60\)\s*\*\s*\(int\)\*\(short \*\)\([^)]*\+ 0x62\)")

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
        if '0x60' not in dec or '0x62' not in dec:
            continue
        if PAT.search(dec):
            name = fn['function']['name']; ea = fn['function']['ea']
            for ln, line in enumerate(dec.splitlines(), start=1):
                if PAT.search(line):
                    rows.append({"fn":name,"ea":ea,"line":ln,"src":line.strip()[:240]})
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Functions with velocity*scale vertical fingerprint\n\n')
        if not rows:
            out.write('No matches.\n'); return
        out.write('| Function | EA | Line | Source |\n|----------|----|------|--------|\n')
        seen=set()
        for r in rows:
            key=(r['fn'],r['line'])
            if key in seen: continue
            seen.add(key)
            out.write(f"| {r['fn']} | 0x{r['ea']:x} | {r['line']} | `{r['src'].replace('|','\\|')}` |\n")
    print('Wrote', OUT.name, 'with', len(rows), 'raw hits')

if __name__ == '__main__':
    main()
