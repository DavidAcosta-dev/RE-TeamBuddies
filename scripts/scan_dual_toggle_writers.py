"""
scan_dual_toggle_writers.py

Search for functions that XOR flip both +0x38 and +0x3c fields (phase/index toggles)
to locate composite schedulers for the vertical subsystem.

Output: exports/vertical_dual_toggle_candidates.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_dual_toggle_candidates.md'

PAT_38 = re.compile(r"\(param_1 \+ 0x38\).*\^ 1")
PAT_3C = re.compile(r"\(param_1 \+ 0x3c\).*\^ 1")

def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except Exception: continue
                if 'function' in obj: yield obj

def main():
    cands=[]
    for fn in iter_funcs():
        dec = fn.get('decompilation') or ''
        if '+ 0x38' not in dec or '+ 0x3c' not in dec: continue
        lines=dec.splitlines()
        idxs_38=[i for i,l in enumerate(lines) if PAT_38.search(l)]
        idxs_3c=[i for i,l in enumerate(lines) if PAT_3C.search(l)]
        if not idxs_38 or not idxs_3c: continue
        # proximity heuristic: any pair within 12 lines
        near=False
        for a in idxs_38:
            if any(abs(a-b)<=12 for b in idxs_3c):
                near=True; break
        if near:
            name=fn['function']['name']; ea=fn['function']['ea']
            snippets=[]
            for i in sorted(set(idxs_38+idxs_3c)):
                snippets.append(f"L{i+1:03d}: {lines[i][:160].strip()}")
            cands.append({"fn":name,"ea":ea,"snip":snippets})
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Dual +0x38/+0x3c toggle candidates\n\n')
        if not cands:
            out.write('None found.\n'); return
        for c in cands:
            out.write(f"## {c['fn']} @ 0x{c['ea']:x}\n\n")
            out.write('``'+'`\n')
            for s in c['snip']: out.write(s+'\n')
            out.write('``'+'`\n\n')
    print('Wrote', OUT.name, 'with', len(cands), 'candidates')

if __name__ == '__main__':
    main()
