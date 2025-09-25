"""
scan_ptr_assign_callers.py

Locate functions that call the secondary pointer assignment function FUN_0002a8c8,
capturing context lines around the call to identify orchestrators that seed +0x11c.

Output: exports/vertical_ptr_assign_callers.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_ptr_assign_callers.md'

CALL_PAT = re.compile(r"FUN_0002a8c8\s*\(")

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
        if 'FUN_0002a8c8' not in dec: continue
        name=fn['function']['name']; ea=fn['function']['ea']
        lines=dec.splitlines()
        for i,l in enumerate(lines):
            if CALL_PAT.search(l):
                snippet='\n'.join(lines[max(0,i-3):i+4])
                rows.append({"fn":name,"ea":ea,"line":i+1,"snippet":snippet[:800]})
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Callers of FUN_0002a8c8 (secondary pointer assignment)\n\n')
        if not rows:
            out.write('No callers found.\n'); return
        out.write('| Function | EA | Line | Snippet |\n|----------|----|------|---------|\n')
        for r in rows:
            out.write(f"| {r['fn']} | 0x{r['ea']:x} | {r['line']} | `{r['snippet'].replace('|','\\|').replace('`','\'')}` |\n")
    print('Wrote', OUT.name, 'with', len(rows), 'callers')

if __name__ == '__main__':
    main()
