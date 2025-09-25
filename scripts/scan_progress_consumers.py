"""
scan_progress_consumers.py

Find potential consumers of vertical progress at +0x5c outside the known updater
functions (FUN_0001abfc, FUN_0001a320 family). Search for '(param_1 + 0x5c)' reads
in other symbols; classify lines as read when not a direct assignment target.

Output: exports/vertical_progress_consumers.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_progress_consumers.md'

EXCLUDE = {"FUN_0001abfc","FUN_0001a320","FUN_0001a348","FUN_0001a3b0","FUN_0001a528"}

PAT = re.compile(r"\(param_1 \+ 0x5c\)")

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
        name=fn['function']['name']
        if name in EXCLUDE: continue
        dec=fn.get('decompilation') or ''
        if '0x5c' not in dec: continue
        lines=dec.splitlines()
        for ln,line in enumerate(lines, start=1):
            if PAT.search(line):
                # treat as write if pattern immediately followed by '=' (assignment)
                frag=line[line.find('(param_1 + 0x5c)'):]
                if re.search(r"\(param_1 \+ 0x5c\)\s*=", frag):
                    continue
                rows.append({"fn":name,"ea":fn['function']['ea'],"line":ln,"src":line.strip()[:240]})
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Potential vertical progress (+0x5c) consumers (excluding core writers)\n\n')
        if not rows:
            out.write('No external consumers found.\n'); return
        out.write('| Function | EA | Line | Source |\n|----------|----|------|--------|\n')
        for r in rows:
            out.write(f"| {r['fn']} | 0x{r['ea']:x} | {r['line']} | `{r['src'].replace('|','\\|')}` |\n")
    print('Wrote', OUT.name, 'with', len(rows), 'hits')

if __name__ == '__main__':
    main()
