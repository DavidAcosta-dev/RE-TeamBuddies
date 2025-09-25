"""
scan_vertical_pointer_tables.py

Heuristic detection of probable function pointer tables referencing >=2 vertical writer
functions (by name or address literal) inside a single function decompilation block.

Output: exports/vertical_pointer_tables.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_pointer_tables.md'

WRITER_NAMES = ["FUN_0001a320","FUN_0001a348","FUN_0001a3b0","FUN_0001a614","FUN_0001abfc"]
WRITER_EAS = [0x1a320,0x1a348,0x1a3b0,0x1a614,0x1abfc]
NAME_PATS = [re.compile(rf"\b{name}\b") for name in WRITER_NAMES]
ADDR_PATS = [re.compile(fr"0x{ea:x}") for ea in WRITER_EAS]

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
    candidates = []
    for fn in iter_funcs():
        dec = fn.get('decompilation') or ''
        name = fn['function']['name']
        fea = fn['function']['ea']
        name_hits = [WRITER_NAMES[i] for i,p in enumerate(NAME_PATS) if p.search(dec)]
        addr_hits = [f"0x{WRITER_EAS[i]:x}" for i,p in enumerate(ADDR_PATS) if p.search(dec)]
        total_unique = set(name_hits + addr_hits)
        if len(total_unique) >= 2:
            # Extract candidate table-like lines: those containing two or more commas and writer hits
            table_lines = []
            for line in dec.splitlines():
                if line.count(',') >= 2 and any(h in line for h in total_unique):
                    table_lines.append(line.strip()[:240])
            candidates.append({"fn":name,"ea":fea,"refs":sorted(total_unique),"lines":table_lines})
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Vertical writer pointer table candidates\n\n')
        if not candidates:
            out.write('No multi-writer reference blocks found.\n')
            return
        for c in candidates:
            out.write(f"## {c['fn']} @ 0x{c['ea']:x}\n\n")
            out.write(f"References: {', '.join(c['refs'])}\n\n")
            if c['lines']:
                out.write('``'+'`\n')
                for l in c['lines']:
                    out.write(l+'\n')
                out.write('``'+'`\n\n')
    print('Wrote', OUT.name, 'with', len(candidates), 'candidates')

if __name__ == '__main__':
    main()
