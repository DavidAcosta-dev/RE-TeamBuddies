"""
extract_vertical_writers.py

Collect full decompilation for suspected vertical writer functions and emit a markdown dossier.
Targets: FUN_0001a320, FUN_0001a614, FUN_0001abfc, FUN_0001a3b0, FUN_0001a348

Output: exports/vertical_writer_functions.md
"""
from __future__ import annotations
import json
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_writer_functions.md'
TARGETS = {
    # Writer / initializer cluster
    "FUN_0001a320","FUN_0001a614","FUN_0001abfc","FUN_0001a3b0","FUN_0001a348","FUN_0001a528","FUN_0001a558",
    # Suspected secondary pointer assignment sites (for linkage context)
    "FUN_0002a8c8","FUN_00001c84"
}

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
    found = {}
    for fn in iter_funcs():
        name = fn['function']['name']
        if name in TARGETS and name not in found:
            found[name] = fn
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Vertical Writer Function Dossier\n\n')
        for name in sorted(found.keys()):
            ea = found[name]['function']['ea']
            dec = found[name].get('decompilation','')
            out.write(f'## {name} @ 0x{ea:x}\n\n')
            out.write('```c\n')
            out.write(dec.strip())
            out.write('\n```\n\n')
    print('Wrote', OUT.name, 'with', len(found), 'functions')

if __name__ == '__main__':
    main()
