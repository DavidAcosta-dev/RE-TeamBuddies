#!/usr/bin/env python3
"""Extract vertical offset usage contexts for gravity-related functions.

Targets:
  - High priority callees from gravity_deep_callees.md
  - Integrators from integrator_lines.md
  - Sibling spatial callers from gravity_sibling_cluster.csv

Captures lines containing vertical offsets (+0x34,+0x38,+0x3c,+0x40) and nearby shift ops.
Outputs summary scoring: vertical_count, shift_count.

Outputs:
  - exports/gravity_vertical_field_patterns.md
  - exports/gravity_vertical_field_summary.csv
"""
from __future__ import annotations
from pathlib import Path
import json, re, csv

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
DEEP = EXPORTS / 'gravity_deep_callees.md'
INTEGRATORS = EXPORTS / 'integrator_lines.md'
SIB = EXPORTS / 'gravity_sibling_cluster.csv'
BUNDLE = EXPORTS / 'bundle_GAME.BIN.jsonl'
OUT_MD = EXPORTS / 'gravity_vertical_field_patterns.md'
OUT_CSV = EXPORTS / 'gravity_vertical_field_summary.csv'

for p in [DEEP, INTEGRATORS, SIB, BUNDLE]:
    if not p.exists():
        raise SystemExit(f'Missing required artifact: {p.name}')

vertical_offsets = ['+ 0x34','+ 0x36','+ 0x38','+ 0x3c','+ 0x3e','+ 0x40','+ 0x44']

def collect_funcs():
    funcs = set()
    # deep callees
    for ln in DEEP.read_text(encoding='utf-8').splitlines():
        if ln.startswith('|') and '|' in ln and ln.count('|') >= 6 and 'Priority' not in ln:
            parts = [p.strip() for p in ln.strip().strip('|').split('|')]
            if len(parts) >= 6 and parts[1].startswith('FUN_'):
                funcs.add(parts[1])
    # integrators
    for ln in INTEGRATORS.read_text(encoding='utf-8').splitlines():
        for token in ln.split():
            if token.startswith('FUN_'):
                funcs.add(token.strip(',);'))
    # siblings
    import csv as _csv
    with SIB.open() as fh:
        rdr = _csv.DictReader(fh)
        for row in rdr:
            funcs.add(row['function'])
    return funcs

targets = collect_funcs()

patterns = {f: [] for f in targets}
metrics = {}

with BUNDLE.open('r', encoding='utf-8', errors='ignore') as fh:
    for line in fh:
        try:
            obj = json.loads(line)
        except Exception:
            continue
        fn = obj.get('function', {}).get('name')
        if fn not in targets:
            continue
        dec = obj.get('decompilation') or ''
        lines = dec.splitlines()
        hits = []
        for i,l in enumerate(lines):
            if any(vo in l for vo in vertical_offsets):
                # capture a small window
                start = max(0, i-3)
                end = min(len(lines), i+4)
                block = '\n'.join(lines[start:end])
                hits.append(block)
        shift_count = dec.count('>> 0xc')
        vert_count = sum(dec.count(vo) for vo in vertical_offsets)
        if hits:
            patterns[fn] = hits
        metrics[fn] = {'vert_refs': vert_count, 'shifts': shift_count}

with OUT_MD.open('w', encoding='utf-8') as fh:
    fh.write('# Gravity Vertical Field Patterns\n\n')
    fh.write(f'Target functions scanned: {len(targets)}\n\n')
    for fn in sorted(targets):
        fh.write(f'## {fn}\n\n')
        m = metrics.get(fn, {'vert_refs':0,'shifts':0})
        fh.write(f'VertRefs: {m['vert_refs']}  Shifts: {m['shifts']}\n\n')
        blocks = patterns.get(fn) or []
        if not blocks:
            fh.write('_No vertical offset context blocks._\n\n')
        else:
            for b in blocks:
                fh.write(b)
                fh.write('\n---\n')

with OUT_CSV.open('w', newline='', encoding='utf-8') as fh:
    w = csv.DictWriter(fh, fieldnames=['function','vert_refs','shifts'])
    w.writeheader()
    for fn in sorted(metrics.keys()):
        row = metrics[fn]
        w.writerow({'function': fn, **row})

print(f'Wrote {OUT_MD} vertical patterns for {len(targets)} functions')
