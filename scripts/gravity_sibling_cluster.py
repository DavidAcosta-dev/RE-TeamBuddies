#!/usr/bin/env python3
"""Identify gravity sibling callers sharing struct offset patterns with known caller.

Seeds from existing composed chain caller(s) in gravity_composed_integrators.md then scans
the bundle for other functions matching a signature: occurrences of spatial offset quartet
(+ 0x100/+ 0x102/+ 0x114/+ 0x118) OR at least two of those plus a >> 0xc shift.

Outputs:
  - exports/gravity_sibling_cluster.md (table of candidate siblings)
  - exports/gravity_sibling_cluster.csv
"""
from __future__ import annotations
from pathlib import Path
import re, json, csv

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
COMPOSED = EXPORTS / 'gravity_composed_integrators.md'
BUNDLE = EXPORTS / 'bundle_GAME.BIN.jsonl'
OUT_MD = EXPORTS / 'gravity_sibling_cluster.md'
OUT_CSV = EXPORTS / 'gravity_sibling_cluster.csv'

if not COMPOSED.exists() or not BUNDLE.exists():
    raise SystemExit('Required composed chains or bundle missing.')

seed_callers = set()
for ln in COMPOSED.read_text(encoding='utf-8').splitlines():
    if ln.startswith('| FUN_'):
        parts = [p.strip() for p in ln.strip('|').split('|')]
        if len(parts) >= 2:
            seed_callers.add(parts[0])

SPATIAL = ['+ 0x100','+ 0x102','+ 0x114','+ 0x118']

rows = []
with BUNDLE.open('r', encoding='utf-8', errors='ignore') as fh:
    for line in fh:
        try:
            obj = json.loads(line)
        except Exception:
            continue
        fn = obj.get('function', {}).get('name')
        dec = obj.get('decompilation') or ''
        if not fn or not dec:
            continue
        # Count spatial offsets
        spatial_hits = {s: dec.count(s) for s in SPATIAL}
        total_spatial = sum(spatial_hits.values())
        shifts = dec.count('>> 0xc')
        if total_spatial >= 4 or (total_spatial >= 2 and shifts > 0):
            rows.append({
                'function': fn,
                'total_spatial': total_spatial,
                'distinct_spatial': sum(1 for v in spatial_hits.values() if v),
                'shifts': shifts,
                'seed_overlap': int(fn in seed_callers),
            })

# Filter out already-seed if desire more candidates but keep them for ranking context
rows.sort(key=lambda r: ( -r['seed_overlap'], -r['distinct_spatial'], -r['shifts'], -r['total_spatial'], r['function']))

with OUT_CSV.open('w', newline='', encoding='utf-8') as fh:
    import csv
    w = csv.DictWriter(fh, fieldnames=['function','seed_overlap','distinct_spatial','total_spatial','shifts'])
    w.writeheader()
    for r in rows:
        w.writerow(r)

with OUT_MD.open('w', encoding='utf-8') as fh:
    fh.write('# Gravity Sibling Cluster\n\n')
    fh.write(f'Seed callers: {", ".join(sorted(seed_callers)) or "(none)"}\n\n')
    fh.write('| Function | Seed | DistinctSpatial | TotalSpatial | Shifts |\n')
    fh.write('|----------|-----:|---------------:|------------:|-------:|\n')
    for r in rows[:200]:  # cap display
        fh.write(f"| {r['function']} | {r['seed_overlap']} | {r['distinct_spatial']} | {r['total_spatial']} | {r['shifts']} |\n")
    fh.write('\nHeuristic: Siblings express similar spatial update signature; prioritize those with shifts and multiple distinct offsets.\n')

print(f'Wrote {OUT_MD} with {len(rows)} candidate siblings (showing up to 200)')
