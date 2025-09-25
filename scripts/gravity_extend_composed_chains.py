#!/usr/bin/env python3
"""Extend composed gravity integrator chains using sibling callers.

Combines:
 - Existing caller edges (gravity_neighborhood_callers.csv)
 - Sibling candidates (gravity_sibling_cluster.csv)
 - Integrator list (integrator_lines.md)
Scans sibling function decompilations for calls to integrators and builds new caller->integrator edges
with metrics (spatial/vertical/shift) like the seed script.

Outputs:
  - exports/gravity_composed_integrators_extended.md (all chains)
  - exports/gravity_composed_integrators_extended.csv
"""
from __future__ import annotations
from pathlib import Path
import csv, json

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
BUNDLE = EXPORTS / 'bundle_GAME.BIN.jsonl'
CALLERS_CSV = EXPORTS / 'gravity_neighborhood_callers.csv'
SIB_CSV = EXPORTS / 'gravity_sibling_cluster.csv'
INTEGRATOR_LIST = EXPORTS / 'integrator_lines.md'
OUT_MD = EXPORTS / 'gravity_composed_integrators_extended.md'
OUT_CSV = EXPORTS / 'gravity_composed_integrators_extended.csv'

required = [BUNDLE, CALLERS_CSV, SIB_CSV, INTEGRATOR_LIST]
for p in required:
    if not p.exists():
        raise SystemExit(f'Missing required file: {p.name}')

# Load integrators
integrators = set()
for ln in INTEGRATOR_LIST.read_text(encoding='utf-8').splitlines():
    if 'FUN_' in ln:
        for token in ln.split():
            if token.startswith('FUN_'):
                integrators.add(token.strip(',);'))

# Existing caller edges
existing = []
with CALLERS_CSV.open() as fh:
    rdr = csv.DictReader(fh)
    for row in rdr:
        existing.append(row)
existing_pairs = {(r['caller'], r['integrator']) for r in existing}

# Sibling candidates
siblings = []
with SIB_CSV.open() as fh:
    rdr = csv.DictReader(fh)
    for row in rdr:
        siblings.append(row['function'])

# Build decomp cache for siblings only to keep memory modest
decomp = {}
with BUNDLE.open('r', encoding='utf-8', errors='ignore') as fh:
    for line in fh:
        try:
            obj = json.loads(line)
        except Exception:
            continue
        fn = obj.get('function', {}).get('name')
        if fn in siblings:
            decomp[fn] = obj.get('decompilation') or ''
        # also capture integrators (for metrics if needed)
        if fn in integrators and fn not in decomp:
            decomp[fn] = obj.get('decompilation') or ''

VERT = ['+ 0x34','+ 0x38','+ 0x3c','+ 0x40']
SPATIAL = ['+ 0x100','+ 0x102','+ 0x114','+ 0x118']

new_edges = []
for sib in siblings:
    body = decomp.get(sib, '')
    if not body:
        continue
    for integ in integrators:
        if integ in body and (sib, integ) not in existing_pairs and sib != integ:
            vert_hits = sum(body.count(v) for v in VERT)
            spatial_hits = sum(body.count(s) for s in SPATIAL)
            shifts = body.count('>> 0xc')
            new_edges.append({'integrator': integ, 'caller': sib, 'vert_hits': vert_hits, 'spatial_hits': spatial_hits, 'shifts': shifts})

all_edges = existing + new_edges
all_edges.sort(key=lambda r: (r['integrator'], r['caller']))

with OUT_CSV.open('w', newline='', encoding='utf-8') as fh:
    w = csv.DictWriter(fh, fieldnames=['integrator','caller','vert_hits','spatial_hits','shifts','is_new'])
    w.writeheader()
    for e in all_edges:
        e2 = {**e, 'is_new': int((e['caller'], e['integrator']) in {(n['caller'], n['integrator']) for n in new_edges})}
        w.writerow(e2)

with OUT_MD.open('w', encoding='utf-8') as fh:
    fh.write('# Gravity Composed Integrator Chains (Extended)\n\n')
    fh.write(f'Existing edges: {len(existing)}  Newly discovered: {len(new_edges)}  Total: {len(all_edges)}\n\n')
    if not all_edges:
        fh.write('_No chains._\n')
    else:
        fh.write('| New | Caller | Integrator | CallVert | CallSpatial | CallShifts |\n')
        fh.write('|----:|--------|------------|---------:|------------:|-----------:|\n')
        for e in all_edges:
            is_new = 1 if e in new_edges else 0
            fh.write(f"| {is_new} | {e['caller']} | {e['integrator']} | {e['vert_hits']} | {e['spatial_hits']} | {e['shifts']} |\n")
    if new_edges:
        fh.write('\nNew edges may indicate additional gravity update orchestrators; prioritize those with both spatial+shifts.\n')

print(f'Wrote {OUT_MD} with {len(all_edges)} total edges ({len(new_edges)} new)')
