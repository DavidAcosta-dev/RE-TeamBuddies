#!/usr/bin/env python3
"""Compose integrator caller + callee metrics to find split gravity/integration chains.

Uses outputs from:
 - gravity_neighborhood_callers.csv (caller->integrator)
 - gravity_neighborhood_extend.md / gravity_integrator_callees.csv (integrator metrics + callees)

Heuristic:
 - Caller has spatial_hits >=2 (from earlier CSV) [we only had spatial_hits in that file; if missing shifts we'll treat shifts=0]
 - Integrator (or one of its callees) has shifts>0 OR vertical_hits>0
 - Report combined chain.

Output: exports/gravity_composed_integrators.md
"""
from __future__ import annotations
from pathlib import Path
import csv

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
CALLERS_CSV = EXPORTS / 'gravity_neighborhood_callers.csv'
INTEGRATORS_CSV = EXPORTS / 'gravity_integrator_callees.csv'
OUT = EXPORTS / 'gravity_composed_integrators.md'

if not CALLERS_CSV.exists():
    raise SystemExit('Missing gravity_neighborhood_callers.csv')

integrator_meta = {}
if INTEGRATORS_CSV.exists():
    with INTEGRATORS_CSV.open() as fh:
        rdr = csv.DictReader(fh)
        for row in rdr:
            integrator_meta[row['integrator']] = {
                'spatial_hits': int(row['spatial_hits']),
                'vertical_hits': int(row['vertical_hits']),
                'shifts': int(row['shifts'])
            }

chains = []
with CALLERS_CSV.open() as fh:
    rdr = csv.DictReader(fh)
    for row in rdr:
        integ = row['integrator']
        caller = row['caller']
        spatial = int(row['spatial_hits'])
        shifts = int(row['shifts'])
        vhits = int(row['vert_hits'])
        imeta = integrator_meta.get(integ, {'spatial_hits':0,'vertical_hits':0,'shifts':0})
        interesting = spatial >= 2 and (imeta['shifts'] > 0 or imeta['vertical_hits'] > 0 or shifts > 0 or vhits > 0)
        if interesting:
            chains.append({
                'caller': caller,
                'integrator': integ,
                'caller_spatial': spatial,
                'caller_vertical': vhits,
                'caller_shifts': shifts,
                'integrator_spatial': imeta['spatial_hits'],
                'integrator_vertical': imeta['vertical_hits'],
                'integrator_shifts': imeta['shifts'],
            })

with OUT.open('w', encoding='utf-8') as fh:
    fh.write('# Gravity Composed Integrator Chains\n\n')
    if not chains:
        fh.write('_No composed integrator chains under heuristic._\n')
    else:
        fh.write('| Caller | Integrator | CallSpatial | CallVert | CallShifts | IntegSpatial | IntegVert | IntegShifts |\n')
        fh.write('|--------|------------|-----------:|--------:|----------:|------------:|----------:|-----------:|\n')
        for ch in chains:
            fh.write(f"| {ch['caller']} | {ch['integrator']} | {ch['caller_spatial']} | {ch['caller_vertical']} | {ch['caller_shifts']} | {ch['integrator_spatial']} | {ch['integrator_vertical']} | {ch['integrator_shifts']} |\n")
        fh.write('\nHeuristic: caller has >=2 spatial refs; integration math may be split between chain members.\n')

print(f'Wrote {OUT} with {len(chains)} candidate composed chains')
