#!/usr/bin/env python3
"""Rank gravity composed chains by composite heuristic score.

Inputs:
  - exports/gravity_neighborhood_callers.csv (caller metrics)
  - exports/gravity_integrator_callees.csv (integrator metrics)
  - (optional) exports/gravity_composed_integrators.md (restrict to composed chains only)

Score model (tunable via env weights):
  SCORE = W_CALLER_SPATIAL * caller_spatial
        + W_CALLER_SHIFTS  * caller_shifts
        + W_CALLER_VERTICAL* caller_vertical
        + W_INTEG_SPATIAL  * integ_spatial
        + W_INTEG_VERTICAL * integ_vertical
        + W_INTEG_SHIFTS   * integ_shifts

Defaults: caller_spatial=1.2, caller_shifts=1.5, caller_vertical=0.6,
          integ_spatial=0.8, integ_vertical=1.0, integ_shifts=1.3

Output: exports/gravity_chain_rank.md
"""
from __future__ import annotations
from pathlib import Path
import csv, os

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
CALLERS = EXPORTS / 'gravity_neighborhood_callers.csv'
INTEGRATORS = EXPORTS / 'gravity_integrator_callees.csv'
COMPOSED = EXPORTS / 'gravity_composed_integrators.md'
OUT = EXPORTS / 'gravity_chain_rank.md'

if not CALLERS.exists() or not INTEGRATORS.exists():
    raise SystemExit('Missing required CSVs for ranking.')

def w(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default

W_CALLER_SPATIAL = w('W_CALLER_SPATIAL', 1.2)
W_CALLER_SHIFTS = w('W_CALLER_SHIFTS', 1.5)
W_CALLER_VERTICAL = w('W_CALLER_VERTICAL', 0.6)
W_INTEG_SPATIAL = w('W_INTEG_SPATIAL', 0.8)
W_INTEG_VERTICAL = w('W_INTEG_VERTICAL', 1.0)
W_INTEG_SHIFTS = w('W_INTEG_SHIFTS', 1.3)

integrator_meta = {}
with INTEGRATORS.open() as fh:
    rdr = csv.DictReader(fh)
    for row in rdr:
        integrator_meta[row['integrator']] = {
            'spatial': int(row['spatial_hits']),
            'vertical': int(row['vertical_hits']),
            'shifts': int(row['shifts']),
        }

# Optional filter: if composed file exists, only rank chains present there
restrict_pairs = set()
if COMPOSED.exists():
    lines = COMPOSED.read_text(encoding='utf-8').splitlines()
    for ln in lines:
        if ln.startswith('| FUN_'):
            parts = [p.strip() for p in ln.strip('|').split('|')]
            if len(parts) >= 2:
                caller = parts[0]
                integrator = parts[1]
                restrict_pairs.add((caller, integrator))

chains = []
with CALLERS.open() as fh:
    rdr = csv.DictReader(fh)
    for row in rdr:
        caller = row['caller']
        integ = row['integrator']
        if restrict_pairs and (caller, integ) not in restrict_pairs:
            continue
        c_spatial = int(row['spatial_hits'])
        c_vert = int(row['vert_hits'])
        c_shifts = int(row['shifts'])
        imeta = integrator_meta.get(integ, {'spatial':0,'vertical':0,'shifts':0})
        score = (W_CALLER_SPATIAL * c_spatial +
                 W_CALLER_SHIFTS * c_shifts +
                 W_CALLER_VERTICAL * c_vert +
                 W_INTEG_SPATIAL * imeta['spatial'] +
                 W_INTEG_VERTICAL * imeta['vertical'] +
                 W_INTEG_SHIFTS * imeta['shifts'])
        chains.append({
            'caller': caller,
            'integrator': integ,
            'caller_spatial': c_spatial,
            'caller_vertical': c_vert,
            'caller_shifts': c_shifts,
            'integ_spatial': imeta['spatial'],
            'integ_vertical': imeta['vertical'],
            'integ_shifts': imeta['shifts'],
            'score': score,
        })

chains.sort(key=lambda r: r['score'], reverse=True)

with OUT.open('w', encoding='utf-8') as fh:
    fh.write('# Gravity Chain Ranking\n\n')
    fh.write(f'Weights: caller_spatial={W_CALLER_SPATIAL}, caller_shifts={W_CALLER_SHIFTS}, caller_vertical={W_CALLER_VERTICAL}, integrator_spatial={W_INTEG_SPATIAL}, integrator_vertical={W_INTEG_VERTICAL}, integrator_shifts={W_INTEG_SHIFTS}\n\n')
    if not chains:
        fh.write('_No chains to rank._\n')
    else:
        fh.write('| Score | Caller | Integrator | C_Spatial | C_Vert | C_Shifts | I_Spatial | I_Vert | I_Shifts |\n')
        fh.write('|------:|--------|------------|---------:|-------:|---------:|---------:|-------:|--------:|\n')
        for ch in chains:
            fh.write(f"| {ch['score']:.2f} | {ch['caller']} | {ch['integrator']} | {ch['caller_spatial']} | {ch['caller_vertical']} | {ch['caller_shifts']} | {ch['integ_spatial']} | {ch['integ_vertical']} | {ch['integ_shifts']} |\n")
    fh.write('\nHigher scores emphasize split logic where caller supplies spatial refs and integrator supplies shifts/vertical accumulation.\n')

print(f'Wrote {OUT} ranking {len(chains)} chains')
