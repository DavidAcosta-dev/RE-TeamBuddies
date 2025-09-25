#!/usr/bin/env python3
"""Seed gravity neighborhood from known integrator functions.

Steps:
 1. Parse integrator_lines.md to collect function names (lines containing 'FUN_').
 2. Scan bundle_GAME.BIN.jsonl for decompilations referencing those names (call sites -> callers).
 3. For each integrator function, collect in-degree (callers count) and size if available.
 4. For each caller, count occurrences of vertical-ish offsets (0x34,0x38,0x3c,0x40) and spatial offsets (0x100,0x102,0x114,0x118) to highlight bridging functions.

Outputs:
  - exports/gravity_neighborhood.md (summary tables)
  - exports/gravity_neighborhood_callers.csv (raw caller metrics)
"""
from __future__ import annotations
from pathlib import Path
import re, json, csv

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
INTEGRATOR = EXPORTS / 'integrator_lines.md'
BUNDLE = EXPORTS / 'bundle_GAME.BIN.jsonl'
OUT_MD = EXPORTS / 'gravity_neighborhood.md'
OUT_CSV = EXPORTS / 'gravity_neighborhood_callers.csv'

if not INTEGRATOR.exists() or not BUNDLE.exists():
    raise SystemExit('Required files missing (integrator_lines.md or bundle_GAME.BIN.jsonl)')

integrators = set()
for ln in INTEGRATOR.read_text(encoding='utf-8').splitlines():
    m = re.search(r'(FUN_[0-9a-fA-F]{8})', ln)
    if m:
        integrators.add(m.group(1))

# Map function -> decomp to allow offset counting quickly
decomp_cache = {}
callers = {}  # integrator -> set(caller)
pattern = re.compile(r'FUN_[0-9a-fA-F]{8}')

with BUNDLE.open('r', encoding='utf-8', errors='ignore') as fh:
    for line in fh:
        try:
            obj = json.loads(line)
        except Exception:
            continue
        func = obj.get('function', {}).get('name')
        decomp = obj.get('decompilation') or ''
        if not func or not decomp:
            continue
        decomp_cache[func] = decomp
        # For every integrator referenced, record link
        for integ in integrators:
            # quick substring check; ensure calling not just definition
            if integ in decomp and func != integ:
                callers.setdefault(integ, set()).add(func)

# Analyze caller metrics
VERT_OFFS = ['+ 0x34','+ 0x38','+ 0x3c','+ 0x40']
SPATIAL = ['+ 0x100','+ 0x102','+ 0x114','+ 0x118']

caller_rows = []
for integ, cset in callers.items():
    for c in cset:
        text = decomp_cache.get(c,'')
        vert_hits = sum(text.count(v) for v in VERT_OFFS)
        spatial_hits = sum(text.count(s) for s in SPATIAL)
        shifts = text.count('>> 0xc')
        caller_rows.append({
            'integrator': integ,
            'caller': c,
            'vert_hits': vert_hits,
            'spatial_hits': spatial_hits,
            'shifts': shifts,
        })

caller_rows.sort(key=lambda r: (r['integrator'], -(r['spatial_hits']+r['vert_hits'])))

with OUT_CSV.open('w', newline='', encoding='utf-8') as fh:
    w = csv.DictWriter(fh, fieldnames=['integrator','caller','vert_hits','spatial_hits','shifts'])
    w.writeheader()
    for row in caller_rows:
        w.writerow(row)

with OUT_MD.open('w', encoding='utf-8') as fh:
    fh.write('# Gravity Neighborhood Seed\n\n')
    fh.write(f'Integrator functions identified: {len(integrators)}\n')
    fh.write(f'Integrators with at least one caller: {len(callers)}\n\n')
    if not caller_rows:
        fh.write('_No caller relationships detected referencing integrators._\n')
    else:
        fh.write('| Integrator | Caller | VertHits | SpatialHits | Shifts |\n')
        fh.write('|------------|--------|---------:|------------:|-------:|\n')
        for row in caller_rows:
            fh.write(f"| {row['integrator']} | {row['caller']} | {row['vert_hits']} | {row['spatial_hits']} | {row['shifts']} |\n")
        fh.write('\n## Prioritization\n\n')
        fh.write('High-priority candidates are callers with spatial_hits>0 and shifts>0; these may bridge higher-level logic to integrator core.\n')

print(f'Wrote {OUT_MD} and {OUT_CSV} with {len(caller_rows)} caller edges')
