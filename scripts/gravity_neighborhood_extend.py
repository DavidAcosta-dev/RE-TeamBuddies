#!/usr/bin/env python3
"""Extend gravity neighborhood with integrator callees & metrics.

Reads:
 - integrator_lines.md (for integrator function names)
 - bundle_GAME.BIN.jsonl (function decomp)
Outputs:
 - gravity_neighborhood_extend.md (table of integrators + metrics + callees)
 - gravity_integrator_callees.csv (raw callee metrics)
Metrics per function: spatial_hits (0x100/0x102/0x114/0x118), vertical_hits (0x34/0x38/0x3c/0x40), shifts (>>0xc), callee_count.
"""
from __future__ import annotations
from pathlib import Path
import re, json, csv

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
INTEGRATOR = EXPORTS / 'integrator_lines.md'
BUNDLE = EXPORTS / 'bundle_GAME.BIN.jsonl'
OUT_MD = EXPORTS / 'gravity_neighborhood_extend.md'
OUT_CSV = EXPORTS / 'gravity_integrator_callees.csv'

if not INTEGRATOR.exists() or not BUNDLE.exists():
    raise SystemExit('Missing integrator_lines.md or bundle_GAME.BIN.jsonl')

integrators = set()
for ln in INTEGRATOR.read_text(encoding='utf-8').splitlines():
    m = re.search(r'(FUN_[0-9a-fA-F]{8})', ln)
    if m:
        integrators.add(m.group(1))

SPATIAL = ['+ 0x100','+ 0x102','+ 0x114','+ 0x118']
VERT = ['+ 0x34','+ 0x38','+ 0x3c','+ 0x40']
SHIFT = '>> 0xc'

FUNC_RE = re.compile(r'FUN_[0-9a-fA-F]{8}')

integrator_meta = {}
callee_edges = []  # list of dicts

with BUNDLE.open('r', encoding='utf-8', errors='ignore') as fh:
    for line in fh:
        try:
            obj = json.loads(line)
        except Exception:
            continue
        fn = obj.get('function', {}).get('name')
        dec = obj.get('decompilation') or ''
        if not fn:
            continue
        if fn in integrators:
            spatial_hits = sum(dec.count(s) for s in SPATIAL)
            vertical_hits = sum(dec.count(v) for v in VERT)
            shifts = dec.count(SHIFT)
            callees = set(FUNC_RE.findall(dec)) - {fn}
            integrator_meta[fn] = {
                'spatial_hits': spatial_hits,
                'vertical_hits': vertical_hits,
                'shifts': shifts,
                'callee_count': len(callees),
            }
            for c in sorted(callees):
                # gather callee metrics too (lightweight)
                callee_edges.append({'integrator': fn, 'callee': c})

# Enhance callee edges with basic metrics by re-scanning only needed callees
needed_callees = {e['callee'] for e in callee_edges}
callee_metrics = {}
if needed_callees:
    with BUNDLE.open('r', encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            fn = obj.get('function', {}).get('name')
            if fn not in needed_callees:
                continue
            dec = obj.get('decompilation') or ''
            callee_metrics[fn] = {
                'spatial_hits': sum(dec.count(s) for s in SPATIAL),
                'vertical_hits': sum(dec.count(v) for v in VERT),
                'shifts': dec.count(SHIFT),
            }

with OUT_CSV.open('w', newline='', encoding='utf-8') as fh:
    w = csv.DictWriter(fh, fieldnames=['integrator','spatial_hits','vertical_hits','shifts','callee_count'])
    w.writeheader()
    for fn,meta in sorted(integrator_meta.items()):
        w.writerow({'integrator': fn, **meta})

with OUT_MD.open('w', encoding='utf-8') as fh:
    fh.write('# Gravity Neighborhood Extend\n\n')
    fh.write(f'Integrators analyzed: {len(integrator_meta)}\n\n')
    if not integrator_meta:
        fh.write('_No integrator metadata extracted._\n')
    else:
        fh.write('| Integrator | SpatialHits | VerticalHits | Shifts | Callees |\n')
        fh.write('|------------|------------:|------------:|-------:|--------:|\n')
        for fn,meta in sorted(integrator_meta.items()):
            fh.write(f"| {fn} | {meta['spatial_hits']} | {meta['vertical_hits']} | {meta['shifts']} | {meta['callee_count']} |\n")
    if callee_edges:
        fh.write('\n## Callee Metrics (non-zero interesting ones)\n\n')
        fh.write('| Integrator | Callee | CalleeSpatial | CalleeVertical | CalleeShifts |\n')
        fh.write('|------------|--------|--------------:|--------------:|------------:|\n')
        for edge in callee_edges:
            cm = callee_metrics.get(edge['callee'], {'spatial_hits':0,'vertical_hits':0,'shifts':0})
            if cm['spatial_hits'] or cm['vertical_hits'] or cm['shifts']:
                fh.write(f"| {edge['integrator']} | {edge['callee']} | {cm['spatial_hits']} | {cm['vertical_hits']} | {cm['shifts']} |\n")
        fh.write('\n### Notes\n\nCallees with spatial+shift or vertical+shift likely contain partial integration math split from core loop.\n')

print(f'Wrote {OUT_MD} with {len(integrator_meta)} integrators; {len(callee_edges)} callee edges')
