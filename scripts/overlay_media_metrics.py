#!/usr/bin/env python3
"""Derive media metrics (sectors, approximate seconds) for XA audio and core containers.

Reads overlay_hashes.json. For XA files: sectors = size / 2352 (approx), seconds = sectors / 75 (CD audio frames per second).
Outputs: exports/overlay_media_metrics.md
"""
from __future__ import annotations
from pathlib import Path
import json, math

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
HASHES = EXPORTS / 'overlay_hashes.json'
OUT = EXPORTS / 'overlay_media_metrics.md'

if not HASHES.exists():
    print('overlay_hashes.json missing; run hash_overlays.py first')
    raise SystemExit(1)

data = json.loads(HASHES.read_text())
rows = []
for e in data:
    if e.get('class') == 'audio_xa':
        size = e['size']
        sectors = size / 2352.0
        seconds = sectors / 75.0
        rows.append((e['file'], size, sectors, seconds))

rows.sort()
with OUT.open('w', encoding='utf-8') as fh:
    fh.write('# Overlay Media Metrics (XA Audio)\n\n')
    fh.write('| File | Size (bytes) | Sectors (~2352) | Seconds (~75/sec) |\n')
    fh.write('|------|-------------:|---------------:|------------------:|\n')
    for name,size,sectors,seconds in rows:
        fh.write(f'| {name} | {size} | {sectors:.1f} | {seconds/60:.2f} min ({seconds:.1f} s) |\n')
print(f'Wrote {OUT} with {len(rows)} XA entries')
