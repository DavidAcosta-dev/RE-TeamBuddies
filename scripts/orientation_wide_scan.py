#!/usr/bin/env python3
"""Wide orientation scan including additional sources.

Sources scanned: snippets_*.md, trig_table_locator.md, direction_table_dump.txt, mask_fff_functions.md
Collects: functions with &0xFFF, functions referencing 0x26800 / 0x27800.
Outputs differential list vs existing orientation_candidates.md.
"""
from __future__ import annotations
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
OUT = EXPORTS / 'orientation_wide_scan.md'

FUNC_RE = re.compile(r'FUN_[0-9a-fA-F]{8}')
mask_funcs = set()
sin_funcs = set()
cos_funcs = set()

def scan_file(p: Path):
    try:
        lines = p.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return
    current = None
    for ln in lines:
        m = FUNC_RE.search(ln)
        if m:
            current = m.group(0)
        if not current:
            continue
        if '& 0xFFF' in ln or '&0xFFF' in ln:
            mask_funcs.add(current)
        if '0x26800' in ln:
            sin_funcs.add(current)
        if '0x27800' in ln:
            cos_funcs.add(current)

for f in EXPORTS.glob('snippets_*.md'):
    scan_file(f)

extra_sources = [ROOT/'trig_table_locator.md', ROOT/'direction_table_dump.txt', ROOT/'mask_fff_functions.md']
for p in extra_sources:
    if p.exists():
        scan_file(p)

union = mask_funcs | sin_funcs | cos_funcs
with OUT.open('w', encoding='utf-8') as fh:
    fh.write('# Wide Orientation Scan\n\n')
    fh.write(f'Total unique candidate functions: {len(union)}\n\n')
    fh.write('| Function | Mask | SinRef | CosRef |\n|----------|-----:|-------:|-------:|\n')
    for fn in sorted(union):
        fh.write(f'| {fn} | {int(fn in mask_funcs)} | {int(fn in sin_funcs)} | {int(fn in cos_funcs)} |\n')
print(f'Wrote {OUT} with {len(union)} functions')
