#!/usr/bin/env python3
"""Extract multi-category hub functions that involve input.

Parses mapping_coverage_report.md, finds lines in the multi-category section containing 'input'.
Output: exports/input_hubs.md
"""
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / 'exports' / 'mapping_coverage_report.md'
OUT = ROOT / 'exports' / 'input_hubs.md'

if not REPORT.exists():
    print('mapping_coverage_report.md not found; run coverage script first')
    raise SystemExit(1)

lines = REPORT.read_text(encoding='utf-8', errors='ignore').splitlines()
collect = False
targets = []
for ln in lines:
    if 'Multi-Category Function Candidates' in ln:
        collect = True
        continue
    if collect and ln.startswith('## '):
        break
    if collect and ln.startswith('- FUN_') and 'input' in ln:
        targets.append(ln[2:])

with OUT.open('w', encoding='utf-8') as fh:
    fh.write('# Input Hub Functions\n\n')
    fh.write('Extracted from multi-category orchestrator list (contain input tag).\n\n')
    for t in targets:
        fh.write(f'- {t}\n')
print(f'Wrote {OUT} ({len(targets)} functions)')
