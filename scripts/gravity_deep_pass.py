#!/usr/bin/env python3
"""Gravity deep pass placeholder.

Currently:
  - Loads gravity_candidates.md
  - Cross-references with vertical_core_functions.md / vertical_consumer_functions.md
  - Produces prioritized list where gravity candidate also appears in vertical sets.
Output: exports/gravity_priority.md
"""
from __future__ import annotations
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'

def collect(path: Path):
    if not path.exists():
        return set()
    txt = path.read_text(encoding='utf-8', errors='ignore')
    return set(re.findall(r'FUN_[0-9a-fA-F]{8}', txt))

gravity = collect(EXPORTS / 'gravity_candidates.md')
vcore = collect(EXPORTS / 'vertical_core_functions.md')
vcons = collect(EXPORTS / 'vertical_consumer_functions.md')

priority = sorted((gravity & (vcore | vcons)))
out = EXPORTS / 'gravity_priority.md'
with out.open('w', encoding='utf-8') as fh:
    fh.write('# Gravity Priority List\n\n')
    fh.write('Intersection of gravity candidates with vertical sets (higher likelihood of true Y motion handlers).\n\n')
    for fn in priority:
        tag = 'core' if fn in vcore else 'consumer'
        fh.write(f'- {fn} ({tag})\n')
print(f'Wrote {out} ({len(priority)} prioritized functions)')
