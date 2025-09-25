#!/usr/bin/env python3
"""Enrich input hub skeletons with detected pad bit constants and referenced crate/pickup functions.

Heuristics:
 - Look for hex constants 0x10,0x20,0x40,0x80,0x100 in snippet lines associated with hub function.
 - Collect any function names in those lines that belong to crate or pickup_drop categories (from function_category_index.json).
Append sections if not already filled.
"""
from __future__ import annotations
from pathlib import Path
import json,re

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
HUB_DIR = EXPORTS / 'input_hubs'
INDEX = EXPORTS / 'inventory' / 'function_category_index.json'

if not HUB_DIR.exists() or not INDEX.exists():
    print('Prerequisites missing (input hub dir or category index).')
    raise SystemExit(1)

cat_index = json.loads(INDEX.read_text())

PAD_CONSTS = ['0x10','0x20','0x40','0x80','0x100']
FUNC_RE = re.compile(r'FUN_[0-9a-fA-F]{8}')

# Build reverse category sets
crate_funcs = {f for f,data in cat_index.items() if 'crate' in data['categories']}
pickup_funcs = {f for f,data in cat_index.items() if 'pickup_drop' in data['categories']}

# Preload snippet lines by function for quick lookups
func_lines = {}
for snip in EXPORTS.glob('snippets_*.md'):
    lines = snip.read_text(encoding='utf-8', errors='ignore').splitlines()
    current = None
    buf = []
    for ln in lines:
        m = FUNC_RE.search(ln)
        if m:
            if current and buf:
                func_lines.setdefault(current, []).extend(buf)
            current = m.group(0)
            buf = []
        if current:
            buf.append(ln)
    if current and buf:
        func_lines.setdefault(current, []).extend(buf)

updated = 0
for hub_file in HUB_DIR.glob('FUN_*.md'):
    name = hub_file.stem
    content = hub_file.read_text(encoding='utf-8')
    if name not in func_lines:
        continue
    lines = func_lines[name]
    pad_hits = sorted({c for c in PAD_CONSTS for ln in lines if c in ln})
    related = sorted({fn for ln in lines for fn in FUNC_RE.findall(ln) if fn in crate_funcs or fn in pickup_funcs})
    additions = []
    if '## Pad Bit Consumption' in content and 'AUTO-DETECTED PAD BITS' not in content and pad_hits:
        additions.append('\n### AUTO-DETECTED PAD BITS\n' + ', '.join(pad_hits) + '\n')
    if '## Crate / Pickup Paths' in content and 'AUTO-DETECTED CRATE/PICKUP REFS' not in content and related:
        additions.append('\n### AUTO-DETECTED CRATE/PICKUP REFS\n' + '\n'.join(f'- {r}' for r in related) + '\n')
    if additions:
        hub_file.write_text(content + '\n'.join(additions), encoding='utf-8')
        updated += 1

print(f'Enriched {updated} input hub files')
