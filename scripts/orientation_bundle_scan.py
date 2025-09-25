#!/usr/bin/env python3
"""Scan bundle_*.jsonl decompilations for orientation patterns not present in snippets.

Patterns:
 - Bitmask & 0xFFF (case-insensitive, allow spaces) -> mask use.
 - Table references: 0x26800 (sin) / 0x27800 (cos) in immediate form or added to base pointer.
 - Combined presence classed as strong candidate.

Output: exports/orientation_bundle_scan.md
Adds functions not already in orientation_candidates.md for differential clarity.
"""
from __future__ import annotations
from pathlib import Path
import json, re

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
OUT = EXPORTS / 'orientation_bundle_scan.md'

mask_re = re.compile(r'&\s*0x0*fff', re.IGNORECASE)
sin_pat = '0x26800'
cos_pat = '0x27800'

existing = set()
can_file = EXPORTS / 'orientation_candidates.md'
if can_file.exists():
    for line in can_file.read_text(encoding='utf-8').splitlines():
        if line.startswith('- FUN_'):
            existing.add(line.split()[1].strip())

records = {}

def note(name, mask=False, sin=False, cos=False):
    rec = records.setdefault(name, {'mask':False,'sin':False,'cos':False})
    rec['mask'] |= mask
    rec['sin'] |= sin
    rec['cos'] |= cos

for bundle in EXPORTS.glob('bundle_*.jsonl'):
    # Skip massive aggregate or ghidra script logs not containing decomp
    if 'all_plus' in bundle.name:
        continue
    with bundle.open('r', encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            line=line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            func = obj.get('function', {}).get('name')
            decomp = obj.get('decompilation') or ''
            if not func or 'FUN_' not in func:
                continue
            has_mask = bool(mask_re.search(decomp))
            has_sin = sin_pat in decomp
            has_cos = cos_pat in decomp
            if has_mask or has_sin or has_cos:
                note(func, has_mask, has_sin, has_cos)

new_only = [f for f in records if f not in existing]
new_only.sort()

with OUT.open('w', encoding='utf-8') as fh:
    fh.write('# Orientation Bundle Scan\n\n')
    fh.write(f'Total hits: {len(records)} (existing list overlap: {len(records)-len(new_only)})\n\n')
    fh.write(f'New (not in orientation_candidates.md): {len(new_only)}\n\n')
    if not records:
        fh.write('_No orientation pattern hits in bundle JSONL files._\n')
    else:
        fh.write('| Function | Mask &0xFFF | SinTbl | CosTbl | Existing List |\n')
        fh.write('|----------|-----------:|-------:|-------:|---------------:|\n')
        for fn,meta in sorted(records.items()):
            fh.write(f"| {fn} | {int(meta['mask'])} | {int(meta['sin'])} | {int(meta['cos'])} | {int(fn in existing)} |\n")
    if new_only:
        fh.write('\n## New Candidates\n\n')
        for fn in new_only:
            meta = records[fn]
            tags = []
            if meta['mask']: tags.append('mask')
            if meta['sin']: tags.append('sin')
            if meta['cos']: tags.append('cos')
            fh.write(f'- {fn} ({",".join(tags)})\n')

print(f'Wrote {OUT} with {len(records)} total orientation pattern hits; {len(new_only)} new.')
