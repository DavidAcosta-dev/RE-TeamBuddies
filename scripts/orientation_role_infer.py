#!/usr/bin/env python3
"""Infer coarse roles for orientation candidates based on context features.

Inputs:
 - exports/orientation_focus_context.md
 - exports/orientation_scored.md

Features:
  mask (&0xfff), trig_table (-0x7ffeb164), cop_usage (setCopControlWord/Reg),
  angle_normalize (pattern ' & 0xfff;' or wrap comparisons), shift (>> 0xc),
  table_index_math ((index & 0xfff) * 4), dual_trig_pair (two successive table fetches).

Role Heuristic precedence:
  1. matrix_apply_or_camera_setup: trig_table & cop_usage
  2. angle_normalization_update: angle_normalize & trig_table
  3. trig_lookup_transform: trig_table & table_index_math
  4. angle_wrap_only: mask & not trig_table
  5. misc_orientation_candidate

Output: exports/orientation_roles.md (table) + exports/orientation_roles_features.csv
"""
from __future__ import annotations
from pathlib import Path
import re, csv

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
FOCUS = EXPORTS / 'orientation_focus_context.md'
SCORED = EXPORTS / 'orientation_scored.md'
OUT_MD = EXPORTS / 'orientation_roles.md'
OUT_CSV = EXPORTS / 'orientation_roles_features.csv'

if not FOCUS.exists() or not SCORED.exists():
    raise SystemExit('Required orientation exports missing.')

# Parse scores
scores = {}
table_mode = False
for ln in SCORED.read_text(encoding='utf-8').splitlines():
    if ln.startswith('| Score |'):
        table_mode = True
        continue
    if table_mode and ln.startswith('|') and not ln.startswith('|------'):
        cols = [c.strip() for c in ln.strip().strip('|').split('|')]
        if len(cols) >= 2 and cols[1].startswith('FUN_'):
            try:
                scores[cols[1]] = float(cols[0])
            except ValueError:
                pass

focus_text = FOCUS.read_text(encoding='utf-8')
sections = {}
current = None
buf = []
for ln in focus_text.splitlines():
    if ln.startswith('## FUN_'):
        if current:
            sections[current] = '\n'.join(buf)
        current = ln.split()[1]
        buf = []
    else:
        if current:
            buf.append(ln)
if current:
    sections[current] = '\n'.join(buf)

def infer_features(text: str):
    return {
        'mask': bool(re.search(r'&\s*0x0*fff', text, re.IGNORECASE)),
        'trig_table': '-0x7ffeb164' in text,
        'cop_usage': ('setCopControlWord' in text) or ('setCopReg' in text),
        'angle_normalize': bool(re.search(r'&\s*0x0*fff\)', text, re.IGNORECASE)) or ' & 0xfff;' in text,
        'shift': '>> 0xc' in text,
        'table_index_math': bool(re.search(r'&\s*0x0*fff\) \* 4', text, re.IGNORECASE)),
        'dual_trig_pair': text.count('-0x7ffeb164') >= 2,
    }

def infer_role(f):
    if f['trig_table'] and f['cop_usage']:
        return 'matrix_apply_or_camera_setup'
    if f['angle_normalize'] and f['trig_table']:
        return 'angle_normalization_update'
    if f['trig_table'] and f['table_index_math']:
        return 'trig_lookup_transform'
    if f['mask'] and not f['trig_table']:
        return 'angle_wrap_only'
    return 'misc_orientation_candidate'

rows = []
for fn, ctx in sections.items():
    feats = infer_features(ctx)
    role = infer_role(feats)
    rows.append({
        'function': fn,
        'score': scores.get(fn, 0.0),
        'role': role,
        **feats
    })

rows.sort(key=lambda r: (-r['score'], r['function']))

with OUT_MD.open('w', encoding='utf-8') as fh:
    fh.write('# Orientation Role Inference\n\n')
    fh.write('| Function | Score | Role | mask | trig_table | cop_usage | angle_normalize | shift | table_index_math | dual_trig_pair |\n')
    fh.write('|----------|------:|------|-----:|-----------:|----------:|---------------:|------:|-----------------:|---------------:|\n')
    for r in rows:
        fh.write(f"| {r['function']} | {r['score']:.2f} | {r['role']} | {int(r['mask'])} | {int(r['trig_table'])} | {int(r['cop_usage'])} | {int(r['angle_normalize'])} | {int(r['shift'])} | {int(r['table_index_math'])} | {int(r['dual_trig_pair'])} |\n")

with OUT_CSV.open('w', newline='', encoding='utf-8') as fh:
    fieldnames = ['function','score','role','mask','trig_table','cop_usage','angle_normalize','shift','table_index_math','dual_trig_pair']
    w = csv.DictWriter(fh, fieldnames=fieldnames)
    w.writeheader()
    for r in rows:
        w.writerow(r)

print(f'Wrote {OUT_MD} with {len(rows)} orientation role rows')
