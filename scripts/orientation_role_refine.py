#!/usr/bin/env python3
"""Refine orientation role classification by splitting camera vs object transforms.

Inputs:
  - orientation_roles.md (base roles)
  - orientation_focus_context.md (context lines)

Adds refinement tag:
  camera_matrix_build: base role matrix_apply_or_camera_setup OR (cop_usage & dual_trig_pair)
  object_angle_update: base role angle_normalization_update OR (angle_wrap_only & shift)
  lookup_helper: base role angle_wrap_only without shift and trig_table missing
  mixed_or_ambiguous: otherwise

Output: orientation_roles_refined.md
"""
from __future__ import annotations
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
BASE = EXPORTS / 'orientation_roles.md'
FOCUS = EXPORTS / 'orientation_focus_context.md'
OUT = EXPORTS / 'orientation_roles_refined.md'

if not BASE.exists() or not FOCUS.exists():
    raise SystemExit('Required orientation role artifacts missing')

role_rows = []
lines = BASE.read_text(encoding='utf-8').splitlines()
for ln in lines:
    if ln.startswith('| FUN_'):
        parts = [p.strip() for p in ln.strip('|').split('|')]
        # Expected columns from orientation_roles.md header:
        # Function | Score | Role | mask | trig_table | cop_usage | angle_normalize | shift | table_index_math | dual_trig_pair
        if len(parts) >= 10:
            fn = parts[0]
            try:
                score = float(parts[1])
            except ValueError:
                continue
            role = parts[2]
            mask = parts[3] == '1'
            trig = parts[4] == '1'
            cop = parts[5] == '1'
            angle_norm = parts[6] == '1'
            shift = parts[7] == '1'
            tbl_idx = parts[8] == '1'
            dual = parts[9] == '1'
            role_rows.append({
                'fn': fn,
                'score': score,
                'role': role,
                'mask': mask,
                'trig': trig,
                'cop': cop,
                'angle_norm': angle_norm,
                'shift': shift,
                'tbl_idx': tbl_idx,
                'dual': dual,
            })

focus_text = FOCUS.read_text(encoding='utf-8')

def refine(r):
    if r['role'] == 'matrix_apply_or_camera_setup' or (r['cop'] and r['dual']):
        return 'camera_matrix_build'
    if r['role'] == 'angle_normalization_update' or (r['role'] == 'angle_wrap_only' and r['shift']):
        return 'object_angle_update'
    if r['role'] == 'angle_wrap_only' and not r['shift'] and not r['trig']:
        return 'lookup_helper'
    return 'mixed_or_ambiguous'

for r in role_rows:
    r['refined'] = refine(r)

role_rows.sort(key=lambda r: (-r['score'], r['fn']))

with OUT.open('w', encoding='utf-8') as fh:
    fh.write('# Orientation Roles (Refined)\n\n')
    fh.write('| Function | Score | BaseRole | RefinedRole | COP | Dual | Shift | Trig | TableIdx | AngleNorm |\n')
    fh.write('|----------|------:|----------|-------------|----:|-----:|------:|-----:|---------:|----------:|\n')
    for r in role_rows:
        fh.write(f"| {r['fn']} | {r['score']:.2f} | {r['role']} | {r['refined']} | {int(r['cop'])} | {int(r['dual'])} | {int(r['shift'])} | {int(r['trig'])} | {int(r['tbl_idx'])} | {int(r['angle_norm'])} |\n")

print(f'Wrote {OUT} with {len(role_rows)} refined orientation roles')
