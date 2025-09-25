#!/usr/bin/env python3
"""Update the Automated Coverage Crosswalk section in notes/coverage_progress.md.

Extracts category counts & total from mapping_coverage_report.md and rewrites the
crosswalk table while preserving manual narrative outside the section.
"""
from __future__ import annotations
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / 'exports' / 'mapping_coverage_report.md'
NOTES = ROOT / 'notes' / 'coverage_progress.md'
VERT_ROLES = ROOT / 'exports' / 'gravity_vertical_field_roles.csv'

if not REPORT.exists() or not NOTES.exists():
    print('Required files missing; aborting.')
    raise SystemExit(1)

report = REPORT.read_text(encoding='utf-8', errors='ignore').splitlines()
total = 0
cat_counts = []
total_re = re.compile(r'^Total unique functions \(bundled\): (\d+)')
row_re = re.compile(r'^\| (\w+) \| (\d+) \| ([0-9.]+)% \|$')
for ln in report:
    m = total_re.match(ln)
    if m:
        total = int(m.group(1))
    m2 = row_re.match(ln)
    if m2:
        cat_counts.append((m2.group(1), int(m2.group(2))))

if not total or not cat_counts:
    print('Could not parse report; aborting.')
    raise SystemExit(1)

# Build new table rows for the crosswalk section referencing select subsystems
def find(cat):
    for c,n in cat_counts:
        if c == cat:
            return n
    return 0

physics_total = find('vertical_core') + find('vertical_consumer') + find('gravity')
crate_total = find('crate') + find('pickup_drop')
input_total = find('input')
cd_total = find('cdstream')
orientation_total = find('orientation')  # may be zero
anim_total = find('vertical_consumer')  # placeholder subset

def pct(n):
    return f"{(n/total*100):.2f}%" if total else '0%'

new_table = []
new_table.append('| Manual Subsystem | Related Automated Categories | Raw Function Counts (distinct) | Approx Share of Total | Notes / Reconciliation |')
new_table.append('|------------------|------------------------------|-------------------------------:|-----------------------:|------------------------|')
semantic_note = 'Structural tall; semantic understanding still maturing for many consumers.'
if VERT_ROLES.exists():
    try:
        lines_v = VERT_ROLES.read_text(encoding='utf-8').splitlines()[1:]
        locked_vel = 0
        mag_locked = False
        dir_locked = 0
        for ln in lines_v:
            parts = ln.split(',')
            if len(parts) >= 9:
                role = parts[1]
                note = parts[-2]  # notes column
                evidence = parts[-1]
                if role.startswith('velocity_axis_') and 'locked' in note:
                    locked_vel += 1
                if role == 'velocity_magnitude' and ('locked' in note or 'reuse' in evidence):
                    mag_locked = True
                if role.startswith('base_dir_axis_') and 'locked' in note:
                    dir_locked += 1
        if locked_vel >= 3:
            semantic_note += f' Velocity axis roles resolved ({locked_vel}/3).'
        if mag_locked:
            semantic_note += ' Magnitude scalar reuse pattern established.'
        if dir_locked >= 3:
            semantic_note += ' Direction basis locked (3/3).'
    except Exception:
        pass
new_table.append(f'| Physics Integrator (incl. vertical motion aspects) | vertical_core ({find("vertical_core")}) + vertical_consumer ({find("vertical_consumer")}) + gravity ({find("gravity")}) | {physics_total} | {pct(physics_total)} | {semantic_note} |')
new_table.append(f'| Animation / Effects / Particles | vertical_consumer subset | (subset of {find("vertical_consumer")}) | — | Requires tagging refinement to isolate pure FX vs motion math. |')
new_table.append(f'| Crate Interaction | crate ({find("crate")}) + pickup_drop ({find("pickup_drop")}) | {crate_total} | {pct(crate_total)} | High structural coverage; semantics deeply mapped. |')
new_table.append(f'| Input Dispatch | input ({find("input")}) | {input_total} | {pct(input_total)} | Remaining unlabeled input hubs under review. |')
new_table.append(f'| CD Streaming | cdstream ({find("cdstream")}) | {cd_total} | {pct(cd_total)} | Core streaming logic identified; asset linkage pending. |')
if orientation_total:
    new_table.append(f'| Orientation / Direction Tables | orientation ({orientation_total}) | {orientation_total} | {pct(orientation_total)} | Derived from trig mask & table reference heuristic. |')
else:
    new_table.append('| Orientation / Direction Tables | (not separately auto-tagged) | — | — | Pending orientation detector integration. |')

notes_text = NOTES.read_text(encoding='utf-8', errors='ignore')
start_marker = '## Automated Coverage Crosswalk (Refined Categories Snapshot)'
end_marker = '## Recent Milestones'
if start_marker not in notes_text:
    print('Crosswalk section not found; aborting.')
    raise SystemExit(1)

pre, rest = notes_text.split(start_marker, 1)
if end_marker not in rest:
    print('End marker not found; aborting.')
    raise SystemExit(1)
crosswalk_old, post = rest.split(end_marker, 1)

# Rebuild crosswalk preserving intro paragraph up to first table pipe or old header table line
lines_old = crosswalk_old.splitlines()
intro = []
started = False
for l in lines_old:
    if l.strip().startswith('| Manual Subsystem'):
        started = True
        break
    if l.strip():
        intro.append(l)
intro_text = '\n'.join([x for x in intro if x.strip()]) + '\n\n'

replacement = start_marker + '\n\n' + intro_text + '\n'.join(new_table) + '\n\n'
new_notes = pre + replacement + end_marker + post
NOTES.write_text(new_notes, encoding='utf-8')
print('Updated coverage crosswalk section.')
