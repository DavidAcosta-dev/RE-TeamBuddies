#!/usr/bin/env python3
"""Infer semantic roles for vertical / motion related struct offsets.

Reads the already generated `exports/gravity_vertical_field_patterns.md` which
contains context windows for functions touching suspected vertical / vector
fields. Heuristics derive probable roles for the following offsets:

  0x3c,0x3e,0x40  -> direction / orientation basis components (base_dir_axis_*)
  0x34,0x36,0x38  -> velocity vector components (vel_axis_*)
  0x44            -> magnitude / speed scalar (vel_magnitude)

Evidence categories (simple textual heuristics):
  dot_product:    A line simultaneously referencing 0x3c,0x3e,0x40 and containing '+', '>> 0xc'
  vel_projection: Assignment of 0x34/0x36/0x38 from an expression including corresponding
                  direction component (e.g. *(...+0x34) = (short)(*(...+0x3c) * ... >> 0xc)
  position_update:Line updating position ( + 8 / + 10 / + 0xc ) using a velocity component
  magnitude_usage:Line combining 0x44 with direction components or producing velocity comps

Outputs:
  exports/gravity_vertical_field_roles.csv
  exports/gravity_vertical_field_roles.md (summary)

Environment variables (optional tuning):
  MIN_DOT_COUNT (default 2)      – minimum dot evidence to lock direction axis labels
  MIN_VEL_PROJECTION (default 2) – minimum projection evidence to lock velocity labels

The script is deliberately heuristic and non-invasive; it can be re-run as
additional pattern files evolve without harming prior artifacts.
"""
from __future__ import annotations
import os, re, csv
from pathlib import Path
from dataclasses import dataclass, asdict
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
PATTERN_FILE = ROOT / 'exports' / 'gravity_vertical_field_patterns.md'
CSV_OUT = ROOT / 'exports' / 'gravity_vertical_field_roles.csv'
MD_OUT = ROOT / 'exports' / 'gravity_vertical_field_roles.md'

# Offsets we care about
DIRECTION_OFFSETS = [0x3c, 0x3e, 0x40]
VELOCITY_OFFSETS = [0x34, 0x36, 0x38]
MAG_OFFSET = 0x44
ALL_OFFSETS = VELOCITY_OFFSETS + DIRECTION_OFFSETS + [MAG_OFFSET]

@dataclass
class OffsetEvidence:
    offset: str
    role: str
    dot_product: int = 0
    vel_projection: int = 0
    position_update: int = 0
    magnitude_usage: int = 0
    raw_refs: int = 0
    confidence: float = 0.0
    notes: str = ''
    evidence_kinds: str = ''

def load_lines():
    if not PATTERN_FILE.exists():
        raise SystemExit(f"Missing patterns file: {PATTERN_FILE}")
    return PATTERN_FILE.read_text(encoding='utf-8', errors='ignore').splitlines()

def evidence_scan(lines):
    # Precompile regexes
    assign_re = re.compile(r"=.+>> 0xc")
    # Map offset -> stats dict
    stats = {off: { 'dot':0, 'vel_proj':0, 'pos_upd':0, 'mag_use':0, 'mag_pattern':0, 'refs':0 } for off in ALL_OFFSETS}
    # Track scalar reuse of +0x44 with multiple direction axes in nearby lines
    scalar_reuse = defaultdict(lambda: defaultdict(int))  # mag_offset -> dir_axis -> count

    # Helper to detect presence of specific offset token; ensure not matching 0x134 etc
    def has_offset(line, off):
        # Match '+ 0xNN' not followed by another hex digit to avoid '+ 0xNNN' false positives
        return re.search(rf"\+ 0x{off:02x}(?![0-9a-fA-F])", line) is not None

    recent_proj_dirs = []  # track tuples (line_index, direction_offset)
    # Presence maps for cluster detection
    dir_presence: dict[int, set[int]] = {}
    vel_proj_presence: dict[int, set[int]] = {}
    for idx, line in enumerate(lines):
        # Skip headings / empty
        if not line or line.startswith('## ') or line.startswith('# '):
            continue
        # Count raw references
        for off in ALL_OFFSETS:
            if has_offset(line, off):
                stats[off]['refs'] += 1
        # Track direction presence per line
        for d_off in DIRECTION_OFFSETS:
            if has_offset(line, d_off):
                dir_presence.setdefault(idx, set()).add(d_off)

        # Dot product evidence: line referencing all three direction offsets & right shift
        if all(has_offset(line, o) for o in DIRECTION_OFFSETS) and '>> 0xc' in line and '+' in line:
            for o in DIRECTION_OFFSETS:
                stats[o]['dot'] += 1

        # Velocity projection: assignment to velocity component with fixed-point shift
        # Count even if direction axis isn't on the same line (decomp may split across lines)
        if '>> 0xc' in line and assign_re.search(line):
            for v_off in VELOCITY_OFFSETS:
                if has_offset(line, v_off):
                    stats[v_off]['vel_proj'] += 1
                    vel_proj_presence.setdefault(idx, set()).add(v_off)
                    # Record any direction axes present within a small vicinity window for soft dot inference
                    lo = max(0, idx-2)
                    hi = min(len(lines), idx+3)
                    for j in range(lo, hi):
                        for d_off in DIRECTION_OFFSETS:
                            if has_offset(lines[j], d_off):
                                recent_proj_dirs.append((idx, d_off))
                    # keep sliding window small
                    recent_proj_dirs = [(i,d) for (i,d) in recent_proj_dirs if idx - i <= 6]

        # Position update: line updates (+8/+10/+0xc) adding velocity component (same line)
        if '+ 8)' in line or '+ 10)' in line or '+ 0xc)' in line:
            for v_off in VELOCITY_OFFSETS:
                if has_offset(line, v_off) and '+ =' in line:
                    stats[v_off]['pos_upd'] += 1

        # Magnitude usage & pattern detection + scalar reuse
        if has_offset(line, MAG_OFFSET):
            dir_hits = [d for d in DIRECTION_OFFSETS if has_offset(line, d)]
            if dir_hits:
                stats[MAG_OFFSET]['mag_use'] += 1
            if '>> 0xc' in line:
                stats[MAG_OFFSET]['mag_use'] += 1
            if dir_hits and any(has_offset(line, v) for v in VELOCITY_OFFSETS):
                stats[MAG_OFFSET]['mag_pattern'] += 1
        # Detect scalar reuse: multiply lines referencing a direction axis soon after a +0x44 line
        if any(has_offset(line, d) for d in DIRECTION_OFFSETS) and ('*' in line or 'mul' in line):
            # look back small window for +0x44 reference
            for back in lines[max(0, idx-3):idx+1]:
                if has_offset(back, MAG_OFFSET):
                    for d in DIRECTION_OFFSETS:
                        if has_offset(line, d):
                            scalar_reuse[MAG_OFFSET][d] += 1
                    break

    # Post-pass: infer implicit dot product style evidence if within a short window we saw
    # projections using at least two distinct direction components; award soft dot.
    # If all three components appear in the same window, award a stronger bonus.
    window_dirs = {}
    for line_idx, d_off in recent_proj_dirs:
        window_dirs.setdefault(line_idx // 5, set()).add(d_off)
    for dirs in window_dirs.values():
        if len(dirs) >= 3:
            for d in dirs:
                stats[d]['dot'] += 2  # strong soft award when x,y,z present
        elif len(dirs) == 2:
            for d in dirs:
                stats[d]['dot'] += 1  # weaker soft award
    # Projection cluster detection: if within a small window we see all three velocity
    # components assigned with >>0xc and all three direction axes referenced (anywhere in
    # the window), award an extra dot to each direction axis (captures split-line dots).
    WINDOW = 6
    vel_lines = sorted(vel_proj_presence.keys())
    for i in range(len(vel_lines)):
        start = vel_lines[i]
        end = start + WINDOW
        v_union = set()
        d_union = set()
        for j in vel_lines[i:]:
            if j > end:
                break
            v_union.update(vel_proj_presence.get(j, set()))
            # include dir presence across the same window
            for k in range(start, min(len(lines), end+1)):
                d_union.update(dir_presence.get(k, set()))
        if set(VELOCITY_OFFSETS).issubset(v_union) and set(DIRECTION_OFFSETS).issubset(d_union):
            for d in DIRECTION_OFFSETS:
                stats[d]['dot'] += 1

    stats['scalar_reuse'] = scalar_reuse
    return stats

def infer_roles(stats):
    min_dot = int(os.environ.get('MIN_DOT_COUNT', '2'))
    min_proj = int(os.environ.get('MIN_VEL_PROJECTION', '2'))

    evidences: list[OffsetEvidence] = []

    # Direction axes: label deterministically by conventional order
    for idx, off in enumerate(DIRECTION_OFFSETS):
        axis_map = {0: 'base_dir_axis_x', 1: 'base_dir_axis_y', 2: 'base_dir_axis_z'}
        role = axis_map[idx]
        dot = stats[off]['dot']
        refs = stats[off]['refs']
        # If many references but low explicit dot, still give partial confidence
        ref_boost = 0.2 if refs > 30 else 0.0
        locked = dot >= min_dot or (dot >= 1 and refs > 20)
        conf = 0.5 + 0.4 * min(1.0, dot / max(min_dot, 1)) + ref_boost if locked else 0.25 + 0.32 * (dot / max(min_dot,1)) + ref_boost
        conf = min(conf, 0.95)
        evidences.append(OffsetEvidence(offset=f"0x{off:02x}", role=role, dot_product=dot, raw_refs=refs, confidence=round(conf,3), notes=('locked' if locked else 'low explicit dot')))

    # Velocity components
    for idx, off in enumerate(VELOCITY_OFFSETS):
        role = {0:'velocity_axis_x',1:'velocity_axis_y',2:'velocity_axis_z'}[idx]
        proj = stats[off]['vel_proj']
        pos_upd = stats[off]['pos_upd']
        refs = stats[off]['refs']
        locked = proj >= min_proj
        support = proj + pos_upd
        base_conf = 0.55 if locked else 0.25
        conf = base_conf + 0.15 * min(1.0, pos_upd / max(1, min_proj)) + 0.3 * min(1.0, proj / max(min_proj,1))
        evidences.append(OffsetEvidence(offset=f"0x{off:02x}", role=role, vel_projection=proj, position_update=pos_upd, raw_refs=refs, confidence=round(conf,3), notes=('locked' if locked else 'tentative')))

    # Magnitude / speed scalar
    mag_use = stats[MAG_OFFSET]['mag_use']
    mag_pattern = stats[MAG_OFFSET]['mag_pattern']
    refs = stats[MAG_OFFSET]['refs']
    reuse = stats['scalar_reuse'][MAG_OFFSET]
    reuse_axes = len([d for d,c in reuse.items() if c>1])
    locked = (mag_use >= 2 and reuse_axes >= 2) or mag_pattern >= 2 or (reuse_axes >= 3)
    conf = 0.25
    conf += min(0.25, 0.05 * mag_use)
    conf += min(0.2, 0.1 * mag_pattern)
    if reuse_axes:
        conf += 0.15 + 0.1 * min(2, reuse_axes-1)
    if locked:
        conf = max(conf, 0.65)
    conf = min(conf, 0.9)
    evidence_kinds = []
    if mag_pattern:
        evidence_kinds.append('pattern')
    if reuse_axes:
        evidence_kinds.append(f'reuse{reuse_axes}')
    evidences.append(OffsetEvidence(offset=f"0x{MAG_OFFSET:02x}", role='velocity_magnitude', magnitude_usage=mag_use, raw_refs=refs, confidence=round(conf,3), notes=('locked' if locked else ('pattern' if mag_pattern else 'weak')), evidence_kinds=','.join(evidence_kinds)))

    return evidences

def write_outputs(evidences):
    CSV_OUT.parent.mkdir(parents=True, exist_ok=True)
    with CSV_OUT.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['offset','role','confidence','dot_product','vel_projection','position_update','magnitude_usage','raw_refs','notes','evidence'])
        for ev in evidences:
            w.writerow([ev.offset, ev.role, ev.confidence, ev.dot_product, ev.vel_projection, ev.position_update, ev.magnitude_usage, ev.raw_refs, ev.notes, ev.evidence_kinds])

    # Markdown summary
    lines = ["# Gravity Vertical Field Role Inference", '', f"Source pattern file: {PATTERN_FILE.name}", '']
    lines.append('| Offset | Proposed Role | Confidence | Dot | VelProj | PosUpd | MagUse | RawRefs | Notes | Evidence |')
    lines.append('|--------|---------------|------------|-----|---------|--------|--------|---------|-------|----------|')
    for ev in evidences:
        lines.append(f"| {ev.offset} | {ev.role} | {ev.confidence:.3f} | {ev.dot_product} | {ev.vel_projection} | {ev.position_update} | {ev.magnitude_usage} | {ev.raw_refs} | {ev.notes} | {ev.evidence_kinds} |")
    lines.append('')
    lines.append('Heuristic summary:')
    lines.append('- Direction axes inferred from frequent tri-component dot product style lines with >> 0xc shifts.')
    lines.append('- Velocity components inferred from projection assignments (dir * magnitude >> 0xc) and position update lines.')
    lines.append('- Magnitude field inferred from co-occurrence with direction components and shift scaling.')
    lines.append('')
    lines.append('Tune thresholds with environment variables MIN_DOT_COUNT and MIN_VEL_PROJECTION.')
    MD_OUT.write_text('\n'.join(lines), encoding='utf-8')

def main():
    lines = load_lines()
    stats = evidence_scan(lines)
    evidences = infer_roles(stats)
    write_outputs(evidences)
    print(f"Wrote {CSV_OUT} and {MD_OUT}")

if __name__ == '__main__':
    main()
