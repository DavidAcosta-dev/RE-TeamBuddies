#!/usr/bin/env python3
from __future__ import annotations
"""
Build a concise Crate Interaction Reference from existing reports.

Inputs:
  exports/crate_candidate_edges.md
  exports/crate_timing_constants.md (optional)

Output:
  exports/crate_reference.md
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
EDGES = EXPORTS / 'crate_candidate_edges.md'
TIMING = EXPORTS / 'crate_timing_constants.md'
OUT = EXPORTS / 'crate_reference.md'

BEGIN_MARK = '<!-- BEGIN: confirmed-entry-points -->'
END_MARK = '<!-- END: confirmed-entry-points -->'

def extract_confirmed_block(existing: str | None) -> str | None:
    if not existing:
        return None
    m = re.search(re.escape(BEGIN_MARK) + r"[\s\S]*?" + re.escape(END_MARK), existing)
    return m.group(0) if m else None

def default_confirmed_block() -> str:
    lines = []
    lines.append('## Confirmed Entry Points')
    lines.append('')
    lines.append(BEGIN_MARK)
    lines.append('')
    lines.append('- crate_pickup_start: FUN_00021424 (writes +0x1c=0x1000, +0x20=0, +0x24=0, +0x14=6)')
    lines.append('- crate_throw_start:  FUN_00021cf0 (writes +0x1c=0, +0x20=0, +0x24=0xfffff000)')
    lines.append('- scheduler install:  FUN_00035324(context, slotPtr, cb_secondary=FUN_000240a0, cb_primary=FUN_00023f50)')
    lines.append('- base idle installer: FUN_000204e4 → schedules +0x38 with pair FUN_00024230/FUN_000241f0 in some contexts')
    lines.append('')
    lines.append(END_MARK)
    lines.append('')
    return '\n'.join(lines)

def parse_edges(md: str):
    lines = md.splitlines()
    # find table header
    start = None
    for i,l in enumerate(lines):
        if l.strip().startswith('| Candidate') and 'PadMasksFromCallers' in l:
            start = i
            break
    if start is None:
        return []
    rows = []
    i = start + 2
    while i < len(lines):
        l = lines[i].strip()
        if not l.startswith('|'):
            break
        cells = [c.strip() for c in l.split('|')[1:-1]]
        if len(cells) < 8:
            i += 1
            continue
        rows.append({
            'candidate': cells[0],
            'callers': cells[1],
            'callees': cells[2],
            'from_input': cells[3],
            'slots': cells[4],
            'schedlike': cells[5],
            'padmasks': cells[6],
            'notes': cells[7],
        })
        i += 1
    return rows

def parse_timing(md: str):
    tops = []
    capture = False
    for l in md.splitlines():
        if l.strip().startswith('Top small-constant frequencies'):
            capture = True
            continue
        if capture:
            if l.strip().startswith('- '):
                tops.append(l.strip()[2:])
            elif l.strip() == '':
                # stop after blank line following list
                break
    return tops[:12]

edges_md = EDGES.read_text(encoding='utf-8', errors='ignore') if EDGES.exists() else ''
rows = parse_edges(edges_md) if edges_md else []
existing = OUT.read_text(encoding='utf-8', errors='ignore') if OUT.exists() else ''
preserved_block = extract_confirmed_block(existing)

timing_md = TIMING.read_text(encoding='utf-8', errors='ignore') if TIMING.exists() else ''
timing_list = parse_timing(timing_md) if timing_md else []

def parse_hex_set(cell: str):
    out = set()
    for tok in (cell or '').replace(';',',').split(','):
        tok = tok.strip()
        if not tok:
            continue
        try:
            if tok.startswith('0x') or tok.startswith('0X'):
                out.add(int(tok,16))
            else:
                out.add(int(tok,16) if all(c in '0123456789abcdefABCDEF' for c in tok) else int(tok))
        except Exception:
            continue
    return out

pickup = []
throw = []
for r in rows:
    masks = parse_hex_set(r.get('padmasks',''))
    slots = parse_hex_set(r.get('slots',''))
    if (0x40 in masks) or (0x3c in slots):
        pickup.append(r)
    if (0x10 in masks) or (0x40 in slots):
        throw.append(r)

def table(section, items):
    out = []
    out.append(f'## {section}')
    out.append('')
    if not items:
        out.append('_None found_')
        out.append('')
        return out
    out.append('| Candidate | Pad | Slots | SchedLike | Callers | Callees |')
    out.append('|-----------|-----|-------|-----------|---------|---------|')
    for r in items[:40]:
        sched_like = r.get('schedlike') or r.get('SchedLike') or ''
        out.append(f"| {r['candidate']} | {r['padmasks']} | {r['slots']} | {sched_like} | {r['callers']} | {r['callees']} |")
    out.append('')
    return out

out = []
out.append('# Crate Interaction Reference')
out.append('')
out.append('Derived from candidate edges, input/action masks, and coarse timing constants. Intended for quick navigation and naming pass.')
out.append('')
if preserved_block:
    out.append(preserved_block)
else:
    out.append(default_confirmed_block())
out.extend(table('Pickup Handlers (0x40 / slot 0x3c)', pickup))
out.extend(table('Throw Handlers (0x10 / slot 0x40)', throw))
out.append('')
out.append('## Timing Constants (coarse, top)')
out.append('')
if timing_list:
    for t in timing_list:
        out.append(f'- {t}')
else:
    out.append('_Timing list not available_')
out.append('')

OUT.write_text('\n'.join(out), encoding='utf-8')
print(f'Wrote {OUT}')
