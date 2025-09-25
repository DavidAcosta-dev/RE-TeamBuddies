#!/usr/bin/env python3
from __future__ import annotations
"""
Propose crate function names from crate_candidate_edges.md and patch suggestions.

Outputs:
  exports/crate_naming_suggestions.md
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
EDGES = EXPORTS / 'crate_candidate_edges.md'
OUT = EXPORTS / 'crate_naming_suggestions.md'

def parse_edges(md: str):
    lines = md.splitlines()
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

def count_list(cell: str) -> int:
    cell = (cell or '').strip()
    if not cell:
        return 0
    return len([x for x in cell.split(',') if x.strip()])

edges_md = EDGES.read_text(encoding='utf-8', errors='ignore') if EDGES.exists() else ''
rows = parse_edges(edges_md) if edges_md else []

def score_row(r):
    return (1 if r['from_input'] == '1' else 0) * 10 + count_list(r['callers']) + count_list(r['callees'])

pickup = sorted([r for r in rows if ('3c' in r['slots']) or ('0x40' in r['padmasks'])], key=score_row, reverse=True)
throw = sorted([r for r in rows if ('40' in r['slots']) or ('0x10' in r['padmasks'])], key=score_row, reverse=True)
base  = sorted([r for r in rows if ('38' in r['slots'])], key=score_row, reverse=True)

lines = []
lines.append('# Crate Naming Suggestions')
lines.append('')
def emit(title, items, tag):
    lines.append(f'## {title}')
    lines.append('')
    if not items:
        lines.append('_None_')
        lines.append('')
        return
    for r in items[:8]:
        lines.append(f"- {tag}: {r['candidate']}  | pad={r['padmasks']} | slots={r['slots']} | callers={r['callers']} | callees={r['callees']}")
    lines.append('')

emit('Pickup Start (slot 0x3c / pad 0x40)', pickup, 'crate_pickup_start?')
emit('Throw Start (slot 0x40 / pad 0x10)', throw, 'crate_throw_start?')
emit('Carry/Base Idle (slot 0x38)', base, 'crate_carry_idle_state?')

OUT.write_text('\n'.join(lines), encoding='utf-8')
print(f'Wrote {OUT}')
