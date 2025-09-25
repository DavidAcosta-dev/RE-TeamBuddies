#!/usr/bin/env python3
from __future__ import annotations
"""
Build crate candidate edges by scanning bundle_MAIN.EXE.jsonl for callers/callees
and linking through known input edge functions.

Outputs:
  exports/crate_candidate_edges.md
"""
import json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
BDL = EXPORTS / 'bundle_MAIN.EXE.jsonl'
OUT = EXPORTS / 'crate_candidate_edges.md'
CAND_CSV = EXPORTS / 'crate_system_candidates.csv'

FUN_RE = re.compile(r'FUN_[0-9a-fA-F]{6,}')

if not BDL.exists() or not CAND_CSV.exists():
    raise SystemExit('Missing bundle or candidates CSV')

calls_by_fn = {}
callers_of = {}
bodies_by_fn = {}
with BDL.open('r', encoding='utf-8', errors='ignore') as fh:
    for line in fh:
        try:
            obj = json.loads(line)
        except Exception:
            continue
        fn = obj.get('function', {}).get('name')
        if not fn:
            continue
        body = obj.get('decompilation') or ''
        bodies_by_fn[fn] = body
        callees = set(FUN_RE.findall(body))
        calls_by_fn[fn] = callees
        for c in callees:
            callers_of.setdefault(c, set()).add(fn)

# Input hubs (from exports/input_edges_MAIN.EXE.md) — seed by any FUN_ in that file
input_hubs = set()
inp_path = EXPORTS / 'input_edges_MAIN.EXE.md'
inp = inp_path.read_text(encoding='utf-8', errors='ignore') if inp_path.exists() else ''
for fn in FUN_RE.findall(inp):
    input_hubs.add(fn)

# Extract pad mask hints from input and action edges MD files
def extract_masks(md: str) -> dict[str, set[str]]:
    masks_by_fn: dict[str, set[str]] = {}
    current_fn = None
    for ln in md.splitlines():
        ln = ln.strip()
        if ln.startswith('## '):
            # header like: ## FUN_00010944 (FUN_00010944)
            m = FUN_RE.search(ln)
            current_fn = m.group(0) if m else None
            continue
        if not current_fn:
            continue
        for m in re.findall(r'0x[0-9a-fA-F]+', ln):
            ms = masks_by_fn.setdefault(current_fn, set())
            ms.add(m.lower())
    return masks_by_fn

action_path = EXPORTS / 'action_edges_MAIN.EXE.md'
action_md = action_path.read_text(encoding='utf-8', errors='ignore') if action_path.exists() else ''
mask_map = {}
if inp:
    for k, v in extract_masks(inp).items():
        mask_map.setdefault(k, set()).update(v)
if action_md:
    for k, v in extract_masks(action_md).items():
        mask_map.setdefault(k, set()).update(v)

import csv
cands = []
with CAND_CSV.open('r', encoding='utf-8', errors='ignore') as f:
    rd = csv.DictReader(f)
    for row in rd:
        if row.get('binary') == 'MAIN.EXE':
            cands.append(row['function'])

lines = []
lines.append('# Crate Candidate Edges (MAIN.EXE)')
lines.append('')
lines.append('| Candidate | Callers (top) | Callees (top) | From Input? | SchedSlots | SchedLike | PadMasksFromCallers | Notes |')
lines.append('|-----------|----------------|----------------|------------:|-----------|-----------|---------------------|-------|')

def short_list(s):
    return ','.join(sorted(list(s))[:6])

for fn in cands[:200]:
    callers = callers_of.get(fn, set())
    callees = calls_by_fn.get(fn, set())
    from_input = bool(callers & input_hubs)
    body = bodies_by_fn.get(fn, '')
    sched_slots = []
    for off in ['+ 0x38', '+ 0x3c', '+ 0x40']:
        if off in body:
            sched_slots.append(off.replace('+ ', ''))
    # Heuristic: lines containing both a FUN_ call and one of the slot offsets
    sched_like = set()
    if body:
        for ln in body.splitlines():
            if 'FUN_' in ln and any(tok in ln for tok in ['+ 0x38', '+ 0x3c', '+ 0x40']):
                for m in FUN_RE.findall(ln):
                    sched_like.add(m)
    # Gather pad masks from any known caller sections
    pmasks = set()
    for c in callers:
        for m in mask_map.get(c, set()):
            if m in {'0x10', '0x40'}:
                pmasks.add(m)
    lines.append(f"| {fn} | {short_list(callers)} | {short_list(callees)} | {'1' if from_input else '0'} | {','.join(sched_slots)} | {','.join(sorted(list(sched_like))[:3])} | {','.join(sorted(pmasks))} | |")

OUT.write_text('\n'.join(lines), encoding='utf-8')
print(f'Wrote {OUT}')
