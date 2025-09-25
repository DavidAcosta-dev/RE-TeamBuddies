#!/usr/bin/env python3
"""Re-detect integrator-like functions using fixed-point vel->pos pattern.

Heuristic (per function decompilation body):
- Position updates: lines touching +0x114 or +0x118 that also contain '>> 0xc'
- Velocity refs: lines within a small window of those updates that reference +0x100 or +0x102
- Optional: both axes present yields a small bonus

Inputs:
- exports/bundle_GAME.BIN.jsonl (same source used by other scripts)

Outputs:
- exports/integrator_candidates.csv (ranked)
- exports/integrator_lines_ext.md (snippets for top candidates)

Env:
- MIN_POS_UPD (default 2)
- MAX_RESULTS (default 100)
- CONTEXT_WINDOW (default 3)
"""
from __future__ import annotations
import os, json, csv, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
BUNDLE = EXPORTS / 'bundle_GAME.BIN.jsonl'
CSV_OUT = EXPORTS / 'integrator_candidates.csv'
MD_OUT = EXPORTS / 'integrator_lines_ext.md'

if not BUNDLE.exists():
    raise SystemExit(f"Missing bundle: {BUNDLE}")

MIN_POS_UPD = int(os.environ.get('MIN_POS_UPD', '2'))
MAX_RESULTS = int(os.environ.get('MAX_RESULTS', '100'))
CONTEXT_WINDOW = int(os.environ.get('CONTEXT_WINDOW', '3'))

POS_OFFS = ['+ 0x114)', '+ 0x118)']
VEL_OFFS = ['+ 0x100)', '+ 0x102)']
SHIFT = '>> 0xc'

FUN_RE = re.compile(r'FUN_[0-9a-fA-F]{6,}')

def analyze_body(body: str):
    lines = body.splitlines()
    pos_updates = []  # list of (idx, line, which_pos)
    for i, ln in enumerate(lines):
        if SHIFT in ln and any(p in ln for p in POS_OFFS):
            which = [p for p in POS_OFFS if p in ln]
            pos_updates.append((i, ln, which))
    vel_refs = 0
    for i, _, _ in pos_updates:
        lo = max(0, i - CONTEXT_WINDOW)
        hi = min(len(lines), i + CONTEXT_WINDOW + 1)
        window = lines[lo:hi]
        if any(v in ' '.join(window) for v in VEL_OFFS):
            vel_refs += 1
    both_axes = int(any('+ 0x114)' in l for _, l, _ in pos_updates) and any('+ 0x118)' in l for _, l, _ in pos_updates))
    score = 2*len(pos_updates) + vel_refs + both_axes
    return {
        'pos_updates': len(pos_updates),
        'vel_refs': vel_refs,
        'both_axes': both_axes,
        'score': score,
        'snippets': pos_updates,
    }

rows = []
with BUNDLE.open('r', encoding='utf-8', errors='ignore') as fh:
    for line in fh:
        try:
            obj = json.loads(line)
        except Exception:
            continue
        fn = (obj.get('function') or {}).get('name')
        if not fn:
            continue
        body = obj.get('decompilation') or ''
        if not body or 'FUN_' not in fn:
            continue
        a = analyze_body(body)
        if a['pos_updates'] >= MIN_POS_UPD:
            rows.append({'function': fn, **a})

rows.sort(key=lambda r: r['score'], reverse=True)
if len(rows) > MAX_RESULTS:
    rows = rows[:MAX_RESULTS]

# CSV
CSV_OUT.parent.mkdir(parents=True, exist_ok=True)
with CSV_OUT.open('w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=['function','score','pos_updates','vel_refs','both_axes'])
    w.writeheader()
    for r in rows:
        w.writerow({k: r[k] for k in ['function','score','pos_updates','vel_refs','both_axes']})

# MD snippets
with MD_OUT.open('w', encoding='utf-8') as f:
    f.write('# Integrator Candidates (Extended Heuristic)\n\n')
    f.write(f'Threshold: MIN_POS_UPD={MIN_POS_UPD}, window=±{CONTEXT_WINDOW}, top={len(rows)}\n\n')
    for r in rows:
        f.write(f"## {r['function']}  | score={r['score']} pos_updates={r['pos_updates']} vel_refs={r['vel_refs']}\n\n")
        # Write up to first 6 snippets with surrounding context
        printed = 0
        for idx, line, which in r['snippets']:
            if printed >= 6:
                break
            printed += 1
            f.write('```c\n')
            # naive context:
            # we don't have the full body here, so only print the line; future work can embed more context
            f.write(line.strip() + '\n')
            f.write('```\n\n')

print(f"Wrote {CSV_OUT} and {MD_OUT}")
