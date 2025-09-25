#!/usr/bin/env python3
"""
scan_crate_signatures.py

Heuristic scanner to identify raw FUN_* names for crate-related logic in MAIN.EXE / overlays.
Outputs a CSV (crate_signature_candidates.csv) with several boolean / score features to help
map semantic names (pickup/throw start, per-frame callbacks, animation/effects secondary cb).

Heuristics:
  - Input masks 0x40 (pickup) & 0x10 (throw) appearing in same function decomp.
  - Tri-slot crate offsets: +0x38, +0x3c, +0x40 occurrences.
  - Polarity mask pair: 0x1000 & 0xfffff000 in same function.
  - Large animation/effects call: function calls a very large callee (size threshold) or a callee
    referenced unusually often across codebase (crude proxy for big effects routine).

Scoring (simple additive):
  +2 both input masks present
  +1 each tri-slot offset occurrence (capped 3)
  +2 polarity pair present
  +2 calls a large callee (size > 2000) or that callee is called by > 30 functions

Classification (candidate_type):
  pickup_or_throw_logic: has_input_masks & tri_slot_count >=2
  secondary_cb: large_effects_call & tri_slot_count >=2 & not has_input_masks
  per_frame_cb: tri_slot_count ==3 & not has_input_masks
  polarity_helper: polarity pair present but few tri-slot refs (<2)
  other: fallback

Usage:
  python scripts/scan_crate_signatures.py [--out crate_signature_candidates.csv] [--min-size 0]

Depends only on standard library.
"""

from __future__ import annotations
import argparse
import csv
import json
import re
from pathlib import Path
from collections import defaultdict

TRI_OFFSETS = ["+ 0x38", "+ 0x3c", "+ 0x40", "+0x38", "+0x3c", "+0x40"]
INPUT_MASKS = ["0x40", "0x10"]  # appear elsewhere too; we require both in same function
POLARITY_PARTS = ["0x1000", "0xfffff000"]

BUNDLE_GLOB = "exports/bundle_*.jsonl"

RE_FUN_NAME = re.compile(r"FUN_[0-9a-fA-F]{8}")


def load_functions() -> list[dict]:
    funcs = []
    for path in Path('.').glob(BUNDLE_GLOB):
        with path.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line=line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    fn = data.get('function') or {}
                    if 'name' in fn:
                        data['_file'] = str(path)
                        funcs.append(data)
                except json.JSONDecodeError:
                    continue
    return funcs


def index_callees(funcs: list[dict]):
    sizes = {}
    callers_count = defaultdict(int)
    for d in funcs:
        fn = d.get('function', {})
        sizes[fn.get('name')] = fn.get('size', 0)
        for callee in d.get('callees', []):
            callers_count[callee] += 1
    return sizes, callers_count


def analyze(funcs: list[dict], large_size: int = 2000, large_caller_threshold: int = 30):
    sizes, callers = index_callees(funcs)
    rows = []
    for d in funcs:
        fn = d.get('function', {})
        name = fn.get('name')
        size = fn.get('size', 0)
        decomp = d.get('decompilation') or d.get('decompile') or ""
        lower = decomp.lower()

        has_masks = all(m.lower() in lower for m in INPUT_MASKS)
        tri_count = sum(lower.count(tok.lower()) for tok in TRI_OFFSETS)
        polarity = all(p.lower() in lower for p in POLARITY_PARTS)

        callees = d.get('callees', []) or []
        large_effects_call = False
        for c in callees:
            if sizes.get(c, 0) >= large_size or callers.get(c, 0) >= large_caller_threshold:
                large_effects_call = True
                break

        # Score
        score = 0
        if has_masks:
            score += 2
        score += min(tri_count, 3)  # up to 3 points
        if polarity:
            score += 2
        if large_effects_call:
            score += 2

        # Classification
        if has_masks and tri_count >= 2:
            ctype = 'pickup_or_throw_logic'
        elif large_effects_call and tri_count >= 2 and not has_masks:
            ctype = 'secondary_cb'
        elif tri_count == 3 and not has_masks:
            ctype = 'per_frame_cb'
        elif polarity and tri_count < 2:
            ctype = 'polarity_helper'
        else:
            ctype = 'other'

        rows.append({
            'fun_name': name,
            'ea': fn.get('ea'),
            'size': size,
            'has_input_masks': has_masks,
            'tri_slot_hits': tri_count,
            'polarity_pair': polarity,
            'large_effects_call': large_effects_call,
            'score': score,
            'candidate_type': ctype,
            'source_file': d.get('_file')
        })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='crate_signature_candidates.csv')
    ap.add_argument('--large-size', type=int, default=2000)
    ap.add_argument('--large-caller-threshold', type=int, default=30)
    args = ap.parse_args()

    funcs = load_functions()
    rows = analyze(funcs, args.large_size, args.large_caller_threshold)
    rows.sort(key=lambda r: (-r['score'], r['fun_name']))

    with open(args.out, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {args.out}")
    # Quick top summary
    for r in rows[:15]:
        print(f"TOP {r['fun_name']} score={r['score']} type={r['candidate_type']} tri={r['tri_slot_hits']} masks={r['has_input_masks']} polarity={r['polarity_pair']}")

if __name__ == '__main__':
    main()
