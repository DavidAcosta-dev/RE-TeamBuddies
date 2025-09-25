#!/usr/bin/env python3
"""
scan_vertical_candidates.py

Identify candidate vertical (Y) integrator or gravity application sites by examining '>> 0xc'
shift usage not tied to known X/Z positions (offsets +0x114 / +0x118). We:
  - Collect every function containing a '>> 0xc'
  - Extract lines with shifts and potential store operations
  - Track offsets involved (simple regex for +0xXYZ patterns)
  - Flag functions that also contain small negative immediates (-0x1 to -0x100 range) or
    their unsigned forms (0xffffff00 .. 0xffffffff range) near those shifts (±6 lines context)
  - Output CSV ranking by heuristic score

Heuristic scoring:
  +2 unknown_pos_store: shift >>0xc followed by store to offset not in known set
  +2 has_small_negative_imm near that region
  +1 has both an add/sub to a nearby velocity-looking offset (+0x10x region) before the store

Assumptions:
  - Integrator pattern appears as something like: pos -= vel * scalar >> 0xC (we just look for >> 0xc)
  - Y offsets are not yet known; any store with shift to unknown offset is interesting.

Outputs: vertical_candidates.csv
"""
from __future__ import annotations
import argparse
import csv
import json
import re
from pathlib import Path
from collections import defaultdict, deque

SHIFT_PATTERN = re.compile(r">>\s*0xc", re.IGNORECASE)
OFFSET_PATTERN = re.compile(r"\+[ ]?0x[0-9a-fA-F]+")
SMALL_NEG_PATTERN = re.compile(r"-0x[0-9a-fA-F]{1,3}")  # small negative immediates
UNSIGNED_NEG_PATTERN = re.compile(r"0xfffff[0-9a-fA-F]{3}")

KNOWN_POS_OFFSETS = {"0x114", "0x118"}

BUNDLE_GLOB = "exports/bundle_*.jsonl"


def load_funcs():
    funcs = []
    for path in Path('.').glob(BUNDLE_GLOB):
        with path.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line=line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if 'function' in data:
                        data['_file']=str(path)
                        funcs.append(data)
                except json.JSONDecodeError:
                    continue
    return funcs


def analyze(funcs, context_window=6):
    rows = []
    for d in funcs:
        fn = d['function']
        name = fn.get('name')
        decomp = d.get('decompilation') or ''
        if '>> 0xc' not in decomp and '>> 0xC' not in decomp:
            continue
        lines = decomp.splitlines()
        line_count = len(lines)
        candidate_regions = []
        for idx, line in enumerate(lines):
            if SHIFT_PATTERN.search(line):
                candidate_regions.append(idx)
        if not candidate_regions:
            continue
        score = 0
        unknown_pos_store_hits = 0
        small_neg_hits = 0
        velocity_adj_hits = 0
        offsets_seen = set()

        for ci in candidate_regions:
            # gather context window
            start = max(0, ci - context_window)
            end = min(line_count, ci + context_window + 1)
            region = lines[start:end]
            region_text = '\n'.join(region)
            offs = OFFSET_PATTERN.findall(region_text)
            offs_norm = [o.replace('+','').strip() for o in offs]
            for o in offs_norm:
                offsets_seen.add(o)
            # classify unknown pos store: presence of one offset not in known set near shift
            if any(o.lower() not in {"0x114","0x118"} for o in (x.lower() for x in offs_norm)):
                score += 2
                unknown_pos_store_hits += 1
            # small negative imm present
            if SMALL_NEG_PATTERN.search(region_text) or UNSIGNED_NEG_PATTERN.search(region_text):
                score += 2
                small_neg_hits += 1
            # velocity-like adjustment: look for pattern of '+ 0x10' or '+0x10' or +0x100/+0x102 and add/sub lines
            if re.search(r"(\+\s?0x10[0-9a-fA-F]|\+\s?0x100|\+\s?0x102).*(\+|-)=", region_text):
                score += 1
                velocity_adj_hits += 1

        rows.append({
            'fun_name': name,
            'ea': fn.get('ea'),
            'size': fn.get('size'),
            'shift_sites': len(candidate_regions),
            'unknown_pos_store_hits': unknown_pos_store_hits,
            'small_neg_hits': small_neg_hits,
            'velocity_adj_hits': velocity_adj_hits,
            'heuristic_score': score,
            'source_file': d.get('_file'),
            'offsets_context_sample': ';'.join(sorted(list(offsets_seen))[:12])
        })
    rows.sort(key=lambda r: (-r['heuristic_score'], -r['shift_sites'], r['fun_name']))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='vertical_candidates.csv')
    ap.add_argument('--context', type=int, default=6)
    args = ap.parse_args()
    funcs = load_funcs()
    rows = analyze(funcs, args.context)
    if not rows:
        print('No vertical candidates found (no >>0xc usage).')
        return
    with open(args.out, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f'Wrote {len(rows)} rows to {args.out}')
    for r in rows[:15]:
        print(f"TOP {r['fun_name']} score={r['heuristic_score']} shift_sites={r['shift_sites']} unknownStores={r['unknown_pos_store_hits']} smallNeg={r['small_neg_hits']} offs={r['offsets_context_sample']}")

if __name__ == '__main__':
    main()
