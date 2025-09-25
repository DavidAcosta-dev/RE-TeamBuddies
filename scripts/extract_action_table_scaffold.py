#!/usr/bin/env python3
"""
extract_action_table_scaffold.py

Prototype extractor to locate and emit a provisional action state jump table (target size ~0x4B entries)
by scanning decomp text for switch constructs referencing a bounded value or contiguous address table.

Heuristics:
  1. Look for lines containing 'switch' and a limit compare with 0x4b / 0x4a / 0x4c
  2. If decomp includes case labels up to 0x4a, collect the FUN_* names appearing near 'case'
  3. Fallback: search for a contiguous block of FUN_ addresses on separate lines inside one function
     (treat as a potential indirect jump table cluster)

Outputs:
  action_state_table_candidates.txt - annotated raw extraction attempts.
  action_state_map.csv (index,function_name) if a plausible table found.

Manual follow-up likely required to verify ordering.
"""
from __future__ import annotations
import re
import json
from pathlib import Path
import csv

BUNDLE_GLOB = 'exports/bundle_*.jsonl'
CASE_FUN = re.compile(r'case\s+(0x[0-9a-fA-F]+|\d+):.*?(FUN_[0-9a-fA-F]{8})')
FUN_NAME = re.compile(r'FUN_[0-9a-fA-F]{8}')
LIMIT_PATTERN = re.compile(r'(0x4b|0x4a|0x4c)')


def load_funcs():
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
                        yield data
                except json.JSONDecodeError:
                    continue


def main():
    candidates = []
    best_table = []
    for d in load_funcs():
        fn = d['function']
        name = fn['name']
        decomp = d.get('decompilation') or ''
        if 'switch' not in decomp:
            continue
        if not LIMIT_PATTERN.search(decomp.lower()):
            continue
        # Extract case -> handler pairs
        pairs = CASE_FUN.findall(decomp)
        if pairs:
            # Normalize indices
            entries = []
            for idx_str, fun in pairs:
                if idx_str.startswith('0x'):
                    idx = int(idx_str, 16)
                else:
                    idx = int(idx_str)
                entries.append((idx, fun))
            if entries:
                entries_sorted = sorted(entries, key=lambda x: x[0])
                max_idx = entries_sorted[-1][0]
                coverage = len({i for i,_ in entries})
                candidates.append((name, max_idx, coverage, entries_sorted, d['_file']))
                # Heuristic: plausible table if max index within [0x40,0x60] and coverage > 32
                if 0x40 <= max_idx <= 0x60 and coverage > 32 and not best_table:
                    best_table = entries_sorted
    # Output raw candidates
    with open('action_state_table_candidates.txt','w',encoding='utf-8') as f:
        for name, max_idx, coverage, entries, src in candidates:
            f.write(f"Function {name} (maxCase={hex(max_idx)} coverage={coverage} src={src})\n")
            for idx, fun in entries[:128]:
                f.write(f"  case {idx}: {fun}\n")
            f.write('\n')
    if best_table:
        unique = {}
        for idx, fun in best_table:
            unique[idx] = fun
        max_idx = max(unique)
        with open('action_state_map.csv','w',newline='',encoding='utf-8') as f:
            w=csv.writer(f)
            w.writerow(['index','function'])
            for i in range(max_idx+1):
                w.writerow([i, unique.get(i,'')])
        print(f"Wrote action_state_map.csv with {max_idx+1} rows (heuristic)")
    else:
        print('No plausible full action table found; inspect action_state_table_candidates.txt manually.')

if __name__ == '__main__':
    main()
