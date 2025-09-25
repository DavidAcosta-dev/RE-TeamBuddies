#!/usr/bin/env python3
"""
extract_vertical_candidate_decomp.py

Dump decompilations of top vertical candidate functions (from prior heuristic runs) with
basic offset highlighting and context, producing a markdown file for manual annotation.

Highlights:
  - Known horizontal positions: 0x114, 0x118
  - Common horizontal velocities: 0x100, 0x102
  - Any other offsets in 0x100..0x140 range flagged as POTENTIAL_Y or AUX

"""
from __future__ import annotations
import json
from pathlib import Path
import re

VERTICAL_CANDIDATES = [
    'FUN_00044f80',
    'FUN_00032c18',
    'FUN_00044a14',
    'FUN_0001e750',
]

KNOWN_VEL = {0x100,0x102}
KNOWN_POS = {0x114,0x118}
RANGE_SCAN = range(0x100,0x150)
OFFSET_RE = re.compile(r"\+\s?0x([0-9a-fA-F]{2,4})")

BUNDLE_GLOB = 'exports/bundle_*.jsonl'


def iter_funcs():
    for p in Path('.').glob(BUNDLE_GLOB):
        with p.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip()
                if not line: continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                fn = data.get('function') or {}
                name = fn.get('name')
                if name in VERTICAL_CANDIDATES:
                    yield name, data


def classify_line(line: str):
    annotations = []
    for m in OFFSET_RE.finditer(line):
        off = int(m.group(1),16)
        if off in KNOWN_VEL:
            annotations.append(f"VEL({hex(off)})")
        elif off in KNOWN_POS:
            annotations.append(f"POS({hex(off)})")
        elif off in RANGE_SCAN:
            annotations.append(f"POTENTIAL_Y({hex(off)})")
    if '>> 0xc' in line.lower():
        annotations.append('SHIFT_Q12')
    if '& 0xfff' in line.lower():
        annotations.append('MASK_0xFFF')
    if annotations:
        return line + '    // ' + ' '.join(annotations)
    return line


def main():
    out_path = Path('vertical_candidate_analysis.md')
    with out_path.open('w',encoding='utf-8') as out:
        out.write('# Vertical Candidate Function Decompilation (Annotated)\n\n')
        for name,data in iter_funcs():
            fn = data['function']
            out.write(f"## {name} (ea=0x{fn.get('ea'):x}, size={fn.get('size')})\n\n")
            decomp = data.get('decompilation') or ''
            for line in decomp.splitlines():
                out.write(classify_line(line) + '\n')
            out.write('\n---\n\n')
    print(f"Wrote {out_path}")

if __name__ == '__main__':
    main()
