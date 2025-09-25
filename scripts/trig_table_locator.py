#!/usr/bin/env python3
"""
trig_table_locator.py

Goal: Narrow down potential base addresses for the 4096-entry trig (sin/cos) table
referenced through &0xFFF masked indices.

Heuristics:
 1. Identify functions that contain '& 0xFFF' AND at least one shift by 0xC or 0x4
    (common in fixed-point normalization) and collect immediate large constant patterns.
 2. Look for contiguous memory load patterns using base + (index << 1) or + (index << 2)
    that appear twice in close proximity (suggesting paired sin/cos fetch).
 3. Scan raw string/hex of decompilation for sequences like '<< 0x1' followed by '+ base'
    where base is a constant in the region of typical data segment.

Outputs: trig_table_locator.md summarizing candidate functions and extracted address-like constants.
"""
from __future__ import annotations
import re,json
from pathlib import Path
from collections import defaultdict

MASK_RE=re.compile(r'&\s*0x0*fff',re.IGNORECASE)
SHIFT_PAIR_RE=re.compile(r'<<\s*0x1')
SHIFT12_RE=re.compile(r'>>\s*0xc',re.IGNORECASE)
HEX_CONST_RE=re.compile(r'0x[0-9a-fA-F]{5,}')  # long-ish constants (potential addresses)
INDEX_PAT_RE=re.compile(r'(?:\w+\s*=\s*)?(\w+)\s*<<\s*0x1')

BUNDLE_GLOB='exports/bundle_*.jsonl'


def iter_functions():
    for p in Path('.').glob(BUNDLE_GLOB):
        with p.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip();
                if not line: continue
                try:
                    obj=json.loads(line)
                except json.JSONDecodeError:
                    continue
                if 'function' in obj:
                    yield obj


def analyze(fn):
    dec=fn.get('decompilation') or ''
    if not MASK_RE.search(dec):
        return None
    if not SHIFT12_RE.search(dec):
        # still accept if mask present but no shift12
        pass
    lines=dec.splitlines()
    mask_lines=[i for i,l in enumerate(lines) if MASK_RE.search(l)]
    pair_hits=[]
    for i,l in enumerate(lines):
        if '<<' in l and '0x1' in l:
            # look ahead small window for bracket memory fetch using same temp var
            m=INDEX_PAT_RE.search(l)
            if not m: continue
            var=m.group(1)
            for j in range(i+1,min(i+6,len(lines))):
                l2=lines[j]
                if var in l2 and ('[' in l2 and ']' in l2) and ('+' in l2):
                    pair_hits.append((i,j,var,l.strip(),l2.strip()))
                    break
    long_consts=HEX_CONST_RE.findall(dec)
    return {
        'mask_line_count':len(mask_lines),
        'pair_hits':pair_hits,
        'long_consts':long_consts[:10]
    }


def main():
    out=['# Trig Table Locator Report\n']
    for fn in iter_functions():
        info=analyze(fn)
        if not info: continue
        if not info['pair_hits'] and len(info['long_consts'])==0:
            continue
        fname=fn['function']['name']; ea=fn['function']['ea']
        out.append(f"## {fname} (ea=0x{ea:x})")
        out.append(f"Mask lines: {info['mask_line_count']}  Long consts: {', '.join(info['long_consts']) or '—'}")
        if info['pair_hits']:
            out.append('Potential index pair patterns:')
            for (a,b,var,l1,l2) in info['pair_hits'][:4]:
                out.append(f"- lines {a}->{b} var={var}\n  {l1}\n  {l2}")
        out.append('')
    with open('trig_table_locator.md','w',encoding='utf-8') as f:
        f.write('\n'.join(out))
    print('Wrote trig_table_locator.md')

if __name__=='__main__':
    main()
