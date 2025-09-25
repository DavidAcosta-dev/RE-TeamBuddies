#!/usr/bin/env python3
"""Score orientation candidate functions using richer features.

Inputs: orientation_bundle_scan.md table + existing orientation_candidates.md list + snippets for structural cues.

Features:
  mask: presence of &0xFFF
  trig_pair: both mask and (sin or cos table)
  sin_only / cos_only
  index_pattern: line with shift/and then used as index (heuristic: '& 0xFFF' line followed within 3 lines by '+' or '* 2')
  multi_mask: more than one &0xFFF occurrence
  call_hub_proximity: in_degree from callgraph_hubs_GAME.BIN.csv (normalized bucket)

Score weights (tunable):
  mask:1, trig_pair:+2, index_pattern:+2, multi_mask:+1, hub_bucket:+1.

Output: exports/orientation_scored.md
"""
from __future__ import annotations
from pathlib import Path
import re, csv

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'

bundle_scan = EXPORTS / 'orientation_bundle_scan.md'
orig_list = EXPORTS / 'orientation_candidates.md'
callgraph = EXPORTS / 'callgraph_hubs_GAME.BIN.csv'
OUT = EXPORTS / 'orientation_scored.md'

mask_re = re.compile(r'&\s*0x0*fff', re.IGNORECASE)

# Parse bundle scan table
records = {}
if bundle_scan.exists():
    lines = bundle_scan.read_text(encoding='utf-8').splitlines()
    table = False
    for ln in lines:
        if ln.startswith('| Function |'):
            table = True
            continue
        if table:
            if not ln.startswith('|') or ln.startswith('|---'):
                continue
            cols = [c.strip() for c in ln.strip('|').split('|')]
            if len(cols) < 5:
                continue
            fn = cols[0]
            if not fn.startswith('FUN_'): continue
            records[fn] = {
                'mask': cols[1]=='1',
                'sin': cols[2]=='1',
                'cos': cols[3]=='1',
                'orig': cols[4]=='1',
            }

# Add any original list not in bundle scan
if orig_list.exists():
    for ln in orig_list.read_text(encoding='utf-8').splitlines():
        if ln.startswith('- FUN_'):
            fn = ln.split()[1]
            records.setdefault(fn, {'mask':False,'sin':False,'cos':False,'orig':True})

# Load snippet lines for index/multi-mask heuristics
snippet_cache = {}
for snip in EXPORTS.glob('snippets_*.md'):
    content = snip.read_text(encoding='utf-8', errors='ignore')
    # Split approximate per function for quick search
    for block in content.split('```c'):
        # simple extract function name
        m = re.search(r'FUN_[0-9a-fA-F]{8}', block)
        if m:
            snippet_cache[m.group(0)] = block

# Callgraph in_degree mapping
in_degree = {}
if callgraph.exists():
    with callgraph.open() as fh:
        rdr = csv.DictReader(fh)
        for row in rdr:
            in_degree[row['name']] = int(row['in_degree'])

# Compute scores
scored = []
for fn,data in records.items():
    text = snippet_cache.get(fn,'')
    mask_hits = len(mask_re.findall(text))
    index_pat = False
    if mask_hits:
        # look for &0xFFF line followed closely by + something*2 or <<1
        lines = text.splitlines()
        for i,l in enumerate(lines):
            if '& 0xFFF' in l or '&0xFFF' in l:
                window = '\n'.join(lines[i+1:i+4])
                if ('* 2' in window) or ('<< 1' in window) or ('<<1' in window):
                    index_pat = True
                    break
    trig_pair = data['mask'] and (data['sin'] or data['cos'])
    multi_mask = mask_hits > 1
    indeg = in_degree.get(fn,0)
    hub_bucket = 1 if indeg >= 5 else (0.5 if indeg >=2 else 0)
    score = 0
    if data['mask']: score += 1
    if trig_pair: score += 2
    if index_pat: score += 2
    if multi_mask: score += 1
    if hub_bucket: score += hub_bucket
    scored.append((score, fn, data, index_pat, multi_mask, hub_bucket))

scored.sort(reverse=True)

with OUT.open('w', encoding='utf-8') as fh:
    fh.write('# Orientation Scored Candidates\n\n')
    fh.write('Score weights: mask=1, trig_pair=+2, index_pattern=+2, multi_mask=+1, hub_bucket up to +1.\n\n')
    fh.write('| Score | Function | Mask | Sin | Cos | IndexPat | MultiMask | HubInDegBucket | OrigList |\n')
    fh.write('|------:|----------|-----:|----:|----:|---------:|----------:|---------------:|---------:|\n')
    for score,fn,data,index_pat,multi_mask,hub_bucket in scored:
        fh.write(f'| {score:.1f} | {fn} | {int(data["mask"])} | {int(data["sin"])} | {int(data["cos"])} | {int(index_pat)} | {int(multi_mask)} | {hub_bucket:.1f} | {int(data.get("orig",False))} |\n')
    fh.write(f'\nTotal candidates scored: {len(scored)}\n')

print(f'Wrote {OUT} with {len(scored)} scored orientation candidates')
