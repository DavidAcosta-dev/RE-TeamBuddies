#!/usr/bin/env python3
import sys, json, os, csv, collections

IN = sys.argv[1] if len(sys.argv)>1 else os.path.join(os.path.expanduser('~'),'tb-re','exports','bundle_ghidra.jsonl')
OUT_DIR = os.path.join(os.path.expanduser('~'),'tb-re','exports')
os.makedirs(OUT_DIR, exist_ok=True)

funcs = []
with open(IN, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        line=line.strip()
        if not line:
            continue
        try:
            funcs.append(json.loads(line))
        except Exception:
            pass

# Build a per-binary graph node list and degree metrics
perbin_nodes = collections.defaultdict(dict)  # bin -> name -> node data
for rec in funcs:
    b = (rec.get('binary') or '').strip()
    fn = rec.get('function') or {}
    name = fn.get('name')
    if not name:
        continue
    d = perbin_nodes[b].setdefault(name, {
        'name': name,
        'binary': b,
        'ea': fn.get('ea'),
        'size': fn.get('size') or 0,
        'in_degree': 0,
        'out_degree': 0,
        'callers': set(),
        'callees': set(),
    })
    for c in rec.get('callers', []) or []:
        d['callers'].add(c)
    for c in rec.get('callees', []) or []:
        d['callees'].add(c)

for b, nodes in perbin_nodes.items():
    # finalize degrees
    for n, d in nodes.items():
        d['in_degree'] = len(d['callers'])
        d['out_degree'] = len(d['callees'])
        d['degree'] = d['in_degree'] + d['out_degree']

    # rank by degree then size as tiebreaker
    ranked = sorted(nodes.values(), key=lambda x:(x['degree'], x['size']), reverse=True)
    safe = ''.join(ch if ch.isalnum() or ch in '._-' else '_' for ch in (b or 'unknown'))
    out_csv = os.path.join(OUT_DIR, f'callgraph_hubs_{safe}.csv')
    with open(out_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['name','ea','size','in_degree','out_degree','degree','binary'])
        w.writeheader()
        for r in ranked:
            w.writerow({
                'name': r['name'],
                'ea': r['ea'],
                'size': r['size'],
                'in_degree': r['in_degree'],
                'out_degree': r['out_degree'],
                'degree': r['degree'],
                'binary': r['binary'],
            })

print('Wrote callgraph hub CSVs to', OUT_DIR)
