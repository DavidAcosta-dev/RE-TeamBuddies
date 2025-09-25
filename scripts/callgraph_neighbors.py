#!/usr/bin/env python3
import sys, json, os, collections

IN = sys.argv[1] if len(sys.argv)>1 else os.path.join(os.path.expanduser('~'),'tb-re','exports','bundle_ghidra.jsonl')
SEEDS = sys.argv[2:] or ['MAIN.EXE:FUN_00014f80','MAIN.EXE:FUN_00021c64','GAME.BIN:FUN_00031b38']

# Load records
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

# Aggregate per-binary node data to avoid last-write-wins from duplicate bundles
perbin_nodes = collections.defaultdict(dict)  # bin -> name -> agg node
for rec in funcs:
    b = (rec.get('binary') or '').strip()
    fn = rec.get('function') or {}
    name = fn.get('name')
    if not name:
        continue
    d = perbin_nodes[b].setdefault(name, {
        'function': {'name': name, 'ea': fn.get('ea'), 'size': fn.get('size')},
        'callers': set(),
        'callees': set(),
    })
    # Prefer largest size / latest EA if present
    if (fn.get('size') or 0) > (d['function'].get('size') or 0):
        d['function']['size'] = fn.get('size')
        d['function']['ea'] = fn.get('ea')
    for c in rec.get('callers') or []:
        d['callers'].add(c)
    for c in rec.get('callees') or []:
        d['callees'].add(c)

def neigh(bin_name, name):
    nodes = perbin_nodes.get(bin_name, {})
    if name not in nodes:
        return []
    out = {name: nodes[name]}
    # 1-hop callers/callees
    for v in list(nodes[name]['callers']) + list(nodes[name]['callees']):
        if v in nodes:
            out[v] = nodes[v]
    # expand one more hop from the direct neighbors
    expand = list(out.keys())
    for k in expand:
        r = out[k]
        for v in list(r['callers']) + list(r['callees']):
            if v in nodes:
                out.setdefault(v, nodes[v])
    # compact output
    ret = []
    for k, r in out.items():
        fn = r.get('function') or {}
        indeg = len(r.get('callers') or [])
        outdeg = len(r.get('callees') or [])
        ret.append({
            'name': k,
            'ea': fn.get('ea'),
            'size': fn.get('size'),
            'in_degree': indeg,
            'out_degree': outdeg,
        })
    ret.sort(key=lambda x:(x['in_degree']+x['out_degree'], x['size'] or 0), reverse=True)
    return ret

for s in SEEDS:
    try:
        b, n = s.split(':',1)
    except ValueError:
        continue
    items = neigh(b,n)
    print(f'== Neighborhood for {s} ==')
    for it in items[:30]:
        print(f" - {it['name']} @0x{(it['ea'] or 0):08x} deg={it['in_degree']+it['out_degree']} in={it['in_degree']} out={it['out_degree']} size={it['size']}")
