#!/usr/bin/env python3
import os, sys, json, collections, re

IN = sys.argv[1] if len(sys.argv)>1 else os.path.join(os.path.expanduser('~'),'tb-re','exports','bundle_ghidra.jsonl')
BOOK = os.path.join(os.path.expanduser('~'),'tb-re','exports','suspects_bookmarks.json')
OUT_DIR = os.path.join(os.path.expanduser('~'),'tb-re','exports')
os.makedirs(OUT_DIR, exist_ok=True)

def load_jsonl(path):
    recs = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line=line.strip()
            if not line:
                continue
            try:
                recs.append(json.loads(line))
            except Exception:
                pass
    return recs

funcs = load_jsonl(IN)
try:
    with open(BOOK, 'r', encoding='utf-8') as f:
        bookmarks = json.load(f)
except Exception:
    bookmarks = {}

# Aggregate per-binary nodes with callers/callees sets
perbin_nodes = collections.defaultdict(dict)
for rec in funcs:
    b = (rec.get('binary') or '').strip()
    fn = rec.get('function') or {}
    name = fn.get('name')
    if not name:
        continue
    d = perbin_nodes[b].setdefault(name, {
        'name': name,
        'ea': fn.get('ea'),
        'size': fn.get('size') or 0,
        'callers': set(),
        'callees': set(),
        'strings': tuple(s.get('text','') for s in rec.get('strings_used') or []),
        'dec': rec.get('decompilation') or ''
    })
    # keep max size and latest ea if larger size shows up
    if (fn.get('size') or 0) > (d['size'] or 0):
        d['size'] = fn.get('size') or 0
        d['ea'] = fn.get('ea')
    for c in rec.get('callers') or []:
        d['callers'].add(c)
    for c in rec.get('callees') or []:
        d['callees'].add(c)

PSYQ_TOKENS = [
    ('controller', re.compile(r'\b(Pad(Read|Init|Open|Close|Info|Raw|Flags)?|PAD(open|poll|start|stop|dr)?|libpad|controller|sio|SIO|button|analog|dead\s*zone)\b', re.I)),
    ('rcnt', re.compile(r'\brcnt|rcounter|reset\s*rcnt|StartRCnt|StopRCnt\b', re.I)),
    ('vsync', re.compile(r'\bVSync|DrawSync|WaitVSync\b', re.I)),
    ('gpu', re.compile(r'\bGPU| ordering\s*table|OT\b', re.I)),
    ('spu', re.compile(r'\bSPU|Sound|Voice|libspu\b', re.I)),
    ('cd', re.compile(r'\bCD|libcd|XA\b', re.I)),
]
PHYS_TOKENS = re.compile(r'gravity|jump|vel(ocity)?|accel|decel|friction|speed|air|strafe|throw|kick|move', re.I)

def tags_for(node):
    text = ' '.join([node['name'], node['dec'] or '', ' '.join(node['strings'] or [])])
    tags = []
    if PHYS_TOKENS.search(text):
        tags.append('physics')
    for label, rx in PSYQ_TOKENS:
        if rx.search(text):
            tags.append(label)
    return tags

def degree(node):
    return len(node['callers']) + len(node['callees'])

def neigh(nodes, seed, hops=2):
    if seed not in nodes:
        return {}
    out = {seed}
    frontier = {seed}
    for _ in range(hops):
        nxt = set()
        for k in list(frontier):
            n = nodes[k]
            nxt |= {c for c in n['callers'] if c in nodes}
            nxt |= {c for c in n['callees'] if c in nodes}
        frontier = nxt - out
        out |= frontier
    return {k: nodes[k] for k in out}

for bname, nodes in perbin_nodes.items():
    if not bname:
        continue
    # Prepare ranked hubs list
    ranked = sorted(nodes.values(), key=lambda n:(degree(n), n['size']), reverse=True)
    top_hubs = ranked[:30]

    # Seeds: physics/controller from bookmarks + a couple of known candidates
    seeds = []
    for it in (bookmarks.get(bname) or []):
        if (it.get('category') in ('physics','controller')):
            seeds.append(it.get('name'))
    for fallback in ('FUN_00014f80','FUN_000090e0'):
        if fallback in nodes:
            seeds.append(fallback)
    # dedupe, preserve order
    seen = set(); seeds = [s for s in seeds if not (s in seen or seen.add(s))]

    out_path = os.path.join(OUT_DIR, f'mapping_{re.sub(r"[^A-Za-z0-9._-]","_",bname)}.md')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(f'# Mapping for {bname}\n\n')
        # Hubs table
        f.write('## Top hubs (degree-ranked)\n\n')
        f.write('| name | ea | size | in | out | degree | tags |\n')
        f.write('|---|---:|---:|---:|---:|---:|---|\n')
        for n in top_hubs:
            f.write(f"| {n['name']} | 0x{(n['ea'] or 0):08x} | {n['size']} | {len(n['callers'])} | {len(n['callees'])} | {degree(n)} | {', '.join(tags_for(n))} |\n")

        # Seed neighborhoods
        if seeds:
            f.write('\n## Seed neighborhoods (2 hops)\n')
        for s in seeds:
            f.write(f"\n### {s}\n\n")
            nmap = neigh(nodes, s, hops=2)
            if not nmap:
                f.write('_not found_\n')
                continue
            items = sorted(nmap.values(), key=lambda n:(degree(n), n['size']), reverse=True)
            f.write('| name | ea | size | in | out | degree | tags |\n')
            f.write('|---|---:|---:|---:|---:|---:|---|\n')
            for n in items[:50]:
                f.write(f"| {n['name']} | 0x{(n['ea'] or 0):08x} | {n['size']} | {len(n['callers'])} | {len(n['callees'])} | {degree(n)} | {', '.join(tags_for(n))} |\n")

    print('Wrote mapping to', out_path)
