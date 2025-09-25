import json,re
from pathlib import Path
from collections import defaultdict,deque
"""
scan_cratepath_negative_mutations.py

Restrict search to functions reachable (downstream) from crate throw/pickup seeds
within a limited BFS depth; then look for in-place negative decrements on shorts/ints.

Seeds (adjust names as overlays evolve):
  crate_throw_start
  crate_pickup_start

Output: exports/cratepath_neg_mutations.md
"""
ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / 'exports'

# Updated seeds: raw FUN_* names identified by scan_crate_signatures.py as high-probability crate logic.
# We include several large + small functions to cover state entry, per-frame, and secondary/effects paths.
# Depth increased slightly (5) to reach gravity helper if it sits one layer deeper.
SEEDS = {
    ('MAIN.EXE','FUN_00008528'),
    ('MAIN.EXE','FUN_000090e0'),
    ('MAIN.EXE','FUN_00009708'),
    ('MAIN.EXE','FUN_0001a348'),
    ('MAIN.EXE','FUN_00038748'),
    ('MAIN.EXE','FUN_0003baf8'),
    # Optionally add medium-score candidates:
    ('MAIN.EXE','FUN_00005e70'),
    ('MAIN.EXE','FUN_000063c4'),
}

MUT_SHORT = re.compile(r'\*(?:short|undefined2) \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,4})\)\s*=\s*\*(?:short|undefined2) \*\)\([^)]*\+ 0x\1\)\s*-\s*(0x[0-9a-fA-F]+|\d+)')
MUT_INT   = re.compile(r'\*\(int \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,4})\)\s*=\s*\*\(int \*\)\([^)]*\+ 0x\1\)\s*-\s*(0x[0-9a-fA-F]+|\d+)')
IGN = {0x100,0x102,0x114,0x118}

# Build graph from bundles (callee names) per binary

def load():
    for p in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with p.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip()
                if not line: continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def build_graph():
    graph = defaultdict(set)
    meta = {}
    for fn in load():
        b = fn.get('binary')
        func = fn.get('function') or {}
        name = func.get('name') or ''
        key = (b,name)
        meta[key]=fn
        for cal in fn.get('callees') or []:
            graph[key].add((b,cal))
    return graph,meta


MAX_DEPTH = 5

def bfs(graph, start):
    dist={start:0}
    q=deque([start])
    while q:
        cur=q.popleft(); d=dist[cur]
        if d>=MAX_DEPTH: continue
        for nxt in graph.get(cur,()):
            if nxt[0]!=cur[0]:
                continue
            if nxt not in dist:
                dist[nxt]=d+1
                q.append(nxt)
    return dist


def parse_const(tok):
    return int(tok,16) if tok.startswith('0x') else int(tok)


def main():
    graph,meta = build_graph()
    frontier=set()
    for s in SEEDS:
        if s in meta:
            frontier.update(bfs(graph,s).keys())
    if not frontier:
        print('No seed functions located; aborting.')
        return
    hits=defaultdict(lambda:{'count':0,'funcs':set(),'samples':[],'type':set(),'magnitudes':[]})
    for key in frontier:
        fn = meta.get(key)
        if not fn: continue
        dec = fn.get('decompilation') or ''
        func = fn.get('function') or {}
        fname = func.get('name') or ''
        addr = f"0x{(func.get('ea') or 0):x}"
        for line in dec.splitlines():
            for pat,kind in ((MUT_SHORT,'short'),(MUT_INT,'int')):
                m = pat.search(line)
                if not m: continue
                off = int(m.group(1),16)
                if off in IGN: continue
                val = parse_const(m.group(2))
                if val >= 0x2000: continue
                entry = hits[off]
                entry['count']+=1
                entry['funcs'].add(fname)
                entry['type'].add(kind)
                entry['magnitudes'].append(val)
                if len(entry['samples'])<5:
                    entry['samples'].append(f"{addr} {fname} :: {line.strip()}")
    out = EXPORTS / 'cratepath_neg_mutations.md'
    with out.open('w',encoding='utf-8') as f:
        f.write('# Crate Path Negative Self-Mutations (potential gravity)\n\n')
        if not hits:
            f.write(f'No negative self-mutations found on crate path within depth {MAX_DEPTH}.\n')
            f.write('\n_Note: Gravity may be applied via helper return value or indirect constant; next step is non-literal pattern scan (load -> add const -> store different field).\n')
            return
        f.write('| Offset | Count | Funcs | Types | AvgMag | Sample |\n')
        f.write('|--------|-------|-------|-------|--------|--------|\n')
        for off,data in sorted(hits.items(), key=lambda x: -x[1]['count']):
            avg = sum(data['magnitudes'])/len(data['magnitudes']) if data['magnitudes'] else 0
            sample = data['samples'][0] if data['samples'] else ''
            f.write(f"| 0x{off:x} | {data['count']} | {len(data['funcs'])} | {','.join(sorted(data['type']))} | {avg:.1f} | {sample} |\n")
        f.write('\n---\n\n## Detailed Samples\n\n')
        for off,data in sorted(hits.items(), key=lambda x: -x[1]['count']):
            f.write(f"### Offset 0x{off:x}\n\n")
            for s in data['samples']:
                f.write(f"- {s}\n")
            f.write('\n')
    print(f'Wrote {out}')

if __name__=='__main__':
    main()
