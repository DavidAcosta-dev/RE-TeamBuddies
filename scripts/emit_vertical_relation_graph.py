import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_relation_graph.md'
NODES = set()
EDGES = []  # tuples (caller, callee, kind)
TARGETS = ['FUN_0001a558','FUN_0001abfc','FUN_0001a320','FUN_0001a614']
EMITS = ['FUN_0002d220','FUN_0002d1a4']
ALLOC = 'thunk_FUN_0001f5d4'

CALL_RE = {t: re.compile(rf"\b{t}\s*\(") for t in TARGETS+EMITS+[ALLOC]}


def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except: continue
                if 'function' in obj: yield obj


def main():
    for fn in iter_funcs():
        name=fn['function']['name']
        dec=fn.get('decompilation') or ''
        if not any(r.search(dec) for r in CALL_RE.values()):
            continue
        for tgt,cre in CALL_RE.items():
            if cre.search(dec) and name!=tgt:
                kind='emit' if tgt in EMITS else ('alloc' if tgt==ALLOC else 'vertical')
                NODES.add(name); NODES.add(tgt)
                EDGES.append((name,tgt,kind))
    with OUT.open('w',encoding='utf-8') as f:
        f.write('# Vertical subsystem relation graph (text)\n\n')
        if not EDGES:
            f.write('No edges found.')
            return
        f.write('## Edges\n')
        for c,cal,kind in EDGES:
            f.write(f'- {c} -> {cal} ({kind})\n')
        f.write('\n## Nodes\n')
        for n in sorted(NODES):
            f.write(f'- {n}\n')
    print('Wrote', OUT, 'with', len(EDGES), 'edges')

if __name__=='__main__':
    main()
