import json
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_relaxed_fastpath_allocs.md'

WINDOW = 20

def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except: continue
                if 'function' in obj: yield obj

def main():
    rows=[]
    for fn in iter_funcs():
        dec=fn.get('decompilation') or ''
        if 'FUN_0001a558' not in dec:
            continue
        lines=dec.splitlines()
        call_idxs=[i for i,l in enumerate(lines) if 'FUN_0001a558' in l]
        alloc_idxs=[i for i,l in enumerate(lines) if 'thunk_FUN_0001f5d4(8)' in l]
        if not call_idxs: continue
        best=None
        for c in call_idxs:
            prev_alloc=[a for a in alloc_idxs if 0 < c-a <= WINDOW]
            if prev_alloc:
                dist = c-prev_alloc[-1]
                best = (prev_alloc[-1], c, dist)
                break
        rows.append({
            'name':fn['function']['name'],
            'ea':f"0x{fn['function']['ea']:x}",
            'call_count':len(call_idxs),
            'alloc_count':len(alloc_idxs),
            'has_near_alloc': best is not None,
            'distance': best[2] if best else '',
        })
    rows.sort(key=lambda r:(0 if r['has_near_alloc'] else 1, r['distance'] if isinstance(r['distance'], int) else 9999, -r['call_count']))
    with (EXPORTS / 'vertical_relaxed_fastpath_allocs.md').open('w',encoding='utf-8') as f:
        f.write('# Relaxed fast-path allocation proximity scan\n\n')
        if not rows:
            f.write('No functions call FUN_0001a558.\n'); return
        f.write('| Function | EA | fastCalls | allocCalls | nearAlloc | dist |\n|----------|----|----------:|-----------:|----------:|-----:|\n')
        for r in rows:
            f.write(f"| {r['name']} | {r['ea']} | {r['call_count']} | {r['alloc_count']} | {1 if r['has_near_alloc'] else 0} | {r['distance']} |\n")
    print('Wrote vertical_relaxed_fastpath_allocs.md with', len(rows), 'rows')

if __name__=='__main__':
    main()
