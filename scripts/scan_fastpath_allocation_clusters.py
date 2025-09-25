import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_fastpath_allocation_clusters.md'
# Detect patterns where a small allocation (thunk_FUN_0001f5d4(8)) result feeds FUN_0001a558 quickly.
ALLOC_RE = re.compile(r'thunk_FUN_0001f5d4\(8\)')
FAST_RE = re.compile(r'FUN_0001a558\s*\(')
ZERO_GATE_RE = re.compile(r'\+ 0x88\) = 0')

WINDOW = 14


def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except: continue
                if 'function' in obj: yield obj

def main():
    clusters=[]
    for fn in iter_funcs():
        dec=fn.get('decompilation') or ''
        if 'FUN_0001a558' not in dec or 'thunk_FUN_0001f5d4(8)' not in dec:
            continue
        lines=dec.splitlines()
        alloc_idxs=[i for i,l in enumerate(lines) if ALLOC_RE.search(l)]
        fast_idxs=[i for i,l in enumerate(lines) if FAST_RE.search(l)]
        if not alloc_idxs or not fast_idxs: continue
        # Pair first occurrence windows
        for a in alloc_idxs:
            near=[f for f in fast_idxs if 0 < f-a <= WINDOW]
            if near:
                snippet='\n'.join(lines[a-2 if a>=2 else 0: min(near[-1]+3, len(lines))])
                clusters.append({
                    'fn': fn['function']['name'],
                    'ea': f"0x{fn['function']['ea']:x}",
                    'alloc_line': a+1,
                    'fast_line': near[0]+1,
                    'distance': near[0]-a,
                    'zero_gate': bool(ZERO_GATE_RE.search(snippet)),
                    'snippet': snippet[:800].replace('`','\'')
                })
                break
    clusters.sort(key=lambda c:(c['distance'], c['fn']))
    with OUT.open('w',encoding='utf-8') as f:
        f.write('# Fast-path allocation -> updater clusters\n\n')
        if not clusters:
            f.write('No clusters detected.\n'); return
        f.write('| Function | EA | alloc@ | fast@ | dist | zeroGateInWindow |\n|----------|----|-------:|------:|-----:|------------------:|\n')
        for c in clusters:
            f.write(f"| {c['fn']} | {c['ea']} | {c['alloc_line']} | {c['fast_line']} | {c['distance']} | {1 if c['zero_gate'] else 0} |\n")
        f.write('\n## Snippets\n\n')
        for c in clusters:
            f.write(f"### {c['fn']} {c['ea']} dist={c['distance']}\n\n````\n{c['snippet']}\n````\n\n")
    print('Wrote', OUT.name, 'with', len(clusters), 'clusters')

if __name__=='__main__':
    main()
