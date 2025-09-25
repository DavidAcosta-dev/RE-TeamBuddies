import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_double_fastpath_sequences.md'
FAST = 'FUN_0001a558'
RE_FAST = re.compile(rf'{FAST}\/\*')  # fallback if comments inserted
CALL_FAST = re.compile(rf'\b{FAST}\s*\(')
MAX_GAP = 8


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
        if FAST not in dec: continue
        lines=dec.splitlines()
        call_idxs=[i for i,l in enumerate(lines) if CALL_FAST.search(l)]
        if len(call_idxs)<2: continue
        # find pairs with small gap
        for a,b in zip(call_idxs, call_idxs[1:]):
            if 0 < b-a <= MAX_GAP:
                snippet='\n'.join(lines[a-2 if a>=2 else 0: b+3])
                rows.append({'fn':fn['function']['name'],'ea':f"0x{fn['function']['ea']:x}",'first':a+1,'second':b+1,'gap':b-a,'snippet':snippet[:600].replace('`','\'')})
                break
    rows.sort(key=lambda r:r['gap'])
    with open(OUT,'w',encoding='utf-8') as f:
        f.write('# Functions with double fast-path FUN_0001a558 calls (short gap)\n\n')
        if not rows:
            f.write('No sequences found.\n'); return
        f.write('| Function | EA | firstLine | secondLine | gap |\n|----------|----|----------:|-----------:|----:|\n')
        for r in rows:
            f.write(f"| {r['fn']} | {r['ea']} | {r['first']} | {r['second']} | {r['gap']} |\n")
        f.write('\n## Snippets\n\n')
        for r in rows:
            f.write(f"### {r['fn']} {r['ea']} gap={r['gap']}\n\n````\n{r['snippet']}\n````\n\n")
    print('Wrote', OUT, 'with', len(rows), 'rows')

if __name__=='__main__':
    main()
