import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_bank_population.md'

# Look for assignments into (param_1 + 4|8|0xC|0x10) or (unaff_s0 + ... ) patterns.
ASSIGN_RE = re.compile(r"=.+(param_1 \+ (4|8|0xC|0x10)|unaff_s0 \+ (4|8|0xC|0x10))")
TARGET_OFFS = (' + 4)', ' + 8)', ' + 0xC', ' + 0x10')

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
        if not any(off in dec for off in TARGET_OFFS):
            continue
        hits=[]
        for li,l in enumerate(dec.splitlines()):
            if any(off in l for off in TARGET_OFFS) and ('=' in l) and ('*(' in l):
                # heuristic: potential store
                if 'FUN_0002d1a4' in l or 'FUN_0002d220' in l:
                    continue  # skip argument usage
                hits.append((li+1,l.strip()))
        if hits:
            rows.append({'name':fn['function']['name'],'ea':f"0x{fn['function']['ea']:x}",'hits':hits[:8]})
    rows.sort(key=lambda r: len(r['hits']), reverse=True)
    with OUT.open('w',encoding='utf-8') as f:
        f.write('# Candidate bank population writes into low offsets (4/8/0xC/0x10)\n\n')
        if not rows:
            f.write('No candidate population stores found.\n')
            return
        f.write('| Function | EA | Count |\n|----------|----|------:|\n')
        for r in rows:
            f.write(f"| {r['name']} | {r['ea']} | {len(r['hits'])} |\n")
        f.write('\n## Snippets\n\n')
        for r in rows[:40]:
            f.write(f"### {r['name']} {r['ea']} ({len(r['hits'])})\n\n````\n")
            for (ln,txt) in r['hits']:
                f.write(f"L{ln:04d}: {txt}\n")
            f.write('````\n\n')
    print('Wrote', OUT.name, 'with', len(rows), 'functions')

if __name__=='__main__':
    main()
