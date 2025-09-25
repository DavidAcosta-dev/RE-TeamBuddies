import json
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_bigstruct_pointer_slots.md'

SLOTS = ['param_1[0x3b]','param_1[0x3c]']

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
        if not any(s in dec for s in SLOTS):
            continue
        # Collect non-assignment reads (heuristic: occurrences not followed by '=' on same line)
        reads=[]; writes=[]
        for li,l in enumerate(dec.splitlines()):
            if 'param_1[0x3b]' in l or 'param_1[0x3c]' in l:
                if '=' in l and ('param_1[0x3b] =' in l or 'param_1[0x3c] =' in l):
                    writes.append(li+1)
                else:
                    reads.append(li+1)
        rows.append({'name':fn['function']['name'],'ea':f"0x{fn['function']['ea']:x}",'reads':reads,'writes':writes})
    with OUT.open('w',encoding='utf-8') as f:
        f.write('# Big struct pointer slot usage (indices 0x3b / 0x3c)\n\n')
        if not rows:
            f.write('No occurrences found.\n'); return
        f.write('| Function | EA | Reads | Writes |\n|----------|----|------:|-------:|\n')
        for r in rows:
            f.write(f"| {r['name']} | {r['ea']} | {len(r['reads'])} | {len(r['writes'])} |\n")
        f.write('\n## Detail\n\n')
        for r in rows:
            f.write(f"### {r['name']} {r['ea']}\n\nReads: {r['reads']}\n\nWrites: {r['writes']}\n\n")
    print('Wrote', OUT.name, 'with', len(rows), 'functions')

if __name__=='__main__':
    main()
