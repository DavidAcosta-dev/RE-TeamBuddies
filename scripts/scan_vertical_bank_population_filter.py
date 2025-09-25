import json
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_bank_population_filtered.md'

KEY_FUNCS = {'FUN_0002d1a4','FUN_0002d220'}
LOW_OFFS = [' + 4)', ' + 8)', ' + 0xC)', ' + 0x10)']

def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except: continue
                if 'function' in obj: yield obj

def main():
    candidates=[]
    for fn in iter_funcs():
        dec = fn.get('decompilation') or ''
        if not any(off in dec for off in LOW_OFFS):
            continue
        if not any(k in dec for k in KEY_FUNCS):
            continue
        if 'thunk_FUN_0001f5d4(8)' in dec:  # likely orchestrator; already known
            continue
        # Collect suspicious store lines (assignment into low offset)
        store_lines=[]
        for li,l in enumerate(dec.splitlines()):
            if '=' in l and any(off in l for off in LOW_OFFS) and ('FUN_0002d1a4' not in l and 'FUN_0002d220' not in l):
                store_lines.append((li+1,l.strip()))
        if store_lines:
            candidates.append({
                'name':fn['function']['name'],
                'ea':f"0x{fn['function']['ea']:x}",
                'stores':store_lines[:12],
                'store_count':len(store_lines)
            })
    candidates.sort(key=lambda c:c['store_count'], reverse=True)
    with OUT.open('w',encoding='utf-8') as f:
        f.write('# Filtered low-offset bank population candidates (with emit funcs present)\n\n')
        if not candidates:
            f.write('No filtered candidates.\n'); return
        f.write('| Function | EA | storeCount |\n|----------|----|----------:|\n')
        for c in candidates:
            f.write(f"| {c['name']} | {c['ea']} | {c['store_count']} |\n")
        f.write('\n## Snippets\n\n')
        for c in candidates[:50]:
            f.write(f"### {c['name']} {c['ea']} ({c['store_count']})\n\n````\n")
            for (ln,txt) in c['stores']:
                f.write(f"L{ln:04d}: {txt}\n")
            f.write('````\n\n')
    print('Wrote', OUT.name, 'with', len(candidates), 'candidates')

if __name__=='__main__':
    main()
