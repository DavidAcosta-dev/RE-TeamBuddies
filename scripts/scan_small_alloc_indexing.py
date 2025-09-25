import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_small_alloc_indexing.md'
ALLOC_CALL = 'thunk_FUN_0001f5d4(8)'
INDEX_PATTERN = re.compile(r'\[0x3[bcd]\]')  # capture indices 0x3b 0x3c 0x3d etc.


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
        if ALLOC_CALL not in dec: continue
        if 'FUN_0001a558' not in dec: continue
        name=fn['function']['name']; ea=fn['function']['ea']
        lines=dec.splitlines()
        slot_lines=[(i+1,l.strip()) for i,l in enumerate(lines) if INDEX_PATTERN.search(l)]
        if not slot_lines: continue
        rows.append({'name':name,'ea':f'0x{ea:x}','slots':len(slot_lines),'snippet':'\n'.join(l for _,l in slot_lines[:12])[:600]})
    with OUT.open('w',encoding='utf-8') as f:
        f.write('# Small allocation indexing patterns (slot usage)\n\n')
        if not rows: f.write('No matches.\n'); return
        f.write('| Function | EA | SlotLines |\n|----------|----|----------:|\n')
        for r in rows: f.write(f"| {r['name']} | {r['ea']} | {r['slots']} |\n")
        f.write('\n## Snippets\n\n')
        for r in rows:
            f.write(f"### {r['name']} {r['ea']}\n\n````\n{r['snippet']}\n````\n\n")
    print('Wrote', OUT, 'with', len(rows), 'rows')

if __name__=='__main__':
    main()
