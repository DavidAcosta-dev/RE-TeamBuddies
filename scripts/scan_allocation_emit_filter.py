import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_alloc_emit_filter.md'
ALLOC_RE = re.compile(r'thunk_FUN_0001f5d4\((0x[0-9a-fA-F]+|\d+)\)')
EMIT_RE = re.compile(r'FUN_0001a558\s*\(')
DECORATE_RE = re.compile(r'FUN_000233dc\s*\(')


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
        if 'thunk_FUN_0001f5d4(8)' not in dec or 'FUN_0001a558' not in dec:
            continue
        if 'FUN_000233dc' not in dec: # ensure initializer decoration call present
            continue
        name=fn['function']['name']; ea=fn['function']['ea']
        allocs=len(ALLOC_RE.findall(dec))
        emits=len(EMIT_RE.findall(dec))
        decos=len(DECORATE_RE.findall(dec))
        rows.append({'name':name,'ea':f'0x{ea:x}','allocs':allocs,'emits':emits,'decor':decos})
    rows.sort(key=lambda r:(-r['emits'], -r['allocs']))
    with open(OUT,'w',encoding='utf-8') as f:
        f.write('# Filtered allocation + emit + decorate functions\n\n')
        if not rows:
            f.write('No matches.\n'); return
        f.write('| Function | EA | alloc(8) | emits | decorCalls | emits/alloc |\n|----------|----|---------:|------:|-----------:|-------------:|\n')
        for r in rows:
            ratio = f"{r['emits']/r['allocs']:.2f}" if r['allocs'] else 'n/a'
            f.write(f"| {r['name']} | {r['ea']} | {r['allocs']} | {r['emits']} | {r['decor']} | {ratio} |\n")
    print('Wrote', OUT, 'with', len(rows), 'rows')

if __name__=='__main__':
    main()
