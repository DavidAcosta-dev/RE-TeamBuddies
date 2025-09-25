import re, json, pathlib
from pathlib import Path

TARGET_OFF = '0x88'
PAT = re.compile(r'\+\s*0x88[) ]')

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'

def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except Exception: continue
                if 'function' in obj: yield obj

def main():
    rows = []
    for fn in iter_funcs():
        dec = fn.get('decompilation') or ''
        if '+ 0x88' not in dec: continue
        name = fn['function']['name']; ea = fn['function']['ea']
        for i,l in enumerate(dec.splitlines(), start=1):
            if '(param_1 + 0x88)' in l or '(unaff_s0 + 0x88)' in l or '+ 0x88)' in l:
                cls = 'write' if '= *(short *)(param_1 + 0x88)' in l or '(param_1 + 0x88) =' in l else 'unknown'
                rows.append({'function':name,'ea':f'0x{ea:x}','line':i,'class':cls,'code':l.strip()})
    out = pathlib.Path('exports/vertical_offset_0x88_usage.md')
    with out.open('w',encoding='utf-8') as f:
        f.write('# Usage of offset +0x88 in secondary vertical context\n\n')
        if not rows:
            f.write('No matches found.\n')
            return
        f.write('| Function | EA | Line | Class | Code |\n|----------|----|------|-------|------|\n')
        for r in rows:
            f.write(f"| {r['function']} | {r['ea']} | {r['line']} | {r['class']} | `{r['code'].replace('|','\\|')}` |\n")
    print(f'Wrote {len(rows)} +0x88 rows')

if __name__=='__main__':
    main()
