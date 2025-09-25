import re, pathlib, json
from pathlib import Path

AMPS = ['0x4c','0x4e','0x50','0x52','0x54','0x56','0x58','0x5a']
PAT = re.compile(r'\+\s*0x(4c|4e|50|52|54|56|58|5a)')
skip_writers = {'FUN_0001a320','FUN_0001abfc','FUN_0001a528','FUN_0001a558','FUN_0001a614'}
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
    rows=[]
    for fn in iter_funcs():
        dec = fn.get('decompilation') or ''
        if not any(off in dec for off in AMPS):
            continue
        name = fn['function']['name']; ea = fn['function']['ea']
        for i,l in enumerate(dec.splitlines(), start=1):
            if PAT.search(l):
                is_write = '(param_1 +' in l and '=' in l and l.strip().startswith('*(')
                if name in skip_writers and is_write:
                    continue
                rows.append({'function':name,'ea':f'0x{ea:x}','line':i,'class':'write' if is_write else 'read','code':l.strip()})
    out = pathlib.Path('exports/vertical_amplitude_consumers.md')
    with out.open('w',encoding='utf-8') as f:
        f.write('# Potential amplitude field consumers (reads/writes outside core writers)\n\n')
        if not rows:
            f.write('No external consumers found.\n')
            return
        f.write('| Function | EA | Line | Class | Code |\n|----------|----|------|-------|------|\n')
        for r in rows:
            f.write(f"| {r['function']} | {r['ea']} | {r['line']} | {r['class']} | `{r['code'].replace('|','\\|')}` |\n")
    print(f'Wrote {len(rows)} amplitude consumer rows')

if __name__=='__main__':
    main()
