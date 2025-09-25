import json, sys
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'

def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except: continue
                if 'function' in obj: yield obj

def main():
    if len(sys.argv) < 2:
        print('Usage: python scripts/extract_fun_lines.py <FUNC_NAME|EA_HEX>'); return
    ident = sys.argv[1]
    want_ea=None; want_name=None
    if ident.lower().startswith('0x'):
        try: want_ea=int(ident,16)
        except ValueError: print('Bad EA'); return
    else:
        want_name=ident
    for fn in iter_funcs():
        func=fn['function']
        if want_name and func['name']!=want_name: continue
        if want_ea is not None and func['ea']!=want_ea: continue
        dec=(fn.get('decompilation') or '').splitlines()
        for i,l in enumerate(dec, start=1):
            print(f"{i:04d}: {l}")
        return
    print('Not found')

if __name__=='__main__':
    main()
