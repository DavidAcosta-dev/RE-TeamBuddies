import json, sys
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'fun_window.md'

def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj = json.loads(line)
                except: continue
                if 'function' in obj: yield obj

def main():
    if len(sys.argv) < 3:
        print('Usage: python scripts/scan_fun_window.py <FUNC_NAME|EA_HEX> <context_lines> [output_name]')
        return
    ident = sys.argv[1]
    ctx = int(sys.argv[2])
    out_name = sys.argv[3] if len(sys.argv) > 3 else 'fun_window.md'
    out_path = EXPORTS / out_name
    want_ea = None
    want_name = None
    if ident.lower().startswith('0x'):
        try: want_ea = int(ident, 16)
        except ValueError: pass
    else:
        want_name = ident
    matches = []
    for fn in iter_funcs():
        func = fn['function']
        if want_name and func['name'] != want_name: continue
        if want_ea is not None and func['ea'] != want_ea: continue
        matches.append(fn)
    if not matches:
        print('No matches found')
        return
    target = matches[0]
    dec = (target.get('decompilation') or '').splitlines()
    # Annotate lines containing allocation or fastpath calls for window centering.
    key_indices=[]
    for i,l in enumerate(dec):
        if 'thunk_FUN_0001f5d4(8)' in l or 'FUN_0001a558' in l:
            key_indices.append(i)
    with out_path.open('w', encoding='utf-8') as f:
        f.write(f"# Function window: {target['function']['name']} 0x{target['function']['ea']:x}\n\n")
        if not key_indices:
            f.write('No key lines found. Full function omitted.\n')
        for idx in key_indices:
            start = max(0, idx - ctx)
            end = min(len(dec), idx + ctx + 1)
            f.write(f"## Window around line {idx+1}\n\n")
            for j in range(start, end):
                mark = '>' if j == idx else ' '
                line_txt = dec[j]
                # highlight potential bank writes
                if (
                    ('+ 4)' in line_txt)
                    or ('+ 8)' in line_txt)
                    or ('+ 0xC)' in line_txt)
                    or ('+ 0x10)' in line_txt)
                ) and ('=' in line_txt):
                    mark='*'
                f.write(f"{mark}{j+1:04d}: {line_txt}\n")
            f.write('\n')
    print('Wrote', out_path.name, 'windows for', len(key_indices), 'key lines')

if __name__ == '__main__':
    main()
