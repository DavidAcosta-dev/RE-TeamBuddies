import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_secondary_ptr_size_inference.md'
# Try to infer size of objects allocated then stored into primary+0x11c or later passed to vertical updaters.
# Look for immediate constants in thunk_FUN_0001f5d4 calls (size parameter) and sequences of field zeroing after allocation.
ALLOC_RE = re.compile(r'thunk_FUN_0001f5d4\((0x[0-9a-fA-F]+|\d+)\)')
STORE_SEC_PTR = re.compile(r'\+ 0x11c\) =')
FIELD_ZERO = re.compile(r'= 0;')

WINDOW = 40

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
        if 'thunk_FUN_0001f5d4' not in dec: continue
        lines=dec.splitlines()
        allocs=[(i,l) for i,l in enumerate(lines) if ALLOC_RE.search(l)]
        if not allocs: continue
        for idx,line in allocs:
            m = ALLOC_RE.search(line)
            size = m.group(1) if m else '?'
            window_lines = lines[idx: min(len(lines), idx+WINDOW)]
            zero_count = sum(1 for wl in window_lines if FIELD_ZERO.search(wl))
            store_sec = any('+ 0x11c' in wl and '=' in wl for wl in window_lines)
            updater_call = any('FUN_0001a558' in wl or 'FUN_0001abfc' in wl for wl in window_lines)
            rows.append({'fn':fn['function']['name'],'ea':f"0x{fn['function']['ea']:x}", 'size':size,'zeros':zero_count,'stores_sec':store_sec,'updater':updater_call})
    if rows:
        rows.sort(key=lambda r:(r['size'], -r['zeros']))
    with open(OUT,'w',encoding='utf-8') as f:
        f.write('# Secondary / mini-vertical allocation size inference\n\n')
        if not rows:
            f.write('No allocation patterns detected.\n'); return
        f.write('| Function | EA | SizeArg | ZeroWritesInWindow | StoresTo+0x11c | UpdaterCallInWindow |\n')
        f.write('|----------|----|--------:|------------------:|----------------|---------------------|\n')
        for r in rows:
            f.write(f"| {r['fn']} | {r['ea']} | {r['size']} | {r['zeros']} | {int(r['stores_sec'])} | {int(r['updater'])} |\n")
    print('Wrote', OUT, 'with', len(rows), 'allocation rows')

if __name__=='__main__':
    main()
