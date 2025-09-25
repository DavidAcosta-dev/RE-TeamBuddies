import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_offset_0x88_write_classes.md'

# Capture writes to either param_1 or unaff_s0 variants
WRITE_PATTERNS = [
    re.compile(r'\([^)]*param_1 \+ 0x88\)\s*='),
    re.compile(r'\([^)]*unaff_s0 \+ 0x88\)\s*='),
]

def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except: continue
                if 'function' in obj: yield obj

def classify(line:str)->str:
    line_s = line.replace(' ','')
    if '=0;' in line_s: return 'zero'
    if '=1;' in line_s: return 'one'
    if '=0xffff;' in line_s or '=0xFFFF;' in line_s: return 'neg1'
    if 'unaff_gp' in line: return 'gp_rel'
    # Heuristic: function call on RHS (e.g., = param_2; is other_func_call? treat identifiers w/o numeric immediates)
    if '=' in line and '(' in line.split('=')[1] and ')' in line.split('=')[1]:
        return 'other_func_call'
    return 'other'

def main():
    rows=[]
    for fn in iter_funcs():
        dec = fn.get('decompilation') or ''
        if '+ 0x88' not in dec: continue
        name=fn['function']['name']; ea=fn['function']['ea']
        for ln,l in enumerate(dec.splitlines(), start=1):
            if '=' not in l: continue
            if any(p.search(l) for p in WRITE_PATTERNS):
                rows.append({'fn':name,'ea':f'0x{ea:x}','line':ln,'cls':classify(l),'code':l.strip()})
    rows.sort(key=lambda r:(r['fn'],r['line']))
    with OUT.open('w',encoding='utf-8') as f:
        f.write('# Categorized +0x88 writes (param_1 & unaff_s0)\n\n')
        if not rows:
            f.write('No writes found.\n'); return
        f.write('| Function | EA | Line | Class | Code |\n|----------|----|------|-------|------|\n')
        for r in rows:
            f.write(f"| {r['fn']} | {r['ea']} | {r['line']} | {r['cls']} | `{r['code'].replace('|','\\|')}` |\n")
    print('Wrote', OUT.name, 'with', len(rows), 'writes')

if __name__=='__main__':
    main()
