import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_fastpath_signature_callers.md'
# Core pattern fragments:
#   *(short *)(X + 0x60) * *(short *)(X + 0x62)
#   >> 1 or >> 0x1
#   FUN_0002d220(
#   ^= 1 (xor toggle) on +0x3c or +0x38

MULT_RE = re.compile(r"\(param_1 \+ 0x60\).*\(param_1 \+ 0x62\)")
EMIT_CALL = re.compile(r'FUN_0002d220\s*\(')
XOR_TOGGLE = re.compile(r'\^=\s*1')
OFFSET_TOGGLE = re.compile(r'\+ 0x3c|\+ 0x38')

# We'll allow unaff_s0 too
ALT_MULT_RE = re.compile(r"unaff_s0 \+ 0x60.*unaff_s0 \+ 0x62")
ALT_OFFSET = re.compile(r'unaff_s0 \+ 0x3c|unaff_s0 \+ 0x38')


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
        dec = fn.get('decompilation') or ''
        if 'FUN_0002d220' not in dec: continue
        if not ((' + 0x60' in dec and ' + 0x62' in dec) or ('unaff_s0 + 0x60' in dec)):
            continue
        # quick gating: must have xor and toggle offset
        if '^=' not in dec: continue
        name = fn['function']['name']; ea = fn['function']['ea']
        score=0
        if MULT_RE.search(dec) or ALT_MULT_RE.search(dec): score+=2
        if EMIT_CALL.search(dec): score+=2
        xor_lines=[l for l in dec.splitlines() if '^=' in l and ('0x3c' in l or '0x38' in l)]
        score+=len(xor_lines)
        if score>=4:
            snippet='\n'.join([l for l in dec.splitlines() if any(k in l for k in ['0x60','0x62','0x3c','0x38','FUN_0002d220','^='])])
            rows.append({'name':name,'ea':f'0x{ea:x}','score':score,'xor_count':len(xor_lines),'snippet':snippet[:800].replace('`','\'')})
    with OUT.open('w',encoding='utf-8') as f:
        f.write('# Fast-path vertical signature candidate callers\n\n')
        if not rows:
            f.write('No candidates found.\n'); return
        rows.sort(key=lambda r:r['score'], reverse=True)
        f.write('| Function | EA | Score | XOR Toggles |\n|----------|----|-------|-------------|\n')
        for r in rows:
            f.write(f"| {r['name']} | {r['ea']} | {r['score']} | {r['xor_count']} |\n")
        f.write('\n## Snippets\n\n')
        for r in rows:
            f.write(f"### {r['name']} ({r['ea']}) score={r['score']}\n\n````\n{r['snippet']}\n````\n\n")
    print('Wrote', OUT.name, 'with', len(rows), 'candidates')

if __name__=='__main__':
    main()
