import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_fun_1a558_field_usage.md'
TARGET = 'FUN_0001a558'
# We want to extract lines with pointer arithmetic on first two params or unaff_s0 referencing small offsets (0x0-0x10) OR vertical offsets (0x5c-0x62) to see what belongs to mini vs main.
SMALL_OFF_RE = re.compile(r'\+ 0x0[0-9a-f]\b|\+ 0x10\b')
VERT_OFF_RE = re.compile(r'\+ 0x5c|\+ 0x60|\+ 0x62|\+ 0x38|\+ 0x3c')
PTR_NAMES = ['param_1','param_2','unaff_s0','unaff_s1']


def iter_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except: continue
                if 'function' in obj: yield obj


def main():
    for fn in iter_funcs():
        name=fn['function']['name']
        if name!=TARGET: continue
        dec=fn.get('decompilation') or ''
        lines=dec.splitlines()
        rows=[]
        for idx,l in enumerate(lines, start=1):
            if any(p in l for p in PTR_NAMES) and (SMALL_OFF_RE.search(l) or VERT_OFF_RE.search(l)):
                rows.append((idx,l.strip()))
        with OUT.open('w',encoding='utf-8') as f:
            f.write(f'# Field usage in {TARGET}\n\n')
            for ln,txt in rows:
                f.write(f'- L{ln}: `{txt.replace("|","/")}`\n')
            f.write('\nRaw snippet (truncated):\n\n````\n')
            f.write('\n'.join(lines[:400]))
            f.write('\n````\n')
        print('Wrote', OUT)
        break
    else:
        print('Target function not found')

if __name__=='__main__':
    main()
