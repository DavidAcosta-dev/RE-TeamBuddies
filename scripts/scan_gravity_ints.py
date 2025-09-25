import json, re
from pathlib import Path
from collections import defaultdict
"""
scan_gravity_ints.py

Second-pass gravity/Y locator focusing on 32-bit fields. Some engines keep vertical velocity
as a 32-bit accumulator while horizontal uses 16-bit shorts. We look for:
  1. In-function coexistence of known horizontal integrator pattern (posX/posZ update) AND
     a separate self-add/sub of an int field with a small constant (<0x1000 magnitude) each frame.
  2. Lines with >> 0xc referencing int pointers *(int *)(base + off) not already known.
  3. Potential pattern: *(int *)(base+pos?) += *(int *)(base+vel?) >> 0xc (two-step sequence), but
     compiler may have produced temporaries.

Outputs:
  exports/gravity_int_candidates.md

This is heuristic; manual review needed.
"""
ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / 'exports'

KNOWN_POS = {0x114:'posX',0x118:'posZ'}
KNOWN_VEL = {0x100:'velX',0x102:'velZ'}

SHIFT_RE = re.compile(r'>>\s*0xc')
INT_ASSIGN_RE = re.compile(r'\*\(int \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,4})\)\s*=\s*\*\(int \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,4})\)\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)')
SELF_MUT_RE = re.compile(r'\*\(int \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,4})\)\s*=\s*\*\(int \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,4})\)\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)')
INT_PTR_RE = re.compile(r'\*\(int \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,4})\)')
HEX = lambda s: int(s,16)

def load_bundles():
    for p in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with p.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip()
                if not line: continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

def parse_const(tok):
    return int(tok,16) if tok.startswith('0x') else int(tok)

def main():
    candidates = defaultdict(lambda:{'score':0,'lines':set(),'features':set()})
    for fn in load_bundles():
        dec = fn.get('decompilation') or ''
        if not dec: continue
        func = fn.get('function') or {}
        name = func.get('name') or ''
        addr = f"0x{(func.get('ea') or 0):x}"
        has_horiz = ('0x114' in dec and '0x118' in dec and '>> 0xc' in dec)
        if not has_horiz:
            continue
        lines = dec.splitlines()
        seen_offsets = set()
        for line in lines:
            if '0x114' in line or '0x118' in line:
                pass
            if SHIFT_RE.search(line):
                # capture int pointer offsets appearing on shift lines
                for m in INT_PTR_RE.finditer(line):
                    off = int(m.group(1),16)
                    if off in KNOWN_POS or off in KNOWN_VEL: continue
                    key = (off,)
                    cand = candidates[key]
                    cand['score'] += 1
                    cand['features'].add('shift_line')
                    if len(cand['lines']) < 8:
                        cand['lines'].add(f"{addr} {name} :: {line.strip()}")
            mm = SELF_MUT_RE.search(line)
            if mm:
                dst = int(mm.group(1),16)
                src = int(mm.group(2),16)
                if dst==src and dst not in KNOWN_POS and dst not in KNOWN_VEL:
                    magnitude = parse_const(mm.group(4))
                    if magnitude < 0x1000:
                        key=(dst,)
                        cand = candidates[key]
                        cand['score'] += 3
                        cand['features'].add('self_addsub_small')
                        if len(cand['lines'])<8:
                            cand['lines'].add(f"{addr} {name} :: {line.strip()}")
    out = EXPORTS / 'gravity_int_candidates.md'
    with out.open('w',encoding='utf-8') as f:
        f.write('# Gravity Int Field Candidates (heuristic)\n\n')
        if not candidates:
            f.write('No int candidates surfaced; consider scanning non-horizontal functions next.\n')
        else:
            f.write('| Offset | Score | Features | Sample (up to 3) |\n')
            f.write('|--------|-------|----------|-----------------|\n')
            for (off,), data in sorted(candidates.items(), key=lambda x: -x[1]['score']):
                feats = ','.join(sorted(data['features']))
                samples = list(data['lines'])[:3]
                f.write(f'| 0x{off:x} | {data['score']} | {feats} | {' || '.join(samples)} |\n')
            f.write('\n---\n\nDetailed Lines\n\n')
            for (off,), data in sorted(candidates.items(), key=lambda x: -x[1]['score']):
                f.write(f'## Offset 0x{off:x}\n\n')
                for ln in data['lines']:
                    f.write(f'- {ln}\n')
                f.write('\n')
    print(f'Wrote {out}')

if __name__ == '__main__':
    main()
