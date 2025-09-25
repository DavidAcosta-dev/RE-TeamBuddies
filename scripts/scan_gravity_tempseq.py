import json,re
from pathlib import Path
from collections import defaultdict
"""
scan_gravity_tempseq.py

Detect 3-line load-modify-store sequences indicating a possible gravity decrement:
  v = *(short|int *)(BASE + OFF)
  v = v - CONST   (CONST small)
  *(short|int *)(BASE + OFF) = v

Also supports += for completeness but gravity focus is '-'.

Output: exports/gravity_tempseq_candidates.md
"""
ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / 'exports'

LOAD_RE = re.compile(r'^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\*\((short|int) \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,4})\)')
MOD_RE  = re.compile(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\1\s*([-+])\s*(0x[0-9a-fA-F]+|\d+)')
STORE_RE= re.compile(r'^\s*\*\((short|int) \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,4})\)\s*=\s*([a-zA-Z_][a-zA-Z0-9_]*)')

IGNORE_OFFSETS = {0x100,0x102,0x114,0x118}

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
    seqs = defaultdict(lambda:{'neg':0,'pos':0,'samples':[]})
    for fn in load_bundles():
        dec = fn.get('decompilation') or ''
        if not dec: continue
        func = fn.get('function') or {}
        fname = func.get('name') or ''
        addr_base = f"0x{(func.get('ea') or 0):x}"
        lines = dec.splitlines()
        for i in range(len(lines)-2):
            l1,l2,l3 = lines[i],lines[i+1],lines[i+2]
            m1 = LOAD_RE.search(l1)
            if not m1: continue
            var = m1.group(2); typ = m1.group(3); off = int(m1.group(4),16)
            if off in IGNORE_OFFSETS: continue
            m2 = MOD_RE.search(l2)
            if not m2 or m2.group(1)!=var: continue
            sign = m2.group(2); val = parse_const(m2.group(3))
            if val >= 0x1000: continue
            m3 = STORE_RE.search(l3)
            if not m3: continue
            if m3.group(3)!=var: continue
            off2 = int(m3.group(2),16)
            if off!=off2: continue
            entry = seqs[off]
            if sign=='-': entry['neg'] +=1
            else: entry['pos'] +=1
            if len(entry['samples'])<5:
                entry['samples'].append(f"{addr_base} {fname} :: {l1.strip()} | {l2.strip()} | {l3.strip()}")
    out = EXPORTS / 'gravity_tempseq_candidates.md'
    with out.open('w',encoding='utf-8') as f:
        f.write('# Gravity Temp Sequence Candidates (load-modify-store)\n\n')
        if not seqs:
            f.write('No sequences detected under current heuristic.\n')
            return
        f.write('| Offset | NegSeq | PosSeq | Sample |\n')
        f.write('|--------|--------|--------|--------|\n')
        for off,data in sorted(seqs.items(), key=lambda x: -(x[1]['neg']*2 + x[1]['pos'])):
            sample = data['samples'][0] if data['samples'] else ''
            f.write(f"| 0x{off:x} | {data['neg']} | {data['pos']} | {sample} |\n")
        f.write('\n---\n\n## Detailed Samples\n\n')
        for off,data in sorted(seqs.items(), key=lambda x: -(x[1]['neg']*2 + x[1]['pos'])):
            f.write(f"### Offset 0x{off:x}\n\n")
            for s in data['samples']:
                f.write(f"- {s}\n")
            f.write('\n')
    print(f'Wrote {out}')

if __name__=='__main__':
    main()
