import json, re
from pathlib import Path
from collections import defaultdict
"""
scan_gravity_broad.py

Broader heuristic pass to surface ANY self add/sub of small constants on short or int fields
without requiring simultaneous horizontal integrator presence. Goal: identify recurring
candidate vertical velocity (gravity affected) fields missed by earlier scans.

Heuristics:
  - Match patterns of form *(short*)(base+OFF) = *(short*)(base+OFF) +/- CONST
  - Likewise for *(int*)(base+OFF)
  - CONST magnitude < 0x1000 (fixed-point style small per-frame delta)
  - Count frequency across all functions; track distinct functions referencing same offset.
  - Capture up to N sample lines for each offset.

Output: exports/gravity_broad_candidates.md
"""
ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / 'exports'

SHORT_MUT = re.compile(r'\*(?:short|undefined2) \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,4})\)\s*=\s*\*(?:short|undefined2) \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,4})\)\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)')
INT_MUT = re.compile(r'\*\(int \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,4})\)\s*=\s*\*\(int \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,4})\)\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)')

KNOWN_IGNORE = {0x100,0x102,0x114,0x118}  # already mapped X/Z vel/pos

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
    offsets = defaultdict(lambda:{'hits':0,'funcs':set(),'samples':[],'neg':0,'pos':0,'int':False,'short':False})
    for fn in load_bundles():
        dec = fn.get('decompilation') or ''
        if not dec: continue
        func = fn.get('function') or {}
        name = func.get('name') or ''
        addr = f"0x{(func.get('ea') or 0):x}"
        for line in dec.splitlines():
            for pat, tag in ((SHORT_MUT,'short'),(INT_MUT,'int')):
                m = pat.search(line)
                if not m: continue
                dst = int(m.group(1),16); src = int(m.group(2),16)
                if dst!=src: continue
                if dst in KNOWN_IGNORE: continue
                sign = m.group(3); raw = m.group(4)
                val = parse_const(raw)
                if val >= 0x1000: continue
                entry = offsets[dst]
                entry['hits'] += 1
                entry['funcs'].add(name)
                entry[tag] = True
                if sign == '-': entry['neg'] += 1
                else: entry['pos'] += 1
                if len(entry['samples']) < 6:
                    entry['samples'].append(f"{addr} {name} :: {line.strip()}")
    out = EXPORTS / 'gravity_broad_candidates.md'
    with out.open('w',encoding='utf-8') as f:
        f.write('# Broad Gravity Candidate Self-Mutating Offsets\n\n')
        if not offsets:
            f.write('No self-mutation candidates found under constraints.\n')
            return
        f.write('| Offset | Hits | Funcs | NegMut | PosMut | Types | Sample 1 | Sample 2 |\n')
        f.write('|--------|------|-------|--------|--------|-------|----------|----------|\n')
        for off, data in sorted(offsets.items(), key=lambda x: -x[1]['hits']):
            types = ','.join(t for t,v in (('short',data['short']),('int',data['int'])) if v)
            samples = data['samples'] + ['']*2
            f.write(f"| 0x{off:x} | {data['hits']} | {len(data['funcs'])} | {data['neg']} | {data['pos']} | {types} | {samples[0]} | {samples[1]} |\n")
        f.write('\n---\n\n## Detailed Samples\n\n')
        for off, data in sorted(offsets.items(), key=lambda x: -x[1]['hits']):
            f.write(f"### Offset 0x{off:x}\n\n")
            for s in data['samples']:
                f.write(f"- {s}\n")
            f.write('\n')
    print(f'Wrote {out}')

if __name__ == '__main__':
    main()
