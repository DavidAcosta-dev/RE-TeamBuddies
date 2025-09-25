import json, re
from pathlib import Path
from collections import defaultdict

"""
scan_integrators.py

Enumerate every decompilation line containing the fixed-point pattern '>> 0xc' (Q12 shift)
and extract candidate structure offsets involved. This is a broader sweep to
surface undiscovered velocity/position style integrators (including possible Y axis / gravity sites).

Output:
  exports/integrator_lines.md

Heuristics:
- Capture all hex offsets of the form + 0xXYZ inside pointer expressions '(... + 0xXYZ)'.
- Ignore known horizontal position (0x114/0x118) and velocity (0x100/0x102) only when producing the per-offset summary (they still appear, but are tagged as known).
- Provide counts and sample lines per unique offset.

Next manual step after generation: inspect offsets with high co-occurrence that pair with small constant adjustments elsewhere.
"""

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / 'exports'

LINE_RE = re.compile(r'>>\s*0xc')
OFFSET_RE = re.compile(r'\+\s*0x([0-9a-fA-F]{2,4})')

KNOWN = {0x100: 'velX', 0x102: 'velZ', 0x114: 'posX', 0x118: 'posZ'}


def load_bundles():
    for p in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with p.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line=line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def main():
    per_offset = defaultdict(lambda: {'count':0, 'samples':[], 'role':None})
    total_lines = 0
    for fn in load_bundles():
        dec = fn.get('decompilation') or ''
        if not dec:
            continue
        func = fn.get('function') or {}
        name = func.get('name') or ''
        addr = f"0x{(func.get('ea') or 0):x}"
        for raw in dec.splitlines():
            if '>> 0xc' not in raw:
                continue
            if not LINE_RE.search(raw):
                continue
            total_lines += 1
            offs = {int(m.group(1),16) for m in OFFSET_RE.finditer(raw)}
            for off in sorted(offs):
                entry = per_offset[off]
                entry['count'] += 1
                if len(entry['samples']) < 5:
                    tag = KNOWN.get(off, '')
                    entry['samples'].append(f"{addr} {name} :: {raw.strip()}" + (f"  // {tag}" if tag else ''))
                if off in KNOWN:
                    entry['role'] = KNOWN[off]

    out = EXPORTS / 'integrator_lines.md'
    with out.open('w', encoding='utf-8') as f:
        f.write('# Fixed-Point Integrator Lines (>> 0xC sweep)\n\n')
        f.write(f'Total lines containing >> 0xC: {total_lines}\n\n')
        f.write('| Offset | Count | Known? | Sample 1 | Sample 2 | Sample 3 |\n')
        f.write('|--------|-------|--------|----------|----------|----------|\n')
        for off, data in sorted(per_offset.items(), key=lambda x: -x[1]['count']):
            samples = data['samples'] + ['']*5
            known = data.get('role') or ''
            f.write(f"| 0x{off:x} | {data['count']} | {known} | " + " | ".join(samples[:3]) + " |\n")
        f.write('\n---\n\n## Detailed Samples\n\n')
        for off, data in sorted(per_offset.items(), key=lambda x: -x[1]['count']):
            f.write(f"### Offset 0x{off:x}{' ('+data['role']+')' if data.get('role') else ''}\n\n")
            for s in data['samples']:
                f.write(f"- {s}\n")
            f.write('\n')
    print(f'Wrote {out}')


if __name__ == '__main__':
    main()
