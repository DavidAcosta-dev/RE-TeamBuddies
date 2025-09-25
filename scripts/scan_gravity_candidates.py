import json
import re
from collections import defaultdict, Counter
from pathlib import Path

"""
scan_gravity_candidates.py

Goal: Heuristically locate vertical (Y) velocity + gravity integration patterns not yet mapped.

We already confirmed horizontal integrator:
  posX(0x114) -= (velX(0x100) * frameScalar >> 0xC)
  posZ(0x118) -= (velZ(0x102) * frameScalar >> 0xC)

Missing: Which offset pair represents (velY, posY) and where gravity (a small negative constant per frame) is applied.

Heuristic Approach:
1. Search each function's decompilation text for a right-shift by 0xC combined with a multiply and an assignment to a structure offset *not* in {0x114,0x118} but nearby.
2. Additionally, look for patterns of an assignment like: *(short *)(base + X) = *(short *)(base + X) +/- const  where const is a small magnitude (|const| < 0x180) possibly masked or sign-extended.
3. Collect candidate offsets and score them based on:
   - Co-occurrence with >> 0xc multiply pattern.
   - Presence of a constant negative add/sub in same function.
   - Proximity to known X/Z offsets (within 0x20 bytes window of 0x114/0x118).
4. Output markdown summary highlighting top candidates.

Outputs:
  exports/gravity_candidates.md
"""

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"

SHIFT_PATTERN = re.compile(r'>>\s*0xc')
MULT_LINE = re.compile(r'\*(?:short|undefined2) \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,3})\)[^\n=]*=\s*\*(?:short|undefined2) \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,3})\)[^\n>]*>>\s*0xc')
ASSIGN_LINE = re.compile(r'\*(?:short|undefined2) \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,3})\)\s*=\s*\*(?:short|undefined2) \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,3})\)\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)')
NEG_CONST = re.compile(r'([+\-])\s*(0x[0-9a-fA-F]+|\d+)')

KNOWN_POS = {0x114, 0x118}
KNOWN_VEL = {0x100, 0x102}
WINDOW = list(range(0x0a0, 0x200))  # broaden scan window
SIMPLE_DEC_RE = re.compile(r'\*(?:short|undefined2) \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,3})\)\s*=\s*\*(?:short|undefined2) \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,3})\)\s*-\s*(0x[0-9a-fA-F]+|\d+)')


def load_bundles():
    for p in sorted(EXPORTS.glob("bundle_*.jsonl")):
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line=line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def parse_const(tok: str) -> int:
    if tok.startswith('0x'):
        return int(tok, 16)
    return int(tok)


def main():
    candidates = defaultdict(lambda: Counter())  # offset -> feature score counts
    func_hits = defaultdict(list)  # offset -> list of (fn_name, addr, features)

    for fn in load_bundles():
        dec = fn.get('decompilation') or ''
        if not dec:
            continue
        func = fn.get('function') or {}
        name = func.get('name') or ''
        addr = f"0x{(func.get('ea') or 0):x}"

        # 1. Multiplicative integrator variants
        for m in SHIFT_PATTERN.finditer(dec):
            # We don't parse full expression tree here; rely on line heuristics
            pass
        for line in dec.splitlines():
            if '>> 0xc' not in line:
                continue
            mm = MULT_LINE.search(line)
            if mm:
                dst = int(mm.group(1), 16)
                src = int(mm.group(2), 16)
                # Only consider if within scan window and not already known X/Z pair
                if dst not in KNOWN_POS and dst in WINDOW:
                    feat = []
                    if src in KNOWN_VEL:
                        feat.append('reuses_known_vel')
                    if abs(dst - 0x114) <= 0x20 or abs(dst - 0x118) <= 0x20:
                        feat.append('near_known_pos')
                    if feat:
                        candidates[dst].update(feat)
                        func_hits[dst].append((name, addr, line.strip(), feat))

            # 2. Constant add/sub patterns (possible gravity)
            aa = ASSIGN_LINE.search(line)
            if aa:
                dst = int(aa.group(1), 16)
                src = int(aa.group(2), 16)
                sign = aa.group(3)
                raw_const = aa.group(4)
                val = parse_const(raw_const)
                if dst == src and dst not in KNOWN_POS and dst not in KNOWN_VEL and dst in WINDOW:
                    magnitude = val if sign == '+' else -val
                    if -0x200 < magnitude < 0x200:
                        feat = ['small_const_adjust']
                        if magnitude < 0:
                            feat.append('negative_const')
                        candidates[dst].update(feat)
                        func_hits[dst].append((name, addr, line.strip(), feat))

            # 3. Simple decrement (no +/- reuse) pattern
            dd = SIMPLE_DEC_RE.search(line)
            if dd:
                dst = int(dd.group(1), 16)
                src = int(dd.group(2), 16)
                raw_const = dd.group(3)
                if dst == src and dst not in KNOWN_POS and dst not in KNOWN_VEL and dst in WINDOW:
                    val = parse_const(raw_const)
                    if 0 < val < 0x400:
                        feat = ['simple_decrement']
                        candidates[dst].update(feat)
                        func_hits[dst].append((name, addr, line.strip(), feat))

    out = EXPORTS / 'gravity_candidates.md'
    with out.open('w', encoding='utf-8') as f:
        f.write('# Gravity / Y Integrator Candidate Offsets\n\n')
        if not candidates:
            f.write('No candidates found with current heuristics. Consider widening WINDOW or refining regex.\n')
        else:
            f.write('| Offset | Score | Features | Example Site (first) |\n')
            f.write('|--------|-------|----------|----------------------|\n')
            for off, feats in sorted(candidates.items(), key=lambda x: -sum(x[1].values())):
                total = sum(feats.values())
                first = func_hits[off][0] if func_hits[off] else ('','','','')
                fname, faddr, snippet, featlist = first
                feat_names = ','.join(sorted(set(feats.elements())))
                f.write(f'| 0x{off:x} | {total} | {feat_names} | {faddr} {fname} |\n')
            f.write('\n---\n\nDetailed Hits:\n\n')
            for off in sorted(func_hits.keys()):
                f.write(f'### Offset 0x{off:x}\n\n')
                for fname, faddr, snippet, feat in func_hits[off][:25]:
                    f.write(f'- {faddr} {fname} :: {snippet} ({";".join(feat)})\n')
                f.write('\n')
    print(f'Wrote {out}')


if __name__ == '__main__':
    main()
