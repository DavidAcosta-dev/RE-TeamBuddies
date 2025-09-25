#!/usr/bin/env python3
"""Extract focused context for high-scoring orientation candidates (v2).

Enhancements:
 - Lower default threshold to 1.5 (tunable by --min-score / ORIENT_FOCUS_MIN_SCORE env)
 - Bundle fallback: if snippet context yields no pattern lines, pull from bundle_*.jsonl decomp
 - Regex-based case-insensitive mask matching (&0xFFF variants)
 - Index arithmetic context: include nearby lines with '* 2', '<< 1', '<<1' if mask present

Output: exports/orientation_focus_context.md
"""
from __future__ import annotations
from pathlib import Path
import re, os, argparse, json

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
SCORED = EXPORTS / 'orientation_scored.md'
OUT = EXPORTS / 'orientation_focus_context.md'

parser = argparse.ArgumentParser()
parser.add_argument('--min-score', type=float, default=float(os.environ.get('ORIENT_FOCUS_MIN_SCORE', '1.5')), help='Minimum score threshold (default 1.5 or ORIENT_FOCUS_MIN_SCORE env)')
args = parser.parse_args()
threshold = args.min_score

if not SCORED.exists():
    raise SystemExit('orientation_scored.md missing; run orientation_score step first')

score_rows = []
table = False
for ln in SCORED.read_text(encoding='utf-8').splitlines():
    if ln.startswith('| Score |'):
        table = True
        continue
    if table:
        if not ln.startswith('|') or ln.startswith('|------'):
            continue
        cols = [c.strip() for c in ln.strip().strip('|').split('|')]
        if len(cols) < 9:
            continue
        try:
            score = float(cols[0])
        except ValueError:
            continue
        fn = cols[1]
        if not fn.startswith('FUN_'): continue
        if score >= threshold:
            score_rows.append((score, fn, cols))

# Build snippet index (function -> lines)
FUNC_RE = re.compile(r'FUN_[0-9a-fA-F]{8}')
MASK_RE = re.compile(r'&\s*0x0*fff', re.IGNORECASE)

# Load bundle decomp cache (function->decomp) for fallback
bundle_cache = {}
for bundle in EXPORTS.glob('bundle_*.jsonl'):
    if 'all_plus' in bundle.name:
        continue
    with bundle.open('r', encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            fn = obj.get('function', {}).get('name')
            if not fn:
                continue
            if fn not in bundle_cache:
                bundle_cache[fn] = obj.get('decompilation') or ''
func_text = {}
for snip in EXPORTS.glob('snippets_*.md'):
    lines = snip.read_text(encoding='utf-8', errors='ignore').splitlines()
    current = None
    bucket = []
    for ln in lines:
        m = FUNC_RE.search(ln)
        if m:
            if current and bucket:
                func_text.setdefault(current, '\n'.join(bucket))
            current = m.group(0)
            bucket = [ln]
        else:
            if current:
                bucket.append(ln)
    if current and bucket:
        func_text.setdefault(current, '\n'.join(bucket))

def extract_context(body: str) -> str:
    lines = body.splitlines()
    hits = []
    for i,l in enumerate(lines):
        if (MASK_RE.search(l) or '0x26800' in l or '0x27800' in l):
            start = max(0, i-3)
            end = min(len(lines), i+4)
            hits.append('\n'.join(lines[start:end]))
        # if line has arithmetic index patterns and we already saw a mask earlier in same function, include
        elif ('* 2' in l or '<< 1' in l or '<<1' in l) and any(MASK_RE.search(pr) for pr in lines[max(0,i-5):i]):
            start = max(0, i-2)
            end = min(len(lines), i+3)
            hits.append('\n'.join(lines[start:end]))
    # Deduplicate identical blocks
    seen = []
    out_blocks = []
    for h in hits:
        if h not in seen:
            seen.append(h)
            out_blocks.append(h)
    return '\n---\n'.join(out_blocks)

score_rows.sort(reverse=True)
with OUT.open('w', encoding='utf-8') as fh:
    fh.write('# Orientation Focus Context\n\n')
    fh.write(f'Threshold: score >= {threshold}\nTotal selected: {len(score_rows)}\n\n')
    for score,fn,cols in score_rows:
        body = func_text.get(fn, '')
        ctx = extract_context(body) if body else ''
        # Fallback to bundle if no context lines
        if not ctx:
            bdec = bundle_cache.get(fn, '')
            if bdec:
                ctx = extract_context(bdec)
        fh.write(f'## {fn} (score {score})\n\n')
        fh.write(ctx if ctx else '_No pattern lines captured (snippet+bundle)._')
        fh.write('\n\n')
print(f'Wrote {OUT} with {len(score_rows)} high-score orientation contexts')
