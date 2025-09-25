#!/usr/bin/env python3
"""Emit concise decomp snippets for secondary chain candidates.

Reads gravity_chain_intersections.json to fetch the 'secondary' list, then
pulls decompilations from bundle jsonl. For each function, prints a compact
set of lines highlighting:
- Fixed-point shifts (>> 0xc)
- Vertical/direction offsets (+0x34/+0x36/+0x38/+0x3c/+0x3e/+0x40)
- Magnitude offset (+0x44)

Outputs:
- exports/gravity_chain_secondary_snippets.md

Env:
- MAX_FUN (default 30)        – limit number of secondary candidates
- MAX_SNIPPETS (default 6)    – max snippets per function
- CONTEXT (default 2)         – lines of context before/after hits
"""
from __future__ import annotations
import os, json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
JSON_IN = EXPORTS / 'gravity_chain_intersections.json'
BUNDLE = EXPORTS / 'bundle_GAME.BIN.jsonl'
OUT_MD = EXPORTS / 'gravity_chain_secondary_snippets.md'

if not JSON_IN.exists() or not BUNDLE.exists():
    raise SystemExit('Missing gravity_chain_intersections.json or bundle jsonl')

MAX_FUN = int(os.environ.get('MAX_FUN', '30'))
MAX_SNIPPETS = int(os.environ.get('MAX_SNIPPETS', '6'))
CONTEXT = int(os.environ.get('CONTEXT', '2'))

with JSON_IN.open('r', encoding='utf-8') as f:
    data = json.load(f)
secondary = data.get('secondary', [])[:MAX_FUN]
want = {r['function'] for r in secondary}

# Load decomp bodies only for functions we want
FUN_RE = re.compile(r'^FUN_[0-9a-fA-F]{6,}$')
DECOMP: dict[str,str] = {}

with BUNDLE.open('r', encoding='utf-8', errors='ignore') as fh:
    for line in fh:
        try:
            obj = json.loads(line)
        except Exception:
            continue
        fn = (obj.get('function') or {}).get('name')
        if not fn or fn not in want:
            continue
        body = obj.get('decompilation') or ''
        if body:
            DECOMP[fn] = body

hit_tokens = [
    '>> 0xc',
    '+ 0x34', '+ 0x36', '+ 0x38',
    '+ 0x3c', '+ 0x3e', '+ 0x40',
    '+ 0x44',
]

def collect_snippets(body: str, max_snips: int, context: int):
    lines = body.splitlines()
    hits = []
    for i, ln in enumerate(lines):
        if any(tok in ln for tok in hit_tokens):
            lo = max(0, i - context)
            hi = min(len(lines), i + context + 1)
            snippet = '\n'.join(lines[lo:hi])
            # avoid duplicates
            if not hits or snippet != hits[-1]:
                hits.append(snippet)
            if len(hits) >= max_snips:
                break
    return hits

out = []
out.append('# Secondary Chain Candidate Snippets\n')
if not secondary:
    out.append('_No secondary candidates found in intersections JSON._\n')
else:
    for rec in secondary:
        fn = rec['function']
        out.append(f"\n## {fn}  | score={rec['score']} overlap={rec.get('callee_overlap',0)} overlap2={rec.get('callee_overlap2',0)} vref={rec.get('vertical_refs',0)} shifts={rec.get('shifts',0)}\n")
        body = DECOMP.get(fn)
        if not body:
            out.append('_No decompilation available in bundle._\n')
            continue
        snips = collect_snippets(body, MAX_SNIPPETS, CONTEXT)
        if not snips:
            out.append('_No relevant lines found._\n')
            continue
        for s in snips:
            out.append('```c')
            out.append(s)
            out.append('```')

OUT_MD.write_text('\n'.join(out), encoding='utf-8')
print(f'Wrote {OUT_MD} with {len(secondary)} functions')
