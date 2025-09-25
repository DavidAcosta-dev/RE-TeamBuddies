#!/usr/bin/env python3
"""Gravity pointer-chase analyzer.

Heuristic goals:
 1. Identify functions that load from actor + 0x11C (suspected secondary vertical struct pointer).
 2. Within the same function (or snippet window) also reference amplitude/progress offsets associated with vertical fields:
     Amplitude family: 0x50,0x52,0x54,0x56,0x58,0x5A
     Progress/step/scale: 0x5C,0x5E,0x60,0x62
 3. Score functions higher if BOTH pointer (+0x11C) and one of target offsets occur.
 4. Output ranked list with rationale to exports/gravity_pointer_chase.md

Data source: snippets_*.md exports (textual decomp fragments) assumed to include function marker lines with FUN_XXXXXXXX.

Limitations: Purely textual scan; does not follow actual register flow. Serves as triage list for manual inspection.
"""
from __future__ import annotations
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
OUT = EXPORTS / 'gravity_pointer_chase.md'

FUNC_RE = re.compile(r'FUN_[0-9a-fA-F]{8}')
PTR_MARKERS = ['+0x11C', '+0x11c']
VERT_OFFSETS = ['+0x50','+0x52','+0x54','+0x56','+0x58','+0x5A','+0x5a','+0x5C','+0x5c','+0x5E','+0x5e','+0x60','+0x62']

class Info:
    __slots__ = ('func','ptr_hits','vert_hits','lines')
    def __init__(self, func):
        self.func = func
        self.ptr_hits = 0
        self.vert_hits = 0
        self.lines = 0

infos = {}
current = None

for snippet in EXPORTS.glob('snippets_*.md'):
    lines = snippet.read_text(encoding='utf-8', errors='ignore').splitlines()
    for ln in lines:
        fmatch = FUNC_RE.search(ln)
        if fmatch:
            current = fmatch.group(0)
            infos.setdefault(current, Info(current))
        if not current:
            continue
        info = infos[current]
        info.lines += 1
        if any(m in ln for m in PTR_MARKERS):
            info.ptr_hits += 1
        if any(o in ln for o in VERT_OFFSETS):
            info.vert_hits += 1

scored = []
for inf in infos.values():
    if inf.ptr_hits:
        score = inf.ptr_hits * 2 + inf.vert_hits
        if inf.vert_hits:
            scored.append((score, inf))

scored.sort(key=lambda x: x[0], reverse=True)

with OUT.open('w', encoding='utf-8') as fh:
    fh.write('# Gravity Pointer-Chase Candidates\n\n')
    fh.write('Ranked functions referencing actor+0x11C AND vertical field offsets (+0x50..+0x62). Higher score = more pointer + vertical offset co-occurrence.\n\n')
    fh.write('| Function | Score | +0x11C Hits | VertField Hits | Lines Scanned |\n')
    fh.write('|----------|------:|------------:|--------------:|-------------:|\n')
    for score, inf in scored:
        fh.write(f'| {inf.func} | {score} | {inf.ptr_hits} | {inf.vert_hits} | {inf.lines} |\n')
    if not scored:
        fh.write('\n_No co-occurrence found; broaden heuristics or inspect raw disassembly for hidden pointer chain._\n')

print(f'Wrote {OUT} with {len(scored)} candidate functions')
