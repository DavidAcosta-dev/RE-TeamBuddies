#!/usr/bin/env python3
"""
gravity_fuzzy_scanner.py

Broader heuristic to locate gravity-like application without relying on explicit self-sub
or simple roundtrip variable names.

Strategy:
  - Scan all functions for lines containing offsets in candidate Y range (0x11a..0x120 plus
    extended cluster 0x11c..0x128) excluding known X/Z.
  - Track per function sequences where:
      * A candidate offset appears on RHS of an expression with '+' or '-' (velocity update)
      * Later (within window) a shift '>> 0xc' occurs involving a DIFFERENT offset (possible pos update)
    OR the same candidate offset appears twice with an intervening call (call-return transform pattern).
  - Assign scores favoring: recurrent appearance each frame (calls many times), presence of small
    immediate negatives (0xffxx patterns), or multiple candidate offsets (vel+pos pair).

Outputs: gravity_fuzzy_candidates.md
"""
from __future__ import annotations
import re,json
from pathlib import Path
from collections import defaultdict

BUNDLE_GLOB='exports/bundle_*.jsonl'

CANDIDATE_OFFS={0x11a,0x11c,0x11e,0x120,0x122,0x124,0x126,0x128}
KNOWN_EXCLUDE={0x100,0x102,0x114,0x118}
OFFSET_RE=re.compile(r"\+\s*0x([0-9a-fA-F]{2,4})")
SHIFT_RE=re.compile(r">>\s*0xc",re.IGNORECASE)
NEG_SMALL_RE=re.compile(r"0xff[0-9a-fA-F]{2}")
ARITH_RE=re.compile(r"[+\-]\s*(0x[0-9a-fA-F]+|\d+)")
# Secondary pointer deref pattern: *(int *)(*(int *)(param_X + 0x11c) + 0xYY)
SEC_PTR_RE=re.compile(r"\*\(int \*\)\(\*\(int \*\)\(param_\d+ \+ 0x11c\) \+ 0x([0-9a-fA-F]{2,3})\)")

WINDOW=14


def iter_functions():
    for p in Path('.').glob(BUNDLE_GLOB):
        with p.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip();
                if not line: continue
                try:
                    obj=json.loads(line)
                except json.JSONDecodeError:
                    continue
                if 'function' in obj:
                    yield obj


def analyze(fn):
    decomp=fn.get('decompilation') or ''
    lines=decomp.splitlines()
    hits=[]
    # Collect lines referencing candidate offsets (direct) and note secondary deref usage
    cand_lines=[]
    sec_hits=[]
    for idx,l in enumerate(lines):
        offs=[int(m.group(1),16) for m in OFFSET_RE.finditer(l)]
        relevant=[o for o in offs if o in CANDIDATE_OFFS and o not in KNOWN_EXCLUDE]
        if relevant:
            cand_lines.append((idx,l,relevant))
        for sm in SEC_PTR_RE.finditer(l):
            so=int(sm.group(1),16)
            sec_hits.append((idx,so,l.strip()))
    if not cand_lines:
        return []
    shift_indices=[i for i,l in enumerate(lines) if SHIFT_RE.search(l)]
    shift_set=set(shift_indices)
    res=[]
    for i,(idx,line,offs) in enumerate(cand_lines):
        # Look ahead within window for shift occurrence or repeat of offset
        for j in range(i+1,len(cand_lines)):
            idx2,line2,offs2=cand_lines[j]
            if idx2-idx>WINDOW: break
            intersect=set(offs)&set(offs2)
            # repeat pattern
            if intersect:
                score=4
                if NEG_SMALL_RE.search(line) or NEG_SMALL_RE.search(line2):
                    score+=2
                if ARITH_RE.search(line): score+=1
                if ARITH_RE.search(line2): score+=1
                res.append((min(offs),score,idx,idx2,line.strip(),line2.strip(),'repeat'))
            # shift usage in between referencing other offset
            between_shift=any(k for k in range(idx,idx2+1) if k in shift_set)
            if between_shift and not intersect:
                score=6
                if NEG_SMALL_RE.search(line) or NEG_SMALL_RE.search(line2):
                    score+=2
                if len(set(offs)|set(offs2))>1: score+=1
                res.append((min(offs),score,idx,idx2,line.strip(),line2.strip(),'vel->pos?'))
    # Deduplicate keep top score per (offset,idx,idx2,type)
    final=[]; seen=set()
    for r in sorted(res,key=lambda x:-x[1]):
        key=(r[0],r[2],r[3],r[6])
        if key in seen: continue
        seen.add(key)
        final.append(r)
    return final


def main():
    out_lines=['# Gravity Fuzzy Candidates (enhanced)\n']
    total=0
    for fn in iter_functions():
        results=analyze(fn)
        if not results: continue
        fname=fn['function']['name']
        ea=fn['function']['ea']
        results.sort(key=lambda x:-x[1])
        best=results[:5]
        total+=len(best)
        out_lines.append(f"## {fname} (ea=0x{ea:x})\n")
        for off,score,i1,i2,l1,l2,typ in best:
            out_lines.append(f"- off=0x{off:x} score={score} type={typ} L{i1}->{i2}\n  L{i1}: {l1}\n  L{i2}: {l2}")
        # Append secondary pointer usage lines (top few) for context
        # Re-run lightweight secondary scan here to show context only
        sec_context=[]
        dec=next((r for r in fn.items() if False), None)  # placeholder to avoid linter
        # reuse analyze logic quickly
        decomp=fn.get('decompilation') or ''
        sec_lines=[]
        for idx,line in enumerate(decomp.splitlines()):
            for sm in SEC_PTR_RE.finditer(line):
                so=int(sm.group(1),16)
                sec_lines.append((so, idx, line.strip()))
        if sec_lines:
            out_lines.append('  Secondary ptr uses (+0x11C -> struct):')
            for so,li,ln in sec_lines[:6]:
                out_lines.append(f"    - secOff=0x{so:x} L{li}: {ln}")
        out_lines.append('')
    if total==0:
        out_lines.append('\n_No fuzzy candidates found in scanned set._')
    with open('gravity_fuzzy_candidates.md','w',encoding='utf-8') as f:
        f.write('\n'.join(out_lines))
    print('Wrote gravity_fuzzy_candidates.md with', total, 'candidate link(s)')

if __name__=='__main__':
    main()
