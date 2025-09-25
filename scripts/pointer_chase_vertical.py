#!/usr/bin/env python3
"""
pointer_chase_vertical.py

Goal:
  Investigate hypothesis that (param + 0x11C) is a pointer to a secondary struct
  containing vertical (Y) velocity/position (and maybe more) fields. We look for
  nested dereference patterns that access *(int *)(*(int *)(param_X + 0x11c) + offset)
  or *(short *)(... + offset) and record which secondary offsets appear with:
    - negative immediate constants (0xFFxx) assignments
    - arithmetic +/- operations
    - shift >> 0xC usage near them (possible integrator)

Output:
  pointer_chase_vertical.md listing candidate secondary offsets ranked by score.

Scoring heuristic per secondary offset:
  +3 each negative immediate write
  +2 each arithmetic update line referencing offset
  +1 if a >>0xC appears within a window of 8 lines of a line referencing offset

We aggregate per function as well for context.
"""
from __future__ import annotations
import re,json
from pathlib import Path
from collections import defaultdict

BUNDLE_GLOB='exports/bundle_*.jsonl'
# Regex for second-level offsets off *(int *)(param + 0x11c)
# Capture secondary offset hex
SEC_OFF_PAT=re.compile(r'\*\(\w+ \*\)\(\*\(int \*\)\(param_\d+ \+ 0x11c\) \+ 0x([0-9a-fA-F]{2,3})\)')
# Also capture short/undefined2 pointer forms: *(short *)(*(int *)(param_X + 0x11c) + 0xYY)
SEC_OFF_SHORT_PAT=re.compile(r'\*(?:short|undefined2) \*\)\(\*\(int \*\)\(param_\d+ \+ 0x11c\) \+ 0x([0-9a-fA-F]{2,3})\)')
NEG_WRITE_PAT=re.compile(r'=\s*0xff[0-9a-fA-F]{2}')
ARITH_PAT=re.compile(r'[+\-]=|=\s*[^;]*[+\-]\s*(0x[0-9a-fA-F]+|\d+)')
SHIFT12_PAT=re.compile(r'>>\s*0xc',re.IGNORECASE)

WINDOW=8

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


def analyze_function(fn):
    dec=fn.get('decompilation') or ''
    lines=dec.splitlines()
    if '+ 0x11c)' not in dec:
        return None
    sec_hits=[]
    for idx,l in enumerate(lines):
        for pat in (SEC_OFF_PAT, SEC_OFF_SHORT_PAT):
            for m in pat.finditer(l):
                off=int(m.group(1),16)
                sec_hits.append((idx,off,l))
    if not sec_hits:
        return None
    # Precompute shift lines
    shift_lines=[i for i,l in enumerate(lines) if SHIFT12_PAT.search(l)]
    sec_stats=defaultdict(lambda: {'neg':0,'arith':0,'shift_near':0,'lines':[]})
    for idx,off,l in sec_hits:
        stat=sec_stats[off]
        stat['lines'].append(l.strip())
        if NEG_WRITE_PAT.search(l):
            stat['neg']+=1
        if ARITH_PAT.search(l):
            stat['arith']+=1
        # shift proximity
        for s in shift_lines:
            if abs(s-idx)<=WINDOW:
                stat['shift_near']+=1
                break
    # compute scores
    results=[]
    for off,st in sec_stats.items():
        score=st['neg']*3 + st['arith']*2 + st['shift_near']
        results.append((off,score,st))
    results.sort(key=lambda x:-x[1])
    # Pair analysis: identify off/off+2 both present (potential 32-bit or vel/pos duo)
    offs_sorted=sorted(sec_stats.keys())
    pairs=[]
    for o in offs_sorted:
        if (o+2) in sec_stats:
            total_score = (sec_stats[o]['neg']+sec_stats[o+2]['neg'])*3 + (sec_stats[o]['arith']+sec_stats[o+2]['arith'])*2
            pairs.append((o,o+2,total_score))
    return {'single':results,'pairs':pairs, 'stats':sec_stats}


def main():
    global_sums=defaultdict(int)
    func_mentions=defaultdict(set)
    out_lines=['# Pointer-Chase Vertical Analysis','']
    seen_func=set()
    for fn in iter_functions():
        res=analyze_function(fn)
        if not res: continue
        fname=fn['function']['name']; ea=fn['function']['ea']
        if ea in seen_func: # dedupe repeated serialized copies of same function
            continue
        seen_func.add(ea)
        singles=res['single']
        pairs=res['pairs']
        top=[r for r in singles if r[1]>0][:6]
        if not top: continue
        out_lines.append(f"## {fname} (ea=0x{ea:x})")
        for off,score,st in top:
            global_sums[off]+=score
            func_mentions[off].add(fname)
            out_lines.append(f"- secondary_off=0x{off:x} score={score} neg={st['neg']} arith={st['arith']} shiftNear={st['shift_near']} lines={len(st['lines'])}")
        if pairs:
            pair_str= ', '.join([f"0x{a:x}/0x{b:x}(score={s})" for a,b,s in pairs[:6]])
            out_lines.append(f"  Pairs: {pair_str}")
        out_lines.append('')
    if global_sums:
        out_lines.append('## Global Secondary Offset Ranking')
        for off,tot in sorted(global_sums.items(), key=lambda x:-x[1])[:20]:
            out_lines.append(f"- 0x{off:x}: totalScore={tot} funcs={len(func_mentions[off])}")
    else:
        out_lines.append('_No secondary pointer patterns found involving +0x11C._')
    with open('pointer_chase_vertical.md','w',encoding='utf-8') as f:
        f.write('\n'.join(out_lines))
    print('Wrote pointer_chase_vertical.md')

if __name__=='__main__':
    main()
