#!/usr/bin/env python3
"""
scan_nonliteral_gravity.py

Search for patterns indicating gravity application without a direct literal negative self-mutation.
Patterns targeted inside a narrowed function set (crate seeds frontier + vertical candidates):
  1. LOAD velYcandidate  (offset in 0x100..0x140 excluding known X/Z) -> temp
  2. ADD temp, something (could be another load or function return)   (no explicit literal -const)
  3. STORE temp back to same offset
  4. Later (within N lines) that offset participates in a multiply/shift >> 0xC and updates another offset

Heuristic approach: regex scan per function decomp text windowed; no full AST.
Outputs: nonliteral_gravity_candidates.md
"""
from __future__ import annotations
import json,re
from pathlib import Path
from collections import defaultdict,deque

# Reuse crate seeds
CRATE_SEEDS = {
    ('MAIN.EXE','FUN_00008528'),
    ('MAIN.EXE','FUN_000090e0'),
    ('MAIN.EXE','FUN_00009708'),
    ('MAIN.EXE','FUN_0001a348'),
    ('MAIN.EXE','FUN_00038748'),
    ('MAIN.EXE','FUN_0003baf8'),
    ('MAIN.EXE','FUN_00005e70'),
    ('MAIN.EXE','FUN_000063c4'),
}
VERTICAL_PRIORITY = {'FUN_00044f80','FUN_00032c18','FUN_00044a14','FUN_0001e750'}
MAX_DEPTH = 5
EXPORTS = Path('exports')

OFFSET_RANGE = range(0x100,0x150)
KNOWN_IGNORE = {0x100,0x102,0x114,0x118}

# Simplistic patterns (MIPS decomp textual flavor)
# Capture load of short/int from base + offset into a temp variable symbol (varX / iVarX / sVarX)
LOAD_RE = re.compile(r"(\w+)\s*=\s*\*(?:short|int) \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,4})\)")
STORE_RE = re.compile(r"\*(?:short|int) \*\)\([^)]*\+ 0x([0-9a-fA-F]{2,4})\)\s*=\s*(\w+)\b")
SHIFT_USE_RE = re.compile(r">>\s*0xc")
OFFSET_ANY_RE = re.compile(r"\+\s*0x([0-9a-fA-F]{2,4})")


def load_funcs():
    for p in EXPORTS.glob('bundle_*.jsonl'):
        with p.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip();
                if not line: continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if 'function' in obj:
                    yield obj


def build_graph(funcs):
    graph = defaultdict(set); meta={}
    for fn in funcs:
        b = fn.get('binary'); func = fn.get('function') or {}; name=func.get('name')
        key=(b,name); meta[key]=fn
        for cal in fn.get('callees') or []:
            graph[key].add((b,cal))
    return graph,meta


def bfs(graph, start):
    dist={start:0}; q=deque([start])
    while q:
        cur=q.popleft(); d=dist[cur]
        if d>=MAX_DEPTH: continue
        for nxt in graph.get(cur,()):
            if nxt[0]!=cur[0]: continue
            if nxt not in dist:
                dist[nxt]=d+1; q.append(nxt)
    return dist


def gather_target_set(graph,meta):
    frontier=set()
    for seed in CRATE_SEEDS:
        if seed in meta:
            frontier.update(bfs(graph,seed).keys())
    # add vertical priority directly
    for k,v in list(meta.items()):
        if v.get('function',{}).get('name') in VERTICAL_PRIORITY:
            frontier.add(k)
    return frontier


def analyze_function(fn):
    decomp = fn.get('decompilation') or ''
    lines = decomp.splitlines()
    # Map variable symbol -> offset for loaded values
    var_to_off = {}
    off_access_stats = defaultdict(lambda:{'loads':0,'stores':0,'shift_uses':0,'lines':[]})

    for idx,line in enumerate(lines):
        # LOAD detection
        lm = LOAD_RE.search(line)
        if lm:
            sym, off_hex = lm.group(1), lm.group(2)
            off = int(off_hex,16)
            if off in OFFSET_RANGE and off not in KNOWN_IGNORE:
                # extract symbol token left of '='
                var = sym.split('=')[0].strip()
                var_to_off[var]=off
                off_access_stats[off]['loads'] +=1
                off_access_stats[off]['lines'].append((idx,line.strip()))
        # STORE detection
        sm = STORE_RE.search(line)
        if sm:
            off = int(sm.group(1),16); var=sm.group(2)
            if off in OFFSET_RANGE and off not in KNOWN_IGNORE:
                off_access_stats[off]['stores'] +=1
                off_access_stats[off]['lines'].append((idx,line.strip()))
                # check if var tied to prior load of same off
                if var in var_to_off and var_to_off[var]==off:
                    off_access_stats[off]['roundtrip']=off_access_stats[off].get('roundtrip',0)+1
        # SHIFT usage context
        if SHIFT_USE_RE.search(line):
            # gather offsets referenced in this line
            for m in OFFSET_ANY_RE.finditer(line):
                off = int(m.group(1),16)
                if off in OFFSET_RANGE and off not in KNOWN_IGNORE:
                    off_access_stats[off]['shift_uses'] +=1
                    off_access_stats[off]['lines'].append((idx,line.strip()))
    # Compute heuristic scores
    results=[]
    for off, info in off_access_stats.items():
        if info['loads'] and info['stores'] and info.get('roundtrip') and info['shift_uses']:
            score = info.get('roundtrip',0)*2 + info['shift_uses']*2 + info['stores'] + info['loads']
            results.append((off,score,info))
    results.sort(key=lambda x:-x[1])
    return results


def main():
    funcs = list(load_funcs())
    graph,meta = build_graph(funcs)
    target = gather_target_set(graph,meta)
    out_lines=['# Non-Literal Gravity Candidates\n']
    summary=[]
    for key in target:
        fn = meta.get(key)
        if not fn: continue
        res = analyze_function(fn)
        if not res: continue
        func_name = fn['function']['name']
        for off,score,info in res:
            summary.append({'function':func_name,'offset':off,'score':score,'loads':info['loads'],'stores':info['stores'],'roundtrip':info.get('roundtrip',0),'shift_uses':info['shift_uses']})
            out_lines.append(f"## {func_name} offset 0x{off:x} score {score}\n")
            for li,ltext in info['lines'][:25]:
                out_lines.append(f"  L{li}: {ltext}")
            out_lines.append('')
    if not summary:
        out_lines.append('\nNo non-literal gravity candidates found.')
    # Sort summary
    summary.sort(key=lambda d: (-d['score'], d['function'], d['offset']))
    out_lines.insert(1,'\n## Summary\n')
    for row in summary[:120]:
        out_lines.insert(2,f"- {row['function']} off=0x{row['offset']:x} score={row['score']} loads={row['loads']} stores={row['stores']} rt={row['roundtrip']} shiftUses={row['shift_uses']}")
    with open('nonliteral_gravity_candidates.md','w',encoding='utf-8') as f:
        f.write('\n'.join(out_lines))
    print('Wrote nonliteral_gravity_candidates.md with', len(summary), 'entries')

if __name__ == '__main__':
    main()
