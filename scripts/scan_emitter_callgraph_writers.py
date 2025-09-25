"""
scan_emitter_callgraph_writers.py

Enhanced caller + writer scan for vertical emitters:
  - Identify callers of emitter functions by name (FUN_0001f558 / FUN_0001f5ec) and EA fallbacks.
  - For each caller, search for potential writes to secondary vertical slots:
       * Direct: (*(T *)(*(int *)(X + 0x11c) + 0x60)) = ...
       * Index:  (*(undefined2 **)(X + 0x11c))[0x30] = ...
       * Alias-based: alias = *(...+0x11c); alias[0x30] = ...; *(short *)(alias + 0x60) = ...
       * Nearby offsets cluster (0x5c–0x64) to catch struct sequence writes.
       * memcpy-like calls whose dst aliases *(...+0x11c)

Outputs summary to exports/emitter_callgraph_writers.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'emitter_callgraph_writers.md'
EMITTERS = {'FUN_0001f558','FUN_0001f5ec'}

# Writer patterns
P_DIRECT_60 = re.compile(r"\*\([^)]*short[^)]*\)\(\*\([^)]*int[^)]*\)\([^)]*\+ 0x11c\) \+ 0x60\)\s*=")
P_DIRECT_IDX30 = re.compile(r"\(\*\([^)]*\*\)\([^)]*\+ 0x11c\)\)\)\s*\[0x30\]\s*=")
P_ALIAS_DECL = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*\*\([^)]*\*\)\([^)]*\+ 0x11c\)\s*;")
MEMCPY_LIKE = re.compile(r"func_0x[0-9a-f]{8}\(([^,]+),\s*([^,]+),\s*[^)]+\)")

def load_funcs():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except Exception: continue
                if 'function' in obj: yield obj

def find_callers(funcs):
    callers = {e: [] for e in EMITTERS}
    name_re = {e: re.compile(rf"\b{e}\s*\(") for e in EMITTERS}
    for fn in funcs:
        dec = fn.get('decompilation') or ''
        if not dec: continue
        for e, cre in name_re.items():
            if cre.search(dec) and fn['function']['name'] != e:
                callers[e].append(fn)
    return callers

def scan_writes(fn_obj):
    dec = fn_obj.get('decompilation') or ''
    lines = dec.splitlines()
    aliases = set()
    events = []
    # Collect alias declarations first pass
    for i,l in enumerate(lines):
        m = P_ALIAS_DECL.search(l)
        if m: aliases.add(m.group(1))
    # Helper builders for alias patterns
    def alias_idx30(a): return re.compile(rf"\b{re.escape(a)}\s*\[0x30\]\s*=")
    def alias_off60(a): return re.compile(rf"\*\([^)]*short[^)]*\)\(\s*{re.escape(a)}\s*\+\s*0x60\s*\)\s*=")
    # Nearby cluster offsets
    near_offsets = [f"0x{v:x}" for v in range(0x5c,0x65)]
    cluster_res = [re.compile(rf"\+\s*{o}\)\s*=") for o in near_offsets]

    for i,l in enumerate(lines):
        if P_DIRECT_60.search(l):
            events.append((i+1,'direct_write_+0x60',l.strip()))
        if P_DIRECT_IDX30.search(l):
            events.append((i+1,'direct_write_[0x30]',l.strip()))
        for a in aliases:
            if alias_idx30(a).search(l):
                events.append((i+1,'alias_write_[0x30]',l.strip()))
            if alias_off60(a).search(l):
                events.append((i+1,'alias_write_+0x60',l.strip()))
        # cluster around 0x60 referencing alias base
        if any(cr.search(l) for cr in cluster_res) and any(a in l for a in aliases):
            events.append((i+1,'cluster_write_near_0x60',l.strip()))
        # memcpy-like (dst first argument)
        mm = MEMCPY_LIKE.search(l)
        if mm:
            dst = mm.group(1)
            if '+ 0x11c' in dst or any(dst.strip().startswith(a) for a in aliases):
                events.append((i+1,'memcpy_like',l.strip()))
    return events

def main():
    funcs = list(load_funcs())
    callers = find_callers(funcs)
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Emitter callgraph writer scan\n\n')
        found_any = False
        for em, c_list in callers.items():
            out.write(f'## Callers of {em}\n\n')
            if not c_list:
                out.write('_No callers detected by name scan._\n\n')
                continue
            for c in c_list:
                fname=c['function']['name']; fea=c['function']['ea']
                events=scan_writes(c)
                if not events:
                    out.write(f'- {fname} @ 0x{fea:x}: (no candidate writes)\n')
                else:
                    found_any=True
                    out.write(f'- {fname} @ 0x{fea:x}:\n')
                    for ln,kind,line in events:
                        safe=line.replace('`','\'')
                        out.write(f'  - L{ln}: {kind}: `{safe}`\n')
            out.write('\n')
        if not found_any:
            out.write('_No writer-like patterns in callers._\n')
    print('Wrote', OUT.name)

if __name__ == '__main__':
    main()
