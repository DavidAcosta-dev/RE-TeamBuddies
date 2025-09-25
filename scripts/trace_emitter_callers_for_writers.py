"""
trace_emitter_callers_for_writers.py

Goal: Starting from known vertical emitter functions (FUN_0001f558, FUN_0001f5ec),
enumerate their callers (direct) and scan those caller bodies for:
  - Writes to *(short *)(*(int *)(X + 0x11c) + 0x60)
  - Writes to alias + 0x60 where alias = *(int *)(X + 0x11c)
  - Writes to (*(undefined2 **)(X + 0x11c))[0x30]
  - memcpy-like calls whose destination aliases *(...+0x11c)

This attempts to narrow the vertical Y-slot producer region.

Output: exports/emitter_caller_writer_candidates.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

EXPORTS_DIR = Path(__file__).resolve().parents[1] / 'exports'
OUT_FILE = EXPORTS_DIR / 'emitter_caller_writer_candidates.md'

EMITTER_NAMES = {'FUN_0001f558','FUN_0001f5ec'}

# Patterns for candidate writes
WRITE_OFFSET60_DIRECT = re.compile(r"\*\(short \*\)\(\*\(int \*\)\([^)]*\+ 0x11c\) \+ 0x60\)\s*=")
WRITE_INDEX30_DIRECT = re.compile(r"\(\*\([^)]*\*\)\([^)]*\+ 0x11c\)\)\)\s*\[0x30\]\s*=")
ALIAS_DECL = re.compile(r"^(\s*)([A-Za-z_]\w*)\s*=\s*\*\([^)]*\*\)\([^)]*\+ 0x11c\)\s*;")
ALIAS_WRITE_OFFSET60 = lambda v: re.compile(rf"\*\(short \*\)\(\s*{re.escape(v)}\s*\+\s*0x60\s*\)\s*=")
ALIAS_WRITE_INDEX30 = lambda v: re.compile(rf"{re.escape(v)}\s*\[0x30\]\s*=")

MEMCPY_LIKE = re.compile(r"func_0x[0-9a-f]{8}\(([^,]+),\s*([^,]+),\s*[^)]+\)")

def load_functions():
    funcs = []
    for fp in sorted(EXPORTS_DIR.glob('bundle_*.jsonl')):
        with fp.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                line=line.strip()
                if not line.startswith('{'): continue
                try:
                    obj=json.loads(line)
                except Exception:
                    continue
                if 'function' in obj:
                    funcs.append(obj)
    return funcs

def index_by_name(funcs):
    return {f['function']['name']: f for f in funcs if 'function' in f}

def collect_callers(funcs):
    callers_map = {name: [] for name in EMITTER_NAMES}
    for f in funcs:
        dec = f.get('decompilation') or ''
        if not dec:
            continue
        for em in EMITTER_NAMES:
            # Rough heuristic: direct call pattern "em(..." or " em(" ignoring substrings in identifiers by boundaries
            if re.search(rf"\b{em}\s*\(", dec):
                callers_map[em].append(f)
    return callers_map

def scan_caller(caller_obj):
    dec = caller_obj.get('decompilation') or ''
    lines = dec.splitlines()
    aliases = set()
    events = []
    for i,l in enumerate(lines):
        m = ALIAS_DECL.search(l)
        if m:
            aliases.add(m.group(2))
        if WRITE_OFFSET60_DIRECT.search(l):
            events.append((i+1,'direct_write_offset60',l.strip()))
        if WRITE_INDEX30_DIRECT.search(l):
            events.append((i+1,'direct_write_index30',l.strip()))
    if aliases:
        for i,l in enumerate(lines):
            for a in aliases:
                if ALIAS_WRITE_OFFSET60(a).search(l):
                    events.append((i+1,'alias_write_offset60',l.strip()))
                if ALIAS_WRITE_INDEX30(a).search(l):
                    events.append((i+1,'alias_write_index30',l.strip()))
    # memcpy-like scanning (only flag if first arg is alias or direct *(...+0x11c))
    for i,l in enumerate(lines):
        cm = MEMCPY_LIKE.search(l)
        if not cm: continue
        dst = cm.group(1)
        if '+ 0x11c' in dst or any(dst.strip().startswith(a) for a in aliases):
            events.append((i+1,'memcpy_like',l.strip()))
    return events

def main():
    funcs = load_functions()
    callers_map = collect_callers(funcs)
    with OUT_FILE.open('w',encoding='utf-8') as out:
        out.write('# Emitter caller writer candidates\n\n')
        any_events = False
        for em, callers in callers_map.items():
            out.write(f'## Callers of {em}\n\n')
            if not callers:
                out.write('_No callers found._\n\n')
                continue
            for c in callers:
                fname = c['function']['name']
                fea = c['function']['ea']
                events = scan_caller(c)
                if not events:
                    out.write(f'- {fname} @ 0x{fea:x}: (no candidate writes)\n')
                else:
                    any_events = True
                    out.write(f'- {fname} @ 0x{fea:x}:\n')
                    for ln,kind,line in events:
                        safe = line.replace('`','\'')
                        out.write(f'  - L{ln}: {kind}: `{safe}`\n')
            out.write('\n')
        if not any_events:
            out.write('\n_No writer-like events detected in direct callers._\n')
    print('Wrote', OUT_FILE.name)

if __name__ == '__main__':
    main()
