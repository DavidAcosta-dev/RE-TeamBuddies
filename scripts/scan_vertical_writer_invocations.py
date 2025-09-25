"""
scan_vertical_writer_invocations.py

Goal: Link vertical writer functions to contexts where a secondary pointer (primary+0x11c) is passed.

Heuristic:
  - For each function containing a call to one of the writer names, check if the same decompilation text contains '+ 0x11c' and the call site's argument list includes a variable that previously was assigned from *(int *)(X + 0x11c) or directly has that expression.
  - Record minimal snippet lines around the call.

Output: exports/vertical_writer_invocations.md
"""
from __future__ import annotations
import json, re
from pathlib import Path

EXPORTS = Path(__file__).resolve().parents[1] / 'exports'
OUT = EXPORTS / 'vertical_writer_invocations.md'
WRITERS = ["FUN_0001a320","FUN_0001a614","FUN_0001abfc","FUN_0001a3b0","FUN_0001a348"]
# Match a direct call pattern like FUN_0001a320(  or FUN_0001a320 (
CALL_RE = {w: re.compile(rf"\b{w}\s*\(") for w in WRITERS}
# Allow alias lines like: vX = *(int *)(Y + 0x11c); or vX = *(int *)(param_? + 0x11c)
SEC_ALIAS_ASSIGN = re.compile(r"([A-Za-z_]\w*)\s*=\s*\*\([^)]*\+ 0x11c\)")
SEC_DIRECT_EXPR = re.compile(r"\*\([^)]*\+ 0x11c\)")

def iter_functions():
    for bundle in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with bundle.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except Exception: continue
                if 'function' in obj: yield obj

def analyze(fn_obj):
    dec = fn_obj.get('decompilation') or ''
    name = fn_obj['function']['name']
    ea = fn_obj['function']['ea']
    if not any(c.search(dec) for c in CALL_RE.values()):
        return []
    lines = dec.splitlines()
    aliases = set()
    for l in lines:
        m = SEC_ALIAS_ASSIGN.search(l)
        if m:
            aliases.add(m.group(1))
    hits = []
    for idx,l in enumerate(lines):
        for w, cre in CALL_RE.items():
            if cre.search(l):
                # Determine if any alias or direct sec expr appears in same or previous 10 lines
                window = '\n'.join(lines[max(0,idx-8): idx+4])
                has_sec = any(a in window for a in aliases) or ('+ 0x11c' in window) or SEC_DIRECT_EXPR.search(window)
                if has_sec:
                    hits.append({
                        'caller': name,
                        'caller_ea': ea,
                        'writer': w,
                        'line_no': idx+1,
                        'snippet': window.replace('`','\'')[:600]
                    })
    return hits

def main():
    rows = []
    for fn in iter_functions():
        rows.extend(analyze(fn))
    with OUT.open('w',encoding='utf-8') as out:
        out.write('# Vertical writer invocation links\n\n')
        if not rows:
            out.write('No invocation links detected.\n')
            return
        out.write('| Caller | EA | Writer | Line | Snippet |\n')
        out.write('|--------|----|--------|------|---------|\n')
        for r in rows:
            out.write(f"| {r['caller']} | 0x{r['caller_ea']:x} | {r['writer']} | {r['line_no']} | `{r['snippet'].replace('|','\\|')}` |\n")
        out.write('\n')
    print('Wrote', OUT.name, 'with', len(rows), 'rows')

if __name__ == '__main__':
    main()
