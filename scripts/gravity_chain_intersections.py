#!/usr/bin/env python3
"""Infer additional gravity composed chains via callee-set intersections.

Heuristic:
 1. Collect integrator functions (from integrator_lines.md) and their callees.
 2. Scan all functions (bundle jsonl) building:
       - set of called functions
       - vertical field reference counts (+0x34,+0x36,+0x38,+0x3c,+0x3e,+0x40)
       - shifts count (>> 0xc)
 3. Candidate orchestrators: functions (non-integrator) meeting at least one:
       - Directly call an integrator
       - Intersect >= MIN_CALLEE_INTERSECT integrator callee union
       - Reference >= MIN_VERTICAL_REFS vertical offsets AND shifts >= MIN_SHIFTS
 4. Score: 5*direct_integrator_calls + 2*overlap + 0.5*vertical_refs + 0.5*shifts
 5. Output ranked CSV + Markdown with potential new chain edges and justification.

Environment variables (tunable thresholds):
  MIN_CALLEE_INTERSECT (default 3)
  MIN_VERTICAL_REFS (default 4)
  MIN_SHIFTS (default 2)
  MAX_RESULTS (default 150)

Outputs:
  exports/gravity_chain_intersections.csv
  exports/gravity_chain_intersections.md
"""
from __future__ import annotations
import os, re, json, csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / 'exports'
BUNDLE = EXPORTS / 'bundle_GAME.BIN.jsonl'
INTEGRATOR_MD = EXPORTS / 'integrator_lines.md'
INTEGRATOR_EXT_MD = EXPORTS / 'integrator_lines_ext.md'
OUT_CSV = EXPORTS / 'gravity_chain_intersections.csv'
OUT_MD = EXPORTS / 'gravity_chain_intersections.md'

if not BUNDLE.exists() or not INTEGRATOR_MD.exists():
    raise SystemExit('Missing bundle or integrator_lines.md')

# Thresholds
MIN_CALLEE_INTERSECT = int(os.environ.get('MIN_CALLEE_INTERSECT', '3'))
MIN_VERTICAL_REFS = int(os.environ.get('MIN_VERTICAL_REFS', '4'))
MIN_SHIFTS = int(os.environ.get('MIN_SHIFTS', '2'))
MAX_RESULTS = int(os.environ.get('MAX_RESULTS', '150'))
MIN_CALLEE_INTERSECT2 = int(os.environ.get('MIN_CALLEE_INTERSECT2', '2'))
SECONDARY_MIN_CALLEE_INTERSECT = int(os.environ.get('SECONDARY_MIN_CALLEE_INTERSECT', '2'))
MAX_BRIDGE_DEPTH = int(os.environ.get('MAX_BRIDGE_DEPTH', '4'))
MAX_OVERLAP_NAMES = int(os.environ.get('MAX_OVERLAP_NAMES', '8'))
MAX_SNIPPET_CANDS = int(os.environ.get('MAX_SNIPPET_CANDS', '5'))
MAX_SNIPPET_NEIGHBORS = int(os.environ.get('MAX_SNIPPET_NEIGHBORS', '3'))
SNIPPET_CONTEXT = int(os.environ.get('SNIPPET_CONTEXT', '2'))
OVERLAP_VERT_W = float(os.environ.get('OVERLAP_VERT_W', '0.05'))
OVERLAP_SHIFTS_W = float(os.environ.get('OVERLAP_SHIFTS_W', '0.05'))
OVERLAP_BONUS_CAP = float(os.environ.get('OVERLAP_BONUS_CAP', '5.0'))

VERT_OFFSETS = ['+ 0x34', '+ 0x36', '+ 0x38', '+ 0x3c', '+ 0x3e', '+ 0x40']
SHIFT_TOKEN = '>> 0xc'
FUN_RE = re.compile(r'FUN_[0-9a-fA-F]{6,}')

# Parse integrator list(s)
integrators: set[str] = set()
def add_integrators(path: Path):
    try:
        for ln in path.read_text(encoding='utf-8', errors='ignore').splitlines():
            if 'FUN_' in ln:
                for tok in ln.split():
                    if tok.startswith('FUN_'):
                        integrators.add(tok.strip(',);'))
    except Exception:
        pass

add_integrators(INTEGRATOR_MD)
if INTEGRATOR_EXT_MD.exists():
    add_integrators(INTEGRATOR_EXT_MD)

# First pass: collect decomp + call graph + metrics
callers: dict[str, set[str]] = {}
vertical_refs: dict[str, int] = {}
shift_refs: dict[str, int] = {}
direct_calls_integrators: dict[str, int] = {}
decomp_cache: dict[str, str] = {}

with BUNDLE.open('r', encoding='utf-8', errors='ignore') as fh:
    for line in fh:
        try:
            obj = json.loads(line)
        except Exception:
            continue
        fn = obj.get('function', {}).get('name')
        if not fn:
            continue
        body = obj.get('decompilation') or ''
        decomp_cache[fn] = body
        calls = set(FUN_RE.findall(body))
        callers[fn] = calls
        vcount = sum(body.count(v) for v in VERT_OFFSETS)
        scount = body.count(SHIFT_TOKEN)
        vertical_refs[fn] = vcount
        shift_refs[fn] = scount
        d_int = sum(1 for c in calls if c in integrators)
        if d_int:
            direct_calls_integrators[fn] = d_int

# Build union of integrator callees (excluding integrators themselves for overlap metric)
integrator_callee_union: set[str] = set()
for integ in integrators:
    calls = callers.get(integ, set())
    for c in calls:
        if c not in integrators:
            integrator_callee_union.add(c)

# Build 2-hop union: callees of the callee union
integrator_callee_union2: set[str] = set()
for mid in integrator_callee_union:
    for c2 in callers.get(mid, set()):
        if c2 not in integrators and c2 not in integrator_callee_union:
            integrator_callee_union2.add(c2)

# Build reverse call graph: callee -> callers
reverse_callers: dict[str, set[str]] = {}
for fn, calls in callers.items():
    for cal in calls:
        reverse_callers.setdefault(cal, set()).add(fn)

rows = []
rows_secondary = []
for fn, calls in callers.items():
    if fn in integrators:
        continue
    overlap_set = calls & integrator_callee_union
    overlap2_set = calls & integrator_callee_union2
    overlap = len(overlap_set)
    overlap2 = len(overlap2_set)
    d_calls = direct_calls_integrators.get(fn, 0)
    vref = vertical_refs.get(fn, 0)
    shifts = shift_refs.get(fn, 0)
    qualifies = False
    reasons = []
    if d_calls:
        qualifies = True
        reasons.append('direct_integrator_call')
    if overlap >= MIN_CALLEE_INTERSECT:
        qualifies = True
        reasons.append(f'overlap>={MIN_CALLEE_INTERSECT}')
    if overlap2 >= MIN_CALLEE_INTERSECT2:
        qualifies = True
        reasons.append(f'overlap2>={MIN_CALLEE_INTERSECT2}')
    if vref >= MIN_VERTICAL_REFS and shifts >= MIN_SHIFTS:
        qualifies = True
        reasons.append('vertical+shifts')
    score = 5*d_calls + 2*overlap + 1.2*overlap2 + 0.5*vref + 0.5*shifts
    # Bonus based on density of vertical/shifts in 1-hop overlap neighbors (capped)
    ov_vert = sum(vertical_refs.get(n, 0) for n in overlap_set)
    ov_sh = sum(shift_refs.get(n, 0) for n in overlap_set)
    bonus = min(ov_vert * OVERLAP_VERT_W + ov_sh * OVERLAP_SHIFTS_W, OVERLAP_BONUS_CAP)
    score += bonus
    top_ol = sorted(overlap_set)[:MAX_OVERLAP_NAMES]
    top_ol2 = sorted(overlap2_set)[:MAX_OVERLAP_NAMES]
    rec = {
        'function': fn,
        'score': round(score, 2),
        'overlap_vert_refs': ov_vert,
        'overlap_shifts': ov_sh,
        'direct_integrators': d_calls,
        'callee_overlap': overlap,
        'callee_overlap2': overlap2,
        'vertical_refs': vref,
        'shifts': shifts,
        'reasons': '+'.join(reasons),
        'overlap_names': top_ol,
        'overlap2_names': top_ol2,
    }
    if qualifies:
        rows.append(rec)
    else:
        # Secondary: relaxed on overlap thresholds only
        if overlap >= SECONDARY_MIN_CALLEE_INTERSECT or overlap2 >= SECONDARY_MIN_CALLEE_INTERSECT:
            rows_secondary.append(rec)

rows.sort(key=lambda r: r['score'], reverse=True)
if len(rows) > MAX_RESULTS:
    rows = rows[:MAX_RESULTS]

# Detect potential new edges: candidate functions that directly call integrators
new_edges = []
for r in rows:
    if r['direct_integrators']:
        for callee in sorted(callers[r['function']] & integrators):
            new_edges.append({'caller': r['function'], 'integrator': callee, 'via': ''})

def bfs_bridges(start_fn: str, max_depth: int):
    """Return list of paths (list[str]) from start_fn to any integrator within depth."""
    paths = []
    from collections import deque
    dq = deque()
    dq.append((start_fn, [start_fn]))
    visited = {start_fn:0}
    while dq:
        cur, path = dq.popleft()
        depth = len(path)-1
        if depth >= max_depth:
            continue
        for nxt in sorted(list(callers.get(cur, [])))[:50]:  # cap branching
            nd = depth + 1
            if nxt in visited and visited[nxt] <= nd:
                continue
            new_path = path + [nxt]
            if nxt in integrators:
                paths.append(new_path)
                continue
            visited[nxt] = nd
            dq.append((nxt, new_path))
    return paths

# Bridge search: paths candidate -> ... -> integrator (depth <= MAX_BRIDGE_DEPTH)
bridge_paths = []
for r in rows:
    fn = r['function']
    if r['direct_integrators']:
        continue
    paths = bfs_bridges(fn, MAX_BRIDGE_DEPTH)
    for p in paths:
        bridge_paths.append({'candidate': fn, 'depth': len(p)-1, 'path': ' -> '.join(p), 'integrator': p[-1]})

def bfs_reverse_to_candidate(integ_fn: str, target_fn: str, max_depth: int):
    """Return one path from integrator up-callers to target_fn within depth, or None."""
    from collections import deque
    dq = deque()
    dq.append((integ_fn, [integ_fn]))
    visited = {integ_fn: 0}
    while dq:
        cur, path = dq.popleft()
        depth = len(path) - 1
        if depth >= max_depth:
            continue
        for prev in sorted(list(reverse_callers.get(cur, [])))[:50]:
            nd = depth + 1
            if prev in visited and visited[prev] <= nd:
                continue
            new_path = path + [prev]
            if prev == target_fn:
                return new_path
            visited[prev] = nd
            dq.append((prev, new_path))
    return None

# Reverse bridge search: integrator <- ... <- candidate (depth <= MAX_BRIDGE_DEPTH)
bridge_paths_rev = []
for r in rows:
    fn = r['function']
    if r['direct_integrators']:
        continue
    for integ in integrators:
        p = bfs_reverse_to_candidate(integ, fn, MAX_BRIDGE_DEPTH)
        if p:
            # reverse path currently integ -> ... -> candidate, flip for readability
            bridge_paths_rev.append({'candidate': fn, 'depth': len(p)-1, 'path': ' <- '.join(reversed(p)), 'integrator': integ})
            break

OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
with OUT_CSV.open('w', newline='', encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=['function','score','direct_integrators','callee_overlap','callee_overlap2','vertical_refs','shifts','overlap_vert_refs','overlap_shifts','reasons','overlap_names','overlap2_names'])
    w.writeheader()
    for r in rows:
        row = dict(r)
        row['overlap_names'] = ';'.join(r.get('overlap_names', []))
        row['overlap2_names'] = ';'.join(r.get('overlap2_names', []))
        w.writerow(row)

with OUT_MD.open('w', encoding='utf-8') as f:
    f.write('# Gravity Chain Intersection Inference\n\n')
    f.write(f'Integrator count (union): {len(integrators)}  | Integrator callee union: {len(integrator_callee_union)}\n\n')
    f.write(f'Thresholds: MIN_CALLEE_INTERSECT={MIN_CALLEE_INTERSECT}, MIN_CALLEE_INTERSECT2={MIN_CALLEE_INTERSECT2}, MIN_VERTICAL_REFS={MIN_VERTICAL_REFS}, MIN_SHIFTS={MIN_SHIFTS}\n\n')
    f.write(f'Candidates ranked (top {len(rows)}):\n\n')
    if not rows:
        f.write('_No candidates met thresholds._\n')
    else:
        f.write('| Function | Score | DirInt | Overlap | Overlap2 | VertRefs | Shifts | Reasons | TopOverlap | TopOverlap2 |\n')
        f.write('|----------|------:|-------:|--------:|---------:|---------:|-------:|---------|-----------|------------|\n')
        for r in rows:
            tol = ','.join(r.get('overlap_names', [])[:MAX_OVERLAP_NAMES])
            tol2 = ','.join(r.get('overlap2_names', [])[:MAX_OVERLAP_NAMES])
            f.write(f"| {r['function']} | {r['score']:.2f} | {r['direct_integrators']} | {r['callee_overlap']} | {r.get('callee_overlap2',0)} | {r['vertical_refs']} | {r['shifts']} | {r['reasons']} | {tol} | {tol2} |\n")
    f.write('\n## Potential New Caller→Integrator Edges\n\n')
    if not new_edges:
        f.write('_No direct integrator calls among candidates (beyond existing)_.\n')
    else:
        f.write('| Caller | Integrator |\n|--------|------------|\n')
        for e in new_edges:
            f.write(f"| {e['caller']} | {e['integrator']} |\n")
    f.write(f'\n### Bridge Paths (Depth <= {MAX_BRIDGE_DEPTH})\n\n')
    if not bridge_paths:
        f.write('_No bridge paths discovered._\n')
    else:
        f.write('| Candidate | Depth | Path |\n|-----------|------:|------|\n')
        for bp in sorted(bridge_paths, key=lambda x:(x['depth'], x['candidate']))[:100]:
            f.write(f"| {bp['candidate']} | {bp['depth']} | {bp['path']} |\n")
    f.write(f"\n### Reverse Bridge Paths (Depth <= {MAX_BRIDGE_DEPTH})\n\n")
    if not bridge_paths_rev:
        f.write('_No reverse bridge paths discovered._\n')
    else:
        f.write('| Candidate | Depth | Path |\n|-----------|------:|------|\n')
        for bp in sorted(bridge_paths_rev, key=lambda x:(x['depth'], x['candidate']))[:100]:
            f.write(f"| {bp['candidate']} | {bp['depth']} | {bp['path']} |\n")
    if rows_secondary:
        f.write('\n## Secondary Candidates (Relaxed Overlap)\n\n')
        f.write(f"Relaxed thresholds: overlap>={SECONDARY_MIN_CALLEE_INTERSECT} or overlap2>={SECONDARY_MIN_CALLEE_INTERSECT} (other gates unchanged). Top {min(len(rows_secondary), 50)} shown.\n\n")
        f.write('| Function | Score | DirInt | Overlap | Overlap2 | VertRefs | Shifts | Reasons | TopOverlap | TopOverlap2 |\n')
        f.write('|----------|------:|-------:|--------:|---------:|---------:|-------:|---------|-----------|------------|\n')
        for r in sorted(rows_secondary, key=lambda r: r['score'], reverse=True)[:50]:
            tol = ','.join(r.get('overlap_names', [])[:MAX_OVERLAP_NAMES])
            tol2 = ','.join(r.get('overlap2_names', [])[:MAX_OVERLAP_NAMES])
            f.write(f"| {r['function']} | {r['score']:.2f} | {r['direct_integrators']} | {r['callee_overlap']} | {r.get('callee_overlap2',0)} | {r['vertical_refs']} | {r['shifts']} | {r['reasons']} | {tol} | {tol2} |\n")
    # Neighbor mini-snippets section
    def _collect_snippet(body: str):
        if not body:
            return None
        toks = [SHIFT_TOKEN] + VERT_OFFSETS + ['+ 0x44']
        lines = body.splitlines()
        for i, ln in enumerate(lines):
            if any(t in ln for t in toks):
                lo = max(0, i - SNIPPET_CONTEXT)
                hi = min(len(lines), i + SNIPPET_CONTEXT + 1)
                return '\n'.join(lines[lo:hi])
        return None

    f.write('\n## Top Overlap Neighbor Snippets\n\n')
    if not rows:
        f.write('_No candidates to display._\n')
    else:
        for r in rows[:MAX_SNIPPET_CANDS]:
            cand = r['function']
            f.write(f"### {cand}  (showing up to {MAX_SNIPPET_NEIGHBORS} neighbors)\n\n")
            shown = 0
            ol1 = r.get('overlap_names', []) or []
            ol2 = [n for n in (r.get('overlap2_names', []) or []) if n not in ol1]
            neighbors = ol1 + ol2
            if not neighbors:
                f.write('_No overlapping neighbors._\n\n')
                continue
            for nb in neighbors:
                if shown >= MAX_SNIPPET_NEIGHBORS:
                    break
                body = decomp_cache.get(nb, '')
                snip = _collect_snippet(body)
                f.write(f"- {nb}\n\n")
                if snip:
                    f.write('```c\n')
                    f.write(snip + '\n')
                    f.write('```\n\n')
                else:
                    f.write('_No relevant lines found._\n\n')
                shown += 1
    f.write(f"\n_Heuristic: high overlap without direct call may indicate intermediate aggregation layer; forward/reverse bridge paths (<= {MAX_BRIDGE_DEPTH}) and 2-hop overlap highlight plausible composition chains._\n")

# Emit JSON summary for programmatic triage
JSON_OUT = EXPORTS / 'gravity_chain_intersections.json'
import json as _json
payload = {
    'thresholds': {
        'MIN_CALLEE_INTERSECT': MIN_CALLEE_INTERSECT,
        'MIN_CALLEE_INTERSECT2': MIN_CALLEE_INTERSECT2,
        'MIN_VERTICAL_REFS': MIN_VERTICAL_REFS,
        'MIN_SHIFTS': MIN_SHIFTS,
        'MAX_BRIDGE_DEPTH': MAX_BRIDGE_DEPTH,
        'SECONDARY_MIN_CALLEE_INTERSECT': SECONDARY_MIN_CALLEE_INTERSECT,
    },
    'integrators_count': len(integrators),
    'integrator_callee_union_count': len(integrator_callee_union),
    'integrator_callee_union2_count': len(integrator_callee_union2),
    'candidates': rows,
    'secondary': sorted(rows_secondary, key=lambda r: r['score'], reverse=True)[:200],
    'bridges': bridge_paths,
    'bridges_reverse': bridge_paths_rev,
}
JSON_OUT.write_text(_json.dumps(payload, indent=2), encoding='utf-8')

print(f'Wrote {OUT_MD} ({len(rows)} candidates)')
