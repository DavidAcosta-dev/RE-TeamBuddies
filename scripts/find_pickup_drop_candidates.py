#!/usr/bin/env python3
"""
Find pickup/drop/throw-focused candidates near input dispatchers using strong signals:
- case label 2 (button id)
- mask 0x4 occurrences
- crate-related strings/tokens
- struct access density

Outputs:
- exports/pickup_drop_candidates.csv
- exports/pickup_drop_candidates.md
"""
import json
import re
import csv
from collections import defaultdict, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / 'exports'

SEEDS = [
    ('MAIN.EXE', 'FUN_0001d600'),   # update_state_dispatch
    ('MAIN.EXE', 'FUN_000235d4'),   # suspect_input_decode_table
]

HEX_MASK_RE = re.compile(r'&\s*0x([0-9a-fA-F]+)\b')
SHIFT_DEF_RX = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(?1\w*\s*<<\s*2\w*\)?')
SHIFT_AND_RX = re.compile(r'&\s*\(?1\w*\s*<<\s*2\w*\)?')
CASE_RE = re.compile(r'\bcase\s+(\d+)\s*:')
TOKENS = [r'crate', r'throw', r'pickup', r'pick up', r'drop', r'carry']
RX = [re.compile(t, re.IGNORECASE) for t in TOKENS]

PICKUP_MASK = 0x4


def load_bundles():
    for p in sorted(EXPORTS.glob('bundle_*.jsonl')):
        with p.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                yield obj


def build_graph(objs):
    out = defaultdict(set)
    meta = {}
    for fn in objs:
        b = fn.get('binary')
        func = fn.get('function') or {}
        name = func.get('name') or ''
        k = (b, name)
        meta[k] = fn
        # bidirectional edges
        for c in (fn.get('callees') or []):
            out[k].add((b, c))
        for c in (fn.get('callers') or []):
            out[k].add((b, c))
    return out, meta


def bfs(graph, seeds, max_depth=4):
    dist = {}
    q = deque()
    for s in seeds:
        if s not in graph and s not in dist:
            # still seed, with empty edges assumed
            dist[s] = 0
        else:
            dist[s] = 0
        q.append(s)
    while q:
        cur = q.popleft()
        d = dist[cur]
        if d >= max_depth:
            continue
        cb, _ = cur
        for nxt in graph.get(cur, ()):  # same binary only
            if nxt[0] != cb:
                continue
            if nxt not in dist:
                dist[nxt] = d + 1
                q.append(nxt)
    return dist


def load_overlay():
    overlay = defaultdict(dict)
    ov = EXPORTS / 'curated_overlays.json'
    if ov.exists():
        try:
            data = json.loads(ov.read_text(encoding='utf-8', errors='ignore'))
        except Exception:
            return overlay
        for b, entries in (data or {}).items():
            for e in (entries or []):
                if isinstance(e, dict) and e.get('name') and e.get('new_name'):
                    overlay[b][e['name']] = e['new_name']
    return overlay


def score_fn(fn, pretty_map):
    dec = fn.get('decompilation') or ''
    func = fn.get('function') or {}
    old = func.get('name') or ''
    pretty = pretty_map.get(old, old)
    if pretty.startswith('cdstream_') or pretty.startswith('cd_'):
        return 0, {}
    if ('Bad instruction' in dec) or ('halt_baddata' in dec):
        return 0, {}
    masks = [int(m.group(1), 16) for m in HEX_MASK_RE.finditer(dec)]
    mask_hits = sum(1 for m in masks if m == PICKUP_MASK)
    # Non-literal bit-2 mask detection
    # 1) vars defined as (1 << 2)
    mask_vars = set(m.group(1) for m in SHIFT_DEF_RX.finditer(dec))
    nl_var_uses = 0
    if mask_vars:
        for v in mask_vars:
            # count uses in & expressions
            nl_var_uses += dec.count(f'& {v}') + dec.count(f'{v} &')
    # 2) direct & (1 << 2) pattern
    nl_shift_and = len(SHIFT_AND_RX.findall(dec))
    cases = [int(g) for g in CASE_RE.findall(dec)]
    case2_hits = sum(1 for c in cases if c == 2)
    str_hits = 0
    for s in (fn.get('strings_used') or []):
        if isinstance(s, dict):
            sv = s.get('s') or s.get('str') or s.get('string') or s.get('value') or s.get('text') or ''
        else:
            sv = s or ''
        if not isinstance(sv, str):
            try:
                sv = str(sv)
            except Exception:
                sv = ''
        for rx in RX:
            if rx.search(sv):
                str_hits += 1
    # struct access density
    arrows = dec.count('->')
    size = func.get('size') or 0
    size_score = 2 if 48 <= size <= 1400 else 0
    score = (
        (mask_hits * 5) + (case2_hits * 5)
        + (nl_var_uses * 3) + (nl_shift_and * 4)
        + (min(str_hits, 3) * 2)
        + min(arrows, 4) + size_score
    )
    meta = {
        'mask4': mask_hits,
        'case2': case2_hits,
        'nl_var_uses': nl_var_uses,
        'nl_shift_and': nl_shift_and,
        'str_hits': str_hits,
        'arrows': arrows,
        'size': size,
    }
    return score, meta


def main():
    objs = list(load_bundles())
    graph, meta = build_graph(objs)
    overlay = load_overlay()
    seeds = [s for s in SEEDS if s in meta]
    dist = bfs(graph, seeds, max_depth=4)
    rows = []
    for k, d in dist.items():
        if k[0] != 'MAIN.EXE':
            continue
        fn = meta.get(k)
        s, meta_s = score_fn(fn, overlay.get(k[0], {}))
        if s <= 0:
            continue
        func = fn.get('function') or {}
        rows.append({
            'bin': k[0],
            'addr': f"0x{(func.get('ea') or 0):x}",
            'name': func.get('name') or '',
            'pretty': overlay[k[0]].get(func.get('name') or '', func.get('name') or ''),
            'distance': d,
            'score': s,
            **meta_s,
        })
    rows.sort(key=lambda r: (r['score'], -r['distance'], r['mask4'], r['case2']), reverse=True)

    out_md = EXPORTS / 'pickup_drop_candidates.md'
    out_csv = EXPORTS / 'pickup_drop_candidates.csv'
    with out_md.open('w', encoding='utf-8') as f:
        f.write('# Pickup/Drop/Throw candidates (focused)\n\n')
        for r in rows[:120]:
            f.write(
                f"- {r['bin']}:{r['pretty']} ({r['name']}) @ {r['addr']} | d={r['distance']} | score={r['score']} | "
                f"mask4={r['mask4']} case2={r['case2']} nl_var={r['nl_var_uses']} nl&(1<<2)={r['nl_shift_and']} str={r['str_hits']} ->={r['arrows']} size={r['size']}\n"
            )
    with out_csv.open('w', encoding='utf-8', newline='') as f:
        wr = csv.writer(f)
        wr.writerow(['bin','addr','name','pretty','distance','score','mask4','case2','nl_var_uses','nl_shift_and','str_hits','arrows','size'])
        for r in rows:
            wr.writerow([r['bin'], r['addr'], r['name'], r['pretty'], r['distance'], r['score'], r['mask4'], r['case2'], r['nl_var_uses'], r['nl_shift_and'], r['str_hits'], r['arrows'], r['size']])
    print('Wrote', out_md)
    print('Wrote', out_csv)


if __name__ == '__main__':
    main()
