#!/usr/bin/env python3
"""
Detect paired state togglers likely corresponding to pickup/drop/throw.

Heuristic:
- Parse decompilation text and extract struct writes of the form X->field OP= RHS;
- Classify per (binary, function) the writes by field key and op pattern:
  - assign_zero:  field = 0
  - assign_nonzero: field = <non-zero expr>
  - set_bits:     field |= MASK (or field = field | MASK)
  - clear_bits:   field &= ~MASK (or field = field & ~MASK)
- For each field key, find pairs of functions that perform complementary ops
  (assign_nonzero vs assign_zero) or (set_bits vs clear_bits with same MASK).
- Score pairs by:
  - proximity to input hubs (BFS distance from known seeds per binary)
  - number of struct derefs ("->") inside functions (denser structs favored)
  - presence of pickup/drop/throw tokens in strings_used
  - presence of mask 0x4 or (1<<2) usage

Outputs:
- exports/pickup_drop_pairs.md and .csv
- Optional: propose overlay names (NOT writing curated names; leave to curator step)
"""
from __future__ import annotations
import json
import re
from collections import defaultdict, deque
from pathlib import Path
import csv

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / 'exports'

# Known input dispatch/decode seeds (extended at runtime by parsing input_candidates_*.md)
STATIC_SEED_KEYS = {
    ('MAIN.EXE', 'FUN_0001d600'),  # update_state_dispatch
    ('MAIN.EXE', 'FUN_000235d4'),  # suspect_input_decode_table
}

SEED_LINE_RX = re.compile(r"^Seed:\s*([A-Za-z0-9_]+)")

def discover_seeds_from_reports():
    seeds = set(STATIC_SEED_KEYS)
    for p in EXPORTS.glob('input_candidates_*.md'):  # filename implies binary
        binname = p.stem.replace('input_candidates_', '')
        try:
            text = p.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        for line in text.splitlines()[:8]:  # header area
            m = SEED_LINE_RX.search(line)
            if m:
                fname = m.group(1)
                seeds.add((binname, fname))
                break
    return seeds

# Tokens suggesting crate interactions
TOKENS = [r'crate', r'throw', r'pickup', r'pick up', r'drop', r'carry']
TOKENS_RX = [re.compile(t, re.IGNORECASE) for t in TOKENS]

# Regexes to extract and classify writes
WRITE_RX = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*->\s*([A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+)\s*(\|=|&=|\^=|=)\s*(.*?);",
    re.DOTALL,
)
# Ghidra often emits pointer-offset style writes: *(type *)(base +/- off) OP= RHS;
PTR_WRITE_RX = re.compile(
    r"\*\s*\([^)]*\)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)\s*\)\s*(\|=|&=|\^=|=)\s*(.*?);",
    re.DOTALL,
)
HEX_RX = re.compile(r"0x[0-9a-fA-F]+")
SHIFT1_RX = re.compile(r"1\s*<<\s*(\d+)")
MASK4_RX = re.compile(r"&\s*(0x4)\b|&\s*\(\s*1\s*<<\s*2\s*\)")


def load_bundles():
    bundles = sorted(EXPORTS.glob('bundle_*.jsonl'))
    for p in bundles:
        with p.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def build_graph(records):
    graph = defaultdict(set)
    meta = {}
    for fn in records:
        b = fn.get('binary')
        func = fn.get('function') or {}
        name = func.get('name') or ''
        k = (b, name)
        meta[k] = fn
        for c in (fn.get('callees') or []):
            graph[k].add((b, c))
        for c in (fn.get('callers') or []):
            graph[k].add((b, c))
    return graph, meta


def bfs_dist(graph, seeds, max_depth=4):
    dist = {}
    q = deque()
    for s in seeds:
        dist[s] = 0
        q.append(s)
    while q:
        cur = q.popleft()
        d = dist[cur]
        if d >= max_depth:
            continue
        cb, _ = cur
        for nxt in graph.get(cur, ()):  # same-binary only
            if nxt[0] != cb:
                continue
            if nxt not in dist:
                dist[nxt] = d + 1
                q.append(nxt)
    return dist


def classify_write(op: str, rhs: str):
    rhs_clean = rhs.strip()
    # Direct zero/non-zero assigns
    if op == '=':
        if re.fullmatch(r"0+", rhs_clean) or rhs_clean == '0':
            return 'assign_zero', 0
        # Try to see if constant non-zero
        if HEX_RX.fullmatch(rhs_clean):
            return 'assign_nonzero', int(rhs_clean, 16)
        if SHIFT1_RX.search(rhs_clean):
            try:
                n = int(SHIFT1_RX.search(rhs_clean).group(1))
            except Exception:
                n = None
            return 'assign_nonzero', (1 << n) if n is not None else 1
        return 'assign_nonzero', None  # variable or call result
    # Bitwise ops
    if op == '|=':
        # Extract mask if present
        m = HEX_RX.search(rhs_clean)
        if m:
            return 'set_bits', int(m.group(0), 16)
        ms = SHIFT1_RX.search(rhs_clean)
        if ms:
            try:
                return 'set_bits', 1 << int(ms.group(1))
            except Exception:
                return 'set_bits', None
        return 'set_bits', None
    if op == '&=':
        # Look for ~MASK pattern
        if '~' in rhs_clean:
            # Try constants first
            m = HEX_RX.search(rhs_clean)
            if m:
                return 'clear_bits', int(m.group(0), 16)
            ms = SHIFT1_RX.search(rhs_clean)
            if ms:
                try:
                    return 'clear_bits', 1 << int(ms.group(1))
                except Exception:
                    return 'clear_bits', None
            return 'clear_bits', None
        # Non-inverted AND looks like a mask application; treat as ambiguous
        return 'and_mask', None
    if op == '^=':
        # Toggle bits; could be throw/flip
        m = HEX_RX.search(rhs_clean)
        if m:
            return 'toggle_bits', int(m.group(0), 16)
        ms = SHIFT1_RX.search(rhs_clean)
        if ms:
            try:
                return 'toggle_bits', 1 << int(ms.group(1))
            except Exception:
                return 'toggle_bits', None
        return 'toggle_bits', None
    return 'other', None


def extract_writes(fn_rec):
    dec = fn_rec.get('decompilation') or ''
    func = fn_rec.get('function') or {}
    name = func.get('name') or ''
    bname = fn_rec.get('binary') or ''
    writes = []
    # Struct arrow style
    for m in WRITE_RX.finditer(dec):
        base, field, op, rhs = m.groups()
        kind, mask = classify_write(op, rhs)
        # Skip useless/ambiguous
        if kind in ('other', 'and_mask'):
            continue
        # Form a field key; we ignore the base var name (param naming varies)
        field_key = field
        writes.append({
            'binary': bname,
            'name': name,
            'field': field_key,
            'op': kind,
            'mask': mask,
        })
    # Pointer-offset style
    for m in PTR_WRITE_RX.finditer(dec):
        base, sign, off, op, rhs = m.groups()
        kind, mask = classify_write(op, rhs)
        if kind in ('other', 'and_mask'):
            continue
        try:
            off_int = int(off, 16) if off.lower().startswith('0x') else int(off)
            if sign == '-':
                off_int = -off_int
            off_norm = f"{off_int:+#x}"
        except Exception:
            off_norm = f"{sign}{off}"
        field_key = off_norm  # normalized offset as field key
        writes.append({
            'binary': bname,
            'name': name,
            'field': field_key,
            'op': kind,
            'mask': mask,
        })
    return writes


def has_mask4_usage(dec: str) -> int:
    return 1 if MASK4_RX.search(dec or '') else 0


def token_hits(strings_used) -> int:
    n = 0
    for s in (strings_used or []):
        if isinstance(s, dict):
            sv = s.get('text') or s.get('s') or s.get('value') or ''
        else:
            sv = str(s)
        for rx in TOKENS_RX:
            if rx.search(sv or ''):
                n += 1
                break
    return n


def main():
    recs = list(load_bundles())
    if not recs:
        print('No bundle_*.jsonl records found under exports/. Run export_bundles.ps1 first.')
        return
    graph, meta = build_graph(recs)

    # Build BFS distances from seeds where available
    seed_keys = discover_seeds_from_reports()
    seeds = [s for s in seed_keys if s in meta]
    dist = bfs_dist(graph, seeds, max_depth=4) if seeds else {}

    # Per function metadata used for scoring
    fn_meta = {}
    field_to_fns = defaultdict(list)
    for fn in recs:
        b = fn.get('binary')
        func = fn.get('function') or {}
        name = func.get('name') or ''
        k = (b, name)
        dec = fn.get('decompilation') or ''
        arrows = dec.count('->')
        m4 = has_mask4_usage(dec)
        th = token_hits(fn.get('strings_used'))
        fn_meta[k] = {
            'arrows': arrows,
            'mask4': m4,
            'tok_hits': th,
            'size': func.get('size') or 0,
            'dist': dist.get(k, None),
            'ea': func.get('ea') or 0,
        }
        for w in extract_writes(fn):
            field_to_fns[(b, w['field'])].append((k, w))

    # Identify complementary operation pairs per field
    pairs = []
    for (b, field), entries in field_to_fns.items():
        # Organize ops by function
        by_fn = defaultdict(list)
        for fnk, w in entries:
            by_fn[fnk].append(w)
        fns = list(by_fn.keys())
        # Compare each pair of functions on this field
        for i in range(len(fns)):
            for j in range(i + 1, len(fns)):
                a, bfn = fns[i], fns[j]
                ops_a = by_fn[a]
                ops_b = by_fn[bfn]
                # Look for complementary patterns
                def op_kinds(ops):
                    return {o['op'] for o in ops}
                kinds_a = op_kinds(ops_a)
                kinds_b = op_kinds(ops_b)
                comp = False
                pair_type = None
                mask_match = 0
                # assign_nonzero vs assign_zero
                if ('assign_nonzero' in kinds_a and 'assign_zero' in kinds_b) or ('assign_zero' in kinds_a and 'assign_nonzero' in kinds_b):
                    comp = True
                    pair_type = 'assign_nonzero_vs_zero'
                # set_bits vs clear_bits with same mask
                if not comp and ('set_bits' in kinds_a and 'clear_bits' in kinds_b or 'clear_bits' in kinds_a and 'set_bits' in kinds_b):
                    # Check if they share a mask value when present
                    masks_a = {o['mask'] for o in ops_a if o['op'] in ('set_bits', 'clear_bits') and o['mask'] is not None}
                    masks_b = {o['mask'] for o in ops_b if o['op'] in ('set_bits', 'clear_bits') and o['mask'] is not None}
                    inter = masks_a & masks_b
                    if inter:
                        comp = True
                        pair_type = f"bit_set_clear(mask=0x{next(iter(inter)):x})"
                        mask_match = 1
                    else:
                        # Still consider complementary without explicit mask
                        comp = True
                        pair_type = 'bit_set_clear(mask=? )'
                # toggle_bits paired with either assign or set/clear is also interesting
                if not comp and (('toggle_bits' in kinds_a and ('assign_' in ''.join(kinds_b) or 'set_bits' in kinds_b or 'clear_bits' in kinds_b)) or ('toggle_bits' in kinds_b and ('assign_' in ''.join(kinds_a) or 'set_bits' in kinds_a or 'clear_bits' in kinds_a))):
                    comp = True
                    pair_type = 'toggle_vs_mutate'

                if not comp:
                    continue

                ma = fn_meta.get(a, {})
                mb = fn_meta.get(bfn, {})
                # Score: lower distance is better; if None, treat as 5
                da = ma.get('dist', None)
                db = mb.get('dist', None)
                da = 5 if da is None else da
                db = 5 if db is None else db
                near = 0
                if isinstance(da, int) and da <= 3:
                    near += 1
                if isinstance(db, int) and db <= 3:
                    near += 1
                score = (
                    (2 - min(da, 5)) + (2 - min(db, 5))
                    + min(ma.get('arrows', 0), 4) + min(mb.get('arrows', 0), 4)
                    + (ma.get('mask4', 0) + mb.get('mask4', 0)) * 4
                    + (ma.get('tok_hits', 0) + mb.get('tok_hits', 0)) * 2
                    + mask_match * 3
                )
                pairs.append({
                    'field': field,
                    'a_bin': a[0], 'a_name': a[1], 'a_ea': ma.get('ea'), 'a_dist': ma.get('dist'), 'a_arrows': ma.get('arrows'), 'a_mask4': ma.get('mask4'), 'a_toks': ma.get('tok_hits'),
                    'b_bin': bfn[0], 'b_name': bfn[1], 'b_ea': mb.get('ea'), 'b_dist': mb.get('dist'), 'b_arrows': mb.get('arrows'), 'b_mask4': mb.get('mask4'), 'b_toks': mb.get('tok_hits'),
                    'pair_type': pair_type,
                    'score': int(score),
                })

    # Rank pairs, prefer MAIN.EXE and GAME.BIN
    def pair_key(p):
        pref = 2 if (p['a_bin'] == 'MAIN.EXE' or p['b_bin'] == 'MAIN.EXE') else (1 if (p['a_bin'] == 'GAME.BIN' or p['b_bin'] == 'GAME.BIN') else 0)
        return (p['score'], pref)

    pairs.sort(key=pair_key, reverse=True)

    out_md = EXPORTS / 'pickup_drop_pairs.md'
    out_csv = EXPORTS / 'pickup_drop_pairs.csv'
    with out_md.open('w', encoding='utf-8') as f:
        f.write('# Paired state togglers (pickup/drop/throw suspects)\n\n')
        for p in pairs[:200]:
            f.write(
                f"- field={p['field']} | type={p['pair_type']} | score={p['score']}\n"
                f"  - A: {p['a_bin']}:{p['a_name']} @ 0x{(p['a_ea'] or 0):x} d={p['a_dist']} ->={p['a_arrows']} m4={p['a_mask4']} tok={p['a_toks']}\n"
                f"  - B: {p['b_bin']}:{p['b_name']} @ 0x{(p['b_ea'] or 0):x} d={p['b_dist']} ->={p['b_arrows']} m4={p['b_mask4']} tok={p['b_toks']}\n"
            )
    with out_csv.open('w', encoding='utf-8', newline='') as f:
        wr = csv.writer(f)
        wr.writerow(['field','pair_type','score','a_bin','a_name','a_ea','a_dist','a_arrows','a_mask4','a_toks','b_bin','b_name','b_ea','b_dist','b_arrows','b_mask4','b_toks'])
        for p in pairs:
            wr.writerow([p['field'], p['pair_type'], p['score'], p['a_bin'], p['a_name'], f"0x{(p['a_ea'] or 0):x}", p['a_dist'], p['a_arrows'], p['a_mask4'], p['a_toks'], p['b_bin'], p['b_name'], f"0x{(p['b_ea'] or 0):x}", p['b_dist'], p['b_arrows'], p['b_mask4'], p['b_toks']])
    print('Wrote', out_md)
    print('Wrote', out_csv)


if __name__ == '__main__':
    main()
