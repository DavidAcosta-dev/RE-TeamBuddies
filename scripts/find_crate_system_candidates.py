import json
import re
import csv
from collections import defaultdict, deque, Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


SEEDS = [
    ("MAIN.EXE", "FUN_0001d600"),  # update_state_dispatch (curated)
    ("MAIN.EXE", "FUN_000235d4"),  # suspect_input_decode_table
]


PAD_TOKENS = [
    r"wait_crateHeld", r"if_crateOnPad", r"crates:", r"usePad:",
]
PAD_RX = [re.compile(t, re.IGNORECASE) for t in PAD_TOKENS]

# Additional crate-related tokens to search in strings_used and decompilation
CRATE_TOKENS = [
    r"crate", r"throw", r"pickup", r"pick up", r"drop", r"carry", r"pad",
]
CRATE_RX = [re.compile(t, re.IGNORECASE) for t in CRATE_TOKENS]


HEX_MASK_RE = re.compile(r'&\s*0x([0-9a-fA-F]+)\b')
CASE_RE = re.compile(r'\bcase\s+(\d+)\s*:')
BTN_IDS = {0,1,2,3,5,6,7,8,9,12}
BTN_MASKS = {bid: 1 << bid for bid in BTN_IDS}
PICKUP_ID = 2  # from action_button_ids.json: "pickup/drop"


def load_bundles():
    for p in sorted(EXPORTS.glob("bundle_*.jsonl")):
        with p.open("r", encoding="utf-8", errors="ignore") as f:
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
        b = fn.get("binary")
        func = fn.get("function") or {}
        name = func.get("name") or ""
        k = (b, name)
        meta[k] = fn
        for cal in fn.get("callees", []) or []:
            out[k].add((b, cal))
        # Also connect to callers so BFS can explore upstream too
        for caller in fn.get("callers", []) or []:
            out[k].add((b, caller))
    return out, meta


def bfs(graph, seeds, max_depth=4):
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
        for nxt in graph.get(cur, ()):  # downstream only
            if nxt[0] != cb:
                continue
            if nxt not in dist:
                dist[nxt] = d + 1
                q.append(nxt)
    return dist


def score_function(fn, overlay_labels: dict):
    dec = fn.get("decompilation") or ""
    func = fn.get("function") or {}
    old_name = func.get("name") or ""
    pretty = overlay_labels.get(old_name, old_name)
    # Skip obvious IO/streaming functions to avoid noise
    if pretty.startswith("cdstream_") or pretty.startswith("cd_"):
        return 0, {
            "mask_hits": 0,
            "distinct_masks": 0,
            "multi_gate": 0,
            "pad_hits": 0,
            "str_hits": 0,
            "size": func.get("size") or 0,
        }
    # Skip known-bad decomp stubs
    if ('Bad instruction' in dec) or ('halt_baddata' in dec):
        return 0, {
            "mask_hits": 0,
            "distinct_masks": 0,
            "multi_gate": 0,
            "pad_hits": 0,
            "str_hits": 0,
            "size": func.get("size") or 0,
        }
    # Count button mask occurrences and multi-mask gating
    masks = [int(m.group(1), 16) for m in HEX_MASK_RE.finditer(dec)]
    mask_hits = sum(1 for m in masks if m in BTN_MASKS.values())
    distinct = len(set(m for m in masks if m in BTN_MASKS.values()))
    multi_gate = 1 if distinct >= 2 else 0
    # Pickup/drop specific hits (button 2)
    pickup_mask = 1 << PICKUP_ID
    pickup_mask_hit = sum(1 for m in masks if m == pickup_mask)
    # Case label hits
    cases = [int(g) for g in CASE_RE.findall(dec)]
    pickup_case_hit = sum(1 for c in cases if c == PICKUP_ID)
    # Look for throw/pickup style keywords via tutorial DSL context (present in neighbors)
    pad_hits = sum(1 for rx in PAD_RX if rx.search(dec))
    # Look for crate-centric tokens in strings_used and decomp
    str_hits = 0
    strings = fn.get("strings_used") or []
    if strings:
        for s in strings:
            if isinstance(s, dict):
                sv = s.get('s') or s.get('str') or s.get('string') or s.get('value') or s.get('text') or ''
            else:
                sv = s or ''
            if not isinstance(sv, str):
                try:
                    sv = str(sv)
                except Exception:
                    sv = ''
            for rx in CRATE_RX:
                if rx.search(sv):
                    str_hits += 1
    # Also scan decomp for those tokens (lightly)
    for rx in CRATE_RX:
        if rx.search(dec):
            str_hits += 1
    # Lightweight structural score: small-to-medium functions near dispatcher with multiple bit gates
    size = func.get("size") or 0
    size_score = 2 if 48 <= size <= 1400 else 0
    # Final score weighting
    score = (
        mask_hits
        + (multi_gate * 4)
        + (pad_hits * 2)
        + (min(str_hits, 3) * 2)
        + (pickup_mask_hit * 3)
        + (pickup_case_hit * 3)
        + size_score
    )
    return score, {
        "mask_hits": mask_hits,
        "distinct_masks": distinct,
        "multi_gate": multi_gate,
        "pad_hits": pad_hits,
        "str_hits": str_hits,
        "pickup_mask_hit": pickup_mask_hit,
        "pickup_case_hit": pickup_case_hit,
        "size": size,
    }


def main():
    objs = list(load_bundles())
    graph, meta = build_graph(objs)

    # Overlay for pretty names
    overlay = defaultdict(dict)
    ov = EXPORTS / "curated_overlays.json"
    if ov.exists():
        data = json.loads(ov.read_text(encoding="utf-8", errors="ignore"))
        for b, entries in data.items():
            for e in entries:
                if e.get("name") and e.get("new_name"):
                    overlay[b][e["name"]] = e["new_name"]

    seeds = [s for s in SEEDS if s in meta]
    dist = bfs(graph, seeds, max_depth=3)

    rows = []
    for k, d in dist.items():
        if k[0] != "MAIN.EXE":
            continue
        fn = meta.get(k)
        s, meta_s = score_function(fn, overlay.get(k[0], {}))
        if s <= 0:
            continue
        func = fn.get("function") or {}
        addr = f"0x{(func.get('ea') or 0):x}"
        old = func.get("name") or ""
        rows.append({
            "bin": k[0],
            "addr": addr,
            "name": old,
            "pretty": overlay[k[0]].get(old, old),
            "distance": d,
            "score": s,
            **meta_s,
        })

    rows.sort(key=lambda r: (r["score"], -r["distance"], r["mask_hits"]), reverse=True)

    out_md = EXPORTS / "crate_system_candidates.md"
    out_csv = EXPORTS / "crate_system_candidates.csv"
    with out_md.open("w", encoding="utf-8") as f:
        f.write("# Crate system candidates (pickup/drop/throw/pad)\n\n")
        f.write("Heuristic: multi-button gates near dispatcher, DSL pad/throw hints, crate-related strings.\n\n")
        for r in rows[:100]:
            f.write(
                f"- {r['bin']}:{r['pretty']} ({r['name']}) @ {r['addr']} | d={r['distance']} | score={r['score']} | "
                f"masks={r['mask_hits']} distinct={r['distinct_masks']} multi={r['multi_gate']} pad={r['pad_hits']} str={r['str_hits']} "
                f"pickup_mask={r['pickup_mask_hit']} pickup_case={r['pickup_case_hit']} size={r['size']}\n"
            )
    # Emit CSV for downstream curation
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        wr = csv.writer(f)
        wr.writerow([
            "bin","addr","name","pretty","distance","score",
            "mask_hits","distinct_masks","multi_gate","pad_hits","str_hits",
            "pickup_mask_hit","pickup_case_hit","size"
        ])
        for r in rows:
            wr.writerow([
                r['bin'], r['addr'], r['name'], r['pretty'], r['distance'], r['score'],
                r['mask_hits'], r['distinct_masks'], r['multi_gate'], r['pad_hits'], r['str_hits'],
                r['pickup_mask_hit'], r['pickup_case_hit'], r['size']
            ])
    print(f"Wrote {out_md}")
    print(f"Wrote {out_csv}")


if __name__ == "__main__":
    main()
