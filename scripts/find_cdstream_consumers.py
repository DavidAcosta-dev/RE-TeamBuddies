import csv
import json
import re
from collections import defaultdict, deque
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


# Streaming seeds with emphasis on dispatch/advance path (likely parents of consumers)
SEEDS = [
    ("MAIN.EXE", "FUN_0001a028"),  # cdstream_advance_and_dispatch
    ("MAIN.EXE", "FUN_0001a038"),  # cdstream_advance_and_dispatch2
    ("MAIN.EXE", "FUN_00002434"),  # cdstream_init_or_start
    ("MAIN.EXE", "FUN_000021d4"),  # cdstream_process_queue
    ("MAIN.EXE", "FUN_00002584"),  # cdstream_poll_idle
]


# Low-level CD helpers we want to exclude (driver/wrapper layer)
HELPER_NAMES = {
    "MAIN.EXE": {
        "FUN_00040020",  # cd_cmd_issue
        "thunk_FUN_00040020",  # alias name
        "FUN_0003186c",  # cd_cmd_dispatch
        "FUN_00031734",  # cd_cmd_finalize_a
        "FUN_000317d0",  # cd_cmd_finalize_b
        "FUN_00030de8",  # cd_dma_copy_partial
        "FUN_00030cc8",  # cd_ring_rewind
        "FUN_00031368",  # cd_reset_ptrs
        "FUN_0002db3c",  # cd_poll_ready
        "FUN_000197bc",  # cdstream_device_pump (staging)
        "FUN_00019ec0",  # cdstream_stage_payload (staging)
        "FUN_000199d4",  # cdstream_memcpy_sector
    }
}


HDR_PTR_RE = re.compile(r"_DAT_80059e9c\b")
STATE_TOKENS = [
    r"_DAT_80057a1c", r"_DAT_80057a40", r"_DAT_80059e98",
    r"_DAT_80057a10", r"_DAT_80057a18", r"_DAT_80057a20",
    r"_DAT_80057a38", r"_DAT_80057a24", r"_DAT_80057a3c",
]
STATE_RES = [re.compile(t) for t in STATE_TOKENS]
MEMCPY_RE = re.compile(r"\bmemcpy\b|\bmemmove\b|\bmemset\b", re.IGNORECASE)
LOOP_RE = re.compile(r"\bfor\s*\(|\bwhile\s*\(|\bdo\s*\{", re.IGNORECASE)
TAG_PATTERNS = [
    ("HDR_SKIP_20", re.compile(r"\+\s*0x20\b")),
    ("DMA_1F8", re.compile(r"0x1f8\b|FUN_00030de8|cd_dma_copy_partial")),
    ("SECTOR_800", re.compile(r"0x800\b")),
    ("PACK_END_CHECK", re.compile(r"\(ushort\)\s*_DAT_80059e9c\[3\]\s*-\s*1\s*==")),
]


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
    rev = defaultdict(set)
    meta = {}
    for fn in objs:
        b = fn.get("binary")
        func = fn.get("function") or {}
        name = func.get("name") or ""
        k = (b, name)
        meta[k] = fn
        for cal in fn.get("callees", []) or []:
            out[k].add((b, cal))
            rev[(b, cal)].add(k)
    return out, rev, meta


def bfs_dist(graph, seeds, same_bin=True, max_depth=4):
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
        cur_b, _ = cur
        for nxt in graph.get(cur, ()):
            if same_bin and nxt[0] != cur_b:
                continue
            if nxt not in dist:
                dist[nxt] = d + 1
                q.append(nxt)
    return dist


def main():
    objs = list(load_bundles())
    out_graph, rev_graph, meta = build_graph(objs)

    # Load curated overlay for pretty names
    overlay = defaultdict(dict)
    ov_path = EXPORTS / "curated_overlays.json"
    if ov_path.exists():
        data = json.loads(ov_path.read_text(encoding="utf-8", errors="ignore"))
        for b, entries in data.items():
            for e in entries:
                if e.get("name") and e.get("new_name"):
                    overlay[b][e["name"]] = e["new_name"]

    seeds = [s for s in SEEDS if s in meta]
    # Distance downstream from dispatch/advance (consumers are expected as callees)
    d_down = bfs_dist(out_graph, seeds, same_bin=True, max_depth=5)
    # Also consider upstream distance to catch parents of dispatch/advance (less likely consumers)
    d_up = bfs_dist(rev_graph, seeds, same_bin=True, max_depth=2)

    per_bin = defaultdict(list)
    for k, fn in meta.items():
        b, name = k
        if b != "MAIN.EXE":
            continue
        dec = fn.get("decompilation") or ""
        # Skip seed functions themselves
        if k in seeds:
            continue
        # exclude direct driver/staging helpers
        callees = set(fn.get("callees", []) or [])
        helper_hits = sum(1 for h in HELPER_NAMES.get(b, set()) if h in callees)
        if helper_hits or name in HELPER_NAMES.get(b, set()):
            # likely part of driver layer; skip for consumer list
            continue
        # Exclude generic thunk wrappers to avoid noise
        if name.startswith("thunk_"):
            continue
        # tag signals (header-adjacent markers)
        tag_hits = 0
        tag_flags = []
        for tag, rx in TAG_PATTERNS:
            if rx.search(dec):
                tag_hits += 1
                tag_flags.append(tag)
        # distances
        dd = d_down.get(k, 999)
        du = d_up.get(k, 999)
        prox = dd  # prioritize downstream distance for consumers
        if prox >= 999:
            # Not connected; skip to focus on neighborhood
            continue
        func = fn.get("function") or {}
        ea = func.get("ea") or 0
        callers_n = len(fn.get("callers", []) or [])
        callees_n = len(fn.get("callees", []) or [])
        # feature counts
        hdr_hits = len(HDR_PTR_RE.findall(dec))
        state_hits = sum(len(rx.findall(dec)) for rx in STATE_RES)
        memcpy_hits = len(MEMCPY_RE.findall(dec))
        loops = 1 if LOOP_RE.search(dec) else 0
        # scoring: proximity, state/header usage, structural signals, and some weight for being called
        score = (
            (max(0, 5 - prox) * 4)
            + (state_hits)
            + (hdr_hits * 2)
            + (tag_hits * 2)
            + (memcpy_hits * 2)
            + (loops * 2)
            + min(5, callers_n)
        )
        per_bin[b].append({
            "bin": b,
            "name": name,
            "pretty": overlay[b].get(name, name),
            "addr": f"0x{ea:x}",
            "dist": prox,
            "hdr_hits": hdr_hits,
            "state_hits": state_hits,
            "tag_hits": tag_hits,
            "tags": ",".join(tag_flags),
            "helper_hits": helper_hits,
            "callers": callers_n,
            "callees": callees_n,
            "memcpy": memcpy_hits,
            "loops": loops,
            "score": score,
        })

    # Write CSV and MD
    out_csv = EXPORTS / "cdstream_consumer_candidates.csv"
    rows = sorted(per_bin.get("MAIN.EXE", []), key=lambda r: (r["score"], -r["callers"], -r["state_hits"]), reverse=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "bin", "addr", "name", "pretty", "dist", "hdr_hits", "state_hits", "memcpy", "loops", "tag_hits", "tags", "helper_hits", "callers", "callees", "score"
        ])
        w.writeheader()
        for r in rows:
            w.writerow(r)

    out_md = EXPORTS / "cdstream_consumer_candidates.md"
    with out_md.open("w", encoding="utf-8") as f:
        f.write("# CD stream consumer/pack-parser candidates\n\n")
        f.write("Ranked by proximity to dispatch, header-pointer usage, and marker tags. Excludes low-level CD helpers.\n\n")
        for r in rows[:200]:
            f.write(
                f"- {r['bin']}:{r['pretty']} ({r['name']}) @ {r['addr']} | dist={r['dist']} | hdr={r['hdr_hits']} | state={r['state_hits']} | memcpy={r['memcpy']} | loops={r['loops']} | tags={r['tags'] or '-'} | callers={r['callers']} | score={r['score']}\n"
            )
    print(f"Wrote {out_csv} and {out_md}")


if __name__ == "__main__":
    main()
