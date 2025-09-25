import json
import re
from collections import defaultdict, deque, Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


SEEDS = [
    ("MAIN.EXE", "FUN_00002434"),  # cdstream_init_or_start
    ("MAIN.EXE", "FUN_000021d4"),  # cdstream_process_queue
    ("MAIN.EXE", "FUN_00002584"),  # cdstream_poll_idle
    ("MAIN.EXE", "FUN_000026f4"),  # cdstream_reset
    ("MAIN.EXE", "FUN_000028d8"),  # cdstream_register_callback2
]


# Tokens that strongly suggest PS1 CD/streaming low-level work
TOKENS_STRONG = [
    "CdControl", "CdControlB", "CdControlF", "CdReady", "CdSync",
    "CdlLOC", "CdLOC", "btoi", "itob",
]

# Weaker hints common around raw I/O and sector work
TOKENS_WEAK = [
    "loc.minute", "loc.second", "loc.sector",
    "CdlSetloc", "CdlRead", "CdlReadS", "CdlPlay", "CdlSetfilter",
    "memcpy", "memmove", "memset",
]

# Numeric markers: sector sizes and typical raw sizes
NUM_MARKERS = ["0x800", "2048", "0x930", "2352", "0x924", "2340", "2328"]


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
    graph_out = defaultdict(set)
    graph_in = defaultdict(set)
    meta = {}
    for fn in objs:
        binname = fn.get("binary")
        func = fn.get("function") or {}
        name = func.get("name") or ""
        key = (binname, name)
        meta[key] = fn
        for cal in fn.get("callees", []) or []:
            graph_out[key].add((binname, cal))
        for caller in fn.get("callers", []) or []:
            graph_in[key].add((binname, caller))
    # Ensure reverse edges exist via out edges as well
    for src, outs in list(graph_out.items()):
        for dst in outs:
            graph_in[dst].add(src)
    return graph_out, graph_in, meta


def score_text(txt: str) -> Counter:
    low = txt.lower()
    c = Counter()
    for t in TOKENS_STRONG:
        c[f"strong:{t}"] = low.count(t.lower())
    for t in TOKENS_WEAK:
        c[f"weak:{t}"] = low.count(t.lower())
    for t in NUM_MARKERS:
        # token-ish numeric matches to reduce noise
        c[f"num:{t}"] = len(re.findall(rf"(?<![0-9a-zA-Z_]){re.escape(t)}(?![0-9a-zA-Z_])", low))
    return c


def bfs_neighbors(graph_out, graph_in, seeds, max_depth=3, same_binary=True):
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
        cur_bin, _ = cur
        for nxt in graph_out.get(cur, ()):  # downstream
            if same_binary and nxt[0] != cur_bin:
                continue
            if nxt not in dist:
                dist[nxt] = d + 1
                q.append(nxt)
        for prv in graph_in.get(cur, ()):  # upstream
            if same_binary and prv[0] != cur_bin:
                continue
            if prv not in dist:
                dist[prv] = d + 1
                q.append(prv)
    return dist


def main():
    objs = list(load_bundles())
    graph_out, graph_in, meta = build_graph(objs)

    # Load overlay to show curated names in output
    overlay = defaultdict(dict)
    ov_path = EXPORTS / "curated_overlays.json"
    if ov_path.exists():
        data = json.loads(ov_path.read_text(encoding="utf-8", errors="ignore"))
        for b, entries in data.items():
            for e in entries:
                old = e.get("name")
                new = e.get("new_name")
                if old and new:
                    overlay[b][old] = new

    # Restrict to MAIN.EXE and BFS around seeds
    seeds = [s for s in SEEDS if s in meta]
    if not seeds:
        print("No seeds found in bundles; nothing to do.")
        return

    dist = bfs_neighbors(graph_out, graph_in, seeds, max_depth=3, same_binary=True)

    # Score and collect candidates
    rows = []
    for key, d in dist.items():
        fn = meta.get(key)
        if not fn:
            continue
        decomp = fn.get("decompilation") or ""
        counts = score_text(decomp)
        score = sum(counts.values()) + (3 - d)  # bias closer neighbors a bit
        func = fn.get("function") or {}
        addr = func.get("ea") or 0
        oldname = func.get("name") or ""
        binname = fn.get("binary")
        rows.append({
            "binary": binname,
            "address": hex(addr),
            "oldname": oldname,
            "name": overlay[binname].get(oldname, oldname),
            "distance": d,
            "out_degree": len(graph_out.get(key, ())),
            "in_degree": len(graph_in.get(key, ())),
            "score": score,
            "counts": counts,
        })

    rows.sort(key=lambda r: (r["score"], -r["in_degree"], -r["out_degree"]), reverse=True)

    # Emit CSV and MD
    out_csv = EXPORTS / "cdstream_neighbors_scored.csv"
    out_md = EXPORTS / "cdstream_neighbors_scored.md"
    # Collect dynamic headers for counts
    all_keys = []
    seen = set()
    for r in rows:
        for k in r["counts"].keys():
            if k not in seen:
                seen.add(k)
                all_keys.append(k)
    headers = [
        "binary", "address", "oldname", "name", "distance", "in_degree", "out_degree", "score",
    ] + all_keys

    with out_csv.open("w", encoding="utf-8", newline="") as f:
        f.write(",".join(headers) + "\n")
        for r in rows:
            line = {h: "" for h in headers}
            for h in ["binary", "address", "oldname", "name", "distance", "in_degree", "out_degree", "score"]:
                line[h] = str(r[h])
            for k in all_keys:
                line[k] = str(r["counts"].get(k, 0))
            f.write(",".join(line[h].replace(",", " ") for h in headers) + "\n")

    with out_md.open("w", encoding="utf-8") as f:
        f.write("# CD stream neighbor candidates (scored)\n\n")
        f.write("Seeds:\n")
        for s in seeds:
            b, n = s
            show = overlay[b].get(n, n)
            f.write(f"- {b}:{show} ({n})\n")
        f.write("\nTop candidates by score (top 50):\n\n")
        for r in rows[:50]:
            counts_repr = {k: v for k, v in r["counts"].items() if v}
            f.write(
                f"- {r['binary']}:{r['name']} ({r['oldname']}) @ {r['address']} | d={r['distance']} "
                f"| in={r['in_degree']} out={r['out_degree']} | score={r['score']} | {counts_repr}\n"
            )
    print(f"Wrote {out_csv} and {out_md}")


if __name__ == "__main__":
    main()
