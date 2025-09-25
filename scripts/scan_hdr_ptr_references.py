import json
import re
from collections import defaultdict, deque
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


SEEDS = [
    ("MAIN.EXE", "FUN_00002434"),
    ("MAIN.EXE", "FUN_000021d4"),
    ("MAIN.EXE", "FUN_00002584"),
    ("MAIN.EXE", "FUN_000026f4"),
    ("MAIN.EXE", "FUN_000028d8"),
    ("MAIN.EXE", "FUN_000197bc"),
    ("MAIN.EXE", "FUN_00019ec0"),
]


HDR_PTR_RE = re.compile(r"_DAT_80059e9c\b")


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
    return out, meta


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
        for nxt in graph.get(cur, ()):  # downstream only for now
            if same_bin and nxt[0] != cur_b:
                continue
            if nxt not in dist:
                dist[nxt] = d + 1
                q.append(nxt)
    return dist


def main():
    objs = list(load_bundles())
    graph, meta = build_graph(objs)

    # overlay for pretty names
    overlay = defaultdict(dict)
    ov_path = EXPORTS / "curated_overlays.json"
    if ov_path.exists():
        data = json.loads(ov_path.read_text(encoding="utf-8", errors="ignore"))
        for b, entries in data.items():
            for e in entries:
                if e.get("name") and e.get("new_name"):
                    overlay[b][e["name"]] = e["new_name"]

    seeds = [s for s in SEEDS if s in meta]
    dmap = bfs_dist(graph, seeds, same_bin=True, max_depth=4)

    rows = []
    for k, fn in meta.items():
        if k[0] != "MAIN.EXE":
            continue
        dec = fn.get("decompilation") or ""
        hits = len(HDR_PTR_RE.findall(dec))
        if hits:
            d = dmap.get(k, 999)
            func = fn.get("function") or {}
            addr = hex(func.get("ea") or 0)
            oldname = func.get("name") or ""
            rows.append((hits, -d, k[0], overlay[k[0]].get(oldname, oldname), oldname, addr))

    rows.sort(key=lambda x: (x[1], -x[0]))  # closer distance first, then more hits

    out_md = EXPORTS / "hdr_ptr_references.md"
    with out_md.open("w", encoding="utf-8") as f:
        f.write("# Functions referencing header pointer (_DAT_80059e9c)\n\n")
        f.write("Sorted by proximity to streaming seeds (distance asc), then by hit count desc.\n\n")
        for hits, negd, b, name, oldname, addr in rows[:200]:
            d = -negd if negd != -999 else "inf"
            f.write(f"- {b}:{name} ({oldname}) @ {addr} | dist={d} | hits={hits}\n")
    print(f"Wrote {out_md}")


if __name__ == "__main__":
    main()
