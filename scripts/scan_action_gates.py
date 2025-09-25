import json
import re
from collections import defaultdict, Counter, deque
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


SEED = ("MAIN.EXE", "FUN_0001d600")  # update_state_dispatch
HEX_MASK_RE = re.compile(r'&\s*0x([0-9a-fA-F]+)\b')


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


def bfs(graph, seed, depth=2):
    dist = {seed: 0}
    q = deque([seed])
    while q:
        cur = q.popleft()
        d = dist[cur]
        if d >= depth:
            continue
        cb, _ = cur
        for nxt in graph.get(cur, ()):  # downstream only
            if nxt[0] != cb:
                continue
            if nxt not in dist:
                dist[nxt] = d + 1
                q.append(nxt)
    return dist


def main():
    objs = list(load_bundles())
    graph, meta = build_graph(objs)
    if SEED not in meta:
        print("Seed not found; aborting")
        return
    dist = bfs(graph, SEED, depth=3)

    overlay = defaultdict(dict)
    ov = EXPORTS / "curated_overlays.json"
    if ov.exists():
        data = json.loads(ov.read_text(encoding="utf-8", errors="ignore"))
        for b, entries in data.items():
            for e in entries:
                if e.get("name") and e.get("new_name"):
                    overlay[b][e["name"]] = e["new_name"]

    rows = []
    gate_hist = Counter()
    for k, d in dist.items():
        if k[0] != "MAIN.EXE":
            continue
        fn = meta.get(k)
        dec = fn.get("decompilation") or ""
        gates = [int(m.group(1), 16) for m in HEX_MASK_RE.finditer(dec)]
        if not gates:
            continue
        cnts = Counter(gates)
        for g, c in cnts.items():
            gate_hist[g] += c
        func = fn.get("function") or {}
        addr = f"0x{(func.get('ea') or 0):x}"
        old = func.get("name") or ""
        rows.append((d, addr, overlay[k[0]].get(old, old), old, cnts))

    rows.sort(key=lambda x: (x[0], -sum(x[4].values())))

    out_md = EXPORTS / "action_gate_constants.md"
    with out_md.open("w", encoding="utf-8") as f:
        f.write("# Action gate constants near dispatcher\n\n")
        f.write("Top recurring bit masks across neighbors of update_state_dispatch.\n\n")
        top = gate_hist.most_common(40)
        if top:
            f.write("## Top masks (global)\n\n")
            for g, c in top:
                f.write(f"- 0x{g:x} : {c}\n")
            f.write("\n")
        for d, addr, pretty, old, cnts in rows[:120]:
            f.write(f"- d={d} {addr} {pretty} ({old}) | gates=" + ", ".join(f"0x{k:x}:{v}" for k, v in cnts.most_common()) + "\n")
    print(f"Wrote {out_md}")


if __name__ == "__main__":
    main()
