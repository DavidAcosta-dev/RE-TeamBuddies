import json
from collections import defaultdict
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
    ("MAIN.EXE", "FUN_000199d4"),
    ("MAIN.EXE", "FUN_0001a028"),
    ("MAIN.EXE", "FUN_0001a038"),
    ("MAIN.EXE", "FUN_0003186c"),
    ("MAIN.EXE", "FUN_00031734"),
    ("MAIN.EXE", "FUN_000317d0"),
    ("MAIN.EXE", "FUN_00030de8"),
    ("MAIN.EXE", "FUN_00030cc8"),
    ("MAIN.EXE", "FUN_00031368"),
    ("MAIN.EXE", "FUN_0002db3c"),
    ("MAIN.EXE", "FUN_00040020"),
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


def main():
    overlay = defaultdict(dict)
    ov_path = EXPORTS / "curated_overlays.json"
    if ov_path.exists():
        data = json.loads(ov_path.read_text(encoding="utf-8", errors="ignore"))
        for b, entries in data.items():
            for e in entries:
                if e.get("name") and e.get("new_name"):
                    overlay[b][e["name"]] = e["new_name"]

    nodes = set(SEEDS)
    edges = set()
    meta = {}
    for fn in load_bundles():
        b = fn.get("binary")
        func = fn.get("function") or {}
        name = func.get("name") or ""
        k = (b, name)
        if k not in nodes:
            continue
        meta[k] = fn
        for cal in fn.get("callees", []) or []:
            edges.add((k, (b, cal)))
            nodes.add((b, cal))

    # Optional: load consumer candidates for highlighting
    consumers = set()
    cons_csv = EXPORTS / "cdstream_consumer_candidates.csv"
    if cons_csv.exists():
        try:
            import csv
            with cons_csv.open("r", encoding="utf-8", newline="") as f:
                for i, row in enumerate(csv.DictReader(f)):
                    if i >= 50:
                        break
                    b = row.get("bin") or ""
                    name = row.get("name") or ""
                    consumers.add((b, name))
        except Exception:
            pass

    # emit graphviz dot
    out_dot = EXPORTS / "cdstream_graph.dot"
    with out_dot.open("w", encoding="utf-8") as f:
        f.write("digraph cdstream {\n")
        f.write("  rankdir=LR;\n  node [shape=box,fontsize=10];\n")
        for b, n in nodes:
            label = overlay[b].get(n, n)
            if b != "MAIN.EXE":
                continue
            color = "#cfe8ff" if (b, n) in consumers else "#ffffff"
            f.write(f'  "{b}:{n}" [label="{label}", style=filled, fillcolor="{color}"];\n')
        for (sb, sn), (tb, tn) in edges:
            if sb != "MAIN.EXE" or tb != "MAIN.EXE":
                continue
            sl = overlay[sb].get(sn, sn)
            tl = overlay[tb].get(tn, tn)
            f.write(f'  "{sb}:{sn}" -> "{tb}:{tn}" [label=""];\n')
        f.write("}\n")
    print(f"Wrote {out_dot}")


if __name__ == "__main__":
    main()
