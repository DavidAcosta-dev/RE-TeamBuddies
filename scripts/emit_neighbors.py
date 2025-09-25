import json
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


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
    # load curated names for quick rename mapping
    overlay = defaultdict(dict)
    ov_path = EXPORTS / "curated_overlays.json"
    if ov_path.exists():
        data = json.loads(ov_path.read_text(encoding="utf-8"))
        for binname, entries in data.items():
            for e in entries:
                old = e.get("name")
                new = e.get("new_name")
                if old and new:
                    overlay[binname][old] = new

    # build index by address for MAIN.EXE
    by_name = {}
    edges = defaultdict(lambda: {"in": set(), "out": set(), "fn": None})
    # First pass: record functions and outgoing edges
    for fn in load_bundles():
        binname = fn.get("binary")
        func = fn.get("function") or {}
        name = func.get("name") or ""
        key = (binname, name)
        edges[key]["fn"] = fn
        for cal in fn.get("callees", []) or []:
            edges[key]["out"].add((binname, cal))
        for caller in fn.get("callers", []) or []:
            edges[key]["in"].add((binname, caller))
        by_name[key] = fn

    # Second pass: compute reverse callers from callees
    for src, data in list(edges.items()):
        for b, cal in data["out"]:
            edges[(b, cal)]["in"].add(src)

    targets = [
        ("MAIN.EXE", "FUN_00002434"),
        ("MAIN.EXE", "FUN_000021d4"),
        ("MAIN.EXE", "FUN_00002584"),
        ("MAIN.EXE", "FUN_000026f4"),
        ("MAIN.EXE", "FUN_000028d8"),
    ]

    out_md = EXPORTS / "cdstream_neighbors.md"
    with out_md.open("w", encoding="utf-8") as f:
        f.write("# CD stream neighbors (callers/callees)\n\n")
        for key in targets:
            fn = by_name.get(key)
            if not fn:
                continue
            binname, oldname = key
            show = overlay[binname].get(oldname, oldname)
            f.write(f"## {binname}:{show} ({oldname})\n\n")
            outs = sorted(edges[key]["out"]) if key in edges else []
            ins = sorted(edges[key]["in"]) if key in edges else []
            if outs:
                f.write("- Callees:\n")
                for b, n in outs:
                    nn = overlay[b].get(n, n)
                    f.write(f"  - {b}:{nn} ({n})\n")
            if ins:
                f.write("- Callers:\n")
                for b, n in ins:
                    nn = overlay[b].get(n, n)
                    f.write(f"  - {b}:{nn} ({n})\n")
            f.write("\n")
    print(f"Wrote {out_md}")


if __name__ == "__main__":
    main()
