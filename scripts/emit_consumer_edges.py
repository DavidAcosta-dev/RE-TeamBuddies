import csv
import json
from pathlib import Path


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
    # Load overlay for pretty names
    overlay = {}
    ov = EXPORTS / "curated_overlays.json"
    if ov.exists():
        data = json.loads(ov.read_text(encoding="utf-8", errors="ignore"))
        for b, entries in data.items():
            for e in entries:
                if e.get("name") and e.get("new_name"):
                    overlay[(b, e["name"])] = e["new_name"]

    # Index bundles by (bin,name)
    meta = {}
    for fn in load_bundles():
        b = fn.get("binary")
        f = fn.get("function") or {}
        n = f.get("name") or ""
        meta[(b, n)] = fn

    # Read consumer candidates
    cons_path = EXPORTS / "cdstream_consumer_candidates.csv"
    cand = []
    if cons_path.exists():
        with cons_path.open("r", encoding="utf-8", newline="") as f:
            for i, row in enumerate(csv.DictReader(f)):
                if i >= 50:
                    break
                cand.append((row.get("bin") or "", row.get("name") or ""))

    out = ["# Consumer candidate callers/callees\n"]
    for key in cand:
        fn = meta.get(key)
        if not fn:
            continue
        b, n = key
        pretty = overlay.get(key, n)
        ea = hex((fn.get("function") or {}).get("ea") or 0)
        out.append(f"\n## {b}:{pretty} ({n}) @ {ea}\n")
        callers = [(b, c) for c in (fn.get("callers") or [])]
        callees = [(b, c) for c in (fn.get("callees") or [])]
        if callers:
            out.append("- Callers:\n")
            for cb, cn in callers:
                label = overlay.get((cb, cn), cn)
                out.append(f"  - {cb}:{label} ({cn})\n")
        else:
            out.append("- Callers: (none)\n")
        if callees:
            out.append("- Callees:\n")
            for cb, cn in callees:
                label = overlay.get((cb, cn), cn)
                out.append(f"  - {cb}:{label} ({cn})\n")
        else:
            out.append("- Callees: (none)\n")

    out_path = EXPORTS / "cdstream_consumer_edges.md"
    out_path.write_text("\n".join(out), encoding="utf-8")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
