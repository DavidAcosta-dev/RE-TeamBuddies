import json
import re
from pathlib import Path

EXPORTS_DIR = Path(__file__).resolve().parents[1] / "exports"
OUT_FILE = EXPORTS_DIR / "secondary_gate_writes.md"

GATE_WRITE_RE = re.compile(r"\*\(short \*\)\(\*(?:int|uint) \*\)\([^)]*\+\s*0x11c\) \+ 0x60\)\s*=\s*", re.I)

def scan_file(fp: Path):
    rows = []
    with fp.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            decomp = obj.get("decompilation") or ""
            fn = obj.get("function", {})
            fname = fn.get("name") or "?"
            fea = fn.get("ea")
            if not decomp:
                continue
            if GATE_WRITE_RE.search(decomp):
                rows.append({
                    "file": fp.name,
                    "function": fname,
                    "ea": fea,
                })
    return rows

def main():
    targets = sorted(EXPORTS_DIR.glob("bundle_*.jsonl"))
    all_rows = []
    for fp in targets:
        all_rows.extend(scan_file(fp))
    with OUT_FILE.open("w", encoding="utf-8") as out:
        out.write("# Secondary +0x60 gate writes\n\n")
        if not all_rows:
            out.write("No gate writes found.\n")
            return
        out.write("| File | Function | EA |\n")
        out.write("|------|----------|----|\n")
        for r in all_rows:
            out.write(f"| {r['file']} | {r['function']} | {r['ea']} |\n")

if __name__ == "__main__":
    main()
