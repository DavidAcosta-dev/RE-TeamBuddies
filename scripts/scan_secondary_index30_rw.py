import json
import re
from pathlib import Path

EXPORTS_DIR = Path(__file__).resolve().parents[1] / "exports"
OUT_FILE = EXPORTS_DIR / "secondary_index30_rw.md"

# Match (*(short|undefined2) **)(X + 0x11c))[0x30] used on LHS or RHS
# We’ll detect context of assignment if possible.
IDX30_RE = re.compile(r"\(\*\((?:short|undefined2) \*\)\([^)]*\+\s*0x11c\)\)\)\s*\[0x30\]", re.I)

def classify_usage(line: str) -> str:
    # Heuristic: if immediately followed by '=', likely write; if appears after '=', likely read.
    i = line.find("[0x30]")
    if i == -1:
        return "unknown"
    after = line[i+6:]
    before = line[:i]
    if re.search(r"^\s*=", after):
        return "write"
    if "=" in before and not re.search(r"==|!=|<=|>=", before):
        return "read"
    return "unknown"

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
            for m in IDX30_RE.finditer(decomp):
                # Extract a short window around the match for context
                start = max(0, m.start() - 100)
                end = min(len(decomp), m.end() + 100)
                snippet = decomp[start:end]
                kind = classify_usage(decomp[m.start(): m.start()+80])
                rows.append({
                    "file": fp.name,
                    "function": fname,
                    "ea": fea,
                    "kind": kind,
                    "snippet": snippet.replace('\n', ' ')
                })
    return rows

def main():
    targets = sorted(EXPORTS_DIR.glob("bundle_*.jsonl"))
    all_rows = []
    for fp in targets:
        all_rows.extend(scan_file(fp))
    with OUT_FILE.open("w", encoding="utf-8") as out:
        out.write("# Secondary [0x30] reads/writes\n\n")
        if not all_rows:
            out.write("No [0x30] occurrences found.\n")
            return
        out.write("| File | Function | EA | Kind |\n")
        out.write("|------|----------|----|------|\n")
        for r in all_rows:
            out.write(f"| {r['file']} | {r['function']} | {r['ea']} | {r['kind']} |\n")
        out.write("\n\n## Snippets (truncated)\n\n")
        for r in all_rows:
            out.write(f"### {r['function']} @ {r['ea']} ({r['file']}) [{r['kind']}]\n\n")
            out.write("```c\n" + r["snippet"] + "\n```\n\n")

if __name__ == "__main__":
    main()
