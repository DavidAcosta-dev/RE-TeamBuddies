import json
import re
from pathlib import Path

EXPORTS_DIR = Path(__file__).resolve().parents[1] / "exports"
OUT_FILE = Path(__file__).resolve().parents[1] / "exports" / "primary_secptr_writes.md"

# Regex for writes like: *(int *)(X + 0x11c) = Y;
WRITE_RE = re.compile(r"\*\(int \*\)\(([^)]+)\s*\+\s*0x11c\)\s*=\s*([^;]+);")

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
            for m in WRITE_RE.finditer(decomp):
                base, rhs = m.group(1).strip(), m.group(2).strip()
                snippet = m.group(0)
                rows.append({
                    "file": fp.name,
                    "function": fname,
                    "ea": fea,
                    "base": base,
                    "rhs": rhs,
                    "snippet": snippet
                })
    return rows

def main():
    targets = sorted(EXPORTS_DIR.glob("bundle_*.jsonl"))
    all_rows = []
    for fp in targets:
        all_rows.extend(scan_file(fp))

    with OUT_FILE.open("w", encoding="utf-8") as out:
        out.write("# Primary +0x11C (secondary pointer) writes\n\n")
        if not all_rows:
            out.write("No writes found.\n")
            return
        out.write("| File | Function | EA | BaseExpr | RHS |\n")
        out.write("|------|----------|----|----------|-----|\n")
        for r in all_rows:
            out.write(f"| {r['file']} | {r['function']} | {r['ea']} | `{r['base']}` | `{r['rhs']}` |\n")
        out.write("\n\n## Snippets\n\n")
        for r in all_rows:
            out.write(f"### {r['function']} @ {r['ea']} ({r['file']})\n\n")
            out.write("```c\n" + r["snippet"] + "\n```\n\n")

if __name__ == "__main__":
    main()
