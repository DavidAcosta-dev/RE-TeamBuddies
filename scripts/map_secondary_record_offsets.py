import json
import re
from pathlib import Path

EXPORTS_DIR = Path(__file__).resolve().parents[1] / "exports"
OUT_FILE = EXPORTS_DIR / "secondary_record_offsets.md"

# Capture assignments: *(int *)(<base> + 0x11c) = <rhs>;
ASSIGN_RE = re.compile(r"\*\(int \*\)\(([^)]+)\+\s*0x11c\)\s*=\s*([a-zA-Z0-9_]+);")
# Capture uses like *(type *)(<rhs> + 0xNN)
USE_RE_TMPL = r"\*\([^)]*\)\(\s*{rhs}\s*\+\s*0x([0-9a-fA-F]+)\)"

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
            assigns = ASSIGN_RE.findall(decomp)
            if not assigns:
                continue
            # For each RHS var, find offset uses in this function body
            for _, rhs in assigns:
                use_re = re.compile(USE_RE_TMPL.format(rhs=re.escape(rhs)))
                offsets = set(m.group(1).lower() for m in use_re.finditer(decomp))
                if offsets:
                    rows.append({
                        "file": fp.name,
                        "function": fname,
                        "ea": fea,
                        "rhs": rhs,
                        "offsets": sorted(offsets),
                    })
    return rows

def main():
    targets = sorted(EXPORTS_DIR.glob("bundle_*.jsonl"))
    all_rows = []
    for fp in targets:
        all_rows.extend(scan_file(fp))
    with OUT_FILE.open("w", encoding="utf-8") as out:
        out.write("# Secondary record offsets used after +0x11C assignment\n\n")
        if not all_rows:
            out.write("No assignments or uses found.\n")
            return
        out.write("| File | Function | EA | RHSVar | Offsets(Hex) |\n")
        out.write("|------|----------|----|--------|--------------|\n")
        for r in all_rows:
            out.write(f"| {r['file']} | {r['function']} | {r['ea']} | {r['rhs']} | {', '.join(r['offsets'])} |\n")

if __name__ == "__main__":
    main()
