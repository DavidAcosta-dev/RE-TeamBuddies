import json
import re
from pathlib import Path

EXPORTS_DIR = Path(__file__).resolve().parents[1] / "exports"
OUT_FILE = Path(__file__).resolve().parents[1] / "exports" / "indirect_slots.md"

# Match patterns like: (**(code **)(*(int *)(X + 4) + 0xa4))( ... )
SLOT_CALL_RE = re.compile(r"\(\*\*\(code \*\*\)\(\*(int|uint) \*\)\(([^)]+)\) \+ 0x([0-9a-fA-F]+)\)\)")

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
            # slot calls present?
            slots = []
            for m in SLOT_CALL_RE.finditer(decomp):
                base_expr = m.group(2).strip()
                slot_hex = m.group(3).lower()
                slots.append((base_expr, slot_hex))
            if not slots:
                continue
            # correlate with secondary usage in same function
            sec_uses = "(param_1 + 0x11c)" in decomp or \
                       "+ 0x11c) + 0x60)" in decomp or \
                       ") [0x30]" in decomp or \
                       "+ 0x11c)][0x30]" in decomp
            rows.append({
                "file": fp.name,
                "function": fname,
                "ea": fea,
                "slots": slots,
                "uses_secondary": bool(sec_uses),
            })
    return rows

def main():
    targets = sorted(EXPORTS_DIR.glob("bundle_*.jsonl"))
    all_rows = []
    for fp in targets:
        all_rows.extend(scan_file(fp))
    with OUT_FILE.open("w", encoding="utf-8") as out:
        out.write("# Indirect slot calls (vtable-like)\n\n")
        if not all_rows:
            out.write("No indirect slot calls detected.\n")
            return
        out.write("| File | Function | EA | Slots | UsesSecondary |\n")
        out.write("|------|----------|----|-------|---------------|\n")
        for r in all_rows:
            slots = ", ".join([f"{b}:+0x{s}" for b, s in r["slots"]])
            out.write(f"| {r['file']} | {r['function']} | {r['ea']} | {slots} | {r['uses_secondary']} |\n")

if __name__ == "__main__":
    main()
