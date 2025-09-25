import json
import re
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


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


def main():
    # Load button ids
    btn_path = EXPORTS / "action_button_ids.json"
    btns = json.loads(btn_path.read_text(encoding="utf-8")) if btn_path.exists() else {}
    # Build mask map: id -> 1<<id and also track common alt masks observed
    id_to_mask = {int(k): 1 << int(k) for k in btns.keys()}

    per_btn = defaultdict(list)  # btn -> list of (hits, name, addr)
    for fn in load_bundles():
        if fn.get("binary") != "MAIN.EXE":
            continue
        dec = fn.get("decompilation") or ""
        if not dec:
            continue
        mask_hits = defaultdict(int)
        for m in HEX_MASK_RE.finditer(dec):
            val = int(m.group(1), 16)
            for bid, mval in id_to_mask.items():
                if val == mval:
                    mask_hits[bid] += 1
        if not mask_hits:
            continue
        func = fn.get("function") or {}
        name = func.get("name") or ""
        addr = f"0x{(func.get('ea') or 0):x}"
        for bid, hits in sorted(mask_hits.items(), key=lambda x: -x[1]):
            per_btn[bid].append((hits, name, addr))

    # Emit markdown summary
    out_md = EXPORTS / "input_bitmask_index.md"
    with out_md.open("w", encoding="utf-8") as f:
        f.write("# Input bitmask index (per button)\n\n")
        for bid in sorted(per_btn.keys()):
            label = btns.get(str(bid), "")
            f.write(f"## {bid} — {label}\n\n")
            lst = sorted(per_btn[bid], key=lambda x: x[0], reverse=True)
            for hits, name, addr in lst[:50]:
                f.write(f"- {addr} {name} | hits={hits}\n")
            f.write("\n")
    print(f"Wrote {out_md}")


if __name__ == "__main__":
    main()
