import json
import os
import re
from typing import Dict, List, Tuple

"""
Scan the exported JSONL (exports/bundle_MAIN.EXE.jsonl) and extract calls to the
scheduler function FUN_00035324, classifying whether the target pointer is +0x3c
or +0x40 and capturing surrounding evidence of which pad masks gated the call
inside the same function's decompilation text.

Heuristics:
- Look for lines containing "FUN_00035324(" and then search nearby text for
  substrings "+ 0x3c)" or "+ 0x40)" to categorize the target slot.
- Within the same decompilation, scan for bitmask checks around 0x8000, 0x2000,
  0x40, 0x2, 0x10 to provide context of which input branches exist in the function.

Output:
- Prints a compact report with one entry per function that calls FUN_00035324,
  indicating the slot (+0x3c or +0x40), the callback pair (when addresses are visible),
  and the detected mask literals present in the function body.
"""


BUNDLE_PATH = os.path.join("exports", "bundle_MAIN.EXE.jsonl")


MASK_PATTERNS = {
    0x8000: re.compile(r"&\s*0x8000\)"),
    0x2000: re.compile(r"&\s*0x2000\)"),
    0x0040: re.compile(r"&\s*0x40\)"),
    0x0002: re.compile(r"&\s*2\)"),
    0x0010: re.compile(r"&\s*0x10\)"),
}


def load_bundle(path: str) -> List[Dict]:
    rows: List[Dict] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                # Ignore malformed lines (none expected for our export)
                pass
    return rows


def extract_scheduler_calls(rows: List[Dict]) -> List[Tuple[str, int, str, str, List[int]]]:
    out: List[Tuple[str, int, str, str, List[int]]] = []
    for row in rows:
        func = row.get("function") or {}
        name = func.get("name")
        ea = func.get("ea")
        decomp = row.get("decompilation") or ""

        if "FUN_00035324(" not in decomp:
            continue

        # Classify slot target
        slot = None
        # Search only the argument section to reduce false positives
        # Grab a small window around the call
        for m in re.finditer(r"FUN_00035324\(([^\)]*)\)", decomp):
            args_str = m.group(1)
            tgt = None
            if "+ 0x3c" in args_str:
                tgt = "+0x3c"
            elif "+ 0x40" in args_str:
                tgt = "+0x40"

            # Try to extract callback pair addresses if present in args
            cb1 = None
            cb2 = None
            # naive pattern: ...,0x800240a0,0x80023f50
            cb_addrs = re.findall(r"0x800[0-9a-fA-F]{5}", args_str)
            if len(cb_addrs) >= 2:
                cb1, cb2 = cb_addrs[-2], cb_addrs[-1]

            # Detect mask literals within the full decomp text
            masks_present: List[int] = [mask for mask, pat in MASK_PATTERNS.items() if pat.search(decomp)]

            out.append((name or f"EA_{ea}", ea or -1, tgt or "?", f"{cb1 or '?'} | {cb2 or '?'}", masks_present))

    return out


def main() -> None:
    if not os.path.exists(BUNDLE_PATH):
        print(f"Bundle not found: {BUNDLE_PATH}")
        return
    rows = load_bundle(BUNDLE_PATH)
    sched = extract_scheduler_calls(rows)
    # Sort by EA for stable output
    sched.sort(key=lambda x: x[1])
    print("Function,EA,slot,callbacks(maybe),masks")
    for name, ea, slot, cbs, masks in sched:
        masks_str = ",".join(hex(m) for m in sorted(masks)) if masks else "-"
        print(f"{name},{hex(ea) if isinstance(ea,int) else ea},{slot},{cbs},{masks_str}")


if __name__ == "__main__":
    main()
