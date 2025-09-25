import json
import re
from collections import defaultdict, Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


TARGET_FUNCS = set([
    ("MAIN.EXE", "FUN_00002434"),  # cdstream_init_or_start
    ("MAIN.EXE", "FUN_000021d4"),  # cdstream_process_queue
    ("MAIN.EXE", "FUN_00002584"),  # cdstream_poll_idle
    ("MAIN.EXE", "FUN_000026f4"),  # cdstream_reset
    ("MAIN.EXE", "FUN_000028d8"),  # cdstream_register_callback2
    ("MAIN.EXE", "FUN_000197bc"),  # device pump
    ("MAIN.EXE", "FUN_00019ec0"),  # stage payload
    ("MAIN.EXE", "FUN_000199d4"),  # memcpy sector
])


GLOBAL_RE = re.compile(r"_(?:DAT|FUN)_(800[0-9a-fA-F]{5,6})")


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

    by_key = {}
    globals_counter = Counter()
    globals_by_func = defaultdict(lambda: Counter())
    func_titles = {}

    for fn in load_bundles():
        binname = fn.get("binary")
        func = fn.get("function") or {}
        name = func.get("name") or ""
        key = (binname, name)
        by_key[key] = fn
        if key not in TARGET_FUNCS:
            continue
        title = overlay[binname].get(name, name)
        func_titles[key] = title
        dec = fn.get("decompilation") or ""
        for m in GLOBAL_RE.finditer(dec):
            addr = m.group(1)
            globals_counter[addr] += 1
            globals_by_func[key][addr] += 1

    # Heuristic name suggestions by address clusters
    suggestions = {}
    # group by 80057a** likely state struct; 80053b** looks like HW regs; 80059e** header ptr
    for addr, cnt in globals_counter.most_common():
        if addr.startswith("80057a"):
            suggestions.setdefault(addr, "cds_state_" + addr[-2:])
        elif addr.startswith("80053b"):
            suggestions.setdefault(addr, "cds_hw_" + addr[-2:])
        elif addr.startswith("80053a"):
            suggestions.setdefault(addr, "cds_hw_" + addr[-2:])
        elif addr.startswith("80059e"):
            suggestions.setdefault(addr, "cds_hdr_" + addr[-2:])
        else:
            suggestions.setdefault(addr, "cds_gbl_" + addr[-2:])

    out_md = EXPORTS / "cdstream_globals.md"
    with out_md.open("w", encoding="utf-8") as f:
        f.write("# CD stream globals and suggestions\n\n")
        f.write("Functions scanned:\n")
        for k in TARGET_FUNCS:
            title = func_titles.get(k, k[1])
            f.write(f"- {k[0]}:{title} ({k[1]})\n")
        f.write("\n## Global usage counts (overall)\n\n")
        for addr, cnt in globals_counter.most_common():
            f.write(f"- _DAT_{addr} => used {cnt}x | suggest: {suggestions.get(addr)}\n")
        f.write("\n## Per-function usage\n\n")
        for k in TARGET_FUNCS:
            title = func_titles.get(k, k[1])
            f.write(f"### {k[0]}:{title} ({k[1]})\n\n")
            for addr, cnt in globals_by_func[k].most_common():
                f.write(f"- _DAT_{addr}: {cnt}\n")
            f.write("\n")
    print(f"Wrote {out_md}")


if __name__ == "__main__":
    main()
