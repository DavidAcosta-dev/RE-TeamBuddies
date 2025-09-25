import json
import re
from pathlib import Path
from collections import defaultdict


ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


STREAM_FUNCS = [
    ("MAIN.EXE", "FUN_00002434"),  # init/start
    ("MAIN.EXE", "FUN_000021d4"),  # process_queue
    ("MAIN.EXE", "FUN_00002584"),  # poll_idle
    ("MAIN.EXE", "FUN_000026f4"),  # reset
    ("MAIN.EXE", "FUN_000028d8"),  # register_callback2
    ("MAIN.EXE", "FUN_000197bc"),  # device_pump
    ("MAIN.EXE", "FUN_00019ec0"),  # stage_payload
    ("MAIN.EXE", "FUN_000199d4"),  # memcpy_sector
    ("MAIN.EXE", "FUN_0001a028"),  # advance_and_dispatch
    ("MAIN.EXE", "FUN_0001a038"),  # advance_and_dispatch2
]


PATTERNS = {
    "header_magic": re.compile(r"\*_DAT_80059e9c\s*==\s*0x160"),
    "subhdr_filter": re.compile(r"\(\s*\(ushort\)\s*_DAT_80059e9c\[1\].*>>\s*10\s*&\s*0x1f\)"),
    "pack_end_cmp": re.compile(r"_DAT_80059e9c\[3\]\]\s*-\s*1\s*==\s*\(uint\)\(ushort\)_DAT_80059e9c\[2\]"),
    "flag_final": re.compile(r"_DAT_80057a38\s*=\s*1"),
    "idx_inc": re.compile(r"_DAT_80057a1c\s*=\s*_DAT_80057a1c\s*\+\s*1"),
    "reset_3c": re.compile(r"_DAT_80057a3c\s*=\s*0\b"),
    "reset_40": re.compile(r"_DAT_80057a40\s*=\s*0\b"),
    "hdr_skip": re.compile(r"\+\s*0x20\b"),
    "payload_1f8": re.compile(r"\b0x1f8\b", re.IGNORECASE),
    "sector_800": re.compile(r"\b0x800\b", re.IGNORECASE),
    "cmd_1323": re.compile(r"\b0x1323\b"),
    "cmd_1325": re.compile(r"\b0x1325\b"),
    "cmd_word_a": re.compile(r"\b0x21020843\b"),
    "cmd_word_b": re.compile(r"\b0x20843\b"),
    "cmd_word_c": re.compile(r"\b0x11400100\b"),
}


def load_overlay():
    ov = defaultdict(dict)
    p = EXPORTS / "curated_overlays.json"
    if p.exists():
        data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        for b, entries in data.items():
            for e in entries:
                old = e.get("name")
                new = e.get("new_name")
                if old and new:
                    ov[b][old] = new
    return ov


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
    overlay = load_overlay()
    by_key = {}
    for fn in load_bundles():
        binname = fn.get("binary")
        func = fn.get("function") or {}
        name = func.get("name") or ""
        by_key[(binname, name)] = fn

    out = []
    for key in STREAM_FUNCS:
        fn = by_key.get(key)
        if not fn:
            continue
        binname, oldname = key
        title = overlay[binname].get(oldname, oldname)
        dec = fn.get("decompilation") or ""
        events = []
        # pattern hits
        for tag, rx in PATTERNS.items():
            if rx.search(dec):
                events.append(tag)
        # callees summary
        callees = fn.get("callees", []) or []
        pretty_callees = [overlay[binname].get(c, c) for c in callees]
        out.append((binname, title, oldname, events, pretty_callees))

    # emit markdown
    out_md = EXPORTS / "cdstream_ring_events.md"
    with out_md.open("w", encoding="utf-8") as f:
        f.write("# CD stream ring events (heuristic)\n\n")
        for binname, title, oldname, events, callees in out:
            f.write(f"## {binname}:{title} ({oldname})\n\n")
            if events:
                f.write("- Detected events: " + ", ".join(sorted(events)) + "\n")
            if callees:
                f.write("- Callees: " + ", ".join(callees) + "\n")
            f.write("\n")
    print(f"Wrote {out_md}")


if __name__ == "__main__":
    main()
