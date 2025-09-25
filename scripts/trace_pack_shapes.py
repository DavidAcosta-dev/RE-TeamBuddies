import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


STREAM_FUNCS = [
    ("MAIN.EXE", "FUN_000197bc"),  # device_pump
    ("MAIN.EXE", "FUN_00019ec0"),  # stage_payload
    ("MAIN.EXE", "FUN_00002434"),  # init/start
    ("MAIN.EXE", "FUN_000026f4"),  # reset
    ("MAIN.EXE", "FUN_00002584"),  # poll_idle
    ("MAIN.EXE", "FUN_0001a028"),  # advance
    ("MAIN.EXE", "FUN_0001a038"),  # advance2
]


# Ordered regex tags we want to track; the first match index in text defines order
TAG_PATTERNS = [
    ("HDR_MAGIC", re.compile(r"\*_DAT_80059e9c\s*==\s*0x160\b")),
    ("SUBHDR_FILTER", re.compile(r"\(ushort\)\s*_DAT_80059e9c\[1\].*>>\s*10\s*&\s*0x1f")),
    ("CMD_ISSUE", re.compile(r"thunk_FUN_00040020|cd_cmd_issue")),
    ("DISPATCH", re.compile(r"FUN_0003186c|cd_cmd_dispatch")),
    ("FINAL_A", re.compile(r"FUN_00031734|cd_cmd_finalize_a")),
    ("FINAL_B", re.compile(r"FUN_000317d0|cd_cmd_finalize_b")),
    ("DMA_1F8", re.compile(r"0x1f8\b|FUN_00030de8|cd_dma_copy_partial")),
    ("HDR_SKIP_20", re.compile(r"\+\s*0x20\b")),
    ("SECTOR_800", re.compile(r"0x800\b")),
    ("INC_SECTOR", re.compile(r"_DAT_80057a1c\s*=\s*_DAT_80057a1c\s*\+\s*1")),
    ("RING_REWIND", re.compile(r"FUN_00030cc8|cd_ring_rewind")),
    ("RESET_PTRS", re.compile(r"FUN_00031368|cd_reset_ptrs")),
    ("POLL_READY", re.compile(r"FUN_0002db3c|cd_poll_ready")),
    ("PACK_END_CHECK", re.compile(r"\(ushort\)\s*_DAT_80059e9c\[3\]\s*-\s*1\s*==")),
]


def load_overlay():
    ov = {}
    path = EXPORTS / "curated_overlays.json"
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        for b, entries in data.items():
            for e in entries:
                if e.get("name") and e.get("new_name"):
                    ov[(b, e["name"])] = e["new_name"]
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
        name = (fn.get("function") or {}).get("name") or ""
        by_key[(binname, name)] = fn

    out_lines = ["# CD stream pack shapes (heuristic order of events)\n"]
    for key in STREAM_FUNCS:
        fn = by_key.get(key)
        if not fn:
            continue
        dec = fn.get("decompilation") or ""
        # record first index for each tag
        tag_hits = []
        for tag, rx in TAG_PATTERNS:
            m = rx.search(dec)
            if m:
                tag_hits.append((m.start(), tag))
        tag_hits.sort(key=lambda x: x[0])
        seq = [t for _, t in tag_hits]

        title = overlay.get(key, key[1])
        addr = hex((fn.get("function") or {}).get("ea") or 0)
        out_lines.append(f"\n## {key[0]}:{title} ({key[1]}) @ {addr}\n")
        if seq:
            out_lines.append("- Sequence: " + " -> ".join(seq) + "\n")
        else:
            out_lines.append("- Sequence: (no markers found)\n")

    out_md = EXPORTS / "cdstream_pack_shapes.md"
    out_md.write_text("\n".join(out_lines), encoding="utf-8")
    print(f"Wrote {out_md}")


if __name__ == "__main__":
    main()
