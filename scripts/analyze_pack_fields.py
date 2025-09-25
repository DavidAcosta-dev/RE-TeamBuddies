import json
import re
from collections import defaultdict, Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


STREAM_KEYS = {
    ("MAIN.EXE", "FUN_000197bc"),  # device pump
    ("MAIN.EXE", "FUN_00019ec0"),  # stage payload
    ("MAIN.EXE", "FUN_00002434"),  # init/start
    ("MAIN.EXE", "FUN_000026f4"),  # reset
}


# Regexes to capture pack/header fields and common comparisons
ARR_ACCESS = re.compile(r"_DAT_80059e9c\s*\[\s*(\d+)\s*\]")
HDR_MAGIC = re.compile(r"\*_DAT_80059e9c\s*==\s*0x160\b")
SUB_MODE = re.compile(r"\(\s*\(ushort\)\s*_DAT_80059e9c\[\s*1\s*\]\s*>>\s*10\s*&\s*0x1f\s*\)\s*==\s*(_DAT_80057a4c|[0-9xXa-fA-F]+)")
END_OF_PACK = re.compile(r"\(ushort\)\s*_DAT_80059e9c\[\s*3\s*\]\s*-\s*1\s*==\s*\(uint\)\(ushort\)\s*_DAT_80059e9c\[\s*2\s*\]")
CURR_EQ = re.compile(r"\(int\)\s*_DAT_80057a40\s*==\s*\(uint\)\(ushort\)\s*_DAT_80059e9c\[\s*2\s*\]")
TRACK_EQ = re.compile(r"_DAT_80057a3c\s*==\s*\(ushort\)\s*_DAT_80059e9c\[\s*4\s*\]")
TRACK_NE = re.compile(r"_DAT_80057a30\s*!=\s*\(ushort\)\s*_DAT_80059e9c\[\s*4\s*\]")


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

    # collect relevant functions
    fns = {}
    for fn in load_bundles():
        key = (fn.get("binary"), (fn.get("function") or {}).get("name") or "")
        if key in STREAM_KEYS:
            fns[key] = fn

    index_counts = Counter()
    evidence = defaultdict(list)
    roles = defaultdict(Counter)

    for key, fn in fns.items():
        dec = fn.get("decompilation") or ""
        # index usage counts and snippet capture
        for m in ARR_ACCESS.finditer(dec):
            idx = int(m.group(1))
            index_counts[idx] += 1
        # role heuristics
        if HDR_MAGIC.search(dec):
            roles[0]["hdr_magic_0x160"] += 1
            evidence[0].append("header_magic present in {}:{}".format(*key))
        if SUB_MODE.search(dec):
            roles[1]["sub_mode_bits_>>10&0x1f"] += 1
            evidence[1].append("sub_mode compare present in {}:{}".format(*key))
        if END_OF_PACK.search(dec):
            roles[3]["total_minus_1_equals_curr"] += 1
            roles[2]["curr_equals_total_minus_1"] += 1
            evidence[2].append("curr vs total-1 present in {}:{}".format(*key))
            evidence[3].append("total-1 vs curr present in {}:{}".format(*key))
        if CURR_EQ.search(dec):
            roles[2]["curr_sector_matches_counter"] += 1
            evidence[2].append("curr sector eq local counter in {}:{}".format(*key))
        if TRACK_EQ.search(dec):
            roles[4]["track_matches_state_3c"] += 1
            evidence[4].append("track eq state_3c in {}:{}".format(*key))
        if TRACK_NE.search(dec):
            roles[4]["track_mismatch_state_30"] += 1
            evidence[4].append("track ne expected state_30 in {}:{}".format(*key))

    # propose names for indices
    suggestions = {}
    if roles[0]:
        suggestions[0] = "hdr_magic_or_size"
    if roles[1]:
        suggestions[1] = "sub_mode_bits"
    if roles[2]:
        suggestions[2] = "curr_sector_index"
    if roles[3]:
        suggestions[3] = "total_sectors"
    if roles[4]:
        suggestions[4] = "track_or_channel"

    out_md = EXPORTS / "cdstream_pack_fields.md"
    with out_md.open("w", encoding="utf-8") as f:
        f.write("# CD stream pack/header fields (heuristic)\n\n")
        f.write("Indices used on _DAT_80059e9c[...] across key functions (higher = more usage):\n\n")
        for idx, cnt in index_counts.most_common():
            role = ", ".join(f"{k}:{v}" for k, v in roles[idx].most_common())
            sug = suggestions.get(idx, "")
            f.write(f"- index[{idx}]: used {cnt}x" + (f" | roles: {role}" if role else "") + (f" | suggest: {sug}" if sug else "") + "\n")
        f.write("\n## Evidence snippets\n\n")
        for idx in sorted(evidence.keys()):
            f.write(f"### index[{idx}]\n\n")
            for note in evidence[idx]:
                f.write(f"- {note}\n")
            f.write("\n")
    print(f"Wrote {out_md}")


if __name__ == "__main__":
    main()
