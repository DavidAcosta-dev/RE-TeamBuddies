import json
import re
from pathlib import Path
from collections import Counter, defaultdict


ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


# Heuristic tokens for PS1 CD-ROM control/streaming usage
# Candidate command hex constants occasionally visible in decomp (avoid plain decimals to reduce noise)
CMD_VALUES = [
    "0x06",  # often used in CD control tables (varies across libs)
    "0x15",  # CdlSetloc (typical)
    "0x16",  # CdlReadS (typical)
    "0x1b",  # CdlPlay (typical)
    "0x19",  # CdlSetfilter (typical)
]

SECTOR_SIZES = ["0x800", "2048", "0x930", "2352", "0x924", "2340", "2328"]
HELPER_TOKENS = [
    "btoi", "itob",
    "CdLOC", "CdlLOC",
    "loc.minute", "loc.second", "loc.sector",
    "CdControl", "CdControlB", "CdControlF", "CdSync", "CdReady",
    "StSetRing", "StGetNext", "StCdInterrupt", "DsInit", "DsCommand",
]


def score_text(txt: str) -> Counter:
    c = Counter()
    low = txt.lower()
    for t in CMD_VALUES:
        # prefer exact token-ish matches
        c[f"cmd:{t}"] += len(re.findall(rf"(?<![0-9a-zA-Z_]){re.escape(t)}(?![0-9a-zA-Z_])", low))
    for t in SECTOR_SIZES:
        c[f"sz:{t}"] += len(re.findall(rf"(?<![0-9a-zA-Z_]){re.escape(t)}(?![0-9a-zA-Z_])", low))
    for t in HELPER_TOKENS:
        c[f"tok:{t}"] += low.count(t.lower())
    return c


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
                yield p.name, obj


def main():
    rows = []
    per_bin = defaultdict(list)
    for bundle_name, fn in load_bundles():
        decomp = fn.get("decompilation") or ""
        counts = score_text(decomp)
        score = sum(counts.values())
        if score:
            binname = fn.get("binary") or bundle_name
            per_bin[binname].append((score, counts, fn))
    # Write CSV/MD outputs
    out_csv = EXPORTS / "cd_candidates.csv"
    out_md = EXPORTS / "cd_candidates.md"
    headers = ["binary", "address", "name", "score"] + sorted({k for v in per_bin.values() for _, c, _ in v for k in c.keys()})
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        f.write(",".join(headers) + "\n")
        for binname, lst in per_bin.items():
            lst.sort(key=lambda x: x[0], reverse=True)
            for score, counts, fn in lst[:200]:
                func = fn.get("function") or {}
                addr = func.get("ea") or 0
                name = func.get("name") or ""
                row = {
                    "binary": binname,
                    "address": hex(addr),
                    "name": name,
                    "score": str(score),
                }
                for k in headers[4:]:
                    row[k] = str(counts.get(k, 0))
                f.write(",".join(row[h].replace(",", " ") for h in headers) + "\n")
    with out_md.open("w", encoding="utf-8") as f:
        f.write("# CD-like pattern candidates\n\n")
        for binname, lst in sorted(per_bin.items()):
            lst.sort(key=lambda x: x[0], reverse=True)
            f.write(f"## {binname}\n\n")
            for score, counts, fn in lst[:30]:
                func = fn.get("function") or {}
                name = func.get("name") or ""
                addr = hex(func.get("ea") or 0)
                f.write(f"- {addr} {name} | score={score} | counts={dict((k,v) for k,v in counts.items() if v)}\n")
            f.write("\n")
    print(f"Wrote {out_csv} and {out_md}")


if __name__ == "__main__":
    main()
