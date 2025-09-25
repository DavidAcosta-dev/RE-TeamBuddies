import json
import re
from collections import defaultdict, Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


CONST_TOKENS = [
    "0x1323", "0x1325", "0x21020843", "0x20843", "0x11400100",
]

HELPER_NAMES = {
    "MAIN.EXE": {
        "FUN_00040020",  # thunk wrapper issuing HW command
        "FUN_0003186c",  # dispatch/kick
        "FUN_00031734",  # finalize A
        "FUN_000317d0",  # finalize B
        "FUN_00030de8",  # DMA/memcpy partial
        "FUN_00030cc8",  # ring rewind
        "FUN_00031368",  # reset ptrs
        "FUN_0002db3c",  # poll ready
    }
}


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
    rows = []
    per_bin = defaultdict(list)
    for fn in load_bundles():
        binname = fn.get("binary") or ""
        func = fn.get("function") or {}
        name = func.get("name") or ""
        decomp = fn.get("decompilation") or ""
        low = decomp.lower()
        counts = Counter()
        for t in CONST_TOKENS:
            counts[t] += len(re.findall(rf"(?<![0-9a-zA-Z_]){re.escape(t)}(?![0-9a-zA-Z_])", low))
        # note helper invocations from callee list
        callees = set(fn.get("callees", []) or [])
        helper_hits = 0
        for h in HELPER_NAMES.get(binname, set()):
            if h in callees:
                helper_hits += 1
        score = sum(counts.values()) + helper_hits * 2
        if score:
            per_bin[binname].append((score, counts, helper_hits, fn))

    out_md = EXPORTS / "cd_command_wrappers.md"
    with out_md.open("w", encoding="utf-8") as f:
        f.write("# CD command wrapper candidates\n\n")
        for binname, lst in sorted(per_bin.items()):
            lst.sort(key=lambda x: x[0], reverse=True)
            f.write(f"## {binname}\n\n")
            for score, counts, helper_hits, fn in lst[:50]:
                func = fn.get("function") or {}
                addr = hex(func.get("ea") or 0)
                name = func.get("name") or ""
                nonzero = {k: v for k, v in counts.items() if v}
                f.write(
                    f"- {addr} {name} | score={score} helpers={helper_hits} | counts={nonzero}\n"
                )
            f.write("\n")
    print(f"Wrote {out_md}")


if __name__ == "__main__":
    main()
