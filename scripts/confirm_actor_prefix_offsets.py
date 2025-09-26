#!/usr/bin/env python3
"""
confirm_actor_prefix_offsets.py

Scan exported JSONL bundles for curated functions and confirm usage of
specific TbActorPrefix offsets (position, angles, flags, basis, speed).

Output: exports/actor_prefix_confirmation.md
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, Iterator, List

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"
BUNDLE_GLOB = "exports/bundle_*.jsonl"
OUT_MD = EXPORTS / "actor_prefix_confirmation.md"

# Curated target functions (GAME.BIN primary)
TARGET_FUNCS = {
    "FUN_00022e5c",  # integrator ∩ orientation
    "FUN_00023000",  # integrator ∩ orientation
    "FUN_00023210",  # integrator ∩ orientation
    "FUN_00023110",
    "FUN_00023180",
    "FUN_00022dc8",
    "FUN_00044f80",  # basis normalize
    "FUN_00044a14",  # basis recompute
    "FUN_00032c18",  # config initializer (context)
}

# Offsets of interest: position (0x08..0x10), angles (0x20..0x24), flags (0x26),
# basis fwd (0x34/0x36/0x38), basis len (0x3A), basis src (0x3C/0x3E/0x40), speed (0x44)
OFFSETS = [0x08, 0x0C, 0x10, 0x20, 0x22, 0x24, 0x26, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E, 0x40, 0x44]

# Regex to match "+ 0xNN" patterns (case-insensitive), common in decomp dumps
def make_offset_regex(offset: int) -> re.Pattern:
    return re.compile(r"\+\s*0x{:x}\b".format(offset), re.IGNORECASE)


def iter_jsonl(path: Path) -> Iterator[dict]:
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def collect(paths: Iterable[Path]) -> Dict[str, Dict[int, int]]:
    # results[name][offset] = count occurrences
    results: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    samples: Dict[tuple[str, int], List[str]] = defaultdict(list)
    regs = {off: make_offset_regex(off) for off in OFFSETS}

    for path in paths:
        for entry in iter_jsonl(path):
            fn = entry.get("function") or {}
            name = fn.get("name")
            if name not in TARGET_FUNCS:
                continue
            decomp = entry.get("decompilation") or ""
            if not decomp:
                continue
            for off, rx in regs.items():
                hits = rx.findall(decomp)
                if hits:
                    results[name][off] += len(hits)
            # capture up to 2 sample lines for key offsets per function
            key_offsets = (0x34, 0x36, 0x38, 0x3C, 0x3E, 0x40, 0x44)
            if any(results[name].get(k, 0) for k in key_offsets):
                for ln in decomp.splitlines():
                    if any(f"+ 0x{ko:x}".lower() in ln.lower() for ko in key_offsets):
                        if len(samples[(name, 1)]) < 2:
                            samples[(name, 1)].append(ln.strip())
    return results


def render(results: Dict[str, Dict[int, int]]) -> str:
    lines: List[str] = []
    lines.append("# TbActorPrefix Offset Confirmation")
    lines.append("")
    lines.append("Functions checked: {}".format(", ".join(sorted(results.keys()))))
    lines.append("")
    # table header
    hdr = [
        "Function", "0x08", "0x0C", "0x10", "0x20", "0x22", "0x24", "0x26",
        "0x34", "0x36", "0x38", "0x3A", "0x3C", "0x3E", "0x40", "0x44",
    ]
    lines.append("| " + " | ".join(hdr) + " |")
    lines.append("|" + " --- |" * len(hdr))
    for name in sorted(results.keys()):
        row = [name]
        for off in OFFSETS:
            row.append(str(results[name].get(off, 0)))
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    lines.append("Notes:")
    lines.append("- Position updates should show 0x08/0x0C/0x10 usage in integrators.")
    lines.append("- Basis recompute/normalize should show 0x3C/0x3E/0x40 (source) and 0x34/0x36/0x38 (dest).")
    lines.append("- Speed reads/writes expected at 0x44 in basis-related functions.")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    bundle_paths = sorted(ROOT.glob(BUNDLE_GLOB))
    if not bundle_paths:
        raise SystemExit(f"No JSONL files matched glob: {BUNDLE_GLOB}")
    results = collect(bundle_paths)
    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text(render(results), encoding="utf-8")
    print(f"Wrote {OUT_MD}")


if __name__ == "__main__":
    main()
