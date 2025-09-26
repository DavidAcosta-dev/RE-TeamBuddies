#!/usr/bin/env python3
"""
extract_prefix_annotated_decomp.py

Extract decompilations for curated integrator ∩ orientation functions and basis
helpers, annotating TbActorPrefix offsets and Q12 traits inline to speed review.

Output: exports/decomp_integrator_orientation.md
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, Iterable, Iterator, List

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"
BUNDLE_GLOB = "exports/bundle_*.jsonl"
OUT_MD = EXPORTS / "decomp_integrator_orientation.md"

# Curated target set (prioritized)
TARGETS = [
    # Integrator ∩ Orientation (direct Z)
    "FUN_00022e5c",
    "FUN_00023000",
    "FUN_00023210",
    # Additional direct Z writers in cluster
    "FUN_00022dc8",
    "FUN_00023110",
    "FUN_00023180",
    # Basis/normalize chain
    "FUN_00044f80",
    "FUN_00044a14",
    # Config block init
    "FUN_00032c18",
    # MAIN.EXE integrator variants (cross-binary confirm)
    "FUN_0001e750",
    "FUN_0001e7b4",
    "FUN_0001ea04",
]

# TbActorPrefix offset tags
OFF_TAGS = {
    0x08: "POS.x",
    0x0C: "POS.y",
    0x10: "POS.z",
    0x20: "ANG.yaw",
    0x22: "ANG.pitch",
    0x24: "ANG.roll",
    0x26: "FLAGS",
    0x34: "BD.x",
    0x36: "BD.y",
    0x38: "BD.z",
    0x3A: "BD.len",
    0x3C: "BS.x",
    0x3E: "BS.y",
    0x40: "BS.z",
    0x44: "SPD",
}

OFF_RE = re.compile(r"\+\s*0x([0-9a-fA-F]+)\b")


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


def annotate(line: str) -> str:
    ann: List[str] = []
    for m in OFF_RE.finditer(line):
        try:
            off = int(m.group(1), 16)
        except Exception:
            continue
        tag = OFF_TAGS.get(off)
        if tag:
            ann.append(tag)
    l = line.lower()
    if ">>" in l and ("0xc" in l or ">> 12" in l):
        ann.append("Q12_SHIFT")
    if "*" in l and (">> 12" in l or ">> 0xc" in l):
        ann.append("Q12_PROD")
    if ">> 6" in l:
        ann.append("POS_SHIFT6")
    if "& 0xfff" in l:
        ann.append("ANGLE_MASK")
    if "rsin" in l or "rcos" in l:
        ann.append("TRIG")
    if ann:
        return f"{line}    // {' '.join(ann)}"
    return line


def main() -> None:
    bundles = sorted(ROOT.glob(BUNDLE_GLOB))
    if not bundles:
        raise SystemExit(f"No JSONL files matched glob: {BUNDLE_GLOB}")
    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    with OUT_MD.open("w", encoding="utf-8") as out:
        out.write("# Integrator/Orientation Decomp (Annotated)\n\n")
        for path in bundles:
            for entry in iter_jsonl(path):
                fn = entry.get("function") or {}
                name = fn.get("name")
                if name not in TARGETS:
                    continue
                ea = fn.get("ea")
                bin_name = entry.get("binary") or ""
                out.write(f"## {name} ({bin_name}) @ 0x{ea:06x}\n\n")
                decomp = entry.get("decompilation") or ""
                for ln in decomp.splitlines():
                    out.write(annotate(ln) + "\n")
                out.write("\n---\n\n")
    print(f"Wrote {OUT_MD}")


if __name__ == "__main__":
    main()
