#!/usr/bin/env python3
"""find_q12_math_patterns.py

Scan exported Ghidra JSONL bundles for Q12-style arithmetic patterns:
right/left shifts by 12 (0xC), sign-arithmetic `sar(...)`, rsin/rcos usage,
angle masks (0x0FFF), Q12 constants (0x1000/0x800), velocity→position shifts (>>6),
and common Q12 multiply-then-shift products. Generates JSON and Markdown summaries
with a weighted score and optional filters.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, List

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / "exports"
BUNDLE_GLOB = "exports/bundle_*.jsonl"
DEFAULT_MD = EXPORTS / "q12_math_candidates.md"
DEFAULT_JSON = EXPORTS / "q12_math_candidates.json"

SHIFT_RIGHT_RE = re.compile(r">>\s*(?:0x)?(?:c|12)\b", re.IGNORECASE)
SHIFT_LEFT_RE = re.compile(r"<<\s*(?:0x)?(?:c|12)\b", re.IGNORECASE)
SAR_RE = re.compile(r"\bsar\s*\(", re.IGNORECASE)
RSIN_RE = re.compile(r"\brsin\b", re.IGNORECASE)
RCOS_RE = re.compile(r"\brcos\b", re.IGNORECASE)
ANGLE_MASK_RE = re.compile(r"&\s*(?:0x)?0?fff\b", re.IGNORECASE)
Q12_ONE_RE = re.compile(r"\b(?:0x)?1000\b", re.IGNORECASE)
Q12_HALF_RE = re.compile(r"\b(?:0x)?800\b", re.IGNORECASE)
POS_SHIFT_RE = re.compile(r">>\s*(?:0x)?(?:6)\b", re.IGNORECASE)

# TbActorPrefix offset patterns (evidence for orientation/physics fields)
OFFSETS = [0x08, 0x0C, 0x10, 0x20, 0x22, 0x24, 0x26, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E, 0x40, 0x44]
OFFS_REGEX: dict[int, re.Pattern] = {off: re.compile(r"\+\s*0x{:x}\b".format(off), re.IGNORECASE) for off in OFFSETS}

# Heuristic: lines that contain a multiplication and a subsequent right-shift-by-12
# e.g., (a * b) >> 12 or x*y >> 0xC
def count_q12_products(decomp: str) -> int:
    hits = 0
    for line in decomp.splitlines():
        if '>>' in line and ('12' in line or '0xC' in line or '0xc' in line):
            if '*' in line:
                hits += 1
    return hits


@dataclass
class FunctionHit:
    name: str
    ea: int | None
    binary: str | None
    right_shifts: int = 0
    left_shifts: int = 0
    sar_calls: int = 0
    rsin_calls: int = 0
    rcos_calls: int = 0
    angle_masks: int = 0
    q12_one_consts: int = 0
    q12_half_consts: int = 0
    pos_shifts: int = 0
    q12_products: int = 0
    source_files: set[str] = field(default_factory=set)
    samples: list[str] = field(default_factory=list)
    # TbActorPrefix offset evidence
    off_0x08: int = 0
    off_0x0C: int = 0
    off_0x10: int = 0
    off_0x20: int = 0
    off_0x22: int = 0
    off_0x24: int = 0
    off_0x26: int = 0
    off_0x34: int = 0
    off_0x36: int = 0
    off_0x38: int = 0
    off_0x3A: int = 0
    off_0x3C: int = 0
    off_0x3E: int = 0
    off_0x40: int = 0
    off_0x44: int = 0

    def register(self, decomp: str, source_file: str) -> None:
        self.right_shifts += len(SHIFT_RIGHT_RE.findall(decomp))
        self.left_shifts += len(SHIFT_LEFT_RE.findall(decomp))
        self.sar_calls += len(SAR_RE.findall(decomp))
        self.rsin_calls += len(RSIN_RE.findall(decomp))
        self.rcos_calls += len(RCOS_RE.findall(decomp))
        self.angle_masks += len(ANGLE_MASK_RE.findall(decomp))
        self.q12_one_consts += len(Q12_ONE_RE.findall(decomp))
        self.q12_half_consts += len(Q12_HALF_RE.findall(decomp))
        self.pos_shifts += len(POS_SHIFT_RE.findall(decomp))
        self.q12_products += count_q12_products(decomp)
        self.source_files.add(source_file)
        # Count TbActorPrefix offset usages
        def _add(off: int, attr: str) -> None:
            hits = len(OFFS_REGEX[off].findall(decomp))
            if hits:
                setattr(self, attr, getattr(self, attr) + hits)
        _add(0x08, 'off_0x08')
        _add(0x0C, 'off_0x0C')
        _add(0x10, 'off_0x10')
        _add(0x20, 'off_0x20')
        _add(0x22, 'off_0x22')
        _add(0x24, 'off_0x24')
        _add(0x26, 'off_0x26')
        _add(0x34, 'off_0x34')
        _add(0x36, 'off_0x36')
        _add(0x38, 'off_0x38')
        _add(0x3A, 'off_0x3A')
        _add(0x3C, 'off_0x3C')
        _add(0x3E, 'off_0x3E')
        _add(0x40, 'off_0x40')
        _add(0x44, 'off_0x44')
        if len(self.samples) < 3:
            snippet = " ".join(line.strip() for line in decomp.strip().splitlines()[:10])
            if snippet and snippet not in self.samples:
                self.samples.append(snippet)

    @property
    def total_hits(self) -> int:
        return (
            self.right_shifts + self.left_shifts + self.sar_calls +
            self.angle_masks + self.q12_one_consts + self.q12_half_consts +
            self.pos_shifts + self.q12_products
        )

    @property
    def trig_hits(self) -> int:
        return self.rsin_calls + self.rcos_calls

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "ea": self.ea,
            "ea_hex": f"0x{self.ea:06x}" if self.ea is not None else None,
            "binary": self.binary,
            "right_shifts": self.right_shifts,
            "left_shifts": self.left_shifts,
            "sar_calls": self.sar_calls,
            "rsin_calls": self.rsin_calls,
            "rcos_calls": self.rcos_calls,
            "angle_masks": self.angle_masks,
            "q12_one_consts": self.q12_one_consts,
            "q12_half_consts": self.q12_half_consts,
            "pos_shifts": self.pos_shifts,
            "q12_products": self.q12_products,
            # aggregated TbActorPrefix offset evidence
            "pos_hits": self.off_0x08 + self.off_0x0C + self.off_0x10,
            "angle_hits": self.off_0x20 + self.off_0x22 + self.off_0x24,
            "flags_hits": self.off_0x26,
            "basis_dest_hits": self.off_0x34 + self.off_0x36 + self.off_0x38 + self.off_0x3A,
            "basis_src_hits": self.off_0x3C + self.off_0x3E + self.off_0x40,
            "speed_hits": self.off_0x44,
            "total_hits": self.total_hits,
            "trig_hits": self.trig_hits,
            "source_files": sorted(self.source_files),
            "samples": self.samples,
        }


def iter_jsonl(path: Path) -> Iterator[dict]:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def collect_hits(paths: Iterable[Path]) -> dict[tuple[str, int | None], FunctionHit]:
    hits: dict[tuple[str, int | None], FunctionHit] = {}
    for path in paths:
        for entry in iter_jsonl(path):
            fn = entry.get("function") or {}
            name = fn.get("name") or "UNKNOWN"
            ea = fn.get("ea")
            decomp = entry.get("decompilation") or ""
            if not decomp:
                continue
            key = (name, ea)
            hit = hits.setdefault(
                key,
                FunctionHit(name=name, ea=ea, binary=entry.get("binary")),
            )
            hit.register(decomp, str(path))
    return hits


def summarise(hits: dict[tuple[str, int | None], FunctionHit], *, min_score: int = 0, include_trig_only: bool = True) -> dict:
    total_functions = len(hits)
    weighted = []
    trig_only = []
    for hit in hits.values():
        # Weighted score emphasizing core Q12 signals
        score = (
            3 * hit.right_shifts +
            2 * hit.q12_products +
            2 * hit.sar_calls +
            2 * hit.angle_masks +
            1 * hit.left_shifts +
            1 * hit.pos_shifts +
            1 * hit.q12_one_consts +
            1 * hit.q12_half_consts
        )
        # attach dynamic attribute for downstream use
        hit._weighted_score = score  # type: ignore[attr-defined]
        is_active = score > 0 or (include_trig_only and hit.trig_hits > 0)
        if is_active and score >= min_score:
            weighted.append(hit)
        if score == 0 and hit.trig_hits > 0:
            trig_only.append(hit)
    heavy = sorted(weighted, key=lambda h: (-getattr(h, "_weighted_score", 0), -h.trig_hits, h.name))
    return {
        "total_functions": total_functions,
        "active_count": len(heavy),
        "trig_only_count": len(trig_only),
        "heavy_candidates": heavy,
    }


def write_json(path: Path, hits: dict[tuple[str, int | None], FunctionHit], summary: dict) -> None:
    payload = {
        "summary": {
            k: v
            for k, v in summary.items()
            if k not in {"heavy_candidates"}
        },
        "candidates": [hit.to_json() for hit in summary["heavy_candidates"]],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_markdown(path: Path, summary: dict, limit: int = 60) -> None:
    heavy: List[FunctionHit] = summary["heavy_candidates"]
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# Q12 Math Pattern Candidates")
    lines.append("")
    lines.append(
        f"Total functions scanned: {summary['total_functions']}, candidates with Q12 traits: {summary['active_count']} (trig-only: {summary['trig_only_count']})."
    )
    lines.append("")
    lines.append("| Function | EA | WScore | >>12 | prod>>12 | sar() | &0xFFF | >>6 | Pxyz | Ang | BasisD | BasisS | Spd | rsin/rcos | Src |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |")
    for hit in heavy[:limit]:
        trig = "✔" if hit.trig_hits else ""
        lines.append(
            "| {name} | {ea} | {wscore} | {r} | {prod} | {sar} | {mask} | {pos} | {pxyz} | {ang} | {bd} | {bs} | {spd} | {trig} | {sources} |".format(
                name=hit.name,
                ea=f"0x{hit.ea:06x}" if hit.ea is not None else "—",
                wscore=getattr(hit, "_weighted_score", hit.total_hits),
                r=hit.right_shifts,
                prod=hit.q12_products,
                sar=hit.sar_calls,
                mask=hit.angle_masks,
                pos=hit.pos_shifts,
                pxyz=(hit.off_0x08 + hit.off_0x0C + hit.off_0x10),
                ang=(hit.off_0x20 + hit.off_0x22 + hit.off_0x24),
                bd=(hit.off_0x34 + hit.off_0x36 + hit.off_0x38 + hit.off_0x3A),
                bs=(hit.off_0x3C + hit.off_0x3E + hit.off_0x40),
                spd=hit.off_0x44,
                trig=trig,
                sources=len(hit.source_files),
            )
        )
    lines.append("")
    lines.append("Top entries aggregated across all JSON bundles. WScore is a weighted score favoring >>12, multiply>>12, sar, and angle masks.")
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Identify Q12 math pattern functions from exported bundles")
    parser.add_argument("--glob", default=BUNDLE_GLOB, help="Glob for bundle JSONL files")
    parser.add_argument("--out-md", default=str(DEFAULT_MD), help="Output markdown path")
    parser.add_argument("--out-json", default=str(DEFAULT_JSON), help="Output JSON path")
    parser.add_argument("--limit", type=int, default=60, help="Number of entries to include in markdown table")
    parser.add_argument("--min-score", type=int, default=0, help="Minimum weighted score to include a function")
    parser.add_argument("--no-trig-only", action="store_true", help="Exclude trig-only (rsin/rcos with no other Q12 traits)")
    args = parser.parse_args(argv)

    bundle_paths = sorted(ROOT.glob(args.glob))
    if not bundle_paths:
        raise SystemExit(f"No JSONL files matched glob: {args.glob}")

    hits = collect_hits(bundle_paths)
    summary = summarise(hits, min_score=args.min_score, include_trig_only=not args.no_trig_only)
    write_json(Path(args.out_json), hits, summary)
    write_markdown(Path(args.out_md), summary, limit=args.limit)
    print(f"Analyzed {summary['total_functions']} functions across {len(bundle_paths)} bundles.")
    print(f"Identified {summary['active_count']} candidates with Q12-style traits.")
    print(f"Markdown: {args.out_md}")
    print(f"JSON: {args.out_json}")


if __name__ == "__main__":
    main()
