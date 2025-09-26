#!/usr/bin/env python3
"""generate_crate_signature_report.py

Aggregates the heuristics emitted by scan_crate_signatures.py and produces a
curated markdown + json dossier so we can quickly triage the strongest crate
logic leads.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Iterable, List

ROOT = Path(__file__).resolve().parent.parent
EXPORT_DIR = ROOT / "exports"
NOTES_DIR = ROOT / "notes"
DEFAULT_CSV = ROOT / "crate_signature_candidates.csv"
DEFAULT_MD = EXPORT_DIR / "crate_signature_report.md"
DEFAULT_JSON = EXPORT_DIR / "crate_signature_report.json"
DEFAULT_NOTE = NOTES_DIR / "crate_signature_followup.md"


@dataclass
class RawCandidate:
    fun_name: str
    ea: int | None
    size: int
    has_input_masks: bool
    tri_slot_hits: int
    polarity_pair: bool
    large_effects_call: bool
    score: int
    candidate_type: str
    source_file: str


@dataclass
class AggregatedCandidate:
    fun_name: str
    ea: int | None
    sizes: List[int] = field(default_factory=list)
    scores: List[int] = field(default_factory=list)
    tri_hits: List[int] = field(default_factory=list)
    has_input_masks: bool = False
    polarity_pair: bool = False
    large_effects_call: bool = False
    candidate_type_counts: Counter[str] = field(default_factory=Counter)
    source_files: set[str] = field(default_factory=set)
    best_row: RawCandidate | None = None

    def register(self, row: RawCandidate) -> None:
        if self.ea is None and row.ea is not None:
            self.ea = row.ea
        self.sizes.append(row.size)
        self.scores.append(row.score)
        self.tri_hits.append(row.tri_slot_hits)
        self.has_input_masks = self.has_input_masks or row.has_input_masks
        self.polarity_pair = self.polarity_pair or row.polarity_pair
        self.large_effects_call = self.large_effects_call or row.large_effects_call
        self.candidate_type_counts[row.candidate_type] += 1
        self.source_files.add(row.source_file)
        if self.best_row is None or row.score > self.best_row.score:
            self.best_row = row

    @property
    def max_score(self) -> int:
        return max(self.scores) if self.scores else 0

    @property
    def avg_score(self) -> float:
        return float(mean(self.scores)) if self.scores else 0.0

    @property
    def max_tri_hits(self) -> int:
        return max(self.tri_hits) if self.tri_hits else 0

    @property
    def primary_candidate_type(self) -> str:
        if not self.candidate_type_counts:
            return "unknown"
        return self.candidate_type_counts.most_common(1)[0][0]

    @property
    def ea_hex(self) -> str | None:
        return f"0x{self.ea:06x}" if isinstance(self.ea, int) else None

    @property
    def source_count(self) -> int:
        return len(self.source_files)

    def to_export_dict(self) -> dict:
        return {
            "fun_name": self.fun_name,
            "ea": self.ea,
            "ea_hex": self.ea_hex,
            "max_score": self.max_score,
            "avg_score": round(self.avg_score, 2),
            "max_tri_slot_hits": self.max_tri_hits,
            "has_input_masks": self.has_input_masks,
            "polarity_pair": self.polarity_pair,
            "large_effects_call": self.large_effects_call,
            "primary_candidate_type": self.primary_candidate_type,
            "candidate_type_counts": dict(self.candidate_type_counts),
            "source_files": sorted(self.source_files),
            "source_count": self.source_count,
            "sizes": self.sizes,
            "scores": self.scores,
            "tri_slot_hits": self.tri_hits,
        }


def parse_bool(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def parse_int(value: str) -> int | None:
    value = str(value).strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def load_rows(csv_path: Path) -> list[RawCandidate]:
    rows: list[RawCandidate] = []
    with csv_path.open("r", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        for item in reader:
            rows.append(
                RawCandidate(
                    fun_name=item.get("fun_name", ""),
                    ea=parse_int(item.get("ea", "")),
                    size=int(item.get("size") or 0),
                    has_input_masks=parse_bool(item.get("has_input_masks", "")),
                    tri_slot_hits=int(item.get("tri_slot_hits") or 0),
                    polarity_pair=parse_bool(item.get("polarity_pair", "")),
                    large_effects_call=parse_bool(item.get("large_effects_call", "")),
                    score=int(item.get("score") or 0),
                    candidate_type=item.get("candidate_type", "unknown"),
                    source_file=item.get("source_file", "unknown"),
                )
            )
    return rows


def aggregate_candidates(rows: Iterable[RawCandidate]) -> list[AggregatedCandidate]:
    aggregates: dict[str, AggregatedCandidate] = {}
    for row in rows:
        if row.fun_name not in aggregates:
            aggregates[row.fun_name] = AggregatedCandidate(fun_name=row.fun_name, ea=row.ea)
        aggregates[row.fun_name].register(row)
    return list(aggregates.values())


SCORE_TIERS = [
    (8, "score_8_plus"),
    (6, "score_6_7"),
    (4, "score_4_5"),
]


def score_tier(score: int) -> str:
    for threshold, label in SCORE_TIERS:
        if score >= threshold:
            return label
    return "score_below_4"


def build_source_breakdown(rows: list[RawCandidate], aggregates: list[AggregatedCandidate]) -> list[dict]:
    per_source: dict[str, dict] = defaultdict(lambda: {
        "rows": 0,
        "unique_functions": set(),
        "type_counts": Counter(),
        "score_tiers": Counter(),
        "max_score": 0,
        "high_score_funcs": set(),
    })

    for row in rows:
        entry = per_source[row.source_file]
        entry["rows"] += 1
        entry["unique_functions"].add(row.fun_name)
        entry["type_counts"][row.candidate_type] += 1
        entry["score_tiers"][score_tier(row.score)] += 1
        entry["max_score"] = max(entry["max_score"], row.score)

    for agg in aggregates:
        if agg.max_score < 6:
            continue
        for src in agg.source_files:
            per_source[src]["high_score_funcs"].add(agg.fun_name)

    payload = []
    for source, data in sorted(per_source.items()):
        payload.append({
            "source": source,
            "rows": data["rows"],
            "unique_functions": len(data["unique_functions"]),
            "type_counts": dict(data["type_counts"].most_common()),
            "score_tiers": dict(data["score_tiers"]),
            "max_score": data["max_score"],
            "high_score_count": len(data["high_score_funcs"]),
        })
    return payload


def build_summary(rows: list[RawCandidate], aggregates: list[AggregatedCandidate]) -> dict:
    type_counter = Counter()
    score_hist = Counter()
    tier_hist = Counter()
    for agg in aggregates:
        type_counter[agg.primary_candidate_type] += 1
        score_hist[agg.max_score] += 1
        tier_hist[score_tier(agg.max_score)] += 1

    source_files = sorted({row.source_file for row in rows})

    top_sorted = sorted(
        aggregates,
        key=lambda a: (-a.max_score, -a.max_tri_hits, a.fun_name),
    )

    top_candidates = [cand.to_export_dict() for cand in top_sorted[:20]]

    top_by_type: dict[str, list[dict]] = defaultdict(list)
    for agg in top_sorted:
        label = agg.primary_candidate_type
        if len(top_by_type[label]) < 5:
            top_by_type[label].append(agg.to_export_dict())

    mask_tri_overlap = sum(1 for agg in aggregates if agg.has_input_masks and agg.max_tri_hits >= 3)

    source_breakdown = build_source_breakdown(rows, aggregates)

    return {
        "total_rows": len(rows),
        "unique_functions": len(aggregates),
        "candidate_type_counts": dict(type_counter.most_common()),
        "score_histogram": dict(sorted(score_hist.items(), reverse=True)),
        "score_tier_histogram": dict(tier_hist),
        "source_files": source_files,
        "top_candidates": top_candidates,
        "top_by_type": {k: v for k, v in top_by_type.items()},
        "mask_plus_tri_count": mask_tri_overlap,
    "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_breakdown": source_breakdown,
    }


def write_json(path: Path, aggregates: list[AggregatedCandidate], summary: dict) -> None:
    payload = {
        "summary": summary,
        "candidates": [agg.to_export_dict() for agg in aggregates],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def format_bool(value: bool) -> str:
    return "✅" if value else ""


def write_markdown(path: Path, aggregates: list[AggregatedCandidate], summary: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# Crate Signature Candidate Triage Report")
    lines.append("")
    lines.append(f"Generated: {summary['generated_utc']} UTC")
    lines.append("")
    lines.append("## Snapshot")
    lines.append("")
    lines.append(f"- Total CSV rows: {summary['total_rows']}")
    lines.append(f"- Unique functions: {summary['unique_functions']}")
    lines.append(
        "- Candidate type counts: "
        + ", ".join(f"{k}={v}" for k, v in summary["candidate_type_counts"].items())
    )
    lines.append(
        "- Sources scanned: "
        + ", ".join(summary["source_files"])
        if summary["source_files"]
        else "- Sources scanned: (none)"
    )
    lines.append(
        f"- Functions with pickup masks and full tri-slot coverage: {summary['mask_plus_tri_count']}"
    )
    lines.append("")

    lines.append("## Score Distribution")
    lines.append("")
    if summary["score_histogram"]:
        lines.append("| Score | Functions | Tier |")
        lines.append("| --- | ---: | --- |")
        for score, count in summary["score_histogram"].items():
            tier = score_tier(int(score))
            lines.append(f"| {score} | {count} | {tier} |")
    else:
        lines.append("No score data available.")
    lines.append("")

    lines.append("## Top Candidates (score ≥ 6)")
    lines.append("")
    top_candidates = [agg for agg in aggregates if agg.max_score >= 6]
    if top_candidates:
        lines.append(
            "| Function | EA | Score | Type | Tri Hits | Masks | Polarity | Effects | Sources |"
        )
        lines.append("| --- | --- | ---: | --- | ---: | :---: | :---: | :---: | ---: |")
        for agg in sorted(top_candidates, key=lambda a: (-a.max_score, -a.max_tri_hits, a.fun_name)):
            lines.append(
                "| {name} | {ea} | {score} | {ctype} | {tri} | {masks} | {polarity} | {effects} | {sources} |".format(
                    name=agg.fun_name,
                    ea=agg.ea_hex or "—",
                    score=agg.max_score,
                    ctype=agg.primary_candidate_type,
                    tri=agg.max_tri_hits,
                    masks=format_bool(agg.has_input_masks),
                    polarity=format_bool(agg.polarity_pair),
                    effects=format_bool(agg.large_effects_call),
                    sources=agg.source_count,
                )
            )
    else:
        lines.append("No candidates scored ≥ 6.")
    lines.append("")

    lines.append("## Source Coverage")
    lines.append("")
    if summary["source_breakdown"]:
        lines.append("| Source | Rows | Unique functions | High-score funcs | Max score | Key types |")
        lines.append("| --- | ---: | ---: | ---: | ---: | --- |")
        for entry in summary["source_breakdown"]:
            type_desc = ", ".join(f"{k}:{v}" for k, v in entry["type_counts"].items()) or "—"
            lines.append(
                f"| {entry['source']} | {entry['rows']} | {entry['unique_functions']} | {entry['high_score_count']} | {entry['max_score']} | {type_desc} |"
            )
    else:
        lines.append("No source coverage data available.")
    lines.append("")

    lines.append("## Type Highlights")
    lines.append("")
    for ctype, entries in summary["top_by_type"].items():
        lines.append(f"### {ctype}")
        lines.append("")
        if not entries:
            lines.append("No representatives captured.")
            lines.append("")
            continue
        lines.append(
            "| Function | EA | Score | Tri Hits | Masks | Polarity | Effects | Sources |"
        )
        lines.append("| --- | --- | ---: | ---: | :---: | :---: | :---: | ---: |")
        for entry in entries:
            lines.append(
                "| {name} | {ea} | {score} | {tri} | {masks} | {polarity} | {effects} | {sources} |".format(
                    name=entry["fun_name"],
                    ea=entry["ea_hex"] or "—",
                    score=entry["max_score"],
                    tri=entry["max_tri_slot_hits"],
                    masks="✅" if entry["has_input_masks"] else "",
                    polarity="✅" if entry["polarity_pair"] else "",
                    effects="✅" if entry["large_effects_call"] else "",
                    sources=entry["source_count"],
                )
            )
        lines.append("")

    lines.append("## Follow-up Leads")
    lines.append("")
    lines.append("1. Validate pickup/throw state transitions for the highest scoring `pickup_or_throw_logic` entries.")
    lines.append("2. Map secondary callbacks with strong effects calls to their animation/audio resources.")
    lines.append("3. Confirm polarity helper routines tie into crate ownership checks before installing names.")
    lines.append("4. Feed the top candidates into Ghidra symbol import to accelerate naming passes.")

    path.write_text("\n".join(lines), encoding="utf-8")


def write_followup(path: Path, aggregates: list[AggregatedCandidate], summary: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    pickup = [a for a in aggregates if a.primary_candidate_type == "pickup_or_throw_logic"]
    secondary = [a for a in aggregates if a.primary_candidate_type == "secondary_cb"]
    polarity = [a for a in aggregates if a.primary_candidate_type == "polarity_helper"]
    per_frame = [a for a in aggregates if a.primary_candidate_type == "per_frame_cb"]

    def fmt_entry(agg: AggregatedCandidate) -> str:
        srcs = ", ".join(sorted(agg.source_files))
        return (
            f"- `{agg.fun_name}` @ {agg.ea_hex or '—'} — score {agg.max_score}, tri {agg.max_tri_hits}. "
            f"Masks: {'yes' if agg.has_input_masks else 'no'}, Polarity: {'yes' if agg.polarity_pair else 'no'}, "
            f"Effects: {'yes' if agg.large_effects_call else 'no'}. Sources: {srcs}"
        )

    lines = []
    lines.append("# Crate Signature Follow-up")
    lines.append("")
    lines.append(f"Generated: {summary['generated_utc']} UTC")
    lines.append("")
    lines.append("## High-confidence pickup/throw leads")
    lines.append("")
    top_pickup = sorted(pickup, key=lambda a: (-a.max_score, -a.max_tri_hits, a.fun_name))[:10]
    lines.extend(fmt_entry(agg) for agg in top_pickup)
    if not top_pickup:
        lines.append("- None captured.")
    lines.append("")

    lines.append("## Secondary callback prospects")
    lines.append("")
    top_secondary = sorted(secondary, key=lambda a: (-a.max_score, a.fun_name))[:5]
    lines.extend(fmt_entry(agg) for agg in top_secondary)
    if not top_secondary:
        lines.append("- None captured.")
    lines.append("")

    lines.append("## Polarity helpers to verify")
    lines.append("")
    top_polarity = sorted(polarity, key=lambda a: (-a.max_score, a.fun_name))[:5]
    lines.extend(fmt_entry(agg) for agg in top_polarity)
    if not top_polarity:
        lines.append("- None captured.")
    lines.append("")

    lines.append("## Per-frame handlers worth diffing")
    lines.append("")
    top_pf = sorted(per_frame, key=lambda a: (-a.max_score, a.fun_name))[:5]
    lines.extend(fmt_entry(agg) for agg in top_pf)
    if not top_pf:
        lines.append("- None captured.")
    lines.append("")

    lines.append("## Immediate tasks")
    lines.append("")
    lines.append("1. Diff the pickup/throw integrator calls between MAIN.EXE and overlays for the top 5 leads.")
    lines.append("2. Trace secondary callback install sites for high-scoring entries to map animation/audio assets.")
    lines.append("3. Validate polarity helper usage paths before assigning final names.")
    lines.append("4. Feed confirmed matches back into the SDK label pipeline and Ghidra import script.")

    path.write_text("\n".join(lines), encoding="utf-8")


def run(csv_path: Path, md_path: Path, json_path: Path, note_path: Path) -> None:
    if not csv_path.exists():
        raise SystemExit(f"Input CSV not found: {csv_path}")
    rows = load_rows(csv_path)
    if not rows:
        raise SystemExit("Input CSV had no rows; aborting to avoid empty report.")
    aggregates = aggregate_candidates(rows)
    summary = build_summary(rows, aggregates)
    write_json(json_path, aggregates, summary)
    write_markdown(md_path, aggregates, summary)
    write_followup(note_path, aggregates, summary)
    print(f"Wrote {md_path}")
    print(f"Wrote {json_path}")
    print(f"Wrote {note_path}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Generate triage report for crate signature candidates")
    parser.add_argument("--csv", default=str(DEFAULT_CSV), help="Path to crate_signature_candidates.csv")
    parser.add_argument("--out-md", default=str(DEFAULT_MD), help="Output markdown path")
    parser.add_argument("--out-json", default=str(DEFAULT_JSON), help="Output JSON path")
    parser.add_argument("--out-note", default=str(DEFAULT_NOTE), help="Output follow-up note path")
    args = parser.parse_args(argv)

    csv_path = Path(args.csv)
    md_path = Path(args.out_md)
    json_path = Path(args.out_json)
    note_path = Path(args.out_note)

    run(csv_path, md_path, json_path, note_path)


if __name__ == "__main__":
    main()
