#!/usr/bin/env python3
"""Generate a domain-centric PSYQ tracing cheat sheet from pivot + priority data."""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import pathlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional

PIVOT_CSV = pathlib.Path("exports/crate_domain_pivot.csv")
TARGETS_CSV = pathlib.Path("exports/psyq_trace_targets.csv")
CROSSREF_CSV = pathlib.Path("exports/crate_crossref_summary.csv")
OUTPUT_MD = pathlib.Path("exports/psyq_focus_report.md")

_DOMAINS = ("ai", "combat", "engine", "render", "support")
_DOMAIN_LABEL = {
    "ai": "AI / libgte vectors",
    "combat": "Combat FX (libgte/libgpu)",
    "engine": "State machine core",
    "render": "Rendering (libgpu/libgte)",
    "support": "Support systems (libspu/libpad)",
}


@dataclass
class PivotEntry:
    crate_index: int
    label: str
    counts: Mapping[str, int]


@dataclass
class TargetEntry:
    priority: str
    score: float
    focus_hint: str
    combined_total: int


@dataclass
class DomainRow:
    crate_index: int
    label: str
    domain_count: int
    priority: str
    score: float
    focus_hint: str
    combined_total: int

    def to_markdown_row(self) -> str:
        focus = self.focus_hint or "—"
        priority = self.priority or "watch"
        score = f"{self.score:.1f}" if self.score else "—"
        highlight = f"{self.domain_count} hits"
        return f"| {self.crate_index} | {self.label} | {priority} | {score} | {highlight} | {self.combined_total} | {focus} |"


def _read_csv(path: pathlib.Path) -> Iterable[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        yield from csv.DictReader(f)


def load_pivot(path: pathlib.Path) -> Dict[int, PivotEntry]:
    pivot: Dict[int, PivotEntry] = {}
    for row in _read_csv(path):
        try:
            crate_index = int(row.get("crate_index", ""))
        except (TypeError, ValueError):
            continue
        label = row.get("crate_label", "").strip() or f"INDEX_{crate_index:02d}"
        counts = {domain: int(row.get(f"both_domain_{domain}", "") or 0) for domain in _DOMAINS}
        pivot[crate_index] = PivotEntry(crate_index=crate_index, label=label, counts=counts)
    return pivot


def load_targets(path: pathlib.Path) -> Dict[int, TargetEntry]:
    targets: Dict[int, TargetEntry] = {}
    if not path.exists():
        return targets
    for row in _read_csv(path):
        try:
            crate_index = int(row.get("crate_index", ""))
        except (TypeError, ValueError):
            continue
        priority = row.get("priority", "").strip()
        try:
            score = float(row.get("score", "") or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        focus_hint = row.get("psyq_focus_hint", "").strip()
        combined_total = int(row.get("combined_total", "") or 0)
        targets[crate_index] = TargetEntry(
            priority=priority,
            score=score,
            focus_hint=focus_hint,
            combined_total=combined_total,
        )
    return targets


def load_crossref(path: pathlib.Path) -> Dict[int, int]:
    totals: Dict[int, int] = {}
    if not path.exists():
        return totals
    for row in _read_csv(path):
        try:
            crate_index = int(row.get("crate_index", ""))
        except (TypeError, ValueError):
            continue
        totals[crate_index] = int(row.get("combined_total", "") or 0)
    return totals


def select_top_by_domain(
    pivot: Mapping[int, PivotEntry],
    targets: Mapping[int, TargetEntry],
    crossref_totals: Mapping[int, int],
    domain: str,
    limit: int = 10,
) -> List[DomainRow]:
    rows: List[DomainRow] = []
    for entry in pivot.values():
        domain_count = entry.counts.get(domain, 0)
        if domain_count <= 0:
            continue
        target = targets.get(entry.crate_index)
        combined_total = target.combined_total if target else crossref_totals.get(entry.crate_index, 0)
        focus_hint = target.focus_hint if target else ""
        priority = target.priority if target else ""
        score = target.score if target else 0.0
        rows.append(
            DomainRow(
                crate_index=entry.crate_index,
                label=entry.label,
                domain_count=domain_count,
                priority=priority,
                score=score,
                focus_hint=focus_hint,
                combined_total=combined_total,
            )
        )
    rows.sort(
        key=lambda row: (
            row.domain_count,
            row.score,
            row.combined_total,
            -row.crate_index,
        ),
        reverse=True,
    )
    return rows[:limit]


def write_markdown(sections: Mapping[str, List[DomainRow]], out_path: pathlib.Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    today = _dt.date.today().isoformat()
    lines: List[str] = []
    lines.append(f"# PSYQ focus report ({today})\n")
    lines.append("Derived from crate domain pivots and psyq_trace_targets.csv.\n")
    lines.append("Run `scripts/summarize_psyq_focus.py` after refreshing pivots/targets to regenerate this file.\n")
    for domain in _DOMAINS:
        rows = sections.get(domain, [])
        if not rows:
            continue
        label = _DOMAIN_LABEL.get(domain, domain)
        lines.append(f"## {label}\n")
        lines.append("| Crate | Label | Priority | Score | Domain hits | Crossrefs | Focus hint |\n")
        lines.append("|-------|-------|----------|-------|-------------|-----------|------------|\n")
        for row in rows:
            lines.append(row.to_markdown_row() + "\n")
        lines.append("\n")
    lines.append("---\n")
    lines.append("Focus ranking favours crates with high domain counts, breaking ties by priority score and crossref density.\n")
    out_path.write_text("".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize top crates per PSYQ domain")
    parser.add_argument("--pivot", default=str(PIVOT_CSV), help="Path to crate_domain_pivot.csv")
    parser.add_argument("--targets", default=str(TARGETS_CSV), help="Path to psyq_trace_targets.csv")
    parser.add_argument("--crossref", default=str(CROSSREF_CSV), help="Path to crate_crossref_summary.csv")
    parser.add_argument("--output", default=str(OUTPUT_MD), help="Destination Markdown path")
    parser.add_argument("--limit", type=int, default=8, help="Rows per domain section")
    args = parser.parse_args()

    pivot_path = pathlib.Path(args.pivot)
    target_path = pathlib.Path(args.targets)
    crossref_path = pathlib.Path(args.crossref)
    output_path = pathlib.Path(args.output)

    if not pivot_path.exists():
        raise FileNotFoundError(f"Missing pivot CSV: {pivot_path}. Run summarize_crate_domain_counts.py first.")

    pivot = load_pivot(pivot_path)
    targets = load_targets(target_path)
    crossref_totals = load_crossref(crossref_path)

    sections = {}
    for domain in _DOMAINS:
        sections[domain] = select_top_by_domain(pivot, targets, crossref_totals, domain, limit=args.limit)

    write_markdown(sections, output_path)
    print(f"Wrote {output_path}")


if __name__ == "__main__":
    main()
