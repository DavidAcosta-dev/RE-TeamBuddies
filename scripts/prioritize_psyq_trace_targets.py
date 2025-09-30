#!/usr/bin/env python3
"""Rank crate indexes by PSYQ tracing value using domain pivots and crossref density."""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import pathlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence

PIVOT_CSV = pathlib.Path("exports/crate_domain_pivot.csv")
CROSSREF_CSV = pathlib.Path("exports/crate_crossref_summary.csv")
OUTPUT_CSV = pathlib.Path("exports/psyq_trace_targets.csv")
OUTPUT_MD = pathlib.Path("exports/psyq_trace_targets.md")

_DOMAINS = ("ai", "combat", "engine", "render", "support")
_DOMAIN_FOCUS = {
    "ai": "libgte vector routines",
    "combat": "libgte/libgpu combat loops",
    "engine": "state-machine scheduler",
    "render": "libgpu geometry + libgte transforms",
    "support": "libspu/libpad support systems",
}
_DOMAIN_WEIGHTS = {
    "ai": 1.1,
    "combat": 1.25,
    "engine": 0.9,
    "render": 1.3,
    "support": 1.05,
}


@dataclass
class PivotRow:
    crate_index: int
    crate_label: str
    domains: Mapping[str, int]
    both_total: int

    @property
    def domain_span(self) -> int:
        return sum(1 for value in self.domains.values() if value > 0)


@dataclass
class CrossrefRow:
    combined_total: int
    dominant_domain: str
    dominant_domain_hint: str


@dataclass
class CrateScore:
    crate_index: int
    crate_label: str
    score: float
    domain_span: int
    domains: Mapping[str, int]
    combined_total: int
    dominant_domain: str
    dominant_domain_hint: str
    priority: str

    @property
    def top_domains(self) -> List[str]:
        return [domain for domain, _ in sorted(
            self.domains.items(), key=lambda item: (item[1], item[0]), reverse=True
        ) if self.domains[domain] > 0][:2]

    @property
    def focus_hint(self) -> str:
        tops = self.top_domains
        if not tops:
            return "Data sparse"
        mapped = [_DOMAIN_FOCUS.get(domain, domain) for domain in tops]
        return " + ".join(mapped)

    @property
    def highlight_counts(self) -> str:
        meaningful = [
            (domain, self.domains.get(domain, 0))
            for domain in _DOMAINS
            if self.domains.get(domain, 0)
        ]
        meaningful.sort(key=lambda item: item[1], reverse=True)
        snippets = [f"{domain}:{value}" for domain, value in meaningful[:4]]
        return ", ".join(snippets) if snippets else "—"


def _read_csv_rows(path: pathlib.Path) -> Iterable[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Missing required CSV: {path}")
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        yield from reader


def load_pivot(path: pathlib.Path) -> Dict[int, PivotRow]:
    result: Dict[int, PivotRow] = {}
    for row in _read_csv_rows(path):
        try:
            crate_index = int(row.get("crate_index", ""))
        except (TypeError, ValueError):
            continue
        label = row.get("crate_label", "").strip()
        if not label:
            label = f"INDEX_{crate_index:02d}"
        domains = {domain: int(row.get(f"both_domain_{domain}", "") or 0) for domain in _DOMAINS}
        both_total = int(row.get("both_total", "") or 0)
        result[crate_index] = PivotRow(crate_index=crate_index, crate_label=label, domains=domains, both_total=both_total)
    return result


def load_crossref(path: pathlib.Path) -> Dict[int, CrossrefRow]:
    result: Dict[int, CrossrefRow] = {}
    for row in _read_csv_rows(path):
        try:
            crate_index = int(row.get("crate_index", ""))
        except (TypeError, ValueError):
            continue
        combined_total = int(row.get("combined_total", "") or 0)
        dominant_domain = row.get("dominant_domain", "").strip()
        dominant_hint = row.get("dominant_domain_hint", "").strip()
        result[crate_index] = CrossrefRow(
            combined_total=combined_total,
            dominant_domain=dominant_domain,
            dominant_domain_hint=dominant_hint,
        )
    return result


def compute_score(pivot: PivotRow, crossref: CrossrefRow | None) -> float:
    weighted = sum(pivot.domains.get(domain, 0) * _DOMAIN_WEIGHTS[domain] for domain in _DOMAINS)
    span_bonus = pivot.domain_span * 5.0
    combined = crossref.combined_total if crossref else 0
    combined_bonus = min(combined, 2500) / 60.0
    return weighted + span_bonus + combined_bonus


def assign_priority(scores: Sequence[CrateScore]) -> None:
    for idx, crate in enumerate(scores):
        if idx < 5:
            crate.priority = "high"
        elif idx < 10:
            crate.priority = "second"
        else:
            crate.priority = "watch"


def write_csv(scores: Sequence[CrateScore], path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    headers = [
        "crate_index",
        "crate_label",
        "priority",
        "score",
        "domain_span",
        *[f"domain_{domain}" for domain in _DOMAINS],
        "combined_total",
        "dominant_domain",
        "dominant_domain_hint",
        "psyq_focus_hint",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for crate in scores:
            row = {
                "crate_index": crate.crate_index,
                "crate_label": crate.crate_label,
                "priority": crate.priority,
                "score": f"{crate.score:.2f}",
                "domain_span": crate.domain_span,
                "combined_total": crate.combined_total,
                "dominant_domain": crate.dominant_domain,
                "dominant_domain_hint": crate.dominant_domain_hint,
                "psyq_focus_hint": crate.focus_hint,
            }
            for domain in _DOMAINS:
                row[f"domain_{domain}"] = crate.domains.get(domain, 0)
            writer.writerow(row)


def write_markdown(scores: Sequence[CrateScore], path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    today = _dt.date.today().isoformat()
    lines: List[str] = []
    lines.append(f"# PSYQ crate trace targets (auto-generated {today})\n")
    lines.append("These rankings are derived from domain pivot counts and cross-reference density.\n")
    lines.append("Run `scripts/prioritize_psyq_trace_targets.py` after refreshing the matrix/pivot to regenerate this file.\n")

    def emit_section(title: str, items: Sequence[CrateScore]) -> None:
        if not items:
            return
        lines.append(f"## {title}\n")
        lines.append("| Crate | Label | Score | Highlights | PSYQ focus |\n")
        lines.append("|-------|-------|-------|------------|------------|\n")
        for crate in items:
            lines.append(
                f"| {crate.crate_index} | {crate.crate_label} | {crate.score:.1f} | {crate.highlight_counts} | {crate.focus_hint} |\n"
            )
        lines.append("\n")

    high = [crate for crate in scores if crate.priority == "high"]
    second = [crate for crate in scores if crate.priority == "second"]
    watch = [crate for crate in scores if crate.priority == "watch"][:10]

    emit_section("High priority", high)
    emit_section("Second wave", second)
    emit_section("Watch list", watch)

    lines.append("---\n")
    lines.append("Scores blend domain coverage with crossref totals. Domain weights emphasise render/combat-heavy crates for PSYQ instrumentation.\n")

    path.write_text("".join(lines), encoding="utf-8")


def rank_crates(pivot_rows: Mapping[int, PivotRow], crossref_rows: Mapping[int, CrossrefRow]) -> List[CrateScore]:
    scores: List[CrateScore] = []
    for crate_index, pivot in pivot_rows.items():
        crossref = crossref_rows.get(crate_index)
        score_value = compute_score(pivot, crossref)
        combined_total = crossref.combined_total if crossref else 0
        dominant_domain = crossref.dominant_domain if crossref else ""
        dominant_hint = crossref.dominant_domain_hint if crossref else ""
        scores.append(
            CrateScore(
                crate_index=crate_index,
                crate_label=pivot.crate_label,
                score=score_value,
                domain_span=pivot.domain_span,
                domains=dict(pivot.domains),
                combined_total=combined_total,
                dominant_domain=dominant_domain,
                dominant_domain_hint=dominant_hint,
                priority="",
            )
        )

    scores.sort(key=lambda crate: crate.score, reverse=True)
    assign_priority(scores)
    return scores


def main() -> None:
    parser = argparse.ArgumentParser(description="Prioritize crates for PSYQ runtime tracing")
    parser.add_argument("--pivot", default=str(PIVOT_CSV), help="Path to crate_domain_pivot.csv")
    parser.add_argument("--crossref", default=str(CROSSREF_CSV), help="Path to crate_crossref_summary.csv")
    parser.add_argument("--output-csv", default=str(OUTPUT_CSV), help="Destination CSV path")
    parser.add_argument("--output-md", default=str(OUTPUT_MD), help="Destination Markdown path")
    args = parser.parse_args()

    pivot_path = pathlib.Path(args.pivot)
    crossref_path = pathlib.Path(args.crossref)
    out_csv = pathlib.Path(args.output_csv)
    out_md = pathlib.Path(args.output_md)

    pivot_rows = load_pivot(pivot_path)
    if not pivot_rows:
        raise RuntimeError("No crate domain pivot rows loaded. Run summarize_crate_domain_counts.py first.")
    crossref_rows = load_crossref(crossref_path)

    scores = rank_crates(pivot_rows, crossref_rows)
    write_csv(scores, out_csv)
    write_markdown(scores, out_md)
    print(f"Wrote {out_csv} and {out_md}")


if __name__ == "__main__":
    main()
