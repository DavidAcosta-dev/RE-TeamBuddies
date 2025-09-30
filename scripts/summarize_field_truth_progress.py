#!/usr/bin/env python3
"""Summarize PSYQ field-truth checklist progress."""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import pathlib
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping

FIELD_TRUTH_CSV = pathlib.Path("exports/psyq_field_truth_sheet.csv")
OUTPUT_MD = pathlib.Path("exports/psyq_field_truth_progress.md")

_PRIORITY_ORDER = ["high", "second", "watch", "other"]


@dataclass
class SlotRecord:
    crate_index: int
    crate_label: str
    priority: str
    observed: bool


@dataclass
class CrateSummary:
    crate_index: int
    crate_label: str
    priority: str
    total_slots: int
    observed_slots: int

    @property
    def percent(self) -> float:
        return (self.observed_slots / self.total_slots) * 100 if self.total_slots else 0.0

    def to_markdown_row(self) -> str:
        return (
            f"| {self.crate_index} | {self.crate_label} | {self.observed_slots}/{self.total_slots} | "
            f"{self.percent:5.1f}% |"
        )


@dataclass
class PrioritySummary:
    priority: str
    total_slots: int
    observed_slots: int

    @property
    def percent(self) -> float:
        return (self.observed_slots / self.total_slots) * 100 if self.total_slots else 0.0


def _read_csv(path: pathlib.Path) -> Iterable[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Field truth sheet not found: {path}. Run prepare_field_truth_sheet.py first.")
    with path.open(newline="", encoding="utf-8") as f:
        yield from csv.DictReader(f)


def load_slots(path: pathlib.Path) -> List[SlotRecord]:
    slots: List[SlotRecord] = []
    for row in _read_csv(path):
        try:
            crate_index = int(row.get("crate_index", ""))
        except (TypeError, ValueError):
            continue
        crate_label = row.get("crate_label", "").strip() or f"INDEX_{crate_index:02d}"
        priority = (row.get("priority", "") or "watch").lower()
        observed = bool(row.get("observed_psyq_calls")) or bool(row.get("observed_slot_notes"))
        slots.append(SlotRecord(crate_index=crate_index, crate_label=crate_label, priority=priority, observed=observed))
    return slots


def aggregate_by_crate(slots: Iterable[SlotRecord]) -> Dict[int, CrateSummary]:
    summary: Dict[int, CrateSummary] = {}
    for slot in slots:
        entry = summary.get(slot.crate_index)
        if not entry:
            entry = CrateSummary(
                crate_index=slot.crate_index,
                crate_label=slot.crate_label,
                priority=slot.priority,
                total_slots=0,
                observed_slots=0,
            )
            summary[slot.crate_index] = entry
        entry.total_slots += 1
        if slot.observed:
            entry.observed_slots += 1
    return summary


def aggregate_by_priority(slots: Iterable[SlotRecord]) -> Dict[str, PrioritySummary]:
    totals: Dict[str, PrioritySummary] = {}
    for slot in slots:
        priority = slot.priority if slot.priority in _PRIORITY_ORDER else "other"
        entry = totals.get(priority)
        if not entry:
            entry = PrioritySummary(priority=priority, total_slots=0, observed_slots=0)
            totals[priority] = entry
        entry.total_slots += 1
        if slot.observed:
            entry.observed_slots += 1
    return totals


def order_priorities(mapping: Mapping[str, PrioritySummary]) -> List[PrioritySummary]:
    ordered: List[PrioritySummary] = []
    for key in _PRIORITY_ORDER:
        if key in mapping:
            ordered.append(mapping[key])
    for key, summary in mapping.items():
        if key not in _PRIORITY_ORDER:
            ordered.append(summary)
    return ordered


def write_markdown(
    crate_summaries: Mapping[int, CrateSummary],
    priority_summaries: Iterable[PrioritySummary],
    out_path: pathlib.Path,
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    today = _dt.date.today().isoformat()
    lines: List[str] = []
    lines.append(f"# PSYQ field-truth progress ({today})\n")
    lines.append("Derived from exports/psyq_field_truth_sheet.csv. Run prepare_field_truth_sheet.py then annotate the sheet before refreshing this report.\n")

    total_slots = sum(summary.total_slots for summary in crate_summaries.values())
    total_observed = sum(summary.observed_slots for summary in crate_summaries.values())
    overall_percent = (total_observed / total_slots) * 100 if total_slots else 0.0
    lines.append(f"Overall progress: **{total_observed}/{total_slots} slots ({overall_percent:5.1f}%)**\n\n")

    lines.append("## By priority\n")
    lines.append("| Priority | Observed/Total | Percent |\n")
    lines.append("|----------|----------------|---------|\n")
    for summary in priority_summaries:
        label = summary.priority.capitalize()
        if summary.priority == "other":
            label = "Other"
        lines.append(f"| {label} | {summary.observed_slots}/{summary.total_slots} | {summary.percent:5.1f}% |\n")
    lines.append("\n")

    buckets: Dict[str, List[CrateSummary]] = defaultdict(list)
    for summary in crate_summaries.values():
        priority = summary.priority if summary.priority in _PRIORITY_ORDER else "other"
        buckets[priority].append(summary)

    for priority in _PRIORITY_ORDER:
        crate_list = buckets.get(priority)
        if not crate_list:
            continue
        label = priority.capitalize() if priority != "other" else "Other"
        lines.append(f"## {label} crates\n")
        lines.append("| Crate | Label | Observed | Percent |\n")
        lines.append("|-------|-------|----------|---------|\n")
        for summary in sorted(crate_list, key=lambda s: (-s.percent, s.crate_index)):
            lines.append(summary.to_markdown_row() + "\n")
        lines.append("\n")

    if any(key not in _PRIORITY_ORDER for key in buckets):
        label = "Other"
        crate_list = buckets.get("other", [])
        if crate_list:
            lines.append(f"## {label} crates\n")
            lines.append("| Crate | Label | Observed | Percent |\n")
            lines.append("|-------|-------|----------|---------|\n")
            for summary in sorted(crate_list, key=lambda s: (-s.percent, s.crate_index)):
                lines.append(summary.to_markdown_row() + "\n")
            lines.append("\n")

    lines.append("---\n")
    lines.append("Populate `observed_psyq_calls` or `observed_slot_notes` in the checklist to mark progress.\n")

    out_path.write_text("".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize PSYQ field-truth sheet progress")
    parser.add_argument("--sheet", default=str(FIELD_TRUTH_CSV), help="Path to psyq_field_truth_sheet.csv")
    parser.add_argument("--output", default=str(OUTPUT_MD), help="Destination Markdown path")
    args = parser.parse_args()

    sheet_path = pathlib.Path(args.sheet)
    out_path = pathlib.Path(args.output)

    slots = load_slots(sheet_path)
    crates = aggregate_by_crate(slots)
    priority_stats = order_priorities(aggregate_by_priority(slots))

    write_markdown(crates, priority_stats, out_path)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
