#!/usr/bin/env python3
"""Recommend next PSYQ field-truth targets from the checklist."""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import pathlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional

FIELD_TRUTH_CSV = pathlib.Path("exports/psyq_field_truth_sheet.csv")
OUTPUT_MD = pathlib.Path("exports/psyq_field_truth_next.md")

_PRIORITY_ORDER = ["high", "second", "watch", "other"]
_DEFAULT_LIMIT = 5


@dataclass
class SlotCandidate:
    crate_index: int
    crate_label: str
    priority: str
    slot: int
    value_a_domain: str
    value_b_domain: str
    value_a_crossref: int
    value_b_crossref: int
    focus_hint: str

    @property
    def combined_crossref(self) -> int:
        return self.value_a_crossref + self.value_b_crossref

    def to_markdown_row(self) -> str:
        domains = ", ".join(
            filter(None, [self.value_a_domain or "?", self.value_b_domain or "?"])
        )
        return (
            f"| {self.crate_index} | {self.slot} | {self.crate_label} | {domains} | "
            f"{self.combined_crossref} | {self.focus_hint or '—'} |"
        )


def _read_csv(path: pathlib.Path) -> Iterable[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(
            f"Field truth sheet not found: {path}. Run prepare_field_truth_sheet.py first."
        )
    with path.open(newline="", encoding="utf-8") as f:
        yield from csv.DictReader(f)


def _safe_int(value: Optional[str]) -> int:
    if not value:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def load_candidates(path: pathlib.Path) -> List[SlotCandidate]:
    candidates: List[SlotCandidate] = []
    for row in _read_csv(path):
        observed = bool(row.get("observed_psyq_calls")) or bool(row.get("observed_slot_notes"))
        if observed:
            continue
        try:
            crate_index = int(row.get("crate_index", ""))
            slot = int(row.get("slot", ""))
        except (TypeError, ValueError):
            continue
        priority = (row.get("priority", "") or "watch").lower()
        if priority not in _PRIORITY_ORDER:
            priority = "other"
        candidates.append(
            SlotCandidate(
                crate_index=crate_index,
                crate_label=row.get("crate_label", "").strip() or f"INDEX_{crate_index:02d}",
                priority=priority,
                slot=slot,
                value_a_domain=row.get("value_a_domain", "").strip(),
                value_b_domain=row.get("value_b_domain", "").strip(),
                value_a_crossref=_safe_int(row.get("value_a_crossref_total")),
                value_b_crossref=_safe_int(row.get("value_b_crossref_total")),
                focus_hint=row.get("focus_hint", "").strip()
                or row.get("dominant_domain_hint", "").strip(),
            )
        )
    return candidates


def group_by_priority(candidates: Iterable[SlotCandidate]) -> Dict[str, List[SlotCandidate]]:
    buckets: Dict[str, List[SlotCandidate]] = {key: [] for key in _PRIORITY_ORDER}
    for candidate in candidates:
        buckets.setdefault(candidate.priority, []).append(candidate)
    return buckets


def sort_candidates(candidates: List[SlotCandidate]) -> None:
    candidates.sort(
        key=lambda item: (
            item.combined_crossref,
            item.value_a_crossref,
            item.value_b_crossref,
            -item.crate_index,
        ),
        reverse=True,
    )


def write_markdown(buckets: Mapping[str, List[SlotCandidate]], limit: int, out_path: pathlib.Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    today = _dt.date.today().isoformat()
    lines: List[str] = []
    lines.append(f"# PSYQ field-truth next targets ({today})\n")
    lines.append("Derived from exports/psyq_field_truth_sheet.csv. Rows shown below remain unverified.\n")
    lines.append("Update observed_psyq_calls or observed_slot_notes to remove a slot from this list.\n\n")

    for priority in _PRIORITY_ORDER:
        candidates = buckets.get(priority, [])
        if not candidates:
            continue
        sort_candidates(candidates)
        head = candidates[:limit]
        if not head:
            continue
        label = priority.capitalize() if priority != "other" else "Other"
        lines.append(f"## {label} priority\n")
        lines.append("| Crate | Slot | Label | Domains | Combined crossrefs | Focus hint |\n")
        lines.append("|-------|------|-------|---------|--------------------|-------------|\n")
        for candidate in head:
            lines.append(candidate.to_markdown_row() + "\n")
        remaining = len(candidates) - len(head)
        if remaining > 0:
            lines.append(f"\n_{remaining} additional slot(s) not shown; increase --limit to view all._\n")
        lines.append("\n")

    lines.append("---\n")
    lines.append(
        "Tune priorities via --priorities or adjust row limit via --limit when generating the field-truth sheet."
    )

    out_path.write_text("".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Recommend next PSYQ field-truth slots")
    parser.add_argument("--sheet", default=str(FIELD_TRUTH_CSV), help="Path to psyq_field_truth_sheet.csv")
    parser.add_argument("--output", default=str(OUTPUT_MD), help="Destination Markdown path")
    parser.add_argument("--limit", type=int, default=_DEFAULT_LIMIT, help="Slots per priority to display")
    args = parser.parse_args()

    sheet_path = pathlib.Path(args.sheet)
    out_path = pathlib.Path(args.output)

    candidates = load_candidates(sheet_path)
    buckets = group_by_priority(candidates)
    write_markdown(buckets, args.limit, out_path)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
