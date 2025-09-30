#!/usr/bin/env python3
"""Emit a Ghidra headless job file for PSYQ field-truth verification."""
from __future__ import annotations

import argparse
import csv
import json
import pathlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

FIELD_TRUTH_CSV = pathlib.Path("exports/psyq_field_truth_sheet.csv")
TARGETS_CSV = pathlib.Path("exports/psyq_trace_targets.csv")
OUTPUT_JSON = pathlib.Path("exports/ghidra_field_truth_job.json")
DEFAULT_PRIORITY = ["high", "second"]


@dataclass
class SlotTarget:
    crate_index: int
    crate_label: str
    slot: int
    priority: str
    focus_hint: str
    domains: List[str]
    focus_score: int


@dataclass
class JobConfig:
    project_path: str
    script_path: str
    headless_path: str
    additional_args: List[str]


def _read_csv(path: pathlib.Path) -> Iterable[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Required CSV missing: {path}")
    with path.open(newline="", encoding="utf-8") as f:
        yield from csv.DictReader(f)


def load_targets(path: pathlib.Path, priorities: List[str]) -> Dict[int, Dict[str, str]]:
    result: Dict[int, Dict[str, str]] = {}
    priorities_lower = {p.lower() for p in priorities}
    for row in _read_csv(path):
        priority = (row.get("priority", "") or "").lower()
        if priorities_lower and priority not in priorities_lower:
            continue
        try:
            crate_index = int(row.get("crate_index", ""))
        except (TypeError, ValueError):
            continue
        result[crate_index] = row
    return result


def load_slots(path: pathlib.Path, crate_filters: Dict[int, Dict[str, str]]) -> List[SlotTarget]:
    slots: List[SlotTarget] = []
    for row in _read_csv(path):
        try:
            crate_index = int(row.get("crate_index", ""))
            slot = int(row.get("slot", ""))
        except (TypeError, ValueError):
            continue
        if crate_index not in crate_filters:
            continue
        if row.get("observed_psyq_calls") or row.get("observed_slot_notes"):
            continue
        target_row = crate_filters[crate_index]
        priority = (target_row.get("priority", "") or "watch").lower()
        focus_hint = target_row.get("psyq_focus_hint", "")
        focus_score = int(float(target_row.get("score", "0") or 0) * 10)
        domains = []
        for key in ("value_a_domain", "value_b_domain"):
            domain = (row.get(key, "") or "").strip()
            if domain:
                domains.append(domain)
        slots.append(
            SlotTarget(
                crate_index=crate_index,
                crate_label=row.get("crate_label", "") or f"INDEX_{crate_index:02d}",
                slot=slot,
                priority=priority,
                focus_hint=focus_hint,
                domains=domains,
                focus_score=focus_score,
            )
        )
    slots.sort(key=lambda s: (s.priority, -s.focus_score, s.crate_index, s.slot))
    return slots


def build_job(slots: List[SlotTarget], config: JobConfig, limit: Optional[int]) -> Dict[str, object]:
    if limit is not None:
        slots = slots[: limit]
    payload = {
        "project_path": config.project_path,
        "headless_path": config.headless_path,
        "script_path": config.script_path,
        "additional_args": config.additional_args,
        "targets": [
            {
                "crate_index": slot.crate_index,
                "crate_label": slot.crate_label,
                "slot": slot.slot,
                "priority": slot.priority,
                "focus_hint": slot.focus_hint,
                "domains": slot.domains,
                "focus_score": slot.focus_score,
            }
            for slot in slots
        ],
    }
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Ghidra headless job config for field truth")
    parser.add_argument("--sheet", default=str(FIELD_TRUTH_CSV), help="Path to psyq_field_truth_sheet.csv")
    parser.add_argument("--targets", default=str(TARGETS_CSV), help="Path to psyq_trace_targets.csv")
    parser.add_argument("--output", default=str(OUTPUT_JSON), help="Destination JSON path")
    parser.add_argument("--project", required=True, help="Path to the Ghidra project")
    parser.add_argument("--script", required=True, help="Path to the Ghidra script to execute")
    parser.add_argument("--headless", default="/opt/ghidra/support/analyzeHeadless", help="Ghidra headless executable path")
    parser.add_argument("--priorities", nargs="*", default=list(DEFAULT_PRIORITY), help="Priority tiers to include")
    parser.add_argument("--limit", type=int, help="Maximum number of slots to emit")
    parser.add_argument("--extra", nargs=argparse.REMAINDER, default=[], help="Additional args to pass to the script")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    crate_filters = load_targets(pathlib.Path(args.targets), priorities=args.priorities)
    slots = load_slots(pathlib.Path(args.sheet), crate_filters)
    config = JobConfig(
        project_path=args.project,
        script_path=args.script,
        headless_path=args.headless,
        additional_args=args.extra,
    )
    job = build_job(slots, config, args.limit)
    out_path = pathlib.Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(job, indent=2), encoding="utf-8")
    print(f"Wrote {out_path} with {len(job['targets'])} targets")


if __name__ == "__main__":
    main()
