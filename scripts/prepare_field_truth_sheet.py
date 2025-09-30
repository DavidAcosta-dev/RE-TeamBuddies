#!/usr/bin/env python3
"""Export a field-truth checklist for PSYQ crate tracing sessions."""
from __future__ import annotations

import argparse
import csv
import pathlib
from collections import defaultdict
from typing import Dict, Iterable, List, Mapping, Sequence

TARGETS_CSV = pathlib.Path("exports/psyq_trace_targets.csv")
MATRIX_CSV = pathlib.Path("exports/crate_weapon_projectile_matrix.csv")
OUTPUT_CSV = pathlib.Path("exports/psyq_field_truth_sheet.csv")

DEFAULT_PRIORITIES = ("high", "second")


def read_csv(path: pathlib.Path) -> List[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Required CSV not found: {path}")
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def filter_targets(rows: Iterable[Dict[str, str]], priorities: Sequence[str]) -> List[Dict[str, str]]:
    priorities_lower = {p.lower() for p in priorities}
    results: List[Dict[str, str]] = []
    for row in rows:
        priority = (row.get("priority", "") or "").lower()
        if priorities_lower and priority not in priorities_lower:
            continue
        results.append(row)
    return results


def build_slot_view(matrix_rows: Iterable[Dict[str, str]]) -> Dict[int, Dict[int, Dict[str, str]]]:
    crates: Dict[int, Dict[int, Dict[str, str]]] = defaultdict(dict)
    for row in matrix_rows:
        try:
            crate_index = int(row.get("crate_index", ""))
            slot_index = int(row.get("slot", ""))
        except (TypeError, ValueError):
            continue
        if slot_index not in crates[crate_index]:
            crates[crate_index][slot_index] = row
    return crates


def compose_rows(
    targets: Iterable[Dict[str, str]],
    slot_lookup: Mapping[int, Mapping[int, Dict[str, str]]],
) -> List[Dict[str, str]]:
    output_rows: List[Dict[str, str]] = []
    for target in targets:
        try:
            crate_index = int(target.get("crate_index", ""))
        except (TypeError, ValueError):
            continue
        slots = slot_lookup.get(crate_index, {})
        if not slots:
            continue
        base = {
            "crate_index": crate_index,
            "crate_label": target.get("crate_label", ""),
            "priority": target.get("priority", ""),
            "score": target.get("score", ""),
            "focus_hint": target.get("psyq_focus_hint", ""),
            "combined_total": target.get("combined_total", ""),
            "dominant_domain": target.get("dominant_domain", ""),
            "dominant_domain_hint": target.get("dominant_domain_hint", ""),
        }
        for slot in sorted(slots):
            row = dict(base)
            slot_row = slots[slot]
            row.update(
                {
                    "slot": slot,
                    "value_a": slot_row.get("value_a", ""),
                    "value_a_kind": slot_row.get("value_a_kind", ""),
                    "value_a_domain": slot_row.get("value_a_domain", ""),
                    "value_a_domain_hint": slot_row.get("value_a_domain_hint", ""),
                    "value_a_crossref_total": slot_row.get("value_a_crossref_total", ""),
                    "value_b": slot_row.get("value_b", ""),
                    "value_b_kind": slot_row.get("value_b_kind", ""),
                    "value_b_domain": slot_row.get("value_b_domain", ""),
                    "value_b_domain_hint": slot_row.get("value_b_domain_hint", ""),
                    "value_b_crossref_total": slot_row.get("value_b_crossref_total", ""),
                    "toy_present": slot_row.get("toy_present", ""),
                    "vehicle_present": slot_row.get("vehicle_present", ""),
                    "weapon_matches": slot_row.get("weapon_matches", ""),
                }
            )
            row["observed_psyq_calls"] = ""
            row["observed_slot_notes"] = ""
            output_rows.append(row)
    return output_rows


def write_csv(rows: Sequence[Dict[str, str]], out_path: pathlib.Path) -> None:
    if not rows:
        print("No rows matched the filter; nothing to write.")
        return
    headers = list(rows[0].keys())
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"Wrote {len(rows)} checklist rows -> {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare PSYQ field-truth checklist")
    parser.add_argument("--targets", default=str(TARGETS_CSV), help="Path to psyq_trace_targets.csv")
    parser.add_argument("--matrix", default=str(MATRIX_CSV), help="Path to crate_weapon_projectile_matrix.csv")
    parser.add_argument("--output", default=str(OUTPUT_CSV), help="Destination CSV path")
    parser.add_argument(
        "--priorities",
        nargs="*",
        default=list(DEFAULT_PRIORITIES),
        help="Priority tiers to include (default: high second)",
    )
    args = parser.parse_args()

    target_rows = read_csv(pathlib.Path(args.targets))
    matrix_rows = read_csv(pathlib.Path(args.matrix))

    filtered_targets = filter_targets(target_rows, args.priorities)
    slot_lookup = build_slot_view(matrix_rows)
    output_rows = compose_rows(filtered_targets, slot_lookup)
    write_csv(output_rows, pathlib.Path(args.output))


if __name__ == "__main__":
    main()
