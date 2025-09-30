#!/usr/bin/env python3
"""Aggregate crate rows that resolve to VEHICLES.BIN payloads."""
from __future__ import annotations

import argparse
import csv
import pathlib
from collections import defaultdict
from typing import Dict, Iterable, List, Sequence

MATRIX_CSV = pathlib.Path("exports/crate_weapon_projectile_matrix.csv")
OUTPUT_CSV = pathlib.Path("exports/crate_vehicle_payloads.csv")


def load_matrix(path: pathlib.Path) -> List[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(
            f"Crate/weapon matrix not found: {path}. Run join_crate_weapon_projectile.py first."
        )
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def collect_vehicle_rows(rows: Iterable[Dict[str, str]], word_limit: int = 12) -> Sequence[Dict[str, str]]:
    buckets: Dict[int, Dict[str, object]] = {}
    contexts: Dict[int, set[str]] = defaultdict(set)
    for row in rows:
        try:
            vehicle_present = int(row.get("vehicle_present", "0"))
            value_b = int(row.get("value_b", "0"))
        except (TypeError, ValueError):
            continue
        if not vehicle_present:
            continue

        label = row.get("crate_label", "")
        slot = row.get("slot", "?")
        contexts[value_b].add(f"{label}:{slot}")

        vehicle_words: List[int | str] = []
        for idx in range(word_limit):
            key = f"vehicle_w{idx:02d}"
            value = row.get(key, "")
            if value == "":
                vehicle_words.append("")
            else:
                try:
                    vehicle_words.append(int(value))
                except ValueError:
                    vehicle_words.append(value)

        weapon_matches = row.get("weapon_matches", "0")
        try:
            weapon_match_count = int(weapon_matches)
        except ValueError:
            weapon_match_count = 0

        buckets.setdefault(
            value_b,
            {
                "vehicle_index": value_b,
                "vehicle_words": vehicle_words,
                "weapon_match_count": weapon_match_count,
                "weapon_match_kind": set(),
            },
        )

        if weapon_match_count:
            kind = row.get("weapon_match_kind", "")
            if kind:
                buckets[value_b]["weapon_match_kind"].add(kind)

    summary_rows: List[Dict[str, object]] = []
    for vehicle_index in sorted(buckets):
        bucket = buckets[vehicle_index]
        vehicle_words = bucket["vehicle_words"]
        summary: Dict[str, object] = {
            "vehicle_index": vehicle_index,
            "crate_slot_count": len(contexts[vehicle_index]),
            "crate_slots": " | ".join(sorted(contexts[vehicle_index])),
            "weapon_match_count": bucket["weapon_match_count"],
            "weapon_match_kind": ",".join(sorted(bucket["weapon_match_kind"])) if bucket["weapon_match_kind"] else "",
        }
        for idx, value in enumerate(vehicle_words):
            summary[f"vehicle_w{idx:02d}"] = value
        summary_rows.append(summary)
    return summary_rows


def write_summary(rows: Sequence[Dict[str, object]], out_path: pathlib.Path) -> None:
    if not rows:
        print("No vehicle-backed crate rows detected; skipping write.")
        return

    headers = list(rows[0].keys())
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"Wrote {len(rows)} vehicle payload rows -> {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize crate payloads that map to vehicles")
    parser.add_argument("--matrix", default=str(MATRIX_CSV), help="Crate/weapon matrix CSV path")
    parser.add_argument("--output", default=str(OUTPUT_CSV), help="Vehicle payload summary CSV path")
    parser.add_argument("--word-limit", type=int, default=12, help="Number of vehicle halfwords to emit per row")
    args = parser.parse_args()

    matrix_path = pathlib.Path(args.matrix)
    output_path = pathlib.Path(args.output)

    rows = load_matrix(matrix_path)
    summary = collect_vehicle_rows(rows, word_limit=args.word_limit)
    write_summary(summary, output_path)


if __name__ == "__main__":
    main()
