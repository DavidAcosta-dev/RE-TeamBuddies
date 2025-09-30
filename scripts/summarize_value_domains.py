#!/usr/bin/env python3
"""Summarize crate value IDs with PSYQ domain hints."""
from __future__ import annotations

import argparse
import csv
import pathlib
from collections import Counter, defaultdict
from typing import Dict, Iterable, Set

CRATE_SUMMARY_CSV = pathlib.Path("exports/crate_contents_summary.csv")
CROSSREF_CSV = pathlib.Path("exports/crate_value_crossrefs.csv")
OUTPUT_CSV = pathlib.Path("exports/crate_value_domain_summary.csv")

TABLE_TO_DOMAIN = {
    "ACTION.BIN": "engine",
    "ATTITUDE.BIN": "ai",
    "BUDDIES.BIN": "ai",
    "PERCEPT.BIN": "ai",
    "POWERUP.BIN": "support",
    "PROJECTILES.BIN": "render",
    "STATICS.BIN": "render",
    "TOYS.BIN": "support",
    "VEHICLES.BIN": "render",
    "WEAPONS.BIN": "combat",
}

DOMAIN_HINT = {
    "ai": "AI behaviour (libgte vectors)",
    "combat": "Combat runtime (libgte/libgpu)",
    "engine": "Core state machines",
    "render": "Rendering & geometry (libgpu/libgte)",
    "support": "Support systems (libspu/libpad)",
    "other": "Unmapped",
}


def load_crate_summary(path: pathlib.Path):
    contexts_a: Dict[int, Set[str]] = defaultdict(set)
    contexts_b: Dict[int, Set[str]] = defaultdict(set)
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                crate_index = int(row["index"])
                value_a = int(row["value_a"])
                value_b = int(row["value_b"])
                slot = int(row.get("slot", "0") or 0)
            except (KeyError, TypeError, ValueError):
                continue
            label = row.get("label", "").strip() or f"INDEX_{crate_index:02d}"
            context = f"{crate_index}:{label}:{slot}"
            contexts_a[value_a].add(context)
            contexts_b[value_b].add(context)
    return contexts_a, contexts_b


def load_crossrefs(path: pathlib.Path) -> Dict[int, Counter[str]]:
    hits: Dict[int, Counter[str]] = defaultdict(Counter)
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                value = int(row["value"])
            except (KeyError, TypeError, ValueError):
                continue
            table = row.get("table", "unknown")
            hits[value][table] += 1
    return hits


def summarize_values(contexts_a, contexts_b, hits: Dict[int, Counter[str]]):
    domain_keys = sorted(DOMAIN_HINT)
    values = sorted(set(hits.keys()) | set(contexts_a.keys()) | set(contexts_b.keys()))
    rows = []
    for value in values:
        tables = hits.get(value, Counter())
        domains = Counter()
        for table, count in tables.items():
            domain = TABLE_TO_DOMAIN.get(table, "other")
            domains[domain] += count

        total_hits = sum(tables.values())
        kind_flags = []
        contexts = []
        if value in contexts_a:
            kind_flags.append("value_a")
            contexts.extend(contexts_a[value])
        if value in contexts_b:
            kind_flags.append("value_b")
            contexts.extend(contexts_b[value])
        kind = "+".join(kind_flags) if kind_flags else "unknown"

        dominant_domain = ""
        dominant_hint = ""
        if domains:
            dominant_domain, _ = domains.most_common(1)[0]
            dominant_hint = DOMAIN_HINT.get(dominant_domain, "")

        row = {
            "value": value,
            "kind": kind,
            "total_hits": total_hits,
            "dominant_domain": dominant_domain,
            "dominant_domain_hint": dominant_hint,
            "crate_slot_count": len(set(contexts)),
            "crate_slots": " | ".join(sorted(set(contexts))),
        }
        for table, count in tables.items():
            row[f"table_{table}"] = count
        for domain in domain_keys:
            row[f"domain_{domain}"] = domains.get(domain, 0)
        rows.append(row)
    return rows


def write_rows(rows, out_path: pathlib.Path):
    if not rows:
        print("No values to summarize; skipping write.")
        return
    # Collect all keys to ensure consistent header ordering.
    header_keys = [
        "value",
        "kind",
        "total_hits",
        "dominant_domain",
        "dominant_domain_hint",
        "crate_slot_count",
        "crate_slots",
    ]
    extra_keys = sorted({key for row in rows for key in row.keys() if key not in header_keys})
    headers = header_keys + extra_keys

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"Wrote {len(rows)} value domain rows -> {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize crate value domains")
    parser.add_argument("--crate-summary", default=str(CRATE_SUMMARY_CSV))
    parser.add_argument("--crossref", default=str(CROSSREF_CSV))
    parser.add_argument("--output", default=str(OUTPUT_CSV))
    args = parser.parse_args()

    crate_summary_path = pathlib.Path(args.crate_summary)
    crossref_path = pathlib.Path(args.crossref)
    output_path = pathlib.Path(args.output)

    contexts_a, contexts_b = load_crate_summary(crate_summary_path)
    hits = load_crossrefs(crossref_path)
    rows = summarize_values(contexts_a, contexts_b, hits)
    write_rows(rows, output_path)


if __name__ == "__main__":
    main()
