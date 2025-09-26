#!/usr/bin/env python3
"""Categorise PSYQ SDK symbols using MAP source paths as heuristics.

Outputs two CSV reports:
- exports/symbols/sdk_symbol_groups.csv: per-symbol metadata with inferred categories.
- exports/symbols/sdk_symbol_group_counts.csv: aggregate counts per category.
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

RAW_HEADER = ("map_file", "symbol", "address_hex", "annotation")
SUMMARY_HEADER = (
    "symbol",
    "canonical_address_hex",
    "observations",
    "distinct_addresses",
    "map_files",
    "address_histogram",
)

CATEGORY_KEYWORDS: Tuple[Tuple[str, str], ...] = (
    ("graphics", "graphics"),
    ("gte", "graphics"),
    ("gpu", "graphics"),
    ("texture", "graphics"),
    ("sprite", "graphics"),
    ("mesh", "graphics"),
    ("subdiv", "graphics"),
    ("geom", "graphics"),
    ("libgs", "graphics"),
    ("libgte", "graphics"),
    ("sound", "audio"),
    ("spu", "audio"),
    ("snd", "audio"),
    ("libsnd", "audio"),
    ("libspu", "audio"),
    ("music", "audio"),
    ("xm", "audio"),
    ("pad", "input"),
    ("controller", "input"),
    ("libpad", "input"),
    ("memcard", "io"),
    ("libcard", "io"),
    ("card", "io"),
    ("cd", "cdrom"),
    ("stream", "cdrom"),
    ("movie", "cdrom"),
    ("module", "module"),
    ("menu", "ui"),
    ("anim", "ui"),
    ("font", "ui"),
    ("libapi", "kernel"),
    ("libetc", "kernel"),
    ("libsys", "kernel"),
)


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _parse_args() -> argparse.Namespace:
    repo_root = _default_repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--raw",
        type=Path,
        default=repo_root / "exports" / "symbols" / "sdk_map_symbols.csv",
        help="Path to sdk_map_symbols.csv",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=repo_root / "exports" / "symbols" / "sdk_symbol_summary.csv",
        help="Path to sdk_symbol_summary.csv",
    )
    parser.add_argument(
        "--symbol-groups",
        type=Path,
        default=repo_root / "exports" / "symbols" / "sdk_symbol_groups.csv",
        help="Output CSV for per-symbol group data",
    )
    parser.add_argument(
        "--group-counts",
        type=Path,
        default=repo_root / "exports" / "symbols" / "sdk_symbol_group_counts.csv",
        help="Output CSV for aggregated counts per category",
    )
    parser.add_argument(
        "--keywords",
        type=Path,
        default=None,
        help="Optional path to custom keyword definition file (CSV: keyword,category)",
    )
    return parser.parse_args()


def _load_keyword_overrides(path: Path | None) -> Tuple[Tuple[str, str], ...]:
    if path is None:
        return CATEGORY_KEYWORDS
    overrides: List[Tuple[str, str]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 2:
                continue
            overrides.append((row[0].strip().lower(), row[1].strip().lower()))
    return tuple(overrides)


def _load_raw(raw_path: Path) -> Dict[str, List[str]]:
    mapping: Dict[str, List[str]] = defaultdict(list)
    with raw_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = set(RAW_HEADER) - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Raw CSV missing columns: {sorted(missing)}")
        for row in reader:
            symbol = row["symbol"].strip()
            map_path = row["map_file"].strip()
            if not symbol or not map_path:
                continue
            mapping[symbol].append(map_path.lower())
    return mapping


def _load_summary(summary_path: Path) -> Dict[str, Dict[str, str]]:
    summary: Dict[str, Dict[str, str]] = {}
    with summary_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = set(SUMMARY_HEADER) - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Summary CSV missing columns: {sorted(missing)}")
        for row in reader:
            symbol = row["symbol"].strip()
            if not symbol:
                continue
            summary[symbol] = {
                "canonical_address_hex": row["canonical_address_hex"].strip(),
                "observations": row["observations"].strip(),
                "distinct_addresses": row["distinct_addresses"].strip(),
                "map_files": row["map_files"].strip(),
                "address_histogram": row["address_histogram"].strip(),
            }
    return summary


def _infer_categories(map_paths: Sequence[str], keyword_table: Tuple[Tuple[str, str], ...]) -> List[str]:
    categories: set[str] = set()
    for lower_path in map_paths:
        for keyword, category in keyword_table:
            if keyword in lower_path:
                categories.add(category)
    if not categories:
        categories.add("unknown")
    return sorted(categories)


def _write_symbol_groups(
    output_path: Path,
    summary: Dict[str, Dict[str, str]],
    map_paths: Dict[str, List[str]],
    keyword_table: Tuple[Tuple[str, str], ...],
) -> Counter:
    counts: Counter = Counter()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "symbol",
                "canonical_address_hex",
                "observations",
                "distinct_addresses",
                "category_list",
                "map_file_count",
                "example_map_file",
            ]
        )
        for symbol in sorted(summary.keys()):
            categories = _infer_categories(map_paths.get(symbol, []), keyword_table)
            for cat in categories:
                counts[cat] += 1
            example_path = map_paths.get(symbol, [""])[0]
            writer.writerow(
                [
                    symbol,
                    summary[symbol]["canonical_address_hex"],
                    summary[symbol]["observations"],
                    summary[symbol]["distinct_addresses"],
                    ";".join(categories),
                    len(map_paths.get(symbol, [])),
                    example_path,
                ]
            )
    return counts


def _write_group_counts(output_path: Path, counts: Counter) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    total = sum(counts.values())
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["category", "symbol_count", "percentage"])
        for category, count in counts.most_common():
            pct = (count / total) * 100 if total else 0.0
            writer.writerow([category, count, f"{pct:.2f}"])


def main() -> None:
    args = _parse_args()
    if not args.raw.exists():
        raise SystemExit(f"Raw CSV not found: {args.raw}")
    if not args.summary.exists():
        raise SystemExit(f"Summary CSV not found: {args.summary}")

    keywords = _load_keyword_overrides(args.keywords)
    map_paths = _load_raw(args.raw)
    summary = _load_summary(args.summary)
    counts = _write_symbol_groups(args.symbol_groups, summary, map_paths, keywords)
    _write_group_counts(args.group_counts, counts)
    print(
        "Generated symbol group reports -> {0}, {1}".format(
            args.symbol_groups, args.group_counts
        )
    )


if __name__ == "__main__":
    main()
