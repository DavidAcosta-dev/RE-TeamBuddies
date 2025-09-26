#!/usr/bin/env python3
"""Derive high-confidence PSYQ symbol labels for downstream tooling.

Reads the raw MAP export (`sdk_map_symbols.csv`) and the aggregated summary
(`sdk_symbol_summary.csv`), then filters down to symbols that meet observation
thresholds. The resulting JSON is consumed by `ghidra_scripts/ApplySdkSymbols.py`
to seed function names in the Team Buddies binary.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence


@dataclass
class SymbolRecord:
    symbol: str
    address_hex: str
    observations: int
    distinct_addresses: int
    map_files: Sequence[str]
    address_histogram: str
    categories: Sequence[str]


RAW_HEADER = ("map_file", "symbol", "address_hex", "annotation")
SUMMARY_HEADER = (
    "symbol",
    "canonical_address_hex",
    "observations",
    "distinct_addresses",
    "map_files",
    "address_histogram",
)


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _parse_args() -> argparse.Namespace:
    repo_root = _default_repo_root()
    default_raw = repo_root / "exports" / "symbols" / "sdk_map_symbols.csv"
    default_summary = repo_root / "exports" / "symbols" / "sdk_symbol_summary.csv"
    default_groups = repo_root / "exports" / "symbols" / "sdk_symbol_groups.csv"
    default_output = repo_root / "exports" / "symbols" / "sdk_symbol_labels.json"

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, default=default_raw, help="Path to sdk_map_symbols.csv")
    parser.add_argument(
        "--summary", type=Path, default=default_summary, help="Path to sdk_symbol_summary.csv"
    )
    parser.add_argument(
        "--symbol-groups",
        type=Path,
        default=default_groups,
        help="Path to sdk_symbol_groups.csv for category enrichment",
    )
    parser.add_argument(
        "--output", type=Path, default=default_output, help="Output JSON path"
    )
    parser.add_argument(
        "--min-observations",
        type=int,
        default=2,
        help="Require at least this many sightings before emitting a symbol",
    )
    parser.add_argument(
        "--max-distinct-addresses",
        type=int,
        default=1,
        help="Only emit symbols observed at or below this many distinct addresses",
    )
    parser.add_argument(
        "--max-map-files",
        type=int,
        default=20,
        help="Drop symbols referenced in more than N unique MAP files (likely generic sample names)",
    )
    parser.add_argument(
        "--min-address",
        type=lambda value: int(value, 0),
        default=0x80000000,
        help="Ignore canonical addresses below this value (default: 0x80000000)",
    )
    parser.add_argument(
        "--max-address",
        type=lambda value: int(value, 0),
        default=0x8FFFFFFF,
        help="Ignore canonical addresses above this value (default: 0x8FFFFFFF)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional cap on number of symbols (0 = no cap). Useful for quick tests.",
    )
    return parser.parse_args()


def _load_raw(raw_path: Path) -> Dict[str, List[str]]:
    symbol_to_maps: Dict[str, List[str]] = defaultdict(list)
    with raw_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = set(RAW_HEADER) - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Raw CSV missing columns: {sorted(missing)}")
        for row in reader:
            symbol = row["symbol"].strip()
            map_file = row["map_file"].strip()
            if not symbol or not map_file:
                continue
            if map_file not in symbol_to_maps[symbol]:
                symbol_to_maps[symbol].append(map_file)
    return symbol_to_maps


def _load_categories(groups_path: Path) -> Dict[str, Sequence[str]]:
    categories: Dict[str, Sequence[str]] = {}
    with groups_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if "symbol" not in reader.fieldnames or "category_list" not in reader.fieldnames:
            raise ValueError("Symbol groups CSV missing required columns (symbol, category_list)")
        for row in reader:
            symbol = row["symbol"].strip()
            cats = [c.strip() for c in row["category_list"].split(";") if c.strip()]
            categories[symbol] = tuple(cats)
    return categories


def _load_summary(
    summary_path: Path,
    symbol_to_maps: Dict[str, List[str]],
    symbol_to_categories: Dict[str, Sequence[str]],
    *,
    min_observations: int,
    max_distinct_addresses: int,
    max_map_files: int,
    min_address: int,
    max_address: int,
    limit: int,
) -> List[SymbolRecord]:
    records: List[SymbolRecord] = []
    with summary_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = set(SUMMARY_HEADER) - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Summary CSV missing columns: {sorted(missing)}")

        for row in reader:
            observations = int(row["observations"])
            distinct = int(row["distinct_addresses"])
            if observations < min_observations:
                continue
            if distinct > max_distinct_addresses:
                continue
            symbol = row["symbol"].strip()
            map_files = symbol_to_maps.get(symbol, [])
            if max_map_files and len(map_files) > max_map_files:
                continue
            addr_int = int(row["canonical_address_hex"], 16)
            if addr_int < min_address or addr_int > max_address:
                continue
            record = SymbolRecord(
                symbol=symbol,
                address_hex=row["canonical_address_hex"].strip(),
                observations=observations,
                distinct_addresses=distinct,
                map_files=tuple(sorted(map_files)),
                address_histogram=row["address_histogram"].strip(),
                categories=symbol_to_categories.get(symbol, ()),
            )
            records.append(record)
            if limit and len(records) >= limit:
                break
    records.sort(key=lambda rec: int(rec.address_hex, 16))
    return records


def _write_output(output_path: Path, records: Iterable[SymbolRecord]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump([asdict(rec) for rec in records], handle, indent=2)
        handle.write("\n")


def main() -> None:
    args = _parse_args()
    if not args.raw.exists():
        raise SystemExit(f"Raw CSV not found: {args.raw}")
    if not args.summary.exists():
        raise SystemExit(f"Summary CSV not found: {args.summary}")
    if not args.symbol_groups.exists():
        raise SystemExit(f"Symbol groups CSV not found: {args.symbol_groups}")

    symbol_to_maps = _load_raw(args.raw)
    symbol_to_categories = _load_categories(args.symbol_groups)
    records = _load_summary(
        args.summary,
        symbol_to_maps,
        symbol_to_categories,
        min_observations=args.min_observations,
        max_distinct_addresses=args.max_distinct_addresses,
        max_map_files=args.max_map_files,
        min_address=args.min_address,
        max_address=args.max_address,
        limit=args.limit,
    )

    if not records:
        raise SystemExit("No symbols satisfied the provided filters.")

    _write_output(args.output, records)
    print(f"Wrote {len(records)} labels -> {args.output}")


if __name__ == "__main__":
    main()
