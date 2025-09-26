#!/usr/bin/env python3
"""Filter sdk_symbol_labels.json by categories for targeted rename passes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, List, Sequence, Set


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _parse_args() -> argparse.Namespace:
    repo_root = _default_repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--labels",
        type=Path,
        default=repo_root / "exports" / "symbols" / "sdk_symbol_labels.json",
        help="Path to the base label JSON",
    )
    parser.add_argument(
        "--include",
        type=str,
        default="",
        help="Comma-separated category list to include (required unless --exclude-only)",
    )
    parser.add_argument(
        "--exclude",
        type=str,
        default="",
        help="Comma-separated category list to exclude",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output path (defaults to <labels>.<categories>.json)",
    )
    return parser.parse_args()


def _split_categories(raw: str) -> Set[str]:
    return {token.strip().lower() for token in raw.split(",") if token.strip()}


def _derive_output(base: Path, categories: Sequence[str]) -> Path:
    if not categories:
        suffix = "filtered"
    else:
        suffix = "+".join(categories)
    target = base.with_suffix(base.suffix + f".{suffix}.json")
    return target


def _filter_records(
    records: Iterable[dict],
    include: Set[str],
    exclude: Set[str],
) -> List[dict]:
    filtered: List[dict] = []
    for record in records:
        categories = {cat.lower() for cat in record.get("categories", []) if cat}
        if include:
            if not categories or categories.isdisjoint(include):
                continue
        if exclude and not categories.isdisjoint(exclude):
            continue
        filtered.append(record)
    return filtered


def main() -> None:
    args = _parse_args()
    if not args.labels.exists():
        raise SystemExit(f"Label JSON not found: {args.labels}")

    include = _split_categories(args.include)
    exclude = _split_categories(args.exclude)
    if not include and not exclude:
        raise SystemExit("Specify at least one category via --include or --exclude")

    with args.labels.open("r", encoding="utf-8") as handle:
        records = json.load(handle)

    filtered = _filter_records(records, include, exclude)
    if not filtered:
        raise SystemExit("No records matched the provided filters")

    categories_for_suffix = sorted(include) if include else sorted(exclude)
    output_path = args.output or _derive_output(args.labels, categories_for_suffix)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(filtered, handle, indent=2)
        handle.write("\n")

    print(
        f"Wrote {len(filtered)} filtered labels -> {output_path}"
    )


if __name__ == "__main__":
    main()
