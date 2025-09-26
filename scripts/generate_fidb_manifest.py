#!/usr/bin/env python3
"""Generate manifest and inventory reports for PSYQ static libraries.

The manifest produced here feeds the Ghidra Function ID generation pipeline.
It enumerates selected ``.LIB`` archives from the PSYQ SDK and persists their
relative paths for deterministic reuse. A richer inventory log is also emitted
so future audits can track changes to the SDK payloads.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
from pathlib import Path
from typing import Iterable, List, Set


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _parse_args() -> argparse.Namespace:
    repo_root = _default_repo_root()
    default_sdk = repo_root / "assets" / "PSYQ_SDK"
    default_manifest = repo_root / "scripts" / "data" / "fidb_libs.txt"
    default_inventory = repo_root / "scripts" / "logs" / "fidb_lib_inventory.txt"

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sdk-root",
        type=Path,
        default=default_sdk,
        help="Path to the PSYQ SDK root (default: %(default)s)",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=default_manifest,
        help="Output path for the manifest file (default: %(default)s)",
    )
    parser.add_argument(
        "--inventory-log",
        type=Path,
        default=default_inventory,
        help="Output path for the inventory log (default: %(default)s)",
    )
    parser.add_argument(
        "--include-patches",
        action="store_true",
        help="Include psyq/psx/lib/patches/*.lib in addition to core runtime libs.",
    )
    parser.add_argument(
        "--extra-glob",
        action="append",
        default=[],
        help="Additional glob pattern(s) relative to --sdk-root to include.",
    )
    parser.add_argument(
        "--all-libs",
        action="store_true",
        help="Shortcut to include every *.lib under the SDK root.",
    )
    return parser.parse_args()


def _collect_libs(
    sdk_root: Path, *, include_patches: bool, extra_globs: Iterable[str], all_libs: bool
) -> List[Path]:
    if not sdk_root.exists():
        raise FileNotFoundError(f"SDK root does not exist: {sdk_root}")

    patterns: List[str]
    if all_libs:
        patterns = ["**/*.lib"]
    else:
        patterns = [
            "psyq/lib/*.lib",
            "psyq/psx/lib/*.lib",
        ]
        if include_patches:
            patterns.append("psyq/psx/lib/patches/*.lib")
        patterns.extend(extra_globs)

    libs: Set[Path] = set()
    for pattern in patterns:
        libs.update(sdk_root.glob(pattern))

    return sorted(path.resolve() for path in libs if path.is_file())


def _write_manifest(repo_root: Path, manifest_path: Path, libs: Iterable[Path]) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", encoding="utf-8", newline="\n") as fh:
        for lib in libs:
            rel = lib.relative_to(repo_root)
            fh.write(rel.as_posix())
            fh.write("\n")


def _write_inventory(
    repo_root: Path, inventory_path: Path, libs: Iterable[Path]
) -> None:
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    header = "repo_relative_path,size_bytes,modified_iso"
    lines = [header]
    for lib in libs:
        rel = lib.relative_to(repo_root)
        stat = lib.stat()
        mtime = dt.datetime.fromtimestamp(stat.st_mtime, tz=dt.timezone.utc)
        lines.append(
            f"{rel.as_posix()},{stat.st_size},{mtime.isoformat()}"
        )
    inventory_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    args = _parse_args()
    repo_root = _default_repo_root()
    libs = _collect_libs(
        args.sdk_root,
        include_patches=args.include_patches,
        extra_globs=args.extra_glob,
        all_libs=args.all_libs,
    )

    if not libs:
        raise SystemExit("No libraries found with the supplied filters.")

    _write_manifest(repo_root, args.manifest, libs)
    _write_inventory(repo_root, args.inventory_log, libs)

    manifest_rel = args.manifest.relative_to(repo_root)
    inventory_rel = args.inventory_log.relative_to(repo_root)
    print(
        f"Indexed {len(libs)} libraries.\n"
        f"Manifest written to   {manifest_rel.as_posix()}\n"
        f"Inventory log written to {inventory_rel.as_posix()}"
    )


if __name__ == "__main__":
    main()
