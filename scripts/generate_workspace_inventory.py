#!/usr/bin/env python
"""Generate CSV/Markdown inventories for one or more workspace roots."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

EXT_DESCRIPTIONS: Dict[str, str] = {
    ".py": "Python script for automation or tooling.",
    ".ps1": "PowerShell script.",
    ".txt": "Plain text notes or captured logs.",
    ".md": "Markdown documentation or research log.",
    ".csv": "Comma-separated dataset exported during analysis.",
    ".json": "JSON configuration or structured data.",
    ".yml": "YAML configuration.",
    ".yaml": "YAML configuration.",
    ".bat": "Windows batch helper.",
    ".sh": "Shell helper script.",
    ".cs": "C# source file for Unity/Mono behaviours.",
    ".meta": "Unity metadata asset.",
    ".asset": "Unity serialized asset.",
    ".prefab": "Unity prefab asset.",
    ".mat": "Unity material asset.",
    ".png": "Image resource (PNG).",
    ".jpg": "Image resource (JPEG).",
    ".jpeg": "Image resource (JPEG).",
    ".tga": "Image resource (TGA).",
    ".fbx": "3D model asset (FBX).",
    ".anim": "Unity animation clip.",
    ".controller": "Unity animator controller.",
    ".dll": "Compiled library or plugin.",
    ".so": "Shared library.",
    ".exe": "Executable binary.",
    ".bin": "Binary blob or capture.",
    ".dat": "Generic data payload.",
    ".log": "Log file.",
    ".svg": "Vector graphic.",
    ".xml": "XML configuration or data.",
    ".ini": "INI configuration file.",
    ".cfg": "Configuration file.",
    ".sln": "Visual Studio solution file.",
    ".csproj": "C# project file.",
    ".asm": "Assembly source artifact.",
    ".hpp": "C/C++ header file.",
    ".h": "C/C++ header file.",
    ".c": "C source file.",
    ".cpp": "C++ source file.",
}


def default_description(path: Path) -> str:
    if path.is_dir():
        return "Directory container for nested assets."
    ext = path.suffix.lower()
    if ext in EXT_DESCRIPTIONS:
        return EXT_DESCRIPTIONS[ext]
    if not ext:
        return "Binary or extensionless artifact." if path.is_file() else "Directory container for nested assets."
    return f"File with extension {ext} (auto-classified)."


def gather_entries(root: Path) -> Iterable[Dict[str, object]]:
    for current_root, dirs, files in os.walk(root):
        current = Path(current_root)
        relative_root = current.relative_to(root)
        for directory in sorted(dirs):
            dir_path = current / directory
            rel_path = dir_path.relative_to(root)
            try:
                stat = dir_path.stat()
                modified_iso = dt.datetime.fromtimestamp(stat.st_mtime).isoformat()
            except (OSError, ValueError):
                stat = None
                modified_iso = "unavailable"
            yield {
                "root": str(root),
                "path": str(rel_path) + "\\",  # mark directory
                "type": "directory",
                "size_bytes": 0,
                "modified_iso": modified_iso,
                "description": default_description(dir_path),
            }
        for filename in sorted(files):
            file_path = current / filename
            rel_path = file_path.relative_to(root)
            try:
                stat = file_path.stat()
                size_bytes = stat.st_size
                modified_iso = dt.datetime.fromtimestamp(stat.st_mtime).isoformat()
            except (OSError, ValueError):
                size_bytes = -1
                modified_iso = "unavailable"
            yield {
                "root": str(root),
                "path": str(rel_path),
                "type": file_path.suffix.lower().lstrip(".") or "(none)",
                "size_bytes": size_bytes,
                "modified_iso": modified_iso,
                "description": default_description(file_path),
            }


def write_csv(entries: Iterable[Dict[str, object]], output_path: Path) -> None:
    rows: List[Dict[str, object]] = list(entries)
    if not rows:
        output_path.write_text("root,path,type,size_bytes,modified_iso,description\n", encoding="utf-8")
        return
    fieldnames = ["root", "path", "type", "size_bytes", "modified_iso", "description"]
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(rows: List[Dict[str, object]], output_path: Path) -> None:
    lines: List[str] = []
    lines.append("# Workspace Inventory\n")
    lines.append(f"Generated: {dt.datetime.now().isoformat()}\n")
    lines.append("\n")
    lines.append("This document lists every tracked file and directory collected by `generate_workspace_inventory.py`. For full fidelity, consult the accompanying CSV.\n")
    lines.append("\n")
    totals: Dict[str, int] = {}
    for row in rows:
        root = row["root"]
        totals[root] = totals.get(root, 0) + 1
    lines.append("## Summary\n\n")
    lines.append("| Root | Entries |\n")
    lines.append("| --- | ---: |\n")
    for root, count in sorted(totals.items()):
        lines.append(f"| `{Path(root)}` | {count} |\n")
    lines.append("\n")
    lines.append("## Entries\n\n")
    lines.append("| Root | Path | Type | Size (bytes) | Modified | Description |\n")
    lines.append("| --- | --- | --- | ---: | --- | --- |\n")
    for row in rows:
        lines.append(
            "| {root} | `{path}` | {type} | {size} | {modified} | {description} |\n".format(
                root=f"`{Path(row['root']).name}`",
                path=row["path"].replace("|", "\\|"),
                type=row["type"],
                size=row["size_bytes"],
                modified=row["modified_iso"],
                description=row["description"].replace("|", "\\|"),
            )
        )
    output_path.write_text("".join(lines), encoding="utf-8")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "roots",
        nargs="+",
        type=Path,
        help="Workspace roots to index.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("inventory"),
        help="Directory where inventory files will be written.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also emit a JSON snapshot alongside CSV/Markdown.",
    )
    args = parser.parse_args(argv)

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    rows: List[Dict[str, object]] = []
    for root in args.roots:
        if not root.exists():
            raise SystemExit(f"Root path not found: {root}")
        rows.extend(gather_entries(root))

    csv_path = output_dir / "workspace_inventory.csv"
    markdown_path = output_dir / "workspace_inventory.md"

    write_csv(rows, csv_path)
    write_markdown(rows, markdown_path)

    if args.json:
        json_path = output_dir / "workspace_inventory.json"
        json_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
