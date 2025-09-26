#!/usr/bin/env python3
"""
generate_mechanics_scoreboard.py

Aggregate existing exports into a concise mechanics mapping scoreboard.
Inputs (if present):
 - exports/mapping_coverage_report.md
 - exports/orientation_completion_report.json
 - exports/crate_completion_report.json
 - exports/physics_integrator_map.md
 - exports/q12_overlay_report.md

Outputs:
 - exports/mechanics_scoreboard.md
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def parse_mapping_coverage(md: str) -> dict:
    total = None
    cat_counts: dict[str, int] = {}
    # total line: Total unique functions (bundled): 2257
    m = re.search(r"Total unique functions.*?:\s*(\d+)", md)
    if m:
        total = int(m.group(1))
    # parse the Category table rows: | category | number | percent |
    table_started = False
    for line in md.splitlines():
        if line.strip().startswith("| Category |"):
            table_started = True
            continue
        if table_started:
            if not line.strip().startswith("|"):
                break
            parts = [p.strip() for p in line.strip("|\n").split("|")]
            if len(parts) >= 3 and parts[0] and parts[1].isdigit():
                cat_counts[parts[0]] = int(parts[1])
    return {"total": total, "categories": cat_counts}


def parse_orientation_completion(payload: str) -> Optional[float]:
    if not payload:
        return None
    try:
        data = json.loads(payload)
        return float(data["summary"]["overall"]["completion_pct"])  # type: ignore[index]
    except Exception:
        return None


def parse_crate_completion(payload: str) -> Optional[float]:
    if not payload:
        return None
    try:
        data = json.loads(payload)
        return float(data.get("completion_pct"))
    except Exception:
        return None


def parse_integrator_map(md: str) -> tuple[int, int]:
    # Count rows and how many are direct pos writers
    rows = 0
    direct = 0
    for line in md.splitlines():
        if line.startswith("|") and "Function" not in line and "---" not in line and line.count("|") >= 6:
            rows += 1
            # Direct pos write column contains 'yes'
            if re.search(r"\|\s*yes\s*\|\s*$", line):
                direct += 1
    return rows, direct


def parse_q12_overlay(md: str) -> dict:
    # Parse bullets under Summary
    # - Total Q12 candidates: 252
    # - Integrator ∩ Orientation: 3
    # - Integrator only: 9
    # - Orientation only: 3
    # - Other Q12-heavy routines: 237
    stats = {"total": None, "int_orient": None, "int_only": None, "orient_only": None, "other": None}
    for line in md.splitlines():
        line = line.strip()
        if line.startswith("- Total Q12 candidates:"):
            stats["total"] = int(re.findall(r"\d+", line)[0])
        elif line.startswith("- Integrator ∩ Orientation:"):
            stats["int_orient"] = int(re.findall(r"\d+", line)[0])
        elif line.startswith("- Integrator only:"):
            stats["int_only"] = int(re.findall(r"\d+", line)[0])
        elif line.startswith("- Orientation only:"):
            stats["orient_only"] = int(re.findall(r"\d+", line)[0])
        elif line.startswith("- Other Q12-heavy routines:"):
            stats["other"] = int(re.findall(r"\d+", line)[0])
    return stats


def render_scoreboard(coverage: dict, orient_pct: Optional[float], crate_pct: Optional[float],
                      integ_rows: int, integ_direct: int, q12_stats: dict) -> str:
    lines: list[str] = []
    lines.append("# Mechanics Mapping Scoreboard")
    lines.append("")
    # Overview
    total = coverage.get("total")
    lines.append("## Overview")
    lines.append("")
    if total:
        lines.append(f"- Total unique functions scanned: {total}")
    cats = coverage.get("categories", {}) or {}
    if cats:
        lines.append("- Subsystem tagging (function counts):")
        for k in sorted(cats.keys()):
            lines.append(f"  - {k}: {cats[k]}")
    lines.append("")

    # Completion by subsystem
    lines.append("## Subsystem completion")
    lines.append("")
    lines.append("| Subsystem | Completion | Notes |")
    lines.append("|---|---:|---|")
    lines.append(f"| Crate system | {crate_pct if crate_pct is not None else '—'}% | State machine and edges mapped; timings pending |")
    lines.append(f"| Orientation | {orient_pct if orient_pct is not None else '—'}% | 3 integrator∩orientation, basis chain surfaced |")
    lines.append("| Physics integrators | — | {}/{} mapped (direct pos writers) |".format(integ_direct, integ_rows))
    if q12_stats.get("total") is not None:
        lines.append("| Q12-heavy pool | — | total: {total}, ∩: {int_orient}, integ-only: {int_only}, orient-only: {orient_only} |".format(
            total=q12_stats.get("total"),
            int_orient=q12_stats.get("int_orient"),
            int_only=q12_stats.get("int_only"),
            orient_only=q12_stats.get("orient_only"),
        ))
    lines.append("")

    # Focus targets
    lines.append("## Priority targets")
    lines.append("")
    lines.append("- Tag/rename the 3 integrator ∩ orientation functions and confirm TbActorState prefix reads/writes.")
    lines.append("- Wire integrator config (gravity/drag/track magnet) into validated callsites.")
    lines.append("- Finish crate timings and enumerate pickup/drop candidates.")
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    coverage_md = read_text(EXPORTS / "mapping_coverage_report.md")
    orient_json = read_text(EXPORTS / "orientation_completion_report.json")
    crate_json = read_text(EXPORTS / "crate_completion_report.json")
    integ_md = read_text(EXPORTS / "physics_integrator_map.md")
    q12_overlay_md = read_text(EXPORTS / "q12_overlay_report.md")

    coverage = parse_mapping_coverage(coverage_md) if coverage_md else {"total": None, "categories": {}}
    orient_pct = parse_orientation_completion(orient_json)
    crate_pct = parse_crate_completion(crate_json)
    integ_rows, integ_direct = parse_integrator_map(integ_md)
    q12_stats = parse_q12_overlay(q12_overlay_md)

    output = render_scoreboard(coverage, orient_pct, crate_pct, integ_rows, integ_direct, q12_stats)
    (EXPORTS / "mechanics_scoreboard.md").write_text(output, encoding="utf-8")
    print("Wrote exports/mechanics_scoreboard.md")


if __name__ == "__main__":
    main()
