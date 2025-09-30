#!/usr/bin/env python3
"""Aggregate FieldTruthTracer hits into a CSV for downstream analysis."""
from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_DIR = REPO_ROOT / "exports" / "field_truth_logs"
DEFAULT_OUTPUT_CSV = REPO_ROOT / "exports" / "field_truth_hits.csv"
ENTRY_RE = re.compile(
    r"^(?P<name>.+?)\s*@\s*(?P<address>[^\s:]+)\s*::\s*refs=(?P<refs>\d+)\s*::\s*origin=(?P<origin>.+?)\s*$"
)


@dataclass
class Hit:
    crate: int
    slot: int
    crate_label: str
    priority: str
    focus_score: int
    focus_hint: str
    domains: str
    section: str
    name: str
    address: str
    refs: int
    origin: str
    log_path: Path


def parse_log(path: Path) -> List[Hit]:
    crate = 0
    slot = 0
    crate_label = ""
    priority = ""
    focus_score = 0
    focus_hint = ""
    domains = ""
    section = "matches"
    hits: List[Hit] = []

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("crate="):
            parts = line.split(",")
            for part in parts:
                key, _, value = part.partition("=")
                key = key.strip()
                value = value.strip()
                if key == "crate":
                    try:
                        crate = int(value)
                    except ValueError:
                        crate = 0
                elif key == "slot":
                    try:
                        slot = int(value)
                    except ValueError:
                        slot = 0
                elif key == "priority":
                    priority = value
                elif key == "focus_score":
                    try:
                        focus_score = int(value)
                    except ValueError:
                        focus_score = 0
            continue
        if line.startswith("focus_hint="):
            focus_hint = line.split("=", 1)[1]
            continue
        if line.startswith("crate_label="):
            crate_label = line.split("=", 1)[1]
            continue
        if line.startswith("domains="):
            domains = line.split("=", 1)[1]
            continue
        if line.startswith("matches="):
            section = "matches"
            continue
        if line.startswith("Top referenced symbols"):
            section = "fallback"
            continue
        if line == "No keyword matches found.":
            section = "fallback"
            continue
        match = ENTRY_RE.match(line)
        if not match:
            continue
        try:
            refs = int(match.group("refs"))
        except ValueError:
            refs = 0
        hits.append(
            Hit(
                crate=crate,
                slot=slot,
                crate_label=crate_label,
                priority=priority,
                focus_score=focus_score,
                focus_hint=focus_hint,
                domains=domains,
                section=section,
                name=match.group("name").strip(),
                address=match.group("address").strip(),
                refs=refs,
                origin=match.group("origin").strip(),
                log_path=path.relative_to(REPO_ROOT),
            )
        )
    return hits


def collect_hits(log_dir: Path) -> List[Hit]:
    hits: List[Hit] = []
    for path in sorted(log_dir.glob("*.log")):
        hits.extend(parse_log(path))
    return hits


def write_csv(hits: Iterable[Hit], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "crate",
        "slot",
        "crate_label",
        "priority",
        "focus_score",
        "focus_hint",
        "domains",
        "section",
        "name",
        "address",
        "refs",
        "origin",
        "log_path",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for hit in hits:
            writer.writerow({
                "crate": hit.crate,
                "slot": hit.slot,
                "crate_label": hit.crate_label,
                "priority": hit.priority,
                "focus_score": hit.focus_score,
                "focus_hint": hit.focus_hint,
                "domains": hit.domains,
                "section": hit.section,
                "name": hit.name,
                "address": hit.address,
                "refs": hit.refs,
                "origin": hit.origin,
                "log_path": str(hit.log_path).replace("\\", "/"),
            })


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect FieldTruthTracer hits into CSV")
    parser.add_argument("--log-dir", default=str(DEFAULT_LOG_DIR), help="Directory containing FieldTruth logs")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_CSV), help="CSV path to write")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    log_dir = Path(args.log_dir)
    hits = collect_hits(log_dir)
    output_path = Path(args.output)
    write_csv(hits, output_path)
    print(f"Wrote {output_path} with {len(hits)} entries")


if __name__ == "__main__":
    main()
