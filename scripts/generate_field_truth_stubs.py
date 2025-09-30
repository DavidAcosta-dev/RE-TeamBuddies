#!/usr/bin/env python3
"""Convert FieldTruthTracer logs into stubbed reconstructed source files.

The script walks the FieldTruth log directory, extracts symbol hits (keywords or
fallback entries), and emits skeleton translation units under
`reconstructed_src/field_truth/`. Each stub records the originating crate/slot
metadata to keep the trace evidence close to the reconstructed routine.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_DIR = REPO_ROOT / "exports" / "field_truth_logs"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "reconstructed_src" / "field_truth"
ENTRY_RE = re.compile(
    r"^(?P<name>.+?)\s*@\s*(?P<address>[^\s:]+)\s*::\s*refs=(?P<refs>\d+)\s*::\s*origin=(?P<origin>.+?)\s*$"
)


@dataclass
class Candidate:
    name: str
    address: str
    refs: int
    origin: str
    source_log: Path
    section: str
    crate: int
    slot: int
    priority: str
    focus_hint: str
    domains: str
    focus_score: int


def parse_log(path: Path) -> List[Candidate]:
    lines = path.read_text(encoding="utf-8").splitlines()
    metadata = {
        "crate": 0,
        "slot": 0,
        "priority": "",
        "focus_hint": "",
        "domains": "",
        "focus_score": 0,
    }
    candidates: List[Candidate] = []
    section: str | None = "matches"
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("Field Truth Trace Log"):
            continue
        if line.startswith("crate="):
            try:
                parts = line.split(",")
                for part in parts:
                    key, value = part.strip().split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    if key == "crate":
                        metadata["crate"] = int(value)
                    elif key == "slot":
                        metadata["slot"] = int(value)
                    elif key == "priority":
                        metadata["priority"] = value
                    elif key == "focus_score":
                        metadata["focus_score"] = int(value)
            except ValueError:
                pass
            continue
        if line.startswith("focus_hint="):
            metadata["focus_hint"] = line.split("=", 1)[1]
            continue
        if line.startswith("domains="):
            metadata["domains"] = line.split("=", 1)[1]
            continue
        if line.startswith("matches="):
            continue
        if line.startswith("fallback"):
            continue
        if line == "No keyword matches found.":
            section = None
            continue
        if line.startswith("Top referenced symbols"):
            section = "fallback"
            continue
        match = ENTRY_RE.match(line)
        if match and section:
            try:
                refs = int(match.group("refs"))
            except ValueError:
                refs = 0
            candidates.append(
                Candidate(
                    name=match.group("name").strip(),
                    address=match.group("address").strip(),
                    refs=refs,
                    origin=match.group("origin").strip(),
                    source_log=path.relative_to(REPO_ROOT),
                    section=section,
                    crate=int(metadata.get("crate", 0)),
                    slot=int(metadata.get("slot", 0)),
                    priority=str(metadata.get("priority", "")),
                    focus_hint=str(metadata.get("focus_hint", "")),
                    domains=str(metadata.get("domains", "")),
                    focus_score=int(metadata.get("focus_score", 0)),
                )
            )
    return candidates


def sanitize_identifier(name: str) -> str:
    candidate = re.sub(r"[^A-Za-z0-9_]", "_", name.strip())
    if not candidate:
        candidate = "func"
    if candidate[0].isdigit():
        candidate = f"f_{candidate}"
    return candidate


def sanitize_filename(address: str, identifier: str) -> str:
    base = re.sub(r"[^0-9a-zA-Z_]+", "_", address.strip().lower())
    if not base:
        base = "addr"
    ident = sanitize_identifier(identifier).lower()
    return f"{base}_{ident}.c"


def build_stub(candidate: Candidate, timestamp: str) -> str:
    header_lines = [
        "/*",
        f" * Auto-generated from FieldTruth log: {candidate.source_log}",
        f" * Crate {candidate.crate}, Slot {candidate.slot}, Priority {candidate.priority}",
        f" * Focus score {candidate.focus_score} :: {candidate.focus_hint}",
        f" * Domains: {candidate.domains}",
        f" * Extraction section: {candidate.section} (refs={candidate.refs}, origin={candidate.origin})",
        f" * Generated on {timestamp}",
        " */",
    ]
    identifier = sanitize_identifier(candidate.name)
    body_lines = [
        "#include <stdint.h>",
        "",
        f"void {identifier}(void)",
        "{",
        "    // TODO: Translate from original binary using trace evidence.",
        f"    // Address: {candidate.address}",
        "}",
        "",
    ]
    return "\n".join(header_lines + body_lines)


def emit_stubs(
    candidates: Iterable[Candidate],
    output_dir: Path,
    *,
    overwrite: bool,
    max_per_log: int | None,
) -> List[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    emitted: List[Path] = []
    timestamp = _dt.datetime.now(_dt.timezone.utc).isoformat()

    by_log: Dict[Path, List[Candidate]] = {}
    for candidate in candidates:
        by_log.setdefault(candidate.source_log, []).append(candidate)

    seen_keys = set()
    for log_path, items in by_log.items():
        if max_per_log is not None:
            items = items[:max_per_log]
        for candidate in items:
            key = (candidate.address, candidate.name)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            identifier = sanitize_identifier(candidate.name)
            filename = sanitize_filename(candidate.address, identifier)
            stub_path = output_dir / filename
            if stub_path.exists() and not overwrite:
                continue
            content = build_stub(candidate, timestamp)
            stub_path.write_text(content, encoding="utf-8")
            emitted.append(stub_path.relative_to(REPO_ROOT))
    return emitted


def walk_logs(log_dir: Path) -> List[Candidate]:
    collected: List[Candidate] = []
    for path in sorted(log_dir.glob("*.log")):
        collected.extend(parse_log(path))
    return collected


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate reconstructed stubs from FieldTruth logs")
    parser.add_argument("--log-dir", default=str(DEFAULT_LOG_DIR), help="Directory containing FieldTruth log files")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Destination directory for generated stubs")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing stub files")
    parser.add_argument("--max-per-log", type=int, help="Limit number of stubs generated per log")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    log_dir = Path(args.log_dir)
    if not log_dir.is_absolute():
        log_dir = REPO_ROOT / log_dir
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = REPO_ROOT / output_dir

    candidates = walk_logs(log_dir)
    if not candidates:
        print("No candidates found in FieldTruth logs.")
        return

    emitted = emit_stubs(
        candidates,
        output_dir,
        overwrite=args.overwrite,
        max_per_log=args.max_per_log,
    )
    if not emitted:
        print("No new stubs generated (candidates may already exist or logs were empty).")
    else:
        for path in emitted:
            print(f"Generated {path}")


if __name__ == "__main__":
    main()
