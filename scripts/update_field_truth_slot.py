#!/usr/bin/env python3
"""Update a crate slot entry in psyq_field_truth_sheet.csv."""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import pathlib
from typing import Dict, Iterable, List, Optional, Tuple

FIELD_TRUTH_CSV = pathlib.Path("exports/psyq_field_truth_sheet.csv")
BACKUP_DIR = pathlib.Path("exports/.field_truth_backups")

OBSERVED_CALLS_FIELD = "observed_psyq_calls"
OBSERVED_NOTES_FIELD = "observed_slot_notes"
STATUS_FIELD = "observed_status"
TIMESTAMP_FIELD = "observed_timestamp"
OBSERVER_FIELD = "observed_by"


def _read_rows(path: pathlib.Path) -> Tuple[List[Dict[str, str]], List[str]]:
    if not path.exists():
        raise FileNotFoundError(
            f"Field truth sheet not found: {path}. Run prepare_field_truth_sheet.py first."
        )
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = list(reader.fieldnames or [])
    return rows, fieldnames


def _ensure_fields(fieldnames: Iterable[str]) -> List[str]:
    mutable = list(fieldnames)
    for column in (STATUS_FIELD, TIMESTAMP_FIELD, OBSERVER_FIELD):
        if column not in mutable:
            mutable.append(column)
    return mutable


def _write_backup(path: pathlib.Path) -> pathlib.Path:
    timestamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup_path = BACKUP_DIR / f"{path.name}.{timestamp}.bak"
    backup_path.write_bytes(path.read_bytes())
    return backup_path


def update_slot(
    rows: List[Dict[str, str]],
    crate_index: int,
    slot_index: int,
    calls: Optional[str],
    notes: Optional[str],
    append: bool,
    status: Optional[str],
    observer: Optional[str],
    timestamp: Optional[str],
) -> bool:
    updated = False
    for row in rows:
        try:
            row_crate = int(row.get("crate_index", ""))
            row_slot = int(row.get("slot", ""))
        except (TypeError, ValueError):
            continue
        if row_crate != crate_index or row_slot != slot_index:
            continue

        if calls is not None:
            existing = row.get(OBSERVED_CALLS_FIELD, "").strip()
            row[OBSERVED_CALLS_FIELD] = f"{existing}; {calls}".strip("; ") if append and existing else calls
        if notes is not None:
            existing_notes = row.get(OBSERVED_NOTES_FIELD, "").strip()
            row[OBSERVED_NOTES_FIELD] = (
                f"{existing_notes}\n{notes}".strip()
                if append and existing_notes
                else notes
            )
        if status is not None:
            row[STATUS_FIELD] = status
        if observer is not None:
            row[OBSERVER_FIELD] = observer
        if timestamp is not None:
            row[TIMESTAMP_FIELD] = timestamp
        else:
            row.setdefault(TIMESTAMP_FIELD, _dt.datetime.now().isoformat(timespec="seconds"))
        updated = True
    return updated


def write_rows(path: pathlib.Path, fieldnames: List[str], rows: List[Dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update a PSYQ field-truth sheet slot entry")
    parser.add_argument("--crate", type=int, required=True, help="Crate index")
    parser.add_argument("--slot", type=int, required=True, help="Slot index (0-5)")
    parser.add_argument("--sheet", default=str(FIELD_TRUTH_CSV), help="Path to psyq_field_truth_sheet.csv")
    parser.add_argument("--calls", help="Observed PSYQ calls (semicolon-separated)")
    parser.add_argument("--notes", help="Observation notes")
    parser.add_argument("--status", help="Verification status (e.g. verified, partial, mismatch)")
    parser.add_argument("--observer", help="Name or initials of the observer")
    parser.add_argument(
        "--timestamp",
        help="Override timestamp (ISO-8601). Defaults to now if omitted",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to existing calls/notes instead of replacing",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show the changes without writing back to the CSV",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    sheet_path = pathlib.Path(args.sheet)
    rows, fieldnames = _read_rows(sheet_path)
    fieldnames = _ensure_fields(fieldnames)

    did_update = update_slot(
        rows=rows,
        crate_index=args.crate,
        slot_index=args.slot,
        calls=args.calls,
        notes=args.notes,
        append=args.append,
        status=args.status,
        observer=args.observer,
        timestamp=args.timestamp,
    )

    if not did_update:
        raise SystemExit(f"Crate {args.crate} slot {args.slot} not found in {sheet_path}")

    if args.dry_run:
        print("Dry run: skipping write. Use without --dry-run to apply changes.")
        return

    backup_path = _write_backup(sheet_path)
    write_rows(sheet_path, fieldnames, rows)
    print(f"Updated crate {args.crate} slot {args.slot}. Backup -> {backup_path}")


if __name__ == "__main__":
    main()
