#!/usr/bin/env python3
"""Pretty-print decoded WEAPONS.BIN records for deep-dive analysis.

This helper complements ``extract_weapon_table.py`` by emitting both 16-bit and
32-bit interpretations of a weapon record, alongside field annotations pulled
from the loader routines (FUN_000402e0 / FUN_0004033c) we identified in the
Ghidra export.

Usage examples (PowerShell):

    python scripts/dump_weapon_record.py 17
    python scripts/dump_weapon_record.py 3 17 50 --words --dwords
    python scripts/dump_weapon_record.py --summary

When ``--summary`` is selected we generate ``exports/weapons_struct_summary.csv``
covering a curated subset of interesting offsets for every record.
"""
from __future__ import annotations

import argparse
import csv
import pathlib
import struct
from typing import Dict, Iterable, List, Tuple

WEAPONS_BIN = pathlib.Path("assets/extracted/BUDDIES.DAT/container_0288/WEAPONS.BIN")
SUMMARY_CSV = pathlib.Path("exports/weapons_struct_summary.csv")

WORD_NOTES = {
    0x00: "tier/group marker (shared across upgrades)",
    0x04: "crate pairing hint (maps across variants)",
    0x0C: "runtime cooldown? copied during FUN_00040A4C",
    0x0E: "spread/angle scalar read in FUN_00040A4C",
    0x1C: "copied to runtime+0x10 (appears in fire loop)",
    0x20: "copied to runtime+0x08 (likely ammo per shot)",
    0x24: "copied to runtime+0x16 (burst delay?)",
    0x3C: "copied to runtime+0x3C (projectile count)",
    0x3E: "copied to runtime+0x3E (loop count in FUN_00040A4C)",
    0x40: "height offset << 6 (recoil / aim pitch)",
    0x4C: "range segment A (runtime+0x3C)",
    0x50: "range segment B (runtime+0x3E)",
    0x58: "camera kick scalar (shifted by <<6)",
    0x5C: "cooldown ticks (runtime+0x50)",
}

DWORD_NOTES = {
    0x18: "flag bit#1 source (non-zero enables alt fire)",
    0x28: "runtime+0x18 (projectile spawn struct ptr)",
    0x2C: "runtime+0x20 (projectile params ptr)",
    0x30: "crate value_b candidate (matches crate tables)",
    0x34: "paired crate/upgrade id (second stage)",
    0x38: "resource[0] copied to runtime+0x24",
    0x3C: "resource[1]; non-zero toggles flag bit#2",
    0x40: "resource[2] (projectile FX?)",
    0x44: "resource[3]",
    0x48: "resource[4]",
    0x54: "runtime+0x54 (post-fire callback ptr)",
    0x60: "runtime+0x54 tail pointer (cleanup handler)",
}


def load_records(path: pathlib.Path) -> Tuple[List[bytes], int]:
    data = path.read_bytes()
    count = struct.unpack_from("<I", data, 0)[0]
    body = data[4:]
    if count == 0:
        raise ValueError("WEAPONS.BIN reports zero records")
    record_size = len(body) // count
    records = [body[i * record_size : (i + 1) * record_size] for i in range(count)]
    return records, record_size


def format_word(offset: int, value: int) -> str:
    signed = value if value < 0x8000 else value - 0x10000
    note = WORD_NOTES.get(offset)
    base = f"  0x{offset:02X}: 0x{value:04X} (u={value:5d}, s={signed:6d})"
    return f"{base}  # {note}" if note else base


def format_dword(offset: int, value: int) -> str:
    signed = value if value < 0x80000000 else value - 0x100000000
    note = DWORD_NOTES.get(offset)
    base = f"  0x{offset:02X}: 0x{value:08X} (u={value:6d}, s={signed:11d})"
    return f"{base}  # {note}" if note else base


def dump_record(blob: bytes, record_size: int, show_words: bool, show_dwords: bool) -> str:
    lines: List[str] = []
    if show_words:
        lines.append("Words (16-bit little-endian):")
        for offset in range(0, record_size, 2):
            value = struct.unpack_from("<H", blob, offset)[0]
            lines.append(format_word(offset, value))
        lines.append("")
    if show_dwords:
        lines.append("Dwords (32-bit little-endian):")
        for offset in range(0, record_size, 4):
            value = struct.unpack_from("<I", blob, offset)[0]
            lines.append(format_dword(offset, value))
        lines.append("")
    return "\n".join(lines).rstrip()


def emit_summary(records: Iterable[bytes], record_size: int, out_path: pathlib.Path) -> None:
    interesting_words = sorted(set(WORD_NOTES.keys()) & set(range(0, record_size, 2)))
    interesting_dwords = sorted(set(DWORD_NOTES.keys()) & set(range(0, record_size, 4)))

    headers = ["index"]
    headers.extend(f"w_0x{off:02X}" for off in interesting_words)
    headers.extend(f"d_0x{off:02X}" for off in interesting_dwords)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for idx, blob in enumerate(records):
            row: List[int] = [idx]
            for off in interesting_words:
                row.append(struct.unpack_from("<H", blob, off)[0])
            for off in interesting_dwords:
                row.append(struct.unpack_from("<I", blob, off)[0])
            writer.writerow(row)
    print(f"Wrote summary for {len(records)} weapon records -> {out_path}")


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Inspect WEAPONS.BIN records in detail")
    ap.add_argument("indices", nargs="*", type=int, help="Record indices to dump")
    ap.add_argument("--words", action="store_true", help="Show the 16-bit field view")
    ap.add_argument("--dwords", action="store_true", help="Show the 32-bit field view")
    ap.add_argument("--summary", action="store_true", help="Emit CSV summary instead of text dump")
    ap.add_argument("--path", default=str(WEAPONS_BIN), help="Override path to WEAPONS.BIN")
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    records, record_size = load_records(pathlib.Path(args.path))

    indices = args.indices if args.indices else [0]
    show_words = args.words or (not args.dwords and not args.summary)
    show_dwords = args.dwords or (not args.words and not args.summary)

    if args.summary:
        emit_summary(records, record_size, SUMMARY_CSV)
        return

    for idx in indices:
        if idx < 0 or idx >= len(records):
            print(f"Index {idx} out of range (0..{len(records)-1})")
            continue
        blob = records[idx]
        print(f"== Weapon record {idx} (size={record_size} bytes) ==")
        print(dump_record(blob, record_size, show_words, show_dwords))
        if idx != indices[-1]:
            print()


if __name__ == "__main__":
    main()
