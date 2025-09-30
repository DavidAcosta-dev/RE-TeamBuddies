#!/usr/bin/env python3
"""Inspect PROJECTILES.BIN records with annotated offsets.

This complements ``extract_projectile_table.py`` by pretty-printing individual
records (16-bit and/or 32-bit views) while highlighting offsets we have mapped
from the firing pipeline (primarily via ``FUN_000402e0``/``FUN_00040a4c`` and
neighbouring routines).  Use it when you need to correlate a crate payload with
its projectile archetype or when diffing balancing values between missions.

Examples (PowerShell):

    python scripts/dump_projectile_record.py 0 17
    python scripts/dump_projectile_record.py 4 --dwords
    python scripts/dump_projectile_record.py --summary

The ``--summary`` option emits ``exports/projectiles_struct_summary.csv``
covering a curated set of telling offsets for all 82 entries.
"""
from __future__ import annotations

import argparse
import csv
import pathlib
import struct
from typing import Iterable, List, Tuple

PROJECTILES_BIN = pathlib.Path("assets/extracted/BUDDIES.DAT/container_0288/PROJECTILES.BIN")
SUMMARY_CSV = pathlib.Path("exports/projectiles_struct_summary.csv")

WORD_NOTES = {
    0x00: "Archetype ID (ties back to weapon field 0x24 / resource lookups)",
    0x14: "Tracer lifetime? varies across explosive types",
    0x18: "Burst count / loop iterations (mirrors weapon runtime+0x3E)",
    0x1C: "Damage scalar observed in explosive rounds",
    0x20: "0xFFFF sentinel when projectile ignores collision mask",
    0x24: "Initial velocity (signed) along spawn axis",
    0x28: "Asset index A (model/sprite) shared across crate tiers",
    0x2C: "Asset index B (FX or behaviour table entry)",
    0x40: "Homing / behaviour flags",
    0x48: "Gravity delay / fuse ticks",
    0x4C: "Signed X velocity (FFE2 = -30)",
    0x50: "Signed Y velocity",
    0x54: "Signed Z velocity (0x1040 = 0x10 << 6)",
    0x58: "Fuse length (frames)",
    0x5C: "Spawn interval inside burst",
    0x64: "Resource ID A (VFX / sound bank)",
    0x68: "Resource ID B",
    0x6C: "Resource ID C (often matches crate value_b)",
}

DWORD_NOTES = {
    0x00: "Archetype ID (32-bit view)",
    0x18: "Burst count / loop iterations",
    0x1C: "Damage scalar (32-bit view)",
    0x20: "Collision mask (0xFFFF sentinel)",
    0x24: "Initial velocity packed (signed)",
    0x28: "Asset/model index",
    0x2C: "FX/behaviour index",
    0x40: "Behaviour flags",
    0x48: "Gravity delay / fuse ticks",
    0x4C: "Velocity vector (XYZ)",
    0x58: "Fuse & burst timing block",
    0x64: "Resource trio (VFX/SFX entries)",
}


def load_records(path: pathlib.Path) -> Tuple[List[bytes], int]:
    data = path.read_bytes()
    count = struct.unpack_from("<I", data, 0)[0]
    body = data[4:]
    if count == 0:
        raise ValueError("PROJECTILES.BIN reports zero records")
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
    print(f"Wrote summary for {len(records)} projectile records -> {out_path}")


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Inspect PROJECTILES.BIN records in detail")
    ap.add_argument("indices", nargs="*", type=int, help="Record indices to dump")
    ap.add_argument("--words", action="store_true", help="Show the 16-bit field view")
    ap.add_argument("--dwords", action="store_true", help="Show the 32-bit field view")
    ap.add_argument("--summary", action="store_true", help="Emit CSV summary instead of text dump")
    ap.add_argument("--path", default=str(PROJECTILES_BIN), help="Override path to PROJECTILES.BIN")
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
        print(f"== Projectile record {idx} (size={record_size} bytes) ==")
        print(dump_record(blob, record_size, show_words, show_dwords))
        if idx != indices[-1]:
            print()


if __name__ == "__main__":
    main()
