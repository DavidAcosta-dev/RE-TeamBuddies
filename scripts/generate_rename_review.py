#!/usr/bin/env python3
"""
generate_rename_review.py

Emit a CSV of rename candidates with evidence and an `apply` column (0/1).

Inputs:
  - exports/suspects_bookmarks.json
  - exports/rename_checklist.csv (optional; suggested_name + reason)
  - exports/q12_math_candidates.json (for pos/basis evidence)
  - exports/physics_integrator_map.csv (for axes/direct_pos_write)

Output:
  - exports/rename_review.csv with columns:
      binary,function,ea_hex,new_name,suggested_name,reason,
      pos_hits,basis_dest_hits,basis_src_hits,speed_hits,
      integrator,direct_pos_write,axes,weighted_score,apply

Usage:
  python scripts/generate_rename_review.py
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"
BOOK = EXPORTS / "suspects_bookmarks.json"
CHECK = EXPORTS / "rename_checklist.csv"
Q12 = EXPORTS / "q12_math_candidates.json"
INTEG = EXPORTS / "physics_integrator_map.csv"
OUT = EXPORTS / "rename_review.csv"


def load_bookmarks(path: Path) -> dict[str, list[dict]]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_check(path: Path) -> dict[tuple[str, str], dict]:
    if not path.exists():
        return {}
    out: dict[tuple[str, str], dict] = {}
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            out[(row.get("binary"), row.get("function"))] = row
    return out


def load_q12(path: Path) -> dict[str, dict]:
    d = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, dict] = {}
    for e in d.get("candidates", []):
        out[e.get("name")] = e
    return out


def load_integrators(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    out: dict[str, dict] = {}
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            nm = row.get("function")
            if nm:
                out[nm] = row
    return out


def is_generic_name(s: str | None) -> bool:
    if not s:
        return False
    s = s.lower()
    return s.startswith("phys_fun_") or s.startswith("suspect_fun_")


def main() -> None:
    if not (BOOK.exists() and Q12.exists()):
        raise SystemExit("Missing exports; run the generators first.")
    bookmarks = load_bookmarks(BOOK)
    checklist = load_check(CHECK)
    qmap = load_q12(Q12)
    imap = load_integrators(INTEG)

    rows: list[dict] = []
    for bin_name, items in bookmarks.items():
        if not isinstance(items, list):
            continue
        for it in items:
            fn = it.get("name")
            if not fn:
                continue
            q = qmap.get(fn) or {}
            integ = imap.get(fn) or {}
            chk = checklist.get((bin_name, fn)) or {}
            suggested = chk.get("suggested_name") or chk.get("suggested") or it.get("suggested_name") or ""
            reason = chk.get("reason") or ""
            new_name = (it.get("new_name") or "").strip()

            # Only include items that are likely actionable review:
            # - has a suggestion and new_name is empty OR
            # - has a suggestion and new_name is generic placeholder
            if not suggested:
                continue
            if new_name and not is_generic_name(new_name):
                continue

            rows.append({
                "binary": bin_name,
                "function": fn,
                "ea_hex": f"0x{int(it.get('ea', 0)):X}",
                "new_name": new_name,
                "suggested_name": suggested,
                "reason": reason,
                "pos_hits": q.get("pos_hits", 0),
                "basis_dest_hits": q.get("basis_dest_hits", 0),
                "basis_src_hits": q.get("basis_src_hits", 0),
                "speed_hits": q.get("speed_hits", 0),
                "integrator": ("1" if integ else "0"),
                "direct_pos_write": integ.get("direct_pos_write", "0"),
                "axes": integ.get("axes", ""),
                "weighted_score": q.get("weighted_score", 0),
                "apply": "0"
            })

    rows.sort(key=lambda r: (-int(r.get("weighted_score") or 0), r.get("binary"), r.get("function")))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=[
            "binary","function","ea_hex","new_name","suggested_name","reason",
            "pos_hits","basis_dest_hits","basis_src_hits","speed_hits",
            "integrator","direct_pos_write","axes","weighted_score","apply"
        ])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"Wrote {OUT} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
