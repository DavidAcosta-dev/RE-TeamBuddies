#!/usr/bin/env python3
"""Interactive helper to inspect crate payload entries."""
from __future__ import annotations

import argparse
import csv
import pathlib
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional

MATRIX_CSV = pathlib.Path("exports/crate_weapon_projectile_matrix.csv")
PIVOT_CSV = pathlib.Path("exports/crate_domain_pivot.csv")
CROSSREF_CSV = pathlib.Path("exports/crate_crossref_summary.csv")
TARGETS_CSV = pathlib.Path("exports/psyq_trace_targets.csv")

_DOMAINS = ("ai", "combat", "engine", "render", "support")
_DOMAIN_FOCUS = {
    "ai": "libgte vector routines",
    "combat": "libgte/libgpu combat loops",
    "engine": "state-machine scheduler",
    "render": "libgpu geometry + libgte transforms",
    "support": "libspu/libpad support systems",
}


@dataclass
class CrateSummary:
    crate_index: int
    label: str
    combined_total: int
    dominant_domain: str
    dominant_hint: str
    domain_counts: Mapping[str, int]
    priority: str = ""
    score: str = ""
    focus_hint: str = ""


@dataclass
class SlotGroup:
    slot: int
    row: Dict[str, str]
    weapons: List[Dict[str, str]]
    domain_counts: Mapping[str, int]


def load_matrix(path: pathlib.Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def filter_rows(rows: List[Dict[str, str]], crate: int | None, slot: int | None) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    for row in rows:
        try:
            crate_index = int(row.get("crate_index", ""))
            slot_index = int(row.get("slot", ""))
        except (TypeError, ValueError):
            continue
        if crate is not None and crate_index != crate:
            continue
        if slot is not None and slot_index != slot:
            continue
        results.append(row)
    return results


def _read_csv(path: pathlib.Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_targets(path: pathlib.Path) -> Dict[int, Dict[str, str]]:
    if not path.exists():
        return {}
    rows = _read_csv(path)
    result: Dict[int, Dict[str, str]] = {}
    for row in rows:
        try:
            crate_index = int(row.get("crate_index", ""))
        except (TypeError, ValueError):
            continue
        result[crate_index] = row
    return result


def load_pivot(path: pathlib.Path) -> Dict[int, Dict[str, str]]:
    if not path.exists():
        return {}
    rows = _read_csv(path)
    data: Dict[int, Dict[str, str]] = {}
    for row in rows:
        try:
            crate_index = int(row.get("crate_index", ""))
        except (TypeError, ValueError):
            continue
        data[crate_index] = row
    return data


def load_crossref(path: pathlib.Path) -> Dict[int, Dict[str, str]]:
    if not path.exists():
        return {}
    rows = _read_csv(path)
    data: Dict[int, Dict[str, str]] = {}
    for row in rows:
        try:
            crate_index = int(row.get("crate_index", ""))
        except (TypeError, ValueError):
            continue
        data[crate_index] = row
    return data


def _ranked_domains(domain_counts: Mapping[str, int]) -> List[tuple[str, int]]:
    ranked = sorted(
        ((domain, domain_counts.get(domain, 0)) for domain in _DOMAINS),
        key=lambda item: (item[1], item[0]),
        reverse=True,
    )
    return [item for item in ranked if item[1] > 0]


def _focus_from_counts(domain_counts: Mapping[str, int]) -> str:
    ranked = _ranked_domains(domain_counts)
    if not ranked:
        return ""
    tops = [domain for domain, _ in ranked[:2]]
    mapped = [_DOMAIN_FOCUS.get(domain, domain) for domain in tops]
    return " + ".join(mapped)


def _parse_domain_counts(row: Mapping[str, str], prefix: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for domain in _DOMAINS:
        key = f"{prefix}_{domain}"
        value = row.get(key, "")
        counts[domain] = int(value or 0)
    return counts


def build_crate_summary(
    crate_index: int,
    targets_path: pathlib.Path,
    pivot_path: pathlib.Path,
    crossref_path: pathlib.Path,
) -> Optional[CrateSummary]:
    targets = load_targets(targets_path)
    pivot = load_pivot(pivot_path)
    crossref = load_crossref(crossref_path)

    target_row = targets.get(crate_index)
    pivot_row = pivot.get(crate_index)
    crossref_row = crossref.get(crate_index)

    if not any((target_row, pivot_row, crossref_row)):
        return None

    label = ""
    if target_row:
        label = target_row.get("crate_label", "").strip()
    if not label and pivot_row:
        label = pivot_row.get("crate_label", "").strip()
    if not label and crossref_row:
        label = crossref_row.get("crate_label", "").strip()
    if not label:
        label = f"INDEX_{crate_index:02d}"

    if target_row:
        domain_counts = _parse_domain_counts(target_row, "domain")
        combined_total = int(target_row.get("combined_total", "") or 0)
        dominant_domain = target_row.get("dominant_domain", "")
        dominant_hint = target_row.get("dominant_domain_hint", "")
        focus_hint = target_row.get("psyq_focus_hint", "")
        priority = target_row.get("priority", "")
        score = target_row.get("score", "")
    else:
        domain_counts = _parse_domain_counts(pivot_row or {}, "both_domain") if pivot_row else {d: 0 for d in _DOMAINS}
        combined_total = int(crossref_row.get("combined_total", "") or 0) if crossref_row else 0
        dominant_domain = crossref_row.get("dominant_domain", "") if crossref_row else ""
        dominant_hint = crossref_row.get("dominant_domain_hint", "") if crossref_row else ""
        focus_hint = ""
        priority = ""
        score = ""

    if not focus_hint:
        focus_hint = _focus_from_counts(domain_counts)

    if crossref_row and not combined_total:
        combined_total = int(crossref_row.get("combined_total", "") or 0)
    if crossref_row and not dominant_domain:
        dominant_domain = crossref_row.get("dominant_domain", "")
    if crossref_row and not dominant_hint:
        dominant_hint = crossref_row.get("dominant_domain_hint", "")

    return CrateSummary(
        crate_index=crate_index,
        label=label,
        combined_total=combined_total,
        dominant_domain=dominant_domain,
        dominant_hint=dominant_hint,
        domain_counts=domain_counts,
        priority=priority,
        score=score,
        focus_hint=focus_hint,
    )


def print_crate_summary(summary: CrateSummary) -> None:
    print("=== crate summary ===")
    header = f"crate {summary.crate_index} — {summary.label}"
    trailer = []
    if summary.priority:
        trailer.append(f"priority: {summary.priority}")
    if summary.score:
        trailer.append(f"score: {summary.score}")
    if trailer:
        header += " (" + ", ".join(trailer) + ")"
    print(header)

    counts_display = ", ".join(
        f"{domain}:{summary.domain_counts.get(domain, 0)}" for domain in _DOMAINS if summary.domain_counts.get(domain, 0)
    )
    if counts_display:
        print(f"domains: {counts_display}")
    if summary.focus_hint:
        print(f"focus: {summary.focus_hint}")
    if summary.combined_total:
        dominant_line = summary.dominant_domain
        if summary.dominant_hint:
            dominant_line += f" — {summary.dominant_hint}"
        print(f"crossrefs: {summary.combined_total} ({dominant_line})")
    print("-" * 60)


def group_slot_rows(rows: List[Dict[str, str]]) -> List[SlotGroup]:
    grouped: Dict[tuple, SlotGroup] = {}
    for row in rows:
        try:
            slot = int(row.get("slot", ""))
        except (TypeError, ValueError):
            continue
        key = (
            slot,
            row.get("value_a"),
            row.get("value_b"),
            row.get("value_a_kind"),
            row.get("value_b_kind"),
            row.get("value_a_domain"),
            row.get("value_b_domain"),
        )
        if key not in grouped:
            domain_counts = {
                "value_a": int(row.get("value_a_crossref_total", "") or 0),
                "value_b": int(row.get("value_b_crossref_total", "") or 0),
            }
            grouped[key] = SlotGroup(slot=slot, row=row, weapons=[], domain_counts=domain_counts)
        weapon_index = row.get("weapon_index", "")
        if weapon_index:
            grouped[key].weapons.append(
                {
                    "weapon_index": weapon_index,
                    "match_kind": row.get("weapon_match_kind", ""),
                    "projectile": row.get("weapon_projectile_index", ""),
                }
            )
    return sorted(grouped.values(), key=lambda group: group.slot)


def summarize_group(group: SlotGroup) -> str:
    row = group.row
    parts = []
    parts.append(f"slot {group.slot}")
    parts.append(f"  value_a={row.get('value_a')} [{row.get('value_a_kind','?')}] domain={row.get('value_a_domain','?')} ({row.get('value_a_domain_hint','')})")
    parts.append(f"    crossrefs={row.get('value_a_crossref_total','0')} tables={row.get('value_a_crossref_tables','')}")
    toy_fields = [row.get(f"toy_w{i:02d}", "") for i in range(6)]
    parts.append(f"    toy words={toy_fields}")
    parts.append(f"  value_b={row.get('value_b')} [{row.get('value_b_kind','?')}] domain={row.get('value_b_domain','?')} ({row.get('value_b_domain_hint','')})")
    parts.append(f"    crossrefs={row.get('value_b_crossref_total','0')} tables={row.get('value_b_crossref_tables','')}")
    vehicle_present = row.get("vehicle_present", "0")
    if vehicle_present and vehicle_present != "0":
        vehicle_fields = [row.get(f"vehicle_w{i:02d}", "") for i in range(12)]
        parts.append(f"    vehicle words={vehicle_fields}")
    weapon_total = int(row.get("weapon_matches", "0") or 0)
    if group.weapons:
        parts.append(f"    weapons ({weapon_total} matches):")
        for weapon in group.weapons:
            parts.append(
                f"      index={weapon['weapon_index']} kind={weapon['match_kind']} projectile={weapon['projectile']}"
            )
    elif weapon_total:
        parts.append(f"    weapons: {weapon_total} (details not expanded)")
    return "\n".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect crate payload entries from the joined matrix")
    parser.add_argument("--crate", type=int, help="Crate index to inspect", required=True)
    parser.add_argument("--slot", type=int, help="Specific slot (0-5). If omitted, show all slots.", default=None)
    parser.add_argument("--matrix", default=str(MATRIX_CSV), help="Path to crate_weapon_projectile_matrix.csv")
    parser.add_argument("--pivot", default=str(PIVOT_CSV), help="Path to crate_domain_pivot.csv for crate-level domain counts")
    parser.add_argument(
        "--crossref",
        default=str(CROSSREF_CSV),
        help="Path to crate_crossref_summary.csv for combined totals",
    )
    parser.add_argument(
        "--psyq-targets",
        default=str(TARGETS_CSV),
        help="Optional psyq_trace_targets.csv to include priority/focus hints",
    )
    parser.add_argument("--no-summary", action="store_true", help="Skip crate-level summary header")
    args = parser.parse_args()

    matrix_path = pathlib.Path(args.matrix)
    if not matrix_path.exists():
        raise FileNotFoundError(f"Matrix CSV not found: {matrix_path}. Run join_crate_weapon_projectile.py first.")

    rows = load_matrix(matrix_path)
    if not args.no_summary:
        summary = build_crate_summary(
            crate_index=args.crate,
            targets_path=pathlib.Path(args.psyq_targets),
            pivot_path=pathlib.Path(args.pivot),
            crossref_path=pathlib.Path(args.crossref),
        )
        if summary:
            print_crate_summary(summary)
    matches = filter_rows(rows, args.crate, args.slot)
    if not matches:
        print("No matching crate entries found.")
        return

    groups = group_slot_rows(matches)
    for group in groups:
        print(summarize_group(group))
        print("-" * 60)


if __name__ == "__main__":
    main()
