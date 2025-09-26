import csv
import json
import re
from collections import defaultdict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
Q12_JSON = BASE_DIR / "exports" / "q12_math_candidates.json"
ORIENTATION_MD = BASE_DIR / "exports" / "orientation_candidates.md"
INTEGRATOR_CSV = BASE_DIR / "exports" / "physics_integrator_map.csv"
OUTPUT_MD = BASE_DIR / "exports" / "q12_overlay_report.md"

FUNCTION_NAME_RE = re.compile(r"FUN_[0-9a-f]{8}")


def load_q12_candidates(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return payload.get("candidates", [])


def load_orientation_names(path: Path) -> set[str]:
    names: set[str] = set()
    if not path.exists():
        return names
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            match = FUNCTION_NAME_RE.search(line)
            if match:
                names.add(match.group(0))
    return names


def load_integrator_map(path: Path) -> dict[str, dict[str, str]]:
    results: dict[str, dict[str, str]] = {}
    if not path.exists():
        return results
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            name = row.get("function")
            if name:
                results[name] = row
    return results


def build_report_rows(candidates: list[dict], orientation_names: set[str], integrator_map: dict[str, dict[str, str]]):
    rows: list[dict] = []
    summary_bucket = defaultdict(int)

    for entry in candidates:
        name = entry.get("name")
        if not name:
            continue
        # Compute weighted score favoring core Q12 traits; fall back to total_hits when fields absent
        wscore = (
            3 * entry.get("right_shifts", 0)
            + 2 * entry.get("q12_products", 0)
            + 2 * entry.get("sar_calls", 0)
            + 2 * entry.get("angle_masks", 0)
            + 1 * entry.get("left_shifts", 0)
            + 1 * entry.get("pos_shifts", 0)
            + 1 * entry.get("q12_one_consts", 0)
            + 1 * entry.get("q12_half_consts", 0)
        )
        if wscore == 0:
            wscore = entry.get("total_hits", 0)
        row = {
            "name": name,
            "ea": entry.get("ea_hex", "?"),
            "score": wscore,
            "binary": entry.get("binary", "?"),
            "orientation": name in orientation_names,
            "integrator": False,
            "direct_pos": False,
            "axes": "-",
            "rsin": entry.get("rsin_calls", 0),
            "rcos": entry.get("rcos_calls", 0),
            "sar": entry.get("sar_calls", 0),
            # TbActorPrefix evidence columns from scanner JSON
            "pos_hits": entry.get("pos_hits", 0),
            "angle_hits": entry.get("angle_hits", 0),
            "basis_dest_hits": entry.get("basis_dest_hits", 0),
            "basis_src_hits": entry.get("basis_src_hits", 0),
            "speed_hits": entry.get("speed_hits", 0),
        }
        integrator_meta = integrator_map.get(name)
        if integrator_meta:
            row["integrator"] = True
            row["axes"] = integrator_meta.get("axes", "-")
            row["direct_pos"] = integrator_meta.get("direct_pos_write", "0") == "1"
        rows.append(row)

        # build summary buckets
        if row["integrator"] and row["orientation"]:
            summary_bucket["integrator_orientation"] += 1
        elif row["integrator"]:
            summary_bucket["integrator_only"] += 1
        elif row["orientation"]:
            summary_bucket["orientation_only"] += 1
        else:
            summary_bucket["other"] += 1

    return rows, summary_bucket


def render_summary(summary_bucket: dict[str, int], total: int) -> list[str]:
    return [
        "## Summary",
        "",
        f"- Total Q12 candidates: {total}",
        f"- Integrator ∩ Orientation: {summary_bucket.get('integrator_orientation', 0)}",
        f"- Integrator only: {summary_bucket.get('integrator_only', 0)}",
        f"- Orientation only: {summary_bucket.get('orientation_only', 0)}",
        f"- Other Q12-heavy routines: {summary_bucket.get('other', 0)}",
        "",
    ]


def render_table(rows: list[dict], limit: int | None = None) -> list[str]:
    if limit is not None:
        rows = rows[:limit]
    lines = [
        "| Rank | Function | EA | Score | Bin | Int | DirPos | Ori | Axes | Pxyz | Ang | BD | BS | Spd | rsin | rcos | sar |",
        "| --- | --- | --- | ---: | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for idx, row in enumerate(rows, start=1):
        integrator_flag = "✅" if row["integrator"] else ""
        direct_flag = "✅" if row["direct_pos"] else ""
        orientation_flag = "✅" if row["orientation"] else ""
        lines.append(
            f"| {idx} | {row['name']} | {row['ea']} | {row['score']} | {row['binary']} | {integrator_flag} | {direct_flag} | {orientation_flag} | {row['axes']} | {row['pos_hits']} | {row['angle_hits']} | {row['basis_dest_hits']} | {row['basis_src_hits']} | {row['speed_hits']} | {row['rsin']} | {row['rcos']} | {row['sar']} |"
        )
    lines.append("")
    return lines


def render_intersection(rows: list[dict]) -> list[str]:
    lines = ["## Integrator ∩ Orientation", ""]
    intersections = [row for row in rows if row["integrator"] and row["orientation"]]
    if not intersections:
        lines.append("- (none)")
        lines.append("")
        return lines

    for row in intersections:
        direct = "direct pos" if row["direct_pos"] else "no direct pos"
        lines.append(
            f"- {row['name']} @ {row['ea']} ({row['binary']}): {direct}, axes {row['axes']}"
        )
    lines.append("")
    return lines


def render_notes(rows: list[dict]) -> list[str]:
    lines = ["## Observations", ""]
    top_integrators = [row for row in rows if row["integrator"]][:5]
    if top_integrators:
        lines.append("- High-scoring integrators align with previously flagged position writers; use them to validate `TbPhysicsIntegrateBody` call sites.")
    trig_users = [row for row in rows if (row["rsin"] or row["rcos"])]
    if trig_users:
        lines.append(f"- {len(trig_users)} functions invoke trig tables; prioritize them when wiring `tbPhysicsOrientationToForward`.")
    else:
        lines.append("- No trig-heavy routines surfaced in the current candidate list (rsin/rcos counts are zero).")
    lines.append("- Use this overlay to decide which candidates should receive Wipeout-derived names next.")
    lines.append("")
    return lines


def generate_report(limit: int | None = 40) -> None:
    candidates = load_q12_candidates(Q12_JSON)
    orientation_names = load_orientation_names(ORIENTATION_MD)
    integrator_map = load_integrator_map(INTEGRATOR_CSV)

    # sort by weighted score desc, then trig hits, then name for stability
    def _wscore(entry: dict) -> int:
        return (
            3 * entry.get("right_shifts", 0)
            + 2 * entry.get("q12_products", 0)
            + 2 * entry.get("sar_calls", 0)
            + 2 * entry.get("angle_masks", 0)
            + 1 * entry.get("left_shifts", 0)
            + 1 * entry.get("pos_shifts", 0)
            + 1 * entry.get("q12_one_consts", 0)
            + 1 * entry.get("q12_half_consts", 0)
        ) or entry.get("total_hits", 0)

    candidates.sort(key=lambda entry: (-_wscore(entry), -(entry.get("rsin_calls", 0) + entry.get("rcos_calls", 0)), entry.get("name", "")))

    rows, summary_bucket = build_report_rows(candidates, orientation_names, integrator_map)

    output_lines: list[str] = ["# Q12 Overlay Report", ""]
    output_lines.extend(render_summary(summary_bucket, len(candidates)))
    output_lines.append("## Top Candidates")
    output_lines.append("")
    output_lines.extend(render_table(rows, limit=limit))
    output_lines.extend(render_intersection(rows))
    output_lines.extend(render_notes(rows))

    OUTPUT_MD.write_text("\n".join(output_lines), encoding="utf-8")


if __name__ == "__main__":
    generate_report()
