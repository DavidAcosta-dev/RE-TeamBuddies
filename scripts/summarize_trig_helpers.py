import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Robustly parse the bundle jsonl and summarize callers/callees for suspected trig helpers
# Outputs a markdown summary to exports/trig_helpers_summary.md

TARGET_NAMES = {
    "stub_ret0_FUN_0001c7fc",
    "stub_ret0_FUN_0001c83c",
    "suspect_trig_LUT_A",
    "suspect_trig_LUT_B",
}
TARGET_EAS = {0x1C7FC, 0x1C83C}
ANCHORS = {"phys_angle_window_config", "phys_angle_window_config_scaled", "phys_recompute_basis"}


def normalize_ea(ea: Any) -> Optional[int]:
    try:
        if isinstance(ea, int):
            return ea
        if isinstance(ea, str):
            s = ea.strip().lower()
            if s.startswith("0x"):
                return int(s, 16)
            # Allow decimal string fallback
            return int(s, 10)
    except Exception:
        return None
    return None


def load_bundle(bundle_path: Path) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    with bundle_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                items.append(obj)
            except json.JSONDecodeError:
                # tolerate stray lines
                continue
    return items


def extract_name(obj: Dict[str, Any]) -> str:
    # Prefer nested function.name if present
    fn = obj.get("function")
    if isinstance(fn, dict):
        v = fn.get("name")
        if isinstance(v, str) and v:
            return v
    # Fallback: top-level name variations
    for key in ("name", "func_name", "symbol", "id"):
        v = obj.get(key)
        if isinstance(v, str) and v:
            return v
    # Last resort: build from EA
    ea = normalize_ea(obj.get("ea"))
    if ea is None and isinstance(fn, dict):
        ea = normalize_ea(fn.get("ea"))
    if ea is not None:
        return f"FUN_{ea:08x}"
    return "<unknown>"


def extract_ea(obj: Dict[str, Any]) -> Optional[int]:
    ea = normalize_ea(obj.get("ea"))
    if ea is not None:
        return ea
    fn = obj.get("function")
    if isinstance(fn, dict):
        return normalize_ea(fn.get("ea"))
    return None


def extract_callees(obj: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    raw = obj.get("callees")
    if isinstance(raw, list):
        for it in raw:
            if isinstance(it, str):
                out.add(it)
            elif isinstance(it, dict):
                nm = extract_name(it)
                if nm:
                    out.add(nm)
    return out


def build_index(items: List[Dict[str, Any]]):
    by_name: Dict[str, Dict[str, Any]] = {}
    by_ea: Dict[int, Dict[str, Any]] = {}
    for obj in items:
        nm = extract_name(obj)
        ea = extract_ea(obj)
        by_name[nm] = obj
        if ea is not None:
            by_ea[ea] = obj
    # Build reverse call map
    callers: Dict[str, Set[str]] = {extract_name(o): set() for o in items}
    for obj in items:
        src = extract_name(obj)
        for callee in extract_callees(obj):
            callers.setdefault(callee, set()).add(src)
    return by_name, by_ea, callers


def find_targets(by_name: Dict[str, Dict[str, Any]], by_ea: Dict[int, Dict[str, Any]]):
    targets: List[Tuple[str, Dict[str, Any]]] = []
    # By name
    for nm in TARGET_NAMES:
        if nm in by_name:
            targets.append((nm, by_name[nm]))
    # By EA
    for ea in TARGET_EAS:
        obj = by_ea.get(ea)
        if obj is not None:
            nm = extract_name(obj)
            # Avoid duplicates
            if all(nm != t[0] for t in targets):
                targets.append((nm, obj))
    return targets


def summarize(program: str, bundle_path: Path, out_path: Path):
    items = load_bundle(bundle_path)
    by_name, by_ea, callers = build_index(items)
    targets = find_targets(by_name, by_ea)

    lines: List[str] = []
    lines.append(f"# Trig helper summary for {program}")
    lines.append("")
    if not targets:
        lines.append("No suspected trig helper function entries found in bundle.")
        lines.append("")
    # Always include callers-of-target-names section to aid review
    # Find callers of any of the target names even if the target isn't exported
    all_callers: Dict[str, List[Tuple[str, Optional[int]]]] = {}
    for obj in items:
        src_nm = extract_name(obj)
        src_ea = extract_ea(obj)
        callees = extract_callees(obj)
        for tgt in sorted(TARGET_NAMES):
            if tgt in callees:
                all_callers.setdefault(tgt, []).append((src_nm, src_ea))
    if all_callers:
        lines.append("## Callers of suspected trig helpers")
        lines.append("")
        for tgt, lst in sorted(all_callers.items()):
            lines.append(f"### {tgt}")
            lines.append("")
            lines.append(f"- callers: {len(lst)}")
            for src_nm, src_ea in lst[:40]:
                ea_s = f"0x{src_ea:X}" if src_ea is not None else "?"
                # Anchor tags (does caller also call anchors?)
                src_obj = by_name.get(src_nm)
                anchor_tags: List[str] = []
                if src_obj is not None:
                    src_callees = extract_callees(src_obj)
                    for a in sorted(ANCHORS):
                        if a in src_callees:
                            anchor_tags.append(a)
                tag = f" [{', '.join(anchor_tags)}]" if anchor_tags else ""
                lines.append(f"- {src_nm} ({ea_s}){tag}")
            lines.append("")
    for nm, obj in targets:
        ea = extract_ea(obj)
        ea_s = f"0x{ea:X}" if ea is not None else "?"
        cset = sorted(callers.get(nm, set()))
        lines.append(f"## {nm} ({ea_s})")
        lines.append("")
        lines.append(f"- callers: {len(cset)}")
        if cset:
            # Show up to 20 callers with EA if available
            lines.append("")
            lines.append("Callers (up to 20):")
            for src_nm in cset[:20]:
                src_obj = by_name.get(src_nm)
                src_ea = extract_ea(src_obj) if src_obj else None
                src_ea_s = f"0x{src_ea:X}" if src_ea is not None else "?"
                # Anchor context
                anchor_tags = []
                src_callees = extract_callees(src_obj) if src_obj else set()
                for a in sorted(ANCHORS):
                    if a in src_callees:
                        anchor_tags.append(a)
                tag = f" [{', '.join(anchor_tags)}]" if anchor_tags else ""
                lines.append(f"- {src_nm} ({src_ea_s}){tag}")
        # Include decomp snippet if present
        decomp = obj.get("decomp") or obj.get("decompile") or obj.get("decompiled") or obj.get("decompilation")
        if isinstance(decomp, str) and decomp.strip():
            lines.append("")
            lines.append("Decomp (truncated):")
            snippet = "\n".join(decomp.splitlines()[:40])
            lines.append("```")
            lines.append(snippet)
            lines.append("```")
        lines.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--program", default="MAIN.EXE", help="Program name (MAIN.EXE or GAME.BIN)")
    ap.add_argument("--bundle", default=None, help="Path to bundle jsonl (default: exports/bundle_<program>.jsonl)")
    ap.add_argument("--out", default=None, help="Output markdown path (default: exports/trig_helpers_summary.md)")
    args = ap.parse_args()

    program = args.program
    root = Path(__file__).resolve().parents[1]
    bundle_path = Path(args.bundle) if args.bundle else (root / "exports" / f"bundle_{program}.jsonl")
    out_path = Path(args.out) if args.out else (root / "exports" / "trig_helpers_summary.md")

    summarize(program, bundle_path, out_path)
