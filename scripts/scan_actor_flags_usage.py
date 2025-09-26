#!/usr/bin/env python3
"""
scan_actor_flags_usage.py

Scan exported JSONL bundles for uses of the actor flags field at +0x26.
Detect common bitwise operations (AND/OR/XOR/NOT), comparisons, and constants,
then aggregate a mask histogram to propose an initial flag enum.

Output: exports/actor_flags_usage.md
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"
BUNDLE_GLOB = "exports/bundle_*.jsonl"
OUT_MD = EXPORTS / "actor_flags_usage.md"
OUT_JSON = EXPORTS / "actor_flags_usage.json"

OFFSET = 0x26
OFF_RE = re.compile(r"\+\s*0x{:x}\b".format(OFFSET), re.IGNORECASE)
HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
DEC_RE = re.compile(r"\b\d+\b")


def is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def parse_int(tok: str) -> int | None:
    try:
        if tok.lower().startswith("0x"):
            return int(tok, 16)
        return int(tok)
    except Exception:
        return None


def iter_jsonl(path: Path) -> Iterator[dict]:
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


@dataclass
class FlagUse:
    name: str
    binary: str
    ea: int | None
    and_masks: Counter[int]
    or_masks: Counter[int]
    xor_masks: Counter[int]
    cmp_masks: Counter[int]
    not_count: int
    lines: List[str]


def find_masks(line: str) -> List[int]:
    masks: List[int] = []
    for m in HEX_RE.findall(line):
        v = parse_int(m)
        if v is not None:
            masks.append(v)
    # also capture small decimal masks like 1, 2, 4, 8, etc
    for m in DEC_RE.findall(line):
        v = parse_int(m)
        if v is not None and v <= (1 << 16):
            masks.append(v)
    return masks


def collect(paths: Iterable[Path]) -> Dict[str, FlagUse]:
    uses: Dict[str, FlagUse] = {}
    for path in paths:
        for entry in iter_jsonl(path):
            fn = entry.get("function") or {}
            name = fn.get("name") or "UNKNOWN"
            ea = fn.get("ea")
            binary = entry.get("binary") or ""
            decomp = entry.get("decompilation") or ""
            if not decomp:
                continue
            if "+ 0x{:x}".format(OFFSET) not in decomp and "+ 0x{:X}".format(OFFSET) not in decomp:
                continue
            fu = uses.get(name)
            if fu is None:
                fu = FlagUse(
                    name=name,
                    binary=binary,
                    ea=ea,
                    and_masks=Counter(),
                    or_masks=Counter(),
                    xor_masks=Counter(),
                    cmp_masks=Counter(),
                    not_count=0,
                    lines=[],
                )
                uses[name] = fu
            for ln in decomp.splitlines():
                if OFF_RE.search(ln):
                    s = ln.strip()
                    # classify
                    masks = find_masks(s)
                    if "&" in s:
                        for m in masks:
                            fu.and_masks[m] += 1
                    if "|" in s:
                        for m in masks:
                            fu.or_masks[m] += 1
                    if "^" in s:
                        for m in masks:
                            fu.xor_masks[m] += 1
                    if "==" in s or "!=" in s or ">" in s or "<" in s:
                        for m in masks:
                            fu.cmp_masks[m] += 1
                    if "~" in s:
                        fu.not_count += 1
                    # store a few sample lines
                    if len(fu.lines) < 4:
                        fu.lines.append(s)
    return uses


def render(uses: Dict[str, FlagUse]) -> str:
    lines: List[str] = []
    lines.append("# Actor Flags (+0x26) Usage Report")
    lines.append("")
    lines.append(f"Functions touching +0x26: {len(uses)}")
    lines.append("")

    # Global mask histogram
    glob = Counter()
    for fu in uses.values():
        glob.update(fu.and_masks)
        glob.update(fu.or_masks)
        glob.update(fu.xor_masks)
        glob.update(fu.cmp_masks)
    lines.append("## Top Masks")
    lines.append("")
    lines.append("| Mask | Count | Kind | Bits | PoT |")
    lines.append("| --- | ---: | --- | --- | ---: |")
    for mask, cnt in glob.most_common(20):
        kind = []
        if any(mask in d for d in (fu.and_masks for fu in uses.values())):
            kind.append("AND")
        if any(mask in d for d in (fu.or_masks for fu in uses.values())):
            kind.append("OR")
        if any(mask in d for d in (fu.xor_masks for fu in uses.values())):
            kind.append("XOR")
        if any(mask in d for d in (fu.cmp_masks for fu in uses.values())):
            kind.append("CMP")
        # bit positions (up to 16)
        bits = ",".join(str(i) for i in range(16) if mask & (1 << i))
        lines.append(f"| 0x{mask:X} | {cnt} | {','.join(kind)} | {bits} | {1 if is_power_of_two(mask) else 0} |")
    lines.append("")

    # Per-function summary (top 40)
    lines.append("## Per-function usage (top 40)")
    lines.append("")
    rows: List[Tuple[str, int, FlagUse]] = []
    for name, fu in uses.items():
        count = sum(fu.and_masks.values()) + sum(fu.or_masks.values()) + sum(fu.xor_masks.values()) + sum(fu.cmp_masks.values()) + fu.not_count
        rows.append((name, count, fu))
    rows.sort(key=lambda x: -x[1])
    lines.append("| Function | EA | Bin | Ops | AND | OR | XOR | CMP | ~ | Sample |")
    lines.append("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
    for name, count, fu in rows[:40]:
        ea = f"0x{fu.ea:06x}" if fu.ea is not None else "—"
        sample = (fu.lines[0] if fu.lines else "").replace("|", "|")
        lines.append(
            f"| {name} | {ea} | {fu.binary} | {count} | {sum(fu.and_masks.values())} | {sum(fu.or_masks.values())} | {sum(fu.xor_masks.values())} | {sum(fu.cmp_masks.values())} | {fu.not_count} | {sample} |"
        )
    lines.append("")

    # Suggested enum from top PoT masks
    lines.append("## Suggested Flag Bits (draft)")
    lines.append("")
    top_pot = [m for m, c in glob.most_common(64) if is_power_of_two(m)][:12]
    if not top_pot:
        lines.append("- No clear single-bit masks detected yet. Rerun after more bundles are exported.")
    else:
        for i, m in enumerate(top_pot):
            lines.append(f"- FLAG_BIT_{i:02d} = 0x{m:04X}")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    bundle_paths = sorted(ROOT.glob(BUNDLE_GLOB))
    if not bundle_paths:
        raise SystemExit(f"No JSONL files matched glob: {BUNDLE_GLOB}")
    uses = collect(bundle_paths)
    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text(render(uses), encoding="utf-8")
    # Emit JSON summary with global mask histogram
    glob = Counter()
    for fu in uses.values():
        glob.update(fu.and_masks)
        glob.update(fu.or_masks)
        glob.update(fu.xor_masks)
        glob.update(fu.cmp_masks)
    payload = {
        "functions": [
            {
                "name": fu.name,
                "binary": fu.binary,
                "ea": fu.ea,
                "and_masks": dict(fu.and_masks),
                "or_masks": dict(fu.or_masks),
                "xor_masks": dict(fu.xor_masks),
                "cmp_masks": dict(fu.cmp_masks),
                "not_count": fu.not_count,
            }
            for fu in uses.values()
        ],
        "global_mask_counts": dict(glob),
    }
    OUT_JSON.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote {OUT_MD}")


if __name__ == "__main__":
    main()
