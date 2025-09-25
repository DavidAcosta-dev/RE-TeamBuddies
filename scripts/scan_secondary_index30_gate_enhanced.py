"""
scan_secondary_index30_gate_enhanced.py

Purpose: Enhanced detection of reads/writes to the vertical secondary Y slot:
  - Array-form: (*(undefined2 **)(X + 0x11c))[0x30]
  - Pointer + byte offset form (0x60 bytes / 0x30 * sizeof(uint16)): *(short *)(*(int *)(X + 0x11c) + 0x60)
  - Alias-based forms:
        puVar = *(undefined2 **)(param_1 + 0x11c); puVar[0x30] = ...;
        piVar = *(int *)(param_1 + 0x11c); *(short *)(piVar + 0x60) = ...;

Additionally detect gate (+0x60) reads/writes (>=0 comparisons, assignments) and classify usage.

Output: exports/secondary_index30_gate_enhanced.md

Heuristics only; false positives possible but should surface hidden writers.
"""
from __future__ import annotations
import re, json
from pathlib import Path

EXPORTS_DIR = Path(__file__).resolve().parents[1] / "exports"
OUT_FILE = EXPORTS_DIR / "secondary_index30_gate_enhanced.md"

# Regex components
# Direct array index (read or write)
DIRECT_IDX = re.compile(r"\(\*\([^)]*\*\)\([^)]*\+\s*0x11c\)\)\)\s*\[0x30\]")
# Direct offset +0x60 form (read or write)
DIRECT_OFFSET60 = re.compile(r"\*\([^)]*\*\)\(\*\([^)]*\*\)\([^)]*\+\s*0x11c\)\s*\+\s*0x60\)")

# Alias assignment capturing variable name that aliases *(... + 0x11c)
ALIAS_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*\*\([^)]*\*\)\([^)]*\+\s*0x11c\)\s*;")

# Later uses of alias for index 0x30 or +0x60 offset
ALIAS_IDX_TMPL = lambda var: re.compile(rf"\b{re.escape(var)}\s*\[0x30\]")
ALIAS_OFF60_TMPL = lambda var: re.compile(rf"\(\s*{re.escape(var)}\s*\+\s*0x60\s*\)")

def classify_fragment(fragment: str) -> str:
    """Classify usage inside a single line or short fragment."""
    # Write if = appears immediately after pattern; read otherwise
    # Very naive but workable for decompiler output style.
    after = fragment.split(']')[-1] if '] ' in fragment or fragment.endswith(']') else fragment
    if re.search(r"=", after) and not re.search(r"==|!=|<=|>=", after):
        return "write"
    return "read"

def classify_offset60(line: str) -> str:
    # Write if '=' follows the pattern before a semicolon.
    if re.search(r"\+\s*0x60\)\s*=", line):
        return "write"
    return "read"

def scan_function(obj: dict):
    decomp = obj.get("decompilation") or ""
    if not decomp:
        return []
    fn = obj.get("function", {})
    fname = fn.get("name") or "?"
    fea = fn.get("ea")
    lines = decomp.splitlines()
    alias_vars: set[str] = set()
    events = []

    # First pass: collect alias variables
    for line in lines:
        m = ALIAS_ASSIGN.search(line)
        if m:
            alias_vars.add(m.group(1))

    # Second pass: detect direct patterns and alias usages
    for i, line in enumerate(lines):
        # Direct array index pattern occurrences
        for m in DIRECT_IDX.finditer(line):
            frag = line[m.start(): m.end() + 40]
            kind = classify_fragment(line[m.start():])
            events.append({
                "function": fname,
                "ea": fea,
                "line_no": i+1,
                "kind": f"index30_{kind}_direct",
                "alias": "",
                "line": line.strip()
            })
        # Direct +0x60 form
        for m in DIRECT_OFFSET60.finditer(line):
            kind = classify_offset60(line[m.start():])
            events.append({
                "function": fname,
                "ea": fea,
                "line_no": i+1,
                "kind": f"offset60_{kind}_direct",
                "alias": "",
                "line": line.strip()
            })
        # Alias usages
        for av in alias_vars:
            if ALIAS_IDX_TMPL(av).search(line):
                # Distinguish read/write
                if re.search(rf"{re.escape(av)}\s*\[0x30\]\s*=", line):
                    k = "index30_write_alias"
                else:
                    k = "index30_read_alias"
                events.append({
                    "function": fname,
                    "ea": fea,
                    "line_no": i+1,
                    "kind": k,
                    "alias": av,
                    "line": line.strip()
                })
            if ALIAS_OFF60_TMPL(av).search(line):
                # If a write pattern
                if re.search(rf"\(\s*{re.escape(av)}\s*\+\s*0x60\s*\)\s*=", line):
                    k = "offset60_write_alias"
                else:
                    k = "offset60_read_alias"
                events.append({
                    "function": fname,
                    "ea": fea,
                    "line_no": i+1,
                    "kind": k,
                    "alias": av,
                    "line": line.strip()
                })
    return events

def main():
    targets = sorted(EXPORTS_DIR.glob("bundle_*.jsonl"))
    rows = []
    for fp in targets:
        with fp.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if 'function' not in obj:
                    continue
                # Quick prefilter: skip functions without +0x11c reference to reduce work
                if "+ 0x11c" not in obj.get('decompilation',''):
                    continue
                rows.extend(scan_function(obj))

    with OUT_FILE.open("w", encoding="utf-8") as out:
        out.write("# Enhanced secondary index0x30 / +0x60 usage scan\n\n")
        if not rows:
            out.write("No usages detected by enhanced scan.\n")
            return
        out.write("| Function | EA | Line | Kind | Alias | Source |\n")
        out.write("|----------|----|------|------|-------|--------|\n")
        for r in rows:
            ea_fmt = f"0x{r['ea']:x}" if isinstance(r['ea'], int) else r['ea']
            src = r['line'].replace('|', '\\|')[:220]
            out.write(f"| {r['function']} | {ea_fmt} | {r['line_no']} | {r['kind']} | {r['alias']} | `{src}` |\n")

        # Group snippets by function for context
        out.write("\n\n## Per-function snippets\n\n")
        by_fn = {}
        for r in rows:
            by_fn.setdefault((r['function'], r['ea']), []).append(r)
        for (fn, ea), items in sorted(by_fn.items(), key=lambda x: x[0][0]):
            out.write(f"### {fn} @ 0x{ea:x}\n\n")
            for it in items:
                out.write(f"- L{it['line_no']:>4} {it['kind']}: {it['line']}\n")
            out.write("\n")

if __name__ == "__main__":
    main()
