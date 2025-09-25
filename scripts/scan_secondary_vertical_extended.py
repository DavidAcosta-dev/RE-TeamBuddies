"""
scan_secondary_vertical_extended.py

Extends earlier index0x30 / +0x60 scan to include neighboring vertical state indices:
  - index 0x2E (byte +0x5c) : vertProgress
  - index 0x2F (byte +0x5e) : vertProgressPrev / phaseStart
  - index 0x30 (byte +0x60) : vertStep
  - index 0x31 (byte +0x62) : vertScale

Patterns (array-form & offset-form) plus alias detection.
Output: exports/secondary_vertical_extended.md
"""
from __future__ import annotations
import re, json
from pathlib import Path

EXPORTS_DIR = Path(__file__).resolve().parents[1] / "exports"
OUT_FILE = EXPORTS_DIR / "secondary_vertical_extended.md"

INDEX_MAP = {
    0x2e: 0x5c,
    0x2f: 0x5e,
    0x30: 0x60,
    0x31: 0x62,
}

# Build regex sets
ARRAY_IDX_RES = {idx: re.compile(rf"\(\*\([^)]*\*\)\([^)]*\+\s*0x11c\)\)\]\s*\[0x{idx:x}\]" ) for idx in INDEX_MAP}
OFFSET_RES = {idx: re.compile(rf"\*\([^)]*\*\)\(\*\([^)]*\*\)\([^)]*\+\s*0x11c\)\s*\+\s*0x{byte_off:x}\)") for idx, byte_off in INDEX_MAP.items()}
ALIAS_ASSIGN = re.compile(r"([A-Za-z_]\w*)\s*=\s*\*\([^)]*\*\)\([^)]*\+\s*0x11c\)\s*;")

def detect_kind(line: str, pattern_fragment: str) -> str:
    # Crude read/write classifier.
    seg = line[line.find(pattern_fragment):]
    if re.search(r"=", seg) and not re.search(r"==|!=|<=|>=", seg):
        return "write"
    return "read"

def scan_function(fn_obj):
    decomp = fn_obj.get('decompilation') or ''
    if '+ 0x11c' not in decomp:
        return []
    lines = decomp.splitlines()
    aliases = set()
    for l in lines:
        m = ALIAS_ASSIGN.search(l)
        if m:
            aliases.add(m.group(1))
    events = []
    name = fn_obj['function']['name']
    ea = fn_obj['function']['ea']
    for ln, line in enumerate(lines, start=1):
        for idx, rgx in ARRAY_IDX_RES.items():
            for m in rgx.finditer(line):
                k = detect_kind(line, m.group(0))
                events.append({"fn":name,"ea":ea,"line":ln,"field_index":idx,"byte_off":INDEX_MAP[idx],"form":"array","rw":k,"src":line.strip()[:240]})
        for idx, rgx in OFFSET_RES.items():
            for m in rgx.finditer(line):
                k = detect_kind(line, m.group(0))
                events.append({"fn":name,"ea":ea,"line":ln,"field_index":idx,"byte_off":INDEX_MAP[idx],"form":"offset","rw":k,"src":line.strip()[:240]})
        # Alias forms (quick heuristic)
        for a in aliases:
            # array alias: a[0x2e]
            if re.search(rf"\b{a}\s*\[0x([23]e|[23]f|30|31)\]", line):
                idx_hex_match = re.search(r"\[0x([0-9a-f]+)\]", line)
                if idx_hex_match:
                    idx = int(idx_hex_match.group(1), 16)
                    if idx in INDEX_MAP:
                        k = 'write' if re.search(rf"{a}\s*\[0x{idx:x}\]\s*=", line) else 'read'
                        events.append({"fn":name,"ea":ea,"line":ln,"field_index":idx,"byte_off":INDEX_MAP[idx],"form":"alias-array","rw":k,"src":line.strip()[:240]})
            # offset alias: (a + 0x5c)
            for idx, byte_off in INDEX_MAP.items():
                if re.search(rf"\(\s*{a}\s*\+\s*0x{byte_off:x}\s*\)", line):
                    k = 'write' if re.search(rf"\(\s*{a}\s*\+\s*0x{byte_off:x}\s*\)\s*=", line) else 'read'
                    events.append({"fn":name,"ea":ea,"line":ln,"field_index":idx,"byte_off":byte_off,"form":"alias-offset","rw":k,"src":line.strip()[:240]})
    return events

def main():
    bundles = sorted(EXPORTS_DIR.glob('bundle_*.jsonl'))
    all_events = []
    for b in bundles:
        with b.open('r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                if not line.startswith('{'): continue
                try: obj=json.loads(line)
                except Exception: continue
                if 'function' not in obj: continue
                all_events.extend(scan_function(obj))
    with OUT_FILE.open('w',encoding='utf-8') as out:
        out.write('# Extended secondary vertical field usage scan\n\n')
        if not all_events:
            out.write('No vertical field usages detected.\n')
            return
        out.write('| Function | EA | Line | FieldIdx | ByteOff | Form | RW | Source |\n')
        out.write('|----------|----|------|----------|---------|------|----|--------|\n')
        for e in all_events:
            out.write(f"| {e['fn']} | 0x{e['ea']:x} | {e['line']} | 0x{e['field_index']:02x} | 0x{e['byte_off']:02x} | {e['form']} | {e['rw']} | `{e['src'].replace('|','\\|')}` |\n")
    print('Wrote', OUT_FILE.name, 'with', len(all_events), 'events')

if __name__ == '__main__':
    main()
