import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


def usage():
    print("Usage: python scripts/show_func.py <BINARY> <FUNC_NAME|EA_HEX>")
    sys.exit(1)


def load_bundles():
    for p in sorted(EXPORTS.glob("bundle_*.jsonl")):
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                yield obj


def main():
    if len(sys.argv) < 3:
        usage()
    binname = sys.argv[1]
    ident = sys.argv[2]
    want_ea = None
    want_name = None
    if ident.lower().startswith("0x"):
        try:
            want_ea = int(ident, 16)
        except ValueError:
            usage()
    else:
        want_name = ident

    matches = []
    for fn in load_bundles():
        if fn.get("binary") != binname:
            continue
        func = fn.get("function") or {}
        name = func.get("name") or ""
        ea = func.get("ea") or 0
        if want_name and name == want_name:
            matches.append(fn)
        elif want_ea is not None and ea == want_ea:
            matches.append(fn)

    if not matches:
        print("No matches found")
        return

    for m in matches:
        func = m.get("function") or {}
        print(f"== {binname}:{func.get('name')} @ {hex(func.get('ea') or 0)} ==")
        print(m.get("decompilation") or "<no decompilation>")
        print()


if __name__ == "__main__":
    main()
