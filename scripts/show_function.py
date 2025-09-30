#!/usr/bin/env python3
import argparse
import json
import pathlib

def main():
    ap = argparse.ArgumentParser(description="Dump decompilation text for a function exported by Ghidra")
    ap.add_argument("name", help="Function name (e.g. FUN_000402e0)")
    ap.add_argument("--jsonl", default="exports/bundle_ghidra.jsonl")
    ap.add_argument("--limit", type=int, default=1)
    args = ap.parse_args()

    jsonl = pathlib.Path(args.jsonl)
    count = 0
    with jsonl.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if args.name in line:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                fn = rec.get("function", {})
                if fn.get("name") != args.name:
                    continue
                count += 1
                print(f"Function: {fn.get('name')} @ 0x{fn.get('ea'):X} ({rec.get('binary')})")
                print("-" * 80)
                print((rec.get("decompilation") or "").strip())
                print("\nCallers:", len(rec.get("callers", []) or []), " Callees:", len(rec.get("callees", []) or []))
                print("Strings:")
                for s in rec.get("strings_used", []) or []:
                    print("  ", s.get("text"))
                print("=" * 80)
                if count >= args.limit:
                    break
    if count == 0:
        print("No matches found")

if __name__ == "__main__":
    main()
