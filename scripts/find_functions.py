#!/usr/bin/env python3
"""Query helper for ghidra export jsonl files.

Designed to work with `exports/bundle_ghidra.jsonl` produced by existing tooling.
Supports substring and regex search over function names, strings, and decompilation text.
"""
import argparse
import json
import pathlib
import re
from typing import Iterable, Dict, Any

DEFAULT_JSONL = pathlib.Path("exports/bundle_ghidra.jsonl")


def iter_functions(path: pathlib.Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            yield rec


def record_matches(rec: Dict[str, Any], sub: str = None, regex: re.Pattern = None, fields=None, case_sensitive=False) -> bool:
    if fields is None:
        fields = ["function.name", "decompilation", "strings"]

    def gather(field: str) -> Iterable[str]:
        if field == "function.name":
            fn = rec.get("function", {})
            name = fn.get("name")
            if name:
                yield name
        elif field == "strings":
            for s in rec.get("strings_used", []) or []:
                text = s.get("text")
                if text:
                    yield text
        else:
            value = rec.get(field)
            if isinstance(value, str):
                yield value

    if regex is None and sub is None:
        return True

    for field in fields:
        for text in gather(field):
            if regex:
                if regex.search(text):
                    return True
            elif sub is not None:
                haystack = text if case_sensitive else text.lower()
                needle = sub if case_sensitive else sub.lower()
                if needle in haystack:
                    return True
    return False


def main():
    ap = argparse.ArgumentParser(description="Search functions exported to JSONL from Ghidra")
    ap.add_argument("--jsonl", default=str(DEFAULT_JSONL), help="Path to bundle_ghidra.jsonl (default exports/bundle_ghidra.jsonl)")
    ap.add_argument("--pattern", help="Substring pattern to search for")
    ap.add_argument("--regex", help="Regular expression to search for")
    ap.add_argument("--case-sensitive", action="store_true", help="Enable case-sensitive substring search")
    ap.add_argument("--fields", nargs="*", help="Override fields to search (default: function.name decompilation strings)")
    ap.add_argument("--limit", type=int, default=40, help="Maximum matches to print (0 disables limit)")
    ap.add_argument("--output", help="Optional CSV path to store full matched records (name,ea,binary,callers,callees)")
    args = ap.parse_args()

    jsonl_path = pathlib.Path(args.jsonl)
    if not jsonl_path.exists():
        ap.error(f"JSONL file not found: {jsonl_path}")

    regex = re.compile(args.regex, re.IGNORECASE) if args.regex else None
    fields = args.fields if args.fields else None

    matches = []
    for rec in iter_functions(jsonl_path):
        if record_matches(rec, sub=args.pattern, regex=regex, fields=fields, case_sensitive=args.case_sensitive):
            matches.append(rec)

    if args.output:
        import csv
        out_path = pathlib.Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", newline="", encoding="utf-8") as f:
            fieldnames = ["name", "ea", "binary", "callers", "callees"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for rec in matches:
                fn = rec.get("function", {})
                writer.writerow({
                    "name": fn.get("name"),
                    "ea": fn.get("ea"),
                    "binary": rec.get("binary"),
                    "callers": len(rec.get("callers", []) or []),
                    "callees": len(rec.get("callees", []) or []),
                })
        print(f"Wrote {len(matches)} rows to {out_path}")

    limit = args.limit if args.limit is not None else 40
    display = matches if limit == 0 else matches[:limit]
    print(f"Matches: {len(matches)} (showing {len(display)})")
    for rec in display:
        fn = rec.get("function", {})
        name = fn.get("name")
        ea = fn.get("ea")
        binary = rec.get("binary")
        callers = len(rec.get("callers", []) or [])
        callees = len(rec.get("callees", []) or [])
        print(f"{binary or '??'} | {name} | ea=0x{ea:X} | callers={callers} | callees={callees}")

if __name__ == "__main__":
    main()
