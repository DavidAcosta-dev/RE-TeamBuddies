#!/usr/bin/env python3
"""List GAME.BIN functions that call sys_retain/sys_release."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "exports" / "bundle_GAME.BIN.jsonl"


def main() -> None:
    if not BUNDLE.exists():
        raise SystemExit(f"Bundle not found: {BUNDLE}")

    targets: dict[str, set[str]] = defaultdict(set)
    with BUNDLE.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            fn = obj.get("function") or {}
            name = fn.get("name") or fn.get("symbol") or obj.get("address") or "<unnamed>"
            callees = obj.get("callees") or []
            refs = obj.get("refTo") or []
            for t in ("sys_retain", "sys_release"):
                if t in callees or t in refs:
                    targets[t].add(name)

    for key in ("sys_retain", "sys_release"):
        values = sorted(targets.get(key, []))
        print(f"{key}: {len(values)} callers")
        for val in values:
            print(f"  - {val}")


if __name__ == "__main__":
    main()
