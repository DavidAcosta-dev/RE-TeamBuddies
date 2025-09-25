#!/usr/bin/env python3
"""
Callgraph tracer for Ghidra JSONL bundles.

- Builds caller/callee adjacency from bundle_*.jsonl
- Finds shortest paths between EAs (addresses) by BFS

Usage:
  python scripts/callgraph_trace.py exports/bundle_MAIN.EXE.jsonl 0x235d4 0x21cf0

Notes:
- EAs can be hex (with 0x) or decimal
- Prints one or more paths (up to a small limit) if found
- You can invert direction with --reverse to trace callers to target
"""

import argparse
import json
from collections import deque, defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple

EA = int


def parse_ea(s: str) -> EA:
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


def load_bundle(p: Path) -> List[dict]:
    items = []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                # tolerate partial/diagnostic lines (shouldn't happen in normal exports)
                continue
    return items


def build_graph(items: List[dict]) -> Tuple[Dict[EA, List[EA]], Dict[EA, List[EA]], Dict[EA, str]]:
    callee_map: Dict[EA, List[EA]] = defaultdict(list)
    caller_map: Dict[EA, List[EA]] = defaultdict(list)
    names: Dict[EA, str] = {}

    # helper to derive EA from function name like "FUN_00021cf0"
    def name_to_ea(name: str) -> EA:
        if name.startswith("FUN_") and len(name) >= 12:
            try:
                return int(name.split("_")[1], 16)
            except Exception:
                return -1
        return -1

    for it in items:
        fn = it.get("function") or {}
        name = fn.get("name")
        ea = fn.get("ea")
        if ea is None:
            # fallback via function name
            if name:
                ea = name_to_ea(name)
                if ea < 0:
                    continue
            else:
                continue
        names[ea] = name or f"FUN_{ea:08x}"
        # build callee edges
        for callee_name in it.get("callees", []) or []:
            cea = name_to_ea(callee_name)
            if cea >= 0:
                callee_map[ea].append(cea)
                caller_map[cea].append(ea)
    return callee_map, caller_map, names


def bfs_paths(graph: Dict[EA, List[EA]], start: EA, goal: EA, max_depth: int = 8, max_paths: int = 5) -> List[List[EA]]:
    paths: List[List[EA]] = []
    dq: deque = deque()
    dq.append((start, [start]))
    seen: Dict[EA, int] = {start: 0}
    while dq and len(paths) < max_paths:
        node, path = dq.popleft()
        depth = len(path) - 1
        if depth > max_depth:
            continue
        if node == goal and len(path) > 1:
            paths.append(path)
            continue
        for nxt in graph.get(node, []):
            nd = depth + 1
            if nd > max_depth:
                continue
            # allow better (shorter) revisits
            if nxt in seen and seen[nxt] <= nd:
                continue
            seen[nxt] = nd
            dq.append((nxt, path + [nxt]))
    return paths


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle", type=Path)
    ap.add_argument("start_ea")
    ap.add_argument("goal_ea")
    ap.add_argument("--reverse", action="store_true", help="Trace callers to target instead of callees from start")
    ap.add_argument("--max-depth", type=int, default=8)
    ap.add_argument("--max-paths", type=int, default=5)
    args = ap.parse_args()

    start = parse_ea(args.start_ea)
    goal = parse_ea(args.goal_ea)

    items = load_bundle(args.bundle)
    callee_map, caller_map, names = build_graph(items)

    graph = caller_map if args.reverse else callee_map
    paths = bfs_paths(graph, start, goal, max_depth=args.max_depth, max_paths=args.max_paths)

    if not paths:
        print("No path found.")
        return

    def fmt(ea: EA) -> str:
        return f"0x{ea:05x} ({names.get(ea, f'FUN_{ea:08x}')} )"

    for i, p in enumerate(paths, 1):
        print(f"Path {i} ({len(p)-1} hops):")
        for ea in p:
            print("  ", fmt(ea))


if __name__ == "__main__":
    main()
