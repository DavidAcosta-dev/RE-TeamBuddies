#!/usr/bin/env python3
"""
Scan exported decompilations and crate scheduler map to infer return-to-base predicates:
- For cb2 (primary) callbacks, look for evidence of switching back to base slot (+0x38)
  or enqueuing the base callback pair.
- Capture a compact textual predicate (e.g., comparisons, bit tests) near the switch.

Inputs:
- exports/crate_scheduler_map.csv
- exports/bundle_all_plus_demo.jsonl (preferred) / exports/bundle_ghidra.jsonl
- exports/crate_labels.json (optional)

Outputs:
- exports/crate_return_predicates.csv
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set

ROOT = Path(__file__).resolve().parents[1]
EXP = ROOT / 'exports'

SCHED = EXP / 'crate_scheduler_map.csv'
LABELS = EXP / 'crate_labels.json'
def iter_jsonls():
    # Discover all bundle_*.jsonl under exports for broader coverage
    return sorted(EXP.glob('bundle_*.jsonl'))

POS_BASE_OFF = '0x38'

def load_labels():
    if LABELS.exists():
        try:
            return json.loads(LABELS.read_text(encoding='utf-8'))
        except Exception:
            return {}
    return {}

def load_scheduler():
    if not SCHED.exists():
        return []
    with SCHED.open('r', encoding='utf-8', newline='') as f:
        rd = csv.DictReader(f)
        return list(rd)

def load_jsonl() -> Dict[str, str]:
    # Map FUN_* name to decompilation
    out: Dict[str, str] = {}
    for p in iter_jsonls():
        if not p.exists():
            continue
        with p.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                func = obj.get('function') or {}
                name = func.get('name') or obj.get('name')
                decomp = obj.get('decompilation') or obj.get('code') or ''
                if name and decomp and name not in out:
                    out[name] = decomp
    return out


PRED_PAT = re.compile(r"\bif\s*\((?P<p>[^)]+)\)\s*{", re.IGNORECASE)
# Also match if (...) without a following '{'
PRED_NOBRACE_PAT = re.compile(r"\bif\s*\((?P<p>[^)]+)\)\s*(?:;|$)", re.IGNORECASE)
BASE_WRITE_PAT = re.compile(r"\+\s*0x38\)\s*=|\[0x38\]\s*=|\(\*.*\+\s*0x38\)")
HEX_38_PAT = re.compile(r"0x?38\b", re.IGNORECASE)
# Match any call like name(...)
CALLEE_PAT = re.compile(r"\b(FUN_[0-9a-fA-F]{5,}|[A-Za-z_][A-Za-z0-9_]*)\s*\(")
COND_EXPR_PAT = re.compile(r"([A-Za-z0-9_\)\]]+\s*(==|!=|<=|>=|<|>|&|\|)\s*[A-Za-z0-9_\(\[]+)")
SLOTPTR_ASSIGN_PAT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]*\+\s*0x38\b")
TERNARY_PAREN_PAT = re.compile(r"\((?P<cond>[^)]+)\)\s*\?\s*[^:;{}]+:\s*[^;{}]+")
TERNARY_BARE_PAT = re.compile(r"(?P<cond>[^?;(){}]{1,120})\?\s*[^:;{}]+:\s*[^;{}]+")

def parse_args(argstr: str) -> List[str]:
    # Very loose split respecting nested parens by counting
    args: List[str] = []
    cur = []
    depth = 0
    for ch in argstr:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth = max(0, depth - 1)
        if ch == ',' and depth == 0:
            args.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        args.append(''.join(cur).strip())
    return args


def call_targets_base(args: List[str], window_lines: List[str], base_pairs: set[Tuple[str, str]], slot_vars: Optional[Set[str]] = None) -> Tuple[bool, str, Optional[Tuple[str, str]]]:
    # Heuristics:
    # - Any arg mentions + 0x38 or literal 0x38 near call -> base-slot
    # - Last two args look like function names and match a known base pair -> base-pair
    joined = ' '.join(args)
    wl = '\n'.join(window_lines)
    if '+ 0x38' in joined or HEX_38_PAT.search(joined) or '+ 0x38' in wl or HEX_38_PAT.search(wl):
        return True, 'enqueue base-slot', None
    # Try to take last two args as callbacks
    cb2 = cb1 = None
    if len(args) >= 4:
        # Note: in our scheduler, order is (context, slotPtr, cb2, cb1)
        cb2 = args[-2]
        cb1 = args[-1]
        # Strip casts
        for which in ('cb2', 'cb1'):
            pass
    def norm(name: Optional[str]) -> Optional[str]:
        if not name:
            return None
        # remove casts like (code *) and &
        name = re.sub(r"\([^)]*\)", "", name)
        name = name.replace('&', '').strip()
        return name
    cb2n = norm(cb2)
    cb1n = norm(cb1)
    # Extract bare token (FUN_000xxxxx or label)
    tok = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    def first_tok(s: Optional[str]) -> Optional[str]:
        if not s:
            return None
        m = tok.search(s)
        return m.group(0) if m else None
    cb2t = first_tok(cb2n)
    cb1t = first_tok(cb1n)
    if cb2t and cb1t and (cb2t, cb1t) in base_pairs:
        return True, 'enqueue base-pair', (cb2t, cb1t)
    # If a known slot var (+0x38) appears in the args or local window, treat as base-slot
    if slot_vars:
        for sv in slot_vars:
            if re.search(r"\b" + re.escape(sv) + r"\b", joined) or re.search(r"\b" + re.escape(sv) + r"\b", wl):
                return True, 'enqueue base-slot', None
    return False, '', None


def scan_predicates():
    labels = load_labels()
    # Build reverse map: label -> FUN_*
    rev_labels = {}
    for fun, lab in labels.items():
        if isinstance(lab, str) and fun.startswith('FUN_'):
            rev_labels.setdefault(lab, fun)
    sched = load_scheduler()
    code_map = load_jsonl()

    # Determine scheduler-like function names: defaults + label aliases
    sched_candidates = {'FUN_00035324', 'FUN_00032278'}
    for fun, lab in labels.items():
        if fun in ('FUN_00035324', 'FUN_00032278') and isinstance(lab, str):
            sched_candidates.add(lab)
    SCHED_CALL_PAT = re.compile(r"(" + "|".join(re.escape(n) for n in sorted(sched_candidates)) + r")\s*\((?P<args>[^)]*)\)")

    # Focus on cb2 rows
    cb2_set = {r.get('cb2','') for r in sched if r.get('cb2')}

    # Infer base pairs from slot 0x38 occurrences (most frequent pairs)
    pair_counts = {}
    for r in sched:
        if (r.get('slot') == '0x38') and r.get('cb1') and r.get('cb2'):
            key = (r['cb1'], r['cb2'])
            pair_counts[key] = pair_counts.get(key, 0) + 1
    base_pairs = sorted(pair_counts.items(), key=lambda x: -x[1])[:3]
    base_set = {(a, b) for (a, b), _ in base_pairs}
    # Add canonical FUN_* forms to base_set as well
    base_fun_set = set()
    for a, b in list(base_set):
        a_fun = rev_labels.get(a, a)
        b_fun = rev_labels.get(b, b)
        base_fun_set.add((a_fun, b_fun))

    results: List[Dict[str, str]] = []
    def find_in_lines(lines: List[str]) -> Optional[Tuple[str, str, Optional[Tuple[str, str]], str]]:
        # Returns (evidence, branch, pair, predicate)
        # Pre-collect any variables assigned as slot pointers with +0x38
        slot_vars: Set[str] = set()
        for ln_ in lines:
            ms = SLOTPTR_ASSIGN_PAT.search(ln_)
            if ms:
                slot_vars.add(ms.group(1))
        # One-hop propagation: x = y; if y is a slot var, treat x as slot var too
        for ln_ in lines:
            ma = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\b", ln_)
            if ma and ma.group(2) in slot_vars:
                slot_vars.add(ma.group(1))
        for i, ln in enumerate(lines):
            m = PRED_PAT.search(ln) or PRED_NOBRACE_PAT.search(ln)
            if not m:
                continue
            predicate = m.group('p').strip()
            j = i
            in_else = False
            end = min(len(lines), i + 64)
            while j < end:
                seg = '\n'.join(lines[j:j+4])
                if j > i and lines[j].strip().startswith('else'):
                    in_else = True
                if BASE_WRITE_PAT.search(seg):
                    return ('base slot write', 'if-true' if not in_else else 'if-false', None, predicate)
                # Writes through a slot pointer variable
                for sv in slot_vars:
                    if re.search(r"\*\s*" + re.escape(sv) + r"\s*=|\b" + re.escape(sv) + r"\s*\[\s*0\s*\]\s*=", seg):
                        return ('base slot write (via slot ptr)', 'if-true' if not in_else else 'if-false', None, predicate)
                mc = SCHED_CALL_PAT.search(seg)
                if mc:
                    args = parse_args(mc.group('args'))
                    calls_base, ev, pair = call_targets_base(args, lines[max(0, j-10):j+6], base_set, slot_vars)
                    if calls_base:
                        return (ev, 'if-true' if not in_else else 'if-false', pair, predicate)
                # Ternary nearby: prefer capturing condition if present around activity
                mt = TERNARY_PAREN_PAT.search(seg) or TERNARY_BARE_PAT.search(seg)
                if mt and (BASE_WRITE_PAT.search(seg) or SCHED_CALL_PAT.search(seg)):
                    tcond = mt.group('cond').strip()
                    return ('base slot (ternary nearby)', 'unknown-branch', None, tcond)
                j += 1
        # Alternate: anchor on call and search backward for a predicate nearby
        for k, ln in enumerate(lines):
            mc = SCHED_CALL_PAT.search(ln)
            if not mc:
                continue
            args = parse_args(mc.group('args'))
            calls_base, ev, pair = call_targets_base(args, lines[max(0, k-10):k+6], base_set, slot_vars)
            if not calls_base:
                continue
            # Look back up to 10 lines for an if(cond)
            pred = ''
            for j in range(max(0, k-10), k+1):
                mm = PRED_PAT.search(lines[j]) or PRED_NOBRACE_PAT.search(lines[j])
                if mm:
                    pred = mm.group('p').strip()
                else:
                    # As a fallback, extract a conditional expression pattern if present
                    me = COND_EXPR_PAT.search(lines[j])
                    if me and not pred:
                        pred = me.group(1).strip()
                if not pred:
                    mt = TERNARY_PAREN_PAT.search(lines[j]) or TERNARY_BARE_PAT.search(lines[j])
                    if mt:
                        pred = mt.group('cond').strip()
            return (ev, 'unknown-branch', pair, pred or '(nearby)')
        return None

    for cb2 in sorted(cb2_set):
        # Resolve cb2 to FUN_* if only label given
        cb2_fun = rev_labels.get(cb2, cb2)
        text = code_map.get(cb2, '') or code_map.get(cb2_fun, '')
        if not text:
            continue
        lines = text.splitlines()
        hit = find_in_lines(lines)
        if not hit:
            # Callee scan up to depth 2: look into helper functions this cb2 calls
            callees: List[str] = []
            seen: Set[str] = set([cb2])
            frontier: List[Tuple[str, int]] = []
            # depth 1
            for ln in lines:
                for m in CALLEE_PAT.finditer(ln):
                    name = m.group(1)
                    if name not in seen:
                        seen.add(name)
                        frontier.append((name, 1))
            # BFS up to depth 2
            while frontier and not hit:
                name, depth = frontier.pop(0)
                ctext = code_map.get(name, '')
                if ctext:
                    hit = find_in_lines(ctext.splitlines())
                if hit or depth >= 3:
                    continue
                # enqueue callees of this callee
                for ln in ctext.splitlines():
                    for m in CALLEE_PAT.finditer(ln):
                        nm = m.group(1)
                        if nm not in seen:
                            seen.add(nm)
                            frontier.append((nm, depth+1))
        if hit:
            ev, branch, pair, predicate = hit
            extra = ''
            if pair:
                extra = f" pair={pair[0]},{pair[1]}"
            results.append({
                'cb2': cb2,
                'predicate': f"[{branch}] {predicate}",
                'writer': cb2_fun,
                'evidence': ev + extra,
            })

    # Write CSV
    outp = EXP / 'crate_return_predicates.csv'
    with outp.open('w', encoding='utf-8', newline='') as f:
        wr = csv.DictWriter(f, fieldnames=['cb2','predicate','writer','evidence'])
        wr.writeheader()
        wr.writerows(results)

    print(f"Wrote {outp} ({len(results)} predicates)")


if __name__ == '__main__':
    scan_predicates()
