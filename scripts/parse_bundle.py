#!/usr/bin/env python3
import sys, json, os, re, csv, collections

IN = sys.argv[1] if len(sys.argv)>1 else "exports/bundle_ghidra.jsonl"
OUT_DIR = "exports"
os.makedirs(OUT_DIR, exist_ok=True)

funcs = []
with open(IN, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line=line.strip()
        if line:
            try: funcs.append(json.loads(line))
            except: pass

# PSYQ/controller-related tokens (functions, strings, libs)
CTRL_RE = re.compile(r'\b(Pad(Read|Init|Open|Close|Info|Raw|Flags)?|PAD(open|poll|start|stop|dr)?|libpad|controller|dualshock|rumble|button|input|dead\s*zone|analog|haptic|vibration|sio|SIO|pad\s*state)\b', re.IGNORECASE)
# Physics/movement/game-loop tokens
PHYS_RE = re.compile(r'gravity|jump|vel(ocity)?|accel|decel|friction|speed|air|strafe|throw|kick|move|rcnt|vsync|timer|dt|delta\s*time|frame', re.IGNORECASE)

def binary_of(rec):
    return (rec.get("binary") or "").strip()

rows = []
perbin = collections.defaultdict(list)
for rec in funcs:
    fn = rec.get("function",{})
    name = fn.get("name","")
    ea   = fn.get("ea",0)
    size = fn.get("size",0)
    dec  = rec.get("decompilation") or ""
    strings = " ".join(s.get("text","") for s in rec.get("strings_used",[]))
    text = " ".join([name, dec, strings])
    row = {
        "name": name, "ea": ea, "size": size,
        "callers_n": len(rec.get("callers",[])),
        "callees_n": len(rec.get("callees",[])),
        "ctrl_hit": 1 if CTRL_RE.search(text) else 0,
        "phys_hit": 1 if PHYS_RE.search(text) else 0,
        "binary": binary_of(rec)
    }
    rows.append(row)
    perbin[row["binary"]].append(row)

out_csv = os.path.join(OUT_DIR, "functions_scored.csv")
with open(out_csv, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["name"])
    w.writeheader()
    for r in rows: w.writerow(r)

rows.sort(key=lambda r:(r["ctrl_hit"]+r["phys_hit"], r["callees_n"]+r["callers_n"], r["size"]), reverse=True)
out_top = os.path.join(OUT_DIR, "suspects_top50.csv")
with open(out_top, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["name"])
    w.writeheader()
    for r in rows[:50]: w.writerow(r)

print("Wrote: " + out_csv + " and " + out_top)

# Per-binary top lists
for bname, blist in perbin.items():
    if not blist:
        continue
    blist.sort(key=lambda r:(r["ctrl_hit"]+r["phys_hit"], r["callees_n"]+r["callers_n"], r["size"]), reverse=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", bname or "unknown")
    outb = os.path.join(OUT_DIR, f"suspects_top50_{safe}.csv")
    with open(outb, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(blist[0].keys()))
        w.writeheader()
        for r in blist[:50]:
            w.writerow(r)

# Also emit a machine-friendly JSON for Ghidra bookmarking
# Each entry can include optional fields used by BookmarkSuspects.py enhancements:
#   category: "controller" | "physics" | None
#   tags: ["controller", "physics"]
#   score: simple heuristic sum of hits and degree (for display only)
top_for_bookmarks = {}
for b, v in perbin.items():
    ranked = sorted(v, key=lambda r:(r["ctrl_hit"]+r["phys_hit"], r["callees_n"]+r["callers_n"], r["size"]), reverse=True)[:100]
    enriched = []
    for r in ranked:
        tags = []
        if r["ctrl_hit"]:
            tags.append("controller")
        if r["phys_hit"]:
            tags.append("physics")
        category = tags[0] if tags else None
        score = (r["ctrl_hit"] + r["phys_hit"]) * 10 + (r["callees_n"] + r["callers_n"]) + max(0, (r["size"] // 50))
        # Suggest a new name based on category to aid quick triage; keep original as suffix
        prefix = "suspect"
        if category == "controller":
            prefix = "ctrl"
        elif category == "physics":
            prefix = "phys"
        new_name = f"{prefix}_{r['name']}"
        enriched.append({
            "name": r["name"],
            "ea": r["ea"],
            "category": category,
            "tags": tags,
            "score": score,
            "new_name": new_name
        })
    top_for_bookmarks[b] = enriched

with open(os.path.join(OUT_DIR, "suspects_bookmarks.json"), "w", encoding="utf-8") as f:
    json.dump(top_for_bookmarks, f, ensure_ascii=False, indent=2)
