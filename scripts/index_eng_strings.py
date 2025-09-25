from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ROOT / "exports"


def load_strings(fname: Path):
    with fname.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            # Expect format: offset: string (from our extractor) OR plain string list; handle both
            m = re.match(r"^(0x[0-9a-fA-F]+)\s*:\s*(.*)$", line)
            if m:
                off = int(m.group(1), 16)
                s = m.group(2)
                yield off, s
            else:
                yield None, line


def categorize(s: str) -> str:
    t = s.strip().lower()
    if len(t) <= 1:
        return "short"
    if any(k in t for k in ["press ", "button", "controller", "move", "jump", "shoot", "fire", "pickup", "drop", "kick"]):
        return "tutorial_ui"
    if any(k in t for k in ["options", "start", "pause", "continue", "quit", "select", "game over", "memory card", "load", "save"]):
        return "menu_ui"
    if any(k in t for k in ["map", "zone", "team", "buddy", "ammo", "weapon", "build", "crate", "factory", "flag"]):
        return "game_terms"
    if any(k in t for k in ["%d", "%s", "%f"]):
        return "printf"
    if re.match(r"^[A-Za-z0-9_\- ]+$", s) and len(s) < 24:
        return "label"
    return "other"


def main():
    inp = EXPORTS / "eng_ascii_l1.txt"
    if not inp.exists():
        # fallback to ascii
        inp = EXPORTS / "eng_ascii.txt"
    out_csv = EXPORTS / "eng_index.csv"

    rows = []
    for off, s in load_strings(inp):
        cat = categorize(s)
        rows.append((off, cat, s))

    with out_csv.open("w", encoding="utf-8", newline="") as f:
        f.write("offset,category,string\n")
        for off, cat, s in rows:
            off_s = "" if off is None else hex(off)
            s_clean = s.replace("\"", "'").replace(",", " ")
            f.write(f"{off_s},{cat},{s_clean}\n")

    print(f"Wrote {out_csv} with {len(rows)} rows")


if __name__ == "__main__":
    main()
