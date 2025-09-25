#!/usr/bin/env python3
import sys, struct, pathlib, argparse

def u32le(b, o): return struct.unpack_from("<I", b, o)[0]

def find_all(b, needle):
    pos = 0
    out = []
    while True:
        i = b.find(needle, pos)
        if i < 0: break
        out.append(i); pos = i+1
    return out

def parse_bind_at(data, bind_off, end_bound=None):
    """
    Parse one BIND container at absolute offset 'bind_off'.
    Returns (records, header_size, base_choice) where:
      records = list of dicts with fields: name, rel_off, abs_off, size
      header_size = 8 + N*0x28
      base_choice = 'file' or 'data' (offset base the parser used)
    """
    n = len(data)
    if end_bound is None: end_bound = n
    if bind_off + 8 > n: return [], 0, None
    if data[bind_off:bind_off+4] != b"BIND": return [], 0, None
    N = u32le(data, bind_off+4)
    header_size = 8 + N*0x28
    if bind_off + header_size > n: return [], header_size, None

    # read raw entries
    entries = []
    for i in range(N):
        eoff = bind_off+8+i*0x28
        name = data[eoff:eoff+0x20].split(b"\x00",1)[0].decode("ascii","ignore")
        rel  = u32le(data, eoff+0x20)
        size = u32le(data, eoff+0x24)   # already 4-byte padded per note
        entries.append((name, rel, size))

    # try two bases: offsets from file start (bind_off) OR from data area (bind_off+header_size)
    def score(base):
        ok = 0
        abs_entries = []
        for name, rel, size in entries:
            a = base + rel
            if a >= bind_off and a+size <= end_bound:
                ok += 1
            abs_entries.append((name, rel, size, a))
        return ok, abs_entries

    s_file, abs_file = score(bind_off)
    s_data, abs_data = score(bind_off + header_size)
    # pick the interpretation that keeps more entries in-bounds
    if s_data > s_file:
        choice = "data"; abs_entries = abs_data
    else:
        choice = "file"; abs_entries = abs_file

    # make records in order of rel_off (they should be increasing, 4-byte aligned)
    recs = []
    for (name, rel, size, a) in sorted(abs_entries, key=lambda x:x[1]):
        recs.append({"name": name or "", "rel_off": rel, "abs_off": a, "size": size})
    return recs, header_size, choice

def parse_all(path, extract=False, recurse=False, out_root=None):
    p = pathlib.Path(path)
    data = p.read_bytes()
    binds = find_all(data, b"BIND")
    # find container bounds as [BINDpos .. nextBINDpos) or EOF
    bounds = []
    for i, off in enumerate(binds):
        end = binds[i+1] if i+1 < len(binds) else len(data)
        bounds.append((off, end))

    # prep output
    if out_root is None:
        out_root = pathlib.Path.cwd() / "exports"
    out_root.mkdir(parents=True, exist_ok=True)
    idx_csv = out_root / (f"bind_index_{p.name}.csv")
    x_root = pathlib.Path.cwd() / "assets" / "extracted" / p.name
    if extract: x_root.mkdir(parents=True, exist_ok=True)

    # write CSV header
    with idx_csv.open("w", encoding="utf-8", newline="") as idx:
        idx.write("container_i,bind_off,base,entry_i,name,rel_off,abs_off,size\n")
        for ci, (boff, bend) in enumerate(bounds):
            if data[boff:boff+4] != b"BIND": continue
            recs, hdr_sz, base_choice = parse_bind_at(data, boff, bend)
            for ei, r in enumerate(recs):
                # index line
                idx.write(f"{ci},{boff},{base_choice},{ei},\"{r['name']}\",{r['rel_off']},{r['abs_off']},{r['size']}\n")
                # extraction
                if extract and r["abs_off"] is not None and r["size"]>0:
                    out_dir = x_root / f"container_{ci:04d}"
                    out_dir.mkdir(parents=True, exist_ok=True)
                    # sanitize filename; fall back if blank
                    fname = r["name"].strip("\\/") or f"file_{ei:05d}.bin"
                    safe = "".join(ch if ch.isalnum() or ch in "._- " else "_" for ch in fname)
                    (out_dir / safe).write_bytes(data[r["abs_off"]:r["abs_off"]+r["size"]])
                    # recurse into nested .BND if requested
                    if recurse and safe.lower().endswith(".bnd"):
                        try:
                            parse_all(out_dir / safe, extract=True, recurse=True, out_root=out_root)
                        except Exception as e:
                            pass
    return str(idx_csv), (str(x_root) if extract else None)

def main():
    ap = argparse.ArgumentParser(description="Team Buddies BIND/BND parser")
    ap.add_argument("input", help="Path to BUDDIES.DAT or any .BND")
    ap.add_argument("--extract", action="store_true", help="Extract files")
    ap.add_argument("--recurse", action="store_true", help="Also parse nested .BND inside extracted files")
    args = ap.parse_args()
    idx, xroot = parse_all(args.input, extract=args.extract, recurse=args.recurse)
    print("Index CSV:", idx)
    if xroot: print("Extracted to:", xroot)

if __name__ == "__main__":
    main()
