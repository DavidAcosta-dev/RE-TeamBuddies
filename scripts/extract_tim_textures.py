#!/usr/bin/env python3
"""
Quick TIM extractor: scans known TIM containers and standalone TIMs, exports PNGs.

Sources scanned:
- assets/TeamBuddiesGameFiles/** (TIM.BND, .TIM, or embedded TIM blocks if present)
- exports/ (optional staging)

Outputs:
- exports/assets/textures/*.png with sidecar JSON for metadata.

Limitations:
- Supports most 4/8/16/24-bit TIMs with CLUT. PS1 TIM layout: header 0x10, bpp flag, CLUT block optional.
- BND parsing: relies on existing bind_index_*.csv when available; falls back to naive scan for TIM magic 0x10 00 00 00.
"""
import os, struct, json, sys
from pathlib import Path
import argparse

ROOT = Path(os.path.expanduser('~')) / 'tb-re'
ASSETS = ROOT / 'assets' / 'TeamBuddiesGameFiles'
EXPORTS = ROOT / 'exports'
OUTDIR = EXPORTS / 'assets' / 'textures'
OUTDIR.mkdir(parents=True, exist_ok=True)

try:
    from PIL import Image
except Exception:
    Image = None

TIM_MAGIC = 0x00000010

def read_u32(b, off):
    return struct.unpack_from('<I', b, off)[0]

def parse_tim(buf):
    # Returns (image, meta) or (None, meta) if unsupported
    # TIM: magic(4)=0x10, flags(4), then CLUT block(optional), then image block
    if len(buf) < 12:
        return None, {"error":"too short"}
    magic = read_u32(buf, 0)
    if magic != TIM_MAGIC:
        return None, {"error":"bad magic"}
    flags = read_u32(buf, 4)
    has_clut = (flags & 0x08) != 0
    bpp_code = flags & 0x07
    off = 8
    clut = None
    if has_clut:
        clut_len = read_u32(buf, off)
        clut_data = buf[off:off+4+clut_len]
        off += 4 + clut_len
        # CLUT data layout: size, x, y, w, h, then color entries (16-bit BGR555)
        if len(clut_data) >= 12:
            _, cx, cy, cw, ch = struct.unpack_from('<IHHHH', clut_data, 0)
            colors_raw = clut_data[12:]
            # Decode 15-bit BGR -> RGBA
            colors = []
            for i in range(0, len(colors_raw), 2):
                if i+1 >= len(colors_raw):
                    break
                v = struct.unpack_from('<H', colors_raw, i)[0]
                r = (v & 0x1F) << 3
                g = ((v >> 5) & 0x1F) << 3
                b = ((v >> 10) & 0x1F) << 3
                # Treat index 0 (all zero) as transparent by convention
                a = 0 if v == 0 else 255
                colors.append((r, g, b, a))
            clut = {
                'x': cx, 'y': cy, 'w': cw, 'h': ch,
                'colors': colors
            }
    if off+4 > len(buf):
        return None, {"error":"no image block"}
    img_len = read_u32(buf, off)
    img_data = buf[off:off+4+img_len]
    if len(img_data) < 12:
        return None, {"error":"img block short"}
    _, ix, iy, iw, ih = struct.unpack_from('<IHHHH', img_data, 0)
    pixels = img_data[12:]
    meta = {'w': iw, 'h': ih, 'bpp_code': bpp_code, 'has_clut': has_clut}
    if Image is None:
        return None, {**meta, 'warning':'Pillow not installed'}
    # Decode pixel indices based on bpp
    if bpp_code == 0:  # 4bpp indexed
        # Two pixels per byte
        if not clut:
            return None, {**meta, 'error':'missing CLUT for 4bpp'}
        palette = clut['colors']
        img = Image.new('RGBA', (iw, ih))
        px = img.load()
        idx = 0
        for y in range(ih):
            for x in range(0, iw, 2):
                b = pixels[idx]; idx += 1
                i0 = b & 0x0F
                i1 = (b >> 4) & 0x0F
                px[x, y] = palette[i0 % len(palette)]
                if x+1 < iw:
                    px[x+1, y] = palette[i1 % len(palette)]
        return img, meta
    elif bpp_code == 1:  # 8bpp indexed
        if not clut:
            return None, {**meta, 'error':'missing CLUT for 8bpp'}
        palette = clut['colors']
        img = Image.new('RGBA', (iw, ih))
        px = img.load()
        idx = 0
        for y in range(ih):
            for x in range(iw):
                i = pixels[idx]; idx += 1
                px[x, y] = palette[i % len(palette)]
        return img, meta
    elif bpp_code == 2:  # 16bpp BGR555
        img = Image.new('RGBA', (iw, ih))
        px = img.load()
        idx = 0
        for y in range(ih):
            for x in range(iw):
                if idx+1 >= len(pixels):
                    break
                v = struct.unpack_from('<H', pixels, idx)[0]
                idx += 2
                r = (v & 0x1F) << 3
                g = ((v >> 5) & 0x1F) << 3
                b = ((v >> 10) & 0x1F) << 3
                a = 0 if v == 0 else 255
                px[x, y] = (r, g, b, a)
        return img, meta
    else:
        return None, {**meta, 'error':'unsupported bpp'}

def iter_magic_offsets(path, magic=b"\x10\x00\x00\x00", chunk_size=1024*1024):
    # Efficiently scan a file for the TIM magic using chunked reads with overlap
    size = path.stat().st_size
    with path.open('rb') as f:
        overlap = len(magic) - 1
        pos = 0
        prev = b''
        while pos < size:
            f.seek(pos)
            chunk = f.read(chunk_size)
            if not chunk:
                break
            data = prev + chunk
            start = 0
            while True:
                idx = data.find(magic, start)
                if idx == -1:
                    break
                abs_off = pos - len(prev) + idx
                yield abs_off
                start = idx + 1
            # prepare overlap
            if len(chunk) >= overlap:
                prev = chunk[-overlap:]
            else:
                prev = chunk
            pos += len(chunk)

def read_tim_blob(path, offset):
    # Reads just enough bytes for one TIM starting at offset.
    with path.open('rb') as f:
        f.seek(offset)
        head = f.read(8)
        if len(head) < 8:
            return None
        magic, flags = struct.unpack('<II', head)
        if magic != TIM_MAGIC:
            return None
        total = 8
        parts = [head]
        has_clut = (flags & 0x08) != 0
        if has_clut:
            sz_b = f.read(4)
            if len(sz_b) < 4:
                return None
            (clut_len,) = struct.unpack('<I', sz_b)
            clut_block = sz_b + f.read(clut_len)
            parts.append(clut_block)
            total += 4 + len(clut_block) - 4
        sz_b = f.read(4)
        if len(sz_b) < 4:
            return None
        (img_len,) = struct.unpack('<I', sz_b)
        img_block = sz_b + f.read(img_len)
        parts.append(img_block)
        total += 4 + len(img_block) - 4
        return b''.join(parts)

def find_tim_blobs(roots, max_per_file=200, include_exts=None, exclude_exts=None, max_file_size=None, name_contains=None, verbose=False):
    """Stream scan for TIM magic in relevant files and read exact blobs.

    roots: list[Path] to scan under
    include_exts: set like {'.tim', '.bnd', '.dat'}; if None, all files included
    exclude_exts: set like {'.bin'} to skip
    max_file_size: int bytes; if set, skip files larger than this
    name_contains: optional uppercase substring to include (e.g., 'TIM')
    """
    include_exts = {e.lower() for e in (include_exts or set())}
    exclude_exts = {e.lower() for e in (exclude_exts or set())}
    for root in roots:
        for p in root.rglob('*'):
            if not p.is_file():
                continue
            ext = p.suffix.lower()
            if exclude_exts and ext in exclude_exts:
                continue
            if include_exts and (ext not in include_exts) and (not (name_contains and name_contains in p.name.upper())):
                continue
            try:
                size = p.stat().st_size
            except Exception:
                continue
            if max_file_size is not None and size > max_file_size:
                if verbose:
                    print(f"skip (size>{max_file_size}): {p} ({size} bytes)")
                continue
            if verbose:
                print(f"scan: {p} ({size} bytes)")
            found = 0
            try:
                for off in iter_magic_offsets(p):
                    blob = read_tim_blob(p, off)
                    if blob:
                        yield (p, off, blob)
                        found += 1
                        if found >= max_per_file:
                            if verbose:
                                print(f"limit per-file reached: {p}")
                            break
            except KeyboardInterrupt:
                raise
            except Exception as e:
                if verbose:
                    print(f"error scanning {p}: {e}")
                continue

def main(argv=None):
    parser = argparse.ArgumentParser(description="Extract TIM textures to PNG")
    parser.add_argument('--root', action='append', help='Root folder(s) to scan', default=[str(ASSETS)])
    parser.add_argument('--include-ext', help='Comma-separated extensions to include (e.g. .tim,.bnd,.dat)', default='.tim,.bnd,.dat')
    parser.add_argument('--exclude-ext', help='Comma-separated extensions to exclude (e.g. .bin)', default='.bin')
    parser.add_argument('--max-file-size-mb', type=int, default=64, help='Skip files larger than this many MB (default 64)')
    parser.add_argument('--max-per-file', type=int, default=200, help='Max TIMs to extract per file')
    parser.add_argument('--limit-total', type=int, default=0, help='Stop after extracting this many images (0 = no limit)')
    parser.add_argument('--verbose', action='store_true', help='Verbose scan logging')
    args = parser.parse_args(argv)

    roots = [Path(r) for r in args.root]
    include_exts = {e.strip() for e in args.include_ext.split(',') if e.strip()}
    exclude_exts = {e.strip() for e in args.exclude_ext.split(',') if e.strip()}
    max_file_size = args.max_file_size_mb * 1024 * 1024 if args.max_file_size_mb and args.max_file_size_mb > 0 else None

    count = 0
    scanned = 0
    for p, off, blob in find_tim_blobs(
        roots=roots,
        max_per_file=args.max_per_file,
        include_exts=include_exts,
        exclude_exts=exclude_exts,
        max_file_size=max_file_size,
        name_contains='TIM',
        verbose=args.verbose,
    ):
        scanned += 1
        img, meta = parse_tim(blob)
        base = f"{p.stem}_{off:08x}"
        sidecar = OUTDIR / f"{base}.json"
        if img is not None and Image is not None:
            outp = OUTDIR / f"{base}.png"
            try:
                img.save(outp)
                count += 1
                meta.update({'source': str(p), 'offset': off, 'output': str(outp)})
            except Exception as e:
                meta.update({'error': f'png_save_failed: {e}'})
        else:
            meta.update({'source': str(p), 'offset': off})
        sidecar.write_text(json.dumps(meta, indent=2), encoding='utf-8')
        if args.limit_total and count >= args.limit_total:
            if args.verbose:
                print("global limit reached; stopping")
            break
    print(f"Scanned {scanned} TIM blocks; extracted {count} images to {OUTDIR}")

if __name__ == '__main__':
    main()
