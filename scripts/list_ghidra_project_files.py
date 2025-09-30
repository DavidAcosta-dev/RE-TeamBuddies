from pathlib import Path
import re

INDEX_PATH = Path(r"c:/Users/Acost/tb-re/ghidra_proj/TBProject.rep/versioned/~index.dat")

if not INDEX_PATH.exists():
    raise SystemExit("Index file missing; did the project move?")

def extract_strings(data: bytes) -> list[str]:
    matches = re.finditer(rb"[\x20-\x7e]{5,}", data)
    out = []
    for match in matches:
        text = match.group().decode("ascii", "ignore")
        if not any(ch.isalpha() for ch in text):
            continue
        out.append(text)
    return out

def main() -> None:
    data = INDEX_PATH.read_bytes()
    strings = extract_strings(data)
    for text in strings:
        print(text)

if __name__ == "__main__":
    main()
