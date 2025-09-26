# Ghidra Scripts – Team Buddies RE

This folder contains helper scripts to speed up UI tagging in Ghidra.

- ImportCommentsFromCSV.py
  - Imports EOL and plate comments from `../exports/ghidra_comments.csv`.
  - Filters rows by the current program name (endswith match on `binary`).
- ApplyNamesFromBookmarks.py
  - Reads `../exports/suspects_bookmarks.json` and applies `new_name` entries
    to the current program. Uses function rename when possible, otherwise a
    user label at the address.
- ApplyNamesFromCSV.py
  - Reads `../exports/rename_review.csv` and applies only rows with `apply=1`.
  - Use this for a vetted, spreadsheet-based review of suggested names.

Outside Ghidra these scripts no-op safely for linting. In Ghidra, run via the
Script Manager with the target program open (e.g., GAME.BIN or MAIN.EXE).

## Review Flow

1) Generate the review CSV:
   - In the repo root:
     - `python scripts/generate_rename_review.py`
   - Edit `exports/rename_review.csv` and set `apply=1` for rows you want.
2) In Ghidra, run `ApplyNamesFromCSV.py` to apply those names.
3) Optional: run `ImportCommentsFromCSV.py` for inline comments.
4) Re-export bundles so downstream reports pick up the updated names.

Notes:

- Paths are resolved relative to this folder; keep `exports/` at repo root.
- The JSON/CSV files are produced by the Python scanners in `scripts/`.
