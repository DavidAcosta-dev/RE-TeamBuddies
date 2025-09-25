# Full RE pipeline runner: export bundles -> merge -> score -> analyze callgraph
# Usage: pwsh -File scripts/re_pipeline.ps1
$ErrorActionPreference = 'Stop'

Write-Host "[1/4] Exporting bundles via Ghidra headless" -ForegroundColor Cyan
powershell -NoProfile -ExecutionPolicy Bypass -File "$PSScriptRoot\export_bundles.ps1"

Write-Host "[2/4] Merging bundles" -ForegroundColor Cyan
python "$PSScriptRoot\merge_bundles.py"

Write-Host "[3/4] Scoring functions and generating suspects/bookmarks" -ForegroundColor Cyan
python "$PSScriptRoot\parse_bundle.py" "$HOME/tb-re/exports/bundle_ghidra.jsonl"

Write-Host "[4/4] Callgraph hub analysis" -ForegroundColor Cyan
python "$PSScriptRoot\analyze_callgraph.py" "$HOME/tb-re/exports/bundle_ghidra.jsonl"

Write-Host "Pipeline complete. Outputs in $HOME/tb-re/exports" -ForegroundColor Green
