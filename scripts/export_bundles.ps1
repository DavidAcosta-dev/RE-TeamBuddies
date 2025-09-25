# Export per-function JSONL bundles from Ghidra headless for key Team Buddies binaries
# Usage: pwsh -File scripts/export_bundles.ps1
$ErrorActionPreference = 'Stop'

# Locate analyzeHeadless.bat if not already set
if (-not $env:GHIDRA -or -not (Test-Path -LiteralPath $env:GHIDRA)) {
    $defaultAnalyze = Join-Path $env:USERPROFILE 'Downloads\ghidra_11.4.2_PUBLIC_20250826\ghidra_11.4.2_PUBLIC\support\analyzeHeadless.bat'
    if (Test-Path -LiteralPath $defaultAnalyze) {
        $env:GHIDRA = $defaultAnalyze
    }
    else {
        $cand = Get-ChildItem -Path (Join-Path $env:USERPROFILE 'Downloads') -Filter 'analyzeHeadless.bat' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cand) { $env:GHIDRA = $cand.FullName } else { throw 'Could not locate analyzeHeadless.bat. Set $env:GHIDRA to the full path.' }
    }
}
Write-Host "Using GHIDRA: $env:GHIDRA"

$root = "$HOME/tb-re"
$proj = "$root/ghidra_proj"
$scriptPath = "$root/ghidra_scripts"

# Focus on EXE files first to avoid occasional analyzer crashes on raw BIN overlays
$files = @(
    "$root/assets/TeamBuddiesGameFiles/LEGGIT.EXE",
    "$root/assets/TeamBuddiesGameFiles/MAIN.EXE",
    "$root/assets/TeamBuddiesGameFiles/Team buddies demo/PSX.EXE",
    "$root/assets/TeamBuddiesGameFiles/Team buddies demo/LEGGIT.EXE",
    "$root/assets/TeamBuddiesGameFiles/Team buddies demo/MAIN.EXE"
)

foreach ($f in $files) {
    if (Test-Path -LiteralPath $f) {
        Write-Host "Exporting bundle for $(Split-Path $f -Leaf) from $f" -ForegroundColor Cyan
        & $env:GHIDRA "$proj" "TBProject" -import "$f" -overwrite -processor "MIPS:LE:32:default" -analysisTimeoutPerFile 180 `
            -scriptPath "$scriptPath" -postScript ExportRE_Multi.py
    }
    else {
        Write-Warning "Missing file: $f"
    }
}

Write-Host "Export complete. Bundles should be in $HOME/tb-re/exports as bundle_<PROGRAM>.jsonl"
