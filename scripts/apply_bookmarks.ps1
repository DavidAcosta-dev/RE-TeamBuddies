# Re-apply suspect bookmarks across all key Team Buddies binaries via Ghidra headless
# Usage: pwsh -File scripts/apply_bookmarks.ps1
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

$files = @(
    "$root/assets/TeamBuddiesGameFiles/GAME.BIN",
    "$root/assets/TeamBuddiesGameFiles/LEGGIT.EXE",
    "$root/assets/TeamBuddiesGameFiles/MAIN.EXE",
    "$root/assets/TeamBuddiesGameFiles/MNU.BIN",
    "$root/assets/TeamBuddiesGameFiles/MPLR.BIN",
    "$root/assets/TeamBuddiesGameFiles/ROT.BIN",
    "$root/assets/TeamBuddiesGameFiles/SYS.BIN",
    "$root/assets/TeamBuddiesGameFiles/TUTO.BIN",
    "$root/assets/TeamBuddiesGameFiles/Team buddies demo/PSX.EXE",
    "$root/assets/TeamBuddiesGameFiles/Team buddies demo/LEGGIT.EXE",
    "$root/assets/TeamBuddiesGameFiles/Team buddies demo/MAIN.EXE"
)

foreach ($f in $files) {
    if (Test-Path -LiteralPath $f) {
        Write-Host "Applying bookmarks for $(Split-Path $f -Leaf) from $f" -ForegroundColor Cyan
        & $env:GHIDRA "$proj" "TBProject" -import "$f" -overwrite -processor "MIPS:LE:32:default" -analysisTimeoutPerFile 120 -scriptPath "$scriptPath" -postScript BookmarkSuspects.py
    }
    else {
        Write-Warning "Missing file: $f"
    }
}
