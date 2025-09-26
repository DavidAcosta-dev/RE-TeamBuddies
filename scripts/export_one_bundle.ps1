# Exports bundle_<program>.jsonl for a single program using ExportRE_Multi.py
param(
    [string]$Program = "MAIN.EXE"
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Headless = Join-Path $RepoRoot 'ghidra_11.4.2_PUBLIC/support/analyzeHeadless.bat'
$ProjectDir = Join-Path $RepoRoot 'ghidra_proj'
$ProjectName = 'TBProject'
$ScriptPath = Join-Path $RepoRoot 'ghidra_scripts/ExportRE_Multi.py'
$LogDir = Join-Path $RepoRoot 'exports'
$null = New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogPath = Join-Path $LogDir ("export_" + ($Program -replace "[^A-Za-z0-9_.-]", "_") + ".log")

Write-Host "[export_one_bundle] Program=$Program"
Write-Host "[export_one_bundle] Headless=$Headless"

if (-not (Test-Path $Headless)) { throw "Headless launcher not found: $Headless" }
if (-not (Test-Path $ProjectDir)) { throw "Project dir not found: $ProjectDir" }
if (-not (Test-Path $ScriptPath)) { throw "Ghidra script not found: $ScriptPath" }

& $Headless `
    $ProjectDir `
    $ProjectName `
    -process $Program `
    -postScript $ScriptPath `
    -scriptlog $LogPath

if ($LASTEXITCODE -ne 0) {
    Write-Error "Headless export exited with code $LASTEXITCODE. See log: $LogPath"
    exit $LASTEXITCODE
}

Write-Host "[export_one_bundle] Done. Log: $LogPath"

