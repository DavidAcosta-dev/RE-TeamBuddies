# Applies names to a single program in the Ghidra project using ApplyNamesFromCSV.py
param(
    [string]$Program = "MAIN.EXE",
    [string]$Csv = "exports/rename_review.csv"
)

$ErrorActionPreference = 'Stop'

# Resolve repo root (scripts/..)
$RepoRoot = Split-Path -Parent $PSScriptRoot

# Paths
$Headless = Join-Path $RepoRoot 'ghidra_11.4.2_PUBLIC/support/analyzeHeadless.bat'
$ProjectDir = Join-Path $RepoRoot 'ghidra_proj'
$ProjectName = 'TBProject'
$ScriptPath = Join-Path $RepoRoot 'ghidra_scripts/ApplyNamesFromCSV.py'
$CsvPath = if ([System.IO.Path]::IsPathRooted($Csv)) { $Csv } else { Join-Path $RepoRoot $Csv }
$LogDir = Join-Path $RepoRoot 'exports'
$null = New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogPath = Join-Path $LogDir ("apply_names_" + ($Program -replace "[^A-Za-z0-9_.-]", "_") + ".log")

Write-Host "[apply_names_one] Program=$Program"
Write-Host "[apply_names_one] CSV=$CsvPath"
Write-Host "[apply_names_one] Headless=$Headless"

if (-not (Test-Path $Headless)) { throw "Headless launcher not found: $Headless" }
if (-not (Test-Path $ProjectDir)) { throw "Project dir not found: $ProjectDir" }
if (-not (Test-Path $ScriptPath)) { throw "Ghidra script not found: $ScriptPath" }
if (-not (Test-Path $CsvPath)) { throw "CSV not found: $CsvPath" }

& $Headless `
    $ProjectDir `
    $ProjectName `
    -process $Program `
    -postScript $ScriptPath $CsvPath `
    -scriptlog $LogPath

if ($LASTEXITCODE -ne 0) {
    Write-Error "Headless apply exited with code $LASTEXITCODE. See log: $LogPath"
    exit $LASTEXITCODE
}

Write-Host "[apply_names_one] Done. Log: $LogPath"

