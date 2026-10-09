#Requires -Version 5.1

<#
.SYNOPSIS
Combines multiple Autopilot hardware-hash CSVs into one de-duplicated CSV.

.DESCRIPTION
Reads every *.csv in the input folder, de-duplicates on "Device Serial Number" and writes one combined CSV
ready to import into Intune/Autopilot. The combined file is written to the output folder, not the input
folder, so re-running never re-reads an earlier result.

.PARAMETER InputPath
Folder containing the individual hash CSVs (e.g. from Get-WindowsAutopilotInfo).

.PARAMETER OutputPath
Folder for the combined CSV. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER KeyColumn
Column used to de-duplicate. Default "Device Serial Number".

.EXAMPLE
.\Merge-AutopilotHashCsv.ps1 -InputPath D:\Autopilot\Incoming -OutputPath D:\Reports

.EXAMPLE
.\Merge-AutopilotHashCsv.ps1 -InputPath D:\Autopilot\Incoming -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (works on macOS with PowerShell 7)
Permissions:  None (file access only)
When to use:  After collecting hardware hashes from several devices, before the Intune Autopilot import.
Safety:       Read-only on inputs; writes one new file
Version:      1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })][string]$InputPath,
    [string]$OutputPath,
    [string]$CustomerName,
    [string]$KeyColumn = 'Device Serial Number'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-OutputPath {
    param([string]$Path, [string]$CustomerName)
    if (-not $Path) { $Path = $env:TOOLBOX_REPORT_DIR }
    if (-not $Path) { $Path = Read-Host 'Output folder for reports' }
    if (-not $Path) { throw 'An output path is required.' }
    if ($CustomerName) { $Path = Join-Path $Path $CustomerName }
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    (Resolve-Path -LiteralPath $Path).Path
}

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 's'), $Level, $Message
    Write-Host $line
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $line }
}

$stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$csvPath = Join-Path $outDir "Merge-AutopilotHashCsv_$stamp.csv"
$script:LogFile = Join-Path $outDir "Merge-AutopilotHashCsv_$stamp.log"

try {
    $files = @(Get-ChildItem -LiteralPath $InputPath -Filter *.csv -File)
    if ($files.Count -eq 0) { throw "No CSV files found in $InputPath." }
    Write-Log "Merging $($files.Count) file(s)..."

    $rows = $files | ForEach-Object { Import-Csv -LiteralPath $_.FullName }
    $merged = @($rows | Sort-Object $KeyColumn -Unique)
    Write-Log "$(@($rows).Count) row(s) in, $($merged.Count) unique by '$KeyColumn'."

    $merged | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "Combined file written: $csvPath"
}
catch {
    Write-Log "Merge failed: $_" 'ERROR'
    throw
}
