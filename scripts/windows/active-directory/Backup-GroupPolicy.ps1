#Requires -Version 5.1
#Requires -Modules GroupPolicy

<#
.SYNOPSIS
Backs up all (or selected) Group Policy Objects and writes an HTML backup report.

.DESCRIPTION
Enumerates GPOs in the current domain (all of them, or only those named in -GpoDisplayNames) and runs
Backup-Gpo for each one into a timestamped backup folder. The HTML report lists every GPO with its backup status,
backup location (relative to the backup folder), duration and last-modified time, plus success/failure totals.
Optionally an XML manifest of the results is written into the backup folder. The backup folder and the report are
created under the resolved output folder; nothing in Active Directory is changed.

.PARAMETER OutputPath
Folder for the report and backup folder. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER BackupPath
Optional. Folder to hold the GPO backups. Defaults to <output folder>\Backup-GroupPolicy_<timestamp>_Backup.

.PARAMETER GpoDisplayNames
Optional. One or more GPO display names to back up. Default is every GPO in the domain.

.PARAMETER IncludeXmlReport
Also write backup_manifest.xml (Export-Clixml of the results) into the backup folder.

.EXAMPLE
.\Backup-GroupPolicy.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Backup-GroupPolicy.ps1 -OutputPath D:\Reports -CustomerName Contoso -GpoDisplayNames 'Default Domain Policy','Workstation Baseline' -IncludeXmlReport

.NOTES
Platform:     Windows (RSAT GroupPolicy module, domain-joined machine)
Permissions:  Domain user with read access to GPOs (Group Policy Creator Owners or Domain Admin recommended for full coverage)
When to use:  Before changing GPOs, before a domain migration, or as a scheduled safety copy of all policies.
Safety:       Read-only
Version:      1.0
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$CustomerName,
    [string]$BackupPath,
    [string[]]$GpoDisplayNames,
    [switch]$IncludeXmlReport
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

$stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir  = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$htmlPath = Join-Path $outDir "Backup-GroupPolicy_$stamp.html"
$script:LogFile = Join-Path $outDir "Backup-GroupPolicy_$stamp.log"

if (-not $BackupPath) { $BackupPath = Join-Path $outDir "Backup-GroupPolicy_${stamp}_Backup" }

try {
    Import-Module GroupPolicy -ErrorAction Stop

    if (-not (Test-Path -LiteralPath $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    }

    if ($GpoDisplayNames) {
        $GPOs = @($GpoDisplayNames | ForEach-Object {
            $found = Get-Gpo -Name $_ -ErrorAction SilentlyContinue
            if (-not $found) { Write-Log "GPO not found: $_" 'WARN' }
            $found
        } | Where-Object { $null -ne $_ })
    } else {
        $GPOs = @(Get-Gpo -All)
    }
    Write-Log "Backing up $($GPOs.Count) GPO(s) to $BackupPath"

    $BackupResults = @(foreach ($GPO in $GPOs) {
        $StartTime = Get-Date
        try {
            $Backup = Backup-Gpo -Guid $GPO.Id -Path $BackupPath -Domain $GPO.Domain -Server ($GPO.Domain.Split('.')[0]) -ErrorAction Stop
            $Duration = (Get-Date) - $StartTime
            [PSCustomObject]@{
                GpoName       = $GPO.DisplayName
                GpoId         = $GPO.Id
                Status        = "Success"
                BackupPath    = $Backup.BackupDirectory
                BackupId      = $Backup.Id
                Duration      = "$([math]::Round($Duration.TotalSeconds, 2))s"
                Owner         = $GPO.Owner
                Created       = $GPO.CreationTime
                Modified      = $GPO.ModificationTime
                Error         = ""
            }
        } catch {
            Write-Log "Backup failed for '$($GPO.DisplayName)': $($_.Exception.Message)" 'WARN'
            [PSCustomObject]@{
                GpoName       = $GPO.DisplayName
                GpoId         = $GPO.Id
                Status        = "Failed"
                BackupPath    = ""
                BackupId      = ""
                Duration      = "N/A"
                Owner         = $GPO.Owner
                Created       = $GPO.CreationTime
                Modified      = $GPO.ModificationTime
                Error         = $_.Exception.Message
            }
        }
    })

    $SuccessCount = @($BackupResults | Where-Object { $_.Status -eq "Success" }).Count
    $FailCount = @($BackupResults | Where-Object { $_.Status -eq "Failed" }).Count

    $BackupPathPattern = [regex]::Escape($BackupPath)
    $HtmlRows = $BackupResults | ForEach-Object {
        $RowClass = if ($_.Status -eq "Failed") { "class='danger'" } else { "" }
        "<tr $RowClass>
        <td>$($_.GpoName)</td>
        <td>$($_.Status)</td>
        <td>$($_.BackupPath -replace $BackupPathPattern, '.')</td>
        <td>$($_.Duration)</td>
        <td>$($_.Modified)</td>
    </tr>"
    }

    $Html = @"
<!DOCTYPE html>
<html>
<head><title>GPO Backup Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 6px 8px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
</style></head>
<body>
<h1>GPO Backup Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</h1>
<div class='summary'>
    <strong>Backup Path:</strong> $BackupPath<br>
    <strong>Total GPOs:</strong> $($BackupResults.Count) |
    <strong>Success:</strong> $SuccessCount |
    <strong>Failed:</strong> $FailCount
</div>
<table>
<tr><th>GPO Name</th><th>Status</th><th>Backup Path</th><th>Duration</th><th>Modified</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

    $Html | Out-File -LiteralPath $htmlPath -Encoding UTF8

    if ($IncludeXmlReport) {
        $BackupResults | Export-Clixml -LiteralPath (Join-Path $BackupPath 'backup_manifest.xml')
    }

    Write-Log "Backup completed to: $BackupPath"
    Write-Log "Report: $htmlPath"
    Write-Log "Successfully backed up $SuccessCount of $($BackupResults.Count) GPOs"
}
catch {
    Write-Log "GPO backup failed: $_" 'ERROR'
    throw
}
