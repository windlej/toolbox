#Requires -Version 5.1

<#
.SYNOPSIS
Reports Windows Update patch compliance for one or more servers as an HTML report (optional CSV).

.DESCRIPTION
Queries the Windows Update Agent install history on each computer and finds the most recent successful
update. A server is Compliant when that update is no more than -DaysSinceLastUpdate days old, Out of Date
when older, and Never Updated when no successful install is found. Optionally checks for a pending reboot
and for specific KB numbers in the history (the KB results are collected but not shown in the HTML or CSV).
The report is an HTML table with a summary header. A log file is also written.

.PARAMETER ComputerName
One or more computers to check. Default: the local machine. Old name: ComputerNames.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write a CSV of the results next to the HTML report.

.PARAMETER DaysSinceLastUpdate
Maximum age in days of the last successful update for a server to count as Compliant. Default: 30.

.PARAMETER KbIds
Optional KB identifiers (for example KB5030211) to look for in the update history.

.PARAMETER IncludeRebootStatus
Check the registry for a pending reboot on the local machine and set the PendingReboot column.
Note: the registry check runs on the machine running the script, not on remote targets.

.EXAMPLE
.\Get-PatchComplianceReport.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-PatchComplianceReport.ps1 -ComputerName SRV01,SRV02 -DaysSinceLastUpdate 45 -IncludeRebootStatus -ExportCsv -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (Windows Update Agent COM API; remote targets need DCOM/RPC access)
Permissions:  Local administrator on each target computer
When to use:  Monthly patch review, before a maintenance window, or to show a customer which servers have fallen behind on updates.
Safety:       Read-only
Version:      1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [Alias('ComputerNames')]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$CustomerName,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [int]$DaysSinceLastUpdate = 30,

    [Parameter(Mandatory = $false)]
    [string[]]$KbIds,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeRebootStatus
)

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

$stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir   = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$script:LogFile = Join-Path $outDir "Get-PatchComplianceReport_$stamp.log"
$htmlPath = Join-Path $outDir "Get-PatchComplianceReport_$stamp.html"
$csvPath  = Join-Path $outDir "Get-PatchComplianceReport_$stamp.csv"

function Get-PatchStatus {
    param([string]$ComputerName)

    try {
        $Session = [System.Activator]::CreateInstance([Type]::GetTypeFromProgID("Microsoft.Update.Session", $ComputerName))
        $Searcher = $Session.CreateUpdateSearcher()
    } catch {
        Write-Log "Cannot connect to $ComputerName (WUA required): $($_.Exception.Message)" 'WARN'
        return $null
    }

    try {
        $HistoryCount = $Searcher.GetTotalHistoryCount()
        $History = $Searcher.QueryHistory(0, $HistoryCount) | Select-Object -Last 100
    } catch {
        $History = @()
    }

    $LastInstallDate = $null
    $LastUpdateTitle = ""

    if ($History.Count -gt 0) {
        $RecentUpdates = $History | Where-Object { $_.ResultCode -eq 2 -or $_.ResultCode -eq 3 } |
            Sort-Object Date -Descending

        if ($RecentUpdates.Count -gt 0) {
            $LastInstallDate = $RecentUpdates[0].Date
            $LastUpdateTitle = $RecentUpdates[0].Title -replace ',.*', ''
        }
    }

    $DaysSince = if ($LastInstallDate) {
        [math]::Round(((Get-Date) - $LastInstallDate).TotalDays)
    } else { $null }

    $Compliance = if (-not $LastInstallDate) { "Never Updated" }
    elseif ($DaysSince -le $DaysSinceLastUpdate) { "Compliant" }
    else { "Out of Date" }

    $PendingReboot = $false
    if ($IncludeRebootStatus) {
        try {
            $RebootKey = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue
            $CBSReboot = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue
            if ($RebootKey -or $CBSReboot) { $PendingReboot = $true }
        } catch { }
    }

    $SpecificUpdates = @()
    if ($KbIds) {
        foreach ($Kb in $KbIds) {
            $Found = $History | Where-Object { $_.Title -match $Kb }
            $SpecificUpdates += [PSCustomObject]@{
                KB      = $Kb
                Found   = ($Found.Count -gt 0)
                Date    = if ($Found) { ($Found | Sort-Object Date -Descending | Select-Object -First 1).Date } else { $null }
            }
        }
    }

    return [PSCustomObject]@{
        ComputerName     = $ComputerName.ToUpper()
        LastInstallDate  = $LastInstallDate
        LastUpdateTitle  = $LastUpdateTitle
        DaysSinceUpdate  = $DaysSince
        Compliance       = $Compliance
        TotalUpdates     = $HistoryCount
        PendingReboot    = $PendingReboot
        SpecificUpdates  = $SpecificUpdates
    }
}

$AllResults = @()

foreach ($Computer in $ComputerName) {
    Write-Log "Checking $Computer..."
    $Result = Get-PatchStatus -ComputerName $Computer
    if ($Result) {
        $AllResults += $Result
    }
}

$CompliantCount = @($AllResults | Where-Object { $_.Compliance -eq "Compliant" }).Count
$OutOfDateCount = @($AllResults | Where-Object { $_.Compliance -eq "Out of Date" }).Count
$NeverUpdatedCount = @($AllResults | Where-Object { $_.Compliance -eq "Never Updated" }).Count
$PendingRebootCount = @($AllResults | Where-Object { $_.PendingReboot }).Count

Write-Log '=== Patch Compliance Summary ==='
Write-Log "Compliant: $CompliantCount"
Write-Log "Out of Date: $OutOfDateCount"
Write-Log "Never Updated: $NeverUpdatedCount"
if ($IncludeRebootStatus) { Write-Log "Pending Reboot: $PendingRebootCount" }

$HtmlRows = $AllResults | Sort-Object Compliance, ComputerName | ForEach-Object {
    $RowClass = switch ($_.Compliance) {
        "Compliant" { "" }
        "Out of Date" { "warning" }
        "Never Updated" { "danger" }
        default { "" }
    }

    $RebootBadge = if ($_.PendingReboot) { "<span style='color:red;'>[REBOOT]</span>" } else { "" }

    "<tr class='$RowClass'>
        <td>$($_.ComputerName)</td>
        <td>$($_.Compliance)</td>
        <td>$($_.LastInstallDate)</td>
        <td>$($_.DaysSinceUpdate)</td>
        <td>$($_.LastUpdateTitle)</td>
        <td>$($_.TotalUpdates)</td>
        <td>$($_.PendingReboot)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Patch Compliance Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 5px 8px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
.warning td { background: #fff3cd; }
</style></head>
<body>
<h1>Patch Compliance Report</h1>
<div class='summary'>
    <strong>Servers:</strong> $(@($ComputerName).Count) |
    <strong>Compliant:</strong> <span style='color:green;'>$CompliantCount</span> |
    <strong>Out of Date:</strong> <span style='color:orange;'>$OutOfDateCount</span> |
    <strong>Never Updated:</strong> <span style='color:red;'>$NeverUpdatedCount</span> |
    <strong>Pending Reboot:</strong> <span style='color:red;'>$PendingRebootCount</span> |
    <strong>Compliance Window:</strong> $DaysSinceLastUpdate days
</div>
<table>
<tr><th>Server</th><th>Status</th><th>Last Update</th><th>Days Ago</th><th>Last KB</th><th>Total Updates</th><th>Reboot Pending</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "Report written: $htmlPath"

if ($ExportCsv) {
    $CsvData = $AllResults | Select-Object ComputerName, Compliance, LastInstallDate, DaysSinceUpdate, LastUpdateTitle, TotalUpdates, PendingReboot
    $CsvData | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV written: $csvPath"
}
