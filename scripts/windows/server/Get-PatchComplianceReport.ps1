param(
    [Parameter(Mandatory = $false)]
    [string[]]$ComputerNames = @($env:COMPUTERNAME),

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\PatchCompliance_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [int]$DaysSinceLastUpdate = 30,

    [Parameter(Mandatory = $false)]
    [string[]]$KbIds,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeRebootStatus
)

function Get-PatchStatus {
    param([string]$ComputerName)

    try {
        $Session = [System.Activator]::CreateInstance([Type]::GetTypeFromProgID("Microsoft.Update.Session", $ComputerName))
        $Searcher = $Session.CreateUpdateSearcher()
    } catch {
        Write-Warning "Cannot connect to $ComputerName (WUA required): $($_.Exception.Message)"
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

foreach ($Computer in $ComputerNames) {
    Write-Host "Checking $Computer..." -ForegroundColor Yellow
    $Result = Get-PatchStatus -ComputerName $Computer
    if ($Result) {
        $AllResults += $Result
    }
}

$CompliantCount = ($AllResults | Where-Object { $_.Compliance -eq "Compliant" }).Count
$OutOfDateCount = ($AllResults | Where-Object { $_.Compliance -eq "Out of Date" }).Count
$NeverUpdatedCount = ($AllResults | Where-Object { $_.Compliance -eq "Never Updated" }).Count
$PendingRebootCount = ($AllResults | Where-Object { $_.PendingReboot }).Count

Write-Host "`n=== Patch Compliance Summary ===" -ForegroundColor Cyan
Write-Host "Compliant: $CompliantCount" -ForegroundColor Green
Write-Host "Out of Date: $OutOfDateCount" -ForegroundColor Yellow
Write-Host "Never Updated: $NeverUpdatedCount" -ForegroundColor Red
if ($IncludeRebootStatus) { Write-Host "Pending Reboot: $PendingRebootCount" -ForegroundColor Red }

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
    <strong>Servers:</strong> $($ComputerNames.Count) |
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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "`nReport: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $CsvData = $AllResults | Select-Object ComputerName, Compliance, LastInstallDate, DaysSinceUpdate, LastUpdateTitle, TotalUpdates, PendingReboot
    $CsvData | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}
