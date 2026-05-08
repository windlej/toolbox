param(
    [Parameter(Mandatory = $false)]
    [string[]]$ComputerNames = @($env:COMPUTERNAME),

    [Parameter(Mandatory = $false)]
    [int]$HoursBack = 24,

    [Parameter(Mandatory = $false)]
    [int]$MaxEvents = 5000,

    [Parameter(Mandatory = $false)]
    [string[]]$LogNames = @("System", "Application", "Security", "Directory Service", "DNS Server", "File Replication Service"),

    [Parameter(Mandatory = $false)]
    [string[]]$CriticalLevels = @("Error", "Critical"),

    [Parameter(Mandatory = $false)]
    [int[]]$EventIds,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\EventLogReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeInformational
)

$StartTime = (Get-Date).AddHours(-$HoursBack)

$AllEvents = @()

foreach ($Computer in $ComputerNames) {
    Write-Host "Scanning $Computer..." -ForegroundColor Yellow

    foreach ($LogName in $LogNames) {
        try {
            $FilterHash = @{
                LogName   = $LogName
                StartTime = $StartTime
                ComputerName = $Computer
            }

            if (-not $IncludeInformational) {
                $FilterHash.Level = $CriticalLevels
            }

            if ($EventIds) {
                $FilterHash.ID = $EventIds
            }

            $Events = Get-WinEvent -FilterHashTable $FilterHash -ErrorAction SilentlyContinue |
                Select-Object -First $MaxEvents

            foreach ($Event in $Events) {
                $AllEvents += [PSCustomObject]@{
                    TimeCreated    = $Event.TimeCreated
                    ComputerName   = $Computer.ToUpper()
                    LogName        = $LogName
                    EventId        = $Event.Id
                    Level          = $Event.LevelDisplayName
                    Provider       = $Event.ProviderName
                    Message        = ($Event.Message -replace '\r?\n', ' ' -replace '\s+', ' ').Substring(0, [math]::Min(300, ($Event.Message -replace '\r?\n', ' ' -replace '\s+', ' ').Length))
                    UserId         = $Event.UserId
                    ProcessId      = $Event.ProcessId
                    ThreadId       = $Event.ThreadId
                }
            }

            Write-Host "  $LogName : $($Events.Count) events" -ForegroundColor Gray
        } catch {
            continue
        }
    }
}

$MostCommonErrors = $AllEvents | Group-Object EventId | Sort-Object Count -Descending | Select-Object -First 20
$MostCommonProviders = $AllEvents | Group-Object Provider | Sort-Object Count -Descending | Select-Object -First 10
$Timeline = $AllEvents | Group-Object { $_.TimeCreated.ToString("yyyy-MM-dd HH:00") } | Sort-Object Name

$SummaryLines = $MostCommonErrors | ForEach-Object {
    $Desc = switch ($_.Name) {
        "1074" { "System Shutdown/Restart" }
        "6008" { "Unexpected Shutdown" }
        "41" { "Kernel-Power (unexpected shutdown)" }
        "7031" { "Service terminated unexpectedly" }
        "7034" { "Service crashed" }
        "4625" { "Failed Logon" }
        "4624" { "Successful Logon" }
        "4648" { "Logon with explicit credentials" }
        "4768" { "Kerberos TGT requested" }
        "4769" { "Kerberos service ticket requested" }
        "4720" { "User account created" }
        "4732" { "User added to security group" }
        "4728" { "User added to global group" }
        "5140" { "File share accessed" }
        default { "" }
    }
    [PSCustomObject]@{ EventId = $_.Name; Count = $_.Count; Description = $Desc }
}

Write-Host "`n=== Event Log Summary ===" -ForegroundColor Cyan
Write-Host "Total events found: $($AllEvents.Count) in last $HoursBack hours" -ForegroundColor White
Write-Host "`nTop 10 Event IDs:" -ForegroundColor Yellow
$SummaryLines | Select-Object -First 10 | ForEach-Object {
    Write-Host "  [$($_.EventId)] x$($_.Count) $($_.Description)" -ForegroundColor Gray
}

$HtmlTopErrors = $SummaryLines | Select-Object -First 20 | ForEach-Object {
    "<tr><td>$($_.EventId)</td><td>$($_.Count)</td><td>$($_.Description)</td></tr>"
}

$HtmlRows = $AllEvents | Sort-Object TimeCreated -Descending | Select-Object -First 500 | ForEach-Object {
    $RowClass = if ($_.Level -eq "Critical") { "danger" } elseif ($_.Level -eq "Error") { "warning" } else { "" }
    "<tr class='$RowClass'>
        <td>$($_.TimeCreated)</td>
        <td>$($_.ComputerName)</td>
        <td>$($_.LogName)</td>
        <td>$($_.EventId)</td>
        <td>$($_.Level)</td>
        <td>$($_.Provider)</td>
        <td title='$($_.Message)'>$(($_.Message).Substring(0, [math]::Min(100, $_.Message.Length)))</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Event Log Anomaly Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
.top-errors { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; position: sticky; top: 0; }
td { padding: 5px 8px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
.warning td { background: #fff3cd; }
</style></head>
<body>
<h1>Event Log Anomaly Report</h1>
<div class='summary'>
    <strong>Period:</strong> Last $HoursBack hours |
    <strong>Servers:</strong> $($ComputerNames.Count) |
    <strong>Total Events:</strong> $($AllEvents.Count) |
    <strong>Logs Scanned:</strong> $($LogNames.Count)
</div>

<h2>Top Event IDs</h2>
<table>
<tr><th>Event ID</th><th>Count</th><th>Description</th></tr>
$($HtmlTopErrors -join "`n")
</table>

<h2>All Events (last 500)</h2>
<table>
<tr><th>Time</th><th>Server</th><th>Log</th><th>ID</th><th>Level</th><th>Provider</th><th>Message</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "`nReport: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $AllEvents | Sort-Object TimeCreated -Descending | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}
