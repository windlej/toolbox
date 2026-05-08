param(
    [Parameter(Mandatory = $false)]
    [string[]]$ComputerNames = @($env:COMPUTERNAME),

    [Parameter(Mandatory = $false)]
    [int]$WarningThresholdPercent = 20,

    [Parameter(Mandatory = $false)]
    [int]$CriticalThresholdPercent = 10,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\DiskSpaceReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string[]]$AlertEmailTo,

    [Parameter(Mandatory = $false)]
    [string]$SmtpServer = "localhost",

    [Parameter(Mandatory = $false)]
    [switch]$ExcludeNetworkDrives
)

function Get-DiskInfo {
    param([string]$ComputerName)

    try {
        $Disks = Get-CimInstance -ComputerName $ComputerName -ClassName Win32_LogicalDisk `
            -Filter "DriveType = 3" -ErrorAction Stop
    } catch {
        Write-Warning "Failed to connect to $ComputerName : $($_.Exception.Message)"
        return @()
    }

    $Results = foreach ($Disk in $Disks) {
        $FreePercent = if ($Disk.Size -gt 0) {
            [math]::Round(($Disk.FreeSpace / $Disk.Size) * 100, 2)
        } else { 0 }

        $UsedPercent = 100 - $FreePercent

        $FreeGB = [math]::Round($Disk.FreeSpace / 1GB, 2)
        $TotalGB = [math]::Round($Disk.Size / 1GB, 2)
        $UsedGB = [math]::Round(($Disk.Size - $Disk.FreeSpace) / 1GB, 2)

        $AlertLevel = if ($FreePercent -le $CriticalThresholdPercent) { "CRITICAL" }
        elseif ($FreePercent -le $WarningThresholdPercent) { "WARNING" }
        else { "OK" }

        [PSCustomObject]@{
            ComputerName    = $ComputerName.ToUpper()
            Drive           = $Disk.DeviceID
            Label           = $Disk.VolumeName
            TotalGB         = $TotalGB
            UsedGB          = $UsedGB
            FreeGB          = $FreeGB
            FreePercent     = $FreePercent
            UsedPercent     = $UsedPercent
            AlertLevel      = $AlertLevel
        }
    }

    return $Results
}

$AllResults = foreach ($Computer in $ComputerNames) {
    Write-Host "Checking $Computer..." -ForegroundColor Yellow
    Get-DiskInfo -ComputerName $Computer
}

$CriticalDisks = $AllResults | Where-Object { $_.AlertLevel -eq "CRITICAL" }
$WarningDisks = $AllResults | Where-Object { $_.AlertLevel -eq "WARNING" }

Write-Host "`n=== Disk Space Summary ===" -ForegroundColor Cyan
Write-Host "Total drives checked: $($AllResults.Count)" -ForegroundColor White
Write-Host "Critical: $($CriticalDisks.Count)" -ForegroundColor Red
Write-Host "Warning: $($WarningDisks.Count)" -ForegroundColor Yellow
Write-Host "OK: $(($AllResults | Where-Object { $_.AlertLevel -eq "OK" }).Count)" -ForegroundColor Green

foreach ($Disk in $CriticalDisks) {
    Write-Host "CRITICAL: $($Disk.ComputerName) - $($Disk.Drive) - $($Disk.FreePercent)% free ($($Disk.FreeGB)GB / $($Disk.TotalGB)GB)" -ForegroundColor Red
}

foreach ($Disk in $WarningDisks) {
    Write-Host "WARNING: $($Disk.ComputerName) - $($Disk.Drive) - $($Disk.FreePercent)% free ($($Disk.FreeGB)GB / $($Disk.TotalGB)GB)" -ForegroundColor Yellow
}

$HtmlRows = $AllResults | Sort-Object ComputerName, Drive | ForEach-Object {
    $RowClass = switch ($_.AlertLevel) {
        "CRITICAL" { "danger" }
        "WARNING" { "warning" }
        default { "" }
    }
    "<tr class='$RowClass'>
        <td>$($_.ComputerName)</td>
        <td>$($_.Drive)</td>
        <td>$($_.Label)</td>
        <td>$($_.TotalGB)</td>
        <td>$($_.UsedGB)</td>
        <td>$($_.FreeGB)</td>
        <td>$($_.FreePercent)%</td>
        <td>$($_.AlertLevel)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Disk Space Monitoring Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 6px 8px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
.warning td { background: #fff3cd; }
</style></head>
<body>
<h1>Disk Space Monitoring Report</h1>
<div class='summary'>
    <strong>Servers:</strong> $($ComputerNames.Count) |
    <strong>Drives:</strong> $($AllResults.Count) |
    <strong>Critical:</strong> <span style='color:red;'>$($CriticalDisks.Count)</span> |
    <strong>Warning:</strong> <span style='color:orange;'>$($WarningDisks.Count)</span> |
    <strong>Thresholds:</strong> Warning < $WarningThresholdPercent%, Critical < $CriticalThresholdPercent%
</div>
<table>
<tr><th>Server</th><th>Drive</th><th>Label</th><th>Total (GB)</th><th>Used (GB)</th><th>Free (GB)</th><th>Free %</th><th>Status</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $AllResults | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}

if ($AlertEmailTo -and ($CriticalDisks.Count -gt 0 -or $WarningDisks.Count -gt 0)) {
    try {
        $Body = "Disk Space Alert - $(Get-Date -Format 'yyyy-MM-dd HH:mm')`n`n"
        if ($CriticalDisks) {
            $Body += "CRITICAL:`n"
            $Body += ($CriticalDisks | ForEach-Object { "$($_.ComputerName) - $($_.Drive) - $($_.FreePercent)% free ($($_.FreeGB)GB remaining)" }) -join "`n"
            $Body += "`n`n"
        }
        if ($WarningDisks) {
            $Body += "WARNING:`n"
            $Body += ($WarningDisks | ForEach-Object { "$($_.ComputerName) - $($_.Drive) - $($_.FreePercent)% free ($($_.FreeGB)GB remaining)" }) -join "`n"
        }
        $Body += "`n`nReport: $ReportPath"

        Send-MailMessage -To $AlertEmailTo -From "diskspace-monitor@$env:COMPUTERNAME" `
            -Subject "[DISK ALERT] $($CriticalDisks.Count) critical, $($WarningDisks.Count) warning" -Body $Body `
            -SmtpServer $SmtpServer -ErrorAction Stop
        Write-Host "Alert sent to $($AlertEmailTo -join ', ')" -ForegroundColor Yellow
    } catch {
        Write-Warning "Failed to send alert: $($_.Exception.Message)"
    }
}
