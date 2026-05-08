param(
    [Parameter(Mandatory = $false)]
    [string[]]$ComputerNames = @($env:COMPUTERNAME),

    [Parameter(Mandatory = $false)]
    [string[]]$ServiceNames = @(
        "W3SVC", "MSSQLSERVER", "DNS", "NTDS", "Netlogon",
        "Spooler", "DHCP", "LanmanServer", "LanmanWorkstation",
        "WinRM", "RpcSs", "EventLog", "W32Time", "gpsvc"
    ),

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\ServiceHealthReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string[]]$AlertEmailTo,

    [Parameter(Mandatory = $false)]
    [string]$SmtpServer = "localhost",

    [Parameter(Mandatory = $false)]
    [switch]$ShowAllServices
)

function Get-ServiceStatus {
    param(
        [string]$ComputerName,
        [string[]]$Services
    )

    try {
        $AllServices = Get-Service -ComputerName $ComputerName -ErrorAction Stop
    } catch {
        Write-Warning "Cannot connect to $ComputerName : $($_.Exception.Message)"
        return @()
    }

    $Results = foreach ($ServiceName in $Services) {
        $Service = $AllServices | Where-Object { $_.Name -eq $ServiceName }

        if (-not $Service) {
            [PSCustomObject]@{
                ComputerName = $ComputerName.ToUpper()
                ServiceName  = $ServiceName
                DisplayName  = "N/A"
                Status       = "Not Found"
                StartType    = "N/A"
                Health       = "Unknown"
            }
            continue
        }

        $StartType = try {
            (Get-CimInstance -ComputerName $ComputerName -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop).StartMode
        } catch { "Unknown" }

        $Health = switch ($Service.Status) {
            "Running" { "Healthy" }
            "Stopped" {
                if ($StartType -eq "Auto" -or $StartType -eq "Automatic") { "Critical" }
                else { "Stopped" }
            }
            default { "Degraded" }
        }

        [PSCustomObject]@{
            ComputerName = $ComputerName.ToUpper()
            ServiceName  = $Service.Name
            DisplayName  = $Service.DisplayName
            Status       = $Service.Status
            StartType    = $StartType
            Health       = $Health
        }
    }

    return $Results
}

$AllResults = @()

foreach ($Computer in $ComputerNames) {
    Write-Host "Checking services on $Computer..." -ForegroundColor Yellow
    $AllResults += Get-ServiceStatus -ComputerName $Computer -Services $ServiceNames
}

$CriticalServices = $AllResults | Where-Object { $_.Health -eq "Critical" }
$DegradedServices = $AllResults | Where-Object { $_.Health -eq "Degraded" }
$MissingServices = $AllResults | Where-Object { $_.Health -eq "Unknown" }

Write-Host "`n=== Service Health Summary ===" -ForegroundColor Cyan
Write-Host "Total services checked: $($AllResults.Count)" -ForegroundColor White
Write-Host "Healthy: $(($AllResults | Where-Object { $_.Health -eq "Healthy" }).Count)" -ForegroundColor Green
Write-Host "Critical (auto-start stopped): $($CriticalServices.Count)" -ForegroundColor Red
Write-Host "Stopped (manual): $(($AllResults | Where-Object { $_.Health -eq "Stopped" }).Count)" -ForegroundColor Gray
Write-Host "Degraded: $($DegradedServices.Count)" -ForegroundColor Yellow
Write-Host "Missing: $($MissingServices.Count)" -ForegroundColor Red

foreach ($Svc in $CriticalServices) {
    Write-Host "CRITICAL: $($Svc.ComputerName) - $($Svc.ServiceName) ($($Svc.DisplayName)) is STOPPED (start type: $($Svc.StartType))" -ForegroundColor Red
}

$HtmlRows = $AllResults | Sort-Object Health, ComputerName, ServiceName | ForEach-Object {
    $RowClass = switch ($_.Health) {
        "Critical" { "danger" }
        "Degraded" { "warning" }
        "Unknown" { "danger" }
        default { "" }
    }
    "<tr class='$RowClass'>
        <td>$($_.ComputerName)</td>
        <td>$($_.ServiceName)</td>
        <td>$($_.DisplayName)</td>
        <td>$($_.Status)</td>
        <td>$($_.StartType)</td>
        <td>$($_.Health)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Service Health Monitoring Report</title>
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
<h1>Service Health Monitoring Report</h1>
<div class='summary'>
    <strong>Servers:</strong> $($ComputerNames.Count) |
    <strong>Services Monitored:</strong> $($ServiceNames.Count) |
    <strong>Healthy:</strong> $(($AllResults | Where-Object { $_.Health -eq "Healthy" }).Count) |
    <strong>Critical:</strong> <span style='color:red;'>$($CriticalServices.Count)</span> |
    <strong>Degraded:</strong> <span style='color:orange;'>$($DegradedServices.Count)</span> |
    <strong>Missing:</strong> <span style='color:red;'>$($MissingServices.Count)</span>
</div>
<table>
<tr><th>Server</th><th>Service</th><th>Display Name</th><th>Status</th><th>Start Type</th><th>Health</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "`nReport: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $AllResults | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}

if ($AlertEmailTo -and $CriticalServices.Count -gt 0) {
    try {
        $Body = "Critical Service Alert - $(Get-Date -Format 'yyyy-MM-dd HH:mm')`n`n"
        $Body += ($CriticalServices | ForEach-Object {
            "CRITICAL: $($_.ComputerName) - $($_.ServiceName) ($($_.DisplayName)) is $($_.Status)"
        }) -join "`n"
        Send-MailMessage -To $AlertEmailTo -From "svc-monitor@$env:COMPUTERNAME" `
            -Subject "[SERVICE ALERT] $($CriticalServices.Count) critical services" -Body $Body `
            -SmtpServer $SmtpServer -ErrorAction Stop
        Write-Host "Alert sent to $($AlertEmailTo -join ', ')" -ForegroundColor Yellow
    } catch {
        Write-Warning "Failed to send alert: $($_.Exception.Message)"
    }
}
