#Requires -Version 5.1

<#
.SYNOPSIS
Checks that key Windows services are running on one or more servers and reports the result as HTML (optional CSV).

.DESCRIPTION
For each computer, looks up each service in -ServiceNames and classifies it: Healthy (running), Critical
(stopped but set to start automatically), Stopped (stopped, manual or disabled), Degraded (any other state,
for example starting or stopping) or Unknown (service not found). The default list covers common infrastructure
services (IIS, SQL Server, DNS, AD DS, DHCP, file sharing, WinRM and others). Output is an HTML report with a
summary header, an optional CSV and a log file. If -AlertEmailTo is given and any service is Critical, an
email is sent from -From through -SmtpServer; nothing else is changed (the script stops at start-up if
-AlertEmailTo is given without -From). Services are read with CIM (Win32_Service), which works in Windows
PowerShell 5.1 and PowerShell 7; the local computer is queried directly and remote ones over WinRM.

.PARAMETER ComputerName
One or more computers to check. Default: the local machine. Old name: ComputerNames.

.PARAMETER ServiceNames
Service (short) names to check. Default: W3SVC, MSSQLSERVER, DNS, NTDS, Netlogon, Spooler, DHCP,
LanmanServer, LanmanWorkstation, WinRM, RpcSs, EventLog, W32Time, gpsvc.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write a CSV of the results next to the HTML report.

.PARAMETER AlertEmailTo
Optional recipients for an alert email when any service is Critical. No email is sent when omitted. Requires -From.

.PARAMETER From
Sender address for the alert email (for example alerts@contoso.com). Required with -AlertEmailTo.

.PARAMETER SmtpServer
SMTP server used for the alert email. Default: localhost.

.PARAMETER ShowAllServices
Report every service found on each computer instead of only the ones in -ServiceNames. Each is classified the
same way (so stopped automatic services are still Critical).

.EXAMPLE
.\Test-ServiceHealth.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Test-ServiceHealth.ps1 -ComputerName SRV01,SRV02 -ServiceNames W3SVC,MSSQLSERVER -AlertEmailTo it@contoso.com -From alerts@contoso.com -SmtpServer smtp.contoso.com -ExportCsv -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (Windows PowerShell 5.1 or PowerShell 7; CIM over WinRM to remote targets)
Permissions:  Local administrator (or remote service query rights) on each target computer
When to use:  After patching or a reboot to confirm services came back, or as a routine health check on application and infrastructure servers.
Safety:       Read-only
Version:      1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [Alias('ComputerNames')]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter(Mandatory = $false)]
    [string[]]$ServiceNames = @(
        "W3SVC", "MSSQLSERVER", "DNS", "NTDS", "Netlogon",
        "Spooler", "DHCP", "LanmanServer", "LanmanWorkstation",
        "WinRM", "RpcSs", "EventLog", "W32Time", "gpsvc"
    ),

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$CustomerName,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [string[]]$AlertEmailTo,

    [Parameter(Mandatory = $false)]
    [string]$From,

    [Parameter(Mandatory = $false)]
    [string]$SmtpServer = "localhost",

    [Parameter(Mandatory = $false)]
    [switch]$ShowAllServices
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($AlertEmailTo -and -not $From) {
    throw '-AlertEmailTo requires -From.'
}

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
$script:LogFile = Join-Path $outDir "Test-ServiceHealth_$stamp.log"
$htmlPath = Join-Path $outDir "Test-ServiceHealth_$stamp.html"
$csvPath  = Join-Path $outDir "Test-ServiceHealth_$stamp.csv"

function Get-ServiceStatus {
    param(
        [string]$ComputerName,
        [string[]]$Services
    )

    try {
        if ($ComputerName -eq $env:COMPUTERNAME) {
            $AllServices = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
        } else {
            $AllServices = @(Get-CimInstance -ComputerName $ComputerName -ClassName Win32_Service -ErrorAction Stop)
        }
    } catch {
        Write-Log "Cannot connect to $ComputerName : $($_.Exception.Message)" 'WARN'
        return @()
    }

    if ($ShowAllServices) {
        $Services = @($AllServices | ForEach-Object { $_.Name })
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

        $StartType = $Service.StartMode

        $Health = switch ($Service.State) {
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
            Status       = $Service.State
            StartType    = $StartType
            Health       = $Health
        }
    }

    return $Results
}

$AllResults = @()

foreach ($Computer in $ComputerName) {
    Write-Log "Checking services on $Computer..."
    $AllResults += Get-ServiceStatus -ComputerName $Computer -Services $ServiceNames
}

$CriticalServices = @($AllResults | Where-Object { $_.Health -eq "Critical" })
$DegradedServices = @($AllResults | Where-Object { $_.Health -eq "Degraded" })
$MissingServices = @($AllResults | Where-Object { $_.Health -eq "Unknown" })

Write-Log '=== Service Health Summary ==='
Write-Log "Total services checked: $($AllResults.Count)"
Write-Log "Healthy: $(@($AllResults | Where-Object { $_.Health -eq 'Healthy' }).Count)"
Write-Log "Critical (auto-start stopped): $($CriticalServices.Count)"
Write-Log "Stopped (manual): $(@($AllResults | Where-Object { $_.Health -eq 'Stopped' }).Count)"
Write-Log "Degraded: $($DegradedServices.Count)"
Write-Log "Missing: $($MissingServices.Count)"

foreach ($Svc in $CriticalServices) {
    Write-Log "CRITICAL: $($Svc.ComputerName) - $($Svc.ServiceName) ($($Svc.DisplayName)) is STOPPED (start type: $($Svc.StartType))" 'ERROR'
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
    <strong>Servers:</strong> $(@($ComputerName).Count) |
    <strong>Services Monitored:</strong> $(if ($ShowAllServices) { 'all' } else { @($ServiceNames).Count }) |
    <strong>Healthy:</strong> $(@($AllResults | Where-Object { $_.Health -eq "Healthy" }).Count) |
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

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "Report written: $htmlPath"

if ($ExportCsv) {
    $AllResults | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV written: $csvPath"
}

if ($AlertEmailTo -and $CriticalServices.Count -gt 0) {
    try {
        $Body = "Critical Service Alert - $(Get-Date -Format 'yyyy-MM-dd HH:mm')`n`n"
        $Body += ($CriticalServices | ForEach-Object {
            "CRITICAL: $($_.ComputerName) - $($_.ServiceName) ($($_.DisplayName)) is $($_.Status)"
        }) -join "`n"
        Send-MailMessage -To $AlertEmailTo -From $From `
            -Subject "[SERVICE ALERT] $($CriticalServices.Count) critical services" -Body $Body `
            -SmtpServer $SmtpServer -ErrorAction Stop
        Write-Log "Alert sent to $($AlertEmailTo -join ', ')"
    } catch {
        Write-Log "Failed to send alert: $($_.Exception.Message)" 'WARN'
    }
}
