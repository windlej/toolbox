param(
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\DomainHealth_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string[]]$DomainControllers,

    [Parameter(Mandatory = $false)]
    [switch]$SkipReplication,

    [Parameter(Mandatory = $false)]
    [switch]$SkipDcdiag
)

$Results = @()
$Issues = @()

function Invoke-DcdiagCheck {
    param([string]$Server)

    $dcdiagOutput = dcdiag /s:$Server /q 2>&1
    $Parsed = [PSCustomObject]@{
        Server      = $Server
        Check       = "dcdiag"
        Status      = "Pass"
        Details     = ""
    }

    if ($dcdiagOutput -match "failed|error|warning") {
        $Parsed.Status = "Fail"
        $Parsed.Details = ($dcdiagOutput | Select-String -Pattern "failed|error|warning" -SimpleMatch | Out-String).Trim()
    }

    return $Parsed
}

function Test-ReplicationHealth {
    param([string]$Server)

    $repadminOutput = repadmin /showrepl $Server 2>&1
    $LastSuccess = $repadminOutput | Select-String -Pattern "last success"
    $LastFailure = $repadminOutput | Select-String -Pattern "last failure"

    $Status = "Healthy"
    $Details = ""

    if ($LastFailure) {
        $RecentFails = $LastFailure | Where-Object { $_ -match "\d{1,2}/\d{1,2}/\d{4}" }
        if ($RecentFails) {
            $Status = "Unhealthy"
            $Details = ($RecentFails -join "; ").Trim()
        }
    }

    return [PSCustomObject]@{
        Server  = $Server
        Check   = "Replication"
        Status  = $Status
        Details = $Details
    }
}

function Test-NetlogonService {
    param([string]$Server)

    try {
        $Service = Get-Service -Name "Netlogon" -ComputerName $Server -ErrorAction Stop
        return [PSCustomObject]@{
            Server  = $Server
            Check   = "Netlogon Service"
            Status  = if ($Service.Status -eq "Running") { "Pass" } else { "Fail" }
            Details = $Service.Status
        }
    } catch {
        return [PSCustomObject]@{
            Server  = $Server
            Check   = "Netlogon Service"
            Status  = "Fail"
            Details = $_.Exception.Message
        }
    }
}

function Test-NtpSync {
    param([string]$Server)

    try {
        $w32tm = w32tm /query /computer:$Server /status 2>&1
        if ($w32tm -match "Source:|NtpServer|Reference Identifier") {
            $Source = ($w32tm | Select-String -Pattern "Source:" | ForEach-Object { $_ -replace ".*Source:\s*", "" }).Trim()
            return [PSCustomObject]@{
                Server  = $Server
                Check   = "NTP Sync"
                Status  = "Pass"
                Details = "Source: $Source"
            }
        } else {
            return [PSCustomObject]@{
                Server  = $Server
                Check   = "NTP Sync"
                Status  = "Warn"
                Details = $w32tm
            }
        }
    } catch {
        return [PSCustomObject]@{
            Server  = $Server
            Check   = "NTP Sync"
            Status  = "Warn"
            Details = $_.Exception.Message
        }
    }
}

function Test-FsmoRoles {
    param([string]$Server)

    try {
        $Roles = Get-ADDomain | Select-Object -ExpandProperty PDCEmulator,
            RIDMaster, InfrastructureMaster, SchemaMaster, DomainNamingMaster
        return [PSCustomObject]@{
            Server  = $Server
            Check   = "FSMO Roles"
            Status  = "Pass"
            Details = "PDC: $($Roles[0]), RID: $($Roles[1]), Infra: $($Roles[2]), Schema: $($Roles[3]), Domain: $($Roles[4])"
        }
    } catch {
        return [PSCustomObject]@{
            Server  = $Server
            Check   = "FSMO Roles"
            Status  = "Fail"
            Details = $_.Exception.Message
        }
    }
}

Import-Module ActiveDirectory -ErrorAction Stop

if (-not $DomainControllers) {
    $DomainControllers = (Get-ADDomainController -Filter *).Name | Sort-Object
}

$DomainInfo = Get-ADDomain
$ForestInfo = Get-ADForest

Write-Host "Domain: $($DomainInfo.DNSRoot)" -ForegroundColor Cyan
Write-Host "Forest: $($ForestInfo.ForestMode)" -ForegroundColor Cyan
Write-Host "DCs Found: $($DomainControllers.Count)" -ForegroundColor Green

foreach ($DC in $DomainControllers) {
    Write-Host "Checking $DC..." -ForegroundColor Yellow

    try {
        $Reachable = Test-Connection -ComputerName $DC -Count 1 -Quiet
        if (-not $Reachable) {
            $Results += [PSCustomObject]@{ Server = $DC; Check = "Connectivity"; Status = "Fail"; Details = "Unreachable" }
            continue
        }
    } catch {
        $Results += [PSCustomObject]@{ Server = $DC; Check = "Connectivity"; Status = "Fail"; Details = $_.Exception.Message }
        continue
    }

    $Results += [PSCustomObject]@{ Server = $DC; Check = "Connectivity"; Status = "Pass"; Details = "Reachable" }
    $Results += Test-NetlogonService $DC

    if (-not $SkipDcdiag) {
        $Results += Invoke-DcdiagCheck $DC
    }

    if (-not $SkipReplication) {
        $Results += Test-ReplicationHealth $DC
    }

    $Results += Test-NtpSync $DC
    $Results += Test-FsmoRoles $DC
}

$Failures = $Results | Where-Object { $_.Status -eq "Fail" -or $_.Status -eq "Unhealthy" }
$Warnings = $Results | Where-Object { $_.Status -eq "Warn" }

$HtmlRows = $Results | ForEach-Object {
    $RowClass = switch ($_.Status) {
        "Fail" { "danger" }
        "Warn" { "warning" }
        "Unhealthy" { "danger" }
        default { "" }
    }
    "<tr class='$RowClass'>
        <td>$($_.Server)</td>
        <td>$($_.Check)</td>
        <td>$($_.Status)</td>
        <td>$($_.Details)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Domain Health Check Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.domain-info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 10px 0; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 6px 8px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
.warning td { background: #fff3cd; }
</style></head>
<body>
<h1>Domain Health Check Report</h1>
<div class='domain-info'>
    <strong>Domain:</strong> $($DomainInfo.DNSRoot) |
    <strong>Forest Mode:</strong> $($ForestInfo.ForestMode) |
    <strong>Domain Mode:</strong> $($DomainInfo.DomainMode)<br>
    <strong>Domain Controllers:</strong> $($DomainControllers -join ', ')
</div>
<div class='summary'>
    <strong>Total Checks:</strong> $($Results.Count) |
    <strong>Pass:</strong> $($Results.Count - $Failures.Count - $Warnings.Count) |
    <strong>Warnings:</strong> $($Warnings.Count) |
    <strong>Failures:</strong> $($Failures.Count)
</div>
<table>
<tr><th>DC</th><th>Check</th><th>Status</th><th>Details</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8

Write-Host "`nReport: $ReportPath" -ForegroundColor Green
Write-Host "Summary: $($Results.Count) checks | $($Failures.Count) failures | $($Warnings.Count) warnings" -ForegroundColor Cyan

if ($Failures.Count -gt 0) {
    Write-Host "FAILURES:" -ForegroundColor Red
    $Failures | ForEach-Object { Write-Host "  [$($_.Server)] $($_.Check): $($_.Details)" -ForegroundColor Red }
}
