#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
Runs health checks against every domain controller and writes an HTML report.

.DESCRIPTION
For each domain controller (all DCs in the domain, or those given in -DomainControllers) the script checks
connectivity (ping), the Netlogon service, dcdiag results (unless -SkipDcdiag), replication status via
repadmin /showrepl (unless -SkipReplication), NTP source via w32tm. FSMO role holders are domain/forest-wide, so they are reported once (as a "(domain)" row) rather than per DC. The HTML report
shows the domain and forest mode, the DC list, summary counts and one row per check coloured by Pass, Warn or
Fail. Requires dcdiag, repadmin and w32tm on the machine running the script (installed with the AD DS RSAT tools).

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER DomainControllers
Optional list of domain controller names to check. Default is every DC in the current domain.

.PARAMETER SkipReplication
Skip the repadmin replication check.

.PARAMETER SkipDcdiag
Skip the dcdiag check (the slowest check).

.EXAMPLE
.\Test-DomainHealth.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Test-DomainHealth.ps1 -DomainControllers dc01.contoso.com,dc02.contoso.com -SkipDcdiag -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (RSAT ActiveDirectory module plus dcdiag/repadmin/w32tm, domain-joined machine)
Permissions:  Domain user with network access to the DCs; Domain Admin is recommended for complete dcdiag and repadmin results
When to use:  Start of an engagement, after a DC migration or outage, or as a routine domain health check.
Safety:       Read-only
Version:      1.0
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$CustomerName,
    [string[]]$DomainControllers,
    [switch]$SkipReplication,
    [switch]$SkipDcdiag
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

$stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir   = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$htmlPath = Join-Path $outDir "Test-DomainHealth_$stamp.html"
$script:LogFile = Join-Path $outDir "Test-DomainHealth_$stamp.log"

$Results = @()

function Invoke-DcdiagCheck {
    param([string]$Server)

    # Windows PowerShell 5.1 turns native stderr into terminating errors under 'Stop'; keep native output as data.
    $ErrorActionPreference = 'Continue'

    $dcdiagOutput = dcdiag /s:$Server /q 2>&1
    $Parsed = [PSCustomObject]@{
        Server      = $Server
        Check       = "dcdiag"
        Status      = "Pass"
        Details     = ""
    }

    $Hits = @($dcdiagOutput -match "failed|error|warning")
    if ($Hits.Count -gt 0) {
        $Parsed.Status = "Fail"
        $Parsed.Details = (($Hits | ForEach-Object { "$_".Trim() }) -join "; ")
    }

    return $Parsed
}

function Test-ReplicationHealth {
    param([string]$Server)

    # Windows PowerShell 5.1 turns native stderr into terminating errors under 'Stop'; keep native output as data.
    $ErrorActionPreference = 'Continue'

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

    # Windows PowerShell 5.1 turns native stderr into terminating errors under 'Stop'; keep native output as data.
    $ErrorActionPreference = 'Continue'

    try {
        $w32tm = w32tm /query /computer:$Server /status 2>&1
        if ($w32tm -match "Source:|NtpServer|Reference Identifier") {
            $Source = (@($w32tm | Select-String -Pattern "Source:" | ForEach-Object { ("$_" -replace ".*Source:\s*", "").Trim() }) -join ", ")
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
    # FSMO roles are domain/forest-wide, so they are checked once rather than per DC.
    param($Domain, $Forest)

    try {
        return [PSCustomObject]@{
            Server  = "(domain)"
            Check   = "FSMO Roles"
            Status  = "Pass"
            Details = "PDC: $($Domain.PDCEmulator), RID: $($Domain.RIDMaster), Infra: $($Domain.InfrastructureMaster), Schema: $($Forest.SchemaMaster), Domain naming: $($Forest.DomainNamingMaster)"
        }
    } catch {
        return [PSCustomObject]@{
            Server  = "(domain)"
            Check   = "FSMO Roles"
            Status  = "Fail"
            Details = $_.Exception.Message
        }
    }
}

Import-Module ActiveDirectory -ErrorAction Stop

if (-not $DomainControllers) {
    $DomainControllers = @((Get-ADDomainController -Filter *).Name | Sort-Object)
}

$DomainInfo = Get-ADDomain
$ForestInfo = Get-ADForest

Write-Log "Domain: $($DomainInfo.DNSRoot)"
Write-Log "Forest: $($ForestInfo.ForestMode)"
Write-Log "DCs Found: $(@($DomainControllers).Count)"

foreach ($DC in $DomainControllers) {
    Write-Log "Checking $DC..."

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
}

$Results += Test-FsmoRoles -Domain $DomainInfo -Forest $ForestInfo

$Failures = @($Results | Where-Object { $_.Status -eq "Fail" -or $_.Status -eq "Unhealthy" })
$Warnings = @($Results | Where-Object { $_.Status -eq "Warn" })

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

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8

Write-Log "Report: $htmlPath"
Write-Log "Summary: $($Results.Count) checks | $($Failures.Count) failures | $($Warnings.Count) warnings"

if ($Failures.Count -gt 0) {
    Write-Log "FAILURES:" 'ERROR'
    $Failures | ForEach-Object { Write-Log "  [$($_.Server)] $($_.Check): $($_.Details)" 'ERROR' }
}
