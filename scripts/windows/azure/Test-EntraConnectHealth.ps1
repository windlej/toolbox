#Requires -Version 5.1
#Requires -Modules Az.Accounts, Az.Resources

<#
.SYNOPSIS
Runs basic Azure/Entra connectivity checks and reports whether on-premises directory sync (Entra Connect) is enabled.

.DESCRIPTION
Signs in to Azure and records a short list of checks: Az connectivity, tenant discovery, subscription access, and
(via Microsoft Graph) whether the tenant has on-premises directory synchronization enabled.
When sync is enabled, informational rows are added reminding you to verify sync health and password hash sync
in the Entra Connect Health portal.

This is a lightweight sanity check, not a full Entra Connect health assessment: it does not read sync cycles,
connector errors or server status. The sync-status lookup uses Invoke-MgGraphRequest. An existing Graph session with
Organization.Read.All is reused; otherwise the script signs in with Connect-MgGraph -Scopes Organization.Read.All.
If the Graph module is missing, sign-in fails, or -SkipGraphConnect is set, the status is reported as undetermined.
The "Az Module Connection" check passes when an Az context with an account exists.

Output is an HTML report (primary) with pass/warn/fail counts and one row per check, plus an optional CSV.
The script makes no changes to Azure or Entra.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the check results to a CSV next to the HTML report.

.PARAMETER SkipAzConnect
Use the existing Az session instead of calling Connect-AzAccount.

.PARAMETER SkipGraphConnect
Do not call Connect-MgGraph. If no Graph session with Organization.Read.All exists, the sync-status check is skipped and reported as undetermined.

.EXAMPLE
.\Test-EntraConnectHealth.ps1 -OutputPath D:\Reports

.EXAMPLE
Connect-MgGraph -Scopes Organization.Read.All; .\Test-EntraConnectHealth.ps1 -SkipAzConnect -ExportCsv -CustomerName Contoso -OutputPath D:\Reports

.NOTES
Platform:     Windows (PowerShell 5.1+ with Az.Accounts and Az.Resources; Microsoft.Graph.Authentication for the sync-status check)
Permissions:  Any Azure RBAC role giving subscription visibility (Reader); Graph delegated Organization.Read.All (Entra role Global Reader or Directory Readers) for the sync status
When to use:  First-pass check of a hybrid tenant before a migration or when users report that on-premises changes are not syncing.
Safety:       Read-only
Version:      1.2
#>
[CmdletBinding()]
param(
    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCsv,

    [switch]$SkipAzConnect,

    [switch]$SkipGraphConnect
)

Set-StrictMode -Version Latest

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
$htmlPath = Join-Path $outDir "Test-EntraConnectHealth_$stamp.html"
$csvPath  = Join-Path $outDir "Test-EntraConnectHealth_$stamp.csv"
$script:LogFile = Join-Path $outDir "Test-EntraConnectHealth_$stamp.log"

$Results = [System.Collections.Generic.List[PSObject]]::new()

function Connect-ToAzure {
    try {
        Connect-AzAccount -ErrorAction Stop | Out-Null
        Write-Log 'Connected to Azure.'
    } catch {
        Write-Log "Azure connection failed: $_" 'ERROR'
        throw
    }
}

# Returns $true when a Graph session usable for the organization lookup exists (or was created), else $false.
function Connect-ToGraph {
    if (-not (Get-Command -Name Connect-MgGraph -ErrorAction SilentlyContinue)) {
        Write-Log 'Microsoft.Graph.Authentication is not installed; skipping the sync-status check. Install-Module Microsoft.Graph.Authentication' 'WARN'
        return $false
    }
    $ctx = Get-MgContext
    if ($ctx -and ($ctx.Scopes -contains 'Organization.Read.All' -or $ctx.Scopes -contains 'Organization.ReadWrite.All')) {
        Write-Log 'Using the existing Microsoft Graph session.'
        return $true
    }
    if ($SkipGraphConnect) {
        Write-Log 'No Microsoft Graph session with Organization.Read.All; skipping the sync-status check (-SkipGraphConnect).' 'WARN'
        return $false
    }
    try {
        Connect-MgGraph -Scopes 'Organization.Read.All' -NoWelcome -ErrorAction Stop | Out-Null
        Write-Log 'Connected to Microsoft Graph (Organization.Read.All).'
        return $true
    } catch {
        Write-Log "Microsoft Graph connection failed; skipping the sync-status check: $_" 'WARN'
        return $false
    }
}

function Get-ADConnectServer {
    $Uri = "https://graph.microsoft.com/v1.0/organization"
    try {
        $Org = Invoke-MgGraphRequest -Uri $Uri -Method Get -ErrorAction SilentlyContinue
        return $Org.value[0].onPremisesSyncEnabled
    } catch {
        return $null
    }
}

# -- MAIN --
Write-Log 'Entra Connect health check starting.'

if (-not $SkipAzConnect) {
    Connect-ToAzure
}

$ADConnectServer = $null
try {
    if (Connect-ToGraph) {
        $ADConnectServer = Get-ADConnectServer
    }
    if ($ADConnectServer -eq $true) {
        Write-Log 'Hybrid sync is ENABLED for this tenant.'
    } elseif ($ADConnectServer -eq $false) {
        Write-Log 'Hybrid sync is NOT enabled (cloud-only).'
    } else {
        Write-Log 'Could not determine sync status (is there a Microsoft Graph session?).' 'WARN'
    }
} catch {
    Write-Log "Cannot check sync status: $_" 'WARN'
}

$AzContext = $null
try {
    $AzContext = Get-AzContext -ErrorAction Stop
} catch {
    Write-Log "Could not read the Az context: $_" 'WARN'
}
$ConnectivityResults = [bool]($AzContext -and $AzContext.Account)

$Results.Add([PSCustomObject]@{
    CheckCategory    = "Azure Connectivity"
    CheckName        = "Az Module Connection"
    Status           = if ($ConnectivityResults) { "Pass" } else { "Fail" }
    Detail           = if ($ConnectivityResults) { "Az session active (context present)" } else { "No Az session (run Connect-AzAccount or omit -SkipAzConnect)" }
})

try {
    $Tenant = Get-AzTenant -ErrorAction SilentlyContinue
    $Results.Add([PSCustomObject]@{
        CheckCategory = "Azure Connectivity"
        CheckName     = "Tenant Discovery"
        Status        = if ($Tenant) { "Pass" } else { "Fail" }
        Detail        = if ($Tenant) { "Tenant: $($Tenant.Id)" } else { "No tenants found" }
    })
} catch {
    $Results.Add([PSCustomObject]@{
        CheckCategory = "Azure Connectivity"
        CheckName     = "Tenant Discovery"
        Status        = "Fail"
        Detail        = $_.Exception.Message
    })
}

try {
    $Subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue
    $SubCount = ($Subscriptions | Measure-Object).Count
    $Results.Add([PSCustomObject]@{
        CheckCategory = "Azure Connectivity"
        CheckName     = "Subscription Access"
        Status        = if ($SubCount -gt 0) { "Pass" } else { "Warn" }
        Detail        = "$SubCount subscriptions accessible"
    })
} catch {
    $Results.Add([PSCustomObject]@{
        CheckCategory = "Azure Connectivity"
        CheckName     = "Subscription Access"
        Status        = "Fail"
        Detail        = $_.Exception.Message
    })
}

if ($ADConnectServer -eq $true) {
    $Results.Add([PSCustomObject]@{
        CheckCategory = "Hybrid Identity"
        CheckName     = "AD Connect Sync Status"
        Status        = "Info"
        Detail        = "On-premises directory sync is enabled"
    })

    $Results.Add([PSCustomObject]@{
        CheckCategory = "Hybrid Identity"
        CheckName     = "Password Hash Sync"
        Status        = "Info"
        Detail        = "Check in Azure AD Connect portal"
    })
}

$PassCount = @($Results | Where-Object { $_.Status -eq "Pass" }).Count
$FailCount = @($Results | Where-Object { $_.Status -eq "Fail" }).Count
$WarnCount = @($Results | Where-Object { $_.Status -eq "Warn" }).Count

Write-Log "Summary: Checks $($Results.Count) | Pass $PassCount | Warn $WarnCount | Fail $FailCount"

$HtmlRows = $Results | ForEach-Object {
    $RowClass = switch ($_.Status) {
        "Pass" { "" }
        "Fail" { "danger" }
        "Warn" { "warning" }
        default { "" }
    }
    "<tr class='$RowClass'>
        <td>$($_.CheckCategory)</td>
        <td>$($_.CheckName)</td>
        <td>$($_.Status)</td>
        <td>$($_.Detail)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Entra Connect Health Check</title>
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
<h1>Entra Connect Health Check</h1>
<div class='summary'>
    <strong>Total Checks:</strong> $($Results.Count) |
    <strong>Pass:</strong> $PassCount |
    <strong>Warnings:</strong> $WarnCount |
    <strong>Failures:</strong> $FailCount
</div>
<table>
<tr><th>Category</th><th>Check</th><th>Status</th><th>Detail</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "Report written: $htmlPath"

if ($ExportCsv) {
    $Results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV written: $csvPath"
}
