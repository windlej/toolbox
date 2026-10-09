param(
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\ADConnectHealth_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAzConnect
)

$Results = [System.Collections.Generic.List[PSObject]]::new()

function Connect-ToAzure {
    try {
        Connect-AzAccount -ErrorAction Stop
        Write-Host "Connected to Azure" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Azure connection failed: $_"
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

# ── MAIN ──
Write-Host "=== Azure AD Connect Health Check ===" -ForegroundColor Cyan

if (-not $SkipAzConnect) {
    $Connected = Connect-ToAzure
    if (-not $Connected) { return }
}

try {
    $ADConnectServer = Get-ADConnectServer
    if ($ADConnectServer -eq $true) {
        Write-Host "Hybrid sync is ENABLED for this tenant" -ForegroundColor Green
    } elseif ($ADConnectServer -eq $false) {
        Write-Host "Hybrid sync is NOT enabled (cloud-only)" -ForegroundColor Yellow
    } else {
        Write-Host "Could not determine sync status" -ForegroundColor Yellow
    }
} catch {
    Write-Warning "Cannot check sync status: $_"
}

$AADConnect = Get-AzADApplication -ErrorAction SilentlyContinue | Select-Object -First 1

$ConnectivityResults = $false
try {
    Test-AzADServicePrincipalCredential -ErrorAction SilentlyContinue | Out-Null
    $ConnectivityResults = $true
} catch { }

$Results.Add([PSCustomObject]@{
    CheckCategory    = "Azure Connectivity"
    CheckName        = "Az Module Connection"
    Status           = if ($ConnectivityResults) { "Pass" } else { "Fail" }
    Detail           = if ($ConnectivityResults) { "Connected to Azure" } else { "Connection failed" }
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

$PassCount = ($Results | Where-Object { $_.Status -eq "Pass" }).Count
$FailCount = ($Results | Where-Object { $_.Status -eq "Fail" }).Count
$WarnCount = ($Results | Where-Object { $_.Status -eq "Warn" }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Checks: $($Results.Count) | Pass: $PassCount | Warn: $WarnCount | Fail: $FailCount"

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
<head><title>Azure AD Connect Health Check</title>
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
<h1>Azure AD Connect Health Check</h1>
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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}
