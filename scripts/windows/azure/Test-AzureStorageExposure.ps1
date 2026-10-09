param(
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\StorageExposure_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

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

function Test-StorageExposure {
    param([PSObject]$StorageAccount)

    $Flags = @()
    $Risk = "Low"

    if ($StorageAccount.AllowBlobPublicAccess -eq $true) {
        $Flags += "BlobPublicAccessEnabled"
        $Risk = "High"
    }

    if ($StorageAccount.NetworkRuleSet.DefaultAction -eq "Allow") {
        $Flags += "FirewallDisabled (All networks allowed)"
        $Risk = "High"
    }

    if (-not $StorageAccount.EnableHttpsTrafficOnly) {
        $Flags += "HTTPSNotRequired"
        $Risk = "Medium"
    }

    if ($StorageAccount.MinimumTlsVersion -ne "TLS1_2" -and $StorageAccount.MinimumTlsVersion -ne "TLS1_3") {
        $Flags += "TLSVersion:$($StorageAccount.MinimumTlsVersion)"
        $Risk = if ($Risk -ne "High") { "Medium" } else { $Risk }
    }

    if ($StorageAccount.AllowSharedKeyAccess -ne $false) {
        $Flags += "SharedKeyAccessEnabled"
    }

    if ($StorageAccount.PrivateEndpointConnections.Count -eq 0 -and $StorageAccount.NetworkRuleSet.DefaultAction -eq "Deny") {
        $Flags += "NoPrivateEndpoint"
    }

    return @{ Risk = $Risk; Flags = $Flags }
}

# ── MAIN ──
Write-Host "=== Storage Account Public Exposure Check ===" -ForegroundColor Cyan

if (-not $SkipAzConnect) {
    $Connected = Connect-ToAzure
    if (-not $Connected) { return }
}

if (-not $SubscriptionIds) {
    $Subscriptions = Get-AzSubscription -ErrorAction Stop
    $SubscriptionIds = $Subscriptions.Id
}

foreach ($SubId in $SubscriptionIds) {
    try {
        Set-AzContext -SubscriptionId $SubId | Out-Null
        $SubName = (Get-AzContext).Subscription.Name
    } catch { continue }

    Write-Host "Checking $SubName..." -ForegroundColor Yellow

    $StorageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue

    foreach ($SA in $StorageAccounts) {
        $Analysis = Test-StorageExposure -StorageAccount $SA

        $Results.Add([PSCustomObject]@{
            SubscriptionName    = $SubName
            ResourceGroup       = $SA.ResourceGroupName
            StorageAccountName  = $SA.StorageAccountName
            Location            = $SA.Location
            SkuName             = $SA.Sku.Name
            Kind                = $SA.Kind
            PublicBlobAccess    = $SA.AllowBlobPublicAccess
            HttpsOnly           = $SA.EnableHttpsTrafficOnly
            MinTlsVersion       = $SA.MinimumTlsVersion
            FirewallMode        = $SA.NetworkRuleSet.DefaultAction
            PrivateEndpoints    = $SA.PrivateEndpointConnections.Count
            RiskLevel           = $Analysis.Risk
            RiskFlags           = ($Analysis.Flags -join '; ')
        })
    }
}

$HighCount = ($Results | Where-Object { $_.RiskLevel -eq "High" }).Count
$MediumCount = ($Results | Where-Object { $_.RiskLevel -eq "Medium" }).Count
$LowCount = ($Results | Where-Object { $_.RiskLevel -eq "Low" }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Storage Accounts: $($Results.Count) | High: $HighCount | Medium: $MediumCount | Low: $LowCount"

$HtmlRows = $Results | Sort-Object RiskLevel, SubscriptionName | ForEach-Object {
    $RowClass = switch ($_.RiskLevel) {
        "High" { "danger" }
        "Medium" { "warning" }
        default { "" }
    }
    "<tr class='$RowClass'>
        <td>$($_.SubscriptionName)</td>
        <td>$($_.StorageAccountName)</td>
        <td>$($_.Kind)</td>
        <td>$($_.PublicBlobAccess)</td>
        <td>$($_.FirewallMode)</td>
        <td>$($_.HttpsOnly)</td>
        <td>$($_.MinTlsVersion)</td>
        <td>$($_.PrivateEndpoints)</td>
        <td>$($_.RiskLevel)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Storage Account Public Exposure Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 11px; }
th { background: #2c3e50; color: white; padding: 6px; text-align: left; }
td { padding: 4px 6px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
.warning td { background: #fff3cd; }
</style></head>
<body>
<h1>Storage Account Public Exposure Check</h1>
<div class='summary'>
    <strong>Total:</strong> $($Results.Count) |
    <strong>High Risk:</strong> <span style='color:red;'>$HighCount</span> |
    <strong>Medium Risk:</strong> <span style='color:orange;'>$MediumCount</span> |
    <strong>Low Risk:</strong> $LowCount
</div>
<table>
<tr><th>Subscription</th><th>Storage Account</th><th>Kind</th><th>Blob Public</th><th>Firewall</th><th>HTTPS Only</th><th>TLS</th><th>Private EP</th><th>Risk</th></tr>
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
