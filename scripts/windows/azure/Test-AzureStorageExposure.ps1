#Requires -Version 5.1
#Requires -Modules Az.Accounts, Az.Storage

<#
.SYNOPSIS
Checks Azure storage accounts for public exposure and weak transport/network settings.

.DESCRIPTION
For each accessible subscription (or the ones you list) the script reads every storage account and flags:
anonymous blob public access, firewall default action Allow, HTTPS not required, minimum TLS below 1.2,
shared key access enabled, and no private endpoint when the firewall is set to Deny. Each account is rated
Low / Medium / High.

Output is an HTML report (primary) with risk counts and one row per storage account, plus an optional CSV that
also includes the risk flag text. The script makes no changes to Azure.

.PARAMETER SubscriptionIds
Optional list of subscription ids to check. Default: every subscription the signed-in account can see.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the results to a CSV next to the HTML report.

.PARAMETER SkipAzConnect
Use the existing Az session instead of calling Connect-AzAccount.

.EXAMPLE
.\Test-AzureStorageExposure.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Test-AzureStorageExposure.ps1 -SubscriptionIds 00000000-0000-0000-0000-000000000000 -ExportCsv -CustomerName Fabrikam -OutputPath D:\Reports

.NOTES
Platform:     Windows (PowerShell 5.1+ with Az.Accounts and Az.Storage modules)
Permissions:  Azure RBAC Reader on each subscription (Microsoft.Storage/storageAccounts/read); no data-plane access needed
When to use:  Security assessment, after a data-exposure scare, or before a compliance audit to find storage accounts open to the Internet.
Safety:       Read-only
Version:      1.1
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionIds,

    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCsv,

    [switch]$SkipAzConnect
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
$htmlPath = Join-Path $outDir "Test-AzureStorageExposure_$stamp.html"
$csvPath  = Join-Path $outDir "Test-AzureStorageExposure_$stamp.csv"
$script:LogFile = Join-Path $outDir "Test-AzureStorageExposure_$stamp.log"

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

# -- MAIN --
Write-Log 'Storage account public exposure check starting.'

if (-not $SkipAzConnect) {
    Connect-ToAzure
}

if (-not $SubscriptionIds) {
    $Subscriptions = Get-AzSubscription -ErrorAction Stop
    $SubscriptionIds = $Subscriptions.Id
}

foreach ($SubId in $SubscriptionIds) {
    try {
        Set-AzContext -SubscriptionId $SubId -ErrorAction Stop | Out-Null
        $SubName = (Get-AzContext).Subscription.Name
    } catch {
        Write-Log "Cannot access subscription ${SubId}: $_" 'WARN'
        continue
    }

    Write-Log "Checking $SubName..."

    try {
        $StorageAccounts = Get-AzStorageAccount -ErrorAction Stop
    } catch {
        Write-Log "Could not list storage accounts in ${SubName}: $_" 'WARN'
        continue
    }

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

$HighCount = @($Results | Where-Object { $_.RiskLevel -eq "High" }).Count
$MediumCount = @($Results | Where-Object { $_.RiskLevel -eq "Medium" }).Count
$LowCount = @($Results | Where-Object { $_.RiskLevel -eq "Low" }).Count

Write-Log "Summary: Storage accounts $($Results.Count) | High $HighCount | Medium $MediumCount | Low $LowCount"

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

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "Report written: $htmlPath"

if ($ExportCsv) {
    $Results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV written: $csvPath"
}
