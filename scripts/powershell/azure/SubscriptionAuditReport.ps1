param(
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\SubscriptionAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeSpending,

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

function Get-ResourceCounts {
    param([string]$SubscriptionId)

    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    $Resources = Get-AzResource -ErrorAction SilentlyContinue

    $Counts = @{
        VMs = ($Resources | Where-Object { $_.ResourceType -eq "Microsoft.Compute/virtualMachines" }).Count
        Storage = ($Resources | Where-Object { $_.ResourceType -eq "Microsoft.Storage/storageAccounts" }).Count
        SQL = ($Resources | Where-Object { $_.ResourceType -like "Microsoft.Sql/*" }).Count
        Networks = ($Resources | Where-Object { $_.ResourceType -like "Microsoft.Network/*" }).Count
        WebApps = ($Resources | Where-Object { $_.ResourceType -eq "Microsoft.Web/sites" }).Count
        KeyVaults = ($Resources | Where-Object { $_.ResourceType -eq "Microsoft.KeyVault/vaults" }).Count
        Total = $Resources.Count
    }

    return $Counts
}

# ── MAIN ──
Write-Host "=== Subscription Audit Report ===" -ForegroundColor Cyan

if (-not $SkipAzConnect) {
    $Connected = Connect-ToAzure
    if (-not $Connected) { return }
}

$Subscriptions = Get-AzSubscription -ErrorAction Stop
$SubCount = ($Subscriptions | Measure-Object).Count

Write-Host "Found $SubCount subscriptions" -ForegroundColor Yellow

foreach ($Sub in $Subscriptions) {
    Write-Host "  Auditing: $($Sub.Name) ($($Sub.Id))" -ForegroundColor Gray

    try {
        Set-AzContext -SubscriptionId $Sub.Id | Out-Null

        $ResourceCounts = Get-ResourceCounts -SubscriptionId $Sub.Id

        $Locations = Get-AzLocation -ErrorAction SilentlyContinue
        $RegionCount = ($Locations | Where-Object { $_.Providers -contains "Microsoft.Compute" }).Count

        $RoleAssignments = Get-AzRoleAssignment -ErrorAction SilentlyContinue |
            Where-Object { $_.Scope -like "/subscriptions/$($Sub.Id)" }
        $OwnerCount = ($RoleAssignments | Where-Object { $_.RoleDefinitionName -eq "Owner" }).Count
        $ContributorCount = ($RoleAssignments | Where-Object { $_.RoleDefinitionName -eq "Contributor" }).Count

        $Tags = (Get-AzResourceGroup -ErrorAction SilentlyContinue).Tags
        $TaggedRGs = ($Tags | Where-Object { $_ -and $_.Count -gt 0 }).Count
        $TotalRGs = (Get-AzResourceGroup -ErrorAction SilentlyContinue).Count

        $State = (Get-AzSubscription -SubscriptionId $Sub.Id).State

        $Results.Add([PSCustomObject]@{
            SubscriptionName    = $Sub.Name
            SubscriptionId      = $Sub.Id
            State               = $State
            TotalResources      = $ResourceCounts.Total
            VMs                 = $ResourceCounts.VMs
            StorageAccounts     = $ResourceCounts.Storage
            SQLServers          = $ResourceCounts.SQL
            NetworkResources    = $ResourceCounts.Networks
            WebApps             = $ResourceCounts.WebApps
            KeyVaults           = $ResourceCounts.KeyVaults
            ResourceGroups      = $TotalRGs
            TaggedRGs           = $TaggedRGs
            Owners              = $OwnerCount
            Contributors        = $ContributorCount
            AvailableRegions    = $RegionCount
        })
    } catch {
        $Results.Add([PSCustomObject]@{
            SubscriptionName = $Sub.Name
            SubscriptionId   = $Sub.Id
            State            = "Error"
            TotalResources   = 0; VMs = 0; StorageAccounts = 0; SQLServers = 0
            NetworkResources = 0; WebApps = 0; KeyVaults = 0
            ResourceGroups   = 0; TaggedRGs = 0; Owners = 0; Contributors = 0
            AvailableRegions = 0
        })
    }
}

$TotalVMs = ($Results | Measure-Object -Property VMs -Sum).Sum
$TotalStorage = ($Results | Measure-Object -Property StorageAccounts -Sum).Sum
$TotalResources = ($Results | Measure-Object -Property TotalResources -Sum).Sum
$ActiveSubs = ($Results | Where-Object { $_.State -eq "Enabled" }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Subscriptions: $SubCount (Active: $ActiveSubs)" -ForegroundColor White
Write-Host "Total Resources: $TotalResources | VMs: $TotalVMs | Storage: $TotalStorage"

$HtmlRows = $Results | Sort-Object TotalResources -Descending | ForEach-Object {
    $StateClass = if ($_.State -ne "Enabled") { "danger" } else { "" }
    "<tr class='$StateClass'>
        <td>$($_.SubscriptionName)</td>
        <td>$($_.SubscriptionId)</td>
        <td>$($_.State)</td>
        <td>$($_.TotalResources)</td>
        <td>$($_.VMs)</td>
        <td>$($_.StorageAccounts)</td>
        <td>$($_.VMs)</td>
        <td>$($_.ResourceGroups)</td>
        <td>$($_.Owners)</td>
        <td>$($_.Contributors)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Subscription Audit Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 11px; }
th { background: #2c3e50; color: white; padding: 6px; text-align: left; }
td { padding: 4px 6px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
</style></head>
<body>
<h1>Subscription Audit Report</h1>
<div class='summary'>
    <strong>Subscriptions:</strong> $SubCount |
    <strong>Active:</strong> $ActiveSubs |
    <strong>Total Resources:</strong> $TotalResources |
    <strong>VMs:</strong> $TotalVMs |
    <strong>Storage:</strong> $TotalStorage
</div>
<table>
<tr><th>Subscription</th><th>ID</th><th>State</th><th>Resources</th><th>VMs</th><th>Storage</th><th>SQL</th><th>RGs</th><th>Owners</th><th>Contributors</th></tr>
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
