#Requires -Version 5.1
#Requires -Modules Az.Accounts, Az.Resources

<#
.SYNOPSIS
Produces a per-subscription overview of resource counts, resource groups and privileged role assignments.

.DESCRIPTION
Loops over every subscription the signed-in account can see and records its state, total resources, counts of
VMs, storage accounts, SQL, network, web app and Key Vault resources, resource group and tagged resource group
counts, and the number of Owner and Contributor assignments at subscription scope. A subscription that cannot be
read is listed with State "Error".

Output is an HTML report (primary) with totals and one row per subscription, plus an optional CSV with the full
column set. The script makes no changes to Azure.

.PARAMETER SubscriptionIds
Currently not applied: the script audits every accessible subscription regardless of this value.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the full result set to a CSV next to the HTML report.

.PARAMETER IncludeSpending
Reserved. Accepted for compatibility but currently has no effect (no cost data is collected).

.PARAMETER SkipAzConnect
Use the existing Az session instead of calling Connect-AzAccount.

.EXAMPLE
.\Get-AzureSubscriptionReport.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-AzureSubscriptionReport.ps1 -ExportCsv -SkipAzConnect -CustomerName Contoso -OutputPath D:\Reports

.NOTES
Platform:     Windows (PowerShell 5.1+ with Az.Accounts and Az.Resources modules)
Permissions:  Azure RBAC Reader on each subscription to be included
When to use:  First look at an unfamiliar tenant, to size an engagement, or to find empty or disabled subscriptions.
Safety:       Read-only
Version:      1.1
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionIds,

    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCsv,

    [switch]$IncludeSpending,

    [switch]$SkipAzConnect
)

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
$htmlPath = Join-Path $outDir "Get-AzureSubscriptionReport_$stamp.html"
$csvPath  = Join-Path $outDir "Get-AzureSubscriptionReport_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-AzureSubscriptionReport_$stamp.log"

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

function Get-ResourceCounts {
    param([string]$SubscriptionId)

    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    $Resources = Get-AzResource -ErrorAction SilentlyContinue

    $Counts = @{
        VMs = @($Resources | Where-Object { $_.ResourceType -eq "Microsoft.Compute/virtualMachines" }).Count
        Storage = @($Resources | Where-Object { $_.ResourceType -eq "Microsoft.Storage/storageAccounts" }).Count
        SQL = @($Resources | Where-Object { $_.ResourceType -like "Microsoft.Sql/*" }).Count
        Networks = @($Resources | Where-Object { $_.ResourceType -like "Microsoft.Network/*" }).Count
        WebApps = @($Resources | Where-Object { $_.ResourceType -eq "Microsoft.Web/sites" }).Count
        KeyVaults = @($Resources | Where-Object { $_.ResourceType -eq "Microsoft.KeyVault/vaults" }).Count
        Total = @($Resources).Count
    }

    return $Counts
}

# -- MAIN --
Write-Log 'Subscription audit starting.'

if (-not $SkipAzConnect) {
    Connect-ToAzure
}

$Subscriptions = Get-AzSubscription -ErrorAction Stop
$SubCount = ($Subscriptions | Measure-Object).Count

Write-Log "Found $SubCount subscriptions."

foreach ($Sub in $Subscriptions) {
    Write-Log "  Auditing: $($Sub.Name) ($($Sub.Id))"

    try {
        Set-AzContext -SubscriptionId $Sub.Id -ErrorAction Stop | Out-Null

        $ResourceCounts = Get-ResourceCounts -SubscriptionId $Sub.Id

        $Locations = Get-AzLocation -ErrorAction SilentlyContinue
        $RegionCount = @($Locations | Where-Object { $_.Providers -contains "Microsoft.Compute" }).Count

        $RoleAssignments = Get-AzRoleAssignment -ErrorAction SilentlyContinue |
            Where-Object { $_.Scope -like "/subscriptions/$($Sub.Id)" }
        $OwnerCount = @($RoleAssignments | Where-Object { $_.RoleDefinitionName -eq "Owner" }).Count
        $ContributorCount = @($RoleAssignments | Where-Object { $_.RoleDefinitionName -eq "Contributor" }).Count

        $RGs = @(Get-AzResourceGroup -ErrorAction SilentlyContinue)
        $TaggedRGs = @($RGs | Where-Object { $_.Tags -and $_.Tags.Count -gt 0 }).Count
        $TotalRGs = $RGs.Count

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
        Write-Log "Failed to audit subscription $($Sub.Name): $_" 'WARN'
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
$ActiveSubs = @($Results | Where-Object { $_.State -eq "Enabled" }).Count

Write-Log "Summary: Subscriptions $SubCount (Active: $ActiveSubs) | Total resources $TotalResources | VMs $TotalVMs | Storage $TotalStorage"

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

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "Report written: $htmlPath"

if ($ExportCsv) {
    $Results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV written: $csvPath"
}
