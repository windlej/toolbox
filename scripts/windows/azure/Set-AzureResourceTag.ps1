param(
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\TaggingAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $true)]
    [string[]]$RequiredTags = @("Environment", "Owner", "CostCenter"),

    [Parameter(Mandatory = $false)]
    [string[]]$EnforcedTagValues,

    [Parameter(Mandatory = $false)]
    [switch]$ApplyTags,

    [Parameter(Mandatory = $false)]
    [string]$DefaultValue = "Unknown",

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAzConnect
)

$Results = [System.Collections.Generic.List[PSObject]]::new()

function Connect-ToAzure {
    try {
        if (-not (Get-Module Az.Resources -ListAvailable -ErrorAction SilentlyContinue)) {
            Write-Warning "Az module not found"
            return $false
        }
        Connect-AzAccount -ErrorAction Stop
        Write-Host "Connected to Azure" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Azure connection failed: $_"
        return $false
    }
}

function Get-ResourceTags {
    param([string]$ResourceId)

    try {
        $Resource = Get-AzResource -ResourceId $ResourceId -ErrorAction SilentlyContinue
        if ($Resource) { return $Resource.Tags }
    } catch { }
    return $null
}

function Set-ResourceTags {
    param([string]$ResourceId, [hashtable]$Tags)

    if ($WhatIf) {
        Write-Host "[WhatIf] Would update tags on: $ResourceId" -ForegroundColor Yellow
        return "WhatIf"
    }

    try {
        Update-AzTag -ResourceId $ResourceId -Tag $Tags -Operation Merge -ErrorAction Stop
        return "Updated"
    } catch {
        return "Failed"
    }
}

function Get-ResourcesByType {
    param([string]$ResourceType)

    try {
        $Resources = Get-AzResource -ResourceType $ResourceType -ErrorAction SilentlyContinue
        return $Resources
    } catch { return @() }
}

# ── MAIN ──
Write-Host "=== Resource Tagging Enforcement ===" -ForegroundColor Cyan
Write-Host "Required Tags: $($RequiredTags -join ', ')" -ForegroundColor White

if (-not $SkipAzConnect) {
    Connect-ToAzure
}

if (-not $SubscriptionIds) {
    $Subscriptions = Get-AzSubscription -ErrorAction Stop
    $SubscriptionIds = $Subscriptions.Id
}

$ResourceTypes = @(
    "Microsoft.Compute/virtualMachines",
    "Microsoft.Network/networkSecurityGroups",
    "Microsoft.Network/publicIPAddresses",
    "Microsoft.Network/virtualNetworks",
    "Microsoft.Storage/storageAccounts",
    "Microsoft.Sql/servers",
    "Microsoft.Web/sites",
    "Microsoft.ContainerRegistry/registries",
    "Microsoft.KeyVault/vaults",
    "Microsoft.ManagedIdentity/userAssignedIdentities",
    "Microsoft.Network/loadBalancers",
    "Microsoft.Network/applicationGateways",
    "Microsoft.Compute/disks",
    "Microsoft.Automation/automationAccounts",
    "Microsoft.DataFactory/factories"
)

$TagMap = @{}
$RequiredTags | ForEach-Object { $TagMap[$_] = "Required" }
if ($EnforcedTagValues) {
    foreach ($Entry in $EnforcedTagValues) {
        $Parts = $Entry -split '='
        if ($Parts.Count -eq 2) { $TagMap[$Parts[0]] = $Parts[1] }
    }
}

foreach ($SubId in $SubscriptionIds) {
    try {
        Set-AzContext -SubscriptionId $SubId | Out-Null
        $SubName = (Get-AzContext).Subscription.Name
    } catch { continue }

    Write-Host "Auditing subscription: $SubName" -ForegroundColor Yellow

    foreach ($Type in $ResourceTypes) {
        $Resources = Get-ResourcesByType -ResourceType $Type
        if (-not $Resources) { continue }
        $TypeShort = $Type -replace 'Microsoft\.\w+\.', ''

        foreach ($Resource in $Resources) {
            $Tags = $Resource.Tags
            $MissingTags = @()
            $PresentTags = @()

            foreach ($ReqTag in $RequiredTags) {
                if ($Tags -and $Tags.ContainsKey($ReqTag)) {
                    $PresentTags += $ReqTag
                    $Val = $Tags[$ReqTag]

                    if ($EnforcedTagValues -and $TagMap[$ReqTag] -and $TagMap[$ReqTag] -ne "Required") {
                        $ExpectedValue = $TagMap[$ReqTag]
                        if ($Val -ne $ExpectedValue) {
                            $MissingTags += "$ReqTag (expected: $ExpectedValue, actual: $Val)"
                        }
                    }
                } else {
                    $MissingTags += $ReqTag
                }
            }

            $Compliant = $MissingTags.Count -eq 0

            $Action = "None"
            if (-not $Compliant -and $ApplyTags) {
                $NewTags = @{ }
                if ($Tags) { $Tags.GetEnumerator() | ForEach-Object { $NewTags[$_.Key] = $_.Value } }
                foreach ($Tag in $RequiredTags) {
                    if (-not $NewTags.ContainsKey($Tag)) { $NewTags[$Tag] = $DefaultValue }
                }
                $Action = Set-ResourceTags -ResourceId $Resource.ResourceId -Tags $NewTags
            }

            $Results.Add([PSCustomObject]@{
                SubscriptionName = $SubName
                ResourceGroup    = $Resource.ResourceGroupName
                ResourceName     = $Resource.Name
                ResourceType     = $TypeShort
                Location         = $Resource.Location
                MissingTags      = ($MissingTags -join '; ')
                PresentTags      = ($PresentTags -join '; ')
                Compliant        = $Compliant
                Action           = $Action
            })
        }
    }
}

$TotalResources = $Results.Count
$CompliantCount = ($Results | Where-Object { $_.Compliant }).Count
$NonCompliantCount = ($Results | Where-Object { -not $_.Compliant }).Count
$UpdatedCount = ($Results | Where-Object { $_.Action -eq "Updated" }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Resources Audited: $TotalResources" -ForegroundColor White
Write-Host "Compliant: $CompliantCount" -ForegroundColor Green
Write-Host "Non-Compliant: $NonCompliantCount" -ForegroundColor Red
if ($ApplyTags) { Write-Host "Updated: $UpdatedCount" -ForegroundColor Yellow }

$HtmlRows = $Results | Sort-Object Compliant, SubscriptionName, ResourceType | ForEach-Object {
    $RowClass = if (-not $_.Compliant) { "danger" } else { "" }
    "<tr class='$RowClass'>
        <td>$($_.SubscriptionName)</td>
        <td>$($_.ResourceGroup)</td>
        <td>$($_.ResourceName)</td>
        <td>$($_.ResourceType)</td>
        <td>$($_.MissingTags)</td>
        <td>$($_.Compliant)</td>
        <td>$($_.Action)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Resource Tagging Audit Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 11px; }
th { background: #2c3e50; color: white; padding: 6px; text-align: left; }
td { padding: 4px 6px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
</style></head>
<body>
<h1>Resource Tagging Audit Report</h1>
<div class='summary'>
    <strong>Resources:</strong> $TotalResources |
    <strong>Compliant:</strong> <span style='color:green;'>$CompliantCount</span> |
    <strong>Non-Compliant:</strong> <span style='color:red;'>$NonCompliantCount</span> |
    <strong>Updated:</strong> $UpdatedCount |
    <strong>Required Tags:</strong> $($RequiredTags -join ', ')
</div>
<table>
<tr><th>Subscription</th><th>RG</th><th>Resource</th><th>Type</th><th>Missing Tags</th><th>Compliant</th><th>Action</th></tr>
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
