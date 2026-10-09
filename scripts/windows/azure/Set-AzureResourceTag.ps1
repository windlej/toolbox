#Requires -Version 5.1
#Requires -Modules Az.Accounts, Az.Resources

<#
.SYNOPSIS
Audits Azure resources for required tags and optionally adds the missing ones with a default value.

.DESCRIPTION
For each accessible subscription (or the ones you list) the script reads resources of 15 common types (VMs,
NSGs, public IPs, VNets, storage, SQL servers, web apps, container registries, Key Vaults, managed identities,
load balancers, application gateways, disks, automation accounts, data factories) and checks each for the tags
named in -RequiredTags. With -EnforcedTagValues ("Tag=Value") the tag must also have that exact value.

By default nothing is changed. With -ApplyTags, each non-compliant resource gets the missing required tags
merged in with -DefaultValue (existing tags are preserved; wrong values on enforced tags are reported but not
overwritten). Each write is guarded by ShouldProcess, so -WhatIf shows what would change and -Confirm prompts.

Output is an HTML report (primary) with compliance counts and one row per resource, plus an optional CSV.

.PARAMETER SubscriptionIds
Optional list of subscription ids to process. Default: every subscription the signed-in account can see.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the results to a CSV next to the HTML report.

.PARAMETER RequiredTags
Tag names every resource must have. Optional. Default: Environment, Owner, CostCenter.

.PARAMETER EnforcedTagValues
Optional list of "Tag=Value" entries. A required tag listed here must equal that value to be compliant.
Every tag named here must also be in -RequiredTags, and each entry must be Tag=Value (the value may itself
contain '='); otherwise the script stops before doing anything.

.PARAMETER ApplyTags
Add missing required tags (value from -DefaultValue). Without this switch the script is read-only.

.PARAMETER DefaultValue
Value written for missing tags when -ApplyTags is used. Default: Unknown.

.PARAMETER SkipAzConnect
Use the existing Az session instead of calling Connect-AzAccount.

.EXAMPLE
.\Set-AzureResourceTag.ps1 -RequiredTags Environment,Owner,CostCenter -OutputPath D:\Reports

.EXAMPLE
.\Set-AzureResourceTag.ps1 -RequiredTags Environment,Owner -ApplyTags -DefaultValue TBD -WhatIf -SubscriptionIds 00000000-0000-0000-0000-000000000000 -OutputPath D:\Reports

.NOTES
Platform:     Windows (PowerShell 5.1+ with Az.Accounts and Az.Resources modules)
Permissions:  Azure RBAC Reader to audit; Tag Contributor (or Contributor) on the scope when using -ApplyTags
When to use:  Tag governance clean-up before a cost-allocation exercise or policy rollout; run without -ApplyTags first and review the report.
Safety:       Changes data (supports -WhatIf)
Version:      1.2
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$SubscriptionIds,

    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCsv,

    [ValidateNotNullOrEmpty()]
    [string[]]$RequiredTags = @("Environment", "Owner", "CostCenter"),

    [string[]]$EnforcedTagValues,

    [switch]$ApplyTags,

    [string]$DefaultValue = "Unknown",

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

$EnforcedMap = @{}
foreach ($Entry in @($EnforcedTagValues)) {
    if ([string]::IsNullOrEmpty($Entry)) { continue }
    $Parts = $Entry -split '=', 2
    if ($Parts.Count -ne 2 -or -not $Parts[0]) {
        throw "-EnforcedTagValues entry '$Entry' must be in Tag=Value form."
    }
    if ($RequiredTags -notcontains $Parts[0]) {
        throw "-EnforcedTagValues tag '$($Parts[0])' must also be listed in -RequiredTags."
    }
    $EnforcedMap[$Parts[0]] = $Parts[1]
}

$stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir   = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$htmlPath = Join-Path $outDir "Set-AzureResourceTag_$stamp.html"
$csvPath  = Join-Path $outDir "Set-AzureResourceTag_$stamp.csv"
$script:LogFile = Join-Path $outDir "Set-AzureResourceTag_$stamp.log"

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

function Set-ResourceTags {
    param([string]$ResourceId, [hashtable]$Tags)

    try {
        Update-AzTag -ResourceId $ResourceId -Tag $Tags -Operation Merge -ErrorAction Stop | Out-Null
        return "Updated"
    } catch {
        Write-Log "Failed to update tags on ${ResourceId}: $_" 'WARN'
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

# -- MAIN --
Write-Log 'Resource tagging audit starting.'
Write-Log "Required tags: $($RequiredTags -join ', ')"
if ($ApplyTags) { Write-Log "-ApplyTags set: missing tags will be added with value '$DefaultValue'." 'WARN' }

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
foreach ($Key in $EnforcedMap.Keys) { $TagMap[$Key] = $EnforcedMap[$Key] }

foreach ($SubId in $SubscriptionIds) {
    try {
        Set-AzContext -SubscriptionId $SubId -ErrorAction Stop | Out-Null
        $SubName = (Get-AzContext).Subscription.Name
    } catch {
        Write-Log "Cannot access subscription ${SubId}: $_" 'WARN'
        continue
    }

    Write-Log "Auditing subscription: $SubName"

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
                if ($PSCmdlet.ShouldProcess($Resource.ResourceId, "Merge required tags ($($RequiredTags -join ', '))")) {
                    $Action = Set-ResourceTags -ResourceId $Resource.ResourceId -Tags $NewTags
                }
                else {
                    $Action = "Skipped"
                }
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
$CompliantCount = @($Results | Where-Object { $_.Compliant }).Count
$NonCompliantCount = @($Results | Where-Object { -not $_.Compliant }).Count
$UpdatedCount = @($Results | Where-Object { $_.Action -eq "Updated" }).Count

Write-Log "Summary: Resources audited $TotalResources | Compliant $CompliantCount | Non-compliant $NonCompliantCount"
if ($ApplyTags) { Write-Log "Updated: $UpdatedCount" }

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

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "Report written: $htmlPath"

if ($ExportCsv) {
    $Results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV written: $csvPath"
}
