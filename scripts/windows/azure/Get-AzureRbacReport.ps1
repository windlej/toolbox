#Requires -Version 5.1
#Requires -Modules Az.Accounts, Az.Resources

<#
.SYNOPSIS
Reports privileged Azure RBAC role assignments (Owner, Contributor, User Access Administrator) per subscription and resource group.

.DESCRIPTION
For each accessible subscription (or the ones you list) the script reads role assignments at the subscription
scope and at every resource group scope, and keeps the ones whose role is in the privileged role list.
Each result row records the principal (display name, sign-in name, object type), role, scope and whether the
principal is a service principal.

Output is an HTML report (primary) with Owner / Contributor / user / service principal counts and one row per
assignment, plus an optional CSV. The script makes no changes to Azure.

.PARAMETER SubscriptionIds
Optional list of subscription ids to audit. Default: every subscription the signed-in account can see.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the assignments to a CSV next to the HTML report.

.PARAMETER PrivilegedRoles
Role names treated as privileged. Default: Owner, Contributor, User Access Administrator.

.PARAMETER SkipAzConnect
Use the existing Az session instead of calling Connect-AzAccount.

.EXAMPLE
.\Get-AzureRbacReport.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-AzureRbacReport.ps1 -SubscriptionIds 00000000-0000-0000-0000-000000000000 -PrivilegedRoles Owner,'User Access Administrator' -ExportCsv -CustomerName Fabrikam -OutputPath D:\Reports

.NOTES
Platform:     Windows (PowerShell 5.1+ with Az.Accounts and Az.Resources modules)
Permissions:  Azure RBAC Reader on each subscription (needs Microsoft.Authorization/roleAssignments/read); Entra directory read to resolve principal names
When to use:  Access review of a customer subscription, before removing standing Owner rights, or to list who can grant access.
Safety:       Read-only
Version:      1.1
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionIds,

    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCsv,

    [string[]]$PrivilegedRoles = @("Owner", "Contributor", "User Access Administrator"),

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
$htmlPath = Join-Path $outDir "Get-AzureRbacReport_$stamp.html"
$csvPath  = Join-Path $outDir "Get-AzureRbacReport_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-AzureRbacReport_$stamp.log"

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

function Get-RoleAssignmentsRecursive {
    param(
        [string]$Scope,
        [string]$SubscriptionName
    )

    $Assignments = $null
    try {
        $Assignments = Get-AzRoleAssignment -Scope $Scope -ErrorAction Stop
    } catch {
        Write-Log "Could not read role assignments at ${Scope}: $_" 'WARN'
    }
    $Found = @()

    foreach ($Assignment in $Assignments) {
        if ($Assignment.RoleDefinitionName -in $PrivilegedRoles) {
            $ScopeType = "Subscription"
            $ScopeName = $SubscriptionName

            $Found += [PSCustomObject]@{
                SubscriptionName  = $SubscriptionName
                Scope             = $Scope
                ScopeType         = $ScopeType
                ScopeName         = $ScopeName
                DisplayName       = $Assignment.DisplayName
                SignInName        = $Assignment.SignInName
                ObjectId          = $Assignment.ObjectId
                ObjectType        = $Assignment.ObjectType
                RoleDefinitionName = $Assignment.RoleDefinitionName
                RoleDefinitionId  = $Assignment.RoleDefinitionId
                IsServicePrincipal = $Assignment.ObjectType -eq "ServicePrincipal"
                CanDelegate       = $Assignment.CanDelegate
            }
        }
    }

    return $Found
}

# -- MAIN --
Write-Log 'RBAC audit starting.'
Write-Log "Monitoring roles: $($PrivilegedRoles -join ', ')"

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

    Write-Log "Auditing: $SubName"

    foreach ($Item in @(Get-RoleAssignmentsRecursive -Scope "/subscriptions/$SubId" -SubscriptionName $SubName)) {
        $Results.Add($Item)
    }

    try {
        $RGs = Get-AzResourceGroup -ErrorAction Stop
    } catch {
        Write-Log "Could not list resource groups in ${SubName}: $_" 'WARN'
        $RGs = @()
    }
    foreach ($RG in $RGs) {
        $RGAssignments = @(Get-RoleAssignmentsRecursive -Scope $RG.ResourceId -SubscriptionName $SubName)
        foreach ($Item in $RGAssignments) {
            $Results.Add($Item)
        }

        if ($RGAssignments.Count -gt 0) {
            Write-Log "  Found $($RGAssignments.Count) privileged assignments in RG: $($RG.ResourceGroupName)"
        }
    }
}

$TotalAssignments = $Results.Count
$OwnerCount = @($Results | Where-Object { $_.RoleDefinitionName -eq "Owner" }).Count
$ContributorCount = @($Results | Where-Object { $_.RoleDefinitionName -eq "Contributor" }).Count
$SPCount = @($Results | Where-Object { $_.IsServicePrincipal }).Count
$UserCount = @($Results | Where-Object { -not $_.IsServicePrincipal }).Count

Write-Log "Summary: Privileged assignments $TotalAssignments | Owners $OwnerCount | Contributors $ContributorCount | Users $UserCount | Service principals $SPCount"

$HtmlRows = $Results | Sort-Object RoleDefinitionName, DisplayName | ForEach-Object {
    $RowClass = if ($_.RoleDefinitionName -eq "Owner") { "danger" }
    elseif ($_.RoleDefinitionName -eq "Contributor") { "warning" }
    else { "" }
    "<tr class='$RowClass'>
        <td>$($_.SubscriptionName)</td>
        <td>$($_.DisplayName)</td>
        <td>$($_.SignInName)</td>
        <td>$($_.ObjectType)</td>
        <td>$($_.RoleDefinitionName)</td>
        <td>$($_.Scope)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>RBAC Audit Report</title>
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
<h1>RBAC Audit Report</h1>
<div class='summary'>
    <strong>Total Assignments:</strong> $TotalAssignments |
    <strong>Owners:</strong> <span style='color:red;'>$OwnerCount</span> |
    <strong>Contributors:</strong> <span style='color:orange;'>$ContributorCount</span> |
    <strong>Users:</strong> $UserCount |
    <strong>Service Principals:</strong> $SPCount
</div>
<table>
<tr><th>Subscription</th><th>Name</th><th>UPN</th><th>Type</th><th>Role</th><th>Scope</th></tr>
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
