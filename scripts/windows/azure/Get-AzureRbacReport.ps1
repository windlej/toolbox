param(
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\RBACAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string[]]$PrivilegedRoles = @("Owner", "Contributor", "User Access Administrator"),

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

function Get-RoleAssignmentsRecursive {
    param(
        [string]$Scope,
        [string]$SubscriptionName
    )

    $Assignments = Get-AzRoleAssignment -Scope $Scope -ErrorAction SilentlyContinue
    $Results = @()

    foreach ($Assignment in $Assignments) {
        if ($Assignment.RoleDefinitionName -in $PrivilegedRoles) {
            $ScopeType = "Subscription"
            $ScopeName = $SubscriptionName

            $Results += [PSCustomObject]@{
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

    return $Results
}

# ── MAIN ──
Write-Host "=== RBAC Audit Script ===" -ForegroundColor Cyan
Write-Host "Monitoring roles: $($PrivilegedRoles -join ', ')" -ForegroundColor White

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

    Write-Host "Auditing: $SubName" -ForegroundColor Yellow

    $Results.AddRange((Get-RoleAssignmentsRecursive -Scope "/subscriptions/$SubId" -SubscriptionName $SubName))

    $RGs = Get-AzResourceGroup -ErrorAction SilentlyContinue
    foreach ($RG in $RGs) {
        $RGAssignments = Get-RoleAssignmentsRecursive -Scope $RG.ResourceId -SubscriptionName $SubName
        $Results.AddRange($RGAssignments)

        if ($RGAssignments.Count -gt 0) {
            Write-Host "  Found $($RGAssignments.Count) privileged assignments in RG: $($RG.ResourceGroupName)" -ForegroundColor Gray
        }
    }
}

$TotalAssignments = $Results.Count
$OwnerCount = ($Results | Where-Object { $_.RoleDefinitionName -eq "Owner" }).Count
$ContributorCount = ($Results | Where-Object { $_.RoleDefinitionName -eq "Contributor" }).Count
$SPCount = ($Results | Where-Object { $_.IsServicePrincipal }).Count
$UserCount = ($Results | Where-Object { -not $_.IsServicePrincipal }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total Privileged Assignments: $TotalAssignments" -ForegroundColor White
Write-Host "  Owners: $OwnerCount" -ForegroundColor Red
Write-Host "  Contributors: $ContributorCount" -ForegroundColor Yellow
Write-Host "  Users: $UserCount" -ForegroundColor Gray
Write-Host "  Service Principals: $SPCount" -ForegroundColor Gray

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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}
