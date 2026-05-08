param(
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\PrivilegedRoleAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludePimEligible,

    [Parameter(Mandatory = $false)]
    [switch]$IncludePermanent,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGraphConnect
)

$Results = [System.Collections.Generic.List[PSObject]]::new()
$PimActivations = @()

function Connect-ToGraph {
    $scopes = @(
        'RoleManagement.Read.Directory',
        'Directory.Read.All',
        'User.Read.All',
        'AuditLog.Read.All'
    )
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Host "Connected to Graph" -ForegroundColor Green
    } catch {
        throw "Graph auth failed: $_"
    }
}

$PrivilegedRoleNames = @(
    'Global Administrator',
    'Privileged Role Administrator',
    'Exchange Administrator',
    'SharePoint Administrator',
    'Security Administrator',
    'Conditional Access Administrator',
    'Application Administrator',
    'Cloud Application Administrator',
    'User Administrator',
    'Helpdesk Administrator',
    'Password Administrator',
    'Billing Administrator',
    'Hybrid Identity Administrator',
    'Identity Governance Administrator',
    'Privileged Authentication Administrator',
    'Authentication Administrator',
    'Groups Administrator',
    'Intune Administrator',
    'Device Administrators',
    'Power BI Administrator',
    'Teams Administrator',
    'Compliance Administrator',
    'Information Protection Administrator'
)

function Resolve-RoleTemplateId {
    $Uri = "https://graph.microsoft.com/v1.0/directoryRoles"
    $Response = Invoke-MgGraphRequest -Uri $Uri -Method Get -ErrorAction Stop
    $Templates = @{}
    foreach ($Role in $Response.value) {
        $Templates[$Role.roleTemplateId] = $Role.displayName
    }
    return $Templates
}

function Resolve-UnifiedRoleDefinitionId {
    $Uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
    $RoleMap = @{}
    try {
        $Response = Invoke-MgGraphRequest -Uri $Uri -Method Get -ErrorAction Stop
        foreach ($Role in $Response.value) {
            $RoleMap[$Role.id] = $Role.displayName
        }
    } catch { }
    return $RoleMap
}

function Get-DirectoryRoleMembers {
    param([hashtable]$RoleTemplateMap)

    $Results = @()
    $Uri = "https://graph.microsoft.com/v1.0/directoryRoles"

    try {
        $Roles = Invoke-MgGraphRequest -Uri $Uri -Method Get -ErrorAction Stop
        foreach ($Role in $Roles.value) {
            $RoleDisplayName = $RoleTemplateMap[$Role.roleTemplateId]
            if (-not $RoleDisplayName) { $RoleDisplayName = $Role.displayName }

            $MembersUri = "https://graph.microsoft.com/v1.0/directoryRoles/$($Role.id)/members"
            try {
                $Members = Invoke-MgGraphRequest -Uri $MembersUri -Method Get -ErrorAction Stop
                foreach ($Member in $Members.value) {
                    $UserDetail = Get-MgUser -UserId $Member.id -Property DisplayName,
                        UserPrincipalName, UserType, Department, JobTitle,
                        CreatedDateTime -ErrorAction SilentlyContinue

                    $Results += [PSCustomObject]@{
                        RoleDisplayName    = $RoleDisplayName
                        RoleId             = $Role.id
                        UserId             = $Member.id
                        UserPrincipalName  = if ($UserDetail) { $UserDetail.UserPrincipalName } else { "Unknown" }
                        DisplayName        = if ($UserDetail) { $UserDetail.DisplayName } else { $Member.displayName }
                        UserType           = if ($UserDetail) { $UserDetail.UserType } else { "Unknown" }
                        Department         = if ($UserDetail) { $UserDetail.Department } else { "" }
                        JobTitle           = if ($UserDetail) { $UserDetail.JobTitle } else { "" }
                        AssignmentType     = "Permanent (Directory Role)"
                        CreatedDateTime    = if ($UserDetail) { $UserDetail.CreatedDateTime } else { $null }
                    }
                }
            } catch { }
        }
    } catch { }

    return $Results
}

function Get-UnifiedRoleAssignments {
    param(
        [hashtable]$RoleDefinitionMap,
        [bool]$IncludePermanent,
        [bool]$IncludeEligible
    )

    $Results = @()

    $Uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$expand=principal&`$top=100"
    try {
        while ($true) {
            $Response = Invoke-MgGraphRequest -Uri $Uri -Method Get -ErrorAction Stop
            foreach ($Assignment in $Response.value) {
                $RoleName = $RoleDefinitionMap[$Assignment.roleDefinitionId]
                if (-not $RoleName) { $RoleName = $Assignment.roleDefinitionId }

                $Principal = $Assignment.principal
                if (-not $Principal -or $Principal.'@odata.type' -ne '#microsoft.graph.user') { continue }

                $Results += [PSCustomObject]@{
                    RoleDisplayName   = $RoleName
                    RoleId            = $Assignment.roleDefinitionId
                    UserId            = $Principal.id
                    UserPrincipalName = $Principal.userPrincipalName
                    DisplayName       = $Principal.displayName
                    UserType          = $null
                    Department        = ""
                    JobTitle          = ""
                    AssignmentType    = "Permanent (Unified Role)"
                    CreatedDateTime   = $null
                }
            }

            $Uri = $Response.'@odata.nextLink'
            if (-not $Uri) { break }
        }
    } catch { }

    if ($IncludeEligible) {
        $EligibleUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=principal&`$top=100"
        try {
            $Response = Invoke-MgGraphRequest -Uri $EligibleUri -Method Get -ErrorAction Stop
            foreach ($Assignment in $Response.value) {
                $RoleName = $RoleDefinitionMap[$Assignment.roleDefinitionId]
                if (-not $RoleName) { $RoleName = $Assignment.roleDefinitionId }

                $Principal = $Assignment.principal
                if (-not $Principal -or $Principal.'@odata.type' -ne '#microsoft.graph.user') { continue }

                $Results += [PSCustomObject]@{
                    RoleDisplayName   = $RoleName
                    RoleId            = $Assignment.roleDefinitionId
                    UserId            = $Principal.id
                    UserPrincipalName = $Principal.userPrincipalName
                    DisplayName       = $Principal.displayName
                    UserType          = $null
                    Department        = ""
                    JobTitle          = ""
                    AssignmentType    = "Eligible (PIM)"
                    CreatedDateTime   = $Assignment.startDateTime
                }
            }
        } catch {
            Write-Warning "PIM eligibility data unavailable (requires P2 licensing): $_"
        }
    }

    return $Results
}

# ── MAIN ──

Write-Host "=== Privileged Role Assignment Audit ===" -ForegroundColor Cyan

if (-not $SkipGraphConnect) {
    Connect-ToGraph
}

Write-Host "Resolving role definitions..." -ForegroundColor Yellow
$RoleTemplateMap = Resolve-RoleTemplateId
$RoleDefinitionMap = Resolve-UnifiedRoleDefinitionId

Write-Host "Retrieving directory role assignments..." -ForegroundColor Yellow
$DirRoleResults = Get-DirectoryRoleMembers -RoleTemplateMap $RoleTemplateMap
Write-Host "Found $($DirRoleResults.Count) directory role assignments" -ForegroundColor Gray

Write-Host "Retrieving unified role assignments..." -ForegroundColor Yellow
$UnifiedResults = Get-UnifiedRoleAssignments -RoleDefinitionMap $RoleDefinitionMap `
    -IncludePermanent $IncludePermanent -IncludeEligible $IncludePimEligible
Write-Host "Found $($UnifiedResults.Count) unified role assignments" -ForegroundColor Gray

$Results = $DirRoleResults + $UnifiedResults
$Results = $Results | Where-Object {
    $PrivilegedRoleNames -contains $_.RoleDisplayName
} | Sort-Object RoleDisplayName, UserPrincipalName | Select-Object -Unique

$GlobalAdminCount = ($Results | Where-Object { $_.RoleDisplayName -eq "Global Administrator" }).Count
$PermanentCount = ($Results | Where-Object { $_.AssignmentType -match "Permanent" }).Count
$PimCount = ($Results | Where-Object { $_.AssignmentType -match "Eligible" }).Count
$UniqueRoles = ($Results | Select-Object -ExpandProperty RoleDisplayName -Unique).Count
$UniqueUsers = ($Results | Select-Object -ExpandProperty UserPrincipalName -Unique).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total Privileged Assignments: $($Results.Count)" -ForegroundColor White
Write-Host "  Global Admins: $GlobalAdminCount" -ForegroundColor Red
Write-Host "  Permanent Assignments: $PermanentCount" -ForegroundColor Yellow
Write-Host "  PIM Eligible: $PimCount" -ForegroundColor Green
Write-Host "  Unique Roles: $UniqueRoles" -ForegroundColor Gray
Write-Host "  Unique Users: $UniqueUsers" -ForegroundColor Yellow

$HtmlRows = $Results | Sort-Object RoleDisplayName, UserPrincipalName | ForEach-Object {
    $RowClass = if ($_.RoleDisplayName -eq "Global Administrator") { "danger" }
    elseif ($_.AssignmentType -match "Permanent") { "warning" }
    else { "" }
    "<tr class='$RowClass'>
        <td>$($_.RoleDisplayName)</td>
        <td>$($_.UserPrincipalName)</td>
        <td>$($_.DisplayName)</td>
        <td>$($_.AssignmentType)</td>
        <td>$($_.Department)</td>
        <td>$($_.JobTitle)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Privileged Role Audit Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 5px 8px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
.warning td { background: #fff3cd; }
</style></head>
<body>
<h1>Privileged Role Assignment Audit</h1>
<div class='summary'>
    <strong>Total Assignments:</strong> $($Results.Count) |
    <strong>Global Admins:</strong> <span style='color:red;'>$GlobalAdminCount</span> |
    <strong>Permanent:</strong> <span style='color:orange;'>$PermanentCount</span> |
    <strong>PIM Eligible:</strong> $PimCount |
    <strong>Unique Roles:</strong> $UniqueRoles |
    <strong>Unique Users:</strong> $UniqueUsers
</div>
<table>
<tr><th>Role</th><th>User</th><th>Name</th><th>Assignment Type</th><th>Department</th><th>Job Title</th></tr>
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

if ($PermanentCount -gt 0) {
    Write-Host "`nRecommendation: Convert permanent privileged role assignments to PIM eligible assignments." -ForegroundColor Yellow
}
