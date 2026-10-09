#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users

<#
.SYNOPSIS
Audits who holds privileged Entra ID (Azure AD) directory roles, permanent and optionally PIM-eligible.

.DESCRIPTION
Reads active directory role members and unified role assignments through Microsoft Graph, optionally adds
PIM eligible assignments, and keeps only assignments to users for a list of well-known privileged roles
(Global Administrator, Exchange Administrator, Security Administrator and others). The output is an HTML
report (primary) with a summary (Global Admin count, permanent versus eligible, unique roles and users) and
one row per assignment, plus an optional CSV of the same data. This script is read-only.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the assignments to a CSV next to the HTML report.

.PARAMETER IncludePimEligible
Also query PIM eligible role assignments (requires Entra ID P2 licensing).

.PARAMETER IncludePermanent
Reserved. Permanent assignments are always included; this switch currently has no effect.

.PARAMETER SkipGraphConnect
Skip Connect-MgGraph (use when a Graph session with suitable scopes already exists).

.EXAMPLE
.\Get-PrivilegedRoleReport.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-PrivilegedRoleReport.ps1 -OutputPath D:\Reports -CustomerName Contoso -IncludePimEligible -ExportCsv

.NOTES
Platform:     Windows (PowerShell 5.1+ with Microsoft Graph PowerShell SDK)
Permissions:  Graph scopes RoleManagement.Read.Directory, Directory.Read.All, User.Read.All, AuditLog.Read.All (Global Reader or Security Reader); PIM eligibility needs Entra ID P2
When to use:  Access reviews, security assessments, or before cutting down the number of Global Administrators.
Safety:       Read-only
Version:      1.1
#>
[CmdletBinding()]
param(
    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCsv,

    [switch]$IncludePimEligible,

    [switch]$IncludePermanent,

    [switch]$SkipGraphConnect
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

$stamp          = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir         = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$ReportPath     = Join-Path $outDir "Get-PrivilegedRoleReport_$stamp.html"
$CsvPath        = Join-Path $outDir "Get-PrivilegedRoleReport_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-PrivilegedRoleReport_$stamp.log"

function Connect-ToGraph {
    $scopes = @(
        'RoleManagement.Read.Directory',
        'Directory.Read.All',
        'User.Read.All',
        'AuditLog.Read.All'
    )
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Log 'Connected to Graph'
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
    $Uri = 'https://graph.microsoft.com/v1.0/directoryRoles'
    $Response = Invoke-MgGraphRequest -Uri $Uri -Method Get -ErrorAction Stop
    $Templates = @{}
    foreach ($Role in $Response.value) {
        $Templates[$Role.roleTemplateId] = $Role.displayName
    }
    return $Templates
}

function Resolve-UnifiedRoleDefinitionId {
    $Uri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions'
    $RoleMap = @{}
    try {
        $Response = Invoke-MgGraphRequest -Uri $Uri -Method Get -ErrorAction Stop
        foreach ($Role in $Response.value) {
            $RoleMap[$Role.id] = $Role.displayName
        }
    } catch {
        Write-Log "Could not read role definitions (role names may show as IDs): $_" 'WARN'
    }
    return $RoleMap
}

function Get-DirectoryRoleMembers {
    param([hashtable]$RoleTemplateMap)

    $Results = @()
    $Uri = 'https://graph.microsoft.com/v1.0/directoryRoles'

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
                        RoleDisplayName   = $RoleDisplayName
                        RoleId            = $Role.id
                        UserId            = $Member.id
                        UserPrincipalName = if ($UserDetail) { $UserDetail.UserPrincipalName } else { 'Unknown' }
                        DisplayName       = if ($UserDetail) { $UserDetail.DisplayName } else { $Member.displayName }
                        UserType          = if ($UserDetail) { $UserDetail.UserType } else { 'Unknown' }
                        Department        = if ($UserDetail) { $UserDetail.Department } else { '' }
                        JobTitle          = if ($UserDetail) { $UserDetail.JobTitle } else { '' }
                        AssignmentType    = 'Permanent (Directory Role)'
                        CreatedDateTime   = if ($UserDetail) { $UserDetail.CreatedDateTime } else { $null }
                    }
                }
            } catch {
                Write-Log "Could not read members of directory role '$RoleDisplayName': $_" 'WARN'
            }
        }
    } catch {
        Write-Log "Could not read directory roles: $_" 'WARN'
    }

    return $Results
}

function Get-UnifiedRoleAssignments {
    param(
        [hashtable]$RoleDefinitionMap,
        [bool]$IncludePermanent,
        [bool]$IncludeEligible
    )

    $Results = @()

    $Uri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal&$top=100'
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
                    Department        = ''
                    JobTitle          = ''
                    AssignmentType    = 'Permanent (Unified Role)'
                    CreatedDateTime   = $null
                }
            }

            $Uri = $Response.'@odata.nextLink'
            if (-not $Uri) { break }
        }
    } catch {
        Write-Log "Could not read unified role assignments: $_" 'WARN'
    }

    if ($IncludeEligible) {
        $EligibleUri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal&$top=100'
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
                    Department        = ''
                    JobTitle          = ''
                    AssignmentType    = 'Eligible (PIM)'
                    CreatedDateTime   = $Assignment.startDateTime
                }
            }
        } catch {
            Write-Log "PIM eligibility data unavailable (requires P2 licensing): $_" 'WARN'
        }
    }

    return $Results
}

# -- MAIN --

try {
    Write-Log '=== Privileged Role Assignment Audit ==='

    if (-not $SkipGraphConnect) {
        Connect-ToGraph
    }

    Write-Log 'Resolving role definitions...'
    $RoleTemplateMap = Resolve-RoleTemplateId
    $RoleDefinitionMap = Resolve-UnifiedRoleDefinitionId

    Write-Log 'Retrieving directory role assignments...'
    $DirRoleResults = @(Get-DirectoryRoleMembers -RoleTemplateMap $RoleTemplateMap)
    Write-Log "Found $($DirRoleResults.Count) directory role assignments"

    Write-Log 'Retrieving unified role assignments...'
    $UnifiedResults = @(Get-UnifiedRoleAssignments -RoleDefinitionMap $RoleDefinitionMap `
        -IncludePermanent ([bool]$IncludePermanent) -IncludeEligible ([bool]$IncludePimEligible))
    Write-Log "Found $($UnifiedResults.Count) unified role assignments"

    $Results = @($DirRoleResults + $UnifiedResults)
    $Results = @($Results | Where-Object {
        $PrivilegedRoleNames -contains $_.RoleDisplayName
    } | Sort-Object RoleDisplayName, UserPrincipalName | Select-Object -Unique)

    $GlobalAdminCount = @($Results | Where-Object { $_.RoleDisplayName -eq 'Global Administrator' }).Count
    $PermanentCount   = @($Results | Where-Object { $_.AssignmentType -match 'Permanent' }).Count
    $PimCount         = @($Results | Where-Object { $_.AssignmentType -match 'Eligible' }).Count
    $UniqueRoles      = @($Results | Select-Object -ExpandProperty RoleDisplayName -Unique).Count
    $UniqueUsers      = @($Results | Select-Object -ExpandProperty UserPrincipalName -Unique).Count

    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total Privileged Assignments: $($Results.Count)" -ForegroundColor White
    Write-Host "  Global Admins: $GlobalAdminCount" -ForegroundColor Red
    Write-Host "  Permanent Assignments: $PermanentCount" -ForegroundColor Yellow
    Write-Host "  PIM Eligible: $PimCount" -ForegroundColor Green
    Write-Host "  Unique Roles: $UniqueRoles" -ForegroundColor Gray
    Write-Host "  Unique Users: $UniqueUsers" -ForegroundColor Yellow

    $HtmlRows = $Results | Sort-Object RoleDisplayName, UserPrincipalName | ForEach-Object {
        $RowClass = if ($_.RoleDisplayName -eq 'Global Administrator') { 'danger' }
        elseif ($_.AssignmentType -match 'Permanent') { 'warning' }
        else { '' }
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

    $Html | Out-File -LiteralPath $ReportPath -Encoding UTF8
    Write-Log "Report: $ReportPath"

    if ($ExportCsv) {
        $Results | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Log "CSV: $CsvPath"
    }

    if ($PermanentCount -gt 0) {
        Write-Log 'Recommendation: Convert permanent privileged role assignments to PIM eligible assignments.' 'WARN'
    }
}
catch {
    Write-Log "Privileged role report failed: $_" 'ERROR'
    throw
}
