#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
Audits Active Directory group membership and writes an HTML report (optional CSV).

.DESCRIPTION
For each group named in -GroupNames (or every group matching -GroupNameFilter) lists the members with their type,
name, SamAccountName, enabled state, title, department, last logon and manager (users only). Disabled users and
distribution groups are skipped unless requested, and -Recursive expands nested groups. The HTML report has one
row per group member; -ExportCsv adds a CSV with the same data plus group category, scope, last logon and manager.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER GroupNames
Optional. Names of the groups to audit. If omitted, groups are selected with -GroupNameFilter.

.PARAMETER GroupNameFilter
Filter on group Name used when -GroupNames is not given. Default '*' (all groups). '*' is the only wildcard;
all other characters, including quotes, parentheses and backslashes, are matched literally.

.PARAMETER ExportCsv
Also write a CSV next to the HTML report.

.PARAMETER Recursive
Expand nested group membership.

.PARAMETER IncludeDisabledUsers
Include disabled user accounts (skipped by default).

.PARAMETER IncludeDistributionGroups
Include distribution groups (skipped by default; only security groups are audited).

.EXAMPLE
.\Get-ADGroupMembershipReport.ps1 -GroupNames 'Domain Admins','Server Operators' -OutputPath D:\Reports

.EXAMPLE
.\Get-ADGroupMembershipReport.ps1 -GroupNameFilter 'SG-*' -Recursive -IncludeDisabledUsers -ExportCsv -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (RSAT ActiveDirectory module, domain-joined machine)
Permissions:  Read-only domain user (standard users can read group membership)
When to use:  Access reviews, audits of who is in which security group, or before cleaning up groups.
Safety:       Read-only
Version:      1.0
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$CustomerName,
    [string[]]$GroupNames,
    [string]$GroupNameFilter = "*",
    [switch]$ExportCsv,
    [switch]$Recursive,
    [switch]$IncludeDisabledUsers,
    [switch]$IncludeDistributionGroups
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

$stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir   = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$htmlPath = Join-Path $outDir "Get-ADGroupMembershipReport_$stamp.html"
$csvPath  = Join-Path $outDir "Get-ADGroupMembershipReport_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-ADGroupMembershipReport_$stamp.log"

Import-Module ActiveDirectory -ErrorAction Stop

function Get-GroupMembershipDetail {
    param(
        [string]$GroupName,
        [bool]$Recurse
    )

    try {
        $Group = Get-ADGroup -Identity $GroupName -Properties Description, GroupCategory, GroupScope, Created, DistinguishedName
    } catch {
        Write-Log "Group not found: $GroupName" 'WARN'
        return $null
    }

    if ($Group.GroupCategory -eq "Distribution" -and -not $IncludeDistributionGroups) {
        return $null
    }

    $Members = if ($Recurse) {
        Get-ADGroupMember -Identity $Group.DistinguishedName -Recursive | Where-Object { $_.objectClass -ne "foreignSecurityPrincipal" }
    } else {
        Get-ADGroupMember -Identity $Group.DistinguishedName | Where-Object { $_.objectClass -ne "foreignSecurityPrincipal" }
    }

    $MemberDetails = foreach ($Member in $Members) {
        try {
            if ($Member.objectClass -eq "user") {
                $User = Get-ADUser -Identity $Member.DistinguishedName -Properties Title, Department, Enabled, LastLogonDate, Manager
                if (-not $IncludeDisabledUsers -and -not $User.Enabled) {
                    continue
                }
                $ManagerName = if ($User.Manager) {
                    try { (Get-ADUser -Identity $User.Manager).Name } catch { "N/A" }
                } else { "N/A" }
                [PSCustomObject]@{
                    Type            = "User"
                    Name            = $User.Name
                    SamAccountName  = $User.SamAccountName
                    Enabled         = $User.Enabled
                    Title           = $User.Title
                    Department      = $User.Department
                    LastLogonDate   = $User.LastLogonDate
                    Manager         = $ManagerName
                    DistinguishedName = $Member.DistinguishedName
                }
            } elseif ($Member.objectClass -eq "group") {
                [PSCustomObject]@{
                    Type            = "Group"
                    Name            = $Member.Name
                    SamAccountName  = $Member.SamAccountName
                    Enabled         = $null
                    Title           = ""
                    Department      = ""
                    LastLogonDate   = $null
                    Manager         = ""
                    DistinguishedName = $Member.DistinguishedName
                }
            } elseif ($Member.objectClass -eq "computer") {
                [PSCustomObject]@{
                    Type            = "Computer"
                    Name            = $Member.Name
                    SamAccountName  = $Member.SamAccountName
                    Enabled         = $null
                    Title           = ""
                    Department      = ""
                    LastLogonDate   = $null
                    Manager         = ""
                    DistinguishedName = $Member.DistinguishedName
                }
            }
        } catch {
            [PSCustomObject]@{
                Type            = $Member.objectClass
                Name            = $Member.Name
                SamAccountName  = ""
                Enabled         = $null
                Title           = ""
                Department      = ""
                LastLogonDate   = $null
                Manager         = ""
                DistinguishedName = $Member.DistinguishedName
            }
        }
    }

    return @{
        Group   = $Group
        Members = $MemberDetails
    }
}

if ($GroupNames) {
    $TargetGroups = $GroupNames
} else {
    # RFC 4515 escaping so the value cannot alter the filter; '*' stays a wildcard.
    $EscapedFilter = $GroupNameFilter.Replace('\', '\5c').Replace('(', '\28').Replace(')', '\29')
    $TargetGroups = (Get-ADGroup -LDAPFilter "(name=$EscapedFilter)" | Sort-Object Name).Name
}

$AuditResults = foreach ($GroupName in $TargetGroups) {
    Write-Log "Processing group: $GroupName"
    $Result = Get-GroupMembershipDetail -GroupName $GroupName -Recurse $Recursive
    if ($Result) {
        [PSCustomObject]@{
            GroupName       = $Result.Group.Name
            GroupCategory   = $Result.Group.GroupCategory
            GroupScope      = $Result.Group.GroupScope
            Description     = $Result.Group.Description
            Created         = $Result.Group.Created
            TotalMembers    = ($Result.Members | Measure-Object).Count
            Members         = $Result.Members
        }
    }
}

Write-Log "Audited $(@($AuditResults).Count) groups"

$HtmlRows = foreach ($Group in $AuditResults) {
    $MemberRows = foreach ($Member in $Group.Members) {
        $EnabledStr = if ($Member.Enabled -eq $true) { "Yes" } elseif ($Member.Enabled -eq $false) { "No" } else { "N/A" }
        "<tr>
            <td>$($Group.GroupName)</td>
            <td>$($Member.Type)</td>
            <td>$($Member.Name)</td>
            <td>$($Member.SamAccountName)</td>
            <td>$EnabledStr</td>
            <td>$($Member.Title)</td>
            <td>$($Member.Department)</td>
        </tr>"
    }
    $MemberRows -join "`n"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>AD Group Membership Audit</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; position: sticky; top: 0; }
td { padding: 5px 8px; border-bottom: 1px solid #ddd; }
tr:hover { background: #f5f5f5; }
.group-header { background: #e3f2fd; font-weight: bold; }
</style></head>
<body>
<h1>Active Directory Group Membership Audit</h1>
<div class='summary'>
    <strong>Groups Audited:</strong> $(@($AuditResults).Count) |
    <strong>Recursive:</strong> $Recursive |
    <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm')
</div>
<table>
<tr>
    <th>Group</th><th>Type</th><th>Name</th><th>SamAccountName</th>
    <th>Enabled</th><th>Title</th><th>Department</th>
</tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "HTML report: $htmlPath"

if ($ExportCsv) {
    $CsvData = foreach ($Group in $AuditResults) {
        foreach ($Member in $Group.Members) {
            [PSCustomObject]@{
                GroupName      = $Group.GroupName
                GroupCategory  = $Group.GroupCategory
                GroupScope     = $Group.GroupScope
                MemberType     = $Member.Type
                MemberName     = $Member.Name
                SamAccountName = $Member.SamAccountName
                Enabled        = $Member.Enabled
                Title          = $Member.Title
                Department     = $Member.Department
                LastLogon      = $Member.LastLogonDate
                Manager        = $Member.Manager
            }
        }
    }
    $CsvData | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV export: $csvPath"
}
