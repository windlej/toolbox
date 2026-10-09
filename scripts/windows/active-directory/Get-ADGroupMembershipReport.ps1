param(
    [Parameter(Mandatory = $false)]
    [string[]]$GroupNames,

    [Parameter(Mandatory = $false)]
    [string]$GroupNameFilter = "*",

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\GroupMembershipAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$Recursive,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabledUsers,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDistributionGroups
)

Import-Module ActiveDirectory -ErrorAction Stop

function Get-GroupMembershipDetail {
    param(
        [string]$GroupName,
        [bool]$Recurse
    )

    try {
        $Group = Get-ADGroup -Identity $GroupName -Properties Description, GroupCategory, GroupScope, Created, DistinguishedName
    } catch {
        Write-Warning "Group not found: $GroupName"
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
    $TargetGroups = (Get-ADGroup -Filter "Name -like '$GroupNameFilter'" | Sort-Object Name).Name
}

$AuditResults = foreach ($GroupName in $TargetGroups) {
    Write-Host "Processing group: $GroupName" -ForegroundColor Yellow
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

Write-Host "Audited $($AuditResults.Count) groups" -ForegroundColor Green

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
    <strong>Groups Audited:</strong> $($AuditResults.Count) |
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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "HTML report: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
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
    $CsvData | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV export: $CsvPath" -ForegroundColor Green
}
