param(
    [Parameter(Mandatory = $false)]
    [string]$OuPath,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\OU_Structure_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath
)

Import-Module ActiveDirectory -ErrorAction Stop

function Get-OuHierarchy {
    param(
        [string]$DistinguishedName,
        [int]$Depth = 0
    )

    $Ou = Get-ADOrganizationalUnit -Identity $DistinguishedName -Properties Description,ProtectedFromAccidentalDeletion
    $Computers = Get-ADComputer -Filter * -SearchBase $DistinguishedName -SearchScope OneLevel -ResultSetSize 500 | Select-Object Name, OperatingSystem
    $Users = Get-ADUser -Filter * -SearchBase $DistinguishedName -SearchScope OneLevel -ResultSetSize 500 -Properties Title, Department | Select-Object Name, SamAccountName, Title, Department
    $Groups = Get-ADGroup -Filter * -SearchBase $DistinguishedName -SearchScope OneLevel -ResultSetSize 500 | Select-Object Name, GroupCategory

    $Entry = [PSCustomObject]@{
        Path                         = $DistinguishedName
        Name                         = $Ou.Name
        Depth                        = $Depth
        Description                  = $Ou.Description
        Protected                    = $Ou.ProtectedFromAccidentalDeletion
        Created                      = $Ou.Created
        Modified                     = $Ou.Modified
        ComputerCount                = $Computers.Count
        UserCount                    = $Users.Count
        GroupCount                   = $Groups.Count
        GpoInheritanceBlocked        = (Get-GpoInheritance -Target $DistinguishedName).GpoInheritanceBlocked
    }

    $Results = @($Entry)

    $ChildOus = Get-ADOrganizationalUnit -Filter * -SearchBase $DistinguishedName -SearchScope OneLevel
    foreach ($ChildOu in $ChildOus) {
        $Results += Get-OuHierarchy -DistinguishedName $ChildOu.DistinguishedName -Depth ($Depth + 1)
    }

    return $Results
}

if ($OuPath) {
    try {
        $RootOu = Get-ADOrganizationalUnit -Identity $OuPath -ErrorAction Stop
    } catch {
        Write-Error "OU not found: $OuPath"
        return
    }
} else {
    $DomainDN = (Get-ADDomain).DistinguishedName
    $RootOu = Get-ADOrganizationalUnit -Filter * -SearchBase $DomainDN -SearchScope OneLevel |
        Sort-Object Name | Select-Object -First 1
    $OuPath = $RootOu.DistinguishedName
}

Write-Host "Building OU hierarchy from: $OuPath" -ForegroundColor Cyan

$OuData = Get-OuHierarchy -DistinguishedName $OuPath -Depth 0

$MaxDepth = ($OuData | Measure-Object -Property Depth -Maximum).Maximum

Write-Host "Found $($OuData.Count) OUs across $MaxDepth levels" -ForegroundColor Green

function Format-OuName {
    param([string]$Name, [int]$Depth)
    $Indent = "&nbsp;" * ($Depth * 4)
    $Icon = if ($Depth -eq 0) { "&#x1F4C1;" } else { "&#x1F4C2;" }
    return "$Indent$Icon $Name"
}

$HtmlRows = $OuData | ForEach-Object {
    $BlockedBadge = if ($_.GpoInheritanceBlocked) { " <span style='color:red;'>(GPO Blocked)</span>" } else { "" }
    $ProtectedBadge = if ($_.Protected) { " <span style='color:orange;'>[Protected]</span>" } else { "" }
    "<tr>
        <td style='padding-left: $($_.Depth * 20)px;'>$(Format-OuName -Name $_.Name -Depth $_.Depth)$BlockedBadge$ProtectedBadge</td>
        <td>$($_.Description)</td>
        <td>$($_.ComputerCount)</td>
        <td>$($_.UserCount)</td>
        <td>$($_.GroupCount)</td>
        <td>$($_.Created)</td>
        <td>$($_.GpoInheritanceBlocked)</td>
    </tr>"
}

$DomainDN = (Get-ADDomain).DistinguishedName

$Html = @"
<!DOCTYPE html>
<html>
<head><title>OU Structure Documentation</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.meta { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 6px 8px; border-bottom: 1px solid #ddd; vertical-align: top; }
tr:hover { background: #f5f5f5; }
.level-0 { font-weight: bold; background: #e3f2fd; }
</style></head>
<body>
<h1>Active Directory OU Structure</h1>
<div class='meta'>
    <strong>Domain:</strong> $DomainDN<br>
    <strong>Root OU:</strong> $OuPath<br>
    <strong>Total OUs:</strong> $($OuData.Count) |
    <strong>Max Depth:</strong> $MaxDepth |
    <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm')
</div>
<table>
<tr>
    <th>Organizational Unit</th><th>Description</th><th>Computers</th>
    <th>Users</th><th>Groups</th><th>Created</th><th>GPO Blocked</th>
</tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "HTML report: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $OuData | Select-Object Path, Name, Depth, Description, Protected, ComputerCount, UserCount, GroupCount, GpoInheritanceBlocked, Created |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV export: $CsvPath" -ForegroundColor Green
}
