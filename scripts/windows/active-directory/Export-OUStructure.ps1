#Requires -Version 5.1
#Requires -Modules ActiveDirectory, GroupPolicy

<#
.SYNOPSIS
Documents the OU hierarchy with object counts and GPO inheritance state as an HTML report (optional CSV).

.DESCRIPTION
Walks an OU tree (from -OuPath, or the first top-level OU alphabetically if omitted) and, for each OU, records
its description, accidental-deletion protection, created/modified dates, the number of computers, users and groups
directly inside it (capped at 500 per type per OU) and whether GPO inheritance is blocked. The HTML report shows
the tree indented by depth; -ExportCsv adds the same data as CSV.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER OuPath
Optional distinguished name of the root OU to document. Default is the first top-level OU in the domain.

.PARAMETER ExportCsv
Also write a CSV next to the HTML report.

.EXAMPLE
.\Export-OUStructure.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Export-OUStructure.ps1 -OuPath "OU=Corp,DC=contoso,DC=com" -ExportCsv -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (RSAT ActiveDirectory and GroupPolicy modules, domain-joined machine)
Permissions:  Read-only domain user (read access to AD objects and GPO links)
When to use:  Documenting an unfamiliar environment, planning a GPO or delegation redesign, or before an OU cleanup.
Safety:       Read-only
Version:      1.0
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$CustomerName,
    [string]$OuPath,
    [switch]$ExportCsv
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
$htmlPath = Join-Path $outDir "Export-OUStructure_$stamp.html"
$csvPath  = Join-Path $outDir "Export-OUStructure_$stamp.csv"
$script:LogFile = Join-Path $outDir "Export-OUStructure_$stamp.log"

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

function Get-OuHierarchy {
    param(
        [string]$DistinguishedName,
        [int]$Depth = 0
    )

    $Ou = Get-ADOrganizationalUnit -Identity $DistinguishedName -Properties Description,ProtectedFromAccidentalDeletion,Created,Modified
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
        ComputerCount                = @($Computers).Count
        UserCount                    = @($Users).Count
        GroupCount                   = @($Groups).Count
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
        Write-Log "OU not found: $OuPath" 'ERROR'
        throw
    }
} else {
    $DomainDN = (Get-ADDomain).DistinguishedName
    $RootOu = Get-ADOrganizationalUnit -Filter * -SearchBase $DomainDN -SearchScope OneLevel |
        Sort-Object Name | Select-Object -First 1
    if (-not $RootOu) { throw 'No organizational units found in the domain.' }
    $OuPath = $RootOu.DistinguishedName
}

Write-Log "Building OU hierarchy from: $OuPath"

$OuData = @(Get-OuHierarchy -DistinguishedName $OuPath -Depth 0)

$MaxDepth = ($OuData | Measure-Object -Property Depth -Maximum).Maximum

Write-Log "Found $($OuData.Count) OUs across $MaxDepth levels"

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

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "HTML report: $htmlPath"

if ($ExportCsv) {
    $OuData | Select-Object Path, Name, Depth, Description, Protected, ComputerCount, UserCount, GroupCount, GpoInheritanceBlocked, Created |
        Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV export: $csvPath"
}
