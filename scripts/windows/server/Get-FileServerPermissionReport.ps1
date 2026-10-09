#Requires -Version 5.1

<#
.SYNOPSIS
Audits NTFS permissions on one or more folder trees and writes an HTML report (optional CSV).

.DESCRIPTION
Walks each path in -Paths down to -MaxDepth levels (folders plus common document file types) and records
every access control entry: identity, rights, allow/deny, owner and whether it is inherited. Local-machine
accounts and inherited entries are hidden unless you ask for them. The HTML report highlights Deny entries
and FullControl grants. With -ReportUnusedShares it also enumerates SMB shares on the target computers
(collected in memory; the share list is not currently included in the HTML or CSV).

.PARAMETER Paths
One or more folder paths (local or UNC) to audit, for example D:\Shares\Finance.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write a CSV of all permission entries next to the HTML report.

.PARAMETER MaxDepth
How many folder levels below each path to scan. Default: 3.

.PARAMETER IncludeInherited
Include inherited entries (by default only explicit entries are listed).

.PARAMETER IncludeLocalUsers
Include entries for local machine accounts (COMPUTERNAME\...), which are hidden by default.

.PARAMETER ReportUnusedShares
Also enumerate SMB shares on the computers in -ComputerName.

.PARAMETER ComputerName
Computers whose SMB shares are enumerated when -ReportUnusedShares is used. Default: the local machine.
Old name: ShareComputers.

.EXAMPLE
.\Get-FileServerPermissionReport.ps1 -Paths D:\Shares\Finance -OutputPath D:\Reports

.EXAMPLE
.\Get-FileServerPermissionReport.ps1 -Paths D:\Shares\Finance,D:\Shares\HR -MaxDepth 2 -IncludeInherited -ExportCsv -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (file server or any host that can reach the paths)
Permissions:  Read and read-permissions (READ_CONTROL) on the scanned folders; local admin or Backup Operators on a file server is typical
When to use:  Access reviews, tracking down who has FullControl or explicit Deny on a share, or before a file server migration.
Safety:       Read-only
Version:      1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Paths,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$CustomerName,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [int]$MaxDepth = 3,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeInherited,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeLocalUsers,

    [Parameter(Mandatory = $false)]
    [switch]$ReportUnusedShares,

    [Parameter(Mandatory = $false)]
    [Alias('ShareComputers')]
    [string[]]$ComputerName = @($env:COMPUTERNAME)
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
$script:LogFile = Join-Path $outDir "Get-FileServerPermissionReport_$stamp.log"
$htmlPath = Join-Path $outDir "Get-FileServerPermissionReport_$stamp.html"
$csvPath  = Join-Path $outDir "Get-FileServerPermissionReport_$stamp.csv"

function Get-PermissionReport {
    param(
        [string]$Path,
        [int]$Depth = 0
    )

    if ($Depth -gt $MaxDepth) { return @() }

    $Results = @()

    try {
        $Acl = Get-Acl -Path $Path -ErrorAction Stop
    } catch {
        Write-Log "Cannot access $Path : $($_.Exception.Message)" 'WARN'
        return @()
    }

    $Item = Get-Item -Path $Path -ErrorAction SilentlyContinue
    $IsDirectory = $Item -is [System.IO.DirectoryInfo]
    $SizeKB = if (-not $IsDirectory -and $Item) {
        [math]::Round($Item.Length / 1KB, 2)
    } else { $null }

    $Owner = $Acl.Owner
    $InheritanceEnabled = (-not $Acl.AreAccessRulesProtected)

    $Permissions = foreach ($Access in $Acl.Access) {
        if (-not $IncludeInherited -and $Access.IsInherited) { continue }
        if (-not $IncludeLocalUsers -and $Access.IdentityReference.Value -match "^$env:COMPUTERNAME\\") { continue }

        [PSCustomObject]@{
            Path        = $Path
            Name        = $Item.Name
            Type        = if ($IsDirectory) { "Directory" } else { "File" }
            Identity    = $Access.IdentityReference.Value
            Rights      = $Access.FileSystemRights.ToString()
            AccessType  = $Access.AccessControlType
            IsInherited = $Access.IsInherited
            Depth       = $Depth
            Owner       = $Owner
            SizeKB      = $SizeKB
            Inherited   = $Access.IsInherited
        }
    }

    $Results += $Permissions

    if ($IsDirectory) {
        $SubItems = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue |
            Where-Object { $_.PSIsContainer -or $_.Extension -match '\.(docx?|xlsx?|pptx?|pdf|txt|csv|dat|conf|log)$' }

        foreach ($SubItem in $SubItems) {
            $Results += Get-PermissionReport -Path $SubItem.FullName -Depth ($Depth + 1)
        }
    }

    return $Results
}

function Get-ShareReport {
    param([string[]]$Computers)

    $Results = @()

    foreach ($Computer in $Computers) {
        try {
            $Shares = Get-CimInstance -ComputerName $Computer -ClassName Win32_Share -Filter "Type = 0" -ErrorAction Stop
        } catch {
            Write-Log "Cannot enumerate shares on $Computer : $($_.Exception.Message)" 'WARN'
            continue
        }

        foreach ($Share in $Shares) {
            $SecDescriptor = try {
                Get-SmbShare -Name $Share.Name -CimSession $Computer -ErrorAction SilentlyContinue
            } catch { $null }

            $Permissions = @()

            if ($SecDescriptor) {
                $Permissions = $SecDescriptor.SecurityDescriptor.Access |
                    ForEach-Object { "$($_.AccountName)=$($_.AccessRight)" }
            }

            $Results += [PSCustomObject]@{
                ComputerName = $Computer.ToUpper()
                ShareName    = $Share.Name
                Path         = $Share.Path
                Description  = $Share.Description
                Permissions  = ($Permissions -join "; ")
                IsSpecial    = $Share.Name -match '^(ADMIN\$|IPC\$|C\$|D\$|PRINT\$|FAX\$)$'
            }
        }
    }

    return $Results
}

Write-Log '=== File Server Permission Audit ==='

$AllPermissions = @()

foreach ($Path in $Paths) {
    Write-Log "Scanning $Path..."
    $AllPermissions += Get-PermissionReport -Path $Path -Depth 0
}

Write-Log "Total permission entries: $($AllPermissions.Count)"

$UniquePaths = ($AllPermissions | Select-Object -ExpandProperty Path -Unique).Count
$UniqueIdentities = ($AllPermissions | Select-Object -ExpandProperty Identity -Unique).Count

$ExplicitPermissions = $AllPermissions | Where-Object { -not $_.IsInherited }
$DenyPermissions = $AllPermissions | Where-Object { $_.AccessType -eq "Deny" }
$FullControlPermissions = $AllPermissions | Where-Object { $_.Rights -match "FullControl" }

Write-Log "Unique folders/files: $UniquePaths"
Write-Log "Unique identities: $UniqueIdentities"
Write-Log "Explicit (non-inherited) ACEs: $(@($ExplicitPermissions).Count)"
Write-Log "Deny entries: $(@($DenyPermissions).Count)"
Write-Log "FullControl entries: $(@($FullControlPermissions).Count)"

$ShareResults = @()
if ($ReportUnusedShares -and $ComputerName) {
    Write-Log 'Enumerating shares...'
    $ShareResults = Get-ShareReport -Computers $ComputerName
    Write-Log "Found $(@($ShareResults).Count) shares"
}

$HtmlRows = $AllPermissions | Sort-Object Path | ForEach-Object {
    $RowClass = if ($_.AccessType -eq "Deny") { "danger" }
    elseif ($_.Rights -match "FullControl") { "fullcontrol" }
    elseif ($_.IsInherited) { "inherited" }
    else { "" }

    $DepthIndent = "&nbsp;" * ($_.Depth * 2)

    "<tr class='$RowClass'>
        <td>$($_.Path)</td>
        <td>$($_.Identity)</td>
        <td>$($_.Rights)</td>
        <td>$($_.AccessType)</td>
        <td>$($_.Owner)</td>
        <td>$($_.IsInherited)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>File Server Permission Audit</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 11px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; position: sticky; top: 0; }
td { padding: 4px 6px; border-bottom: 1px solid #ddd; font-family: 'Consolas', monospace; font-size: 11px; }
.danger td { background: #f8d7da; }
.fullcontrol td { background: #fff3cd; }
.inherited td { color: #999; }
</style></head>
<body>
<h1>File Server Permission Audit</h1>
<div class='summary'>
    <strong>Paths Scanned:</strong> $($Paths.Count) |
    <strong>Total ACEs:</strong> $($AllPermissions.Count) |
    <strong>Unique Folders/Files:</strong> $UniquePaths |
    <strong>Unique Identities:</strong> $UniqueIdentities |
    <strong>Explicit:</strong> $(@($ExplicitPermissions).Count) |
    <strong>Deny:</strong> $(@($DenyPermissions).Count) |
    <strong>FullControl:</strong> $(@($FullControlPermissions).Count)<br>
    <strong>Scan Depth:</strong> $MaxDepth |
    <strong>Include Inherited:</strong> $IncludeInherited
</div>
<table>
<tr><th>Path</th><th>Identity</th><th>Rights</th><th>Type</th><th>Owner</th><th>Inherited</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "Report written: $htmlPath"

if ($ExportCsv) {
    $AllPermissions | Select-Object Path, Name, Type, Identity, Rights, AccessType, Owner, IsInherited, Depth |
        Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV written: $csvPath"
}
