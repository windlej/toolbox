param(
    [Parameter(Mandatory = $true)]
    [string[]]$Paths,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\FileServerAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [int]$MaxDepth = 3,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeInherited,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeLocalUsers,

    [Parameter(Mandatory = $false)]
    [switch]$ReportUnusedShares,

    [Parameter(Mandatory = $false)]
    [string[]]$ShareComputers
)

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
        Write-Warning "Cannot access $Path : $($_.Exception.Message)"
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
            Write-Warning "Cannot enumerate shares on $Computer : $($_.Exception.Message)"
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

Write-Host "=== File Server Permission Audit ===" -ForegroundColor Cyan

$AllPermissions = @()

foreach ($Path in $Paths) {
    Write-Host "Scanning $Path..." -ForegroundColor Yellow
    $AllPermissions += Get-PermissionReport -Path $Path -Depth 0
}

Write-Host "Total permission entries: $($AllPermissions.Count)" -ForegroundColor White

$UniquePaths = ($AllPermissions | Select-Object -ExpandProperty Path -Unique).Count
$UniqueIdentities = ($AllPermissions | Select-Object -ExpandProperty Identity -Unique).Count

$ExplicitPermissions = $AllPermissions | Where-Object { -not $_.IsInherited }
$DenyPermissions = $AllPermissions | Where-Object { $_.AccessType -eq "Deny" }
$FullControlPermissions = $AllPermissions | Where-Object { $_.Rights -match "FullControl" }

Write-Host "Unique folders/files: $UniquePaths" -ForegroundColor Gray
Write-Host "Unique identities: $UniqueIdentities" -ForegroundColor Gray
Write-Host "Explicit (non-inherited) ACEs: $($ExplicitPermissions.Count)" -ForegroundColor Yellow
Write-Host "Deny entries: $($DenyPermissions.Count)" -ForegroundColor Red
Write-Host "FullControl entries: $($FullControlPermissions.Count)" -ForegroundColor Yellow

$ShareResults = @()
if ($ReportUnusedShares -and $ShareComputers) {
    Write-Host "`nEnumerating shares..." -ForegroundColor Cyan
    $ShareResults = Get-ShareReport -Computers $ShareComputers
    Write-Host "Found $($ShareResults.Count) shares" -ForegroundColor Gray
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
    <strong>Explicit:</strong> $($ExplicitPermissions.Count) |
    <strong>Deny:</strong> $($DenyPermissions.Count) |
    <strong>FullControl:</strong> $($FullControlPermissions.Count)<br>
    <strong>Scan Depth:</strong> $MaxDepth |
    <strong>Include Inherited:</strong> $IncludeInherited
</div>
<table>
<tr><th>Path</th><th>Identity</th><th>Rights</th><th>Type</th><th>Owner</th><th>Inherited</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "`nReport: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $AllPermissions | Select-Object Path, Name, Type, Identity, Rights, AccessType, Owner, IsInherited, Depth |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}
