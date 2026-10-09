#Requires -Version 5.1

<#
.SYNOPSIS
Verifies that backups are recent: Windows Server Backup sets and/or the newest file in backup folders.

.DESCRIPTION
For each computer, optionally lists Windows Server Backup sets (-CheckWbadmin) and optionally inspects
backup folders (-BackupPaths, local or via the administrative share) to find the newest file. Each result is
marked OK, Stale (older than -AlertIfOlderThanHours), Failed, Empty Backup Path or Unreachable. Output is an
HTML report with a summary header, an optional CSV and a log file. If -AlertEmailTo is given and any backup
is Failed or Stale, an email summary is sent through -SmtpServer (this is the only action outside the report
folder; nothing else is changed).

.PARAMETER ComputerName
One or more computers to check. Default: the local machine. Old name: ComputerNames.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write a CSV of the results next to the HTML report.

.PARAMETER AlertIfOlderThanHours
Backups older than this many hours are marked Stale. Default: 48.

.PARAMETER AlertEmailTo
Optional recipients for an alert email when backups are Failed or Stale. No email is sent when omitted.

.PARAMETER SmtpServer
SMTP server used for the alert email. Default: localhost.

.PARAMETER BackupPaths
Folders (for example D:\Backups) whose newest file is checked. Remote computers are reached via the
administrative share (\\computer\D$\...).

.PARAMETER CheckWbadmin
Also query Windows Server Backup sets with Get-WBBackupSet.

.EXAMPLE
.\Test-BackupStatus.ps1 -BackupPaths D:\Backups -OutputPath D:\Reports

.EXAMPLE
.\Test-BackupStatus.ps1 -ComputerName SRV01,SRV02 -CheckWbadmin -AlertIfOlderThanHours 30 -AlertEmailTo it@contoso.com -SmtpServer smtp.contoso.com -ExportCsv -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (Windows Server Backup cmdlets for -CheckWbadmin; SMB access for remote backup paths)
Permissions:  Local administrator on each target; read access to the backup folders or administrative shares
When to use:  Daily or weekly backup verification, or to confirm a customer's backups are actually landing before a change window.
Safety:       Read-only
Version:      1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [Alias('ComputerNames')]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$CustomerName,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [int]$AlertIfOlderThanHours = 48,

    [Parameter(Mandatory = $false)]
    [string[]]$AlertEmailTo,

    [Parameter(Mandatory = $false)]
    [string]$SmtpServer = "localhost",

    [Parameter(Mandatory = $false)]
    [string[]]$BackupPaths,

    [Parameter(Mandatory = $false)]
    [switch]$CheckWbadmin
)

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
$script:LogFile = Join-Path $outDir "Test-BackupStatus_$stamp.log"
$htmlPath = Join-Path $outDir "Test-BackupStatus_$stamp.html"
$csvPath  = Join-Path $outDir "Test-BackupStatus_$stamp.csv"

function Test-WbadminBackup {
    param([string]$ComputerName)

    try {
        $Backups = Get-WBBackupSet -ComputerName $ComputerName -ErrorAction Stop
    } catch {
        Write-Log "Cannot query Windows Backup on $ComputerName : $($_.Exception.Message)" 'WARN'
        return @()
    }

    if (-not $Backups) {
        return @()
    }

    $Results = foreach ($Backup in $Backups) {
        $Age = ((Get-Date) - $Backup.BackupTime).TotalHours
        $SizeGB = if ($Backup.BackupSize) { [math]::Round($Backup.BackupSize / 1GB, 2) } else { "N/A" }

        $Status = if ($Backup.SnapshotFailed) { "Failed" }
        elseif ($Age -gt $AlertIfOlderThanHours) { "Stale" }
        else { "OK" }

        $Components = ($Backup.Application | ForEach-Object { $_.ApplicationFriendlyName }) -join "; "
        if (-not $Components) { $Components = ($Backup.SystemState | ForEach-Object { "System State" }) -join "; " }
        if (-not $Components) { $Components = "Full System" }

        [PSCustomObject]@{
            ComputerName    = $ComputerName.ToUpper()
            BackupType      = "Windows Backup (Wbadmin)"
            BackupTime      = $Backup.BackupTime
            AgeHours        = [math]::Round($Age, 1)
            SizeGB          = $SizeGB
            Components      = $Components
            Status          = $Status
            VersionId       = $Backup.VersionId
            Target          = $Backup.BackupTarget
            DetailedResult  = ""
        }
    }

    return $Results
}

function Test-FileBackup {
    param(
        [string]$ComputerName,
        [string[]]$Paths
    )

    $Results = foreach ($Path in $Paths) {
        $UncPath = if ($ComputerName -eq $env:COMPUTERNAME) {
            $Path
        } else {
            "\\$ComputerName\$($Path -replace ':', '$')"
        }

        try {
            if (Test-Path $UncPath) {
                $Items = Get-ChildItem -Path $UncPath -Recurse -File -ErrorAction SilentlyContinue
                $RecentFile = $Items | Sort-Object LastWriteTime -Descending | Select-Object -First 1

                $AgeHours = if ($RecentFile) {
                    [math]::Round(((Get-Date) - $RecentFile.LastWriteTime).TotalHours, 1)
                } else { $null }

                $Status = if (-not $RecentFile) { "Empty Backup Path" }
                elseif ($AgeHours -gt $AlertIfOlderThanHours) { "Stale" }
                else { "OK" }

                [PSCustomObject]@{
                    ComputerName    = $ComputerName.ToUpper()
                    BackupType      = "File Backup"
                    BackupTime      = if ($RecentFile) { $RecentFile.LastWriteTime } else { $null }
                    AgeHours        = $AgeHours
                    SizeGB          = [math]::Round(($Items | Measure-Object -Property Length -Sum).Sum / 1GB, 2)
                    Components      = $Path
                    Status          = $Status
                    VersionId       = ""
                    Target          = $UncPath
                    DetailedResult  = "Latest file: $(if($RecentFile){$RecentFile.Name})"
                }
            } else {
                [PSCustomObject]@{
                    ComputerName    = $ComputerName.ToUpper()
                    BackupType      = "File Backup"
                    BackupTime      = $null
                    AgeHours        = $null
                    SizeGB          = $null
                    Components      = $Path
                    Status          = "Unreachable"
                    VersionId       = ""
                    Target          = $UncPath
                    DetailedResult  = "Cannot access path"
                }
            }
        } catch {
            [PSCustomObject]@{
                ComputerName    = $ComputerName.ToUpper()
                BackupType      = "File Backup"
                BackupTime      = $null
                AgeHours        = $null
                SizeGB          = $null
                Components      = $Path
                Status          = "Unreachable"
                VersionId       = ""
                Target          = $UncPath
                DetailedResult  = $_.Exception.Message
            }
        }
    }

    return $Results
}

$AllResults = @()

foreach ($Computer in $ComputerName) {
    Write-Log "Checking backups on $Computer..."

    if ($CheckWbadmin) {
        $WbadminResults = @(Test-WbadminBackup -ComputerName $Computer)
        $AllResults += $WbadminResults
        Write-Log "Windows Backup on ${Computer}: $($WbadminResults.Count) sets found"
    }

    if ($BackupPaths) {
        $FileResults = Test-FileBackup -ComputerName $Computer -Paths $BackupPaths
        $AllResults += $FileResults
        Write-Log "File paths checked on ${Computer}: $(@($BackupPaths).Count)"
    }
}

$FailedCount = @($AllResults | Where-Object { $_.Status -eq "Failed" }).Count
$StaleCount = @($AllResults | Where-Object { $_.Status -eq "Stale" }).Count
$OkCount = @($AllResults | Where-Object { $_.Status -eq "OK" }).Count
$UnreachableCount = @($AllResults | Where-Object { $_.Status -eq "Unreachable" -or $_.Status -eq "Empty Backup Path" }).Count

if ($AllResults.Count -eq 0) {
    Write-Log 'No backup data found.' 'WARN'
    return
}

Write-Log '=== Backup Verification Summary ==='
Write-Log "Total backups checked: $($AllResults.Count)"
Write-Log "OK: $OkCount"
Write-Log "Stale: $StaleCount"
Write-Log "Failed: $FailedCount"
Write-Log "Unreachable/Empty: $UnreachableCount"

$HtmlRows = $AllResults | Sort-Object Status, ComputerName | ForEach-Object {
    $RowClass = switch ($_.Status) {
        "Failed" { "danger" }
        "Stale" { "warning" }
        "Unreachable" { "danger" }
        "Empty Backup Path" { "warning" }
        default { "" }
    }
    "<tr class='$RowClass'>
        <td>$($_.ComputerName)</td>
        <td>$($_.BackupType)</td>
        <td>$($_.Components)</td>
        <td>$($_.BackupTime)</td>
        <td>$($_.AgeHours)</td>
        <td>$($_.SizeGB)</td>
        <td>$($_.Target)</td>
        <td>$($_.Status)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Backup Verification Report</title>
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
<h1>Backup Verification Report</h1>
<div class='summary'>
    <strong>Servers:</strong> $(@($ComputerName).Count) |
    <strong>Backups Checked:</strong> $($AllResults.Count) |
    <strong>OK:</strong> $OkCount |
    <strong>Stale:</strong> <span style='color:orange;'>$StaleCount</span> |
    <strong>Failed:</strong> <span style='color:red;'>$FailedCount</span> |
    <strong>Unreachable:</strong> <span style='color:red;'>$UnreachableCount</span>
</div>
<table>
<tr><th>Server</th><th>Type</th><th>Component</th><th>Last Backup</th><th>Age (hrs)</th><th>Size (GB)</th><th>Target</th><th>Status</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "Report written: $htmlPath"

if ($ExportCsv) {
    $AllResults | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV written: $csvPath"
}

if ($AlertEmailTo -and ($FailedCount -gt 0 -or $StaleCount -gt 0)) {
    try {
        $Body = "Backup Verification Alert - $(Get-Date -Format 'yyyy-MM-dd HH:mm')`n`n"
        $Body += "Summary: $FailedCount failed, $StaleCount stale, $UnreachableCount unreachable`n`n"
        $Body += ($AllResults | Where-Object { $_.Status -ne "OK" } | ForEach-Object {
            "[$($_.Status)] $($_.ComputerName) - $($_.Components) - Last: $($_.BackupTime)"
        }) -join "`n"

        Send-MailMessage -To $AlertEmailTo -From "backup-monitor@$env:COMPUTERNAME" `
            -Subject "[BACKUP ALERT] $FailedCount failed, $StaleCount stale" -Body $Body `
            -SmtpServer $SmtpServer -ErrorAction Stop
        Write-Log "Alert sent to $($AlertEmailTo -join ', ')"
    } catch {
        Write-Log "Failed to send alert: $($_.Exception.Message)" 'WARN'
    }
}
