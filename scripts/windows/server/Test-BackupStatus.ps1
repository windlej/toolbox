param(
    [Parameter(Mandatory = $false)]
    [string[]]$ComputerNames = @($env:COMPUTERNAME),

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\BackupVerification_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

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

function Test-WbadminBackup {
    param([string]$ComputerName)

    try {
        $Backups = Get-WBBackupSet -ComputerName $ComputerName -ErrorAction Stop
    } catch {
        Write-Warning "Cannot query Windows Backup on $ComputerName : $($_.Exception.Message)"
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

foreach ($Computer in $ComputerNames) {
    Write-Host "Checking backups on $Computer..." -ForegroundColor Yellow

    if ($CheckWbadmin) {
        $WbadminResults = Test-WbadminBackup -ComputerName $Computer
        $AllResults += $WbadminResults
        Write-Host "  Windows Backup: $($WbadminResults.Count) sets found" -ForegroundColor Gray
    }

    if ($BackupPaths) {
        $FileResults = Test-FileBackup -ComputerName $Computer -Paths $BackupPaths
        $AllResults += $FileResults
        Write-Host "  File paths checked: $($BackupPaths.Count)" -ForegroundColor Gray
    }
}

$FailedCount = ($AllResults | Where-Object { $_.Status -eq "Failed" }).Count
$StaleCount = ($AllResults | Where-Object { $_.Status -eq "Stale" }).Count
$OkCount = ($AllResults | Where-Object { $_.Status -eq "OK" }).Count
$UnreachableCount = ($AllResults | Where-Object { $_.Status -eq "Unreachable" -or $_.Status -eq "Empty Backup Path" }).Count

if ($AllResults.Count -eq 0) {
    Write-Host "No backup data found." -ForegroundColor Yellow
    return
}

Write-Host "`n=== Backup Verification Summary ===" -ForegroundColor Cyan
Write-Host "Total backups checked: $($AllResults.Count)" -ForegroundColor White
Write-Host "OK: $OkCount" -ForegroundColor Green
Write-Host "Stale: $StaleCount" -ForegroundColor Yellow
Write-Host "Failed: $FailedCount" -ForegroundColor Red
Write-Host "Unreachable/Empty: $UnreachableCount" -ForegroundColor Red

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
    <strong>Servers:</strong> $($ComputerNames.Count) |
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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "`nReport: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $AllResults | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
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
        Write-Host "Alert sent" -ForegroundColor Yellow
    } catch {
        Write-Warning "Failed to send alert: $($_.Exception.Message)"
    }
}
