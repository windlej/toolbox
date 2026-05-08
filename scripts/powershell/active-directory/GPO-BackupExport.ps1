param(
    [Parameter(Mandatory = $false)]
    [string]$BackupPath = ".\GPO_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')",

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\GPO_Backup_Report.html",

    [Parameter(Mandatory = $false)]
    [string[]]$GpoDisplayNames,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeXmlReport
)

Import-Module GroupPolicy -ErrorAction Stop

if (-not (Test-Path $BackupPath)) {
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
}

if ($GpoDisplayNames) {
    $GPOs = $GpoDisplayNames | ForEach-Object {
        Get-Gpo -Name $_ -ErrorAction SilentlyContinue
    } | Where-Object { $_ -ne $null }
} else {
    $GPOs = Get-Gpo -All
}

$BackupResults = foreach ($GPO in $GPOs) {
    $StartTime = Get-Date
    try {
        $Backup = Backup-Gpo -Guid $GPO.Id -Path $BackupPath -Domain $GPO.Domain -Server ($GPO.Domain.Split('.')[0]) -ErrorAction Stop
        $Duration = (Get-Date) - $StartTime
        [PSCustomObject]@{
            GpoName       = $GPO.DisplayName
            GpoId         = $GPO.Id
            Status        = "Success"
            BackupPath    = $Backup.BackupDirectory
            BackupId      = $Backup.Id
            Duration      = "$($Duration.TotalSeconds)N
            Owner         = $GPO.Owner
            Created       = $GPO.CreationTime
            Modified      = $GPO.ModificationTime
        }
    } catch {
        [PSCustomObject]@{
            GpoName       = $GPO.DisplayName
            GpoId         = $GPO.Id
            Status        = "Failed"
            BackupPath    = ""
            BackupId      = ""
            Duration      = "N/A"
            Owner         = $GPO.Owner
            Created       = $GPO.CreationTime
            Modified      = $GPO.ModificationTime
            Error         = $_.Exception.Message
        }
    }
}

$SuccessCount = ($BackupResults | Where-Object { $_.Status -eq "Success" }).Count
$FailCount = ($BackupResults | Where-Object { $_.Status -eq "Failed" }).Count

$HtmlRows = $BackupResults | ForEach-Object {
    $RowClass = if ($_.Status -eq "Failed") { "class='danger'" } else { "" }
    "<tr $RowClass>
        <td>$($_.GpoName)</td>
        <td>$($_.Status)</td>
        <td>$($_.BackupPath -replace $BackupPath, '.')</td>
        <td>$($_.Duration)</td>
        <td>$($_.Modified)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>GPO Backup Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 6px 8px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
</style></head>
<body>
<h1>GPO Backup Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</h1>
<div class='summary'>
    <strong>Backup Path:</strong> $BackupPath<br>
    <strong>Total GPOs:</strong> $($BackupResults.Count) |
    <strong>Success:</strong> $SuccessCount |
    <strong>Failed:</strong> $FailCount
</div>
<table>
<tr><th>GPO Name</th><th>Status</th><th>Backup Path</th><th>Duration</th><th>Modified</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8

if ($IncludeXmlReport) {
    $BackupResults | Export-Clixml -Path "$BackupPath\backup_manifest.xml"
}

Write-Host "Backup completed to: $BackupPath" -ForegroundColor Green
Write-Host "Report: $ReportPath" -ForegroundColor Cyan
Write-Host "Successfully backed up $SuccessCount of $($BackupResults.Count) GPOs" -ForegroundColor Green
