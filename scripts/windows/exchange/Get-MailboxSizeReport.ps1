param(
    [Parameter(Mandatory = $false)]
    [string[]]$UserPrincipalNames,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\MailboxSizes_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvExportPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeArchive,

    [Parameter(Mandatory = $false)]
    [switch]$ShowGrowth,

    [Parameter(Mandatory = $false)]
    [int]$TopGrowthDays = 30,

    [Parameter(Mandatory = $false)]
    [int]$WarningSizeGB = 50,

    [Parameter(Mandatory = $false)]
    [int]$CriticalSizeGB = 80,

    [Parameter(Mandatory = $false)]
    [switch]$SkipExchangeConnect
)

$Results = [System.Collections.Generic.List[PSObject]]::new()

function Connect-ToExchange {
    try {
        $Module = Get-Module ExchangeOnlineManagement -ListAvailable -ErrorAction SilentlyContinue
        if (-not $Module) { return $false }
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Host "Connected to Exchange Online" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Exchange connection failed: $_"
        return $false
    }
}

function Get-MailboxStats {
    param([string]$Identity)

    try {
        $Stats = Get-MailboxStatistics -Identity $Identity -ErrorAction SilentlyContinue
        if (-not $Stats) { return $null }

        $Mailbox = Get-Mailbox -Identity $Identity -ErrorAction SilentlyContinue

        $TotalSizeGB = [math]::Round($Stats.TotalItemSize.Value.ToBytes() / 1GB, 2)
        $ItemCount = $Stats.ItemCount
        $LastLogon = $Stats.LastLogonTime
        $LastUserAction = $Stats.LastUserActionTime
        $ArchiveSizeGB = $null
        $ArchiveItemCount = $null

        if ($IncludeArchive -and $Mailbox.ArchiveStatus -eq "Active") {
            try {
                $ArchiveStats = Get-MailboxStatistics -Identity $Identity -Archive -ErrorAction SilentlyContinue
                if ($ArchiveStats) {
                    $ArchiveSizeGB = [math]::Round($ArchiveStats.TotalItemSize.Value.ToBytes() / 1GB, 2)
                    $ArchiveItemCount = $ArchiveStats.ItemCount
                }
            } catch { }
        }

        $Status = "OK"
        if ($TotalSizeGB -ge $CriticalSizeGB) { $Status = "Critical" }
        elseif ($TotalSizeGB -ge $WarningSizeGB) { $Status = "Warning" }

        $TotalWithArchive = if ($ArchiveSizeGB) { $TotalSizeGB + $ArchiveSizeGB } else { $TotalSizeGB }

        return [PSCustomObject]@{
            UserPrincipalName   = $Identity
            DisplayName         = $Mailbox.DisplayName
            RecipientType       = $Mailbox.RecipientTypeDetails
            Department          = $Mailbox.Department
            TotalSizeGB         = $TotalSizeGB
            ItemCount           = $ItemCount
            ArchiveSizeGB       = $ArchiveSizeGB
            ArchiveItemCount    = $ArchiveItemCount
            TotalWithArchiveGB  = $TotalWithArchive
            LastLogonTime       = $LastLogon
            LastUserActionTime  = $LastUserAction
            Status              = $Status
            ProhibitSendQuota   = $Mailbox.ProhibitSendQuota
            IssueWarningQuota   = $Mailbox.IssueWarningQuota
            ArchiveQuota        = $Mailbox.ArchiveQuota
            ArchiveStatus       = $Mailbox.ArchiveStatus
        }
    } catch {
        return $null
    }
}

# ── MAIN ──
Write-Host "=== Mailbox Size & Growth Report ===" -ForegroundColor Cyan
Write-Host "Warning: >= ${WarningSizeGB}GB | Critical: >= ${CriticalSizeGB}GB" -ForegroundColor White

if (-not $SkipExchangeConnect) {
    Connect-ToExchange
}

if ($CsvPath) {
    $CsvData = Import-Csv $CsvPath
    $UserPrincipalNames = $CsvData.UserPrincipalName
}

if (-not $UserPrincipalNames) {
    Write-Host "Retrieving all mailboxes..." -ForegroundColor Yellow
    $Mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
    $UserPrincipalNames = $Mailboxes.UserPrincipalName
}

Write-Host "Checking $($UserPrincipalNames.Count) mailboxes..." -ForegroundColor Yellow

$i = 0
foreach ($UPN in $UserPrincipalNames) {
    $i++
    if ($i % 50 -eq 0) { Write-Host "  $i / $($UserPrincipalNames.Count)..." -ForegroundColor Gray }
    $Stats = Get-MailboxStats -Identity $UPN
    if ($Stats) { $Results.Add($Stats) }
}

$TotalMailboxes = $Results.Count
$CriticalCount = ($Results | Where-Object { $_.Status -eq "Critical" }).Count
$WarningCount = ($Results | Where-Object { $_.Status -eq "Warning" }).Count
$OkCount = ($Results | Where-Object { $_.Status -eq "OK" }).Count
$TotalStorage = ($Results | Measure-Object -Property TotalWithArchiveGB -Sum).Sum
$ArchiveCount = ($Results | Where-Object { $_.ArchiveSizeGB }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Mailboxes: $TotalMailboxes | Total Storage: $([math]::Round($TotalStorage, 0)) GB" -ForegroundColor White
Write-Host "OK: $OkCount | Warning: $WarningCount | Critical: $CriticalCount | Archive: $ArchiveCount"

$HtmlRows = $Results | Sort-Object TotalWithArchiveGB -Descending | Select-Object -First 500 | ForEach-Object {
    $RowClass = switch ($_.Status) {
        "Critical" { "danger" }
        "Warning" { "warning" }
        default { "" }
    }
    "<tr class='$RowClass'>
        <td>$($_.UserPrincipalName)</td>
        <td>$($_.DisplayName)</td>
        <td>$($_.RecipientType)</td>
        <td>$($_.TotalSizeGB)</td>
        <td>$($_.ItemCount)</td>
        <td>$($_.ArchiveSizeGB)</td>
        <td>$($_.TotalWithArchiveGB)</td>
        <td>$($_.LastUserActionTime)</td>
        <td>$($_.Status)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Mailbox Size Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 11px; }
th { background: #2c3e50; color: white; padding: 6px; text-align: left; }
td { padding: 4px 6px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
.warning td { background: #fff3cd; }
</style></head>
<body>
<h1>Mailbox Size & Growth Report</h1>
<div class='summary'>
    <strong>Mailboxes:</strong> $TotalMailboxes |
    <strong>Total Storage:</strong> $([math]::Round($TotalStorage, 0)) GB |
    <strong>OK:</strong> $OkCount |
    <strong>Warning (>= ${WarningSizeGB}GB):</strong> <span style='color:orange;'>$WarningCount</span> |
    <strong>Critical (>= ${CriticalSizeGB}GB):</strong> <span style='color:red;'>$CriticalCount</span> |
    <strong>Archive Enabled:</strong> $ArchiveCount
</div>
<table>
<tr><th>User</th><th>Name</th><th>Type</th><th>Size (GB)</th><th>Items</th><th>Archive (GB)</th><th>Total (GB)</th><th>Last Used</th><th>Status</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvExportPath) {
    $Results | Export-Csv -Path $CsvExportPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvExportPath" -ForegroundColor Green
}
