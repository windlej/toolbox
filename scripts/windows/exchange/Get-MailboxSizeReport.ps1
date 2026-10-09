#Requires -Version 5.1

<#
.SYNOPSIS
Reports Exchange Online mailbox sizes (and optionally archive sizes) with warning and critical thresholds.

.DESCRIPTION
For all mailboxes, a list of UPNs, or a CSV with a UserPrincipalName column, collects total item size, item count,
last logon / last user action, quotas and (with -IncludeArchive) archive size. Each mailbox is rated OK, Warning or
Critical against -WarningSizeGB and -CriticalSizeGB based on the primary mailbox size.

Output is an HTML report (primary, largest 500 mailboxes shown, Warning/Critical rows highlighted), an optional
CSV with every mailbox (-ExportCsv) and a log file, all in the output folder. The script does not change anything.

.PARAMETER UserPrincipalNames
Optional list of mailboxes (UPNs) to check. If neither this nor -CsvPath is given, all mailboxes are checked.

.PARAMETER CsvPath
Optional input CSV with a UserPrincipalName column listing the mailboxes to check.

.PARAMETER OutputPath
Folder for the report, CSV and log. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write all mailbox rows to a CSV next to the HTML report.

.PARAMETER IncludeArchive
Also collect archive mailbox size and item count for mailboxes with an active archive.

.PARAMETER ShowGrowth
Reserved. Accepted for compatibility but not used by the current report.

.PARAMETER TopGrowthDays
Reserved. Accepted for compatibility but not used by the current report.

.PARAMETER WarningSizeGB
Primary mailbox size in GB at or above which a mailbox is rated Warning. Default 50.

.PARAMETER CriticalSizeGB
Primary mailbox size in GB at or above which a mailbox is rated Critical. Default 80.

.PARAMETER SkipExchangeConnect
Do not call Connect-ExchangeOnline; use an existing session.

.EXAMPLE
.\Get-MailboxSizeReport.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-MailboxSizeReport.ps1 -IncludeArchive -WarningSizeGB 40 -CriticalSizeGB 90 -ExportCsv -CustomerName Contoso -OutputPath D:\Reports

.NOTES
Platform:     Windows (ExchangeOnlineManagement module, Exchange Online)
Permissions:  Exchange Online role View-Only Recipients (Get-Mailbox) and View-Only Recipients or Mail Recipients (Get-MailboxStatistics)
When to use:  Capacity planning, finding mailboxes near quota, or sizing a migration or archive rollout.
Safety:       Read-only
Version:      1.1
#>
[CmdletBinding()]
param(
    [string[]]$UserPrincipalNames,
    [string]$CsvPath,
    [string]$OutputPath,
    [string]$CustomerName,
    [switch]$ExportCsv,
    [switch]$IncludeArchive,
    [switch]$ShowGrowth,
    [int]$TopGrowthDays = 30,
    [int]$WarningSizeGB = 50,
    [int]$CriticalSizeGB = 80,
    [switch]$SkipExchangeConnect
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
$htmlPath = Join-Path $outDir "Get-MailboxSizeReport_$stamp.html"
$csvPath  = Join-Path $outDir "Get-MailboxSizeReport_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-MailboxSizeReport_$stamp.log"

$Results = [System.Collections.Generic.List[PSObject]]::new()

function Connect-ToExchange {
    if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
        throw 'ExchangeOnlineManagement module not found. Install: Install-Module ExchangeOnlineManagement -Scope CurrentUser'
    }
    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Log 'Connected to Exchange Online'
    } catch {
        Write-Log "Exchange connection failed: $_" 'ERROR'
        throw
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
            } catch {
                Write-Log "Could not read archive statistics for $Identity : $_" 'WARN'
            }
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
        Write-Log "Could not read statistics for $Identity : $_" 'WARN'
        return $null
    }
}

# ── MAIN ──
try {
    Write-Log 'Mailbox size report started.'
    Write-Log "Thresholds: Warning >= ${WarningSizeGB}GB | Critical >= ${CriticalSizeGB}GB"

    if (-not $SkipExchangeConnect) {
        Connect-ToExchange
    }

    if ($CsvPath) {
        $CsvData = Import-Csv -LiteralPath $CsvPath
        $UserPrincipalNames = $CsvData.UserPrincipalName
    }

    if (-not $UserPrincipalNames) {
        Write-Log 'Retrieving all mailboxes...'
        $Mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
        $UserPrincipalNames = $Mailboxes.UserPrincipalName
    }

    $UserPrincipalNames = @($UserPrincipalNames)
    Write-Log "Checking $($UserPrincipalNames.Count) mailboxes..."

    $i = 0
    foreach ($UPN in $UserPrincipalNames) {
        $i++
        if ($i % 50 -eq 0) { Write-Log "  $i / $($UserPrincipalNames.Count)..." }
        $Stats = Get-MailboxStats -Identity $UPN
        if ($Stats) { $Results.Add($Stats) }
    }

    $TotalMailboxes = $Results.Count
    $CriticalCount = @($Results | Where-Object { $_.Status -eq "Critical" }).Count
    $WarningCount = @($Results | Where-Object { $_.Status -eq "Warning" }).Count
    $OkCount = @($Results | Where-Object { $_.Status -eq "OK" }).Count
    $TotalStorage = [double](($Results | Measure-Object -Property TotalWithArchiveGB -Sum).Sum)
    $ArchiveCount = @($Results | Where-Object { $_.ArchiveSizeGB }).Count

    Write-Log 'Summary'
    Write-Log "Mailboxes: $TotalMailboxes | Total Storage: $([math]::Round($TotalStorage, 0)) GB"
    Write-Log "OK: $OkCount | Warning: $WarningCount | Critical: $CriticalCount | Archive: $ArchiveCount"

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

    $Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
    Write-Log "Report written: $htmlPath"

    if ($ExportCsv) {
        $Results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log "CSV written: $csvPath"
    }
}
catch {
    Write-Log "Mailbox size report failed: $_" 'ERROR'
    throw
}
