#Requires -Version 5.1

<#
.SYNOPSIS
Reports who has FullAccess, SendAs and SendOnBehalf permissions on Exchange Online mailboxes.

.DESCRIPTION
Audits mailbox delegation for all mailboxes, a list of UPNs, or a CSV with a UserPrincipalName column. For each
mailbox it collects FullAccess (Get-MailboxPermission), SendAs (Get-RecipientPermission) and SendOnBehalf
(GrantSendOnBehalfTo) entries. Built-in entries (NT AUTHORITY, SIDs, Exchange Servers) are skipped, and inherited
FullAccess entries are skipped unless -ShowInherited is used.

Output is an HTML report (primary) with FullAccess rows highlighted and Deny entries in red, an optional CSV
(-ExportCsv) and a log file, all in the output folder. The script does not change anything.

.PARAMETER UserPrincipalNames
Optional list of mailboxes (UPNs) to audit. If neither this nor -CsvPath is given, all mailboxes are audited.

.PARAMETER CsvPath
Optional input CSV with a UserPrincipalName column listing the mailboxes to audit.

.PARAMETER OutputPath
Folder for the report, CSV and log. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the permission entries to a CSV next to the HTML report.

.PARAMETER IncludePermissionTypes
Comma-separated list of permission types to collect: FullAccess, SendAs, SendOnBehalf. Default is all three.

.PARAMETER ShowInherited
Include inherited FullAccess entries (hidden by default).

.PARAMETER SkipExchangeConnect
Do not call Connect-ExchangeOnline; use an existing session.

.EXAMPLE
.\Get-MailboxPermissionReport.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-MailboxPermissionReport.ps1 -CsvPath D:\Input\executives.csv -IncludePermissionTypes "FullAccess,SendAs" -ExportCsv -CustomerName Contoso -OutputPath D:\Reports

.NOTES
Platform:     Windows (ExchangeOnlineManagement module, Exchange Online)
Permissions:  Exchange Online role View-Only Recipients (Get-Mailbox, Get-MailboxPermission, Get-RecipientPermission)
When to use:  Access reviews, offboarding checks, or investigating who can read or send as a sensitive mailbox.
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
    [string]$IncludePermissionTypes = "FullAccess,SendAs,SendOnBehalf",
    [switch]$ShowInherited,
    [switch]$SkipExchangeConnect
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
$htmlPath = Join-Path $outDir "Get-MailboxPermissionReport_$stamp.html"
$csvPath  = Join-Path $outDir "Get-MailboxPermissionReport_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-MailboxPermissionReport_$stamp.log"

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

function Get-MailboxAccessRights {
    param(
        [string]$Identity,
        [string[]]$PermissionTypes
    )

    $Found = @()

    if ($PermissionTypes -contains "FullAccess" -or $PermissionTypes -contains "*") {
        $Permissions = Get-MailboxPermission -Identity $Identity -ErrorAction SilentlyContinue |
            Where-Object { -not $_.IsInherited -or $ShowInherited }
        foreach ($Perm in $Permissions) {
            if ($Perm.User -notlike "NT AUTHORITY\*" -and $Perm.User -notlike "S-1-*" -and $Perm.User -ne "Exchange Servers") {
                $Found += [PSCustomObject]@{
                    Mailbox      = $Identity
                    User         = $Perm.User
                    AccessRights = ($Perm.AccessRights -join ', ')
                    PermissionType = "FullAccess"
                    IsInherited  = $Perm.IsInherited
                    Deny         = $Perm.Deny
                }
            }
        }
    }

    if ($PermissionTypes -contains "SendAs") {
        $SendAsPerms = Get-RecipientPermission -Identity $Identity -ErrorAction SilentlyContinue |
            Where-Object { $_.Trustee -notlike "NT AUTHORITY\*" -and $_.Trustee -ne "Exchange Servers" }
        foreach ($Perm in $SendAsPerms) {
            $Found += [PSCustomObject]@{
                Mailbox      = $Identity
                User         = $Perm.Trustee
                AccessRights = "SendAs"
                PermissionType = "SendAs"
                IsInherited  = $false
                Deny         = $false
            }
        }
    }

    if ($PermissionTypes -contains "SendOnBehalf") {
        $Mailbox = Get-Mailbox -Identity $Identity -ErrorAction SilentlyContinue
        if ($Mailbox.GrantSendOnBehalfTo) {
            foreach ($Delegate in $Mailbox.GrantSendOnBehalfTo) {
                $Found += [PSCustomObject]@{
                    Mailbox      = $Identity
                    User         = $Delegate
                    AccessRights = "SendOnBehalf"
                    PermissionType = "SendOnBehalf"
                    IsInherited  = $false
                    Deny         = $false
                }
            }
        }
    }

    return $Found
}

# ── MAIN ──
try {
    Write-Log 'Mailbox permission audit started.'

    if (-not $SkipExchangeConnect) {
        Connect-ToExchange
    }

    if ($CsvPath) {
        $CsvData = Import-Csv -LiteralPath $CsvPath
        $UserPrincipalNames = $CsvData.UserPrincipalName
    }

    if (-not $UserPrincipalNames) {
        Write-Log 'No specific users specified. Retrieving all mailboxes...'
        $Mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
        $UserPrincipalNames = $Mailboxes.UserPrincipalName
    }

    $UserPrincipalNames = @($UserPrincipalNames)
    Write-Log "Auditing $($UserPrincipalNames.Count) mailboxes..."

    $PermTypes = @($IncludePermissionTypes -split ',' | ForEach-Object { $_.Trim() })

    $i = 0
    foreach ($UPN in $UserPrincipalNames) {
        $i++
        if ($i % 50 -eq 0) { Write-Log "  $i / $($UserPrincipalNames.Count)..." }
        $Perms = Get-MailboxAccessRights -Identity $UPN -PermissionTypes $PermTypes
        foreach ($Perm in $Perms) {
            $Results.Add($Perm)
        }
    }

    $TotalPerms = $Results.Count
    $MailboxesWithPerms = @($Results | Select-Object -ExpandProperty Mailbox -Unique).Count
    $FullAccessCount = @($Results | Where-Object { $_.PermissionType -eq "FullAccess" }).Count
    $SendAsCount = @($Results | Where-Object { $_.PermissionType -eq "SendAs" }).Count
    $SendOnBehalfCount = @($Results | Where-Object { $_.PermissionType -eq "SendOnBehalf" }).Count

    Write-Log 'Summary'
    Write-Log "Total Permissions: $TotalPerms (FullAccess: $FullAccessCount, SendAs: $SendAsCount, SendOnBehalf: $SendOnBehalfCount)"
    Write-Log "Mailboxes with Permissions: $MailboxesWithPerms"

    $HtmlRows = $Results | Sort-Object Mailbox, User | ForEach-Object {
        $RowClass = if ($_.Deny) { "danger" }
        elseif ($_.PermissionType -eq "FullAccess") { "warning" }
        else { "" }
        "<tr class='$RowClass'>
        <td>$($_.Mailbox)</td>
        <td>$($_.User)</td>
        <td>$($_.AccessRights)</td>
        <td>$($_.PermissionType)</td>
        <td>$($_.IsInherited)</td>
        <td>$($_.Deny)</td>
    </tr>"
    }

    $Html = @"
<!DOCTYPE html>
<html>
<head><title>Mailbox Permission Audit</title>
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
<h1>Mailbox Permission Audit</h1>
<div class='summary'>
    <strong>Mailboxes:</strong> $($UserPrincipalNames.Count) |
    <strong>With Permissions:</strong> $MailboxesWithPerms |
    <strong>Total ACEs:</strong> $TotalPerms |
    <strong>FullAccess:</strong> $FullAccessCount |
    <strong>SendAs:</strong> $SendAsCount |
    <strong>SendOnBehalf:</strong> $SendOnBehalfCount
</div>
<table>
<tr><th>Mailbox</th><th>User/Group</th><th>Access Rights</th><th>Type</th><th>Inherited</th><th>Deny</th></tr>
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
    Write-Log "Mailbox permission audit failed: $_" 'ERROR'
    throw
}
