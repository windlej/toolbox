#Requires -Version 5.1

<#
.SYNOPSIS
Finds inbox rules that look like mail exfiltration or hiding activity (forward/redirect, delete, keywords, bad domains).

.DESCRIPTION
Reads the inbox rules of all Exchange Online mailboxes, a list of UPNs, or a CSV with a UserPrincipalName column,
and flags rules that forward or redirect mail, delete messages without moving them, stop rule processing, contain
any of the -SuspiciousKeywords in their name/description/actions, or forward to any of the -SuspiciousDomains.
By default only flagged rules are reported; use -ReportAllRules to list every rule.

Output is an HTML report (primary, suspicious rows highlighted), an optional CSV with the full rule detail
(-ExportCsv) and a log file, all in the output folder. The script does not change anything. Note that the rule
detail (forward targets, subject/body match text) may be sensitive; store the output accordingly.

.PARAMETER UserPrincipalNames
Optional list of mailboxes (UPNs) to check. If neither this nor -CsvPath is given, all mailboxes are checked.

.PARAMETER CsvPath
Optional input CSV with a UserPrincipalName column listing the mailboxes to check.

.PARAMETER OutputPath
Folder for the report, CSV and log. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the rule rows to a CSV next to the HTML report.

.PARAMETER SuspiciousKeywords
Keywords that flag a rule when found in its name, description or action text. A built-in list is used by default.

.PARAMETER SuspiciousDomains
Optional list of domains; rules forwarding or redirecting to any of them are flagged.

.PARAMETER MaxRuleReportLength
Reserved. Accepted for compatibility but not used by the current report.

.PARAMETER ReportAllRules
Report every inbox rule found, not just the suspicious ones.

.PARAMETER SkipExchangeConnect
Do not call Connect-ExchangeOnline; use an existing session.

.EXAMPLE
.\Get-SuspiciousInboxRule.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-SuspiciousInboxRule.ps1 -UserPrincipalNames user@contoso.com -SuspiciousDomains fabrikam.net -ReportAllRules -ExportCsv -CustomerName Contoso -OutputPath D:\Reports

.NOTES
Platform:     Windows (ExchangeOnlineManagement module, Exchange Online)
Permissions:  Exchange Online roles View-Only Recipients and Mail Recipients (Get-InboxRule reads other users' rules)
When to use:  After a phishing or business-email-compromise incident, or as a periodic sweep for attacker-created inbox rules.
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
    [string[]]$SuspiciousKeywords = @(
        "forward", "redirect", "auto forward", "auto reply", "external",
        "transfer", "copy", "bcc", "rule", "delete", "permanent delete",
        "archive", "move to", "mark as read", "report spam",
        "forwarding", "email forwarding", "automatic reply"
    ),
    [string[]]$SuspiciousDomains,
    [int]$MaxRuleReportLength = 5000,
    [switch]$ReportAllRules,
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
$htmlPath = Join-Path $outDir "Get-SuspiciousInboxRule_$stamp.html"
$csvPath  = Join-Path $outDir "Get-SuspiciousInboxRule_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-SuspiciousInboxRule_$stamp.log"

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

function Test-InboxRuleSuspicious {
    param(
        [PSObject]$Rule,
        [string[]]$Keywords,
        [string[]]$SuspiciousDomains
    )

    $Flags = @()
    $RuleText = @(
        $Rule.Name,
        $Rule.Description,
        $Rule.RedirectTo,
        $Rule.ForwardTo,
        $Rule.ForwardToRecipients,
        $Rule.SendTo,
        $Rule.DeleteMessage,
        $Rule.MarkAsRead,
        $Rule.StopProcessingRules,
        $Rule.Name
    ) -join ' '

    if ($Rule.ForwardTo -or $Rule.RedirectTo) {
        $Flags += "Forward/Redirect Action"
    }

    if ($Rule.DeleteMessage -and -not $Rule.MoveToFolder) {
        $Flags += "Delete Action"
    }

    if ($Rule.StopProcessingRules) {
        $Flags += "StopProcessing"
    }

    foreach ($Keyword in $Keywords) {
        if ($RuleText -match [regex]::Escape($Keyword)) {
            $Flags += "Keyword: '$Keyword'"
            break
        }
    }

    if ($SuspiciousDomains) {
        $ForwardTargets = @($Rule.ForwardTo) + @($Rule.RedirectTo) + @($Rule.ForwardToRecipients)
        foreach ($Target in $ForwardTargets) {
            foreach ($Domain in $SuspiciousDomains) {
                if ($Target -match [regex]::Escape($Domain)) {
                    $Flags += "SuspiciousDomain: $Domain"
                }
            }
        }
    }

    return $Flags
}

# ── MAIN ──
try {
    Write-Log 'Inbox rule exfiltration detection started.'

    if (-not $SkipExchangeConnect) {
        Connect-ToExchange
    }

    if ($CsvPath) {
        $CsvData = Import-Csv -LiteralPath $CsvPath
        $UserPrincipalNames = $CsvData.UserPrincipalName
    }

    if (-not $UserPrincipalNames) {
        Write-Log 'Scanning all mailboxes...'
        $Mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
        $UserPrincipalNames = $Mailboxes.UserPrincipalName
    }

    $UserPrincipalNames = @($UserPrincipalNames)
    Write-Log "Checking $($UserPrincipalNames.Count) mailboxes for inbox rules..."

    $i = 0
    foreach ($UPN in $UserPrincipalNames) {
        $i++
        if ($i % 100 -eq 0) { Write-Log "  $i / $($UserPrincipalNames.Count)..." }

        try {
            $Rules = Get-InboxRule -Mailbox $UPN -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Could not read inbox rules for $UPN : $_" 'WARN'
            continue
        }

        if (-not $Rules) { continue }

        foreach ($Rule in $Rules) {
            $SuspiciousFlags = @(Test-InboxRuleSuspicious -Rule $Rule -Keywords $SuspiciousKeywords -SuspiciousDomains $SuspiciousDomains)
            $IsSuspicious = $SuspiciousFlags.Count -gt 0

            if ($IsSuspicious -or $ReportAllRules) {
                $Results.Add([PSCustomObject]@{
                    UserPrincipalName = $UPN
                    RuleName          = $Rule.Name
                    Description       = $Rule.Description
                    Enabled           = $Rule.Enabled
                    Priority          = $Rule.Priority
                    ForwardTo         = ($Rule.ForwardTo -join '; ')
                    RedirectTo        = ($Rule.RedirectTo -join '; ')
                    DeleteMessage     = $Rule.DeleteMessage
                    MarkAsRead        = $Rule.MarkAsRead
                    StopProcessing    = $Rule.StopProcessingRules
                    HasAttachment     = $Rule.HasAttachment
                    FlaggedForAction  = $Rule.FlaggedForAction
                    FromAddresses     = ($Rule.FromAddresses -join '; ')
                    SentTo            = ($Rule.SentTo -join '; ')
                    SubjectContains   = ($Rule.SubjectContains -join '; ')
                    BodyContains      = ($Rule.BodyContains -join '; ')
                    SuspiciousFlags   = ($SuspiciousFlags -join '; ')
                    IsSuspicious      = $IsSuspicious
                })
            }
        }
    }

    $SuspiciousCount = @($Results | Where-Object { $_.IsSuspicious }).Count
    $TotalRules = $Results.Count

    Write-Log 'Summary'
    Write-Log "Mailboxes Scanned: $($UserPrincipalNames.Count)"
    Write-Log "Rules Reported: $TotalRules"
    if ($SuspiciousCount -gt 0) {
        Write-Log "Suspicious Rules: $SuspiciousCount" 'WARN'
        $Results | Where-Object { $_.IsSuspicious } | ForEach-Object {
            Write-Log "  [$($_.UserPrincipalName)] $($_.RuleName) : $($_.SuspiciousFlags)" 'WARN'
        }
    }
    else {
        Write-Log 'Suspicious Rules: 0'
    }

    $HtmlRows = $Results | Sort-Object -Property @{ Expression = 'IsSuspicious'; Descending = $true }, 'UserPrincipalName' | ForEach-Object {
        $RowClass = if ($_.IsSuspicious) { "danger" } else { "" }
        "<tr class='$RowClass'>
        <td>$($_.UserPrincipalName)</td>
        <td>$($_.RuleName)</td>
        <td>$($_.Enabled)</td>
        <td>$($_.ForwardTo)</td>
        <td>$($_.RedirectTo)</td>
        <td>$($_.DeleteMessage)</td>
        <td>$($_.SuspiciousFlags)</td>
    </tr>"
    }

    $Html = @"
<!DOCTYPE html>
<html>
<head><title>Inbox Rule Exfiltration Detection</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 5px 8px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
</style></head>
<body>
<h1>Inbox Rule Exfiltration Detection Report</h1>
<div class='summary'>
    <strong>Mailboxes Scanned:</strong> $($UserPrincipalNames.Count) |
    <strong>Rules Found:</strong> $TotalRules |
    <strong>Suspicious:</strong> <span style='color:red;'>$SuspiciousCount</span>
</div>
<table>
<tr><th>Mailbox</th><th>Rule Name</th><th>Enabled</th><th>Forward To</th><th>Redirect To</th><th>Delete</th><th>Suspicious Flags</th></tr>
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
    Write-Log "Inbox rule detection failed: $_" 'ERROR'
    throw
}
