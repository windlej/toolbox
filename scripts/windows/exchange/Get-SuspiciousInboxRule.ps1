param(
    [Parameter(Mandatory = $false)]
    [string[]]$UserPrincipalNames,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\InboxRuleAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvExportPath,

    [Parameter(Mandatory = $false)]
    [string[]]$SuspiciousKeywords = @(
        "forward", "redirect", "auto forward", "auto reply", "external",
        "transfer", "copy", "bcc", "rule", "delete", "permanent delete",
        "archive", "move to", "mark as read", "report spam",
        "forwarding", "email forwarding", "automatic reply"
    ),

    [Parameter(Mandatory = $false)]
    [string[]]$SuspiciousDomains,

    [Parameter(Mandatory = $false)]
    [int]$MaxRuleReportLength = 5000,

    [Parameter(Mandatory = $false)]
    [switch]$ReportAllRules,

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
Write-Host "=== Inbox Rule Exfiltration Detection ===" -ForegroundColor Cyan

if (-not $SkipExchangeConnect) {
    Connect-ToExchange
}

if ($CsvPath) {
    $CsvData = Import-Csv $CsvPath
    $UserPrincipalNames = $CsvData.UserPrincipalName
}

if (-not $UserPrincipalNames) {
    Write-Host "Scanning all mailboxes..." -ForegroundColor Yellow
    $Mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
    $UserPrincipalNames = $Mailboxes.UserPrincipalName
}

Write-Host "Checking $($UserPrincipalNames.Count) mailboxes for inbox rules..." -ForegroundColor Yellow

$i = 0
foreach ($UPN in $UserPrincipalNames) {
    $i++
    if ($i % 100 -eq 0) { Write-Host "  $i / $($UserPrincipalNames.Count)..." -ForegroundColor Gray }

    try {
        $Rules = Get-InboxRule -Mailbox $UPN -ErrorAction SilentlyContinue
    } catch {
        continue
    }

    if (-not $Rules) { continue }

    foreach ($Rule in $Rules) {
        $SuspiciousFlags = Test-InboxRuleSuspicious -Rule $Rule -Keywords $SuspiciousKeywords -SuspiciousDomains $SuspiciousDomains
        $IsSuspicious = $SuspiciousFlags.Count -gt 0

        if ($IsSuspicious -or $ReportAllRules) {
            $Results.Add([PSCustomObject]@{
                UserPrincipalName = $UPN
                RuleName          = $Rule.Name
                Description       = $Rule.Description
                Enabled           = $Rule.Enabled
                Priority          = $Rule.Priority
                ForwardTo         = ($Rule.ForwardTo -join '; ')
                RedirectTo        = $Rule.RedirectTo
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

$SuspiciousCount = ($Results | Where-Object { $_.IsSuspicious }).Count
$TotalRules = $Results.Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Mailboxes Scanned: $($UserPrincipalNames.Count)" -ForegroundColor White
Write-Host "Rules Found: $TotalRules" -ForegroundColor White
Write-Host "Suspicious Rules: $SuspiciousCount" -ForegroundColor $(if ($SuspiciousCount -gt 0) { "Red" } else { "Green" })

if ($SuspiciousCount -gt 0) {
    Write-Host "`nSuspicious Rules Detected!" -ForegroundColor Red
    $Results | Where-Object { $_.IsSuspicious } | ForEach-Object {
        Write-Host "  [$($_.UserPrincipalName)] $($_.RuleName) : $($_.SuspiciousFlags)" -ForegroundColor Yellow
    }
}

$HtmlRows = $Results | Sort-Object IsSuspicious -Descending, UserPrincipalName | ForEach-Object {
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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvExportPath) {
    $Results | Export-Csv -Path $CsvExportPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvExportPath" -ForegroundColor Green
}
