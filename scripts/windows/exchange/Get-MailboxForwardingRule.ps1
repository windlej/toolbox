#Requires -Version 5.1

<#
.SYNOPSIS
Finds mailbox-level forwarding and inbox-rule forwarding/redirects, and can optionally remove them.

.DESCRIPTION
Scans Exchange Online mailboxes (all mailboxes, a list of UPNs, or a CSV with a UserPrincipalName column) for
mail forwarding. With -DetectMailboxForwarding it reports ForwardingAddress / ForwardingSmtpAddress set on the
mailbox. With -DetectInboxRuleForwarding it reports inbox rules that use ForwardTo or RedirectTo. Each finding is
flagged as external when the target domain differs from the tenant's default accepted domain.

The script is read-only unless -RemoveForwarding is given. With -RemoveForwarding it clears the mailbox forwarding
properties and disables the offending inbox rules (the rules are disabled, not deleted). Use -WhatIf to preview.

Output is an HTML report (primary) with external forwarders highlighted, an optional CSV (-ExportCsv) and a log file,
all written to the output folder.

.PARAMETER UserPrincipalNames
Optional list of mailboxes (UPNs) to check. If neither this nor -CsvPath is given, all mailboxes are scanned.

.PARAMETER CsvPath
Optional input CSV with a UserPrincipalName column listing the mailboxes to check.

.PARAMETER OutputPath
Folder for the report, CSV and log. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the findings to a CSV next to the HTML report.

.PARAMETER DetectMailboxForwarding
Check the ForwardingAddress / ForwardingSmtpAddress properties on each mailbox. If neither this nor
-DetectInboxRuleForwarding is given, both checks run.

.PARAMETER DetectInboxRuleForwarding
Check each mailbox's inbox rules for ForwardTo / RedirectTo actions. If neither this nor
-DetectMailboxForwarding is given, both checks run.

.PARAMETER RemoveForwarding
Clear detected mailbox forwarding and disable detected inbox rules. Supports -WhatIf and -Confirm.

.PARAMETER SkipExchangeConnect
Do not call Connect-ExchangeOnline; use an existing session.

.EXAMPLE
.\Get-MailboxForwardingRule.ps1 -DetectMailboxForwarding -DetectInboxRuleForwarding -OutputPath D:\Reports

.EXAMPLE
.\Get-MailboxForwardingRule.ps1 -CsvPath D:\Input\users.csv -DetectInboxRuleForwarding -RemoveForwarding -WhatIf -ExportCsv -CustomerName Contoso -OutputPath D:\Reports

.NOTES
Platform:     Windows (ExchangeOnlineManagement module, Exchange Online)
Permissions:  Exchange Online roles View-Only Recipients (report); Mail Recipients (to use -RemoveForwarding)
When to use:  After a suspected account compromise, during a security review, or before offboarding to find mail leaving the tenant.
Safety:       Changes data (supports -WhatIf)
Version:      1.2
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$UserPrincipalNames,
    [string]$CsvPath,
    [string]$OutputPath,
    [string]$CustomerName,
    [switch]$ExportCsv,
    [switch]$DetectMailboxForwarding,
    [switch]$DetectInboxRuleForwarding,
    [switch]$RemoveForwarding,
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
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force -WhatIf:$false | Out-Null }
    (Resolve-Path -LiteralPath $Path).Path
}

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 's'), $Level, $Message
    Write-Host $line
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $line -WhatIf:$false }
}

$stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir   = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$htmlPath = Join-Path $outDir "Get-MailboxForwardingRule_$stamp.html"
$csvPath  = Join-Path $outDir "Get-MailboxForwardingRule_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-MailboxForwardingRule_$stamp.log"

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

function Test-ExternalDomain {
    param([string]$Address, [string]$PrimaryDomain)

    if (-not $Address) { return $false }
    $Domain = ($Address -split '@')[1]
    if (-not $Domain) { return $false }
    return $Domain -ne $PrimaryDomain -and $Domain -ne ""
}

function Get-PrimaryDomain {
    try {
        $Accepted = Get-AcceptedDomain | Where-Object { $_.Default -eq $true }
        return $Accepted.DomainName
    } catch { return "" }
}

function Get-MailboxForwarding {
    param([string]$Identity, [string]$PrimaryDomain)

    try {
        $Mailbox = Get-Mailbox -Identity $Identity -ErrorAction SilentlyContinue
        if (-not $Mailbox) { return @() }

        $Found = @()

        if ($Mailbox.ForwardingAddress -or $Mailbox.ForwardingSmtpAddress) {
            $Target = if ($Mailbox.ForwardingAddress) {
                $Mailbox.ForwardingAddress
            } else {
                $Mailbox.ForwardingSmtpAddress
            }

            $IsExternal = Test-ExternalDomain -Address $Target -PrimaryDomain $PrimaryDomain

            $Found += [PSCustomObject]@{
                UserPrincipalName  = $Identity
                ForwardingType     = "Mailbox Forwarding"
                Target             = $Target
                DeliverToMailbox   = $Mailbox.DeliverToMailboxAndForward
                IsExternal         = $IsExternal
                Source             = "Mailbox property"
                Action             = "Reported"
            }
        }

        return $Found
    } catch { return @() }
}

function Get-InboxRuleForwarding {
    param([string]$Identity, [string]$PrimaryDomain)

    try {
        $Rules = Get-InboxRule -Mailbox $Identity -ErrorAction SilentlyContinue
        $Found = @()

        foreach ($Rule in $Rules) {
            $ForwardTargets = @()
            if ($Rule.ForwardTo) { $ForwardTargets += $Rule.ForwardTo }
            if ($Rule.RedirectTo) { $ForwardTargets += $Rule.RedirectTo }

            foreach ($Target in $ForwardTargets) {
                $IsExternal = Test-ExternalDomain -Address $Target -PrimaryDomain $PrimaryDomain

                $Found += [PSCustomObject]@{
                    UserPrincipalName  = $Identity
                    ForwardingType     = if ($Rule.RedirectTo) { "Inbox Rule - Redirect" } else { "Inbox Rule - Forward" }
                    Target             = $Target
                    DeliverToMailbox   = $null
                    IsExternal         = $IsExternal
                    Source             = "Rule: $($Rule.Name)"
                    Action             = "Reported"
                }
            }
        }

        return $Found
    } catch { return @() }
}

function Remove-MailboxForwardingSetting {
    param([string]$Identity)

    if (-not $PSCmdlet.ShouldProcess($Identity, 'Remove mailbox forwarding')) {
        return "WhatIf"
    }

    try {
        Set-Mailbox -Identity $Identity -ForwardingAddress $null -ForwardingSmtpAddress $null -ErrorAction Stop
        return "Removed"
    } catch {
        Write-Log "Failed to remove forwarding for $Identity : $_" 'WARN'
        return "Failed"
    }
}

function Remove-InboxRuleForwarding {
    param([string]$Identity, [string]$RuleName)

    if (-not $PSCmdlet.ShouldProcess("$Identity\$RuleName", 'Disable inbox rule')) {
        return "WhatIf"
    }

    try {
        Disable-InboxRule -Identity "$Identity\$RuleName" -Confirm:$false -ErrorAction Stop
        return "Disabled"
    } catch {
        Write-Log "Failed to disable rule '$RuleName' for $Identity : $_" 'WARN'
        return "Failed"
    }
}

# ── MAIN ──
try {
    Write-Log 'Forwarding rule detection started.'
    if (-not $DetectMailboxForwarding -and -not $DetectInboxRuleForwarding) {
        $DetectMailboxForwarding   = $true
        $DetectInboxRuleForwarding = $true
        Write-Log 'Neither -DetectMailboxForwarding nor -DetectInboxRuleForwarding was given; checking both.' 'WARN'
    }
    $scope = @()
    if ($DetectMailboxForwarding)   { $scope += 'Mailbox forwarding' }
    if ($DetectInboxRuleForwarding) { $scope += 'Inbox rules' }
    Write-Log "Scope: $($scope -join ' + ')"
    if ($RemoveForwarding) { Write-Log 'RemoveForwarding is set: detected forwarding will be removed/disabled (honours -WhatIf).' 'WARN' }

    if (-not $SkipExchangeConnect) {
        Connect-ToExchange
    }

    $PrimaryDomain = Get-PrimaryDomain
    Write-Log "Primary domain: $PrimaryDomain"

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
    Write-Log "Checking $($UserPrincipalNames.Count) mailboxes..."

    $i = 0
    foreach ($UPN in $UserPrincipalNames) {
        $i++
        if ($i % 100 -eq 0) { Write-Log "  $i / $($UserPrincipalNames.Count)..." }

        if ($DetectMailboxForwarding) {
            $Forwarding = Get-MailboxForwarding -Identity $UPN -PrimaryDomain $PrimaryDomain
            foreach ($F in $Forwarding) {
                if ($RemoveForwarding -and $F.Target) {
                    $F.Action = Remove-MailboxForwardingSetting -Identity $UPN
                }
                $Results.Add($F)
            }
        }

        if ($DetectInboxRuleForwarding) {
            $RuleForwarding = Get-InboxRuleForwarding -Identity $UPN -PrimaryDomain $PrimaryDomain
            foreach ($F in $RuleForwarding) {
                if ($RemoveForwarding -and $F.Target) {
                    $RuleName = ($F.Source -replace 'Rule: ', '')
                    $F.Action = Remove-InboxRuleForwarding -Identity $UPN -RuleName $RuleName
                }
                $Results.Add($F)
            }
        }
    }

    $ExternalCount = @($Results | Where-Object { $_.IsExternal }).Count
    $InternalCount = @($Results | Where-Object { -not $_.IsExternal }).Count
    $RemovedCount = @($Results | Where-Object { $_.Action -eq "Removed" -or $_.Action -eq "Disabled" }).Count

    Write-Log 'Summary'
    Write-Log "Total Forwarding Rules: $($Results.Count)"
    Write-Log "  External: $ExternalCount"
    Write-Log "  Internal: $InternalCount"
    Write-Log "  Removed/Disabled: $RemovedCount"

    $HtmlRows = $Results | Sort-Object -Property @{ Expression = 'IsExternal'; Descending = $true }, 'UserPrincipalName' | ForEach-Object {
        $RowClass = if ($_.IsExternal) { "danger" } else { "" }
        "<tr class='$RowClass'>
        <td>$($_.UserPrincipalName)</td>
        <td>$($_.ForwardingType)</td>
        <td>$($_.Target)</td>
        <td>$($_.IsExternal)</td>
        <td>$($_.Source)</td>
        <td>$($_.Action)</td>
    </tr>"
    }

    $Html = @"
<!DOCTYPE html>
<html>
<head><title>Forwarding Rule Detection Report</title>
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
<h1>Forwarding Rule Detection Report</h1>
<div class='summary'>
    <strong>Mailboxes Scanned:</strong> $($UserPrincipalNames.Count) |
    <strong>Rules Found:</strong> $($Results.Count) |
    <strong>External:</strong> <span style='color:red;'>$ExternalCount</span> |
    <strong>Internal:</strong> $InternalCount |
    <strong>Removed:</strong> $RemovedCount
</div>
<table>
<tr><th>Mailbox</th><th>Type</th><th>Forward To</th><th>External</th><th>Source</th><th>Action</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

    $Html | Out-File -LiteralPath $htmlPath -Encoding UTF8 -WhatIf:$false
    Write-Log "Report written: $htmlPath"

    if ($ExportCsv) {
        $Results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false
        Write-Log "CSV written: $csvPath"
    }
}
catch {
    Write-Log "Forwarding rule detection failed: $_" 'ERROR'
    throw
}
