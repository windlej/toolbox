param(
    [Parameter(Mandatory = $false)]
    [string[]]$UserPrincipalNames,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\ForwardingRules_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvExportPath,

    [Parameter(Mandatory = $false)]
    [switch]$DetectMailboxForwarding,

    [Parameter(Mandatory = $false)]
    [switch]$DetectInboxRuleForwarding,

    [Parameter(Mandatory = $false)]
    [switch]$RemoveForwarding,

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,

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

        $Results = @()

        if ($Mailbox.ForwardingAddress -or $Mailbox.ForwardingSmtpAddress) {
            $Target = if ($Mailbox.ForwardingAddress) {
                $Mailbox.ForwardingAddress
            } else {
                $Mailbox.ForwardingSmtpAddress
            }

            $IsExternal = Test-ExternalDomain -Address $Target -PrimaryDomain $PrimaryDomain

            $Results += [PSCustomObject]@{
                UserPrincipalName  = $Identity
                ForwardingType     = "Mailbox Forwarding"
                Target             = $Target
                DeliverToMailbox   = $Mailbox.DeliverToMailboxAndForward
                IsExternal         = $IsExternal
                Source             = "Mailbox property"
                Action             = "Reported"
            }
        }

        return $Results
    } catch { return @() }
}

function Get-InboxRuleForwarding {
    param([string]$Identity, [string]$PrimaryDomain)

    try {
        $Rules = Get-InboxRule -Mailbox $Identity -ErrorAction SilentlyContinue
        $Results = @()

        foreach ($Rule in $Rules) {
            $ForwardTargets = @()
            if ($Rule.ForwardTo) { $ForwardTargets += $Rule.ForwardTo }
            if ($Rule.RedirectTo) { $ForwardTargets += $Rule.RedirectTo }

            foreach ($Target in $ForwardTargets) {
                $IsExternal = Test-ExternalDomain -Address $Target -PrimaryDomain $PrimaryDomain

                $Results += [PSCustomObject]@{
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

        return $Results
    } catch { return @() }
}

function Remove-MailboxForwardingSetting {
    param([string]$Identity)

    if ($WhatIf) {
        Write-Host "[WhatIf] Would remove mailbox forwarding for $Identity" -ForegroundColor Yellow
        return "WhatIf"
    }

    try {
        Set-Mailbox -Identity $Identity -ForwardingAddress $null -ForwardingSmtpAddress $null -ErrorAction Stop
        return "Removed"
    } catch {
        Write-Warning "Failed to remove forwarding for $Identity : $_"
        return "Failed"
    }
}

function Remove-InboxRuleForwarding {
    param([string]$Identity, [string]$RuleName)

    if ($WhatIf) {
        Write-Host "[WhatIf] Would disable inbox rule '$RuleName' for $Identity" -ForegroundColor Yellow
        return "WhatIf"
    }

    try {
        Disable-InboxRule -Identity "$Identity\$RuleName" -Confirm:$false -ErrorAction Stop
        return "Disabled"
    } catch {
        Write-Warning "Failed to disable rule '$RuleName' for $Identity : $_"
        return "Failed"
    }
}

# ── MAIN ──
Write-Host "=== Forwarding Rule Detection ===" -ForegroundColor Cyan
Write-Host "Scope: $((if($DetectMailboxForwarding){'Mailbox '})+$(if($DetectInboxRuleForwarding){'+ Inbox Rules'}))" -ForegroundColor White

if (-not $SkipExchangeConnect) {
    Connect-ToExchange
}

$PrimaryDomain = Get-PrimaryDomain
Write-Host "Primary domain: $PrimaryDomain" -ForegroundColor Gray

if ($CsvPath) {
    $CsvData = Import-Csv $CsvPath
    $UserPrincipalNames = $CsvData.UserPrincipalName
}

if (-not $UserPrincipalNames) {
    Write-Host "Scanning all mailboxes..." -ForegroundColor Yellow
    $Mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
    $UserPrincipalNames = $Mailboxes.UserPrincipalName
}

Write-Host "Checking $($UserPrincipalNames.Count) mailboxes..." -ForegroundColor Yellow

$i = 0
foreach ($UPN in $UserPrincipalNames) {
    $i++
    if ($i % 100 -eq 0) { Write-Host "  $i / $($UserPrincipalNames.Count)..." -ForegroundColor Gray }

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

$ExternalCount = ($Results | Where-Object { $_.IsExternal }).Count
$InternalCount = ($Results | Where-Object { -not $_.IsExternal }).Count
$RemovedCount = ($Results | Where-Object { $_.Action -eq "Removed" -or $_.Action -eq "Disabled" }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total Forwarding Rules: $($Results.Count)" -ForegroundColor White
Write-Host "  External: $ExternalCount" -ForegroundColor $(if ($ExternalCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Internal: $InternalCount" -ForegroundColor Gray
Write-Host "  Removed/Disabled: $RemovedCount" -ForegroundColor Yellow

$HtmlRows = $Results | Sort-Object IsExternal -Descending, UserPrincipalName | ForEach-Object {
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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvExportPath) {
    $Results | Export-Csv -Path $CsvExportPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvExportPath" -ForegroundColor Green
}
