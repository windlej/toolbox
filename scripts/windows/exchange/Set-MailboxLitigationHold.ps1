#Requires -Version 5.1

<#
.SYNOPSIS
Reports, enables or disables Litigation Hold on Exchange Online mailboxes.

.DESCRIPTION
For each mailbox given by -UserPrincipalNames or a CSV with a UserPrincipalName column (-CsvPath), reads the current
Litigation Hold state, duration, note and retention-hold flag. With -EnableHold it turns Litigation Hold on (using
-HoldDurationDays and -HoldNote) for mailboxes where it is off. With -DisableHold it turns Litigation Hold off for
mailboxes where it is on. With neither switch, or with -ReportOnly, it only reports.

Disabling a hold can allow preserved data to be purged under the retention policy, so confirm with legal/compliance
first. Use -WhatIf to preview every change. If both -EnableHold and -DisableHold are given, enabling takes priority.

Output is an HTML report (primary) with one row per mailbox and the action taken, an optional CSV (-ExportCsv) and
a log file, all in the output folder.

.PARAMETER UserPrincipalNames
Mailboxes (UPNs) to process. Required unless -CsvPath is used.

.PARAMETER CsvPath
Input CSV with a UserPrincipalName column listing the mailboxes to process (used instead of -UserPrincipalNames).

.PARAMETER OutputPath
Folder for the report, CSV and log. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the per-mailbox results to a CSV next to the HTML report.

.PARAMETER HoldDurationDays
Hold duration in days applied when enabling a hold. Default 365.

.PARAMETER EnableHold
Turn Litigation Hold on for mailboxes where it is currently off.

.PARAMETER DisableHold
Turn Litigation Hold off for mailboxes where it is currently on.

.PARAMETER ReportOnly
Report current hold state only, even if -EnableHold or -DisableHold is given.

.PARAMETER HoldNote
Note stored on the mailbox when enabling a hold.

.PARAMETER SkipExchangeConnect
Do not call Connect-ExchangeOnline; use an existing session.

.EXAMPLE
.\Set-MailboxLitigationHold.ps1 -UserPrincipalNames user@contoso.com -ReportOnly -OutputPath D:\Reports

.EXAMPLE
.\Set-MailboxLitigationHold.ps1 -CsvPath D:\Input\custodians.csv -EnableHold -HoldDurationDays 730 -HoldNote "Matter 2026-014" -WhatIf -ExportCsv -CustomerName Contoso -OutputPath D:\Reports

.NOTES
Platform:     Windows (ExchangeOnlineManagement module, Exchange Online)
Permissions:  Exchange Online roles Mailbox Search or Legal Hold (to set holds) and View-Only Recipients (to report)
When to use:  Placing custodian mailboxes on hold for legal or compliance requests, or auditing which mailboxes are on hold before offboarding.
Safety:       Destructive (supports -WhatIf)
Version:      1.1
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ByUpn')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'ByUpn')]
    [string[]]$UserPrincipalNames,

    [Parameter(Mandatory = $true, ParameterSetName = 'ByCsv')]
    [string]$CsvPath,

    [string]$OutputPath,
    [string]$CustomerName,
    [switch]$ExportCsv,
    [int]$HoldDurationDays = 365,
    [switch]$EnableHold,
    [switch]$DisableHold,
    [switch]$ReportOnly,
    [string]$HoldNote = "Litigation hold enabled for legal compliance.",
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
$htmlPath = Join-Path $outDir "Set-MailboxLitigationHold_$stamp.html"
$csvOut   = Join-Path $outDir "Set-MailboxLitigationHold_$stamp.csv"
$script:LogFile = Join-Path $outDir "Set-MailboxLitigationHold_$stamp.log"

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

function Get-MailboxHoldStatus {
    param([string]$Identity)

    try {
        $Mailbox = Get-Mailbox -Identity $Identity -ErrorAction SilentlyContinue
        if (-not $Mailbox) {
            return [PSCustomObject]@{
                UserPrincipalName = $Identity
                DisplayName       = "Not Found"
                RecipientType     = $null
                LitigationHoldEnabled = $null
                HoldDuration      = $null
                HoldNote          = ""
                RetentionHold     = $null
                ComplianceTag     = ""
                CurrentStatus     = "Not Found"
            }
        }

        $Duration = if ($Mailbox.LitigationHoldDuration) {
            "$($Mailbox.LitigationHoldDuration.Days) days"
        } else { "Unlimited" }

        $Status = if ($Mailbox.LitigationHoldEnabled) { "On" } else { "Off" }

        return [PSCustomObject]@{
            UserPrincipalName       = $Identity
            DisplayName             = $Mailbox.DisplayName
            RecipientType           = $Mailbox.RecipientTypeDetails
            LitigationHoldEnabled   = $Mailbox.LitigationHoldEnabled
            HoldDuration            = $Duration
            HoldNote                = $Mailbox.LitigationHoldNote
            RetentionHold           = $Mailbox.RetentionHoldEnabled
            CurrentStatus           = $Status
        }
    } catch {
        return [PSCustomObject]@{
            UserPrincipalName = $Identity
            DisplayName       = "Error"
            RecipientType     = $null
            LitigationHoldEnabled = $null
            HoldDuration      = $null
            HoldNote          = ""
            CurrentStatus     = "Error"
        }
    }
}

function Set-LitigationHold {
    param(
        [string]$Identity,
        [bool]$Enable,
        [int]$DurationDays,
        [string]$Note
    )

    $Action = if ($Enable) { "Enable Litigation Hold" } else { "Disable Litigation Hold" }

    if (-not $PSCmdlet.ShouldProcess($Identity, $Action)) {
        return "WhatIf"
    }

    try {
        $Params = @{
            Identity = $Identity
            Confirm  = $false
            ErrorAction = 'Stop'
        }

        if ($Enable) {
            $Params.LitigationHoldEnabled = $true
            $Params.LitigationHoldDuration = $DurationDays
            $Params.LitigationHoldNote = $Note
        } else {
            $Params.LitigationHoldEnabled = $false
        }

        Set-Mailbox @Params
        if ($Enable) { return "Enabled" } else { return "Disabled" }
    } catch {
        Write-Log "Failed to set hold on $Identity : $_" 'WARN'
        return "Failed"
    }
}

# ── MAIN ──
try {
    Write-Log 'Litigation hold run started.'
    if ($ReportOnly) { Write-Log 'Action: REPORT only (no changes)' }
    elseif ($EnableHold) { Write-Log "Action: ENABLE hold ($HoldDurationDays days)" }
    elseif ($DisableHold) { Write-Log 'Action: DISABLE hold' 'WARN' }
    else { Write-Log 'Action: REPORT only (neither -EnableHold nor -DisableHold given)' }

    if (-not $SkipExchangeConnect) {
        Connect-ToExchange
    }

    if ($CsvPath) {
        $CsvData = Import-Csv -LiteralPath $CsvPath
        $UserPrincipalNames = $CsvData.UserPrincipalName
    }

    $UserPrincipalNames = @($UserPrincipalNames)
    Write-Log "Processing $($UserPrincipalNames.Count) mailboxes..."

    foreach ($UPN in $UserPrincipalNames) {
        Write-Log "  $UPN"

        $Current = Get-MailboxHoldStatus -Identity $UPN

        $Action = ""
        if (-not $ReportOnly) {
            if ($EnableHold -and -not $Current.LitigationHoldEnabled) {
                $Result = Set-LitigationHold -Identity $UPN -Enable $true -DurationDays $HoldDurationDays -Note $HoldNote
                $Action = $Result
            } elseif ($DisableHold -and $Current.LitigationHoldEnabled) {
                $Result = Set-LitigationHold -Identity $UPN -Enable $false -DurationDays $HoldDurationDays -Note $HoldNote
                $Action = $Result
            }
        }

        $Results.Add([PSCustomObject]@{
            UserPrincipalName     = $UPN
            DisplayName           = $Current.DisplayName
            RecipientType         = $Current.RecipientType
            CurrentHoldEnabled    = $Current.LitigationHoldEnabled
            CurrentDuration       = $Current.HoldDuration
            CurrentNote           = $Current.HoldNote
            Action                = if ($Action) { $Action } else { "NoChange" }
        })
    }

    $EnabledCount = @($Results | Where-Object { $_.Action -eq "Enabled" }).Count
    $DisabledCount = @($Results | Where-Object { $_.Action -eq "Disabled" }).Count
    $AlreadyOn = @($Results | Where-Object { $_.Action -eq "NoChange" -and $_.CurrentHoldEnabled }).Count
    $AlreadyOff = @($Results | Where-Object { $_.Action -eq "NoChange" -and -not $_.CurrentHoldEnabled }).Count
    $FailedCount = @($Results | Where-Object { $_.Action -eq "Failed" }).Count

    Write-Log 'Summary'
    Write-Log "Enabled: $EnabledCount | Disabled: $DisabledCount | Already On: $AlreadyOn | Already Off: $AlreadyOff | Failed: $FailedCount"

    $HtmlRows = $Results | ForEach-Object {
        $RowClass = switch ($_.Action) {
            "Enabled" { "success" }
            "Disabled" { "warning" }
            "Failed" { "danger" }
            default { "" }
        }
        "<tr class='$RowClass'>
        <td>$($_.UserPrincipalName)</td>
        <td>$($_.DisplayName)</td>
        <td>$($_.CurrentHoldEnabled)</td>
        <td>$($_.CurrentDuration)</td>
        <td>$($_.Action)</td>
    </tr>"
    }

    $Html = @"
<!DOCTYPE html>
<html>
<head><title>Litigation Hold Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
.success td { background: #d4edda; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 5px 8px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
.warning td { background: #fff3cd; }
</style></head>
<body>
<h1>Litigation Hold Enablement Report</h1>
<div class='summary'>
    <strong>Total Mailboxes:</strong> $($Results.Count) |
    <strong>Enabled:</strong> <span style='color:green;'>$EnabledCount</span> |
    <strong>Disabled:</strong> $DisabledCount |
    <strong>Already On:</strong> $AlreadyOn |
    <strong>Failed:</strong> <span style='color:red;'>$FailedCount</span> |
    <strong>Duration:</strong> $HoldDurationDays days
</div>
<table>
<tr><th>Mailbox</th><th>Display Name</th><th>Hold Enabled</th><th>Duration</th><th>Action</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

    $Html | Out-File -LiteralPath $htmlPath -Encoding UTF8 -WhatIf:$false
    Write-Log "Report written: $htmlPath"

    if ($ExportCsv) {
        $Results | Export-Csv -LiteralPath $csvOut -NoTypeInformation -Encoding UTF8 -WhatIf:$false
        Write-Log "CSV written: $csvOut"
    }
}
catch {
    Write-Log "Litigation hold run failed: $_" 'ERROR'
    throw
}
