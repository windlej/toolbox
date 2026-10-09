#Requires -Version 5.1

<#
.SYNOPSIS
Exports Exchange Online transport rules to an XML file, or imports (recreates) them from a previous export.

.DESCRIPTION
Export mode (default): reads all transport rules with Get-TransportRule and writes a snapshot (name, state,
priority, mode, conditions, actions and common condition/action properties) to a Clixml file, plus an HTML summary
report (name, state, priority, mode, created date) and a log file, all in the output folder.

Import mode (-ImportPath): reads an XML file produced by export mode and recreates each rule with New-TransportRule
(name, priority, comments, mode, enabled state and the common conditions/actions that are present in the file).
Rules whose name already exists are skipped unless -SkipDuplicateCheck is used. Import supports -WhatIf and -Confirm.
Only a subset of rule properties is carried over; review imported rules before enabling them in production.

.PARAMETER OutputPath
Folder for the export XML, HTML report and log. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ImportPath
Import mode. Path to an XML file created by this script's export mode.

.PARAMETER SkipDuplicateCheck
Import mode. Do not skip rules whose name already exists in the tenant.

.PARAMETER SkipExchangeConnect
Do not call Connect-ExchangeOnline; use an existing session.

.EXAMPLE
.\Invoke-TransportRuleTransfer.ps1 -OutputPath D:\Reports -CustomerName Contoso

.EXAMPLE
.\Invoke-TransportRuleTransfer.ps1 -ImportPath D:\Reports\Contoso\Invoke-TransportRuleTransfer_20260101_090000.xml -OutputPath D:\Reports -WhatIf

.NOTES
Platform:     Windows (ExchangeOnlineManagement module, Exchange Online)
Permissions:  Exchange Online role Transport Rules (View-Only Configuration to export; Transport Rules to import)
When to use:  Backing up transport rules before changes, or copying rules from one tenant (for example a migration source) to another.
Safety:       Changes data (supports -WhatIf)
Version:      1.1
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Export')]
param(
    [string]$OutputPath,
    [string]$CustomerName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Import')]
    [string]$ImportPath,

    [Parameter(ParameterSetName = 'Import')]
    [switch]$SkipDuplicateCheck,

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
$xmlPath  = Join-Path $outDir "Invoke-TransportRuleTransfer_$stamp.xml"
$htmlPath = Join-Path $outDir "Invoke-TransportRuleTransfer_$stamp.html"
$script:LogFile = Join-Path $outDir "Invoke-TransportRuleTransfer_$stamp.log"

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

function Export-TransportRules {
    param([string]$ExportFile)

    try {
        $Rules = Get-TransportRule -ErrorAction Stop
        if (-not $Rules) {
            Write-Log 'No transport rules found to export.' 'WARN'
            return $null
        }

        $ExportData = @(foreach ($Rule in $Rules) {
            [PSCustomObject]@{
                Name                    = $Rule.Name
                State                   = $Rule.State
                Priority                = $Rule.Priority
                Comments                = $Rule.Comments
                Description             = $Rule.Description
                Mode                    = $Rule.Mode
                Conditions              = $Rule.Conditions
                Actions                 = $Rule.Actions
                Exceptions              = $Rule.Exceptions
                RuleVersion             = $Rule.RuleVersion
                WhenChanged             = $Rule.WhenChanged
                WhenCreated             = $Rule.WhenCreated
                SenderDomainConditions  = $Rule.SenderDomainIs
                RecipientDomainContains = $Rule.AnyOfRecipientAddressContains
                SubjectContains         = $Rule.SubjectContains
                BodyContains            = $Rule.BodyContains
                FromMemberOf            = $Rule.FromMemberOf
                SentToMemberOf          = $Rule.SentToMemberOf
                ApplyClassification     = $Rule.ApplyClassification
                ApplyHtmlDisclaimer     = $Rule.ApplyHtmlDisclaimerLocation
                RedirectMessageTo       = $Rule.RedirectMessageTo
                BlindCopyTo             = $Rule.BlindCopyTo
                ModerateMessageByUser   = $Rule.ModerateMessageByUser
                RejectMessageReasonText = $Rule.RejectMessageReasonText
                Quarantine              = $Rule.Quarantine
            }
        })

        $ExportData | Export-Clixml -LiteralPath $ExportFile -Depth 5 -Force -WhatIf:$false
        Write-Log "Exported $($ExportData.Count) transport rules to $ExportFile"

        $EnabledRules = @($ExportData | Where-Object { $_.State -eq "Enabled" }).Count
        $DisabledRules = @($ExportData | Where-Object { $_.State -eq "Disabled" }).Count

        return [PSCustomObject]@{
            TotalRules    = $ExportData.Count
            EnabledRules  = $EnabledRules
            DisabledRules = $DisabledRules
            ExportPath    = $ExportFile
            Rules         = $ExportData
        }
    } catch {
        Write-Log "Export failed: $_" 'ERROR'
        return $null
    }
}

function Import-TransportRules {
    param([string]$InputPath)

    if (-not (Test-Path -LiteralPath $InputPath)) {
        Write-Log "File not found: $InputPath" 'ERROR'
        return $null
    }

    try {
        $ImportData = @(Import-Clixml -LiteralPath $InputPath -ErrorAction Stop)
    } catch {
        Write-Log "Failed to import XML: $_" 'ERROR'
        return $null
    }

    $ExistingRules = Get-TransportRule -ErrorAction SilentlyContinue
    $ExistingNames = @($ExistingRules | Select-Object -ExpandProperty Name)

    $ImportCount = 0
    $SkipCount = 0
    $FailCount = 0

    foreach ($RuleData in $ImportData) {
        if (-not $SkipDuplicateCheck -and $ExistingNames -contains $RuleData.Name) {
            Write-Log "  Skipping duplicate: $($RuleData.Name)" 'WARN'
            $SkipCount++
            continue
        }

        if (-not $PSCmdlet.ShouldProcess($RuleData.Name, 'Create transport rule')) {
            Write-Log "  [WhatIf] Would import rule: $($RuleData.Name)"
            $ImportCount++
            continue
        }

        try {
            $NewRuleParams = @{
                Name        = $RuleData.Name
                Priority    = $RuleData.Priority
                Comments    = $RuleData.Comments
                Mode        = $RuleData.Mode
                ErrorAction = 'Stop'
            }

            if ($RuleData.State -eq "Enabled") { $NewRuleParams.Enabled = $true }
            else { $NewRuleParams.Enabled = $false }

            if ($RuleData.FromMemberOf) { $NewRuleParams.FromMemberOf = $RuleData.FromMemberOf }
            if ($RuleData.SentToMemberOf) { $NewRuleParams.SentToMemberOf = $RuleData.SentToMemberOf }
            if ($RuleData.SubjectContains) { $NewRuleParams.SubjectContains = $RuleData.SubjectContains }
            if ($RuleData.BodyContains) { $NewRuleParams.BodyContains = $RuleData.BodyContains }
            if ($RuleData.RedirectMessageTo) { $NewRuleParams.RedirectMessageTo = $RuleData.RedirectMessageTo }
            if ($RuleData.BlindCopyTo) { $NewRuleParams.BlindCopyTo = $RuleData.BlindCopyTo }
            if ($RuleData.RejectMessageReasonText) { $NewRuleParams.RejectMessageReasonText = $RuleData.RejectMessageReasonText }
            if ($RuleData.Quarantine) { $NewRuleParams.Quarantine = $RuleData.Quarantine }
            if ($RuleData.ApplyClassification) { $NewRuleParams.ApplyClassification = $RuleData.ApplyClassification }

            New-TransportRule @NewRuleParams | Out-Null
            Write-Log "  Imported: $($RuleData.Name)"
            $ImportCount++
        } catch {
            Write-Log "  Failed to import '$($RuleData.Name)': $_" 'WARN'
            $FailCount++
        }
    }

    return [PSCustomObject]@{
        TotalInFile  = $ImportData.Count
        Imported     = $ImportCount
        Skipped      = $SkipCount
        Failed       = $FailCount
    }
}

# ── MAIN ──
try {
    Write-Log 'Transport rule export/import started.'

    if (-not $SkipExchangeConnect) {
        Connect-ToExchange
    }

    if ($ImportPath) {
        Write-Log "Import mode: $ImportPath"
        $ImportResult = Import-TransportRules -InputPath $ImportPath
        if ($ImportResult) {
            Write-Log 'Import Summary'
            Write-Log "In file: $($ImportResult.TotalInFile) | Imported: $($ImportResult.Imported) | Skipped: $($ImportResult.Skipped) | Failed: $($ImportResult.Failed)"
        }
    } else {
        Write-Log "Export mode -> $xmlPath"
        $ExportResult = Export-TransportRules -ExportFile $xmlPath

        if ($ExportResult) {
            Write-Log 'Export Summary'
            Write-Log "Total Rules: $($ExportResult.TotalRules) | Enabled: $($ExportResult.EnabledRules) | Disabled: $($ExportResult.DisabledRules)"
            Write-Log "Saved to: $xmlPath"

            $Html = @"
<!DOCTYPE html>
<html>
<head><title>Transport Rule Export Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 5px 8px; border-bottom: 1px solid #ddd; }
</style></head>
<body>
<h1>Transport Rule Export Report</h1>
<div class='summary'>
    <strong>Total:</strong> $($ExportResult.TotalRules) |
    <strong>Enabled:</strong> $($ExportResult.EnabledRules) |
    <strong>Disabled:</strong> $($ExportResult.DisabledRules) |
    <strong>Export:</strong> $xmlPath
</div>
<table>
<tr><th>Name</th><th>State</th><th>Priority</th><th>Mode</th><th>Created</th></tr>
"@
            foreach ($Rule in $ExportResult.Rules) {
                $Html += "<tr><td>$($Rule.Name)</td><td>$($Rule.State)</td><td>$($Rule.Priority)</td><td>$($Rule.Mode)</td><td>$($Rule.WhenCreated)</td></tr>"
            }
            $Html += "</table></body></html>"
            $Html | Out-File -LiteralPath $htmlPath -Encoding UTF8 -WhatIf:$false
            Write-Log "Report written: $htmlPath"
        }
    }
}
catch {
    Write-Log "Transport rule transfer failed: $_" 'ERROR'
    throw
}
