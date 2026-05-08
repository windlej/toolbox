param(
    [Parameter(Mandatory = $false, ParameterSetName = "Export")]
    [string]$ExportPath = ".\TransportRules_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml",

    [Parameter(Mandatory = $false, ParameterSetName = "Export")]
    [string]$ReportPath,

    [Parameter(Mandatory = $true, ParameterSetName = "Import")]
    [string]$ImportPath,

    [Parameter(Mandatory = $false, ParameterSetName = "Import")]
    [switch]$SkipDuplicateCheck,

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

function Export-TransportRules {
    param([string]$OutputPath)

    try {
        $Rules = Get-TransportRule -ErrorAction Stop
        if (-not $Rules) {
            Write-Host "No transport rules found to export." -ForegroundColor Yellow
            return $null
        }

        $ExportData = foreach ($Rule in $Rules) {
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
        }

        $ExportData | Export-Clixml -Path $OutputPath -Depth 5 -Force
        Write-Host "Exported $($ExportData.Count) transport rules to $OutputPath" -ForegroundColor Green

        $TotalRules = $ExportData.Count
        $EnabledRules = ($ExportData | Where-Object { $_.State -eq "Enabled" }).Count
        $DisabledRules = ($ExportData | Where-Object { $_.State -eq "Disabled" }).Count

        return [PSCustomObject]@{
            TotalRules    = $ExportData.Count
            EnabledRules  = $EnabledRules
            DisabledRules = $DisabledRules
            ExportPath    = $OutputPath
            Rules         = $ExportData
        }
    } catch {
        Write-Error "Export failed: $_"
        return $null
    }
}

function Import-TransportRules {
    param([string]$InputPath)

    if (-not (Test-Path $InputPath)) {
        Write-Error "File not found: $InputPath"
        return $null
    }

    try {
        $ImportData = Import-Clixml -Path $InputPath -ErrorAction Stop
    } catch {
        Write-Error "Failed to import XML: $_"
        return $null
    }

    $ExistingRules = Get-TransportRule -ErrorAction SilentlyContinue
    $ExistingNames = $ExistingRules | Select-Object -ExpandProperty Name

    $ImportCount = 0
    $SkipCount = 0
    $FailCount = 0

    foreach ($RuleData in $ImportData) {
        if (-not $SkipDuplicateCheck -and $ExistingNames -contains $RuleData.Name) {
            Write-Host "  Skipping duplicate: $($RuleData.Name)" -ForegroundColor Yellow
            $SkipCount++
            continue
        }

        if ($WhatIf) {
            Write-Host "[WhatIf] Would import rule: $($RuleData.Name)" -ForegroundColor Yellow
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

            New-TransportRule @NewRuleParams
            Write-Host "  Imported: $($RuleData.Name)" -ForegroundColor Green
            $ImportCount++
        } catch {
            Write-Warning "  Failed to import '$($RuleData.Name)': $_"
            $FailCount++
        }
    }

    return [PSCustomObject]@{
        TotalInFile  = $ImportData.Count
        Imported     = $ImportCount
        Skipped      = $SkipCount
        Failed       = $FailCount
        WhatIf       = $WhatIf
    }
}

# ── MAIN ──
Write-Host "=== Transport Rule Export/Import Tool ===" -ForegroundColor Cyan

if (-not $SkipExchangeConnect) {
    Connect-ToExchange
}

if ($ImportPath) {
    Write-Host "Import mode: $ImportPath" -ForegroundColor Yellow
    $ImportResult = Import-TransportRules -InputPath $ImportPath
    if ($ImportResult) {
        Write-Host "`n=== Import Summary ===" -ForegroundColor Cyan
        Write-Host "In file: $($ImportResult.TotalInFile) | Imported: $($ImportResult.Imported) | Skipped: $($ImportResult.Skipped) | Failed: $($ImportResult.Failed)"
    }
} else {
    Write-Host "Export mode -> $ExportPath" -ForegroundColor Yellow
    $ExportResult = Export-TransportRules -OutputPath $ExportPath

    if ($ExportResult) {
        Write-Host "`n=== Export Summary ===" -ForegroundColor Cyan
        Write-Host "Total Rules: $($ExportResult.TotalRules) | Enabled: $($ExportResult.EnabledRules) | Disabled: $($ExportResult.DisabledRules)"
        Write-Host "Saved to: $ExportPath" -ForegroundColor Green

        if ($ReportPath) {
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
    <strong>Export:</strong> $ExportPath
</div>
<table>
<tr><th>Name</th><th>State</th><th>Priority</th><th>Mode</th><th>Created</th></tr>
"@
            foreach ($Rule in $ExportResult.Rules) {
                $Html += "<tr><td>$($Rule.Name)</td><td>$($Rule.State)</td><td>$($Rule.Priority)</td><td>$($Rule.Mode)</td><td>$($Rule.WhenCreated)</td></tr>"
            }
            $Html += "</table></body></html>"
            $Html | Out-File -FilePath $ReportPath -Encoding UTF8
            Write-Host "Report: $ReportPath" -ForegroundColor Green
        }
    }
}
