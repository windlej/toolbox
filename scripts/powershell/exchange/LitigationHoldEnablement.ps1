param(
    [Parameter(Mandatory = $true)]
    [string[]]$UserPrincipalNames,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\LitigationHold_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvExportPath,

    [Parameter(Mandatory = $false)]
    [int]$HoldDurationDays = 365,

    [Parameter(Mandatory = $false)]
    [switch]$EnableHold,

    [Parameter(Mandatory = $false)]
    [switch]$DisableHold,

    [Parameter(Mandatory = $false)]
    [switch]$ReportOnly,

    [Parameter(Mandatory = $false)]
    [string]$HoldNote = "Litigation hold enabled for legal compliance.",

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

function Get-MailboxHoldStatus {
    param([string]$Identity)

    try {
        $Mailbox = Get-Mailbox -Identity $Identity -ErrorAction SilentlyContinue
        if (-not $Mailbox) {
            return [PSCustomObject]@{
                UserPrincipalName = $Identity
                DisplayName       = "Not Found"
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

    $Action = if ($Enable) { "EnableHold" } else { "DisableHold" }

    if ($WhatIf) {
        Write-Host "[WhatIf] Would $Action for $Identity" -ForegroundColor Yellow
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
        return if ($Enable) { "Enabled" } else { "Disabled" }
    } catch {
        Write-Warning "Failed to set hold on $Identity : $_"
        return "Failed"
    }
}

# ── MAIN ──
Write-Host "=== Litigation Hold Enablement ===" -ForegroundColor Cyan
$(if ($EnableHold) { Write-Host "Action: ENABLE hold ($HoldDurationDays days)" -ForegroundColor Yellow })
$(if ($DisableHold) { Write-Host "Action: DISABLE hold" -ForegroundColor Yellow })
$(if ($ReportOnly) { Write-Host "Action: REPORT only (no changes)" -ForegroundColor Cyan })

if (-not $SkipExchangeConnect) {
    Connect-ToExchange
}

if ($CsvPath) {
    $CsvData = Import-Csv $CsvPath
    $UserPrincipalNames = $CsvData.UserPrincipalName
}

Write-Host "Processing $($UserPrincipalNames.Count) mailboxes..." -ForegroundColor Yellow

foreach ($UPN in $UserPrincipalNames) {
    Write-Host "  $UPN" -ForegroundColor Gray

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

$EnabledCount = ($Results | Where-Object { $_.Action -eq "Enabled" }).Count
$DisabledCount = ($Results | Where-Object { $_.Action -eq "Disabled" }).Count
$AlreadyOn = ($Results | Where-Object { $_.Action -eq "NoChange" -and $_.CurrentHoldEnabled }).Count
$AlreadyOff = ($Results | Where-Object { $_.Action -eq "NoChange" -and -not $_.CurrentHoldEnabled }).Count
$FailedCount = ($Results | Where-Object { $_.Action -eq "Failed" }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Enabled: $EnabledCount | Disabled: $DisabledCount | Already On: $AlreadyOn | Already Off: $AlreadyOff | Failed: $FailedCount"

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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvExportPath) {
    $Results | Export-Csv -Path $CsvExportPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvExportPath" -ForegroundColor Green
}
