#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users

<#
.SYNOPSIS
Audits Entra ID (Azure AD) guest accounts and optionally blocks or removes stale ones.

.DESCRIPTION
Retrieves every guest user (userType eq 'Guest') with sign-in activity and group membership, and flags guests whose last sign-in is older than the stale threshold (or who never signed in).
By default the script is read-only. With -BlockSignInForStale it disables stale guest accounts; with
-RemoveStaleGuests it deletes them (removal takes precedence when both are given). Both actions honour
-WhatIf and -Confirm. Output is an HTML report (primary) with a summary and one row per guest, plus an
optional CSV of the same data.

.PARAMETER StaleGuestDays
Number of days without a sign-in after which a guest is considered stale. Default 90.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the guest data to a CSV next to the HTML report.

.PARAMETER RemoveStaleGuests
Delete stale guest accounts. Destructive; use -WhatIf first.

.PARAMETER BlockSignInForStale
Disable sign-in (AccountEnabled = false) for stale guest accounts. Ignored for a guest when -RemoveStaleGuests is also set.

.PARAMETER SkipGraphConnect
Skip Connect-MgGraph (use when a Graph session with suitable scopes already exists).

.EXAMPLE
.\Get-GuestAccountReport.ps1 -OutputPath D:\Reports -StaleGuestDays 120 -ExportCsv

.EXAMPLE
.\Get-GuestAccountReport.ps1 -OutputPath D:\Reports -CustomerName Contoso -BlockSignInForStale -WhatIf

.NOTES
Platform:     Windows (PowerShell 5.1+ with Microsoft Graph PowerShell SDK)
Permissions:  Graph scopes User.Read.All, AuditLog.Read.All, Directory.Read.All; User.ReadWrite.All when -RemoveStaleGuests or -BlockSignInForStale is used (Global Administrator or User Administrator)
When to use:  Quarterly external-access review, or before cleaning up guests left behind by finished projects.
Safety:       Destructive (supports -WhatIf)
Version:      1.2
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [int]$StaleGuestDays = 90,

    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCsv,

    [switch]$RemoveStaleGuests,

    [switch]$BlockSignInForStale,

    [switch]$SkipGraphConnect
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

$stamp          = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir         = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$ReportPath     = Join-Path $outDir "Get-GuestAccountReport_$stamp.html"
$CsvPath        = Join-Path $outDir "Get-GuestAccountReport_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-GuestAccountReport_$stamp.log"

$Results = [System.Collections.Generic.List[PSObject]]::new()

function Connect-ToGraph {
    $scopes = @(
        'User.Read.All',
        'AuditLog.Read.All',
        'Directory.Read.All'
    )
    if ($RemoveStaleGuests -or $BlockSignInForStale) { $scopes += 'User.ReadWrite.All' }

    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Log 'Connected to Graph'
    } catch {
        throw "Graph auth failed: $_"
    }
}

function Get-GuestGroupMembership {
    param([string]$UserId)

    try {
        $Groups = @(Get-MgUserMemberOf -UserId $UserId -All -ErrorAction Stop)
        return (@($Groups | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' } |
            ForEach-Object { $_.AdditionalProperties.displayName }) -join '; ')
    } catch {
        return 'Error retrieving'
    }
}

function Get-GuestDetail {
    param(
        [PSObject]$Guest,
        [int]$StaleDays
    )

    $LastSignIn = $Guest.SignInActivity.LastSignInDateTime
    $DaysSinceSignIn = if ($LastSignIn) {
        [math]::Round(((Get-Date) - $LastSignIn).TotalDays)
    } else { $null }

    $IsStale = (-not $LastSignIn) -or ($DaysSinceSignIn -ge $StaleDays)

    $GroupMembership = Get-GuestGroupMembership -UserId $Guest.Id

    return [PSCustomObject]@{
        UserPrincipalName  = $Guest.UserPrincipalName
        DisplayName        = $Guest.DisplayName
        Mail               = $Guest.Mail
        AccountEnabled     = $Guest.AccountEnabled
        CreatedDateTime    = $Guest.CreatedDateTime
        LastSignInDateTime = $LastSignIn
        DaysSinceSignIn    = $DaysSinceSignIn
        GroupMembership    = $GroupMembership
        Department         = $Guest.Department
        IsStale            = $IsStale
        Action             = 'None'
    }
}

# -- MAIN --

try {
    Write-Log '=== Guest Account Audit & Cleanup ==='
    if ($RemoveStaleGuests) {
        Write-Log '-RemoveStaleGuests specified: stale guest accounts will be DELETED (honours -WhatIf).' 'WARN'
    }

    if (-not $SkipGraphConnect) {
        Connect-ToGraph
    }

    Write-Log 'Retrieving guest users...'
    $Guests = @(Get-MgUser -All -Filter "userType eq 'Guest'" -Property Id, DisplayName,
        UserPrincipalName, Mail, AccountEnabled, CreatedDateTime, SignInActivity,
        Department -ErrorAction Stop)
    Write-Log "Found $($Guests.Count) guest accounts"

    Write-Log 'Analyzing guests...'
    foreach ($Guest in $Guests) {
        $Results.Add((Get-GuestDetail -Guest $Guest -StaleDays $StaleGuestDays))
    }

    if ($RemoveStaleGuests -or $BlockSignInForStale) {
        Write-Log 'Applying actions...'
        foreach ($Entry in @($Results | Where-Object { $_.IsStale })) {
            if ($RemoveStaleGuests) {
                if ($PSCmdlet.ShouldProcess($Entry.UserPrincipalName, 'Remove stale guest account')) {
                    try {
                        Remove-MgUser -UserId $Entry.UserPrincipalName -ErrorAction Stop
                        $Entry.Action = 'Removed'
                        Write-Log "Removed guest: $($Entry.UserPrincipalName)"
                    } catch {
                        Write-Log "Failed to remove $($Entry.UserPrincipalName) : $_" 'WARN'
                        $Entry.Action = 'RemoveFailed'
                    }
                } else {
                    $Entry.Action = 'WhatIf-Remove'
                }
            } elseif ($BlockSignInForStale) {
                if ($PSCmdlet.ShouldProcess($Entry.UserPrincipalName, 'Block sign-in for stale guest account')) {
                    try {
                        Update-MgUser -UserId $Entry.UserPrincipalName -AccountEnabled:$false -ErrorAction Stop
                        $Entry.Action = 'Blocked'
                        Write-Log "Blocked guest: $($Entry.UserPrincipalName)"
                    } catch {
                        Write-Log "Failed to block $($Entry.UserPrincipalName) : $_" 'WARN'
                        $Entry.Action = 'BlockFailed'
                    }
                } else {
                    $Entry.Action = 'WhatIf-Block'
                }
            }
        }
    }

    $TotalGuests  = $Results.Count
    $StaleCount   = @($Results | Where-Object { $_.IsStale }).Count
    $EnabledCount = @($Results | Where-Object { $_.AccountEnabled }).Count
    $NeverSignedIn = @($Results | Where-Object { -not $_.LastSignInDateTime }).Count
    $RemovedCount = @($Results | Where-Object { $_.Action -eq 'Removed' }).Count
    $BlockedCount = @($Results | Where-Object { $_.Action -eq 'Blocked' }).Count

    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total Guests: $TotalGuests" -ForegroundColor White
    Write-Host "  Enabled: $EnabledCount" -ForegroundColor Green
    Write-Host "  Stale (>=$StaleGuestDays days): $StaleCount" -ForegroundColor Yellow
    Write-Host "  Never Signed In: $NeverSignedIn" -ForegroundColor Yellow
    Write-Host "  Removed: $RemovedCount" -ForegroundColor Red
    Write-Host "  Blocked: $BlockedCount" -ForegroundColor Red

    $HtmlRows = $Results | Sort-Object -Property @{ Expression = 'IsStale'; Descending = $true }, 'LastSignInDateTime' | ForEach-Object {
        $RowClass = if ($_.Action -eq 'Removed' -or $_.Action -eq 'RemoveFailed') { 'danger' }
        elseif ($_.IsStale) { 'warning' }
        else { '' }
        "<tr class='$RowClass'>
        <td>$($_.UserPrincipalName)</td>
        <td>$($_.DisplayName)</td>
        <td>$($_.Mail)</td>
        <td>$($_.AccountEnabled)</td>
        <td>$($_.CreatedDateTime)</td>
        <td>$($_.LastSignInDateTime)</td>
        <td>$($_.DaysSinceSignIn)</td>
        <td>$($_.GroupMembership)</td>
        <td>$($_.Action)</td>
    </tr>"
    }

    $Html = @"
<!DOCTYPE html>
<html>
<head><title>Guest Account Audit Report</title>
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
<h1>Guest Account Audit & Cleanup Report</h1>
<div class='summary'>
    <strong>Total Guests:</strong> $TotalGuests |
    <strong>Enabled:</strong> $EnabledCount |
    <strong>Stale (>=$StaleGuestDays days):</strong> <span style='color:orange;'>$StaleCount</span> |
    <strong>Removed:</strong> <span style='color:red;'>$RemovedCount</span> |
    <strong>Blocked:</strong> <span style='color:red;'>$BlockedCount</span> |
    <strong>Threshold:</strong> $StaleGuestDays days
</div>
<table>
<tr><th>UPN</th><th>Name</th><th>Mail</th><th>Enabled</th><th>Created</th><th>Last Sign-In</th><th>Days</th><th>Groups</th><th>Action</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

    $Html | Out-File -LiteralPath $ReportPath -Encoding UTF8
    Write-Log "Report: $ReportPath"

    if ($ExportCsv) {
        $Results | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Log "CSV: $CsvPath"
    }
}
catch {
    Write-Log "Guest account report failed: $_" 'ERROR'
    throw
}
