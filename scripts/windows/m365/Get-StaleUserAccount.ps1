#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users

<#
.SYNOPSIS
Finds Entra ID (Azure AD) users who have not signed in recently and can optionally disable them.

.DESCRIPTION
Retrieves all users of the selected types (Member and/or Guest) with their sign-in activity and lists those
whose last sign-in is older than the inactivity threshold. Users who have never signed in are only included
when -IncludeNeverLoggedIn is set. By default the script is read-only. With -DisableUsers it sets
AccountEnabled to false on each stale account that is currently enabled; this honours -WhatIf and -Confirm.
The output is an HTML report (primary) with a summary and one row per stale user (sorted by days inactive),
plus an optional CSV of the same data.

.PARAMETER InactiveDays
Days without a sign-in after which a user is considered stale. Default 90.

.PARAMETER UserTypes
User types to include: Member, Guest or both. Default both.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the stale-user list to a CSV next to the HTML report.

.PARAMETER IncludeNeverLoggedIn
Also treat users with no recorded sign-in at all as stale.

.PARAMETER DisableUsers
Disable (block sign-in for) stale accounts that are still enabled. Use -WhatIf first.

.PARAMETER SkipGraphConnect
Skip Connect-MgGraph (use when a Graph session with suitable scopes already exists).

.EXAMPLE
.\Get-StaleUserAccount.ps1 -InactiveDays 90 -OutputPath D:\Reports

.EXAMPLE
.\Get-StaleUserAccount.ps1 -InactiveDays 120 -UserTypes Guest -DisableUsers -WhatIf -OutputPath D:\Reports -CustomerName Contoso -ExportCsv

.NOTES
Platform:     Windows (PowerShell 5.1+ with Microsoft Graph PowerShell SDK)
Permissions:  Graph scopes User.Read.All, AuditLog.Read.All, Directory.Read.All; User.ReadWrite.All when -DisableUsers is used (User Administrator or higher)
When to use:  Quarterly access review, license cleanup, or before an offboarding sweep.
Safety:       Changes data (supports -WhatIf)
Version:      1.1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [int]$InactiveDays = 90,

    [ValidateSet('Member', 'Guest')]
    [string[]]$UserTypes = @('Member', 'Guest'),

    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCsv,

    [switch]$IncludeNeverLoggedIn,

    [switch]$DisableUsers,

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
$ReportPath     = Join-Path $outDir "Get-StaleUserAccount_$stamp.html"
$CsvPath        = Join-Path $outDir "Get-StaleUserAccount_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-StaleUserAccount_$stamp.log"

function Connect-ToGraph {
    $scopes = @(
        'User.Read.All',
        'AuditLog.Read.All',
        'Directory.Read.All'
    )
    if ($DisableUsers) { $scopes += 'User.ReadWrite.All' }

    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Log 'Connected to Graph'
    } catch {
        throw "Graph auth failed: $_"
    }
}

function Get-StaleUsers {
    param(
        [int]$DaysInactive,
        [string[]]$IncludeTypes,
        [bool]$IncludeNeverLogged
    )

    $AllUsers = @(Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, UserType,
        AccountEnabled, CreatedDateTime, SignInActivity, Mail, MailNickname,
        Department, JobTitle, LastPasswordChangeDateTime -ErrorAction Stop)

    $Filtered = @($AllUsers | Where-Object { $_.UserType -in $IncludeTypes })

    $StaleList = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($User in $Filtered) {
        $LastSignIn = $User.SignInActivity.LastSignInDateTime
        $DaysSinceSignIn = if ($LastSignIn) {
            [math]::Round(((Get-Date) - $LastSignIn).TotalDays)
        } else { $null }

        $IsStale = $false
        if ($LastSignIn -and $DaysSinceSignIn -ge $DaysInactive) {
            $IsStale = $true
        } elseif (-not $LastSignIn -and $IncludeNeverLogged) {
            $IsStale = $true
        }

        if ($IsStale) {
            $StaleList.Add([PSCustomObject]@{
                UserPrincipalName          = $User.UserPrincipalName
                DisplayName                = $User.DisplayName
                UserType                   = $User.UserType
                AccountEnabled             = $User.AccountEnabled
                Department                 = $User.Department
                JobTitle                   = $User.JobTitle
                Mail                       = $User.Mail
                CreatedDateTime            = $User.CreatedDateTime
                LastSignInDateTime         = $LastSignIn
                DaysSinceLastSignIn        = $DaysSinceSignIn
                LastPasswordChangeDateTime = $User.LastPasswordChangeDateTime
            })
        }
    }

    return $StaleList
}

# -- MAIN --

try {
    Write-Log '=== Stale User Detection ==='
    Write-Log "Inactive threshold: $InactiveDays days"
    Write-Log "User types: $($UserTypes -join ', ')"
    if ($DisableUsers) {
        Write-Log '-DisableUsers specified: stale enabled accounts will be disabled (honours -WhatIf).' 'WARN'
    }

    if (-not $SkipGraphConnect) {
        Connect-ToGraph
    }

    Write-Log 'Retrieving users...'
    $StaleUsers = @(Get-StaleUsers -DaysInactive $InactiveDays -IncludeTypes $UserTypes -IncludeNeverLogged ([bool]$IncludeNeverLoggedIn))
    Write-Log "Found $($StaleUsers.Count) stale users"

    foreach ($User in $StaleUsers) {
        if ($DisableUsers -and $User.AccountEnabled) {
            if ($PSCmdlet.ShouldProcess($User.UserPrincipalName, 'Disable stale user account')) {
                try {
                    Update-MgUser -UserId $User.UserPrincipalName -AccountEnabled:$false -ErrorAction Stop
                    Write-Log "Disabled: $($User.UserPrincipalName)"
                    $User | Add-Member -NotePropertyName 'Action' -NotePropertyValue 'Disabled'
                } catch {
                    Write-Log "Failed to disable $($User.UserPrincipalName) : $_" 'WARN'
                    $User | Add-Member -NotePropertyName 'Action' -NotePropertyValue 'Failed'
                }
            } else {
                $User | Add-Member -NotePropertyName 'Action' -NotePropertyValue 'WhatIf-Disable'
            }
        } else {
            $User | Add-Member -NotePropertyName 'Action' -NotePropertyValue 'Reported'
        }
    }

    $TotalStale     = $StaleUsers.Count
    $GuestCount     = @($StaleUsers | Where-Object { $_.UserType -eq 'Guest' }).Count
    $MemberCount    = @($StaleUsers | Where-Object { $_.UserType -eq 'Member' }).Count
    $DisabledAction = @($StaleUsers | Where-Object { $_.Action -eq 'Disabled' }).Count
    $NeverLogged    = @($StaleUsers | Where-Object { -not $_.LastSignInDateTime }).Count

    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Stale Users: $TotalStale" -ForegroundColor White
    Write-Host "  Members: $MemberCount" -ForegroundColor Yellow
    Write-Host "  Guests: $GuestCount" -ForegroundColor Yellow
    Write-Host "  Never Logged In: $NeverLogged" -ForegroundColor Gray
    if ($DisableUsers) { Write-Host "  Disabled: $DisabledAction" -ForegroundColor Red }

    $HtmlRows = $StaleUsers | Sort-Object DaysSinceLastSignIn -Descending | ForEach-Object {
        $RowClass = if ($_.Action -eq 'Disabled') { 'danger' }
        elseif (-not $_.LastSignInDateTime) { 'warning' }
        elseif ($_.DaysSinceLastSignIn -ge 365) { 'danger' }
        elseif ($_.DaysSinceLastSignIn -ge 180) { 'warning' }
        else { '' }
        "<tr class='$RowClass'>
        <td>$($_.UserPrincipalName)</td>
        <td>$($_.DisplayName)</td>
        <td>$($_.UserType)</td>
        <td>$($_.LastSignInDateTime)</td>
        <td>$($_.DaysSinceLastSignIn)</td>
        <td>$($_.AccountEnabled)</td>
        <td>$($_.Department)</td>
        <td>$($_.CreatedDateTime)</td>
        <td>$($_.Action)</td>
    </tr>"
    }

    $Html = @"
<!DOCTYPE html>
<html>
<head><title>Stale User Detection Report</title>
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
<h1>Stale User Detection Report</h1>
<div class='summary'>
    <strong>Threshold:</strong> $InactiveDays days inactive |
    <strong>Total Stale:</strong> $TotalStale |
    <strong>Members:</strong> $MemberCount |
    <strong>Guests:</strong> $GuestCount |
    <strong>Disabled:</strong> $DisabledAction |
    <strong>Never Logged In:</strong> $NeverLogged
</div>
<table>
<tr><th>UPN</th><th>Name</th><th>Type</th><th>Last Sign-In</th><th>Days Inactive</th><th>Enabled</th><th>Department</th><th>Created</th><th>Action</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

    $Html | Out-File -LiteralPath $ReportPath -Encoding UTF8
    Write-Log "Report: $ReportPath"

    if ($ExportCsv) {
        $StaleUsers | Select-Object UserPrincipalName, DisplayName, UserType, AccountEnabled,
            Department, LastSignInDateTime, DaysSinceLastSignIn, CreatedDateTime, Action |
            Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Log "CSV: $CsvPath"
    }

    if ($TotalStale -gt 0) {
        Write-Log 'Recommendation: Review stale users above and disable or remove as appropriate.'
    }
}
catch {
    Write-Log "Stale user report failed: $_" 'ERROR'
    throw
}
