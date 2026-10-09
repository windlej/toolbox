param(
    [Parameter(Mandatory = $false)]
    [int]$InactiveDays = 90,

    [Parameter(Mandatory = $false)]
    [string[]]$UserTypes = @("Member", "Guest"),

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\StaleUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeNeverLoggedIn,

    [Parameter(Mandatory = $false)]
    [switch]$DisableUsers,

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGraphConnect
)

$Results = [System.Collections.Generic.List[PSObject]]::new()

function Connect-ToGraph {
    $scopes = @(
        'User.Read.All',
        'AuditLog.Read.All',
        'Directory.Read.All'
    )
    if ($DisableUsers) { $scopes += 'User.ReadWrite.All' }

    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Host "Connected to Graph" -ForegroundColor Green
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

    $CutoffDate = (Get-Date).AddDays(-$DaysInactive).ToString('yyyy-MM-ddTHH:mm:ssZ')

    $AllUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, UserType,
        AccountEnabled, CreatedDateTime, SignInActivity, Mail, MailNickname,
        Department, JobTitle, LastPasswordChangeDateTime -ErrorAction Stop

    $Filtered = $AllUsers | Where-Object { $_.UserType -in $IncludeTypes }

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
                UserPrincipalName        = $User.UserPrincipalName
                DisplayName              = $User.DisplayName
                UserType                 = $User.UserType
                AccountEnabled           = $User.AccountEnabled
                Department               = $User.Department
                JobTitle                 = $User.JobTitle
                Mail                     = $User.Mail
                CreatedDateTime          = $User.CreatedDateTime
                LastSignInDateTime       = $LastSignIn
                DaysSinceLastSignIn      = $DaysSinceSignIn
                LastPasswordChangeDateTime = $User.LastPasswordChangeDateTime
            })
        }
    }

    return $StaleList
}

# ── MAIN ──

Write-Host "=== Stale User Detection ===" -ForegroundColor Cyan
Write-Host "Inactive threshold: $InactiveDays days" -ForegroundColor White
Write-Host "User types: $($UserTypes -join ', ')" -ForegroundColor White

if (-not $SkipGraphConnect) {
    Connect-ToGraph
}

Write-Host "Retrieving users..." -ForegroundColor Yellow
$StaleUsers = Get-StaleUsers -DaysInactive $InactiveDays -IncludeTypes $UserTypes -IncludeNeverLogged $IncludeNeverLoggedIn
Write-Host "Found $($StaleUsers.Count) stale users" -ForegroundColor Yellow

$ActionCount = 0
foreach ($User in $StaleUsers) {
    if ($DisableUsers -and $User.AccountEnabled) {
        $ActionCount++
        if ($WhatIf) {
            Write-Host "[WhatIf] Would disable: $($User.UserPrincipalName)" -ForegroundColor Yellow
            $User | Add-Member -NotePropertyName "Action" -NotePropertyValue "WhatIf-Disable"
        } else {
            try {
                Update-MgUser -UserId $User.UserPrincipalName -AccountEnabled:$false -ErrorAction Stop
                Write-Host "Disabled: $($User.UserPrincipalName)" -ForegroundColor Red
                $User | Add-Member -NotePropertyName "Action" -NotePropertyValue "Disabled"
            } catch {
                Write-Warning "Failed to disable $($User.UserPrincipalName) : $_"
                $User | Add-Member -NotePropertyName "Action" -NotePropertyValue "Failed"
            }
        }
    } else {
        $User | Add-Member -NotePropertyName "Action" -NotePropertyValue "Reported"
    }
}

$TotalStale = $StaleUsers.Count
$GuestCount = ($StaleUsers | Where-Object { $_.UserType -eq "Guest" }).Count
$MemberCount = ($StaleUsers | Where-Object { $_.UserType -eq "Member" }).Count
$DisabledAction = ($StaleUsers | Where-Object { $_.Action -eq "Disabled" }).Count
$NeverLogged = ($StaleUsers | Where-Object { -not $_.LastSignInDateTime }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Stale Users: $TotalStale" -ForegroundColor White
Write-Host "  Members: $MemberCount" -ForegroundColor Yellow
Write-Host "  Guests: $GuestCount" -ForegroundColor Yellow
Write-Host "  Never Logged In: $NeverLogged" -ForegroundColor Gray
if ($DisableUsers) { Write-Host "  Disabled: $DisabledAction" -ForegroundColor Red }

$HtmlRows = $StaleUsers | Sort-Object DaysSinceLastSignIn -Descending | ForEach-Object {
    $RowClass = if ($_.Action -eq "Disabled") { "danger" }
    elseif (-not $_.LastSignInDateTime) { "warning" }
    elseif ($_.DaysSinceLastSignIn -ge 365) { "danger" }
    elseif ($_.DaysSinceLastSignIn -ge 180) { "warning" }
    else { "" }
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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $StaleUsers | Select-Object UserPrincipalName, DisplayName, UserType, AccountEnabled,
        Department, LastSignInDateTime, DaysSinceLastSignIn, CreatedDateTime, Action |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}

if ($TotalStale -gt 0) {
    Write-Host "`nRecommendation: Review stale users above and disable or remove as appropriate." -ForegroundColor Yellow
}
