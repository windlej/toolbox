param(
    [Parameter(Mandatory = $false)]
    [int]$StaleGuestDays = 90,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\GuestAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$RemoveStaleGuests,

    [Parameter(Mandatory = $false)]
    [switch]$BlockSignInForStale,

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGraphConnect
)

$Results = [System.Collections.Generic.List[PSObject]]::new()
$InvitedGuestDetails = @{}

function Connect-ToGraph {
    $scopes = @(
        'User.Read.All',
        'AuditLog.Read.All',
        'Directory.Read.All'
    )
    if ($RemoveStaleGuests) { $scopes += 'User.ReadWrite.All' }

    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Host "Connected to Graph" -ForegroundColor Green
    } catch {
        throw "Graph auth failed: $_"
    }
}

function Get-InvitationDetails {
    $Invitations = Get-MgInvitation -All -ErrorAction SilentlyContinue

    $DetailMap = @{}
    foreach ($Invite in $Invitations) {
        $DetailMap[$Invite.InvitedUserEmailAddress] = @{
            InvitedByEmail = $Invite.InvitedByEmailAddress
            InviteRedeemUrl = $Invite.InviteRedeemUrl
            InviteSentDate = $Invite.InvitedDateTime
            InviteStatus = $Invite.InviteStatus
        }
    }
    return $DetailMap
}

function Get-GuestGroupMembership {
    param([string]$UserId)

    try {
        $Groups = Get-MgUserMemberOf -UserId $UserId -All -ErrorAction SilentlyContinue
        return ($Groups | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' } |
            Select-Object -ExpandProperty DisplayName) -join '; '
    } catch {
        return "Error retrieving"
    }
}

function Get-GuestDetail {
    param(
        [PSObject]$Guest,
        [hashtable]$InviteMap,
        [int]$StaleDays
    )

    $LastSignIn = $Guest.SignInActivity.LastSignInDateTime
    $DaysSinceSignIn = if ($LastSignIn) {
        [math]::Round(((Get-Date) - $LastSignIn).TotalDays)
    } else { $null }

    $IsStale = ($DaysSinceSignIn -ge $StaleDays) -or (-not $LastSignIn)

    $InviteInfo = $InviteMap[$Guest.Mail]
    if (-not $InviteInfo) {
        $InviteInfo = $InviteMap[$Guest.UserPrincipalName]
    }

    $GroupMembership = Get-GuestGroupMembership -UserId $Guest.Id

    $Action = "None"
    if ($IsStale) {
        if ($RemoveStaleGuests -or $BlockSignInForStale) {
            if ($RemoveStaleGuests -and $WhatIf) {
                $Action = "WhatIf-Remove"
            } elseif ($RemoveStaleGuests) {
                $Action = "Removed"
            } elseif ($BlockSignInForStale -and $WhatIf) {
                $Action = "WhatIf-Block"
            } elseif ($BlockSignInForStale) {
                $Action = "Blocked"
            }
        }
    }

    return [PSCustomObject]@{
        UserPrincipalName  = $Guest.UserPrincipalName
        DisplayName        = $Guest.DisplayName
        Mail               = $Guest.Mail
        AccountEnabled     = $Guest.AccountEnabled
        CreatedDateTime    = $Guest.CreatedDateTime
        LastSignInDateTime = $LastSignIn
        DaysSinceSignIn    = $DaysSinceSignIn
        InvitedBy          = $InviteInfo.InvitedByEmail
        InviteSentDate     = $InviteInfo.InviteSentDate
        InviteStatus       = $InviteInfo.InviteStatus
        GroupMembership    = $GroupMembership
        Department         = $Guest.Department
        IsStale            = $IsStale
        Action             = $Action
    }
}

# ── MAIN ──

Write-Host "=== Guest Account Audit & Cleanup ===" -ForegroundColor Cyan

if (-not $SkipGraphConnect) {
    Connect-ToGraph
}

Write-Host "Retrieving invitation details..." -ForegroundColor Yellow
$InviteMap = Get-InvitationDetails
Write-Host "Found $($InviteMap.Count) invitations" -ForegroundColor Gray

Write-Host "Retrieving guest users..." -ForegroundColor Yellow
$Guests = Get-MgUser -All -Filter "userType eq 'Guest'" -Property Id, DisplayName,
    UserPrincipalName, Mail, AccountEnabled, CreatedDateTime, SignInActivity,
    Department -ErrorAction Stop
Write-Host "Found $($Guests.Count) guest accounts" -ForegroundColor Yellow

Write-Host "Analyzing guests..." -ForegroundColor Yellow
foreach ($Guest in $Guests) {
    $Results.Add((Get-GuestDetail -Guest $Guest -InviteMap $InviteMap -StaleDays $StaleGuestDays))
}

if ($RemoveStaleGuests -or $BlockSignInForStale) {
    Write-Host "`nApplying actions..." -ForegroundColor Yellow
    foreach ($Entry in $Results | Where-Object { $_.IsStale }) {
        if ($RemoveStaleGuests -and -not $WhatIf) {
            try {
                Remove-MgUser -UserId $Entry.UserPrincipalName -ErrorAction Stop
                $Entry.Action = "Removed"
                Write-Host "Removed guest: $($Entry.UserPrincipalName)" -ForegroundColor Red
            } catch {
                Write-Warning "Failed to remove $($Entry.UserPrincipalName) : $_"
                $Entry.Action = "RemoveFailed"
            }
        } elseif ($BlockSignInForStale -and -not $WhatIf) {
            try {
                Update-MgUser -UserId $Entry.UserPrincipalName -AccountEnabled:$false -ErrorAction Stop
                $Entry.Action = "Blocked"
                Write-Host "Blocked guest: $($Entry.UserPrincipalName)" -ForegroundColor Red
            } catch {
                Write-Warning "Failed to block $($Entry.UserPrincipalName) : $_"
                $Entry.Action = "BlockFailed"
            }
        }
    }
}

$TotalGuests = $Results.Count
$StaleCount = ($Results | Where-Object { $_.IsStale }).Count
$EnabledCount = ($Results | Where-Object { $_.AccountEnabled }).Count
$NeverSignedIn = ($Results | Where-Object { -not $_.LastSignInDateTime }).Count
$RemovedCount = ($Results | Where-Object { $_.Action -eq "Removed" }).Count
$BlockedCount = ($Results | Where-Object { $_.Action -eq "Blocked" }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total Guests: $TotalGuests" -ForegroundColor White
Write-Host "  Enabled: $EnabledCount" -ForegroundColor Green
Write-Host "  Stale (>=$StaleGuestDays days): $StaleCount" -ForegroundColor Yellow
Write-Host "  Never Signed In: $NeverSignedIn" -ForegroundColor Yellow
Write-Host "  Removed: $RemovedCount" -ForegroundColor Red
Write-Host "  Blocked: $BlockedCount" -ForegroundColor Red

$HtmlRows = $Results | Sort-Object IsStale -Descending, LastSignInDateTime | ForEach-Object {
    $RowClass = if ($_.Action -eq "Removed" -or $_.Action -eq "RemoveFailed") { "danger" }
    elseif ($_.IsStale) { "warning" }
    else { "" }
    "<tr class='$RowClass'>
        <td>$($_.UserPrincipalName)</td>
        <td>$($_.DisplayName)</td>
        <td>$($_.Mail)</td>
        <td>$($_.AccountEnabled)</td>
        <td>$($_.CreatedDateTime)</td>
        <td>$($_.LastSignInDateTime)</td>
        <td>$($_.DaysSinceSignIn)</td>
        <td>$($_.InvitedBy)</td>
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
<tr><th>UPN</th><th>Name</th><th>Mail</th><th>Enabled</th><th>Created</th><th>Last Sign-In</th><th>Days</th><th>Invited By</th><th>Groups</th><th>Action</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}
