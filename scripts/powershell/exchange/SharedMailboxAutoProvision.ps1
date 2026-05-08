param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\SharedMailboxProvision_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [switch]$AddUsersAsMembers,

    [Parameter(Mandatory = $false)]
    [switch]$GrantFullAccess,

    [Parameter(Mandatory = $false)]
    [switch]$GrantSendAs,

    [Parameter(Mandatory = $false)]
    [switch]$HideFromGAL,

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

function New-SharedMailbox {
    param([PSObject]$CsvRow)

    $Name = $CsvRow.DisplayName
    $Alias = $CsvRow.Alias
    $UPN = "$Alias@$($CsvRow.Domain)"
    $DisplayName = $Name

    if ($WhatIf) {
        Write-Host "[WhatIf] Would create shared mailbox: $UPN ($DisplayName)" -ForegroundColor Yellow
        Write-Result -Mailbox $UPN -Action "Create" -Status "WhatIf" -Detail ""
        return $UPN
    }

    try {
        $MailboxParams = @{
            Name                  = $Name
            Alias                 = $Alias
            DisplayName           = $DisplayName
            Shared                = $true
            PrimarySmtpAddress    = $UPN
        }

        if ($CsvRow.Users) { $MailboxParams.GrantSendOnBehalfTo = $CsvRow.Users }
        if ($CsvRow.Department) { $MailboxParams.Office = $CsvRow.Department }

        $Mailbox = New-Mailbox @MailboxParams -ErrorAction Stop

        if ($HideFromGAL) {
            Set-Mailbox -Identity $UPN -HiddenFromAddressListsEnabled $true -ErrorAction SilentlyContinue
        }

        Write-Result -Mailbox $UPN -Action "Create" -Status "Success" -Detail ""
        Write-Host "  Created shared mailbox: $UPN" -ForegroundColor Green
        return $UPN
    } catch {
        Write-Result -Mailbox $UPN -Action "Create" -Status "Failed" -Detail $_.Exception.Message
        Write-Warning "  Failed to create $UPN : $_"
        return $null
    }
}

function Add-UserToSharedMailbox {
    param(
        [string]$Mailbox,
        [string[]]$Users
    )

    if (-not $Users -or $Users.Count -eq 0) { return }

    foreach ($User in $Users) {
        if ($GrantFullAccess) {
            if ($WhatIf) {
                Write-Result -Mailbox $Mailbox -Action "GrantFullAccess" -Status "WhatIf" -Detail $User
                continue
            }
            try {
                Add-MailboxPermission -Identity $Mailbox -User $User -AccessRights FullAccess -AutoMapping $true -ErrorAction Stop
                Write-Result -Mailbox $Mailbox -Action "GrantFullAccess" -Status "Success" -Detail $User
                Write-Host "    FullAccess granted to $User" -ForegroundColor Green
            } catch {
                Write-Result -Mailbox $Mailbox -Action "GrantFullAccess" -Status "Failed" -Detail "$User : $_"
            }
        }

        if ($GrantSendAs) {
            if ($WhatIf) {
                Write-Result -Mailbox $Mailbox -Action "GrantSendAs" -Status "WhatIf" -Detail $User
                continue
            }
            try {
                Add-RecipientPermission -Identity $Mailbox -Trustee $User -AccessRights SendAs -Confirm:$false -ErrorAction Stop
                Write-Result -Mailbox $Mailbox -Action "GrantSendAs" -Status "Success" -Detail $User
                Write-Host "    SendAs granted to $User" -ForegroundColor Green
            } catch {
                Write-Result -Mailbox $Mailbox -Action "GrantSendAs" -Status "Failed" -Detail "$User : $_"
            }
        }

        if ($AddUsersAsMembers) {
            try {
                Add-DistributionGroupMember -Identity $Mailbox -Member $User -ErrorAction SilentlyContinue
            } catch { }
        }
    }
}

function Write-Result {
    param($Mailbox, $Action, $Status, $Detail)
    $Results.Add([PSCustomObject]@{
        UserPrincipalName = $Mailbox
        Action            = $Action
        Status            = $Status
        Detail            = $Detail
        Timestamp         = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    })
}

# ── MAIN ──
Write-Host "=== Shared Mailbox Auto-Provision ===" -ForegroundColor Cyan

if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV not found: $CsvPath"
    return
}

$Mailboxes = Import-Csv $CsvPath
Write-Host "Provisioning $($Mailboxes.Count) shared mailboxes from: $CsvPath" -ForegroundColor Yellow

Write-Host "CSV columns expected: DisplayName, Alias, Domain, Users, Department" -ForegroundColor Gray
Write-Host "Users can be semicolon-separated for multiple delegates" -ForegroundColor Gray

if (-not $SkipExchangeConnect) {
    Connect-ToExchange
}

foreach ($Entry in $Mailboxes) {
    Write-Host "`nProcessing: $($Entry.DisplayName)" -ForegroundColor Yellow

    $UPN = New-SharedMailbox -CsvRow $Entry
    if (-not $UPN) { continue }

    if ($Entry.Users) {
        $UserList = $Entry.Users -split ';' | ForEach-Object { $_.Trim() }
        Add-UserToSharedMailbox -Mailbox $UPN -Users $UserList
    }
}

$SuccessCount = ($Results | Where-Object { $_.Status -eq "Success" }).Count
$FailCount = ($Results | Where-Object { $_.Status -eq "Failed" }).Count
$WhatIfCount = ($Results | Where-Object { $_.Status -eq "WhatIf" }).Count

$HtmlRows = $Results | ForEach-Object {
    $RowClass = switch ($_.Status) {
        "Success" { "" }
        "Failed" { "danger" }
        "WhatIf" { "warning" }
        default { "" }
    }
    "<tr class='$RowClass'>
        <td>$($_.UserPrincipalName)</td>
        <td>$($_.Action)</td>
        <td>$($_.Status)</td>
        <td>$($_.Detail)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Shared Mailbox Provisioning Report</title>
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
<h1>Shared Mailbox Provisioning Report</h1>
<div class='summary'>
    <strong>CSV:</strong> $CsvPath |
    <strong>Total:</strong> $($Mailboxes.Count) |
    <strong>Success:</strong> $SuccessCount |
    <strong>Failed:</strong> $FailCount |
    <strong>WhatIf:</strong> $WhatIfCount
</div>
<table>
<tr><th>Mailbox</th><th>Action</th><th>Status</th><th>Detail</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green
Write-Host "Success: $SuccessCount | Failed: $FailCount | WhatIf: $WhatIfCount"
