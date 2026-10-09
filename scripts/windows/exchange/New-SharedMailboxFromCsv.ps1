#Requires -Version 5.1

<#
.SYNOPSIS
Creates Exchange Online shared mailboxes in bulk from a CSV and optionally grants delegate permissions.

.DESCRIPTION
Reads a CSV with the columns DisplayName, Alias, Domain, Users and Department (Users may hold several delegates
separated by ';'; Department is optional). For each row it creates a shared mailbox <Alias>@<Domain> with New-Mailbox
(delegates are also set as SendOnBehalf). Optional switches then grant each delegate FullAccess (with automapping),
SendAs, and/or add them as members of a distribution group named after the mailbox. -HideFromGAL hides the new
mailbox from address lists.

Nothing is changed unless the script is run for real; use -WhatIf to preview every create/grant without making
changes. Output is an HTML report of every action and its status (Success / Failed / WhatIf) and a log file in the
output folder.

.PARAMETER CsvPath
Input CSV with the columns DisplayName, Alias, Domain, Users, Department.

.PARAMETER OutputPath
Folder for the report and log. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER AddUsersAsMembers
Add each delegate as a member of a distribution group with the same identity as the mailbox.

.PARAMETER GrantFullAccess
Grant each delegate FullAccess (automapping on) on the new mailbox.

.PARAMETER GrantSendAs
Grant each delegate SendAs on the new mailbox.

.PARAMETER HideFromGAL
Hide the new mailbox from the global address list.

.PARAMETER SkipExchangeConnect
Do not call Connect-ExchangeOnline; use an existing session.

.EXAMPLE
.\New-SharedMailboxFromCsv.ps1 -CsvPath D:\Input\shared-mailboxes.csv -GrantFullAccess -GrantSendAs -WhatIf -OutputPath D:\Reports

.EXAMPLE
.\New-SharedMailboxFromCsv.ps1 -CsvPath D:\Input\shared-mailboxes.csv -GrantFullAccess -HideFromGAL -CustomerName Contoso -OutputPath D:\Reports

.NOTES
Platform:     Windows (ExchangeOnlineManagement module, Exchange Online)
Permissions:  Exchange Online roles Mail Recipient Creation and Mail Recipients (New-Mailbox, Set-Mailbox, Add-MailboxPermission, Add-RecipientPermission); Distribution Groups if -AddUsersAsMembers
When to use:  Provisioning many shared mailboxes at once, for example during onboarding or a tenant migration.
Safety:       Changes data (supports -WhatIf)
Version:      1.1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [string]$OutputPath,
    [string]$CustomerName,
    [switch]$AddUsersAsMembers,
    [switch]$GrantFullAccess,
    [switch]$GrantSendAs,
    [switch]$HideFromGAL,
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
$htmlPath = Join-Path $outDir "New-SharedMailboxFromCsv_$stamp.html"
$script:LogFile = Join-Path $outDir "New-SharedMailboxFromCsv_$stamp.log"

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

function New-SharedMailbox {
    param([PSObject]$CsvRow)

    $Name = $CsvRow.DisplayName
    $Alias = $CsvRow.Alias
    $UPN = "$Alias@$($CsvRow.Domain)"
    $DisplayName = $Name

    if (-not $PSCmdlet.ShouldProcess($UPN, "Create shared mailbox '$DisplayName'")) {
        Write-Log "[WhatIf] Would create shared mailbox: $UPN ($DisplayName)"
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
        Write-Log "  Created shared mailbox: $UPN"
        return $UPN
    } catch {
        Write-Result -Mailbox $UPN -Action "Create" -Status "Failed" -Detail $_.Exception.Message
        Write-Log "  Failed to create $UPN : $_" 'WARN'
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
            if (-not $PSCmdlet.ShouldProcess($Mailbox, "Grant FullAccess to $User")) {
                Write-Result -Mailbox $Mailbox -Action "GrantFullAccess" -Status "WhatIf" -Detail $User
            }
            else {
                try {
                    Add-MailboxPermission -Identity $Mailbox -User $User -AccessRights FullAccess -AutoMapping $true -ErrorAction Stop | Out-Null
                    Write-Result -Mailbox $Mailbox -Action "GrantFullAccess" -Status "Success" -Detail $User
                    Write-Log "    FullAccess granted to $User"
                } catch {
                    Write-Result -Mailbox $Mailbox -Action "GrantFullAccess" -Status "Failed" -Detail "$User : $_"
                    Write-Log "    FullAccess grant failed for $User : $_" 'WARN'
                }
            }
        }

        if ($GrantSendAs) {
            if (-not $PSCmdlet.ShouldProcess($Mailbox, "Grant SendAs to $User")) {
                Write-Result -Mailbox $Mailbox -Action "GrantSendAs" -Status "WhatIf" -Detail $User
            }
            else {
                try {
                    Add-RecipientPermission -Identity $Mailbox -Trustee $User -AccessRights SendAs -Confirm:$false -ErrorAction Stop | Out-Null
                    Write-Result -Mailbox $Mailbox -Action "GrantSendAs" -Status "Success" -Detail $User
                    Write-Log "    SendAs granted to $User"
                } catch {
                    Write-Result -Mailbox $Mailbox -Action "GrantSendAs" -Status "Failed" -Detail "$User : $_"
                    Write-Log "    SendAs grant failed for $User : $_" 'WARN'
                }
            }
        }

        if ($AddUsersAsMembers) {
            if ($PSCmdlet.ShouldProcess($Mailbox, "Add $User as distribution group member")) {
                try {
                    Add-DistributionGroupMember -Identity $Mailbox -Member $User -ErrorAction SilentlyContinue
                } catch {
                    Write-Log "    Could not add $User to group $Mailbox : $_" 'WARN'
                }
            }
        }
    }
}

# ── MAIN ──
try {
    Write-Log 'Shared mailbox provisioning started.'

    if (-not (Test-Path -LiteralPath $CsvPath)) {
        throw "CSV not found: $CsvPath"
    }

    $Mailboxes = @(Import-Csv -LiteralPath $CsvPath)
    Write-Log "Provisioning $($Mailboxes.Count) shared mailboxes from: $CsvPath"
    Write-Log 'CSV columns expected: DisplayName, Alias, Domain, Users, Department (Users may be semicolon-separated)'

    if (-not $SkipExchangeConnect) {
        Connect-ToExchange
    }

    foreach ($Entry in $Mailboxes) {
        Write-Log "Processing: $($Entry.DisplayName)"

        $UPN = New-SharedMailbox -CsvRow $Entry
        if (-not $UPN) { continue }

        if ($Entry.Users) {
            $UserList = @($Entry.Users -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            Add-UserToSharedMailbox -Mailbox $UPN -Users $UserList
        }
    }

    $SuccessCount = @($Results | Where-Object { $_.Status -eq "Success" }).Count
    $FailCount = @($Results | Where-Object { $_.Status -eq "Failed" }).Count
    $WhatIfCount = @($Results | Where-Object { $_.Status -eq "WhatIf" }).Count

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

    $CsvName = Split-Path -Leaf $CsvPath

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
    <strong>CSV:</strong> $CsvName |
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

    $Html | Out-File -LiteralPath $htmlPath -Encoding UTF8 -WhatIf:$false
    Write-Log "Report written: $htmlPath"
    Write-Log "Success: $SuccessCount | Failed: $FailCount | WhatIf: $WhatIfCount"
}
catch {
    Write-Log "Shared mailbox provisioning failed: $_" 'ERROR'
    throw
}
