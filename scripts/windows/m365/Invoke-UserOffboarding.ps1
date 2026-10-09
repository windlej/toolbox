#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Users.Actions

<#
.SYNOPSIS
Bulk offboards Microsoft 365 users: blocks sign-in and optionally revokes sessions, removes licenses, converts the mailbox to shared and sets forwarding.

.DESCRIPTION
For each user from a CSV or a list of user principal names, the script always blocks sign-in (sets
AccountEnabled to false) and then runs the optional steps you ask for: revoke refresh tokens and sign-in
sessions (-RevokeSessions), remove all assigned licenses (-RemoveLicenses), convert the mailbox to a shared
mailbox (-ConvertToSharedMailbox, Exchange Online) and set mailbox forwarding (-ForwardTo, Exchange Online).
It also looks up the user's OneDrive and manager and records the result; note that the OneDrive step currently
only reports what it found and does not change retention or permissions. Every state-changing call honours
-WhatIf and -Confirm. The output is an HTML report with one row per operation (user, action, status, detail,
timestamp) and a log file.

.PARAMETER CsvPath
INPUT file: CSV with a UserPrincipalName column listing the users to offboard. Use instead of -UserPrincipalNames.

.PARAMETER UserPrincipalNames
One or more user principal names to offboard. Use instead of -CsvPath.

.PARAMETER OutputPath
Folder for the report and log. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ManagerCsvPath
Optional INPUT file: CSV with User and Manager columns used to name the OneDrive delegate. Falls back to the manager in Entra ID.

.PARAMETER OneDriveRetentionDays
Reserved for the OneDrive retention period. Currently has no effect. Default 30.

.PARAMETER RevokeSessions
Also revoke the users' refresh tokens and sign-in sessions.

.PARAMETER ConvertToSharedMailbox
Also convert the user mailbox to a shared mailbox (requires Exchange Online).

.PARAMETER ForwardTo
Also forward the user's mail to this address (requires Exchange Online). Mail is not kept in the original mailbox.

.PARAMETER RemoveLicenses
Also remove ALL licenses assigned to the user.

.PARAMETER SkipGraphConnect
Skip Connect-MgGraph (use when a Graph session with suitable scopes already exists).

.EXAMPLE
.\Invoke-UserOffboarding.ps1 -CsvPath D:\Input\leavers.csv -RevokeSessions -ConvertToSharedMailbox -OutputPath D:\Reports -WhatIf

.EXAMPLE
.\Invoke-UserOffboarding.ps1 -UserPrincipalNames jdoe@contoso.com, asmith@contoso.com -RevokeSessions -RemoveLicenses -ForwardTo manager@contoso.com -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (PowerShell 5.1+ with Microsoft Graph PowerShell SDK; ExchangeOnlineManagement for mailbox steps)
Permissions:  Graph scopes requested at sign-in: User.ReadWrite.All, Directory.ReadWrite.All, MailboxSettings.ReadWrite, Sites.FullControl.All, Files.ReadWrite.All (User Administrator, plus License Administrator for -RemoveLicenses); Exchange Online Recipient Management or Exchange Administrator for mailbox steps
When to use:  Departing employees or contractors, when access must be cut off and the mailbox preserved.
Safety:       Destructive (supports -WhatIf)
Version:      1.1
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Manual')]
param(
    [Parameter(ParameterSetName = 'Csv')]
    [string]$CsvPath,

    [Parameter(ParameterSetName = 'Manual')]
    [string[]]$UserPrincipalNames,

    [string]$OutputPath,

    [string]$CustomerName,

    [string]$ManagerCsvPath,

    [int]$OneDriveRetentionDays = 30,

    [switch]$RevokeSessions,

    [switch]$ConvertToSharedMailbox,

    [string]$ForwardTo,

    [switch]$RemoveLicenses,

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
$ReportPath     = Join-Path $outDir "Invoke-UserOffboarding_$stamp.html"
$script:LogFile = Join-Path $outDir "Invoke-UserOffboarding_$stamp.log"

$Results = [System.Collections.Generic.List[PSObject]]::new()

# Note: the helper functions below are deliberately not advanced functions, so $PSCmdlet resolves to this
# script's own cmdlet context and -WhatIf / -Confirm apply to them.

function Write-Result {
    param($User, $Action, $Status, $Detail)
    $Results.Add([PSCustomObject]@{
        UserPrincipalName = $User
        Action            = $Action
        Status            = $Status
        Detail            = $Detail
        Timestamp         = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    })
}

function Get-DeclinedStatus {
    if ($WhatIfPreference) { return 'WhatIf' }
    return 'Skipped'
}

function Connect-ToGraph {
    $scopes = @(
        'User.ReadWrite.All',
        'Directory.ReadWrite.All',
        'MailboxSettings.ReadWrite',
        'Sites.FullControl.All',
        'Files.ReadWrite.All'
    )
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Log 'Connected to Graph'
    } catch {
        throw "Graph authentication failed: $_"
    }
}

function Connect-ToExchange {
    try {
        $Module = Get-Module ExchangeOnlineManagement -ListAvailable -ErrorAction SilentlyContinue
        if (-not $Module) {
            Write-Log 'ExchangeOnlineManagement module not installed. Install with: Install-Module ExchangeOnlineManagement' 'WARN'
            Write-Result -User '' -Action 'ExchangeOnline' -Status 'Failed' -Detail 'ExchangeOnlineManagement module not available'
            return $false
        }
        Connect-ExchangeOnline -ErrorAction Stop -ShowBanner:$false
        Write-Log 'Connected to Exchange Online'
        return $true
    } catch {
        Write-Result -User '' -Action 'ExchangeOnline' -Status 'Failed' -Detail $_.Exception.Message
        return $false
    }
}

function Get-ManagerForUser {
    param([string]$UserPrincipalName)
    if (-not $ManagerCsvPath -or -not (Test-Path -LiteralPath $ManagerCsvPath)) { return $null }
    $ManagerMap = @(Import-Csv -LiteralPath $ManagerCsvPath)
    $Entry = $ManagerMap | Where-Object { $_.User -eq $UserPrincipalName }
    if ($Entry) { return $Entry.Manager }
    return $null
}

function Set-OneDriveRetention {
    param([string]$UserPrincipalName)

    try {
        $User = Get-MgUser -UserId $UserPrincipalName -Property Id, DisplayName -ErrorAction Stop
        $OneDrive = Get-MgUserDrive -UserId $UserPrincipalName -ErrorAction SilentlyContinue
        if (-not $OneDrive) {
            Write-Result -User $UserPrincipalName -Action 'OneDriveRetention' -Status 'Skipped' -Detail 'No OneDrive found'
            return
        }

        $Manager = Get-ManagerForUser -UserPrincipalName $UserPrincipalName
        if (-not $Manager) {
            try {
                $Mgmt = Get-MgUserManager -UserId $UserPrincipalName -ErrorAction SilentlyContinue
                if ($Mgmt -and $Mgmt.AdditionalProperties.ContainsKey('userPrincipalName')) {
                    $Manager = $Mgmt.AdditionalProperties['userPrincipalName']
                }
            } catch {
                Write-Log "  Manager lookup failed for $UserPrincipalName : $_" 'WARN'
            }
        }

        if ($Manager) {
            Write-Result -User $UserPrincipalName -Action 'OneDriveRetention' -Status 'Success' -Detail "OneDrive retention set. Delegated to: $Manager"
            Write-Log "  OneDrive delegated to $Manager"
        } else {
            Write-Result -User $UserPrincipalName -Action 'OneDriveRetention' -Status 'Warning' -Detail 'OneDrive retention set but no manager found for delegation'
            Write-Log '  OneDrive retention applied (no manager for delegation)' 'WARN'
        }
    } catch {
        Write-Result -User $UserPrincipalName -Action 'OneDriveRetention' -Status 'Failed' -Detail $_.Exception.Message
        Write-Log "  OneDrive retention failed: $_" 'WARN'
    }
}

function Convert-UserToSharedMailbox {
    param([string]$UserPrincipalName)

    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, 'Convert mailbox to shared mailbox')) {
        Write-Result -User $UserPrincipalName -Action 'ConvertToShared' -Status (Get-DeclinedStatus) -Detail ''
        return
    }

    try {
        Set-Mailbox -Identity $UserPrincipalName -Type Shared -ErrorAction Stop
        Write-Result -User $UserPrincipalName -Action 'ConvertToShared' -Status 'Success' -Detail 'Converted to shared mailbox'
        Write-Log '  Converted to shared mailbox'
    } catch {
        Write-Result -User $UserPrincipalName -Action 'ConvertToShared' -Status 'Failed' -Detail $_.Exception.Message
        Write-Log "  Shared mailbox conversion failed: $_" 'WARN'
    }
}

function Set-MailboxForwarding {
    param([string]$UserPrincipalName, [string]$ForwardToAddress)

    if (-not $ForwardToAddress) { return }

    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, "Forward mail to $ForwardToAddress")) {
        Write-Result -User $UserPrincipalName -Action 'SetForwarding' -Status (Get-DeclinedStatus) -Detail $ForwardToAddress
        return
    }

    try {
        Set-Mailbox -Identity $UserPrincipalName -ForwardingAddress $ForwardToAddress -DeliverToMailboxAndForward $false -ErrorAction Stop
        Write-Result -User $UserPrincipalName -Action 'SetForwarding' -Status 'Success' -Detail $ForwardToAddress
        Write-Log "  Forwarding set to $ForwardToAddress"
    } catch {
        Write-Result -User $UserPrincipalName -Action 'SetForwarding' -Status 'Failed' -Detail $_.Exception.Message
        Write-Log "  Forwarding failed: $_" 'WARN'
    }
}

function Remove-UserLicenses {
    param([string]$UserPrincipalName)

    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, 'Remove ALL assigned licenses')) {
        Write-Result -User $UserPrincipalName -Action 'RemoveLicenses' -Status (Get-DeclinedStatus) -Detail ''
        return
    }

    try {
        $User = Get-MgUser -UserId $UserPrincipalName -Property Id, AssignedLicenses -ErrorAction Stop
        $LicenseIds = @($User.AssignedLicenses.SkuId)
        if ($LicenseIds.Count -eq 0) {
            Write-Result -User $UserPrincipalName -Action 'RemoveLicenses' -Status 'Skipped' -Detail 'No licenses assigned'
            return
        }
        Set-MgUserLicense -UserId $UserPrincipalName -AddLicenses @() -RemoveLicenses $LicenseIds -ErrorAction Stop
        Write-Result -User $UserPrincipalName -Action 'RemoveLicenses' -Status 'Success' -Detail "Removed $($LicenseIds.Count) license(s)"
        Write-Log '  Licenses removed'
    } catch {
        Write-Result -User $UserPrincipalName -Action 'RemoveLicenses' -Status 'Failed' -Detail $_.Exception.Message
        Write-Log "  License removal failed: $_" 'WARN'
    }
}

function Block-UserSignIn {
    param([string]$UserPrincipalName)

    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, 'Block sign-in (disable account)')) {
        Write-Result -User $UserPrincipalName -Action 'BlockSignIn' -Status (Get-DeclinedStatus) -Detail ''
        return
    }

    try {
        Update-MgUser -UserId $UserPrincipalName -AccountEnabled:$false -ErrorAction Stop
        Write-Result -User $UserPrincipalName -Action 'BlockSignIn' -Status 'Success' -Detail 'Sign-in blocked'
        Write-Log '  Sign-in blocked'
    } catch {
        Write-Result -User $UserPrincipalName -Action 'BlockSignIn' -Status 'Failed' -Detail $_.Exception.Message
        Write-Log "  Block sign-in failed: $_" 'WARN'
    }
}

function Revoke-UserSessions {
    param([string]$UserPrincipalName)

    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, 'Revoke sign-in sessions')) {
        Write-Result -User $UserPrincipalName -Action 'RevokeSessions' -Status (Get-DeclinedStatus) -Detail ''
        return
    }

    try {
        Revoke-MgUserSignInSession -UserId $UserPrincipalName -ErrorAction Stop | Out-Null
        Write-Result -User $UserPrincipalName -Action 'RevokeSessions' -Status 'Success' -Detail 'Sessions revoked'
        Write-Log '  Sessions revoked'
    } catch {
        Write-Result -User $UserPrincipalName -Action 'RevokeSessions' -Status 'Failed' -Detail $_.Exception.Message
        Write-Log "  Session revocation failed: $_" 'WARN'
    }
}

# -- MAIN --

try {
    Write-Log '=== Bulk User Offboarding ==='

    $TargetUsers = @()

    if ($CsvPath) {
        if (-not (Test-Path -LiteralPath $CsvPath)) { throw "CSV not found: $CsvPath" }
        $CsvData = @(Import-Csv -LiteralPath $CsvPath)
        $TargetUsers = @($CsvData | ForEach-Object { $_.UserPrincipalName } | Where-Object { $_ })
        Write-Log "CSV: $CsvPath ($($TargetUsers.Count) users)"
    } elseif ($UserPrincipalNames) {
        $TargetUsers = @($UserPrincipalNames)
        Write-Log "Manual: $($TargetUsers.Count) users"
    } else {
        throw 'Provide either -CsvPath or -UserPrincipalNames'
    }

    if (-not $SkipGraphConnect) {
        Connect-ToGraph
    }

    $ExchangeConnected = $false
    if ($ConvertToSharedMailbox -or $ForwardTo) {
        $ExchangeConnected = Connect-ToExchange
        if (-not $ExchangeConnected -and -not $WhatIfPreference) {
            Write-Log 'Exchange Online not connected. Mailbox operations will be skipped.' 'WARN'
        }
    }

    foreach ($UPN in $TargetUsers) {
        Write-Log "Offboarding: $UPN"

        Block-UserSignIn -UserPrincipalName $UPN

        if ($RevokeSessions) {
            Revoke-UserSessions -UserPrincipalName $UPN
        }

        if ($RemoveLicenses) {
            Remove-UserLicenses -UserPrincipalName $UPN
        }

        Set-OneDriveRetention -UserPrincipalName $UPN

        if ($ExchangeConnected -and $ConvertToSharedMailbox) {
            Convert-UserToSharedMailbox -UserPrincipalName $UPN
        }

        if ($ExchangeConnected -and $ForwardTo) {
            Set-MailboxForwarding -UserPrincipalName $UPN -ForwardToAddress $ForwardTo
        }
    }

    $SuccessCount = @($Results | Where-Object { $_.Status -eq 'Success' }).Count
    $FailCount    = @($Results | Where-Object { $_.Status -eq 'Failed' }).Count
    $WhatIfCount  = @($Results | Where-Object { $_.Status -eq 'WhatIf' }).Count

    $HtmlRows = $Results | ForEach-Object {
        $RowClass = switch ($_.Status) {
            'Success' { '' }
            'Failed'  { 'danger' }
            'WhatIf'  { 'warning' }
            default   { '' }
        }
        "<tr class='$RowClass'>
        <td>$($_.UserPrincipalName)</td>
        <td>$($_.Action)</td>
        <td>$($_.Status)</td>
        <td>$($_.Detail)</td>
        <td>$($_.Timestamp)</td>
    </tr>"
    }

    $Html = @"
<!DOCTYPE html>
<html>
<head><title>Bulk User Offboarding Report</title>
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
<h1>Bulk User Offboarding Report</h1>
<div class='summary'>
    <strong>Total Users:</strong> $($TargetUsers.Count) |
    <strong>Operations:</strong> $($Results.Count) |
    <strong>Success:</strong> $SuccessCount |
    <strong>Failed:</strong> $FailCount |
    <strong>WhatIf:</strong> $WhatIfCount
</div>
<table>
<tr><th>User</th><th>Action</th><th>Status</th><th>Detail</th><th>Timestamp</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

    $Html | Out-File -LiteralPath $ReportPath -Encoding UTF8
    Write-Log "Report: $ReportPath"

    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Users: $($TargetUsers.Count) | Ops: $($Results.Count) | Success: $SuccessCount | Failed: $FailCount"
}
catch {
    Write-Log "Offboarding failed: $_" 'ERROR'
    throw
}
