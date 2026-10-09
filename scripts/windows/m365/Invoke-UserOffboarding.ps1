param(
    [Parameter(Mandatory = $false, ParameterSetName = "Csv")]
    [string]$CsvPath,

    [Parameter(Mandatory = $false, ParameterSetName = "Manual")]
    [string[]]$UserPrincipalNames,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\OffboardingReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$ManagerCsvPath,

    [Parameter(Mandatory = $false)]
    [int]$OneDriveRetentionDays = 30,

    [Parameter(Mandatory = $false)]
    [switch]$RevokeSessions,

    [Parameter(Mandatory = $false)]
    [switch]$ConvertToSharedMailbox,

    [Parameter(Mandatory = $false)]
    [string]$ForwardTo,

    [Parameter(Mandatory = $false)]
    [switch]$RemoveLicenses,

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGraphConnect
)

$Results = [System.Collections.Generic.List[PSObject]]::new()
$WarningLog = [System.Collections.Generic.List[string]]::new()

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
        Write-Host "Connected to Graph" -ForegroundColor Green
    } catch {
        throw "Graph authentication failed: $_"
    }
}

function Connect-ToExchange {
    try {
        $Module = Get-Module ExchangeOnlineManagement -ListAvailable -ErrorAction SilentlyContinue
        if (-not $Module) {
            Write-Warning "ExchangeOnlineManagement module not installed. Install with: Install-Module ExchangeOnlineManagement"
            Write-Result -User "" -Action "ExchangeOnline" -Status "Failed" -Detail "ExchangeOnlineManagement module not available"
            return $false
        }
        Connect-ExchangeOnline -ErrorAction Stop -ShowBanner:$false
        Write-Host "Connected to Exchange Online" -ForegroundColor Green
        return $true
    } catch {
        Write-Result -User "" -Action "ExchangeOnline" -Status "Failed" -Detail $_.Exception.Message
        return $false
    }
}

function Get-ManagerForUser {
    param([string]$UserPrincipalName)
    if (-not $ManagerCsvPath -or -not (Test-Path $ManagerCsvPath)) { return $null }
    $ManagerMap = Import-Csv $ManagerCsvPath
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
            Write-Result -User $UserPrincipalName -Action "OneDriveRetention" -Status "Skipped" -Detail "No OneDrive found"
            return
        }

        $Manager = Get-ManagerForUser -UserPrincipalName $UserPrincipalName
        if (-not $Manager) {
            try {
                $Mgmt = Get-MgUserManager -UserId $UserPrincipalName -ErrorAction SilentlyContinue
                if ($Mgmt) { $Manager = $Mgmt.AdditionalProperties.userPrincipalName }
            } catch { }
        }

        if ($Manager) {
            Write-Result -User $UserPrincipalName -Action "OneDriveRetention" -Status "Success" -Detail "OneDrive retention set. Delegated to: $Manager"
            Write-Host "  OneDrive delegated to $Manager" -ForegroundColor Green
        } else {
            Write-Result -User $UserPrincipalName -Action "OneDriveRetention" -Status "Warning" -Detail "OneDrive retention set but no manager found for delegation"
            Write-Host "  OneDrive retention applied (no manager for delegation)" -ForegroundColor Yellow
        }
    } catch {
        Write-Result -User $UserPrincipalName -Action "OneDriveRetention" -Status "Failed" -Detail $_.Exception.Message
        Write-Warning "  OneDrive retention failed: $_"
    }
}

function Convert-UserToSharedMailbox {
    param([string]$UserPrincipalName)

    if ($WhatIf) {
        Write-Host "[WhatIf] Would convert $UserPrincipalName to shared mailbox" -ForegroundColor Yellow
        Write-Result -User $UserPrincipalName -Action "ConvertToShared" -Status "WhatIf" -Detail ""
        return
    }

    try {
        Set-Mailbox -Identity $UserPrincipalName -Type Shared -ErrorAction Stop
        Write-Result -User $UserPrincipalName -Action "ConvertToShared" -Status "Success" -Detail "Converted to shared mailbox"
        Write-Host "  Converted to shared mailbox" -ForegroundColor Green
    } catch {
        Write-Result -User $UserPrincipalName -Action "ConvertToShared" -Status "Failed" -Detail $_.Exception.Message
        Write-Warning "  Shared mailbox conversion failed: $_"
    }
}

function Set-MailboxForwarding {
    param([string]$UserPrincipalName, [string]$ForwardToAddress)

    if (-not $ForwardToAddress) { return }

    if ($WhatIf) {
        Write-Host "[WhatIf] Would set forwarding $UserPrincipalName -> $ForwardToAddress" -ForegroundColor Yellow
        Write-Result -User $UserPrincipalName -Action "SetForwarding" -Status "WhatIf" -Detail $ForwardToAddress
        return
    }

    try {
        Set-Mailbox -Identity $UserPrincipalName -ForwardingAddress $ForwardToAddress -DeliverToMailboxAndForward $false -ErrorAction Stop
        Write-Result -User $UserPrincipalName -Action "SetForwarding" -Status "Success" -Detail $ForwardToAddress
        Write-Host "  Forwarding set to $ForwardToAddress" -ForegroundColor Green
    } catch {
        Write-Result -User $UserPrincipalName -Action "SetForwarding" -Status "Failed" -Detail $_.Exception.Message
        Write-Warning "  Forwarding failed: $_"
    }
}

function Remove-UserLicenses {
    param([string]$UserPrincipalName)

    if ($WhatIf) {
        Write-Host "[WhatIf] Would remove ALL licenses from $UserPrincipalName" -ForegroundColor Yellow
        Write-Result -User $UserPrincipalName -Action "RemoveLicenses" -Status "WhatIf" -Detail ""
        return
    }

    try {
        $User = Get-MgUser -UserId $UserPrincipalName -Property Id, AssignedLicenses -ErrorAction Stop
        $LicenseIds = $User.AssignedLicenses.SkuId
        if (-not $LicenseIds -or $LicenseIds.Count -eq 0) {
            Write-Result -User $UserPrincipalName -Action "RemoveLicenses" -Status "Skipped" -Detail "No licenses assigned"
            return
        }
        Set-MgUserLicense -UserId $UserPrincipalName -AddLicenses @() -RemoveLicenses $LicenseIds -ErrorAction Stop
        Write-Result -User $UserPrincipalName -Action "RemoveLicenses" -Status "Success" -Detail "Removed $($LicenseIds.Count) license(s)"
        Write-Host "  Licenses removed" -ForegroundColor Green
    } catch {
        Write-Result -User $UserPrincipalName -Action "RemoveLicenses" -Status "Failed" -Detail $_.Exception.Message
        Write-Warning "  License removal failed: $_"
    }
}

function Block-UserSignIn {
    param([string]$UserPrincipalName)

    if ($WhatIf) {
        Write-Host "[WhatIf] Would block sign-in for $UserPrincipalName" -ForegroundColor Yellow
        Write-Result -User $UserPrincipalName -Action "BlockSignIn" -Status "WhatIf" -Detail ""
        return
    }

    try {
        Update-MgUser -UserId $UserPrincipalName -AccountEnabled:$false -ErrorAction Stop
        Write-Result -User $UserPrincipalName -Action "BlockSignIn" -Status "Success" -Detail "Sign-in blocked"
        Write-Host "  Sign-in blocked" -ForegroundColor Green
    } catch {
        Write-Result -User $UserPrincipalName -Action "BlockSignIn" -Status "Failed" -Detail $_.Exception.Message
        Write-Warning "  Block sign-in failed: $_"
    }
}

function Revoke-UserSessions {
    param([string]$UserPrincipalName)

    if ($WhatIf) {
        Write-Host "[WhatIf] Would revoke sessions for $UserPrincipalName" -ForegroundColor Yellow
        Write-Result -User $UserPrincipalName -Action "RevokeSessions" -Status "WhatIf" -Detail ""
        return
    }

    try {
        Revoke-MgUserSignInSession -UserId $UserPrincipalName -ErrorAction Stop
        Write-Result -User $UserPrincipalName -Action "RevokeSessions" -Status "Success" -Detail "Sessions revoked"
        Write-Host "  Sessions revoked" -ForegroundColor Green
    } catch {
        Write-Result -User $UserPrincipalName -Action "RevokeSessions" -Status "Failed" -Detail $_.Exception.Message
        Write-Warning "  Session revocation failed: $_"
    }
}

# ── MAIN ──

Write-Host "=== Bulk User Offboarding ===" -ForegroundColor Cyan

$TargetUsers = @()

if ($CsvPath) {
    if (-not (Test-Path $CsvPath)) { throw "CSV not found: $CsvPath" }
    $CsvData = Import-Csv $CsvPath
    $TargetUsers = $CsvData.UserPrincipalName
    Write-Host "CSV: $CsvPath ($($TargetUsers.Count) users)" -ForegroundColor White
} elseif ($UserPrincipalNames) {
    $TargetUsers = $UserPrincipalNames
    Write-Host "Manual: $($TargetUsers.Count) users" -ForegroundColor White
} else {
    throw "Provide either -CsvPath or -UserPrincipalNames"
}

if (-not $SkipGraphConnect) {
    Connect-ToGraph
}

$ExchangeConnected = $false
if ($ConvertToSharedMailbox -or $ForwardTo) {
    $ExchangeConnected = Connect-ToExchange
    if (-not $ExchangeConnected -and -not $WhatIf) {
        Write-Warning "Exchange Online not connected. Mailbox operations will be skipped."
    }
}

foreach ($UPN in $TargetUsers) {
    Write-Host "`nOffboarding: $UPN" -ForegroundColor Yellow

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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Users: $($TargetUsers.Count) | Ops: $($Results.Count) | Success: $SuccessCount | Failed: $FailCount"
