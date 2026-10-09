#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
Reports per-user MFA registration and Conditional Access MFA coverage for the tenant.

.DESCRIPTION
Reads all enabled Conditional Access policies that require MFA, then checks every user's registered
authentication methods (phone, Microsoft Authenticator, FIDO2, Windows Hello for Business). A user is
"Compliant" when they have a registered strong method or are covered by an MFA Conditional Access policy.
The output is an HTML report (primary) with a summary and one row per user, plus an optional CSV of the
same data. This script is read-only.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the per-user data to a CSV next to the HTML report.

.PARAMETER IncludeExcludedUsers
Include disabled accounts in the report. By default only enabled accounts are checked.

.PARAMETER SkipGraphConnect
Skip Connect-MgGraph (use when a Graph session with suitable scopes already exists).

.EXAMPLE
.\Get-MfaStatusReport.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-MfaStatusReport.ps1 -OutputPath D:\Reports -CustomerName Fabrikam -ExportCsv -IncludeExcludedUsers

.NOTES
Platform:     Windows (PowerShell 5.1+ with Microsoft Graph PowerShell SDK)
Permissions:  Graph scopes User.Read.All, Policy.Read.All, AuditLog.Read.All, Directory.Read.All, UserAuthenticationMethod.Read.All (Global Reader or Security Reader plus Authentication Administrator-level read of auth methods)
When to use:  Before enforcing MFA, during a security assessment, or to prove MFA coverage to an auditor.
Safety:       Read-only
Version:      1.1
#>
[CmdletBinding()]
param(
    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCsv,

    [switch]$IncludeExcludedUsers,

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
$ReportPath     = Join-Path $outDir "Get-MfaStatusReport_$stamp.html"
$CsvPath        = Join-Path $outDir "Get-MfaStatusReport_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-MfaStatusReport_$stamp.log"

$Results = [System.Collections.Generic.List[PSObject]]::new()

function Connect-ToGraph {
    $scopes = @(
        'User.Read.All',
        'Policy.Read.All',
        'AuditLog.Read.All',
        'Directory.Read.All',
        'UserAuthenticationMethod.Read.All'
    )
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Log 'Connected to Graph'
    } catch {
        throw "Graph auth failed: $_"
    }
}

function Get-CAPolicyMFAStatus {
    $Policies = @()
    try {
        $Policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
    } catch {
        Write-Log "Could not read Conditional Access policies (CA coverage will be empty): $_" 'WARN'
    }
    $MfaPolicies = @($Policies | Where-Object {
        $_.State -eq 'enabled' -and
        $_.GrantControls.BuiltInControls -contains 'mfa'
    })

    $CoveredUsers = @()
    foreach ($Policy in $MfaPolicies) {
        $Users = $Policy.Conditions.Users
        $CoveredUsers += @($Users.IncludeUsers)
        if ($Users.IncludeGuestsOrExternalUsers) {
            $CoveredUsers += 'AllGuests'
        }
    }

    return @{
        TotalPolicies = $Policies.Count
        MfaPolicies   = $MfaPolicies.Count
        CoveredUsers  = @($CoveredUsers | Select-Object -Unique)
    }
}

function Get-UserMfaStatus {
    param([string]$UserId)

    $Status = 'Disabled'
    $Methods = @()
    $DefaultMfaMethod = ''

    try {
        $AuthMethods = @(Get-MgUserAuthenticationMethod -UserId $UserId -ErrorAction Stop)
        $Methods = @($AuthMethods | ForEach-Object { $_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', '' })
        if ($Methods -contains 'phoneAuthenticationMethod' -or
            $Methods -contains 'microsoftAuthenticatorAuthenticationMethod' -or
            $Methods -contains 'fido2AuthenticationMethod' -or
            $Methods -contains 'windowsHelloForBusinessAuthenticationMethod') {
            $Status = 'Enabled'
        }

        $Default = $AuthMethods | Select-Object -First 1
        if ($Default) {
            $DefaultMfaMethod = ($Default.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', '') -replace 'AuthenticationMethod', ''
        }

    } catch {
        $Status = 'Error'
    }

    return @{
        Status        = $Status
        Methods       = ($Methods -join ', ')
        DefaultMethod = $DefaultMfaMethod
    }
}

function Test-UserMfaCompliance {
    param(
        [PSObject]$User,
        [array]$CAPolicyCoverage
    )

    $MfaState = Get-UserMfaStatus -UserId $User.Id

    $CaMfaCovered = $false
    if ($CAPolicyCoverage -contains 'All' -or
        $CAPolicyCoverage -contains $User.UserPrincipalName -or
        $CAPolicyCoverage -contains $User.Id) {
        $CaMfaCovered = $true
    }

    $Compliant = $MfaState.Status -eq 'Enabled' -or $CaMfaCovered

    return [PSCustomObject]@{
        UserPrincipalName  = $User.UserPrincipalName
        DisplayName        = $User.DisplayName
        UserType           = $User.UserType
        Department         = $User.Department
        JobTitle           = $User.JobTitle
        MfaStatus          = $MfaState.Status
        MfaMethods         = $MfaState.Methods
        DefaultMfaMethod   = $MfaState.DefaultMethod
        CaMfaCovered       = $CaMfaCovered
        Compliant          = $Compliant
        AccountEnabled     = $User.AccountEnabled
        CreatedDateTime    = $User.CreatedDateTime
        LastSignInDateTime = $User.SignInActivity.LastSignInDateTime
    }
}

# -- MAIN --

try {
    Write-Log '=== MFA Enforcement Report ==='

    if (-not $SkipGraphConnect) {
        Connect-ToGraph
    }

    Write-Log 'Retrieving Conditional Access policies...'
    $CAStatus = Get-CAPolicyMFAStatus
    Write-Log "CA Policies: $($CAStatus.TotalPolicies) total, $($CAStatus.MfaPolicies) require MFA"

    Write-Log 'Retrieving all users...'
    $AllUsers = @(Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, UserType, Department, JobTitle,
        AccountEnabled, CreatedDateTime, SignInActivity -ErrorAction Stop)

    if (-not $IncludeExcludedUsers) {
        $AllUsers = @($AllUsers | Where-Object { $_.AccountEnabled -eq $true })
    }

    Write-Log "Checking $($AllUsers.Count) users..."
    $i = 0
    foreach ($User in $AllUsers) {
        $i++
        if ($i % 50 -eq 0) { Write-Log "  $i / $($AllUsers.Count)..." }
        $Results.Add((Test-UserMfaCompliance -User $User -CAPolicyCoverage $CAStatus.CoveredUsers))
    }

    $TotalUsers        = $Results.Count
    $CompliantCount    = @($Results | Where-Object { $_.Compliant }).Count
    $NonCompliantCount = @($Results | Where-Object { -not $_.Compliant }).Count
    $EnabledMfa        = @($Results | Where-Object { $_.MfaStatus -eq 'Enabled' }).Count
    $NoMfa             = @($Results | Where-Object { $_.MfaStatus -eq 'Disabled' }).Count
    $ErrorMfa          = @($Results | Where-Object { $_.MfaStatus -eq 'Error' }).Count

    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total Users: $TotalUsers" -ForegroundColor White
    Write-Host "Compliant: $CompliantCount" -ForegroundColor Green
    Write-Host "Non-Compliant: $NonCompliantCount" -ForegroundColor Red
    Write-Host "MFA Enabled: $EnabledMfa" -ForegroundColor Green
    Write-Host "MFA Disabled: $NoMfa" -ForegroundColor Red
    if ($ErrorMfa -gt 0) {
        Write-Log "$ErrorMfa user(s) could not be checked (MfaStatus = Error); verify UserAuthenticationMethod.Read.All consent." 'WARN'
    }

    $HtmlRows = $Results | Sort-Object Compliant, UserPrincipalName | ForEach-Object {
        $RowClass = if (-not $_.Compliant) { 'danger' } elseif ($_.MfaStatus -eq 'Enabled') { '' } else { 'warning' }
        "<tr class='$RowClass'>
        <td>$($_.UserPrincipalName)</td>
        <td>$($_.DisplayName)</td>
        <td>$($_.UserType)</td>
        <td>$($_.Department)</td>
        <td>$($_.MfaStatus)</td>
        <td>$($_.DefaultMfaMethod)</td>
        <td>$($_.CaMfaCovered)</td>
        <td>$($_.Compliant)</td>
        <td>$($_.LastSignInDateTime)</td>
    </tr>"
    }

    $Html = @"
<!DOCTYPE html>
<html>
<head><title>MFA Enforcement Report</title>
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
<h1>MFA Enforcement Report</h1>
<div class='summary'>
    <strong>Total Users:</strong> $TotalUsers |
    <strong>Compliant:</strong> <span style='color:green;'>$CompliantCount</span> |
    <strong>Non-Compliant:</strong> <span style='color:red;'>$NonCompliantCount</span> |
    <strong>CA Policies Requiring MFA:</strong> $($CAStatus.MfaPolicies)
</div>
<table>
<tr><th>UPN</th><th>Name</th><th>Type</th><th>Department</th><th>MFA Status</th><th>Default Method</th><th>CA Covered</th><th>Compliant</th><th>Last Sign-In</th></tr>
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
    Write-Log "MFA status report failed: $_" 'ERROR'
    throw
}
