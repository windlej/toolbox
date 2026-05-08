param(
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\MFAReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeExcludedUsers,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGraphConnect
)

$Results = @()

function Connect-ToGraph {
    $scopes = @(
        'User.Read.All',
        'Policy.Read.All',
        'AuditLog.Read.All',
        'Directory.Read.All'
    )
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Host "Connected to Graph" -ForegroundColor Green
    } catch {
        throw "Graph auth failed: $_"
    }
}

function Get-CAPolicyMFAStatus {
    $Policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue
    $MfaPolicies = $Policies | Where-Object {
        $_.State -eq 'enabled' -and
        $_.GrantControls.BuiltInControls -contains 'mfa'
    }

    $CoveredUsers = @()
    foreach ($Policy in $MfaPolicies) {
        $Users = $Policy.Conditions.Users
        $CoveredUsers += $Users.IncludeUsers
        if ($Users.IncludeGuestsOrExternalUsers) {
            $CoveredUsers += 'AllGuests'
        }
    }

    return @{
        TotalPolicies = $Policies.Count
        MfaPolicies = $MfaPolicies.Count
        CoveredUsers = ($CoveredUsers | Select-Object -Unique)
    }
}

function Get-AuthenticationMethods {
    $Methods = Get-MgUserAuthenticationMethod -UserId $null -ErrorAction SilentlyContinue
    return $Methods
}

function Get-UserMfaStatus {
    param([string]$UserId)

    $Status = "Disabled"
    $Methods = @()
    $DefaultMfaMethod = ""

    try {
        $AuthMethods = Get-MgUserAuthenticationMethod -UserId $UserId -ErrorAction SilentlyContinue
        $Methods = $AuthMethods.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', ''
        if ($Methods -contains 'phoneAuthenticationMethod' -or
            $Methods -contains 'microsoftAuthenticatorAuthenticationMethod' -or
            $Methods -contains 'fido2AuthenticationMethod' -or
            $Methods -contains 'windowsHelloForBusinessAuthenticationMethod') {
            $Status = "Enabled"
        }

        $Default = Get-MgUserAuthenticationMethod -UserId $UserId -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($Default) {
            $DefaultMfaMethod = ($Default.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', '') -replace 'AuthenticationMethod', ''
        }

    } catch {
        $Status = "Error"
    }

    return @{
        Status = $Status
        Methods = ($Methods -join ', ')
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

    $Compliant = $MfaState.Status -eq "Enabled" -or $CaMfaCovered

    return [PSCustomObject]@{
        UserPrincipalName     = $User.UserPrincipalName
        DisplayName           = $User.DisplayName
        UserType              = $User.UserType
        Department            = $User.Department
        JobTitle              = $User.JobTitle
        MfaStatus             = $MfaState.Status
        MfaMethods            = $MfaState.Methods
        DefaultMfaMethod      = $MfaState.DefaultMethod
        CaMfaCovered          = $CaMfaCovered
        Compliant             = $Compliant
        AccountEnabled        = $User.AccountEnabled
        CreatedDateTime       = $User.CreatedDateTime
        LastSignInDateTime    = $User.SignInActivity.LastSignInDateTime
    }
}

# ── MAIN ──

Write-Host "=== MFA Enforcement Report ===" -ForegroundColor Cyan

if (-not $SkipGraphConnect) {
    Connect-ToGraph
}

Write-Host "Retrieving Conditional Access policies..." -ForegroundColor Yellow
$CAStatus = Get-CAPolicyMFAStatus
Write-Host "CA Policies: $($CAStatus.TotalPolicies) total, $($CAStatus.MfaPolicies) require MFA" -ForegroundColor Cyan

Write-Host "Retrieving all users..." -ForegroundColor Yellow
$AllUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, UserType, Department, JobTitle,
    AccountEnabled, CreatedDateTime, SignInActivity -ErrorAction Stop

if (-not $IncludeExcludedUsers) {
    $AllUsers = $AllUsers | Where-Object { $_.AccountEnabled -eq $true }
}

Write-Host "Checking $($AllUsers.Count) users..." -ForegroundColor Yellow
$i = 0
foreach ($User in $AllUsers) {
    $i++
    if ($i % 50 -eq 0) { Write-Host "  $i / $($AllUsers.Count)..." -ForegroundColor Gray }
    $Results += Test-UserMfaCompliance -User $User -CAPolicyCoverage $CAStatus.CoveredUsers
}

$TotalUsers = $Results.Count
$CompliantCount = ($Results | Where-Object { $_.Compliant }).Count
$NonCompliantCount = ($Results | Where-Object { -not $_.Compliant }).Count
$EnabledMfa = ($Results | Where-Object { $_.MfaStatus -eq "Enabled" }).Count
$NoMfa = ($Results | Where-Object { $_.MfaStatus -eq "Disabled" }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total Users: $TotalUsers" -ForegroundColor White
Write-Host "Compliant: $CompliantCount" -ForegroundColor Green
Write-Host "Non-Compliant: $NonCompliantCount" -ForegroundColor Red
Write-Host "MFA Enabled: $EnabledMfa" -ForegroundColor Green
Write-Host "MFA Disabled: $NoMfa" -ForegroundColor Red

$HtmlRows = $Results | Sort-Object Compliant, UserPrincipalName | ForEach-Object {
    $RowClass = if (-not $_.Compliant) { "danger" } elseif ($_.MfaStatus -eq "Enabled") { "" } else { "warning" }
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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}
