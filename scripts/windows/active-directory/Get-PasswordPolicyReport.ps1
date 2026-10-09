#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
Reports the domain password policy and, optionally, per-user password compliance as HTML (optional CSV).

.DESCRIPTION
Reads the default domain password policy and any fine-grained password policies and lists them in an HTML report.
With -AuditUsers it also evaluates every user (enabled only unless -IncludeDisabledUsers) and classifies each
password as OK, WARNING, CRITICAL, EXPIRED or NEVER_EXPIRES based on the days until expiry and the thresholds
-PasswordAgeWarningDays / -PasswordAgeCriticalDays. The user table shows name, account, status, last set and expiry
dates and lockout state; no password data is read. -ExportCsv writes the per-user results (only with -AuditUsers).

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write a CSV of the per-user results. Only has an effect together with -AuditUsers.

.PARAMETER AuditUsers
Include the per-user password compliance audit (list of named user accounts). Without it only the policy is reported.

.PARAMETER PasswordAgeWarningDays
Users whose password expires within this many days are marked WARNING. Default 30.

.PARAMETER PasswordAgeCriticalDays
Users whose password expires within this many days are marked CRITICAL. Default 60 (should be lower than the
warning value for sensible results; the critical check runs first).

.PARAMETER IncludeDisabledUsers
Include disabled accounts in the user audit.

.EXAMPLE
.\Get-PasswordPolicyReport.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-PasswordPolicyReport.ps1 -AuditUsers -IncludeDisabledUsers -ExportCsv -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (RSAT ActiveDirectory module, domain-joined machine)
Permissions:  Read-only domain user (fine-grained policy objects may need Domain Admin to read)
When to use:  Security assessments, audit evidence for password policy, or finding accounts with expired or never-expiring passwords.
Safety:       Read-only
Version:      1.0
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$CustomerName,
    [switch]$ExportCsv,
    [switch]$AuditUsers,
    [int]$PasswordAgeWarningDays = 30,
    [int]$PasswordAgeCriticalDays = 60,
    [switch]$IncludeDisabledUsers
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

$stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir   = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$htmlPath = Join-Path $outDir "Get-PasswordPolicyReport_$stamp.html"
$csvPath  = Join-Path $outDir "Get-PasswordPolicyReport_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-PasswordPolicyReport_$stamp.log"

Import-Module ActiveDirectory -ErrorAction Stop

$Domain = Get-ADDomain
$DomainDN = $Domain.DistinguishedName

$DefaultPolicy = Get-ADDefaultDomainPasswordPolicy
$FineGrainedPolicies = Get-ADFineGrainedPasswordPolicy -ErrorAction SilentlyContinue

$PolicySummary = [PSCustomObject]@{
    Domain                    = $Domain.DNSRoot
    MinPasswordLength         = $DefaultPolicy.MinPasswordLength
    MinPasswordAge            = $DefaultPolicy.MinPasswordAge
    MaxPasswordAge            = $DefaultPolicy.MaxPasswordAge
    PasswordHistoryCount      = $DefaultPolicy.PasswordHistoryCount
    PasswordComplexity        = $DefaultPolicy.ComplexityEnabled
    ReversibleEncryption      = $DefaultPolicy.ReversibleEncryptionEnabled
    LockoutThreshold          = $DefaultPolicy.LockoutThreshold
    LockoutDuration           = $DefaultPolicy.LockoutDuration
    LockoutObservationWindow = $DefaultPolicy.LockoutObservationWindow
    FineGrainedPolicies       = ($FineGrainedPolicies | ForEach-Object { $_.Name }) -join "; "
}

Write-Log ("Domain Password Policy:" + [Environment]::NewLine + (($PolicySummary | Format-List | Out-String).TrimEnd()))

$AuditUsers = if ($AuditUsers) { $true } else { $false }

$UserResults = @()

if ($AuditUsers) {
    Write-Log "Auditing user password compliance..."

    $UserFilter = "ObjectClass -eq 'user' -and ObjectCategory -eq 'person'"
    if (-not $IncludeDisabledUsers) {
        $UserFilter += " -and Enabled -eq 'True'"
    }

    $AllUsers = Get-ADUser -Filter $UserFilter -Properties Name, SamAccountName, Enabled,
        PasswordLastSet, PasswordNeverExpires, PasswordExpired, LastLogonDate, Title, Department,
        CannotChangePassword, msDS-UserPasswordExpiryTimeComputed, LockedOut

    foreach ($User in $AllUsers) {
        $DaysSincePwdSet = if ($User.PasswordLastSet) {
            [math]::Round(((Get-Date) - $User.PasswordLastSet).TotalDays)
        } else { $null }

        $ExpiryComputed = $User.'msDS-UserPasswordExpiryTimeComputed'
        $PasswordExpiryDate = if ($ExpiryComputed -and $ExpiryComputed -ne 0 -and $ExpiryComputed -ne 9223372036854775807) {
            [DateTime]::FromFileTime($ExpiryComputed)
        } elseif ($User.PasswordNeverExpires) {
            $null
        } elseif ($User.PasswordLastSet -and $DefaultPolicy.MaxPasswordAge.TotalDays -gt 0) {
            $User.PasswordLastSet.AddDays($DefaultPolicy.MaxPasswordAge.TotalDays)
        } else { $null }

        $DaysUntilExpiry = if ($PasswordExpiryDate) {
            [math]::Round(($PasswordExpiryDate - (Get-Date)).TotalDays)
        } else { $null }

        $PasswordStatus = "OK"
        if ($User.PasswordNeverExpires) { $PasswordStatus = "NEVER_EXPIRES" }
        elseif ($User.PasswordExpired) { $PasswordStatus = "EXPIRED" }
        elseif ($DaysUntilExpiry -le 0) { $PasswordStatus = "EXPIRED" }
        elseif ($DaysUntilExpiry -le $PasswordAgeCriticalDays) { $PasswordStatus = "CRITICAL" }
        elseif ($DaysUntilExpiry -le $PasswordAgeWarningDays) { $PasswordStatus = "WARNING" }

        $UserResults += [PSCustomObject]@{
            Name                = $User.Name
            SamAccountName      = $User.SamAccountName
            Enabled             = $User.Enabled
            Title               = $User.Title
            Department          = $User.Department
            PasswordLastSet     = $User.PasswordLastSet
            PasswordNeverExpires = $User.PasswordNeverExpires
            PasswordExpired     = $User.PasswordExpired
            PasswordExpiryDate  = $PasswordExpiryDate
            DaysSincePwdSet     = $DaysSincePwdSet
            DaysUntilExpiry     = $DaysUntilExpiry
            PasswordStatus      = $PasswordStatus
            LockedOut           = $User.LockedOut
            CannotChangePassword = $User.CannotChangePassword
            LastLogonDate       = $User.LastLogonDate
        }
    }

    $TotalUsers = @($UserResults).Count
    $ExpiredPasswords = @($UserResults | Where-Object { $_.PasswordStatus -eq "EXPIRED" }).Count
    $NeverExpires = @($UserResults | Where-Object { $_.PasswordNeverExpires }).Count
    $CriticalPasswords = @($UserResults | Where-Object { $_.PasswordStatus -eq "CRITICAL" }).Count
    $WarningPasswords = @($UserResults | Where-Object { $_.PasswordStatus -eq "WARNING" }).Count

    Write-Log "Audited $TotalUsers users"
    Write-Log "  Password OK: $($TotalUsers - $ExpiredPasswords - $NeverExpires - $CriticalPasswords - $WarningPasswords)"
    Write-Log "  Warning: $WarningPasswords"
    Write-Log "  Critical: $CriticalPasswords"
    Write-Log "  Expired: $ExpiredPasswords" 'WARN'
    Write-Log "  Never Expires: $NeverExpires" 'WARN'
}

$HtmlPolicyRows = @"
<tr><td>Min Password Length</td><td>$($PolicySummary.MinPasswordLength)</td></tr>
<tr><td>Max Password Age (days)</td><td>$($PolicySummary.MaxPasswordAge.TotalDays)</td></tr>
<tr><td>Min Password Age (days)</td><td>$($PolicySummary.MinPasswordAge.TotalDays)</td></tr>
<tr><td>Password History Count</td><td>$($PolicySummary.PasswordHistoryCount)</td></tr>
<tr><td>Complexity Enabled</td><td>$($PolicySummary.PasswordComplexity)</td></tr>
<tr><td>Reversible Encryption</td><td>$($PolicySummary.ReversibleEncryption)</td></tr>
<tr><td>Lockout Threshold</td><td>$($PolicySummary.LockoutThreshold)</td></tr>
<tr><td>Lockout Duration (mins)</td><td>$($PolicySummary.LockoutDuration.TotalMinutes)</td></tr>
<tr><td>Lockout Window (mins)</td><td>$($PolicySummary.LockoutObservationWindow.TotalMinutes)</td></tr>
"@

$HtmlUserRows = if ($AuditUsers) {
    $UserResults | ForEach-Object {
        $RowClass = switch ($_.PasswordStatus) {
            "EXPIRED" { "danger" }
            "CRITICAL" { "danger" }
            "NEVER_EXPIRES" { "warning" }
            "WARNING" { "warning" }
            default { "" }
        }
        "<tr class='$RowClass'>
            <td>$($_.Name)</td>
            <td>$($_.SamAccountName)</td>
            <td>$($_.Enabled)</td>
            <td>$($_.PasswordStatus)</td>
            <td>$($_.PasswordLastSet)</td>
            <td>$($_.PasswordExpiryDate)</td>
            <td>$($_.DaysSincePwdSet)</td>
            <td>$($_.DaysUntilExpiry)</td>
            <td>$($_.PasswordNeverExpires)</td>
            <td>$($_.LockedOut)</td>
        </tr>"
    }
} else { @() }

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Password Policy Compliance Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
h2 { color: #34495e; }
.policy-box { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 10px 0; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 12px; margin: 10px 0; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 5px 8px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
.warning td { background: #fff3cd; }
</style></head>
<body>
<h1>Password Policy Compliance Report</h1>
<div class='policy-box'>
<h2>Domain Password Policy - $($Domain.DNSRoot)</h2>
<table>
<tr><th>Setting</th><th>Value</th></tr>
$HtmlPolicyRows
</table>
$(if ($FineGrainedPolicies) {
"<h3>Fine-Grained Password Policies</h3>
<p>$($PolicySummary.FineGrainedPolicies)</p>"
})
</div>

$(if ($AuditUsers) {
@"
<h2>User Password Compliance</h2>
<div class='summary'>
    <strong>Total Users:</strong> $TotalUsers |
    <strong>OK:</strong> $($TotalUsers - $ExpiredPasswords - $NeverExpires - $CriticalPasswords - $WarningPasswords) |
    <strong>Warning:</strong> $WarningPasswords |
    <strong>Critical:</strong> $CriticalPasswords |
    <strong>Expired:</strong> $ExpiredPasswords |
    <strong>Never Expires:</strong> $NeverExpires
</div>
<table>
<tr>
    <th>Name</th><th>SamAccountName</th><th>Enabled</th><th>Status</th>
    <th>Pwd Last Set</th><th>Pwd Expiry</th><th>Days Since Set</th>
    <th>Days Until Expiry</th><th>Never Expires</th><th>Locked Out</th>
</tr>
$($HtmlUserRows -join "`n")
</table>
"@
})
</body></html>
"@

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "Report: $htmlPath"

if ($ExportCsv -and $AuditUsers) {
    $UserResults | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV: $csvPath"
}
elseif ($ExportCsv) {
    Write-Log "-ExportCsv has no effect without -AuditUsers; no CSV written." 'WARN'
}
