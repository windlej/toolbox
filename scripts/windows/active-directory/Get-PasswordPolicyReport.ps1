param(
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\PasswordPolicyReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$AuditUsers,

    [Parameter(Mandatory = $false)]
    [int]$PasswordAgeWarningDays = 30,

    [Parameter(Mandatory = $false)]
    [int]$PasswordAgeCriticalDays = 60,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabledUsers
)

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
    ReversibleEncryption      = $DefaultPolicy.ReversibleEncryptionEncryptionEnabled
    LockoutThreshold          = $DefaultPolicy.LockoutThreshold
    LockoutDuration           = $DefaultPolicy.LockoutDuration
    LockoutObservationWindow = $DefaultPolicy.LockoutObservationWindow
    FineGrainedPolicies       = ($FineGrainedPolicies | ForEach-Object { $_.Name }) -join "; "
}

Write-Host "Domain Password Policy:" -ForegroundColor Cyan
$PolicySummary | Format-List

$AuditUsers = if ($AuditUsers) { $true } else { $false }

$UserResults = @()

if ($AuditUsers) {
    Write-Host "Auditing user password compliance..." -ForegroundColor Cyan

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

        $PasswordExpiryDate = if ($User.msDS-UserPasswordExpiryTimeComputed -and $User.msDS-UserPasswordExpiryTimeComputed -ne 0 -and $User.msDS-UserPasswordExpiryTimeComputed -ne 9223372036854775807) {
            [DateTime]::FromFileTime($User.msDS-UserPasswordExpiryTimeComputed)
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

    $TotalUsers = $UserResults.Count
    $ExpiredPasswords = ($UserResults | Where-Object { $_.PasswordStatus -eq "EXPIRED" }).Count
    $NeverExpires = ($UserResults | Where-Object { $_.PasswordNeverExpires }).Count
    $CriticalPasswords = ($UserResults | Where-Object { $_.PasswordStatus -eq "CRITICAL" }).Count
    $WarningPasswords = ($UserResults | Where-Object { $_.PasswordStatus -eq "WARNING" }).Count

    Write-Host "Audited $TotalUsers users" -ForegroundColor Green
    Write-Host "  Password OK: $($TotalUsers - $ExpiredPasswords - $NeverExpires - $CriticalPasswords - $WarningPasswords)" -ForegroundColor Green
    Write-Host "  Warning: $WarningPasswords" -ForegroundColor Yellow
    Write-Host "  Critical: $CriticalPasswords" -ForegroundColor Yellow
    Write-Host "  Expired: $ExpiredPasswords" -ForegroundColor Red
    Write-Host "  Never Expires: $NeverExpires" -ForegroundColor Red
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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvPath -and $AuditUsers) {
    $UserResults | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}
