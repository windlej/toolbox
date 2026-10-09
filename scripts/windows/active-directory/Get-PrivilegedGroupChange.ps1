#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
Reports membership of privileged AD groups and detects additions/removals against a saved baseline.

.DESCRIPTION
Recursively enumerates the user members of a list of privileged groups (Domain Admins, Enterprise Admins,
Schema Admins, Administrators and others by default) and writes an HTML report with each member's enabled state,
title, department, password and logon dates, flagging disabled accounts and accounts whose password never expires.
-UpdateBaseline saves the current membership to a baseline XML file; -CompareWithBaseline loads that file and
lists members who were Added or Removed since it was taken. -AlertEmailTo sends the change list by e-mail
(Send-MailMessage). Active Directory is never modified; the only things written are the report, the log and,
with -UpdateBaseline, the baseline file.

The baseline is persistent state with a fixed file name (Get-PrivilegedGroupChange_Baseline.xml) inside the
resolved output folder. To compare against an earlier baseline you MUST reuse the same -OutputPath and
-CustomerName on every run (or pass the same explicit -BaselinePath). Typical routine: run once with
-UpdateBaseline, then run on a schedule with -CompareWithBaseline. Note that using both switches in one run
saves the new baseline first, so the comparison will then show no changes.

.PARAMETER OutputPath
Folder for the report, log and default baseline file. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.
Reuse the same value between runs so the baseline can be found.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder. Reuse the same value between runs.

.PARAMETER ProtectedGroups
Names of the groups to monitor. Defaults to the common built-in privileged groups.

.PARAMETER BaselinePath
Optional full path to the baseline XML file. Default is <output folder>\Get-PrivilegedGroupChange_Baseline.xml.

.PARAMETER UpdateBaseline
Save the current membership as the baseline (overwrites the existing baseline file). Supports -WhatIf.

.PARAMETER CompareWithBaseline
Compare current membership with the baseline file and report Added/Removed members.

.PARAMETER AlertEmailTo
Optional recipients for an e-mail alert when changes are detected. Supports -WhatIf.

.PARAMETER SmtpServer
SMTP server used for the alert e-mail. Default localhost.

.PARAMETER SmtpPort
SMTP port used for the alert e-mail. Default 25.

.EXAMPLE
.\Get-PrivilegedGroupChange.ps1 -UpdateBaseline -OutputPath D:\Reports -CustomerName Contoso

.EXAMPLE
.\Get-PrivilegedGroupChange.ps1 -CompareWithBaseline -OutputPath D:\Reports -CustomerName Contoso -AlertEmailTo secops@contoso.com -SmtpServer smtp.contoso.com

.NOTES
Platform:     Windows (RSAT ActiveDirectory module, domain-joined machine)
Permissions:  Read-only domain user (read access to group membership and user attributes)
When to use:  Scheduled monitoring for unexpected additions to Domain Admins and other privileged groups, or a point-in-time privileged access review.
Safety:       Changes data (supports -WhatIf)
Version:      1.0
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputPath,
    [string]$CustomerName,
    [string[]]$ProtectedGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Server Operators",
        "Print Operators",
        "Backup Operators",
        "Replicator",
        "Group Policy Creator Owners",
        "Domain Controllers",
        "Read-only Domain Controllers",
        "Organization Management"
    ),
    [string]$BaselinePath,
    [switch]$UpdateBaseline,
    [switch]$CompareWithBaseline,
    [string[]]$AlertEmailTo,
    [string]$SmtpServer = "localhost",
    [int]$SmtpPort = 25
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
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $line -WhatIf:$false }
}

$stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
# Report folder, report and log are always written, even under -WhatIf (WhatIf only guards the state changes below).
$WhatIfSaved = $WhatIfPreference
$WhatIfPreference = $false
$outDir   = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$WhatIfPreference = $WhatIfSaved
$htmlPath = Join-Path $outDir "Get-PrivilegedGroupChange_$stamp.html"
$script:LogFile = Join-Path $outDir "Get-PrivilegedGroupChange_$stamp.log"
if (-not $BaselinePath) { $BaselinePath = Join-Path $outDir 'Get-PrivilegedGroupChange_Baseline.xml' }

Import-Module ActiveDirectory -ErrorAction Stop

function Get-PrivilegedMembers {
    param([string[]]$Groups)

    $Results = @()

    foreach ($GroupName in $Groups) {
        try {
            $Group = Get-ADGroup -Identity $GroupName -ErrorAction SilentlyContinue
            if (-not $Group) { continue }

            $Members = Get-ADGroupMember -Identity $Group.DistinguishedName -Recursive -ErrorAction SilentlyContinue |
                Where-Object { $_.objectClass -eq "user" }

            foreach ($Member in $Members) {
                try {
                    $User = Get-ADUser -Identity $Member.DistinguishedName -Properties Title, Department, Enabled,
                        LastLogonDate, PasswordLastSet, PasswordNeverExpires, LastBadPasswordAttempt, BadLogonCount,
                        MemberOf, Created, WhenChanged
                } catch {
                    $User = $null
                }

                $NestedGroups = try {
                    (Get-ADPrincipalGroupMembership -Identity $Member.DistinguishedName -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -in $Groups }).Name -join "; "
                } catch { "" }

                $Results += [PSCustomObject]@{
                    GroupName              = $GroupName
                    UserName               = $Member.Name
                    SamAccountName         = $Member.SamAccountName
                    Enabled                = if ($User) { $User.Enabled } else { $null }
                    Title                  = if ($User) { $User.Title } else { "" }
                    Department             = if ($User) { $User.Department } else { "" }
                    Created                = if ($User) { $User.Created } else { $null }
                    PasswordLastSet        = if ($User) { $User.PasswordLastSet } else { $null }
                    PasswordNeverExpires   = if ($User) { $User.PasswordNeverExpires } else { $null }
                    LastLogonDate          = if ($User) { $User.LastLogonDate } else { $null }
                    LastBadPasswordAttempt = if ($User) { $User.LastBadPasswordAttempt } else { $null }
                    BadLogonCount          = if ($User) { $User.BadLogonCount } else { $null }
                    DirectGroups           = if ($User) { (($User.MemberOf | ForEach-Object {
                            ($_ -split ',')[0] -replace 'CN=',''
                        }) -join "; ") } else { "" }
                    NestedGroupMembership  = $NestedGroups
                    SecondsSinceChange     = if ($User -and $User.WhenChanged) {
                            [math]::Round(((Get-Date) - $User.WhenChanged).TotalSeconds)
                    } else { $null }
                }
            }
        } catch {
            Write-Log "Error processing group '$GroupName': $($_.Exception.Message)" 'WARN'
        }
    }

    return $Results
}

function Find-Changes {
    param(
        [array[]]$Current,
        [array[]]$Baseline
    )

    $Changes = @()

    foreach ($Entry in $Current) {
        $Match = $Baseline | Where-Object {
            $_.UserName -eq $Entry.UserName -and $_.GroupName -eq $Entry.GroupName
        }

        if (-not $Match) {
            $Changes += [PSCustomObject]@{
                Type    = "Added"
                Detail  = "$($Entry.UserName) ($($Entry.SamAccountName)) added to $($Entry.GroupName)"
                Entry   = $Entry
            }
        }
    }

    foreach ($Entry in $Baseline) {
        $Match = $Current | Where-Object {
            $_.UserName -eq $Entry.UserName -and $_.GroupName -eq $Entry.GroupName
        }

        if (-not $Match) {
            $Changes += [PSCustomObject]@{
                Type    = "Removed"
                Detail  = "$($Entry.UserName) ($($Entry.SamAccountName)) removed from $($Entry.GroupName)"
                Entry   = $Entry
            }
        }
    }

    return $Changes
}

Write-Log "Scanning privileged groups..."

$CurrentMembership = @(Get-PrivilegedMembers -Groups $ProtectedGroups)

Write-Log "Found $($CurrentMembership.Count) privileged members"

$Changes = @()

if ($UpdateBaseline) {
    if ($PSCmdlet.ShouldProcess($BaselinePath, 'Write privileged group baseline')) {
        $CurrentMembership | Export-Clixml -LiteralPath $BaselinePath -Depth 5
        Write-Log "Baseline updated: $BaselinePath"
    }
}

if ($CompareWithBaseline -and (Test-Path -LiteralPath $BaselinePath)) {
    $Baseline = @(Import-Clixml -LiteralPath $BaselinePath)
    $Changes = @(Find-Changes -Current $CurrentMembership -Baseline $Baseline)

    if ($Changes.Count -gt 0) {
        Write-Log "$($Changes.Count) changes detected since baseline!" 'WARN'
    } else {
        Write-Log "No changes detected since baseline."
    }
}
elseif ($CompareWithBaseline) {
    Write-Log "Baseline not found: $BaselinePath. Use the same -OutputPath/-CustomerName as the run that created it, or run with -UpdateBaseline first." 'WARN'
}

$SecurityWarnings = @($CurrentMembership | Where-Object {
    (-not $_.Enabled) -or
    $_.PasswordNeverExpires -or
    $_.BadLogonCount -gt 50
})

$HtmlChangeRows = $Changes | ForEach-Object {
    $RowClass = if ($_.Type -eq "Added") { "danger" } else { "warning" }
    "<tr class='$RowClass'>
        <td>$($_.Type)</td>
        <td>$($_.Detail)</td>
    </tr>"
}

$HtmlRows = $CurrentMembership | ForEach-Object {
    $WarnFlags = @()
    if (-not $_.Enabled) { $WarnFlags += "DISABLED" }
    if ($_.PasswordNeverExpires) { $WarnFlags += "PWD_NEVER_EXPIRES" }
    $Badge = if ($WarnFlags) { "<span style='color:red;'>[$( $WarnFlags -join '][')]</span>" } else { "" }

    "<tr>
        <td>$($_.GroupName)</td>
        <td>$($_.UserName)$Badge</td>
        <td>$($_.SamAccountName)</td>
        <td>$($_.Enabled)</td>
        <td>$($_.Title)</td>
        <td>$($_.Department)</td>
        <td>$($_.PasswordLastSet)</td>
        <td>$($_.LastLogonDate)</td>
        <td>$($_.PasswordNeverExpires)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Privileged Account Monitor</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #fff3cd; padding: 15px; border-radius: 5px; margin: 10px 0; }
.security { background: #f8d7da; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; position: sticky; top: 0; }
td { padding: 5px 8px; border-bottom: 1px solid #ddd; }
tr:hover { background: #f5f5f5; }
.danger td { background: #f8d7da; }
.warning td { background: #fff3cd; }
</style></head>
<body>
<h1>Privileged Account Monitoring Report</h1>
<div class='summary'>
    <strong>Groups Monitored:</strong> $($ProtectedGroups.Count) |
    <strong>Privileged Members:</strong> $($CurrentMembership.Count) |
    <strong>Changes Since Baseline:</strong> $($Changes.Count) |
    <strong>Security Warnings:</strong> $($SecurityWarnings.Count)
</div>

$(if ($Changes.Count -gt 0) {
@"
<h2>Changes Detected</h2>
<table>
<tr><th>Type</th><th>Detail</th></tr>
$($HtmlChangeRows -join "`n")
</table>
"@
})

$(if ($SecurityWarnings.Count -gt 0) {
@"
<div class='security'>
    <h2>Security Warnings</h2>
    <p>$($SecurityWarnings.Count) privileged accounts require attention</p>
</div>
"@
})

<h2>Current Privileged Membership</h2>
<table>
<tr>
    <th>Group</th><th>Name</th><th>SamAccountName</th><th>Enabled</th>
    <th>Title</th><th>Department</th><th>Pwd Last Set</th><th>Last Logon</th><th>Pwd Never Expires</th>
</tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8 -WhatIf:$false
Write-Log "Report: $htmlPath"

if ($Changes.Count -gt 0 -and $AlertEmailTo) {
    try {
        $Body = "Privileged account changes detected: $($Changes.Count) changes found.`n`n"
        $Body += ($Changes | ForEach-Object { "$($_.Type): $($_.Detail)" }) -join "`n"
        if ($PSCmdlet.ShouldProcess(($AlertEmailTo -join ', '), 'Send privileged group change alert e-mail')) {
            Send-MailMessage -To $AlertEmailTo -From "privileged-monitor@$((Get-ADDomain).DNSRoot)" `
                -Subject "[ALERT] Privileged Account Changes Detected" -Body $Body `
                -SmtpServer $SmtpServer -Port $SmtpPort -ErrorAction Stop
            Write-Log "Alert sent to $($AlertEmailTo -join ', ')"
        }
    } catch {
        Write-Log "Failed to send alert: $($_.Exception.Message)" 'WARN'
    }
}
