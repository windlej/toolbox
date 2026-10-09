param(
    [Parameter(Mandatory = $false)]
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

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\PrivilegedAccountReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$BaselinePath = ".\privileged_baseline.xml",

    [Parameter(Mandatory = $false)]
    [switch]$UpdateBaseline,

    [Parameter(Mandatory = $false)]
    [switch]$CompareWithBaseline,

    [Parameter(Mandatory = $false)]
    [string[]]$AlertEmailTo,

    [Parameter(Mandatory = $false)]
    [string]$SmtpServer = "localhost",

    [Parameter(Mandatory = $false)]
    [int]$SmtpPort = 25
)

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
            Write-Warning "Error processing group '$GroupName': $($_.Exception.Message)"
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

Write-Host "Scanning privileged groups..." -ForegroundColor Cyan

$CurrentMembership = Get-PrivilegedMembers -Groups $ProtectedGroups

Write-Host "Found $($CurrentMembership.Count) privileged members" -ForegroundColor Green

$Changes = @()

if ($UpdateBaseline) {
    $CurrentMembership | Export-Clixml -Path $BaselinePath -Depth 5
    Write-Host "Baseline updated: $BaselinePath" -ForegroundColor Green
}

if ($CompareWithBaseline -and (Test-Path $BaselinePath)) {
    $Baseline = Import-Clixml -Path $BaselinePath
    $Changes = Find-Changes -Current $CurrentMembership -Baseline $Baseline

    if ($Changes.Count -gt 0) {
        Write-Host "WARNING: $($Changes.Count) changes detected since baseline!" -ForegroundColor Red
    } else {
        Write-Host "No changes detected since baseline." -ForegroundColor Green
    }
}

$SecurityWarnings = $CurrentMembership | Where-Object {
    (-not $_.Enabled) -or
    $_.PasswordNeverExpires -or
    $_.BadLogonCount -gt 50
}

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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($Changes.Count -gt 0 -and $AlertEmailTo) {
    try {
        $Body = "Privileged account changes detected: $($Changes.Count) changes found.`n`n"
        $Body += ($Changes | ForEach-Object { "$($_.Type): $($_.Detail)" }) -join "`n"
        Send-MailMessage -To $AlertEmailTo -From "privileged-monitor@$((Get-ADDomain).DNSRoot)" `
            -Subject "[ALERT] Privileged Account Changes Detected" -Body $Body `
            -SmtpServer $SmtpServer -Port $SmtpPort -ErrorAction Stop
        Write-Host "Alert sent to $($AlertEmailTo -join ', ')" -ForegroundColor Yellow
    } catch {
        Write-Warning "Failed to send alert: $($_.Exception.Message)"
    }
}
