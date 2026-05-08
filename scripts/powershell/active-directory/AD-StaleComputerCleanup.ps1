param(
    [Parameter(Mandatory = $false)]
    [int]$InactiveDays = 90,

    [Parameter(Mandatory = $false)]
    [string]$OuPath,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\AD_StaleComputers.html",

    [Parameter(Mandatory = $false)]
    [switch]$DisableComputers,

    [Parameter(Mandatory = $false)]
    [switch]$DeleteComputers,

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

Import-Module ActiveDirectory -ErrorAction Stop

$CutoffDate = (Get-Date).AddDays(-$InactiveDays)

$queryParams = @{
    Properties = @('Name', 'OperatingSystem', 'LastLogonDate', 'PasswordLastSet',
                    'Enabled', 'Created', 'Description', 'IPv4Address')
    Filter     = { LastLogonDate -lt $CutoffDate -and OperatingSystem -like "*Windows*" }
}

if ($OuPath) {
    $queryParams.SearchBase = $OuPath
}

$StaleComputers = Get-ADComputer @queryParams | Sort-Object LastLogonDate

$Results = foreach ($Computer in $StaleComputers) {
    $Action = "None"

    if ($DeleteComputers -and $Computer.Enabled -eq $false) {
        $Action = "Delete"
        if (-not $WhatIf) {
            try {
                Remove-ADComputer -Identity $Computer.DistinguishedName -Confirm:$false
                $Action = "Deleted"
            } catch {
                $Action = "DeleteFailed"
            }
        }
    } elseif ($DisableComputers -and $Computer.Enabled) {
        $Action = "Disable"
        if (-not $WhatIf) {
            try {
                Disable-ADAccount -Identity $Computer.DistinguishedName -Confirm:$false
                $Action = "Disabled"
            } catch {
                $Action = "DisableFailed"
            }
        }
    }

    [PSCustomObject]@{
        Name               = $Computer.Name
        OperatingSystem    = $Computer.OperatingSystem
        Enabled            = $Computer.Enabled
        LastLogonDate      = $Computer.LastLogonDate
        PasswordLastSet    = $Computer.PasswordLastSet
        Created            = $Computer.Created
        DaysSinceLogon     = [math]::Round(((Get-Date) - $Computer.LastLogonDate).TotalDays)
        DistinguishedName  = $Computer.DistinguishedName
        Action             = $Action
    }
}

$TotalStale = ($Results | Where-Object { $_.DaysSinceLogon -ge $InactiveDays }).Count
$TotalDisabled = ($Results | Where-Object { $_.Action -eq "Disabled" }).Count
$TotalDeleted = ($Results | Where-Object { $_.Action -eq "Deleted" }).Count

$HtmlBody = $Results | Where-Object { $_.DaysSinceLogon -ge $InactiveDays } | ForEach-Object {
    $RowColor = switch ($_.Action) {
        "Deleted" { "background-color: #ffcccc;" }
        "Disabled" { "background-color: #fff3cd;" }
        default { "" }
    }
    "<tr style='$RowColor'>
        <td>$($_.Name)</td>
        <td>$($_.OperatingSystem)</td>
        <td>$($_.Enabled)</td>
        <td>$($_.LastLogonDate)</td>
        <td>$($_.DaysSinceLogon)</td>
        <td>$($_.PasswordLastSet)</td>
        <td>$($_.Created)</td>
        <td>$($_.Action)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>AD Stale Computer Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 6px 8px; border-bottom: 1px solid #ddd; }
tr:hover { background: #f5f5f5; }
.warning { background: #fff3cd; }
.danger { background: #f8d7da; }
</style></head>
<body>
<h1>AD Stale Computer Cleanup Report</h1>
<div class='summary'>
    <strong>Parameters:</strong> Inactive Days: $InactiveDays |
    Disable: $($DisableComputers.IsPresent) |
    Delete: $($DeleteComputers.IsPresent) |
    WhatIf: $($WhatIf.IsPresent)<br>
    <strong>Total Stale Computers:</strong> $TotalStale<br>
    <strong>Disabled:</strong> $TotalDisabled |
    <strong>Deleted:</strong> $TotalDeleted
</div>
<table>
<tr>
    <th>Name</th><th>OS</th><th>Enabled</th><th>Last Logon</th>
    <th>Days Inactive</th><th>Pwd Last Set</th><th>Created</th><th>Action</th>
</tr>
$($HtmlBody -join "`n")
</table>
</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8

Write-Host "Report generated: $ReportPath" -ForegroundColor Green
Write-Host "Summary: $TotalStale stale computers | Disabled: $TotalDisabled | Deleted: $TotalDeleted" -ForegroundColor Cyan
