#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
Finds Windows computer accounts that have not logged on recently and optionally disables or deletes them.

.DESCRIPTION
Queries Active Directory for Windows computer accounts whose LastLogonDate is older than -InactiveDays and writes
an HTML report listing each stale computer with its OS, enabled state, last logon, days inactive, password last set,
creation date and the action taken. By default nothing is changed (report only). -DisableComputers disables
enabled stale accounts; -DeleteComputers deletes stale accounts that are already disabled. Both honor -WhatIf and
-Confirm, so a dry run shows the planned action ("Disable"/"Delete") in the report without touching AD.
Recommended order: run report-only, run with -DisableComputers, wait a retention period, then run with -DeleteComputers.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER InactiveDays
Computers with no logon for at least this many days are considered stale. Default 90.

.PARAMETER OuPath
Optional distinguished name of an OU to limit the search to.

.PARAMETER DisableComputers
Disable stale computer accounts that are currently enabled. Supports -WhatIf.

.PARAMETER DeleteComputers
Delete stale computer accounts that are already disabled. Supports -WhatIf. Deletion is permanent unless the AD Recycle Bin is enabled.

.EXAMPLE
.\Remove-StaleADComputer.ps1 -InactiveDays 120 -OutputPath D:\Reports

.EXAMPLE
.\Remove-StaleADComputer.ps1 -InactiveDays 90 -OuPath "OU=Workstations,DC=contoso,DC=com" -DisableComputers -WhatIf -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (RSAT ActiveDirectory module, domain-joined machine)
Permissions:  Read-only domain user for the report; rights to disable/delete computer objects (e.g. Domain Admin or delegated Account Operator) for -DisableComputers / -DeleteComputers
When to use:  Periodic AD hygiene, after decommissioning projects, or before a domain audit to clear out dead computer objects.
Safety:       Destructive (supports -WhatIf)
Version:      1.0
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputPath,
    [string]$CustomerName,
    [int]$InactiveDays = 90,
    [string]$OuPath,
    [switch]$DisableComputers,
    [switch]$DeleteComputers
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
$htmlPath = Join-Path $outDir "Remove-StaleADComputer_$stamp.html"
$script:LogFile = Join-Path $outDir "Remove-StaleADComputer_$stamp.log"

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

$StaleComputers = @(Get-ADComputer @queryParams | Sort-Object LastLogonDate)
Write-Log "Found $($StaleComputers.Count) computer(s) inactive since $CutoffDate."

$Results = @(foreach ($Computer in $StaleComputers) {
    $Action = "None"

    if ($DeleteComputers -and $Computer.Enabled -eq $false) {
        $Action = "Delete"
        if ($PSCmdlet.ShouldProcess($Computer.DistinguishedName, 'Delete computer account')) {
            try {
                Remove-ADComputer -Identity $Computer.DistinguishedName -Confirm:$false
                $Action = "Deleted"
            } catch {
                $Action = "DeleteFailed"
                Write-Log "Delete failed for $($Computer.Name): $($_.Exception.Message)" 'ERROR'
            }
        }
    } elseif ($DisableComputers -and $Computer.Enabled) {
        $Action = "Disable"
        if ($PSCmdlet.ShouldProcess($Computer.DistinguishedName, 'Disable computer account')) {
            try {
                Disable-ADAccount -Identity $Computer.DistinguishedName -Confirm:$false
                $Action = "Disabled"
            } catch {
                $Action = "DisableFailed"
                Write-Log "Disable failed for $($Computer.Name): $($_.Exception.Message)" 'ERROR'
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
})

$TotalStale = @($Results | Where-Object { $_.DaysSinceLogon -ge $InactiveDays }).Count
$TotalDisabled = @($Results | Where-Object { $_.Action -eq "Disabled" }).Count
$TotalDeleted = @($Results | Where-Object { $_.Action -eq "Deleted" }).Count

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
    WhatIf: $WhatIfPreference<br>
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

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8 -WhatIf:$false

Write-Log "Report generated: $htmlPath"
Write-Log "Summary: $TotalStale stale computers | Disabled: $TotalDisabled | Deleted: $TotalDeleted"
