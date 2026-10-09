#Requires -Version 5.1
#Requires -Modules Az.Accounts, Az.Resources, Az.Compute

<#
.SYNOPSIS
Finds Azure VMs without a DevTest auto-shutdown schedule and optionally applies one.

.DESCRIPTION
For each accessible subscription (or the ones you list) the script reads every VM and checks for an enabled
Microsoft.DevTestLab shutdown schedule ("shutdown-computevm"). By default it only reports.

With -ApplySchedules, VMs that have no enabled schedule get a daily shutdown at -DefaultShutdownTime in
-DefaultTimeZone (notifications disabled). Each write is guarded by ShouldProcess, so -WhatIf shows what
would change and -Confirm prompts. VMs that already have a schedule are never modified.

Output is an HTML report (primary) with counts and one row per VM, plus an optional CSV.

.PARAMETER SubscriptionIds
Optional list of subscription ids to process. Default: every subscription the signed-in account can see.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the results to a CSV next to the HTML report.

.PARAMETER DefaultShutdownTime
Daily shutdown time in HHmm 24-hour format, for example 1900. Default: "19:00" (kept from the original script;
the DevTest API expects HHmm, so use 1900 style values if the schedule is rejected).

.PARAMETER DefaultTimeZone
Windows time zone id for the schedule. Default: Eastern Standard Time. Use the customer's zone (tzutil /l).

.PARAMETER ApplySchedules
Create the shutdown schedule on VMs that lack one. Without this switch the script is read-only.

.PARAMETER SkipAzConnect
Use the existing Az session instead of calling Connect-AzAccount.

.EXAMPLE
.\Set-AzureVMAutoShutdown.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Set-AzureVMAutoShutdown.ps1 -ApplySchedules -DefaultShutdownTime 1900 -DefaultTimeZone "Pacific Standard Time" -SubscriptionIds 00000000-0000-0000-0000-000000000000 -WhatIf -OutputPath D:\Reports

.NOTES
Platform:     Windows (PowerShell 5.1+ with Az.Accounts, Az.Resources and Az.Compute modules)
Permissions:  Azure RBAC Reader to audit; Contributor (or Virtual Machine Contributor) on the VMs when using -ApplySchedules
When to use:  Cost control for dev/test subscriptions where VMs are left running overnight; run read-only first, then apply with -WhatIf before the real run.
Safety:       Changes data (supports -WhatIf)
Version:      1.1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$SubscriptionIds,

    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCsv,

    [string]$DefaultShutdownTime = "19:00",

    [string]$DefaultTimeZone = "Eastern Standard Time",

    [switch]$ApplySchedules,

    [switch]$SkipAzConnect
)

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
$htmlPath = Join-Path $outDir "Set-AzureVMAutoShutdown_$stamp.html"
$csvPath  = Join-Path $outDir "Set-AzureVMAutoShutdown_$stamp.csv"
$script:LogFile = Join-Path $outDir "Set-AzureVMAutoShutdown_$stamp.log"

$Results = [System.Collections.Generic.List[PSObject]]::new()

function Connect-ToAzure {
    try {
        Connect-AzAccount -ErrorAction Stop | Out-Null
        Write-Log 'Connected to Azure.'
    } catch {
        Write-Log "Azure connection failed: $_" 'ERROR'
        throw
    }
}

function Get-ExistingAutoShutdown {
    param([string]$VMId)

    try {
        $Shutdown = Get-AzResource -ResourceId "$VMId/providers/Microsoft.DevTestLab/schedules/shutdown-computevm" -ErrorAction SilentlyContinue
        if ($Shutdown) {
            $Properties = $Shutdown.Properties
            return @{
                Enabled = $Properties.taskType -eq "ComputeVmShutdownTask"
                Time    = $Properties.dailyRecurrence.time
                TimeZone = $Properties.timeZoneId
            }
        }
    } catch { }
    return $null
}

function Set-AutoShutdownSchedule {
    param(
        [string]$VMId,
        [string]$Location,
        [string]$ShutdownTime,
        [string]$TimeZone
    )

    try {
        $ShutdownProperties = @{
            taskType = "ComputeVmShutdownTask"
            enabled = "true"
            dailyRecurrence = @{ time = $ShutdownTime }
            timeZoneId = $TimeZone
            notificationSettings = @{
                status = "Disabled"
                timeInMinutes = "30"
            }
        }

        $Params = @{
            ResourceId = "$VMId/providers/Microsoft.DevTestLab/schedules/shutdown-computevm"
            Properties = $ShutdownProperties
            ApiVersion = '2017-04-26-preview'
            Force = $true
            ErrorAction = 'Stop'
        }

        New-AzResource @Params | Out-Null
        return "Applied"
    } catch {
        Write-Log "  Failed to set auto-shutdown on ${VMId}: $_" 'WARN'
        return "Failed"
    }
}

# -- MAIN --
Write-Log 'Azure VM auto-shutdown check starting.'
Write-Log "Default shutdown: $DefaultShutdownTime $DefaultTimeZone"
if ($ApplySchedules) { Write-Log '-ApplySchedules set: VMs without a schedule will be changed.' 'WARN' }

if (-not $SkipAzConnect) {
    Connect-ToAzure
}

if (-not $SubscriptionIds) {
    $Subscriptions = Get-AzSubscription -ErrorAction Stop
    $SubscriptionIds = $Subscriptions.Id
}

foreach ($SubId in $SubscriptionIds) {
    try {
        Set-AzContext -SubscriptionId $SubId -ErrorAction Stop | Out-Null
        $SubName = (Get-AzContext).Subscription.Name
    } catch {
        Write-Log "Cannot access subscription ${SubId}: $_" 'WARN'
        continue
    }

    Write-Log "Checking VMs in $SubName..."

    try {
        $VMs = Get-AzVM -ErrorAction Stop
    } catch {
        Write-Log "Could not list VMs in ${SubName}: $_" 'WARN'
        continue
    }

    foreach ($VM in $VMs) {
        $Existing = Get-ExistingAutoShutdown -VMId $VM.Id

        $HasSchedule = ($Existing -and $Existing.Enabled -eq $true)
        $Action = "None"

        if (-not $HasSchedule -and $ApplySchedules) {
            if ($PSCmdlet.ShouldProcess($VM.Id, "Set auto-shutdown $DefaultShutdownTime $DefaultTimeZone")) {
                $Action = Set-AutoShutdownSchedule -VMId $VM.Id -Location $VM.Location `
                    -ShutdownTime $DefaultShutdownTime -TimeZone $DefaultTimeZone
            }
            else {
                $Action = "Skipped"
            }
        }

        $Results.Add([PSCustomObject]@{
            SubscriptionName = $SubName
            ResourceGroup    = $VM.ResourceGroupName
            VMName           = $VM.Name
            Location         = $VM.Location
            VMSize           = $VM.HardwareProfile.VmSize
            VmId             = $VM.VmId
            HasAutoShutdown  = $HasSchedule
            CurrentSchedule  = if ($Existing) { "$($Existing.Time) $($Existing.TimeZone)" } else { "None" }
            Action           = $Action
        })
    }
}

$TotalVMs = $Results.Count
$ScheduledCount = @($Results | Where-Object { $_.HasAutoShutdown }).Count
$UnscheduledCount = @($Results | Where-Object { -not $_.HasAutoShutdown }).Count
$AppliedCount = @($Results | Where-Object { $_.Action -eq "Applied" }).Count

Write-Log "Summary: Total VMs $TotalVMs | With schedule $ScheduledCount | Without $UnscheduledCount | Applied $AppliedCount"

$HtmlRows = $Results | Sort-Object HasAutoShutdown, SubscriptionName | ForEach-Object {
    $RowClass = if (-not $_.HasAutoShutdown) { "warning" } else { "" }
    "<tr class='$RowClass'>
        <td>$($_.SubscriptionName)</td>
        <td>$($_.VMName)</td>
        <td>$($_.ResourceGroup)</td>
        <td>$($_.Location)</td>
        <td>$($_.VMSize)</td>
        <td>$($_.HasAutoShutdown)</td>
        <td>$($_.CurrentSchedule)</td>
        <td>$($_.Action)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>VM Auto-Shutdown Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 11px; }
th { background: #2c3e50; color: white; padding: 6px; text-align: left; }
td { padding: 4px 6px; border-bottom: 1px solid #ddd; }
.warning td { background: #fff3cd; }
</style></head>
<body>
<h1>Azure VM Auto-Shutdown Schedule Report</h1>
<div class='summary'>
    <strong>Total VMs:</strong> $TotalVMs |
    <strong>With Schedule:</strong> $ScheduledCount |
    <strong>Without Schedule:</strong> <span style='color:orange;'>$UnscheduledCount</span> |
    <strong>Applied:</strong> $AppliedCount
</div>
<table>
<tr><th>Subscription</th><th>VM</th><th>RG</th><th>Region</th><th>Size</th><th>Has Schedule</th><th>Current</th><th>Action</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "Report written: $htmlPath"

if ($ExportCsv) {
    $Results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV written: $csvPath"
}
