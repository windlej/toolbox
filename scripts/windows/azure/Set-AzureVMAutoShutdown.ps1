param(
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\VMAutoShutdown_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$DefaultShutdownTime = "19:00",

    [Parameter(Mandatory = $false)]
    [string]$DefaultTimeZone = "Eastern Standard Time",

    [Parameter(Mandatory = $false)]
    [switch]$ApplySchedules,

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAzConnect
)

$Results = [System.Collections.Generic.List[PSObject]]::new()

function Connect-ToAzure {
    try {
        Connect-AzAccount -ErrorAction Stop
        Write-Host "Connected to Azure" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Azure connection failed: $_"
        return $false
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

    if ($WhatIf) {
        Write-Host "[WhatIf] Would set auto-shutdown $ShutdownTime $TimeZone on: $VMId" -ForegroundColor Yellow
        return "WhatIf"
    }

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

        New-AzResource @Params
        return "Applied"
    } catch {
        Write-Warning "  Failed to set auto-shutdown: $_"
        return "Failed"
    }
}

# ── MAIN ──
Write-Host "=== Azure VM Auto-Shutdown Scheduler ===" -ForegroundColor Cyan
Write-Host "Default shutdown: $DefaultShutdownTime $DefaultTimeZone" -ForegroundColor White

if (-not $SkipAzConnect) {
    $Connected = Connect-ToAzure
    if (-not $Connected) { return }
}

if (-not $SubscriptionIds) {
    $Subscriptions = Get-AzSubscription -ErrorAction Stop
    $SubscriptionIds = $Subscriptions.Id
}

foreach ($SubId in $SubscriptionIds) {
    try {
        Set-AzContext -SubscriptionId $SubId | Out-Null
        $SubName = (Get-AzContext).Subscription.Name
    } catch { continue }

    Write-Host "Checking VMs in $SubName..." -ForegroundColor Yellow

    $VMs = Get-AzVM -ErrorAction SilentlyContinue

    foreach ($VM in $VMs) {
        $Existing = Get-ExistingAutoShutdown -VMId $VM.Id

        $HasSchedule = ($Existing -and $Existing.Enabled -eq $true)
        $Action = "None"

        if (-not $HasSchedule -and $ApplySchedules) {
            $Action = Set-AutoShutdownSchedule -VMId $VM.Id -Location $VM.Location `
                -ShutdownTime $DefaultShutdownTime -TimeZone $DefaultTimeZone
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
$ScheduledCount = ($Results | Where-Object { $_.HasAutoShutdown }).Count
$UnscheduledCount = ($Results | Where-Object { -not $_.HasAutoShutdown }).Count
$AppliedCount = ($Results | Where-Object { $_.Action -eq "Applied" }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total VMs: $TotalVMs | With Schedule: $ScheduledCount | Without: $UnscheduledCount | Applied: $AppliedCount"

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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}
