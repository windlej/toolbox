param(
    [Parameter(Mandatory = $false)]
    [string[]]$HyperVHosts = @($env:COMPUTERNAME),

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\HyperV_Inventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeSnapshots,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeNetworks,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeStorage
)

function Get-VMDetail {
    param([string]$HostName)

    try {
        $VMs = Get-VM -ComputerName $HostName -ErrorAction Stop
    } catch {
        try {
            Import-Module Hyper-V -ErrorAction Stop
            $VMs = Get-VM -ComputerName $HostName
        } catch {
            Write-Warning "Cannot connect to Hyper-V on $HostName (requires Hyper-V module or admin rights)"
            return @()
        }
    }

    if (-not $VMs) {
        Write-Host "  No VMs found on $HostName" -ForegroundColor Gray
        return @()
    }

    $Results = foreach ($VM in $VMs) {
        $MemoryGB = [math]::Round($VM.MemoryStartup / 1GB, 2)
        $Uptime = if ($VM.State -eq "Running") {
            (Get-Date) - $VM.Uptime.Ticks
            $VM.Uptime
        } else { $null }

        $UptimeStr = if ($Uptime) {
            "$($Uptime.Days)d $($Uptime.Hours)h $($Uptime.Minutes)m"
        } else { "N/A" }

        $CpuCount = $VM.ProcessorCount
        $Status = $VM.Status

        $SnapshotInfo = @()
        if ($IncludeSnapshots) {
            $Snapshots = Get-VMSnapshot -VM $VM -ComputerName $HostName -ErrorAction SilentlyContinue
            $SnapshotInfo = foreach ($Snap in $Snapshots) {
                [PSCustomObject]@{
                    SnapshotName = $Snap.Name
                    SnapshotType = $Snap.SnapshotType
                    Created      = $Snap.CreationTime
                    SizeGB       = [math]::Round($Snap.Size / 1GB, 2)
                }
            }
        }

        $NetworkInfo = @()
        if ($IncludeNetworks) {
            $Adapters = Get-VMNetworkAdapter -VM $VM -ComputerName $HostName -ErrorAction SilentlyContinue
            $NetworkInfo = foreach ($Adapter in $Adapters) {
                [PSCustomObject]@{
                    AdapterName   = $Adapter.Name
                    SwitchName    = $Adapter.SwitchName
                    MacAddress    = $Adapter.MacAddress
                    IpAddresses   = ($Adapter.IPAddresses -join "; ")
                }
            }
        }

        $StorageInfo = @()
        if ($IncludeStorage) {
            $Disks = Get-VMHardDiskDrive -VM $VM -ComputerName $HostName -ErrorAction SilentlyContinue
            $StorageInfo = foreach ($Disk in $Disks) {
                $Path = $Disk.Path
                $SizeGB = try {
                    [math]::Round((Get-Item $Path -ErrorAction SilentlyContinue).Length / 1GB, 2)
                } catch { "N/A" }
                [PSCustomObject]@{
                    ControllerType = $Disk.ControllerType
                    ControllerNumber = $Disk.ControllerNumber
                    Path           = $Path
                    SizeGB         = $SizeGB
                }
            }
        }

        [PSCustomObject]@{
            HostName      = $HostName.ToUpper()
            VmName        = $VM.Name
            State         = $VM.State
            CpuCount      = $CpuCount
            MemoryGB      = $MemoryGB
            Uptime        = $UptimeStr
            Status        = $Status
            Generation    = $VM.Generation
            Version       = $VM.Version
            Notes         = $VM.Notes
            SnapshotCount = if ($IncludeSnapshots) { $SnapshotInfo.Count } else { 0 }
            Snapshots     = $SnapshotInfo
            Networks      = $NetworkInfo
            Storage       = $StorageInfo
        }
    }

    return $Results
}

$AllVMs = @()

foreach ($Host in $HyperVHosts) {
    Write-Host "Inventorying VMs on $Host..." -ForegroundColor Yellow
    $VMs = Get-VMDetail -HostName $Host
    $AllVMs += $VMs
    Write-Host "  Found $($VMs.Count) VMs" -ForegroundColor Green
}

$RunningVMs = ($AllVMs | Where-Object { $_.State -eq "Running" }).Count
$StoppedVMs = ($AllVMs | Where-Object { $_.State -eq "Off" }).Count
$TotalMemory = ($AllVMs | Where-Object { $_.State -eq "Running" } | Measure-Object -Property MemoryGB -Sum).Sum

Write-Host "`n=== Hyper-V Inventory Summary ===" -ForegroundColor Cyan
Write-Host "Total VMs: $($AllVMs.Count)" -ForegroundColor White
Write-Host "Running: $RunningVMs" -ForegroundColor Green
Write-Host "Stopped: $StoppedVMs" -ForegroundColor Gray
Write-Host "Total Allocated Memory: $TotalMemory GB" -ForegroundColor Yellow

$HtmlRows = $AllVMs | Sort-Object HostName, VmName | ForEach-Object {
    $RowClass = if ($_.State -eq "Running") { "" } else { "stopped" }
    $SnapBadge = if ($_.SnapshotCount -gt 0) { "<span style='color:orange;'>[$($_.SnapshotCount) snapshots]</span>" } else { "" }
    "<tr class='$RowClass'>
        <td>$($_.HostName)</td>
        <td>$($_.VmName) $SnapBadge</td>
        <td>$($_.State)</td>
        <td>$($_.CpuCount)</td>
        <td>$($_.MemoryGB)</td>
        <td>$($_.Uptime)</td>
        <td>$($_.Generation)</td>
        <td>$($_.Status)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Hyper-V VM Inventory</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 6px 8px; border-bottom: 1px solid #ddd; }
tr:hover { background: #f5f5f5; }
.stopped td { color: #999; }
</style></head>
<body>
<h1>Hyper-V VM Inventory Report</h1>
<div class='summary'>
    <strong>Hosts:</strong> $($HyperVHosts.Count) |
    <strong>Total VMs:</strong> $($AllVMs.Count) |
    <strong>Running:</strong> $RunningVMs |
    <strong>Stopped:</strong> $StoppedVMs |
    <strong>Allocated Memory:</strong> $TotalMemory GB
</div>
<table>
<tr><th>Host</th><th>VM Name</th><th>State</th><th>vCPU</th><th>Memory (GB)</th><th>Uptime</th><th>Gen</th><th>Status</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "`nReport: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $CsvData = $AllVMs | Select-Object HostName, VmName, State, CpuCount, MemoryGB, Uptime, Status, Generation, Version, SnapshotCount
    $CsvData | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}
