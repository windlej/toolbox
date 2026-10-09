#Requires -Version 5.1

<#
.SYNOPSIS
Inventories virtual machines on one or more Hyper-V hosts and writes an HTML report (optional CSV).

.DESCRIPTION
Connects to each host with the Hyper-V PowerShell module and lists every VM with state, vCPU count,
startup memory, uptime, generation, status and configuration version. Optional switches also collect
snapshots, network adapters and virtual hard disks per VM (held in memory; the HTML and CSV show the
snapshot count). Output is an HTML report with a summary header, plus an optional CSV.

.PARAMETER ComputerName
One or more Hyper-V hosts. Default: the local machine. Old name: HyperVHosts.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write a CSV of the VM list next to the HTML report.

.PARAMETER IncludeSnapshots
Collect checkpoint (snapshot) details and show a snapshot badge next to VMs that have them.

.PARAMETER IncludeNetworks
Collect virtual network adapter details for each VM.

.PARAMETER IncludeStorage
Collect virtual hard disk details for each VM.

.EXAMPLE
.\Get-HyperVInventory.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-HyperVInventory.ps1 -ComputerName HV01,HV02 -IncludeSnapshots -ExportCsv -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (Hyper-V PowerShell module on the machine running the script)
Permissions:  Hyper-V Administrators (or local admin) on each host; WinRM/WMI access for remote hosts
When to use:  Capacity planning, documenting a customer's virtual estate, or finding VMs with forgotten snapshots before maintenance.
Safety:       Read-only
Version:      1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [Alias('HyperVHosts')]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$CustomerName,

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeSnapshots,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeNetworks,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeStorage
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
$script:LogFile = Join-Path $outDir "Get-HyperVInventory_$stamp.log"
$htmlPath = Join-Path $outDir "Get-HyperVInventory_$stamp.html"
$csvPath  = Join-Path $outDir "Get-HyperVInventory_$stamp.csv"

function Get-VMDetail {
    param([string]$HostName)

    try {
        $VMs = Get-VM -ComputerName $HostName -ErrorAction Stop
    } catch {
        try {
            Import-Module Hyper-V -ErrorAction Stop
            $VMs = Get-VM -ComputerName $HostName
        } catch {
            Write-Log "Cannot connect to Hyper-V on $HostName (requires Hyper-V module or admin rights)" 'WARN'
            return @()
        }
    }

    if (-not $VMs) {
        Write-Log "No VMs found on $HostName"
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

foreach ($HvHost in $ComputerName) {
    Write-Log "Inventorying VMs on $HvHost..."
    $VMs = @(Get-VMDetail -HostName $HvHost)
    $AllVMs += $VMs
    Write-Log "Found $($VMs.Count) VMs on $HvHost"
}

$RunningVMs = @($AllVMs | Where-Object { $_.State -eq "Running" }).Count
$StoppedVMs = @($AllVMs | Where-Object { $_.State -eq "Off" }).Count
$TotalMemory = ($AllVMs | Where-Object { $_.State -eq "Running" } | Measure-Object -Property MemoryGB -Sum).Sum

Write-Log '=== Hyper-V Inventory Summary ==='
Write-Log "Total VMs: $($AllVMs.Count)"
Write-Log "Running: $RunningVMs"
Write-Log "Stopped: $StoppedVMs"
Write-Log "Total Allocated Memory: $TotalMemory GB"

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
    <strong>Hosts:</strong> $(@($ComputerName).Count) |
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

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "Report written: $htmlPath"

if ($ExportCsv) {
    $CsvData = $AllVMs | Select-Object HostName, VmName, State, CpuCount, MemoryGB, Uptime, Status, Generation, Version, SnapshotCount
    $CsvData | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV written: $csvPath"
}
