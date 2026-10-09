#Requires -Version 5.1
#Requires -Modules Az.Accounts, Az.Compute

<#
.SYNOPSIS
Inventories Azure virtual machines across subscriptions with an estimated monthly and annual cost.

.DESCRIPTION
For each accessible subscription (or the ones you list) the script reads every VM with its power state and
records name, resource group, region, size, OS type, attached managed disk size, tags and the NIC reference.
Cost is an ESTIMATE only: it uses a small built-in pay-as-you-go rate card (USD per month) for common sizes
and a rough per-core guess for others; deallocated or stopped VMs are costed at zero. It does not read actual
billing data.

Output is an HTML report (primary) sorted by estimated cost with running/stopped/OS totals, plus an optional CSV
with all columns. The script makes no changes to Azure.

.PARAMETER SubscriptionIds
Optional list of subscription ids to scan. Default: every subscription the signed-in account can see.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the full inventory to a CSV next to the HTML report.

.PARAMETER SkipAzConnect
Use the existing Az session instead of calling Connect-AzAccount.

.EXAMPLE
.\Get-AzureVMInventory.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-AzureVMInventory.ps1 -SubscriptionIds 00000000-0000-0000-0000-000000000000 -ExportCsv -CustomerName Contoso -OutputPath D:\Reports

.NOTES
Platform:     Windows (PowerShell 5.1+ with Az.Accounts and Az.Compute modules)
Permissions:  Azure RBAC Reader on each subscription being scanned
When to use:  Cloud estate discovery, right-sizing conversations, or finding stopped-but-not-deallocated VMs before a cost review.
Safety:       Read-only
Version:      1.1
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionIds,

    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCsv,

    [switch]$SkipAzConnect
)

Set-StrictMode -Version Latest

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
$htmlPath = Join-Path $outDir "Get-AzureVMInventory_$stamp.html"
$csvPath  = Join-Path $outDir "Get-AzureVMInventory_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-AzureVMInventory_$stamp.log"

$AllVMs = [System.Collections.Generic.List[PSObject]]::new()

function Connect-ToAzure {
    try {
        Connect-AzAccount -ErrorAction Stop | Out-Null
        Write-Log 'Connected to Azure.'
    } catch {
        Write-Log "Azure connection failed: $_" 'ERROR'
        throw
    }
}

function Get-VMCostEstimate {
    param([string]$VMSize, [string]$Region, [bool]$Running)

    $RateCard = @{
        'Standard_B1s' = 9.49; 'Standard_B2s' = 37.96; 'Standard_B2ms' = 75.92
        'Standard_B4ms' = 151.84; 'Standard_B8ms' = 303.68; 'Standard_B12ms' = 455.52
        'Standard_B16ms' = 607.36; 'Standard_B20ms' = 759.20
        'Standard_D2s_v3' = 70.08; 'Standard_D4s_v3' = 140.16; 'Standard_D8s_v3' = 280.32
        'Standard_D16s_v3' = 560.64; 'Standard_D32s_v3' = 1121.28; 'Standard_D64s_v3' = 2242.56
        'Standard_D2_v4' = 70.08; 'Standard_D4_v4' = 140.16; 'Standard_D8_v4' = 280.32
        'Standard_D16_v4' = 560.64; 'Standard_D32_v4' = 1121.28; 'Standard_D64_v4' = 2242.56
        'Standard_E2s_v3' = 140.16; 'Standard_E4s_v3' = 280.32; 'Standard_E8s_v3' = 560.64
        'Standard_E16s_v3' = 1121.28; 'Standard_E32s_v3' = 2242.56; 'Standard_E64s_v3' = 4485.12
        'Standard_E2_v4' = 140.16; 'Standard_E4_v4' = 280.32; 'Standard_E8_v4' = 560.64
        'Standard_E16_v4' = 1121.28; 'Standard_E32_v4' = 2242.56; 'Standard_E64_v4' = 4485.12
        'Standard_F2s_v2' = 84.10; 'Standard_F4s_v2' = 168.19; 'Standard_F8s_v2' = 336.38
        'Standard_F16s_v2' = 672.77; 'Standard_F32s_v2' = 1345.54; 'Standard_F64s_v2' = 2691.07
        'Standard_NC6s_v3' = 2635.20; 'Standard_NC12s_v3' = 5270.40; 'Standard_NC24s_v3' = 10540.80
        'Standard_NC24rs_v3' = 12648.96
    }

    if ($RateCard.ContainsKey($VMSize)) {
        $Monthly = $RateCard[$VMSize]
        if (-not $Running) { $Monthly = 0 }
        return $Monthly
    }

    $Base = $VMSize -replace '^Standard_', ''
    if ($Base -match '(\d+)') {
        $Cores = [int]$Matches[1]
        if ($VMSize -match 'E') { $Monthly = $Cores * 60 }
        elseif ($VMSize -match 'NC|ND|NV') { $Monthly = $Cores * 200 }
        elseif ($VMSize -match 'L') { $Monthly = $Cores * 45 }
        else { $Monthly = $Cores * 30 }
        if (-not $Running) { $Monthly = 0 }
        return $Monthly
    }

    return 0
}

# -- MAIN --
Write-Log 'Azure VM inventory and cost estimate starting.'

if (-not $SkipAzConnect) {
    Connect-ToAzure
}

if (-not $SubscriptionIds) {
    $Subscriptions = Get-AzSubscription -ErrorAction Stop
    $SubscriptionIds = $Subscriptions.Id
}

Write-Log "Scanning $(@($SubscriptionIds).Count) subscriptions..."

foreach ($SubId in $SubscriptionIds) {
    try {
        Set-AzContext -SubscriptionId $SubId -ErrorAction Stop | Out-Null
        $SubName = (Get-AzContext).Subscription.Name
    } catch {
        Write-Log "Cannot access subscription ${SubId}: $_" 'WARN'
        continue
    }

    Write-Log "  Subscription: $SubName ($SubId)"

    try {
        $VMs = Get-AzVM -Status -ErrorAction Stop
    } catch {
        Write-Log "Could not list VMs in ${SubName}: $_" 'WARN'
        continue
    }

    foreach ($VM in $VMs) {
        $Running = $VM.PowerState -eq "VM running"
        $MonthlyCost = Get-VMCostEstimate -VMSize $VM.HardwareProfile.VmSize -Region $VM.Location -Running $Running
        $AnnualCost = $MonthlyCost * 12

        $Disks = Get-AzDisk -ResourceGroupName $VM.ResourceGroupName -ErrorAction SilentlyContinue |
            Where-Object { $_.ManagedBy -match $VM.Id }
        $DiskSizeGB = ($Disks | Measure-Object -Property DiskSizeGB -Sum).Sum
        $OsType = $VM.StorageProfile.OsDisk.OsType
        $Tags = if ($VM.Tags) { ($VM.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ' } else { "" }

        $AllVMs.Add([PSCustomObject]@{
            SubscriptionName  = $SubName
            SubscriptionId    = $SubId
            ResourceGroupName = $VM.ResourceGroupName
            Name              = $VM.Name
            Location          = $VM.Location
            VMSize            = $VM.HardwareProfile.VmSize
            PowerState        = $VM.PowerState
            OsType            = $OsType
            DiskSizeGB        = $DiskSizeGB
            PrivateIP         = ($VM.NetworkProfile.NetworkInterfaces.Primary -join '; ')
            Tags              = $Tags
            MonthlyCostUSD    = $MonthlyCost
            AnnualCostUSD     = $AnnualCost
            Running           = $Running
        })
    }
}

$TotalVMs = $AllVMs.Count
$RunningCount = @($AllVMs | Where-Object { $_.Running }).Count
$StoppedCount = @($AllVMs | Where-Object { -not $_.Running }).Count
$TotalMonthlyCost = ($AllVMs | Measure-Object -Property MonthlyCostUSD -Sum).Sum
$TotalAnnualCost = ($AllVMs | Measure-Object -Property AnnualCostUSD -Sum).Sum
$WindowsCount = @($AllVMs | Where-Object { $_.OsType -eq "Windows" }).Count
$LinuxCount = @($AllVMs | Where-Object { $_.OsType -eq "Linux" }).Count

Write-Log "Summary: Total VMs $TotalVMs | Running $RunningCount | Stopped $StoppedCount | Windows $WindowsCount | Linux $LinuxCount"
Write-Log "Estimated cost: Monthly `$$([math]::Round($TotalMonthlyCost, 2)) | Annual `$$([math]::Round($TotalAnnualCost, 2))"

$HtmlRows = $AllVMs | Sort-Object MonthlyCostUSD -Descending | ForEach-Object {
    $RowClass = if (-not $_.Running) { "stopped" } else { "" }
    "<tr class='$RowClass'>
        <td>$($_.Name)</td>
        <td>$($_.SubscriptionName)</td>
        <td>$($_.ResourceGroupName)</td>
        <td>$($_.Location)</td>
        <td>$($_.VMSize)</td>
        <td>$($_.PowerState)</td>
        <td>$($_.OsType)</td>
        <td>`$$($_.MonthlyCostUSD)</td>
        <td>`$$($_.AnnualCostUSD)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Azure VM Inventory & Cost Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 11px; }
th { background: #2c3e50; color: white; padding: 6px; text-align: left; }
td { padding: 4px 6px; border-bottom: 1px solid #ddd; }
.stopped td { color: #999; }
</style></head>
<body>
<h1>Azure VM Inventory & Cost Estimator</h1>
<div class='summary'>
    <strong>Total VMs:</strong> $TotalVMs |
    <strong>Running:</strong> $RunningCount |
    <strong>Stopped:</strong> $StoppedCount |
    <strong>Windows:</strong> $WindowsCount |
    <strong>Linux:</strong> $LinuxCount |
    <strong>Monthly:</strong> `$$([math]::Round($TotalMonthlyCost, 2)) |
    <strong>Annual:</strong> `$$([math]::Round($TotalAnnualCost, 2))
</div>
<table>
<tr><th>VM Name</th><th>Subscription</th><th>RG</th><th>Region</th><th>Size</th><th>State</th><th>OS</th><th>Monthly</th><th>Annual</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "Report written: $htmlPath"

if ($ExportCsv) {
    $AllVMs | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV written: $csvPath"
}
