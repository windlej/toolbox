#Requires -Version 5.1
#Requires -Modules Az.Accounts, Az.Compute, Az.RecoveryServices

<#
.SYNOPSIS
Checks which Azure VMs are protected by Azure Backup (Recovery Services vaults).

.DESCRIPTION
For each accessible subscription (or the ones you list) the script lists all Recovery Services vaults and the
Azure VM backup items in them, then compares each item's source VM resource ID against every VM in the subscription. Each VM is marked
Protected or UNPROTECTED; vaults and their backup policy names are also recorded.

Output is an HTML report (primary) listing the VMs with coverage percentage, plus an optional CSV of the VM
rows. Matching is by VM resource ID, so same-named VMs in different resource groups are told apart. Vaults are
queried with -VaultId; the deprecated Set-AzRecoveryServicesVaultContext is not used. A vault whose backup items
cannot be read is logged as a warning (VMs may then show as UNPROTECTED). The script makes no changes to Azure.

.PARAMETER SubscriptionIds
Optional list of subscription ids to check. Default: every subscription the signed-in account can see.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the VM protection rows to a CSV next to the HTML report.

.PARAMETER SkipAzConnect
Use the existing Az session instead of calling Connect-AzAccount.

.EXAMPLE
.\Test-AzureBackupCompliance.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Test-AzureBackupCompliance.ps1 -SubscriptionIds 00000000-0000-0000-0000-000000000000 -ExportCsv -CustomerName Contoso -OutputPath D:\Reports

.NOTES
Platform:     Windows (PowerShell 5.1+ with Az.Accounts, Az.Compute and Az.RecoveryServices modules)
Permissions:  Azure RBAC Reader on the subscriptions plus Backup Reader on the Recovery Services vaults
When to use:  Disaster-recovery readiness review, or to prove backup coverage to an auditor or customer.
Safety:       Read-only
Version:      1.2
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
$htmlPath = Join-Path $outDir "Test-AzureBackupCompliance_$stamp.html"
$csvPath  = Join-Path $outDir "Test-AzureBackupCompliance_$stamp.csv"
$script:LogFile = Join-Path $outDir "Test-AzureBackupCompliance_$stamp.log"

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

# -- MAIN --
Write-Log 'Azure backup compliance check starting.'

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

    Write-Log "Checking subscription: $SubName"

    $Vaults = Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue

    try {
        $VMs = Get-AzVM -ErrorAction Stop
    } catch {
        Write-Log "Could not list VMs in ${SubName}: $_" 'WARN'
        continue
    }
    $ProtectedVMs = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($Vault in $Vaults) {
        try {
            $ProtectedItems = Get-AzRecoveryServicesBackupItem -VaultId $Vault.ID -BackupManagementType AzureVM -WorkloadType AzureVM -ErrorAction Stop
            foreach ($Item in $ProtectedItems) {
                # Match on the VM's ARM resource ID, not its name: names repeat across resource groups.
                $ItemVmId = $null
                foreach ($PropName in 'VirtualMachineId', 'SourceResourceId') {
                    $Prop = $Item.PSObject.Properties[$PropName]
                    if ($Prop -and $Prop.Value) { $ItemVmId = [string]$Prop.Value; break }
                }
                if ($ItemVmId) { [void]$ProtectedVMs.Add($ItemVmId.ToLowerInvariant()) }
            }
        } catch {
            Write-Log "Could not read backup items from vault $($Vault.Name): $_" 'WARN'
        }
    }

    foreach ($VM in $VMs) {
        $IsProtected = $ProtectedVMs.Contains(([string]$VM.Id).ToLowerInvariant())
        $Status = if ($IsProtected) { "Protected" } else { "UNPROTECTED" }

        $Results.Add([PSCustomObject]@{
            SubscriptionName = $SubName
            ResourceGroup    = $VM.ResourceGroupName
            VMName           = $VM.Name
            VMSize           = $VM.HardwareProfile.VmSize
            Location         = $VM.Location
            BackupStatus     = $Status
            Protectable      = "Yes"
        })
    }

    foreach ($Vault in $Vaults) {
        try {
            $Policy = Get-AzRecoveryServicesBackupProtectionPolicy -VaultId $Vault.ID -ErrorAction SilentlyContinue
            $PolicyName = if ($Policy) { $Policy.Name } else { "No Policy" }
            $Results.Add([PSCustomObject]@{
                SubscriptionName = $SubName
                ResourceGroup    = $Vault.ResourceGroupName
                VMName           = "[Vault] $($Vault.Name)"
                VMSize           = ""
                Location         = $Vault.Location
                BackupStatus     = "Vault Available: $PolicyName"
                Protectable      = ""
            })
        } catch {
            Write-Log "Could not read policies from vault $($Vault.Name): $_" 'WARN'
        }
    }
}

$TotalVMs = @($Results | Where-Object { $_.Protectable -eq "Yes" }).Count
$ProtectedCount = @($Results | Where-Object { $_.BackupStatus -eq "Protected" }).Count
$UnprotectedCount = @($Results | Where-Object { $_.BackupStatus -eq "UNPROTECTED" }).Count
$ProtectionPercent = if ($TotalVMs -gt 0) { [math]::Round(($ProtectedCount / $TotalVMs) * 100, 1) } else { 0 }

Write-Log "Summary: Total VMs $TotalVMs | Protected $ProtectedCount | Unprotected $UnprotectedCount | Coverage $ProtectionPercent%"

$HtmlRows = $Results | Where-Object { $_.Protectable -eq "Yes" } | Sort-Object BackupStatus, SubscriptionName | ForEach-Object {
    $RowClass = if ($_.BackupStatus -eq "UNPROTECTED") { "danger" } else { "" }
    "<tr class='$RowClass'>
        <td>$($_.SubscriptionName)</td>
        <td>$($_.VMName)</td>
        <td>$($_.ResourceGroup)</td>
        <td>$($_.VMSize)</td>
        <td>$($_.Location)</td>
        <td>$($_.BackupStatus)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Azure Backup Compliance Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 5px 8px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
</style></head>
<body>
<h1>Azure Backup Compliance Report</h1>
<div class='summary'>
    <strong>VMs:</strong> $TotalVMs |
    <strong>Protected:</strong> $ProtectedCount ($ProtectionPercent%) |
    <strong>Unprotected:</strong> <span style='color:red;'>$UnprotectedCount</span>
</div>
<table>
<tr><th>Subscription</th><th>VM Name</th><th>RG</th><th>Size</th><th>Region</th><th>Backup Status</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "Report written: $htmlPath"

if ($ExportCsv) {
    $Results | Where-Object { $_.Protectable -eq "Yes" } | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV written: $csvPath"
}
