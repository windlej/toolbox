param(
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\AzureBackupCompliance_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

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

function Get-VMBackupStatus {
    param([string]$VMId)

    try {
        $Backup = Get-AzRecoveryServicesBackupItem -VaultId $null -ErrorAction SilentlyContinue
        return $null
    } catch { return $null }
}

# ── MAIN ──
Write-Host "=== Azure Backup Compliance Check ===" -ForegroundColor Cyan

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

    Write-Host "Checking subscription: $SubName" -ForegroundColor Yellow

    $Vaults = Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue
    $VaultNames = $Vaults | Select-Object -ExpandProperty Name

    $VMs = Get-AzVM -ErrorAction SilentlyContinue
    $ProtectedVMs = @()

    foreach ($Vault in $Vaults) {
        try {
            Set-AzRecoveryServicesVaultContext -Vault $Vault -ErrorAction Stop
            $ProtectedItems = Get-AzRecoveryServicesBackupItem -VaultId $Vault.ID -BackupManagementType AzureVM -WorkloadType AzureVM -ErrorAction SilentlyContinue
            foreach ($Item in $ProtectedItems) {
                $ProtectedVMs += $Item.VmName
            }
        } catch { }
    }

    foreach ($VM in $VMs) {
        $IsProtected = $ProtectedVMs -contains $VM.Name
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
            Set-AzRecoveryServicesVaultContext -Vault $Vault -ErrorAction Stop
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
        } catch { }
    }
}

$TotalVMs = ($Results | Where-Object { $_.Protectable -eq "Yes" }).Count
$ProtectedCount = ($Results | Where-Object { $_.BackupStatus -eq "Protected" }).Count
$UnprotectedCount = ($Results | Where-Object { $_.BackupStatus -eq "UNPROTECTED" }).Count
$ProtectionPercent = if ($TotalVMs -gt 0) { [math]::Round(($ProtectedCount / $TotalVMs) * 100, 1) } else { 0 }

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total VMs: $TotalVMs | Protected: $ProtectedCount | Unprotected: $UnprotectedCount | Coverage: $ProtectionPercent%"

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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $Results | Where-Object { $_.Protectable -eq "Yes" } | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}
