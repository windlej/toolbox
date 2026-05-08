param(
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\NSGAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDefaultRules,

    [Parameter(Mandatory = $false)]
    [switch]$FlagHighRiskOnly,

    [Parameter(Mandatory = $false)]
    [switch]$SkipAzConnect
)

$Results = [System.Collections.Generic.List[PSObject]]::new()
$HighRiskRules = [System.Collections.Generic.List[PSObject]]::new()

function Connect-ToAzure {
    try {
        if (-not (Get-Module Az.Network -ListAvailable -ErrorAction SilentlyContinue)) {
            Write-Warning "Az.Network module not found"
            return $false
        }
        Connect-AzAccount -ErrorAction Stop
        Write-Host "Connected to Azure" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Azure connection failed: $_"
        return $false
    }
}

function Test-RuleRisk {
    param(
        [PSObject]$Rule,
        [string]$Direction,
        [string]$NSGName,
        [string]$ResourceGroup
    )

    $Flags = @()

    $SourceAny = ($Rule.SourceAddressPrefix -contains "*" -or $Rule.SourceAddressPrefix -contains "Internet" -or $Rule.SourceAddressPrefix -contains "0.0.0.0/0")
    $DestAny = ($Rule.DestinationAddressPrefix -contains "*" -or $Rule.DestinationAddressPrefix -contains "0.0.0.0/0")
    $HighPorts = ($Rule.DestinationPortRange -contains "*" -or $Rule.DestinationPortRange -contains "0-65535" -or $Rule.DestinationPortRange -contains "1-65535")
    $AnyProtocol = ($Rule.Protocol -eq "*" -or $Rule.Protocol -eq "Any")
    $IsAllow = ($Rule.Access -eq "Allow")

    if ($SourceAny -and $IsAllow) { $Flags += "Allow-AnySource" }
    if ($DestAny -and $IsAllow) { $Flags += "Allow-AnyDest" }
    if ($HighPorts -and $IsAllow) { $Flags += "Allow-AllPorts" }
    if ($AnyProtocol -and $SourceAny -and $IsAllow) { $Flags += "Allow-AnyProtocol" }

    if ($SourceAny -and $HighPorts -and $IsAllow -and $Direction -eq "Inbound") {
        $Flags += "CRITICAL: Internet-to-AllPorts"
    }

    $Risk = "Low"
    if ($Flags -match "CRITICAL") { $Risk = "Critical" }
    elseif ($Flags.Count -ge 2) { $Risk = "High" }
    elseif ($Flags.Count -ge 1) { $Risk = "Medium" }

    return @{ Risk = $Risk; Flags = $Flags }
}

# ── MAIN ──
Write-Host "=== NSG Audit (Overly Permissive Rules) ===" -ForegroundColor Cyan

if (-not $SkipAzConnect) {
    Connect-ToAzure
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

    Write-Host "Scanning NSGs in: $SubName" -ForegroundColor Yellow

    $NSGs = Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue

    foreach ($NSG in $NSGs) {
        $Rules = @()
        $Rules += $NSG.SecurityRules
        if ($IncludeDefaultRules) {
            $Rules += $NSG.DefaultSecurityRules
        }

        foreach ($Rule in $Rules) {
            if ($FlagHighRiskOnly) {
                $Analysis = Test-RuleRisk -Rule $Rule -Direction $Rule.Direction -NSGName $NSG.Name -ResourceGroup $NSG.ResourceGroupName
                if ($Analysis.Risk -ne "Low") {
                    $HighRiskRules.Add([PSCustomObject]@{
                        Subscription         = $SubName
                        ResourceGroup        = $NSG.ResourceGroupName
                        NSGName              = $NSG.Name
                        RuleName             = $Rule.Name
                        Direction            = $Rule.Direction
                        Access               = $Rule.Access
                        Priority             = $Rule.Priority
                        Protocol             = $Rule.Protocol
                        SourceAddressPrefix  = ($Rule.SourceAddressPrefix -join ', ')
                        SourcePortRange      = ($Rule.SourcePortRange -join ', ')
                        DestinationAddressPrefix = ($Rule.DestinationAddressPrefix -join ', ')
                        DestinationPortRange = ($Rule.DestinationPortRange -join ', ')
                        Description          = $Rule.Description
                        Risk                 = $Analysis.Risk
                        RiskFlags            = ($Analysis.Flags -join '; ')
                    })
                }
            } else {
                $Analysis = Test-RuleRisk -Rule $Rule -Direction $Rule.Direction -NSGName $NSG.Name -ResourceGroup $NSG.ResourceGroupName
                $Results.Add([PSCustomObject]@{
                    Subscription         = $SubName
                    ResourceGroup        = $NSG.ResourceGroupName
                    NSGName              = $NSG.Name
                    RuleName             = $Rule.Name
                    Direction            = $Rule.Direction
                    Access               = $Rule.Access
                    Priority             = $Rule.Priority
                    Protocol             = $Rule.Protocol
                    SourceAddressPrefix  = ($Rule.SourceAddressPrefix -join ', ')
                    DestinationPortRange = ($Rule.DestinationPortRange -join ', ')
                    Description          = $Rule.Description
                    Risk                 = $Analysis.Risk
                    RiskFlags            = ($Analysis.Flags -join '; ')
                })
            }
        }
    }
}

$FinalResults = if ($FlagHighRiskOnly) { $HighRiskRules } else { $Results }
$CriticalCount = ($FinalResults | Where-Object { $_.Risk -eq "Critical" }).Count
$HighCount = ($FinalResults | Where-Object { $_.Risk -eq "High" }).Count
$MediumCount = ($FinalResults | Where-Object { $_.Risk -eq "Medium" }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total Rules: $($FinalResults.Count)" -ForegroundColor White
Write-Host "Critical: $CriticalCount" -ForegroundColor Red
Write-Host "High: $HighCount" -ForegroundColor Red
Write-Host "Medium: $MediumCount" -ForegroundColor Yellow

$HtmlRows = $FinalResults | Sort-Object Risk, Priority | ForEach-Object {
    $RowClass = switch ($_.Risk) {
        "Critical" { "danger" }
        "High" { "danger" }
        "Medium" { "warning" }
        default { "" }
    }
    "<tr class='$RowClass'>
        <td>$($_.Subscription)</td>
        <td>$($_.NSGName)</td>
        <td>$($_.RuleName)</td>
        <td>$($_.Direction)</td>
        <td>$($_.Access)</td>
        <td>$($_.SourceAddressPrefix)</td>
        <td>$($_.DestinationPortRange)</td>
        <td>$($_.Risk)</td>
        <td>$($_.RiskFlags)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>NSG Audit Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 11px; }
th { background: #2c3e50; color: white; padding: 6px; text-align: left; }
td { padding: 4px 6px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
.warning td { background: #fff3cd; }
</style></head>
<body>
<h1>NSG Audit - Overly Permissive Rules</h1>
<div class='summary'>
    <strong>Rules Analyzed:</strong> $($FinalResults.Count) |
    <strong>Critical:</strong> <span style='color:red;'>$CriticalCount</span> |
    <strong>High:</strong> <span style='color:red;'>$HighCount</span> |
    <strong>Medium:</strong> <span style='color:orange;'>$MediumCount</span>
</div>
<table>
<tr><th>Subscription</th><th>NSG</th><th>Rule</th><th>Direction</th><th>Access</th><th>Source</th><th>Dest Ports</th><th>Risk</th><th>Flags</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $FinalResults | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}
