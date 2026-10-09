#Requires -Version 5.1
#Requires -Modules Az.Accounts, Az.Network

<#
.SYNOPSIS
Audits Azure network security group (NSG) rules for overly permissive access and rates each rule.

.DESCRIPTION
Walks every accessible subscription (or the ones you list) and reads all NSGs and their security rules.
Each rule is flagged when it allows traffic from any source, to any destination, on all ports, or with any
protocol, and is rated Low / Medium / High / Critical (Critical = inbound allow from Internet/any to all ports).
Default platform rules are skipped unless -IncludeDefaultRules is used.

Output is an HTML report (primary) with a summary and one row per rule, plus an optional CSV of the same data.
With -FlagHighRiskOnly only rules rated above Low are included. The script makes no changes to Azure.

.PARAMETER SubscriptionIds
Optional list of subscription ids to scan. Default: every subscription the signed-in account can see.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the findings to a CSV next to the HTML report.

.PARAMETER IncludeDefaultRules
Also analyse the built-in default NSG rules (AllowVnetInBound, etc.).

.PARAMETER FlagHighRiskOnly
Report only rules rated Medium, High or Critical.

.PARAMETER SkipAzConnect
Use the existing Az session instead of calling Connect-AzAccount.

.EXAMPLE
.\Get-AzureNsgRiskReport.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-AzureNsgRiskReport.ps1 -SubscriptionIds 00000000-0000-0000-0000-000000000000 -FlagHighRiskOnly -ExportCsv -CustomerName Contoso -OutputPath D:\Reports

.NOTES
Platform:     Windows (PowerShell 5.1+ with Az.Accounts and Az.Network modules)
Permissions:  Azure RBAC Reader on each subscription being scanned
When to use:  Security review of a new customer tenant, before a pen test, or to find RDP/SSH/any-any rules open to the Internet.
Safety:       Read-only
Version:      1.1
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionIds,

    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCsv,

    [switch]$IncludeDefaultRules,

    [switch]$FlagHighRiskOnly,

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
$htmlPath = Join-Path $outDir "Get-AzureNsgRiskReport_$stamp.html"
$csvPath  = Join-Path $outDir "Get-AzureNsgRiskReport_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-AzureNsgRiskReport_$stamp.log"

$Results = [System.Collections.Generic.List[PSObject]]::new()
$HighRiskRules = [System.Collections.Generic.List[PSObject]]::new()

function Connect-ToAzure {
    try {
        Connect-AzAccount -ErrorAction Stop | Out-Null
        Write-Log 'Connected to Azure.'
    } catch {
        Write-Log "Azure connection failed: $_" 'ERROR'
        throw
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

# -- MAIN --
Write-Log 'NSG audit (overly permissive rules) starting.'

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

    Write-Log "Scanning NSGs in: $SubName"

    try {
        $NSGs = Get-AzNetworkSecurityGroup -ErrorAction Stop
    } catch {
        Write-Log "Could not list NSGs in ${SubName}: $_" 'WARN'
        continue
    }

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
$CriticalCount = @($FinalResults | Where-Object { $_.Risk -eq "Critical" }).Count
$HighCount = @($FinalResults | Where-Object { $_.Risk -eq "High" }).Count
$MediumCount = @($FinalResults | Where-Object { $_.Risk -eq "Medium" }).Count

Write-Log "Summary: Total rules $($FinalResults.Count) | Critical $CriticalCount | High $HighCount | Medium $MediumCount"

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

$Html | Out-File -LiteralPath $htmlPath -Encoding UTF8
Write-Log "Report written: $htmlPath"

if ($ExportCsv) {
    $FinalResults | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV written: $csvPath"
}
