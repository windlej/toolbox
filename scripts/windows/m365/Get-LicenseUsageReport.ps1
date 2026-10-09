#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
Reports Microsoft 365 license inventory, utilization, estimated cost and inactive license holders.

.DESCRIPTION
Lists every subscribed SKU with purchased, assigned and available units, utilization percentage and an
estimated monthly cost (from a built-in approximate price table; unknown SKUs are costed at 0). For SKUs with
more than 5 unassigned licenses it also finds users holding that license who have not signed in within the
inactivity threshold (or never signed in and were created more than 30 days ago), and totals the potential
monthly saving. The output is an HTML report (primary) with the inventory and the inactive-holder list, plus
an optional CSV of the license inventory. This script is read-only.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the license inventory to a CSV next to the HTML report.

.PARAMETER InactiveThresholdDays
Days without a sign-in after which a license holder is considered inactive. Default 90.

.PARAMETER ShowUnlicensedUsers
Reserved. Currently has no effect on the output.

.PARAMETER SkipGraphConnect
Skip Connect-MgGraph (use when a Graph session with suitable scopes already exists).

.EXAMPLE
.\Get-LicenseUsageReport.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-LicenseUsageReport.ps1 -OutputPath D:\Reports -CustomerName Contoso -InactiveThresholdDays 60 -ExportCsv

.NOTES
Platform:     Windows (PowerShell 5.1+ with Microsoft Graph PowerShell SDK)
Permissions:  Graph scopes Organization.Read.All, User.Read.All, AuditLog.Read.All, Directory.Read.All (Global Reader or License Administrator)
When to use:  Before a license true-up or renewal, or to find paid licenses held by users who no longer sign in.
Safety:       Read-only
Version:      1.1
#>
[CmdletBinding()]
param(
    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCsv,

    [int]$InactiveThresholdDays = 90,

    [switch]$ShowUnlicensedUsers,

    [switch]$SkipGraphConnect
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

$stamp          = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir         = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$ReportPath     = Join-Path $outDir "Get-LicenseUsageReport_$stamp.html"
$CsvPath        = Join-Path $outDir "Get-LicenseUsageReport_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-LicenseUsageReport_$stamp.log"

function Connect-ToGraph {
    $scopes = @(
        'Organization.Read.All',
        'User.Read.All',
        'AuditLog.Read.All',
        'Directory.Read.All'
    )
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Log 'Connected to Graph'
    } catch {
        throw "Graph auth failed: $_"
    }
}

function Get-LicenseDetail {
    $SubscribedSkus = @(Get-MgSubscribedSku -All -ErrorAction Stop)

    $LicenseDetails = foreach ($Sku in $SubscribedSkus) {
        $EnabledCount = $Sku.PrepaidUnits.Enabled
        $ConsumedCount = $Sku.ConsumedUnits
        $AvailableCount = $EnabledCount - $ConsumedCount
        $CostPerUser = Get-EstimatedLicenseCost -SkuPartNumber $Sku.SkuPartNumber

        [PSCustomObject]@{
            SkuPartNumber        = $Sku.SkuPartNumber
            SkuId                = $Sku.SkuId
            DisplayName          = Get-LicenseDisplayName -SkuPartNumber $Sku.SkuPartNumber
            TotalLicenses        = $EnabledCount
            Assigned             = $ConsumedCount
            Available            = $AvailableCount
            UtilizationPercent   = if ($EnabledCount -gt 0) { [math]::Round(($ConsumedCount / $EnabledCount) * 100, 1) } else { 0 }
            CostPerUserMonthly   = $CostPerUser
            EstimatedMonthlyCost = [math]::Round($ConsumedCount * $CostPerUser, 2)
            Warning              = $AvailableCount -gt 10 -or $EnabledCount -eq 0
        }
    }

    return @($LicenseDetails)
}

function Get-LicenseDisplayName {
    param([string]$SkuPartNumber)
    $Names = @{
        'O365_BUSINESS_ESSENTIALS' = 'Microsoft 365 Business Basic'
        'O365_BUSINESS_PREMIUM'    = 'Microsoft 365 Business Standard'
        'O365_BUSINESS'            = 'Microsoft 365 Business'
        'SPB'                      = 'Microsoft 365 Business Premium'
        'ENTERPRISEPACK'           = 'Office 365 E3'
        'ENTERPRISEPREMIUM'        = 'Office 365 E5'
        'EMSPREMIUM'               = 'Enterprise Mobility + Security E5'
        'M365EDU_A3_FACULTY'       = 'Microsoft 365 A3 for Faculty'
        'M365EDU_A5_FACULTY'       = 'Microsoft 365 A5 for Faculty'
        'POWER_BI_STANDARD'        = 'Power BI Free'
        'POWER_BI_PRO'             = 'Power BI Pro'
        'FLOW_FREE'                = 'Power Automate Free'
        'VISIOCLIENT'              = 'Visio Online Plan 1'
        'VISIOONLINE_PLAN2'        = 'Visio Online Plan 2'
        'PROJECTPROFESSIONAL'      = 'Project Online Professional'
        'PROJECTONLINE_PLAN_1'     = 'Project Online Plan 1'
        'WIN_ENT_BASIC'            = 'Windows 10/11 Enterprise E3'
        'WIN_ENT_E3'               = 'Windows 10/11 Enterprise E3'
        'WIN_ENT_E5'               = 'Windows 10/11 Enterprise E5'
    }
    if ($Names.ContainsKey($SkuPartNumber)) { return $Names[$SkuPartNumber] }
    return $SkuPartNumber
}

function Get-EstimatedLicenseCost {
    param([string]$SkuPartNumber)
    $Costs = @{
        'O365_BUSINESS_ESSENTIALS' = 6.00
        'O365_BUSINESS_PREMIUM'    = 22.00
        'O365_BUSINESS'            = 8.25
        'SPB'                      = 22.00
        'ENTERPRISEPACK'           = 20.00
        'ENTERPRISEPREMIUM'        = 35.00
        'EMSPREMIUM'               = 14.00
        'M365EDU_A3_FACULTY'       = 0
        'M365EDU_A5_FACULTY'       = 0
        'POWER_BI_PRO'             = 10.00
        'VISIOCLIENT'              = 5.00
        'VISIOONLINE_PLAN2'        = 15.00
        'PROJECTPROFESSIONAL'      = 30.00
        'PROJECTONLINE_PLAN_1'     = 10.00
        'WIN_ENT_E3'               = 7.00
        'WIN_ENT_E5'               = 14.00
    }
    if ($Costs.ContainsKey($SkuPartNumber)) { return $Costs[$SkuPartNumber] }
    return 0
}

function Get-LicenseHolders {
    param(
        [string]$SkuId,
        [int]$InactiveDays
    )

    $Users = @(Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, Department,
        JobTitle, SignInActivity, CreatedDateTime, AssignedLicenses -ErrorAction Stop)

    $LicensedUsers = @($Users | Where-Object {
        $_.AssignedLicenses.SkuId -contains $SkuId
    })

    $Holders = foreach ($User in $LicensedUsers) {
        $LastSignIn = $User.SignInActivity.LastSignInDateTime
        $DaysSinceSignIn = if ($LastSignIn) {
            [math]::Round(((Get-Date) - $LastSignIn).TotalDays)
        } else { $null }

        $IsInactive = ($DaysSinceSignIn -ge $InactiveDays) -or (-not $LastSignIn -and ($User.CreatedDateTime -and ((Get-Date) - $User.CreatedDateTime).TotalDays -gt 30))

        [PSCustomObject]@{
            UserPrincipalName = $User.UserPrincipalName
            DisplayName       = $User.DisplayName
            Department        = $User.Department
            JobTitle          = $User.JobTitle
            LastSignInDate    = $LastSignIn
            DaysSinceSignIn   = $DaysSinceSignIn
            IsInactive        = $IsInactive
        }
    }

    return @($Holders)
}

# -- MAIN --

try {
    Write-Log '=== License Optimization Report ==='

    if (-not $SkipGraphConnect) {
        Connect-ToGraph
    }

    Write-Log 'Analyzing license inventory...'
    $LicenseDetails = Get-LicenseDetail

    $TotalMonthlyCost = [double](($LicenseDetails | Measure-Object -Property EstimatedMonthlyCost -Sum).Sum)
    $TotalAssigned    = [int](($LicenseDetails | Measure-Object -Property Assigned -Sum).Sum)
    $TotalAvailable   = [int](($LicenseDetails | Measure-Object -Property Available -Sum).Sum)

    Write-Host "`n=== License Summary ===" -ForegroundColor Cyan
    foreach ($Lic in @($LicenseDetails | Sort-Object EstimatedMonthlyCost -Descending)) {
        $Warn = if ($Lic.Available -gt 10 -or $Lic.UtilizationPercent -lt 50) { ' << REVIEW' } else { '' }
        Write-Host "$($Lic.DisplayName) : $($Lic.Assigned)/$($Lic.TotalLicenses) assigned ($($Lic.UtilizationPercent)%) - `$$($Lic.EstimatedMonthlyCost)/mo$Warn" -ForegroundColor $(if ($Lic.Warning) { 'Yellow' } else { 'White' })
    }

    Write-Host "`nTotal monthly: `$$TotalMonthlyCost" -ForegroundColor Cyan
    Write-Host "Total assigned: $TotalAssigned | Available: $TotalAvailable" -ForegroundColor White

    $LicenseUsers = @()
    foreach ($Lic in $LicenseDetails) {
        if ($Lic.Available -gt 5) {
            Write-Log "Analyzing $($Lic.SkuPartNumber) holders for inactivity..."
            $Holders = Get-LicenseHolders -SkuId $Lic.SkuId -InactiveDays $InactiveThresholdDays
            $InactiveHolders = @($Holders | Where-Object { $_.IsInactive })
            foreach ($Holder in $InactiveHolders) {
                $LicenseUsers += [PSCustomObject]@{
                    SkuPartNumber     = $Lic.SkuPartNumber
                    LicenseName       = $Lic.DisplayName
                    UserPrincipalName = $Holder.UserPrincipalName
                    DisplayName       = $Holder.DisplayName
                    Department        = $Holder.Department
                    LastSignInDate    = $Holder.LastSignInDate
                    DaysSinceSignIn   = $Holder.DaysSinceSignIn
                    MonthlyCost       = $Lic.CostPerUserMonthly
                }
            }
        }
    }

    $InactiveSavings = [double](($LicenseUsers | Measure-Object -Property MonthlyCost -Sum).Sum)

    Write-Host "`nInactive user license cost: `$$InactiveSavings/mo" -ForegroundColor Yellow

    $HtmlLicenseRows = $LicenseDetails | Sort-Object EstimatedMonthlyCost -Descending | ForEach-Object {
        $RowClass = if ($_.Warning) { 'warning' } else { '' }
        "<tr class='$RowClass'>
        <td>$($_.DisplayName)</td>
        <td>$($_.SkuPartNumber)</td>
        <td>$($_.TotalLicenses)</td>
        <td>$($_.Assigned)</td>
        <td>$($_.Available)</td>
        <td>$($_.UtilizationPercent)%</td>
        <td>`$$($_.CostPerUserMonthly)</td>
        <td>`$$($_.EstimatedMonthlyCost)</td>
    </tr>"
    }

    $HtmlUserRows = $LicenseUsers | Sort-Object SkuPartNumber | ForEach-Object {
        "<tr class='warning'>
        <td>$($_.UserPrincipalName)</td>
        <td>$($_.DisplayName)</td>
        <td>$($_.LicenseName)</td>
        <td>$($_.Department)</td>
        <td>$($_.LastSignInDate)</td>
        <td>$($_.DaysSinceSignIn)</td>
        <td>`$$($_.MonthlyCost)</td>
    </tr>"
    }

    $UserSection = ''
    if ($LicenseUsers.Count -gt 0) {
        $UserSection = @"
<h2>Potentially Inactive License Holders</h2>
<table>
<tr><th>User</th><th>Name</th><th>License</th><th>Department</th><th>Last Sign-In</th><th>Days Inactive</th><th>Monthly Cost</th></tr>
$($HtmlUserRows -join "`n")
</table>
"@
    }

    $Html = @"
<!DOCTYPE html>
<html>
<head><title>License Optimization Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
h2 { color: #34495e; }
.summary { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 12px; margin: 10px 0; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 5px 8px; border-bottom: 1px solid #ddd; }
.warning td { background: #fff3cd; }
.cost { font-weight: bold; }
</style></head>
<body>
<h1>License Optimization Report</h1>
<div class='summary'>
    <strong>Total Monthly Cost:</strong> `$$($TotalMonthlyCost.ToString('N2')) |
    <strong>Total Assigned:</strong> $TotalAssigned |
    <strong>Total Available:</strong> $TotalAvailable |
    <strong>Inactive Cost Savings:</strong> <span style='color:orange;'>`$$($InactiveSavings.ToString('N2'))/mo</span> |
    <strong>Inactivity Threshold:</strong> $InactiveThresholdDays days
</div>

<h2>License Inventory</h2>
<table>
<tr><th>License</th><th>SKU</th><th>Total</th><th>Assigned</th><th>Available</th><th>Utilization</th><th>Cost/User</th><th>Monthly Cost</th></tr>
$($HtmlLicenseRows -join "`n")
</table>

$UserSection

</body></html>
"@

    $Html | Out-File -LiteralPath $ReportPath -Encoding UTF8
    Write-Log "Report: $ReportPath"

    if ($ExportCsv) {
        $LicenseDetails | Select-Object SkuPartNumber, DisplayName, TotalLicenses, Assigned, Available, UtilizationPercent, CostPerUserMonthly, EstimatedMonthlyCost |
            Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Log "CSV: $CsvPath"
    }
}
catch {
    Write-Log "License usage report failed: $_" 'ERROR'
    throw
}
