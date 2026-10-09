param(
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\LicenseReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [int]$InactiveThresholdDays = 90,

    [Parameter(Mandatory = $false)]
    [switch]$ShowUnlicensedUsers,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGraphConnect
)

$Results = @()

function Connect-ToGraph {
    $scopes = @(
        'Organization.Read.All',
        'User.Read.All',
        'AuditLog.Read.All',
        'Directory.Read.All'
    )
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Host "Connected to Graph" -ForegroundColor Green
    } catch {
        throw "Graph auth failed: $_"
    }
}

function Get-LicenseDetail {
    $SubscribedSkus = Get-MgSubscribedSku -All -ErrorAction Stop

    $LicenseDetails = foreach ($Sku in $SubscribedSkus) {
        $EnabledCount = $Sku.PrepaidUnits.Enabled
        $ConsumedCount = $Sku.ConsumedUnits
        $AvailableCount = $EnabledCount - $ConsumedCount
        $CostPerUser = Get-EstimatedLicenseCost -SkuPartNumber $Sku.SkuPartNumber

        [PSCustomObject]@{
            SkuPartNumber      = $Sku.SkuPartNumber
            SkuId              = $Sku.SkuId
            DisplayName        = Get-LicenseDisplayName -SkuPartNumber $Sku.SkuPartNumber
            TotalLicenses      = $EnabledCount
            Assigned           = $ConsumedCount
            Available          = $AvailableCount
            UtilizationPercent = if ($EnabledCount -gt 0) { [math]::Round(($ConsumedCount / $EnabledCount) * 100, 1) } else { 0 }
            CostPerUserMonthly = $CostPerUser
            EstimatedMonthlyCost = [math]::Round($ConsumedCount * $CostPerUser, 2)
            Warning            = $AvailableCount -gt 10 -or $EnabledCount -eq 0
        }
    }

    return $LicenseDetails
}

function Get-LicenseDisplayName {
    param([string]$SkuPartNumber)
    $Names = @{
        'O365_BUSINESS_ESSENTIALS' = 'Microsoft 365 Business Basic'
        'O365_BUSINESS_PREMIUM' = 'Microsoft 365 Business Standard'
        'O365_BUSINESS' = 'Microsoft 365 Business'
        'SPB' = 'Microsoft 365 Business Premium'
        'ENTERPRISEPACK' = 'Office 365 E3'
        'ENTERPRISEPREMIUM' = 'Office 365 E5'
        'EMSPREMIUM' = 'Enterprise Mobility + Security E5'
        'M365EDU_A3_FACULTY' = 'Microsoft 365 A3 for Faculty'
        'M365EDU_A5_FACULTY' = 'Microsoft 365 A5 for Faculty'
        'POWER_BI_STANDARD' = 'Power BI Free'
        'POWER_BI_PRO' = 'Power BI Pro'
        'FLOW_FREE' = 'Power Automate Free'
        'VISIOCLIENT' = 'Visio Online Plan 1'
        'VISIOONLINE_PLAN2' = 'Visio Online Plan 2'
        'PROJECTPROFESSIONAL' = 'Project Online Professional'
        'PROJECTONLINE_PLAN_1' = 'Project Online Plan 1'
        'WIN_ENT_BASIC' = 'Windows 10/11 Enterprise E3'
        'WIN_ENT_E3' = 'Windows 10/11 Enterprise E3'
        'WIN_ENT_E5' = 'Windows 10/11 Enterprise E5'
    }
    if ($Names.ContainsKey($SkuPartNumber)) { return $Names[$SkuPartNumber] }
    return $SkuPartNumber
}

function Get-EstimatedLicenseCost {
    param([string]$SkuPartNumber)
    $Costs = @{
        'O365_BUSINESS_ESSENTIALS' = 6.00
        'O365_BUSINESS_PREMIUM' = 22.00
        'O365_BUSINESS' = 8.25
        'SPB' = 22.00
        'ENTERPRISEPACK' = 20.00
        'ENTERPRISEPREMIUM' = 35.00
        'EMSPREMIUM' = 14.00
        'M365EDU_A3_FACULTY' = 0
        'M365EDU_A5_FACULTY' = 0
        'POWER_BI_PRO' = 10.00
        'VISIOCLIENT' = 5.00
        'VISIOONLINE_PLAN2' = 15.00
        'PROJECTPROFESSIONAL' = 30.00
        'PROJECTONLINE_PLAN_1' = 10.00
        'WIN_ENT_E3' = 7.00
        'WIN_ENT_E5' = 14.00
    }
    if ($Costs.ContainsKey($SkuPartNumber)) { return $Costs[$SkuPartNumber] }
    return 0
}

function Get-LicenseHolders {
    param(
        [string]$SkuId,
        [int]$InactiveDays
    )

    $Users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, Department,
        JobTitle, SignInActivity, CreatedDateTime, AssignedLicenses -ErrorAction Stop

    $LicensedUsers = $Users | Where-Object {
        $_.AssignedLicenses.SkuId -contains $SkuId
    }

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

    return $Holders
}

# ── MAIN ──

Write-Host "=== License Optimization Report ===" -ForegroundColor Cyan

if (-not $SkipGraphConnect) {
    Connect-ToGraph
}

Write-Host "Analyzing license inventory..." -ForegroundColor Yellow
$LicenseDetails = Get-LicenseDetail

$TotalMonthlyCost = ($LicenseDetails | Measure-Object -Property EstimatedMonthlyCost -Sum).Sum
$TotalAssigned = ($LicenseDetails | Measure-Object -Property Assigned -Sum).Sum
$TotalAvailable = ($LicenseDetails | Measure-Object -Property Available -Sum).Sum

Write-Host "`n=== License Summary ===" -ForegroundColor Cyan
foreach ($Lic in $LicenseDetails | Sort-Object EstimatedMonthlyCost -Descending) {
    $Warn = if ($Lic.Available -gt 10 -or $Lic.UtilizationPercent -lt 50) { " << REVIEW" } else { "" }
    Write-Host "$($Lic.DisplayName) : $($Lic.Assigned)/$($Lic.TotalLicenses) assigned ($($Lic.UtilizationPercent)%) - `$$($Lic.EstimatedMonthlyCost)/mo$Warn" -ForegroundColor $(if ($Lic.Warning) { "Yellow" } else { "White" })
}

Write-Host "`nTotal monthly: `$$TotalMonthlyCost" -ForegroundColor Cyan
Write-Host "Total assigned: $TotalAssigned | Available: $TotalAvailable" -ForegroundColor White

$LicenseUsers = @()
foreach ($Lic in $LicenseDetails) {
    if ($Lic.Available -gt 5) {
        Write-Host "`nAnalyzing $($Lic.SkuPartNumber) holders for inactivity..." -ForegroundColor Yellow
        $Holders = Get-LicenseHolders -SkuId $Lic.SkuId -InactiveDays $InactiveThresholdDays
        $InactiveHolders = $Holders | Where-Object { $_.IsInactive }
        foreach ($Holder in $InactiveHolders) {
            $LicenseUsers += [PSCustomObject]@{
                SkuPartNumber      = $Lic.SkuPartNumber
                LicenseName        = $Lic.DisplayName
                UserPrincipalName  = $Holder.UserPrincipalName
                DisplayName        = $Holder.DisplayName
                Department         = $Holder.Department
                LastSignInDate     = $Holder.LastSignInDate
                DaysSinceSignIn    = $Holder.DaysSinceSignIn
                MonthlyCost        = $Lic.CostPerUserMonthly
            }
        }
    }
}

$InactiveSavings = ($LicenseUsers | Measure-Object -Property MonthlyCost -Sum).Sum

Write-Host "`nInactive user license cost: `$$InactiveSavings/mo" -ForegroundColor Yellow

$HtmlLicenseRows = $LicenseDetails | Sort-Object EstimatedMonthlyCost -Descending | ForEach-Object {
    $RowClass = if ($_.Warning) { "warning" } else { "" }
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

$(if ($LicenseUsers.Count -gt 0) {
@"
<h2>Potentially Inactive License Holders</h2>
<table>
<tr><th>User</th><th>Name</th><th>License</th><th>Department</th><th>Last Sign-In</th><th>Days Inactive</th><th>Monthly Cost</th></tr>
$($HtmlUserRows -join "`n")
</table>
"@
})

</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $LicenseDetails | Select-Object SkuPartNumber, DisplayName, TotalLicenses, Assigned, Available, UtilizationPercent, CostPerUserMonthly, EstimatedMonthlyCost |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}
