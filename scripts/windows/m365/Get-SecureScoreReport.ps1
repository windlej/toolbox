param(
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\SecureScoreReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeControlScores,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGraphConnect
)

$Results = @()
$ControlResults = @()

function Connect-ToGraph {
    if ($IncludeControlScores) {
        $scopes = @('SecurityEvents.Read.All')
    } else {
        $scopes = @('SecurityEvents.Read.All')
    }
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Host "Connected to Graph" -ForegroundColor Green
    } catch {
        throw "Graph auth failed: $_"
    }
}

function Get-SecureScoreData {
    $Scores = Get-MgSecuritySecureScore -All -ErrorAction Stop |
        Sort-Object CreatedDateTime -Descending |
        Select-Object -First 10

    return $Scores
}

function Get-ControlScores {
    param([string]$SecureScoreId)

    try {
        $Score = Get-MgSecuritySecureScore -SecureScoreId $SecureScoreId -ErrorAction Stop
        return $Score.ControlScores
    } catch {
        return @()
    }
}

function Invoke-SecureScoreApi {
    $Uri = "https://graph.microsoft.com/beta/security/secureScores?`$top=1&`$orderBy=createdDateTime desc"
    $Result = Invoke-MgGraphRequest -Uri $Uri -Method Get -ErrorAction Stop
    return $Result.value
}

function Invoke-ComplianceApi {
    $Uri = "https://graph.microsoft.com/beta/security/secureScoreControlProfiles"
    $Result = Invoke-MgGraphRequest -Uri $Uri -Method Get -ErrorAction Stop
    return $Result.value
}

# ── MAIN ──

Write-Host "=== Secure Score Reporting ===" -ForegroundColor Cyan

if (-not $SkipGraphConnect) {
    Connect-ToGraph
}

Write-Host "Retrieving Secure Score..." -ForegroundColor Yellow
$ScoreData = Invoke-SecureScoreApi

if (-not $ScoreData -or $ScoreData.Count -eq 0) {
    Write-Warning "No secure score data available. Ensure the tenant has appropriate licensing (Microsoft 365 E5 or security add-on)."
    return
}

$LatestScore = $ScoreData[0]

$CurrentScore = $LatestScore.currentScore
$MaxScore = $LatestScore.maxScore
$ScorePercent = if ($MaxScore -gt 0) { [math]::Round(($CurrentScore / $MaxScore) * 100, 1) } else { 0 }

Write-Host "Current Score: $CurrentScore / $MaxScore ($ScorePercent%)" -ForegroundColor Green
Write-Host "Date: $($LatestScore.createdDateTime)" -ForegroundColor Gray

$Results = [PSCustomObject]@{
    CurrentScore       = $CurrentScore
    MaxScore           = $MaxScore
    ScorePercent       = $ScorePercent
    CreatedDateTime    = $LatestScore.createdDateTime
    LicensedUsers      = $LatestScore.licensedUsers
    VendorInformation  = $LatestScore.vendorInformation
}

if ($IncludeControlScores) {
    Write-Host "Retrieving control profiles..." -ForegroundColor Yellow
    $ControlProfiles = Invoke-ComplianceApi

    Write-Host "Processing $($ControlProfiles.Count) controls..." -ForegroundColor Yellow
    $ControlResults = foreach ($Control in $ControlProfiles) {
        $Max = ($Control.maxScore -as [double])
        $Current = if ($Control.tenantScore) { ($Control.tenantScore -as [double]) } else { 0 }
        $Pct = if ($Max -gt 0) { [math]::Round(($Current / $Max) * 100, 1) } else { 0 }

        $Category = $Control.controlCategory
        $ControlName = $Control.displayName
        $ActionUrl = $Control.implementationUrl

        [PSCustomObject]@{
            ControlId       = $Control.id
            ControlName     = $ControlName
            Category        = $Category
            MaxScore        = $Max
            CurrentScore    = $Current
            ScorePercent    = $Pct
            State           = $Control.state
            ActionUrl       = $ActionUrl
            Tier            = $Control.tier
        }
    }

    $AvgCategory = $ControlResults | Group-Object Category | ForEach-Object {
        $Avg = [math]::Round(($_.Group | Measure-Object -Property ScorePercent -Average).Average, 1)
        [PSCustomObject]@{ Category = $_.Name; AverageScore = $Avg; ControlCount = $_.Count }
    } | Sort-Object AverageScore
}

Write-Host "`n=== Category Scores ===" -ForegroundColor Cyan
if ($IncludeControlScores) {
    $AvgCategory | ForEach-Object {
        Write-Host "$($_.Category.PadRight(20)) $($_.AverageScore)% ($($_.ControlCount) controls)" -ForegroundColor $(if ($_.AverageScore -lt 50) { "Red" } elseif ($_.AverageScore -lt 80) { "Yellow" } else { "Green" })
    }
}

$HtmlControlRows = if ($IncludeControlScores) {
    $ControlResults | Sort-Object ScorePercent | Select-Object -First 50 | ForEach-Object {
        $RowClass = if ($_.ScorePercent -lt 50) { "danger" }
        elseif ($_.ScorePercent -lt 80) { "warning" }
        else { "" }
        "<tr class='$RowClass'>
            <td>$($_.ControlName)</td>
            <td>$($_.Category)</td>
            <td>$($_.CurrentScore)/$($_.MaxScore)</td>
            <td>$($_.ScorePercent)%</td>
            <td>$($_.State)</td>
            <td>$($_.Tier)</td>
        </tr>"
    }
} else { @() }

$HtmlCategoryRows = if ($IncludeControlScores) {
    $AvgCategory | ForEach-Object {
        $RowClass = if ($_.AverageScore -lt 50) { "danger" }
        elseif ($_.AverageScore -lt 80) { "warning" }
        else { "" }
        "<tr class='$RowClass'>
            <td>$($_.Category)</td>
            <td>$($_.AverageScore)%</td>
            <td>$($_.ControlCount)</td>
        </tr>"
    }
} else { @() }

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Secure Score Report</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
h2 { color: #34495e; }
.score-box { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin: 20px 0; text-align: center; }
.score-box .number { font-size: 48px; font-weight: bold; }
.score-box .label { font-size: 16px; opacity: 0.9; }
table { border-collapse: collapse; width: 100%; font-size: 12px; margin: 10px 0; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 5px 8px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
.warning td { background: #fff3cd; }
</style></head>
<body>
<h1>Microsoft Secure Score Report</h1>
<div class='score-box'>
    <div class='number'>$CurrentScore / $MaxScore</div>
    <div class='label'>Secure Score ($ScorePercent%) — $(Get-Date -Format 'yyyy-MM-dd HH:mm')</div>
</div>
<div class='summary'>
    <strong>Licensed Users:</strong> $($LatestScore.licensedUsers) |
    <strong>Tenant:</strong> $($LatestScore.vendorInformation.vendorName) |
    <strong>Score Date:</strong> $($LatestScore.createdDateTime)
</div>

$(if ($IncludeControlScores) {
@"
<h2>Category Breakdown</h2>
<table>
<tr><th>Category</th><th>Average Score</th><th>Controls</th></tr>
$($HtmlCategoryRows -join "`n")
</table>

<h2>Top 50 Controls by Score (lowest first)</h2>
<table>
<tr><th>Control</th><th>Category</th><th>Score</th><th>%</th><th>State</th><th>Tier</th></tr>
$($HtmlControlRows -join "`n")
</table>
"@
})

</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvPath -and $IncludeControlScores) {
    $ControlResults | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}
