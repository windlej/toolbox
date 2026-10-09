#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
Reports the tenant's current Microsoft Secure Score, optionally with a per-control and per-category breakdown.

.DESCRIPTION
Reads the latest Microsoft Secure Score from the Microsoft Graph (beta) security API and writes an HTML
report with the current and maximum score and percentage. With -IncludeControlScores it also reads the
Secure Score control profiles, calculates the percentage achieved per control, averages them per category,
and lists the 50 lowest-scoring controls with their state and tier. An optional CSV contains the per-control
data (only available with -IncludeControlScores). This script is read-only. If no score data is returned,
no report is written.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the per-control data to a CSV. Only effective together with -IncludeControlScores.

.PARAMETER IncludeControlScores
Include per-control and per-category results in the report.

.PARAMETER SkipGraphConnect
Skip Connect-MgGraph (use when a Graph session with suitable scopes already exists).

.EXAMPLE
.\Get-SecureScoreReport.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-SecureScoreReport.ps1 -OutputPath D:\Reports -CustomerName Contoso -IncludeControlScores -ExportCsv

.NOTES
Platform:     Windows (PowerShell 5.1+ with Microsoft Graph PowerShell SDK)
Permissions:  Graph scope SecurityEvents.Read.All (Security Reader or Global Reader)
When to use:  Security posture review, baseline before a hardening project, or quarterly progress reporting.
Safety:       Read-only
Version:      1.1
#>
[CmdletBinding()]
param(
    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCsv,

    [switch]$IncludeControlScores,

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
$ReportPath     = Join-Path $outDir "Get-SecureScoreReport_$stamp.html"
$CsvPath        = Join-Path $outDir "Get-SecureScoreReport_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-SecureScoreReport_$stamp.log"

$ControlResults = @()
$AvgCategory = @()

function Connect-ToGraph {
    $scopes = @('SecurityEvents.Read.All')
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Log 'Connected to Graph'
    } catch {
        throw "Graph auth failed: $_"
    }
}

function Invoke-SecureScoreApi {
    $Uri = 'https://graph.microsoft.com/beta/security/secureScores?$top=1&$orderBy=createdDateTime desc'
    $Result = Invoke-MgGraphRequest -Uri $Uri -Method Get -ErrorAction Stop
    return $Result.value
}

function Invoke-ComplianceApi {
    $Uri = 'https://graph.microsoft.com/beta/security/secureScoreControlProfiles'
    $Result = Invoke-MgGraphRequest -Uri $Uri -Method Get -ErrorAction Stop
    return $Result.value
}

# -- MAIN --

try {
    Write-Log '=== Secure Score Reporting ==='

    if (-not $SkipGraphConnect) {
        Connect-ToGraph
    }

    Write-Log 'Retrieving Secure Score...'
    $ScoreData = @(Invoke-SecureScoreApi)

    if ($ScoreData.Count -eq 0 -or -not $ScoreData[0]) {
        Write-Log 'No secure score data available. Ensure the tenant has appropriate licensing (Microsoft 365 E5 or security add-on). No report written.' 'WARN'
        return
    }

    $LatestScore = $ScoreData[0]

    $CurrentScore = $LatestScore.currentScore
    $MaxScore = $LatestScore.maxScore
    $ScorePercent = if ($MaxScore -gt 0) { [math]::Round(($CurrentScore / $MaxScore) * 100, 1) } else { 0 }

    Write-Host "Current Score: $CurrentScore / $MaxScore ($ScorePercent%)" -ForegroundColor Green
    Write-Host "Date: $($LatestScore.createdDateTime)" -ForegroundColor Gray

    if ($IncludeControlScores) {
        Write-Log 'Retrieving control profiles...'
        $ControlProfiles = @(Invoke-ComplianceApi)

        Write-Log "Processing $($ControlProfiles.Count) controls..."
        $ControlResults = @(foreach ($Control in $ControlProfiles) {
            $Max = ($Control.maxScore -as [double])
            $Current = if ($Control.tenantScore) { ($Control.tenantScore -as [double]) } else { 0 }
            $Pct = if ($Max -gt 0) { [math]::Round(($Current / $Max) * 100, 1) } else { 0 }

            [PSCustomObject]@{
                ControlId    = $Control.id
                ControlName  = $Control.displayName
                Category     = $Control.controlCategory
                MaxScore     = $Max
                CurrentScore = $Current
                ScorePercent = $Pct
                State        = $Control.state
                ActionUrl    = $Control.implementationUrl
                Tier         = $Control.tier
            }
        })

        $AvgCategory = @($ControlResults | Group-Object Category | ForEach-Object {
            $Avg = [math]::Round(($_.Group | Measure-Object -Property ScorePercent -Average).Average, 1)
            [PSCustomObject]@{ Category = $_.Name; AverageScore = $Avg; ControlCount = $_.Count }
        } | Sort-Object AverageScore)
    }

    if ($IncludeControlScores) {
        Write-Host "`n=== Category Scores ===" -ForegroundColor Cyan
        $AvgCategory | ForEach-Object {
            Write-Host "$("$($_.Category)".PadRight(20)) $($_.AverageScore)% ($($_.ControlCount) controls)" -ForegroundColor $(if ($_.AverageScore -lt 50) { 'Red' } elseif ($_.AverageScore -lt 80) { 'Yellow' } else { 'Green' })
        }
    }

    $HtmlControlRows = @()
    $HtmlCategoryRows = @()
    if ($IncludeControlScores) {
        $HtmlControlRows = $ControlResults | Sort-Object ScorePercent | Select-Object -First 50 | ForEach-Object {
            $RowClass = if ($_.ScorePercent -lt 50) { 'danger' }
            elseif ($_.ScorePercent -lt 80) { 'warning' }
            else { '' }
            "<tr class='$RowClass'>
            <td>$($_.ControlName)</td>
            <td>$($_.Category)</td>
            <td>$($_.CurrentScore)/$($_.MaxScore)</td>
            <td>$($_.ScorePercent)%</td>
            <td>$($_.State)</td>
            <td>$($_.Tier)</td>
        </tr>"
        }

        $HtmlCategoryRows = $AvgCategory | ForEach-Object {
            $RowClass = if ($_.AverageScore -lt 50) { 'danger' }
            elseif ($_.AverageScore -lt 80) { 'warning' }
            else { '' }
            "<tr class='$RowClass'>
            <td>$($_.Category)</td>
            <td>$($_.AverageScore)%</td>
            <td>$($_.ControlCount)</td>
        </tr>"
        }
    }

    $ControlSection = ''
    if ($IncludeControlScores) {
        $ControlSection = @"
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
    }

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
    <div class='label'>Secure Score ($ScorePercent%) - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</div>
</div>
<div class='summary'>
    <strong>Licensed Users:</strong> $($LatestScore.licensedUsers) |
    <strong>Tenant:</strong> $($LatestScore.vendorInformation.vendorName) |
    <strong>Score Date:</strong> $($LatestScore.createdDateTime)
</div>

$ControlSection

</body></html>
"@

    $Html | Out-File -LiteralPath $ReportPath -Encoding UTF8
    Write-Log "Report: $ReportPath"

    if ($ExportCsv) {
        if ($IncludeControlScores) {
            $ControlResults | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
            Write-Log "CSV: $CsvPath"
        } else {
            Write-Log '-ExportCsv has no effect without -IncludeControlScores; no CSV written.' 'WARN'
        }
    }
}
catch {
    Write-Log "Secure score report failed: $_" 'ERROR'
    throw
}
