#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users

<#
.SYNOPSIS
Reports Entra ID Protection risk detections for a recent time window.

.DESCRIPTION
Queries Microsoft Graph Identity Protection risk detections for the last N hours, filters them by risk level
and enriches each one with the affected user's name and department. With -IncludeDetails it also pulls the
user's most recent sign-in (client app, operating system and browser). The output is an HTML report (primary)
with a summary (high, medium and low counts, unique users, top event types) and one row per detection, plus
an optional CSV of the same data. Requires Entra ID P2 licensing for Identity Protection data. This script is
read-only. If no detections are found, no report is written.

.PARAMETER HoursBack
How many hours back to look for risk detections. Default 72.

.PARAMETER RiskLevel
Comma-separated risk levels to include (low, medium, high), or "all". Default "low,medium,high".

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCsv
Also write the detections to a CSV next to the HTML report.

.PARAMETER IncludeDetails
Also retrieve each affected user's most recent sign-in (slower; one extra call per detection).

.PARAMETER SkipGraphConnect
Skip Connect-MgGraph (use when a Graph session with suitable scopes already exists).

.EXAMPLE
.\Get-RiskySignInReport.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-RiskySignInReport.ps1 -OutputPath D:\Reports -CustomerName Fabrikam -HoursBack 168 -RiskLevel "medium,high" -IncludeDetails -ExportCsv

.NOTES
Platform:     Windows (PowerShell 5.1+ with Microsoft Graph PowerShell SDK)
Permissions:  Graph scopes IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All, AuditLog.Read.All, User.Read.All (Security Reader or Global Reader); Entra ID P2 licensing
When to use:  After a suspected account compromise, or as a routine weekly review of risky sign-ins.
Safety:       Read-only
Version:      1.1
#>
[CmdletBinding()]
param(
    [int]$HoursBack = 72,

    [string]$RiskLevel = 'low,medium,high',

    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCsv,

    [switch]$IncludeDetails,

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
$ReportPath     = Join-Path $outDir "Get-RiskySignInReport_$stamp.html"
$CsvPath        = Join-Path $outDir "Get-RiskySignInReport_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-RiskySignInReport_$stamp.log"

$Results = [System.Collections.Generic.List[PSObject]]::new()

function Connect-ToGraph {
    $scopes = @(
        'IdentityRiskyUser.Read.All',
        'IdentityRiskEvent.Read.All',
        'AuditLog.Read.All',
        'User.Read.All'
    )
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Log 'Connected to Graph'
    } catch {
        throw "Graph auth failed: $_"
    }
}

function Get-RiskyUsersViaApi {
    param([string]$RiskLevel)

    $Filter = "riskLevel ne 'none'"
    if ($RiskLevel -ne 'all') {
        $Levels = $RiskLevel -split ','
        $LevelFilter = ($Levels | ForEach-Object { "riskLevel eq '$_'" }) -join ' or '
        $Filter = "($LevelFilter)"
    }

    $Uri = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=$Filter&`$top=100"
    $AllRisky = @()
    $Response = $null

    try {
        while ($true) {
            $Response = Invoke-MgGraphRequest -Uri $Uri -Method Get -ErrorAction Stop
            $AllRisky += $Response.value
            $Uri = $Response.'@odata.nextLink'
            if (-not $Uri) { break }
        }
    } catch {
        Write-Log "Risky users query failed (API may require premium licensing): $_" 'WARN'
        return @()
    }

    return $AllRisky
}

function Get-RiskDetectionsViaApi {
    param([int]$HoursBack)

    $StartTime = (Get-Date).AddHours(-$HoursBack).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    $Uri = "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$filter=detectedDateTime ge $StartTime&`$top=100&`$orderBy=detectedDateTime desc"
    $AllDetections = @()
    $Response = $null

    try {
        while ($true) {
            $Response = Invoke-MgGraphRequest -Uri $Uri -Method Get -ErrorAction Stop
            $AllDetections += $Response.value
            $Uri = $Response.'@odata.nextLink'
            if (-not $Uri) { break }
        }
    } catch {
        Write-Log "Risk detections query failed: $_" 'WARN'
        return @()
    }

    Write-Log "Found $(@($AllDetections).Count) risk detections"
    return $AllDetections
}

function Get-UserDetail {
    param([string]$UserId)
    try {
        $User = Get-MgUser -UserId $UserId -Property DisplayName, UserPrincipalName,
            Department, JobTitle, UserType -ErrorAction SilentlyContinue
        return $User
    } catch { return $null }
}

function Get-SignInLogsForUser {
    param([string]$UserId, [int]$HoursBack)

    $StartTime = (Get-Date).AddHours(-$HoursBack).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    $Uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=userId eq '$UserId' and createdDateTime ge $StartTime&`$top=25&`$orderBy=createdDateTime desc"

    try {
        $Response = Invoke-MgGraphRequest -Uri $Uri -Method Get -ErrorAction Stop
        return $Response.value
    } catch {
        Write-Log "Sign-in log query failed for user $UserId : $_" 'WARN'
        return @()
    }
}

# -- MAIN --

try {
    Write-Log '=== Risky Sign-In Log Parser ==='
    Write-Log "Period: Last $HoursBack hours | Risk Level: $RiskLevel"

    if (-not $SkipGraphConnect) {
        Connect-ToGraph
    }

    Write-Log 'Retrieving risk detections...'
    $Detections = @(Get-RiskDetectionsViaApi -HoursBack $HoursBack)

    if ($Detections.Count -eq 0) {
        Write-Log 'No risk detections found in the specified period. No report written.'
        return
    }

    $RiskLevels = $RiskLevel -split ','
    $Detections = @($Detections | Where-Object { $_.riskLevel -in $RiskLevels -or $RiskLevel -eq 'all' })

    foreach ($Detection in $Detections) {
        $UserDetail = Get-UserDetail -UserId $Detection.userId

        $Result = [PSCustomObject]@{
            DetectedDateTime  = $Detection.detectedDateTime
            UserId            = $Detection.userId
            UserPrincipalName = if ($UserDetail) { $UserDetail.UserPrincipalName } else { 'Unknown' }
            DisplayName       = if ($UserDetail) { $UserDetail.DisplayName } else { 'Unknown' }
            Department        = if ($UserDetail) { $UserDetail.Department } else { '' }
            RiskLevel         = $Detection.riskLevel
            RiskType          = $Detection.riskType
            RiskEventType     = $Detection.riskEventType
            AdditionalInfo    = $Detection.additionalInfo
            Source            = $Detection.source
            TokenIssuerType   = $Detection.tokenIssuerType
            Activity          = $Detection.activity
            ActivityDateTime  = $Detection.activityDateTime
            IpAddress         = $Detection.ipAddress
            Location          = "$($Detection.location.city), $($Detection.location.state), $($Detection.location.countryOrRegion)"
            UserAgent         = $Detection.userAgent
            RiskDetail        = $Detection.riskDetail
        }

        if ($IncludeDetails -and $UserDetail) {
            $SignIns = @(Get-SignInLogsForUser -UserId $Detection.userId -HoursBack $HoursBack)
            if ($SignIns.Count -gt 0) {
                $RecentSignIn = $SignIns[0]
                $Result | Add-Member -NotePropertyName 'LastSignInClientApp' -NotePropertyValue $RecentSignIn.clientAppUsed
                $Result | Add-Member -NotePropertyName 'LastSignInDevice' -NotePropertyValue "$($RecentSignIn.deviceDetail.operatingSystem) - $($RecentSignIn.deviceDetail.browser)"
            }
        }

        $Results.Add($Result)
    }

    $HighCount   = @($Results | Where-Object { $_.RiskLevel -eq 'high' }).Count
    $MediumCount = @($Results | Where-Object { $_.RiskLevel -eq 'medium' }).Count
    $LowCount    = @($Results | Where-Object { $_.RiskLevel -eq 'low' }).Count
    $UniqueUsers = @($Results | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
    $TopRisks    = @($Results | Group-Object RiskEventType | Sort-Object Count -Descending | Select-Object -First 10)

    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total Risk Events: $($Results.Count)" -ForegroundColor White
    Write-Host "  High: $HighCount" -ForegroundColor Red
    Write-Host "  Medium: $MediumCount" -ForegroundColor Yellow
    Write-Host "  Low: $LowCount" -ForegroundColor Gray
    Write-Host "Unique Users Affected: $UniqueUsers" -ForegroundColor Yellow
    Write-Host "`nTop Risk Event Types:" -ForegroundColor Cyan
    $TopRisks | ForEach-Object { Write-Host "  $($_.Name) : $($_.Count)" -ForegroundColor Gray }

    $HtmlRows = $Results | Sort-Object DetectedDateTime -Descending | ForEach-Object {
        $RowClass = switch ($_.RiskLevel) {
            'high'   { 'danger' }
            'medium' { 'warning' }
            default  { '' }
        }
        "<tr class='$RowClass'>
        <td>$($_.DetectedDateTime)</td>
        <td>$($_.UserPrincipalName)</td>
        <td>$($_.RiskLevel)</td>
        <td>$($_.RiskEventType)</td>
        <td>$($_.RiskDetail)</td>
        <td>$($_.IpAddress)</td>
        <td>$($_.Location)</td>
    </tr>"
    }

    $Html = @"
<!DOCTYPE html>
<html>
<head><title>Risky Sign-In Report</title>
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
<h1>Risky Sign-In Log Parser</h1>
<div class='summary'>
    <strong>Period:</strong> Last $HoursBack hours |
    <strong>Events:</strong> $($Results.Count) |
    <strong>High:</strong> <span style='color:red;'>$HighCount</span> |
    <strong>Medium:</strong> <span style='color:orange;'>$MediumCount</span> |
    <strong>Low:</strong> $LowCount |
    <strong>Unique Users:</strong> $UniqueUsers
</div>
<table>
<tr><th>Time</th><th>User</th><th>Risk Level</th><th>Event Type</th><th>Detail</th><th>IP</th><th>Location</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

    $Html | Out-File -LiteralPath $ReportPath -Encoding UTF8
    Write-Log "Report: $ReportPath"

    if ($ExportCsv) {
        $Results | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Log "CSV: $CsvPath"
    }
}
catch {
    Write-Log "Risky sign-in report failed: $_" 'ERROR'
    throw
}
