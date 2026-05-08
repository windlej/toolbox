param(
    [Parameter(Mandatory = $false)]
    [int]$HoursBack = 72,

    [Parameter(Mandatory = $false)]
    [string]$RiskLevel = "low,medium,high",

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\RiskySignIns_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDetails,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGraphConnect
)

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
        Write-Host "Connected to Graph" -ForegroundColor Green
    } catch {
        throw "Graph auth failed: $_"
    }
}

function Get-RiskyUsersViaApi {
    param([string]$RiskLevel)

    $Filter = "riskLevel ne 'none'"
    if ($RiskLevel -ne "all") {
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
        Write-Warning "Risky users query failed (API may require premium licensing): $_"
        return @()
    }

    return $AllRisky
}

function Get-RiskDetectionsViaApi {
    param([int]$HoursBack)

    $StartTime = (Get-Date).AddHours(-$HoursBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
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
        Write-Warning "Risk detections query failed: $_"
        return @()
    }

    Write-Host "Found $($AllDetections.Count) risk detections" -ForegroundColor Yellow
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

    $StartTime = (Get-Date).AddHours(-$HoursBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $Uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=userId eq '$UserId' and createdDateTime ge $StartTime&`$top=25&`$orderBy=createdDateTime desc"

    try {
        $Response = Invoke-MgGraphRequest -Uri $Uri -Method Get -ErrorAction Stop
        return $Response.value
    } catch { return @() }
}

# ── MAIN ──

Write-Host "=== Risky Sign-In Log Parser ===" -ForegroundColor Cyan
Write-Host "Period: Last $HoursBack hours | Risk Level: $RiskLevel" -ForegroundColor White

if (-not $SkipGraphConnect) {
    Connect-ToGraph
}

Write-Host "Retrieving risk detections..." -ForegroundColor Yellow
$Detections = Get-RiskDetectionsViaApi -HoursBack $HoursBack

if ($Detections.Count -eq 0) {
    Write-Host "No risk detections found in the specified period." -ForegroundColor Green
    return
}

$RiskLevels = $RiskLevel -split ','
$Detections = $Detections | Where-Object { $_.riskLevel -in $RiskLevels -or $RiskLevel -eq "all" }

foreach ($Detection in $Detections) {
    $UserDetail = Get-UserDetail -UserId $Detection.userId

    $Result = [PSCustomObject]@{
        DetectedDateTime     = $Detection.detectedDateTime
        UserId               = $Detection.userId
        UserPrincipalName    = if ($UserDetail) { $UserDetail.UserPrincipalName } else { "Unknown" }
        DisplayName          = if ($UserDetail) { $UserDetail.DisplayName } else { "Unknown" }
        Department           = if ($UserDetail) { $UserDetail.Department } else { "" }
        RiskLevel            = $Detection.riskLevel
        RiskType             = $Detection.riskType
        RiskEventType        = $Detection.riskEventType
        AdditionalInfo       = $Detection.additionalInfo
        Source               = $Detection.source
        TokenIssuerType      = $Detection.tokenIssuerType
        Activity             = $Detection.activity
        ActivityDateTime     = $Detection.activityDateTime
        IpAddress            = $Detection.ipAddress
        Location             = "$($Detection.city), $($Detection.state), $($Detection.country)"
        UserAgent            = $Detection.userAgent
        RiskDetail           = $Detection.riskDetail
    }

    if ($IncludeDetails -and $UserDetail) {
        $SignIns = Get-SignInLogsForUser -UserId $Detection.userId -HoursBack $HoursBack
        if ($SignIns.Count -gt 0) {
            $RecentSignIn = $SignIns[0]
            $Result | Add-Member -NotePropertyName "LastSignInClientApp" -NotePropertyValue $RecentSignIn.clientAppUsed
            $Result | Add-Member -NotePropertyName "LastSignInDevice" -NotePropertyValue "$($RecentSignIn.deviceDetail.operatingSystem) - $($RecentSignIn.deviceDetail.browser)"
        }
    }

    $Results.Add($Result)
}

$HighCount = ($Results | Where-Object { $_.RiskLevel -eq "high" }).Count
$MediumCount = ($Results | Where-Object { $_.RiskLevel -eq "medium" }).Count
$LowCount = ($Results | Where-Object { $_.RiskLevel -eq "low" }).Count
$UniqueUsers = ($Results | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
$TopRisks = $Results | Group-Object RiskEventType | Sort-Object Count -Descending | Select-Object -First 10

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
        "high" { "danger" }
        "medium" { "warning" }
        default { "" }
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

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvPath) {
    $Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvPath" -ForegroundColor Green
}
