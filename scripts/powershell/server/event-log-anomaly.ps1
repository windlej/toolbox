#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Event Log Anomaly Parser — detects critical errors and behavioral anomalies
    across System, Application, and Security logs on local or remote machines.

.DESCRIPTION
    Parses Windows Event Logs using Get-WinEvent (preferred over Get-EventLog for
    performance). Filters critical/error-level events, detects anomaly patterns such as
    burst activity, repeated Event IDs, service crashes, and auth failures, then
    categorizes and exports results to console table, CSV, or JSON.

.PARAMETER ComputerName
    One or more target machine names. Defaults to the local machine.

.PARAMETER HoursBack
    How many hours back to search. Default is 24.

.PARAMETER Logs
    Which logs to query: System, Application, Security. Default is System + Application.

.PARAMETER EventIDs
    Optional array of specific Event IDs to filter on. Leave empty for all critical/error events.

.PARAMETER ExportCsv
    Full path for CSV export. Omit to skip CSV output.

.PARAMETER ExportJson
    Full path for JSON export. Omit to skip JSON output.

.PARAMETER BurstThreshold
    Number of errors within BurstWindowMinutes that triggers an anomaly flag. Default: 10.

.PARAMETER BurstWindowMinutes
    Sliding window (minutes) used to detect error bursts. Default: 5.

.PARAMETER IncludeSummary
    Switch — if present, prints a summary statistics block at the end.

.EXAMPLE
    # Local machine, last 24 h, show summary
    .\Invoke-EventLogAnomalyParser.ps1 -IncludeSummary

.EXAMPLE
    # Three remote servers, last 7 days, export CSV
    .\Invoke-EventLogAnomalyParser.ps1 `
        -ComputerName SRV01,SRV02,SRV03 `
        -HoursBack 168 `
        -Logs System,Application,Security `
        -ExportCsv "C:\Reports\EventAnomalies.csv" `
        -IncludeSummary

.EXAMPLE
    # Focus on specific Event IDs
    .\Invoke-EventLogAnomalyParser.ps1 -EventIDs 41,6008,7034,1001 -HoursBack 1

.NOTES
    Requires read access to target Event Logs.
    Security log requires elevated privileges or explicit delegation.
    Author  : Windows Automation Toolkit
    Version : 2.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]] $ComputerName = @($env:COMPUTERNAME),

    [ValidateRange(1, 8760)]
    [int]    $HoursBack          = 24,

    [ValidateSet('System', 'Application', 'Security')]
    [string[]] $Logs             = @('System', 'Application'),

    [int[]]  $EventIDs           = @(),

    [string] $ExportCsv          = '',
    [string] $ExportJson         = '',

    [int]    $BurstThreshold     = 10,
    [int]    $BurstWindowMinutes = 5,

    [switch] $IncludeSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────────────────────────────────────
# REGION: CONSTANTS & CATEGORY MAPPING
# ─────────────────────────────────────────────────────────────────────────────

# Well-known Event IDs mapped to human-readable categories.
# Extend this table to suit your environment.
$Script:CategoryMap = [ordered]@{
    # ── System Crash / Kernel ──────────────────────────────────────────────
    41    = 'System Crash / Kernel'   # Kernel power – unexpected reboot
    1001  = 'System Crash / Kernel'   # BugCheck (BSOD) recorded
    6008  = 'System Crash / Kernel'   # Unexpected shutdown
    6009  = 'System Crash / Kernel'   # OS version at boot (logged after dirty shutdown)

    # ── Application Failures ──────────────────────────────────────────────
    1000  = 'Application Failure'     # Application error
    1002  = 'Application Failure'     # Application hang
    1026  = 'Application Failure'     # .NET Runtime exception

    # ── Service Crashes ───────────────────────────────────────────────────
    7034  = 'Service Crash'           # Service terminated unexpectedly
    7031  = 'Service Crash'           # Service terminated; recovery action taken
    7023  = 'Service Crash'           # Service terminated with error
    7024  = 'Service Crash'           # Service terminated with service-specific error

    # ── Disk / I/O Errors ─────────────────────────────────────────────────
    7     = 'Disk / I-O Error'        # Disk error detected by driver
    11    = 'Disk / I-O Error'        # Driver detected controller error
    15    = 'Disk / I-O Error'        # Device not ready
    51    = 'Disk / I-O Error'        # Paging error

    # ── Network / Connectivity ────────────────────────────────────────────
    4202  = 'Network / Connectivity'  # NIC disconnected
    4198  = 'Network / Connectivity'  # IP address conflict
    1014  = 'Network / Connectivity'  # DNS name resolution timeout

    # ── Authentication / Security ─────────────────────────────────────────
    4625  = 'Authentication / Security'  # Failed logon
    4648  = 'Authentication / Security'  # Explicit credentials logon
    4740  = 'Authentication / Security'  # Account locked out
    4719  = 'Authentication / Security'  # System audit policy changed
    4964  = 'Authentication / Security'  # Special groups assigned to new logon
}

# Reverse lookup: category → list of canonical Event IDs for display
$Script:DefaultCriticalIDs = $Script:CategoryMap.Keys

# ─────────────────────────────────────────────────────────────────────────────
# REGION: HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

function Get-EventCategory {
    <#
    .SYNOPSIS  Returns the category string for a given Event ID, or 'Uncategorized'.
    #>
    param([int] $EventId)

    if ($Script:CategoryMap.Contains($EventId)) {
        return $Script:CategoryMap[$EventId]
    }
    return 'Uncategorized'
}

function Invoke-BurstDetection {
    <#
    .SYNOPSIS
        Scans a sorted list of timestamps for bursts: N or more events within M minutes.
    .OUTPUTS
        HashSet of timestamps (as ticks) that fall inside a burst window.
    #>
    param(
        [datetime[]] $Timestamps,
        [int]        $Threshold,
        [int]        $WindowMinutes
    )

    $burstSet  = [System.Collections.Generic.HashSet[long]]::new()
    $sorted    = $Timestamps | Sort-Object
    $count     = $sorted.Count
    $windowTS  = [timespan]::FromMinutes($WindowMinutes)

    for ($i = 0; $i -lt $count; $i++) {
        $windowEnd = $sorted[$i] + $windowTS
        $inWindow  = @($sorted[$i])

        for ($j = $i + 1; $j -lt $count; $j++) {
            if ($sorted[$j] -le $windowEnd) {
                $inWindow += $sorted[$j]
            } else { break }
        }

        if ($inWindow.Count -ge $Threshold) {
            foreach ($ts in $inWindow) {
                [void] $burstSet.Add($ts.Ticks)
            }
        }
    }
    return $burstSet
}

function New-XPathFilter {
    <#
    .SYNOPSIS  Builds an XPath query string for Get-WinEvent — filters by time and level.
    .NOTES     Filtering at query time is vastly faster than piping to Where-Object.
    #>
    param(
        [datetime] $StartTime,
        [int[]]    $Ids   = @()
    )

    # Convert to UTC for WinEvent XPath
    $utcMs = [System.Xml.XmlConvert]::ToString(
        $StartTime.ToUniversalTime(),
        [System.Xml.XmlDateTimeSerializationMode]::Utc
    )

    # Levels: 1 = Critical, 2 = Error
    $levelClause = "(Level=1 or Level=2)"

    if ($Ids.Count -gt 0) {
        $idClause = "(" + (($Ids | ForEach-Object { "EventID=$_" }) -join ' or ') + ")"
        $filter   = "*[System[$levelClause and $idClause and TimeCreated[@SystemTime>='$utcMs']]]"
    } else {
        $filter = "*[System[$levelClause and TimeCreated[@SystemTime>='$utcMs']]]"
    }

    return $filter
}

function Invoke-SafeMessage {
    <#
    .SYNOPSIS  Returns a trimmed, single-line message string (max 200 chars).
    #>
    param([string] $Raw)

    if ([string]::IsNullOrWhiteSpace($Raw)) { return '(no message)' }
    $clean = $Raw -replace '\r?\n', ' ' -replace '\s{2,}', ' '
    return ($clean.Trim()).Substring(0, [Math]::Min($clean.Trim().Length, 200))
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: CORE COLLECTION FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

function Get-CriticalEvents {
    <#
    .SYNOPSIS
        Queries one or more logs on a target machine, returning a list of
        structured event objects ready for anomaly analysis.
    #>
    param(
        [string]   $TargetComputer,
        [string[]] $LogNames,
        [datetime] $StartTime,
        [int[]]    $FilterIDs
    )

    $collected = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($logName in $LogNames) {

        Write-Verbose "  [$TargetComputer] Querying log: $logName"

        $xPath = New-XPathFilter -StartTime $StartTime -Ids $FilterIDs

        $queryParams = @{
            LogName      = $logName
            FilterXPath  = $xPath
            ErrorAction  = 'SilentlyContinue'
        }

        # Add -ComputerName only for remote targets to avoid local permission quirks
        if ($TargetComputer -ne $env:COMPUTERNAME) {
            $queryParams['ComputerName'] = $TargetComputer
        }

        try {
            $events = Get-WinEvent @queryParams
        }
        catch [System.Exception] {
            # No events matching filter = benign; other errors are logged
            if ($_.Exception.Message -notmatch 'No events') {
                Write-Warning "[$TargetComputer][$logName] Query failed: $($_.Exception.Message)"
            }
            continue
        }

        foreach ($evt in $events) {
            $category = Get-EventCategory -EventId $evt.Id
            $obj = [PSCustomObject]@{
                Timestamp    = $evt.TimeCreated
                MachineName  = $evt.MachineName
                LogName      = $logName
                EventID      = $evt.Id
                Level        = $evt.LevelDisplayName
                Source       = $evt.ProviderName
                Message      = Invoke-SafeMessage -Raw $evt.Message
                Category     = $category
                AnomalyFlag  = 'No'          # populated later
            }
            $collected.Add($obj)
        }
    }

    return $collected
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: ANOMALY ENRICHMENT FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

function Add-AnomalyFlags {
    <#
    .SYNOPSIS
        Enriches a flat event list with AnomalyFlag = 'Yes' where patterns are detected:
          1. Burst: >= BurstThreshold events from the same machine within BurstWindowMinutes
          2. Repeat: Event ID appears > 5 times on the same machine in the analysis window
          3. Auth Anomaly: Security category events always flagged
    #>
    param(
        [System.Collections.Generic.List[PSCustomObject]] $Events,
        [int] $Threshold,
        [int] $WindowMinutes
    )

    if ($Events.Count -eq 0) { return $Events }

    # Group by machine for burst detection
    $byMachine = $Events | Group-Object -Property MachineName

    foreach ($machineGroup in $byMachine) {

        $machineEvents = $machineGroup.Group
        $timestamps    = $machineEvents | Select-Object -ExpandProperty Timestamp

        # ── Burst Detection ──────────────────────────────────────────────
        $burstTicks = Invoke-BurstDetection `
            -Timestamps $timestamps `
            -Threshold  $Threshold `
            -WindowMinutes $WindowMinutes

        foreach ($evt in $machineEvents) {
            if ($burstTicks.Contains($evt.Timestamp.Ticks)) {
                $evt.AnomalyFlag = 'Yes'
            }
        }

        # ── Repeat Detection (same EventID > 5 occurrences per machine) ──
        $idGroups = $machineEvents | Group-Object -Property EventID |
                    Where-Object { $_.Count -gt 5 }

        foreach ($grp in $idGroups) {
            foreach ($evt in $grp.Group) {
                $evt.AnomalyFlag = 'Yes'
            }
        }
    }

    # ── Auth Anomaly: always flag security category events ────────────────
    foreach ($evt in $Events) {
        if ($evt.Category -eq 'Authentication / Security') {
            $evt.AnomalyFlag = 'Yes'
        }
    }

    return $Events
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: SUMMARY STATISTICS FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

function Write-SummaryReport {
    param(
        [PSCustomObject[]] $Events,
        [int] $HoursBack
    )

    $total      = $Events.Count
    $anomalies  = ($Events | Where-Object { $_.AnomalyFlag -eq 'Yes' }).Count
    $startLabel = (Get-Date).AddHours(-$HoursBack).ToString('yyyy-MM-dd HH:mm')
    $endLabel   = (Get-Date).ToString('yyyy-MM-dd HH:mm')

    Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  EVENT LOG ANOMALY PARSER — SUMMARY REPORT" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  Analysis Window : $startLabel  →  $endLabel"
    Write-Host "  Total Events    : $total"
    Write-Host "  Anomaly Flagged : $anomalies" -ForegroundColor $(if ($anomalies -gt 0) {'Yellow'} else {'Green'})
    Write-Host ""

    # ── Errors by Category ───────────────────────────────────────────────
    Write-Host "  BY CATEGORY:" -ForegroundColor Cyan
    $Events | Group-Object -Property Category |
        Sort-Object Count -Descending |
        ForEach-Object {
            $bar   = '█' * [Math]::Min($_.Count, 40)
            $color = if ($_.Count -ge 10) { 'Red' } elseif ($_.Count -ge 5) { 'Yellow' } else { 'White' }
            Write-Host ("  {0,-35} {1,4}  {2}" -f $_.Name, $_.Count, $bar) -ForegroundColor $color
        }

    Write-Host ""

    # ── Errors by Host ───────────────────────────────────────────────────
    Write-Host "  BY HOST:" -ForegroundColor Cyan
    $Events | Group-Object -Property MachineName |
        Sort-Object Count -Descending |
        ForEach-Object {
            Write-Host ("  {0,-30} {1,4} events" -f $_.Name, $_.Count)
        }

    Write-Host ""

    # ── Top 10 Recurring Event IDs ────────────────────────────────────────
    Write-Host "  TOP RECURRING EVENT IDs:" -ForegroundColor Cyan
    $Events | Group-Object -Property EventID |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            $cat = Get-EventCategory -EventId ([int]$_.Name)
            Write-Host ("  EventID {0,-6}  Count: {1,-5}  [{2}]" -f $_.Name, $_.Count, $cat)
        }

    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Cyan
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: EXPORT FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

function Export-ToCsv {
    param(
        [PSCustomObject[]] $Events,
        [string]           $Path
    )
    try {
        $Events | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Force
        Write-Host "[EXPORT] CSV written → $Path" -ForegroundColor Green
    }
    catch {
        Write-Warning "[EXPORT] CSV export failed: $($_.Exception.Message)"
    }
}

function Export-ToJson {
    param(
        [PSCustomObject[]] $Events,
        [string]           $Path
    )
    try {
        # Format timestamps as ISO-8601 strings for JSON portability
        $jsonReady = $Events | ForEach-Object {
            [PSCustomObject]@{
                Timestamp   = $_.Timestamp.ToString('o')   # ISO-8601
                MachineName = $_.MachineName
                LogName     = $_.LogName
                EventID     = $_.EventID
                Level       = $_.Level
                Source      = $_.Source
                Message     = $_.Message
                Category    = $_.Category
                AnomalyFlag = $_.AnomalyFlag
            }
        }
        $jsonReady | ConvertTo-Json -Depth 3 |
            Set-Content -Path $Path -Encoding UTF8 -Force
        Write-Host "[EXPORT] JSON written → $Path" -ForegroundColor Green
    }
    catch {
        Write-Warning "[EXPORT] JSON export failed: $($_.Exception.Message)"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: MAIN EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-EventLogAnomalyParser {
    <#
    .SYNOPSIS  Orchestrates collection, enrichment, display, and export.
    #>

    $startTime  = (Get-Date).AddHours(-$HoursBack)
    $filterIDs  = if ($EventIDs.Count -gt 0) { $EventIDs } else { @() }
    $allEvents  = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Host "`n[*] Event Log Anomaly Parser starting..." -ForegroundColor Cyan
    Write-Host "    Targets   : $($ComputerName -join ', ')"
    Write-Host "    Logs      : $($Logs -join ', ')"
    Write-Host "    Window    : Last $HoursBack hour(s) (from $($startTime.ToString('yyyy-MM-dd HH:mm')))"
    Write-Host "    Burst     : >= $BurstThreshold events within $BurstWindowMinutes minute(s)`n"

    foreach ($computer in $ComputerName) {

        Write-Host "[*] Collecting from: $computer" -ForegroundColor Yellow

        try {
            $machineEvents = Get-CriticalEvents `
                -TargetComputer $computer `
                -LogNames       $Logs `
                -StartTime      $startTime `
                -FilterIDs      $filterIDs

            Write-Host "    Found $($machineEvents.Count) critical/error event(s)."
            $allEvents.AddRange($machineEvents)
        }
        catch {
            Write-Warning "Failed to collect from [$computer]: $($_.Exception.Message)"
        }
    }

    if ($allEvents.Count -eq 0) {
        Write-Host "`n[OK] No critical/error events found in the specified window.`n" -ForegroundColor Green
        return
    }

    # ── Anomaly enrichment ────────────────────────────────────────────────
    Write-Host "`n[*] Running anomaly detection..." -ForegroundColor Cyan
    $enriched = Add-AnomalyFlags `
        -Events        $allEvents `
        -Threshold     $BurstThreshold `
        -WindowMinutes $BurstWindowMinutes

    # Sort by timestamp descending for readability
    $sorted = @($enriched | Sort-Object Timestamp -Descending)

    # ── Console table output ──────────────────────────────────────────────
    Write-Host "`n[RESULTS] $($sorted.Count) event(s) | Anomaly-flagged: $(($sorted | Where-Object {$_.AnomalyFlag -eq 'Yes'}).Count)`n"

    $sorted | Format-Table -AutoSize -Property @(
        @{Label='Timestamp';    Expression={$_.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')}; Width=20}
        @{Label='Machine';      Expression={$_.MachineName}; Width=20}
        @{Label='Log';          Expression={$_.LogName}; Width=12}
        @{Label='EventID';      Expression={$_.EventID}; Width=8}
        @{Label='Level';        Expression={$_.Level}; Width=10}
        @{Label='Category';     Expression={$_.Category}; Width=28}
        @{Label='Anomaly';      Expression={$_.AnomalyFlag}; Width=8}
        @{Label='Source';       Expression={$_.Source}; Width=30}
        @{Label='Message';      Expression={$_.Message.Substring(0,[Math]::Min($_.Message.Length,80))}}
    )

    # ── Anomaly-only highlighted table ────────────────────────────────────
    $anomalyEvents = $sorted | Where-Object { $_.AnomalyFlag -eq 'Yes' }
    if ($anomalyEvents) {
        Write-Host "`n[!] ANOMALY-FLAGGED EVENTS:" -ForegroundColor Red
        $anomalyEvents | Format-Table -AutoSize -Property @(
            @{Label='Timestamp';  Expression={$_.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')}; Width=20}
            @{Label='Machine';    Expression={$_.MachineName}; Width=20}
            @{Label='EventID';    Expression={$_.EventID}; Width=8}
            @{Label='Category';   Expression={$_.Category}; Width=28}
            @{Label='Source';     Expression={$_.Source}; Width=30}
            @{Label='Message';    Expression={$_.Message.Substring(0,[Math]::Min($_.Message.Length,90))}}
        )
    }

    # ── Summary block ─────────────────────────────────────────────────────
    if ($IncludeSummary) {
        Write-SummaryReport -Events $sorted -HoursBack $HoursBack
    }

    # ── Export ────────────────────────────────────────────────────────────
    if ($ExportCsv)  { Export-ToCsv  -Events $sorted -Path $ExportCsv  }
    if ($ExportJson) { Export-ToJson -Events $sorted -Path $ExportJson }

    # Return the enriched objects to the pipeline for further processing
    return $sorted
}

# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

Invoke-EventLogAnomalyParser
