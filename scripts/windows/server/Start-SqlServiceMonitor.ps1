#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Ensures all SQL Server services are running. Retries for 30 seconds and alerts if any fail to start.

.DESCRIPTION
    Discovers all SQL Server-related services, attempts to start any that are stopped,
    polls every 5 seconds for up to 30 seconds, and writes an alert to the Event Log
    for any service that fails to reach a Running state in time.

    Exit code 0 means every SQL service is running; 1 means at least one failed to start, which
    makes it suitable for a scheduled task or RMM monitor.

.PARAMETER TimeoutSeconds
    How long (in seconds) to wait for each service to reach Running state. Default: 30.

.PARAMETER PollIntervalSeconds
    How often (in seconds) to check service status during the wait. Default: 5.

.PARAMETER ExcludedService
    Service names that must NOT be started automatically (for example a deliberately stopped instance).

.PARAMETER OutputPath
    Folder for the daily log file. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.
    Scheduled runs must pass -OutputPath, because there is no one to answer the prompt.

.PARAMETER CustomerName
    Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.EXAMPLE
    .\Start-SqlServiceMonitor.ps1 -OutputPath D:\Logs

.EXAMPLE
    .\Start-SqlServiceMonitor.ps1 -TimeoutSeconds 60 -PollIntervalSeconds 10 -OutputPath D:\Logs -ExcludedService 'SQLBROWSER' -WhatIf

.NOTES
    Platform:     Windows (SQL Server host)
    Permissions:  Local administrator (writes to the Application event log, source SQLServiceMonitor)
    When to use:  After patching or reboots, or as a scheduled task, to bring SQL services back up and raise an alert if they won't start.
    Safety:       Changes data (starts stopped services; supports -WhatIf)
    Version:      1.1
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [int] $TimeoutSeconds      = 30,
    [int] $PollIntervalSeconds = 5,
    [string[]] $ExcludedService = @(),
    [string] $OutputPath,
    [string] $CustomerName
)

Set-StrictMode -Version Latest

function Resolve-OutputPath {
    param([string]$Path, [string]$CustomerName)
    if (-not $Path) { $Path = $env:TOOLBOX_REPORT_DIR }
    if (-not $Path) { $Path = Read-Host 'Output folder for reports' }
    if (-not $Path) { throw 'An output path is required.' }
    if ($CustomerName) { $Path = Join-Path $Path $CustomerName }
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    (Resolve-Path -LiteralPath $Path).Path
}

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

# Service name patterns to match (regex). Extend this list as needed.
$SqlServicePatterns = @(
    '^MSSQL\$',          # Named SQL instances  (e.g. MSSQL$SQLEXPRESS)
    '^MSSQLSERVER$',     # Default SQL instance
    '^SQLSERVERAGENT$',  # Default instance Agent
    '^SQLAgent\$',       # Named instance Agent
    '^MSSQLFDLauncher',  # Full-Text Search
    '^SQLBROWSER$',      # SQL Browser
    '^ReportServer',     # SSRS
    '^MsDtsServer',      # SSIS
    '^SQLWriter$',       # SQL VSS Writer
    '^SSASTELEMETRY',    # SSAS Telemetry
    '^MSSQLLaunchpad'    # Extensibility Launchpad
)

# Log file (one per day) inside the resolved output folder
$LogDir  = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$LogFile = Join-Path $LogDir ("Start-SqlServiceMonitor_{0}.log" -f (Get-Date -Format "yyyyMMdd"))

# Event Log source name (created on first run if missing)
$EventSource = "SQLServiceMonitor"
$EventLog    = "Application"

# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

function Initialize-Environment {
    # Register Event Log source if it doesn't exist
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
        try {
            New-EventLog -LogName $EventLog -Source $EventSource -ErrorAction Stop
        } catch {
            Write-Warning "Could not create Event Log source '$EventSource': $_"
        }
    }
}

function Write-Log {
    param(
        [string] $Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")] [string] $Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    $line | Tee-Object -FilePath $LogFile -Append | Write-Host -ForegroundColor $(
        switch ($Level) {
            "INFO"    { "Cyan"    }
            "WARN"    { "Yellow"  }
            "ERROR"   { "Red"     }
            "SUCCESS" { "Green"   }
        }
    )
}

function Write-EventLogEntry {
    param([string] $Message, [string] $EntryType = "Information")
    try {
        Write-EventLog -LogName $EventLog -Source $EventSource `
                       -EventId 9000 -EntryType $EntryType -Message $Message
    } catch {
        Write-Log "Could not write to Event Log: $_" -Level WARN
    }
}

function Get-SqlServices {
    $allServices = Get-Service -ErrorAction SilentlyContinue

    $matched = $allServices | Where-Object {
        $svc = $_
        $isMatch    = $SqlServicePatterns | Where-Object { $svc.Name -match $_ }
        $isExcluded = $ExcludedService   | Where-Object { $svc.Name -eq $_ }
        $isMatch -and -not $isExcluded
    }

    return @($matched | Sort-Object Name)
}

function Wait-ForServiceRunning {
    <#
    .OUTPUTS
        $true if service reached Running within timeout, $false otherwise.
    #>
    param([string] $ServiceName)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $elapsed  = 0

    while ((Get-Date) -lt $deadline) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            return $true
        }
        Write-Log "  [$ServiceName] Status: $($svc.Status) — waiting... ($elapsed s elapsed)" -Level INFO
        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds
    }

    return $false
}

function Start-SqlService {
    param([System.ServiceProcess.ServiceController] $Service)

    $name        = $Service.Name
    $displayName = $Service.DisplayName

    Write-Log "Attempting to start: $displayName ($name)" -Level INFO

    if (-not $PSCmdlet.ShouldProcess("$displayName ($name)", 'Start service')) { return $true }

    try {
        Start-Service -Name $name -ErrorAction Stop
    } catch {
        Write-Log "Start-Service call failed for '$name': $_" -Level WARN
        # Still continue to poll — service may be mid-start from a delayed auto trigger
    }

    $started = Wait-ForServiceRunning -ServiceName $name

    if ($started) {
        Write-Log "SUCCESS — '$displayName' is now Running." -Level SUCCESS
        Write-EventLogEntry -Message "SQL service started successfully: $displayName ($name)" -EntryType Information
        return $true
    } else {
        $msg = "ALERT — '$displayName' ($name) did NOT reach Running state within $TimeoutSeconds seconds."
        Write-Log $msg -Level ERROR
        Write-EventLogEntry -Message $msg -EntryType Error

        return $false
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

Initialize-Environment

Write-Log "═══════════════════════════════════════════════════════" -Level INFO
Write-Log "  SQL Service Monitor — starting on $env:COMPUTERNAME"   -Level INFO
Write-Log "  Timeout: ${TimeoutSeconds}s | Poll: ${PollIntervalSeconds}s"  -Level INFO
Write-Log "═══════════════════════════════════════════════════════" -Level INFO

$sqlServices = @(Get-SqlServices)

if ($sqlServices.Count -eq 0) {
    Write-Log "No SQL Server services found on this machine." -Level WARN
    exit 0
}

Write-Log "Discovered $($sqlServices.Count) SQL service(s):" -Level INFO
$sqlServices | ForEach-Object { Write-Log "  · $($_.DisplayName) [$($_.Name)] — Status: $($_.Status)" -Level INFO }
Write-Log "" -Level INFO

$failed  = [System.Collections.Generic.List[string]]::new()
$started = [System.Collections.Generic.List[string]]::new()
$already = [System.Collections.Generic.List[string]]::new()

foreach ($svc in $sqlServices) {
    $svc.Refresh()

    if ($svc.Status -eq 'Running') {
        Write-Log "[$($svc.Name)] Already Running — no action needed." -Level SUCCESS
        $already.Add($svc.DisplayName)
        continue
    }

    $ok = Start-SqlService -Service $svc

    if ($ok) {
        $started.Add($svc.DisplayName)
    } else {
        $failed.Add($svc.DisplayName)
    }

    Write-Log "" -Level INFO
}

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Log "═══════════════════════════════════════════════════════" -Level INFO
Write-Log "  SUMMARY" -Level INFO
Write-Log "  Already running : $($already.Count)" -Level INFO
Write-Log "  Started OK      : $($started.Count)" -Level INFO
Write-Log "  Failed to start : $($failed.Count)" -Level INFO
Write-Log "═══════════════════════════════════════════════════════" -Level INFO

if ($failed.Count -gt 0) {
    Write-Log "The following services FAILED to start:" -Level ERROR
    $failed | ForEach-Object { Write-Log "  ✗ $_" -Level ERROR }
    exit 1
} else {
    Write-Log "All SQL services are running." -Level SUCCESS
    exit 0
}