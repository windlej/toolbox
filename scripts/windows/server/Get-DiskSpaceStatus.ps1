#Requires -Version 5.1

<#
.SYNOPSIS
    Checks disk space on Windows systems and flags drives whose free space
    falls below a configurable threshold.

.DESCRIPTION
    This script checks one or more drives for available disk space, compares
    the free percentage against a defined threshold, and reports the result on the
    console, in a log file and in the Windows Event Log. Run it on demand on the
    server you are checking.

    Files written to the resolved output folder:
      - Get-DiskSpaceStatus_<yyyyMMdd_HHmmss>.log  (one log per run)
      - Get-DiskSpaceStatus_History.csv            (fixed name; one row per drive per run)
    The history CSV intentionally keeps a fixed name because it accumulates between runs so
    you can trend free space over time. Use the same -OutputPath (and -CustomerName) on each
    run so every run appends to the same file.

.PARAMETER Drive
    Drives to check, for example C: or D:. Default: C: and D:. Old name: DrivesToMonitor.

.PARAMETER ThresholdPercent
    Flag a drive when free space drops below this percentage (1-99). Default: 15.

.PARAMETER OutputPath
    Folder for the log file and history CSV. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
    Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER SkipEventLog
    Do not write entries to the Windows Event Log. By default entries are written under the
    source named by -EventLogSource (creating the source needs an elevated session once).

.PARAMETER EventLogSource
    Event Log source name. Default: DiskSpaceMonitor.

.PARAMETER EventLogName
    Event Log to write into. Default: Application.

.PARAMETER WhatIf
    Dry-run mode (standard PowerShell switch). No Event Log entries are written
    and the history CSV is not appended, but all disk checks and console/log output are
    performed.

.PARAMETER Verbose
    Enables verbose output for detailed execution tracing.

.EXAMPLE
    .\Get-DiskSpaceStatus.ps1 -OutputPath D:\Reports

    Checks C: and D: against the 15% default and logs to D:\Reports.

.EXAMPLE
    .\Get-DiskSpaceStatus.ps1 -Drive C:,E: -ThresholdPercent 10 -OutputPath D:\Reports -CustomerName Contoso -WhatIf

    Dry run: checks C: and E: against 10% and changes nothing.

.EXAMPLE
    .\Get-DiskSpaceStatus.ps1 -Drive C: -ThresholdPercent 20 -OutputPath D:\Reports -SkipEventLog

    Ad hoc check of C: against 20%, without writing to the Event Log (no elevation needed).

.NOTES
    Platform:     Windows (PowerShell 5.1+)
    Permissions:  Local user can read drive free space; Administrator needed once to create the Event Log source
    When to use:  Ad-hoc free-space check on a server, for example during an incident or before a change that needs room.
    Safety:       Changes data (supports -WhatIf)
    Version:      3.0
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Alias('DrivesToMonitor')]
    [string[]]$Drive = @('C:', 'D:'),

    [ValidateRange(1, 99)]
    [int]$ThresholdPercent = 15,

    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$SkipEventLog,

    [string]$EventLogSource = 'DiskSpaceMonitor',

    [string]$EventLogName = 'Application'
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

# Derived settings (previously a hardcoded configuration block)
$EnableEventLog = -not $SkipEventLog

# The output folder and log must exist even in -WhatIf (dry-run) mode
$stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$userWhatIf = $WhatIfPreference
$WhatIfPreference = $false
try {
    $outDir = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
}
finally {
    $WhatIfPreference = $userWhatIf
}
$script:LogFile = Join-Path $outDir "Get-DiskSpaceStatus_$stamp.log"
$CsvExportPath  = Join-Path $outDir 'Get-DiskSpaceStatus_History.csv'

# ────────────────────────────────────────────────────────────
#  HELPER: Timestamp string
# ────────────────────────────────────────────────────────────
function Get-Timestamp {
    return (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
}

# ────────────────────────────────────────────────────────────
#  HELPER: Write-Log  -  appends a line to the log file AND
#          writes to the console with colour coding.
# ────────────────────────────────────────────────────────────
function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO', 'WARNING', 'ERROR', 'ALERT')]
        [string]$Level = 'INFO'
    )

    $line = "[$(Get-Timestamp)] [$Level] $Message"

    # Console colour
    switch ($Level) {
        'WARNING' { Write-Host $line -ForegroundColor Yellow }
        'ERROR'   { Write-Host $line -ForegroundColor Red    }
        'ALERT'   { Write-Host $line -ForegroundColor Magenta }
        default   { Write-Host $line -ForegroundColor Cyan   }
    }

    # File logging
    if ($script:LogFile) {
        try {
            Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -WhatIf:$false
        }
        catch {
            Write-Warning "Could not write to log file '$($script:LogFile)': $_"
        }
    }
}

# ────────────────────────────────────────────────────────────
#  HELPER: Ensure Windows Event Log source exists
# ────────────────────────────────────────────────────────────
function Initialize-EventLogSource {
    if (-not $EnableEventLog) { return }
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
            if ($WhatIfPreference) {
                Write-Log "[WhatIf] Would create Event Log source '$EventLogSource' in '$EventLogName'." -Level INFO
                return
            }
            New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction Stop
            Write-Log "Created Event Log source '$EventLogSource' in '$EventLogName'." -Level INFO
        }
    }
    catch {
        Write-Log "Could not create Event Log source (requires admin): $_" -Level WARNING
        # Non-fatal - continue without Event Log
        $script:EnableEventLog = $false
    }
}

# ────────────────────────────────────────────────────────────
#  HELPER: Write to Windows Event Log
# ────────────────────────────────────────────────────────────
function Write-EventLogEntry {
    param (
        [string]$Message,
        [System.Diagnostics.EventLogEntryType]$EntryType = 'Information',
        [int]$EventId = 1000
    )
    if (-not $EnableEventLog) { return }
    if ($WhatIfPreference) {
        Write-Log "[WhatIf] Would write Event Log entry ($EntryType, $EventId)." -Level INFO
        return
    }
    try {
        Write-EventLog -LogName $EventLogName -Source $EventLogSource `
                       -EntryType $EntryType -EventId $EventId -Message $Message
    }
    catch {
        Write-Log "Event Log write failed: $_" -Level WARNING
    }
}

# ────────────────────────────────────────────────────────────
#  HELPER: Append result row to CSV history file
# ────────────────────────────────────────────────────────────
function Export-CsvRow {
    param ([PSCustomObject]$Row)

    try {
        # Export-Csv with -Append avoids overwriting existing history
        $Row | Export-Csv -LiteralPath $CsvExportPath -Append -NoTypeInformation -Encoding UTF8
    }
    catch {
        Write-Log "CSV export failed: $_" -Level WARNING
    }
}

# ────────────────────────────────────────────────────────────
#  HELPER: Format bytes to human-readable string
# ────────────────────────────────────────────────────────────
function Format-Bytes {
    param ([long]$Bytes)
    if     ($Bytes -ge 1TB) { return '{0:N2} TB' -f ($Bytes / 1TB) }
    elseif ($Bytes -ge 1GB) { return '{0:N2} GB' -f ($Bytes / 1GB) }
    elseif ($Bytes -ge 1MB) { return '{0:N2} MB' -f ($Bytes / 1MB) }
    else                    { return '{0:N2} KB' -f ($Bytes / 1KB) }
}

# ────────────────────────────────────────────────────────────
#  CORE: Check a single drive and return a result object
# ────────────────────────────────────────────────────────────
function Test-DriveSpace {
    param ([string]$DriveLetter)

    # Normalise to 'C:' format
    $drive = $DriveLetter.TrimEnd('\').TrimEnd('/')
    if ($drive -notmatch ':$') { $drive += ':' }

    $result = [PSCustomObject]@{
        Timestamp       = Get-Timestamp
        Drive           = $drive
        TotalGB         = $null
        FreeGB          = $null
        FreePercent     = $null
        Status          = 'UNKNOWN'
        AlertTriggered  = $false
        ErrorMessage    = ''
    }

    try {
        # Get-PSDrive is fast and works without WMI/CIM
        $psDrive = Get-PSDrive -Name ($drive.TrimEnd(':')) -PSProvider FileSystem -ErrorAction Stop

        $totalBytes = $psDrive.Used + $psDrive.Free
        if ($totalBytes -eq 0) {
            throw 'Drive reports zero total size - may be unmounted or offline.'
        }

        $freePercent = [math]::Round(($psDrive.Free / $totalBytes) * 100, 1)

        $result.TotalGB     = [math]::Round($totalBytes   / 1GB, 2)
        $result.FreeGB      = [math]::Round($psDrive.Free / 1GB, 2)
        $result.FreePercent = $freePercent

        if ($freePercent -lt $ThresholdPercent) {
            $result.Status         = 'WARNING'
            $result.AlertTriggered = $true
        }
        else {
            $result.Status = 'OK'
        }
    }
    catch [System.Management.Automation.DriveNotFoundException] {
        $result.Status       = 'NOT_FOUND'
        $result.ErrorMessage = "Drive '$drive' does not exist on this system."
        Write-Log $result.ErrorMessage -Level WARNING
    }
    catch [System.UnauthorizedAccessException] {
        $result.Status       = 'ACCESS_DENIED'
        $result.ErrorMessage = "Access denied reading drive '$drive'. Run as Administrator."
        Write-Log $result.ErrorMessage -Level ERROR
    }
    catch {
        $result.Status       = 'ERROR'
        $result.ErrorMessage = $_.Exception.Message
        Write-Log "Unexpected error checking drive '$drive': $($_.Exception.Message)" -Level ERROR
    }

    return $result
}

# ============================================================
#  MAIN EXECUTION BLOCK
# ============================================================

Write-Log '=================================================' -Level INFO
Write-Log "Disk Space Monitor started. Threshold: $ThresholdPercent%" -Level INFO
Write-Log "Monitoring drives: $($Drive -join ', ')" -Level INFO
Write-Log "Log file: $script:LogFile" -Level INFO
if ($WhatIfPreference) {
    Write-Log '[WhatIf / Test Mode] No Event Log entries will be written and the history CSV is not appended.' -Level WARNING
}

# Initialise Event Log source (requires admin first time)
Initialize-EventLogSource

# Collect results across all drives
$allResults     = [System.Collections.Generic.List[PSCustomObject]]::new()
$alertMessages  = [System.Collections.Generic.List[string]]::new()

foreach ($driveLetter in $Drive) {
    $res = Test-DriveSpace -DriveLetter $driveLetter

    # Build console / log output line
    switch ($res.Status) {
        'OK' {
            $line = "Drive $($res.Drive): Healthy - $($res.FreePercent)% free " +
                    "($($res.FreeGB) GB free of $($res.TotalGB) GB total)"
            Write-Log $line -Level INFO
        }
        'WARNING' {
            $line = "WARNING: Drive $($res.Drive): LOW DISK SPACE - " +
                    "$($res.FreePercent)% free ($($res.FreeGB) GB free of $($res.TotalGB) GB total)"
            Write-Log $line -Level ALERT
            $alertMessages.Add($line)

            # Write Warning event to Event Log
            Write-EventLogEntry -Message $line `
                                -EntryType Warning -EventId 1001
        }
        default {
            $line = "Drive $($res.Drive): Status=$($res.Status) - $($res.ErrorMessage)"
            Write-Log $line -Level ERROR

            # Log errors to Event Log as errors
            Write-EventLogEntry -Message $line `
                                -EntryType Error -EventId 1002
        }
    }

    # Export to CSV history
    Export-CsvRow -Row $res

    $allResults.Add($res)
}

# ────────────────────────────────────────────────────────────
#  SUMMARY
# ────────────────────────────────────────────────────────────
if ($alertMessages.Count -gt 0) {
    Write-Log "$($alertMessages.Count) drive(s) below the $ThresholdPercent% free space threshold." -Level ALERT
}
else {
    $okCount = @($allResults | Where-Object Status -eq 'OK').Count
    Write-Log "All $okCount monitored drive(s) are within healthy thresholds." -Level INFO

    # Informational Event Log entry on clean run
    Write-EventLogEntry -Message "Disk Monitor: All drives OK on $env:COMPUTERNAME." `
                        -EntryType Information -EventId 1000
}

Write-Log 'Disk Space Monitor finished.' -Level INFO
Write-Log '=================================================' -Level INFO
