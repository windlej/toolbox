#Requires -Version 5.1
<#
.SYNOPSIS
    Monitors disk space on Windows systems and sends alerts when free space
    falls below a configurable threshold.

.DESCRIPTION
    This script checks one or more drives for available disk space, compares
    the free percentage against a defined threshold, and triggers alerts via
    email, Windows Event Log, and/or a log file. Designed for unattended
    execution via Windows Task Scheduler.

.PARAMETER WhatIf
    Runs the script in test/dry-run mode. No emails are sent, no Event Log
    entries are written, but all disk checks and console output are performed.

.PARAMETER Verbose
    Enables verbose output for detailed execution tracing.

.EXAMPLE
    # Normal run
    .\Monitor-DiskSpace.ps1

    # Dry-run / test mode (no alerts sent)
    .\Monitor-DiskSpace.ps1 -WhatIf

    # Verbose output
    .\Monitor-DiskSpace.ps1 -Verbose

.NOTES
    Author      : Systems Administrator
    Version     : 2.0.0
    Last Updated: 2026-04-19
    Requires    : PowerShell 5.1+, appropriate SMTP credentials if email is enabled
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param ()

# ============================================================
#  SECTION 1 — CONFIGURATION
#  Edit these variables to match your environment.
# ============================================================

# --- Drives to monitor (comma-separated) ---
$DrivesToMonitor    = @('C:', 'D:')

# --- Alert threshold: alert when free space % drops BELOW this value ---
$ThresholdPercent   = 15          # Integer, e.g. 15 = 15%

# --- Log file path (leave empty '' to disable file logging) ---
$LogFilePath        = 'C:\Logs\DiskMonitor\DiskMonitor.log'

# --- CSV export path (leave empty '' to disable CSV export) ---
$CsvExportPath      = 'C:\Logs\DiskMonitor\DiskMonitor_History.csv'

# --- Windows Event Log settings (set $EnableEventLog = $false to disable) ---
$EnableEventLog     = $true
$EventLogSource     = 'DiskSpaceMonitor'   # Custom source name
$EventLogName       = 'Application'         # Log to write into

# --- Email / SMTP settings (set $EnableEmail = $false to disable) ---
$EnableEmail        = $true
$SmtpServer         = 'smtp.yourdomain.com'
$SmtpPort           = 587
$SmtpUseSsl         = $true
$From               = 'monitor@yourdomain.com'
$To                 = @('admin@yourdomain.com', 'oncall@yourdomain.com')
$EmailSubjectPrefix = '[DISK ALERT]'

# --- Credential handling ---
# Option A: Prompt interactively (suitable for testing)
#   $SmtpCredential = Get-Credential
#
# Option B: Load from an encrypted XML file created with Export-Clixml
#   (See "Setting Up Credentials Securely" instructions at the bottom)
#   $SmtpCredential = Import-Clixml -Path 'C:\Secure\smtp_cred.xml'
#
# Option C: No authentication (open relay / no-auth SMTP)
#   $SmtpCredential = $null
#
# Default below uses Option B; change as needed:
$SmtpCredentialPath = 'C:\Secure\smtp_cred.xml'
$SmtpCredential     = $null   # Will be populated in the credential-loading section

# --- Teams / Slack webhook (set to '' to disable) ---
$TeamsWebhookUrl    = ''       # Paste your Incoming Webhook URL here
$SlackWebhookUrl    = ''

# ============================================================
#  END OF CONFIGURATION — Do not edit below unless needed
# ============================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ────────────────────────────────────────────────────────────
#  HELPER: Timestamp string
# ────────────────────────────────────────────────────────────
function Get-Timestamp {
    return (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
}

# ────────────────────────────────────────────────────────────
#  HELPER: Write-Log  —  appends a line to the log file AND
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
    if ($LogFilePath -ne '') {
        try {
            $logDir = Split-Path $LogFilePath -Parent
            if (-not (Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }
            Add-Content -Path $LogFilePath -Value $line -Encoding UTF8
        }
        catch {
            Write-Warning "Could not write to log file '$LogFilePath': $_"
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
            New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction Stop
            Write-Log "Created Event Log source '$EventLogSource' in '$EventLogName'." -Level INFO
        }
    }
    catch {
        Write-Log "Could not create Event Log source (requires admin): $_" -Level WARNING
        # Non-fatal — continue without Event Log
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
    try {
        Write-EventLog -LogName $EventLogName -Source $EventLogSource `
                       -EntryType $EntryType -EventId $EventId -Message $Message
    }
    catch {
        Write-Log "Event Log write failed: $_" -Level WARNING
    }
}

# ────────────────────────────────────────────────────────────
#  HELPER: Load SMTP credential from encrypted XML
# ────────────────────────────────────────────────────────────
function Get-SmtpCredential {
    if (-not $EnableEmail) { return $null }

    # If caller already set $SmtpCredential, use it as-is
    if ($null -ne $SmtpCredential) { return $SmtpCredential }

    if ($SmtpCredentialPath -ne '' -and (Test-Path $SmtpCredentialPath)) {
        try {
            $cred = Import-Clixml -Path $SmtpCredentialPath -ErrorAction Stop
            Write-Log "SMTP credential loaded from '$SmtpCredentialPath'." -Level INFO
            return $cred
        }
        catch {
            Write-Log "Failed to load SMTP credential from '$SmtpCredentialPath': $_" -Level WARNING
        }
    }
    else {
        Write-Log "SMTP credential file not found at '$SmtpCredentialPath'. Attempting unauthenticated relay." -Level WARNING
    }
    return $null
}

# ────────────────────────────────────────────────────────────
#  HELPER: Send email alert
# ────────────────────────────────────────────────────────────
function Send-EmailAlert {
    param (
        [string]$Subject,
        [string]$Body,
        [System.Management.Automation.PSCredential]$Credential
    )

    if (-not $EnableEmail) { return }
    if ($WhatIfPreference) {
        Write-Log "[WhatIf] Would send email: '$Subject'" -Level INFO
        return
    }

    try {
        $mailParams = @{
            SmtpServer  = $SmtpServer
            Port        = $SmtpPort
            UseSsl      = $SmtpUseSsl
            From        = $From
            To          = $To
            Subject     = $Subject
            Body        = $Body
            BodyAsHtml  = $false
            ErrorAction = 'Stop'
        }
        if ($null -ne $Credential) {
            $mailParams['Credential'] = $Credential
        }

        Send-MailMessage @mailParams
        Write-Log "Email alert sent to: $($To -join ', ')" -Level INFO
    }
    catch {
        Write-Log "Failed to send email alert: $_" -Level ERROR
    }
}

# ────────────────────────────────────────────────────────────
#  HELPER: Send Microsoft Teams webhook alert
# ────────────────────────────────────────────────────────────
function Send-TeamsAlert {
    param ([string]$Message)

    if ($TeamsWebhookUrl -eq '') { return }
    if ($WhatIfPreference) {
        Write-Log "[WhatIf] Would post Teams message: $Message" -Level INFO
        return
    }

    try {
        $payload = @{
            '@type'      = 'MessageCard'
            '@context'   = 'http://schema.org/extensions'
            'summary'    = 'Disk Space Alert'
            'themeColor' = 'FF0000'
            'title'      = 'Disk Space Alert'
            'text'       = $Message
        } | ConvertTo-Json -Depth 3

        Invoke-RestMethod -Uri $TeamsWebhookUrl -Method Post `
                          -ContentType 'application/json' -Body $payload -ErrorAction Stop
        Write-Log "Teams alert sent." -Level INFO
    }
    catch {
        Write-Log "Failed to send Teams alert: $_" -Level ERROR
    }
}

# ────────────────────────────────────────────────────────────
#  HELPER: Send Slack webhook alert
# ────────────────────────────────────────────────────────────
function Send-SlackAlert {
    param ([string]$Message)

    if ($SlackWebhookUrl -eq '') { return }
    if ($WhatIfPreference) {
        Write-Log "[WhatIf] Would post Slack message: $Message" -Level INFO
        return
    }

    try {
        $payload = @{ text = $Message } | ConvertTo-Json
        Invoke-RestMethod -Uri $SlackWebhookUrl -Method Post `
                          -ContentType 'application/json' -Body $payload -ErrorAction Stop
        Write-Log "Slack alert sent." -Level INFO
    }
    catch {
        Write-Log "Failed to send Slack alert: $_" -Level ERROR
    }
}

# ────────────────────────────────────────────────────────────
#  HELPER: Append result row to CSV history file
# ────────────────────────────────────────────────────────────
function Export-CsvRow {
    param ([PSCustomObject]$Row)

    if ($CsvExportPath -eq '') { return }
    try {
        $csvDir = Split-Path $CsvExportPath -Parent
        if (-not (Test-Path $csvDir)) {
            New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
        }
        # Export-Csv with -Append avoids overwriting existing history
        $Row | Export-Csv -Path $CsvExportPath -Append -NoTypeInformation -Encoding UTF8
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
            throw "Drive reports zero total size — may be unmounted or offline."
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
Write-Log "Monitoring drives: $($DrivesToMonitor -join ', ')" -Level INFO
if ($WhatIfPreference) {
    Write-Log '[WhatIf / Test Mode] No alerts will be sent.' -Level WARNING
}

# Initialise Event Log source (requires admin first time)
Initialize-EventLogSource

# Load SMTP credential once
$resolvedCredential = Get-SmtpCredential

# Collect results across all drives
$allResults     = [System.Collections.Generic.List[PSCustomObject]]::new()
$alertMessages  = [System.Collections.Generic.List[string]]::new()

foreach ($driveLetter in $DrivesToMonitor) {
    $res = Test-DriveSpace -DriveLetter $driveLetter

    # Build console / log output line
    switch ($res.Status) {
        'OK' {
            $line = "Drive $($res.Drive): Healthy — $($res.FreePercent)% free " +
                    "($($res.FreeGB) GB free of $($res.TotalGB) GB total)"
            Write-Log $line -Level INFO
        }
        'WARNING' {
            $line = "WARNING: Drive $($res.Drive): LOW DISK SPACE — " +
                    "$($res.FreePercent)% free ($($res.FreeGB) GB free of $($res.TotalGB) GB total)"
            Write-Log $line -Level ALERT
            $alertMessages.Add($line)

            # Write Warning event to Event Log
            Write-EventLogEntry -Message $line `
                                -EntryType Warning -EventId 1001
        }
        default {
            $line = "Drive $($res.Drive): Status=$($res.Status) — $($res.ErrorMessage)"
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
#  ALERTS: Send consolidated notifications if any drives breached
# ────────────────────────────────────────────────────────────
if ($alertMessages.Count -gt 0) {

    $alertBody = @"
DISK SPACE ALERT — $(Get-Timestamp)
Computer : $env:COMPUTERNAME
Script    : $PSCommandPath

The following drives are below the $ThresholdPercent% free space threshold:

$($alertMessages -join "`n")

Please take corrective action (clean up files, extend volume, etc.).

-- Automated Disk Space Monitor --
"@

    $subject = "$EmailSubjectPrefix Low disk space on $env:COMPUTERNAME"

    # Email
    Send-EmailAlert -Subject $subject -Body $alertBody -Credential $resolvedCredential

    # Teams
    Send-TeamsAlert -Message ($alertMessages -join "`n")

    # Slack
    Send-SlackAlert -Message ($alertMessages -join "`n")

    Write-Log "Alert cycle complete. $($alertMessages.Count) drive(s) in WARNING state." -Level ALERT
}
else {
    $okCount = ($allResults | Where-Object Status -eq 'OK').Count
    Write-Log "All $okCount monitored drive(s) are within healthy thresholds." -Level INFO

    # Informational Event Log entry on clean run
    Write-EventLogEntry -Message "Disk Monitor: All drives OK on $env:COMPUTERNAME." `
                        -EntryType Information -EventId 1000
}

Write-Log 'Disk Space Monitor finished.' -Level INFO
Write-Log '=================================================' -Level INFO

# Return exit code 0 (success) or 1 (at least one alert)
if ($alertMessages.Count -gt 0) { exit 1 } else { exit 0 }
