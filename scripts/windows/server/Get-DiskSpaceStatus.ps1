#Requires -Version 5.1

<#
.SYNOPSIS
    Monitors disk space on Windows systems and sends alerts when free space
    falls below a configurable threshold.

.DESCRIPTION
    This script checks one or more drives for available disk space, compares
    the free percentage against a defined threshold, and triggers alerts via
    email, Teams/Slack webhook, Windows Event Log, and/or a log file. Designed
    for unattended execution via Windows Task Scheduler.

    Alerting is opt-in: email is sent only when -SmtpServer, -From and -To are all
    supplied, and webhooks are posted only when a webhook URL is supplied. With none
    of them the script still logs, writes the history CSV and the Event Log entries.

    Files written to the resolved output folder:
      - Get-DiskSpaceStatus_<yyyyMMdd_HHmmss>.log  (one log per run)
      - Get-DiskSpaceStatus_History.csv            (fixed name; one row per drive per run)
    The history CSV intentionally keeps a fixed name because it accumulates between runs so
    you can trend free space over time. Because of that, a scheduled task must always use the
    same -OutputPath (and -CustomerName) so every run appends to the same file.

    Exit code: 0 when all drives are healthy, 1 when at least one drive is below the
    threshold.

.PARAMETER Drive
    Drives to check, for example C: or D:. Default: C: and D:. Old name: DrivesToMonitor.

.PARAMETER ThresholdPercent
    Alert when free space drops below this percentage (1-99). Default: 15.

.PARAMETER OutputPath
    Folder for the log file and history CSV. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.
    Use an explicit path for scheduled tasks (a scheduled task cannot answer the prompt).

.PARAMETER CustomerName
    Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER SkipEventLog
    Do not write entries to the Windows Event Log. By default entries are written under the
    source named by -EventLogSource (creating the source needs an elevated session once).

.PARAMETER EventLogSource
    Event Log source name. Default: DiskSpaceMonitor.

.PARAMETER EventLogName
    Event Log to write into. Default: Application.

.PARAMETER SmtpServer
    SMTP server for email alerts. Email is off unless this, -From and -To are all supplied.

.PARAMETER SmtpPort
    SMTP port. Default: 587.

.PARAMETER NoSmtpSsl
    Disable SSL/TLS for the SMTP connection (SSL is on by default).

.PARAMETER From
    Sender address for email alerts, for example monitor@contoso.com.

.PARAMETER To
    One or more recipient addresses for email alerts, for example admin@contoso.com.

.PARAMETER EmailSubjectPrefix
    Prefix for the alert subject. Default: [DISK ALERT].

.PARAMETER SmtpCredential
    PSCredential for authenticated SMTP. Takes precedence over -SmtpCredentialPath.

.PARAMETER SmtpCredentialPath
    Path to an encrypted credential file created with Export-Clixml (readable only by the
    same user on the same machine). If omitted or not found, unauthenticated relay is tried.

.PARAMETER TeamsWebhookUrl
    Optional Microsoft Teams incoming webhook URL. Teams alerts are off when omitted.

.PARAMETER SlackWebhookUrl
    Optional Slack incoming webhook URL. Slack alerts are off when omitted.

.PARAMETER WhatIf
    Dry-run mode (standard PowerShell switch). No emails or webhook posts are sent, no Event
    Log entries are written and the history CSV is not appended, but all disk checks and
    console/log output are performed.

.PARAMETER Verbose
    Enables verbose output for detailed execution tracing.

.EXAMPLE
    .\Get-DiskSpaceStatus.ps1 -OutputPath D:\Reports

    Checks C: and D: against the 15% default and logs to D:\Reports.

.EXAMPLE
    .\Get-DiskSpaceStatus.ps1 -Drive C:,E: -ThresholdPercent 10 -OutputPath D:\Reports -CustomerName Contoso -WhatIf

    Dry run: checks C: and E: against 10% and sends no alerts.

.EXAMPLE
    .\Get-DiskSpaceStatus.ps1 -OutputPath D:\Reports -SmtpServer smtp.contoso.com -From monitor@contoso.com -To admin@contoso.com -SmtpCredentialPath D:\Secure\smtp_cred.xml

    Emails admin@contoso.com when a drive is below the threshold.

.EXAMPLE
    # Scheduled task (daily 06:00). -OutputPath is passed explicitly because a task cannot be prompted.
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "D:\Scripts\Get-DiskSpaceStatus.ps1" -OutputPath "D:\Reports" -ThresholdPercent 15'
    $trigger = New-ScheduledTaskTrigger -Daily -At 6am
    Register-ScheduledTask -TaskName 'Disk Space Status' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest

.NOTES
    Platform:     Windows (PowerShell 5.1+)
    Permissions:  Local user can read drive free space; Administrator needed once to create the Event Log source; outbound access to the SMTP server or webhook if alerts are used
    When to use:  Scheduled daily check on a server to catch volumes running low before they fill, or an ad-hoc free-space check during an incident.
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

    [string]$EventLogName = 'Application',

    [string]$SmtpServer,

    [int]$SmtpPort = 587,

    [switch]$NoSmtpSsl,

    [string]$From,

    [string[]]$To,

    [string]$EmailSubjectPrefix = '[DISK ALERT]',

    [System.Management.Automation.PSCredential]$SmtpCredential,

    [string]$SmtpCredentialPath,

    [string]$TeamsWebhookUrl,

    [string]$SlackWebhookUrl
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
$SmtpUseSsl     = -not $NoSmtpSsl
$EnableEmail    = [bool]($SmtpServer -and $From -and $To)
if ($SmtpServer -or $From -or $To) {
    if (-not $EnableEmail) {
        Write-Warning 'Email alerts need -SmtpServer, -From and -To together; email is disabled.'
    }
}

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
#  HELPER: Load SMTP credential (parameter, else encrypted XML)
# ────────────────────────────────────────────────────────────
function Get-SmtpCredential {
    if (-not $EnableEmail) { return $null }

    # If caller supplied -SmtpCredential, use it as-is
    if ($null -ne $SmtpCredential) { return $SmtpCredential }

    if ($SmtpCredentialPath -and (Test-Path -LiteralPath $SmtpCredentialPath)) {
        try {
            $cred = Import-Clixml -LiteralPath $SmtpCredentialPath -ErrorAction Stop
            Write-Log "SMTP credential loaded from '$SmtpCredentialPath'." -Level INFO
            return $cred
        }
        catch {
            Write-Log "Failed to load SMTP credential from '$SmtpCredentialPath': $_" -Level WARNING
        }
    }
    else {
        Write-Log 'No SMTP credential supplied or file not found. Attempting unauthenticated relay.' -Level WARNING
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

    if (-not $TeamsWebhookUrl) { return }
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
        Write-Log 'Teams alert sent.' -Level INFO
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

    if (-not $SlackWebhookUrl) { return }
    if ($WhatIfPreference) {
        Write-Log "[WhatIf] Would post Slack message: $Message" -Level INFO
        return
    }

    try {
        $payload = @{ text = $Message } | ConvertTo-Json
        Invoke-RestMethod -Uri $SlackWebhookUrl -Method Post `
                          -ContentType 'application/json' -Body $payload -ErrorAction Stop
        Write-Log 'Slack alert sent.' -Level INFO
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
    Write-Log '[WhatIf / Test Mode] No alerts will be sent.' -Level WARNING
}

# Initialise Event Log source (requires admin first time)
Initialize-EventLogSource

# Load SMTP credential once
$resolvedCredential = Get-SmtpCredential

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
#  ALERTS: Send consolidated notifications if any drives breached
# ────────────────────────────────────────────────────────────
if ($alertMessages.Count -gt 0) {

    $alertBody = @"
DISK SPACE ALERT - $(Get-Timestamp)
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
    $okCount = @($allResults | Where-Object Status -eq 'OK').Count
    Write-Log "All $okCount monitored drive(s) are within healthy thresholds." -Level INFO

    # Informational Event Log entry on clean run
    Write-EventLogEntry -Message "Disk Monitor: All drives OK on $env:COMPUTERNAME." `
                        -EntryType Information -EventId 1000
}

Write-Log 'Disk Space Monitor finished.' -Level INFO
Write-Log '=================================================' -Level INFO

# Return exit code 0 (success) or 1 (at least one alert)
if ($alertMessages.Count -gt 0) { exit 1 } else { exit 0 }
