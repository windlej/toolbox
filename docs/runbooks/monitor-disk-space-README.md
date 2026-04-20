# Disk Space Monitor — Setup & Scheduling Guide

## Files
| File | Purpose |
|---|---|
| `Monitor-DiskSpace.ps1` | Main monitoring script |
| `Register-DiskMonitorTask.ps1` | One-click Task Scheduler registration |

---

## 1. Setting Up SMTP Credentials Securely

PowerShell's `Export-Clixml` encrypts credentials using **Windows Data Protection API (DPAPI)** — the file is tied to the **current Windows user account and machine**, so it cannot be decrypted on another computer.

### Step-by-step

```powershell
# Run once, interactively, as the SERVICE ACCOUNT that will run the task
# (e.g. open PowerShell as that user / runas)

# 1. Create the secure folder (if it doesn't exist)
New-Item -ItemType Directory -Path 'C:\Secure' -Force

# 2. Prompt for SMTP credentials and save encrypted to disk
Get-Credential -Message 'Enter SMTP username and password' |
    Export-Clixml -Path 'C:\Secure\smtp_cred.xml'

# 3. Lock down the file — only the current user can read it
$acl  = Get-Acl 'C:\Secure\smtp_cred.xml'
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "$env:USERDOMAIN\$env:USERNAME", 'FullControl', 'Allow'
)
$acl.SetAccessRule($rule)
Set-Acl 'C:\Secure\smtp_cred.xml' $acl
```

> **Important:** The scheduled task must run as the **same user** that created the XML file, otherwise decryption will fail.

---

## 2. Setting the PowerShell Execution Policy

If scripts are blocked on your machine, run this **once** as Administrator:

```powershell
# Allow locally-written scripts (safest relaxation)
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine

# Or, for the current user only:
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 3. Registering the Scheduled Task

### Option A — PowerShell (recommended, automatable)

Save and run the script below as Administrator:

```powershell
# Register-DiskMonitorTask.ps1
# Run as Administrator

$scriptPath = 'C:\Scripts\Monitor-DiskSpace.ps1'
$taskName   = 'DiskSpaceMonitor'
$taskDesc   = 'Monitors drive free space and sends alerts when below threshold.'

# Action: launch PowerShell and run the script
$action  = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

# Trigger: every 30 minutes, indefinitely
$trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 30) `
    -Once -At (Get-Date)

# Settings: run whether logged in or not, with highest privileges
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
    -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable:$false

# Principal: SYSTEM account (no password needed) or a specific service account
$principal = New-ScheduledTaskPrincipal `
    -UserId 'SYSTEM' `
    -LogonType ServiceAccount `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName   $taskName `
    -Description $taskDesc `
    -Action     $action `
    -Trigger    $trigger `
    -Settings   $settings `
    -Principal  $principal `
    -Force

Write-Host "Task '$taskName' registered successfully." -ForegroundColor Green
```

> **Note on SYSTEM account vs service account:**
> If you use `SYSTEM`, email credentials are not needed for Windows Event Log or log-file-only alerting. To send email, use a dedicated service account that owns the `smtp_cred.xml` file.

---

### Option B — Task Scheduler GUI

1. Open **Task Scheduler** (`taskschd.msc`)
2. Click **Create Task** (not "Basic Task") in the right pane
3. **General** tab:
   - Name: `DiskSpaceMonitor`
   - Check **Run whether user is logged in or not**
   - Check **Run with highest privileges**
   - Configure for: `Windows 10` / `Windows Server 2019` (your OS)
4. **Triggers** tab → **New**:
   - Begin the task: **On a schedule**
   - Settings: **Daily**, repeat every **30 minutes** for a duration of **1 day**
5. **Actions** tab → **New**:
   - Program: `powershell.exe`
   - Arguments: `-NonInteractive -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Monitor-DiskSpace.ps1"`
6. **Conditions** tab:
   - Uncheck **Start the task only if the computer is on AC power** (for servers)
7. **Settings** tab:
   - Check **Run task as soon as possible after a scheduled start is missed**
   - Set **Stop the task if it runs longer than: 5 minutes**
8. Click **OK** and enter the service account password when prompted.

---

## 4. Testing the Script

### Dry-run (no alerts sent, full console output)
```powershell
.\Monitor-DiskSpace.ps1 -WhatIf
```

### Verbose tracing
```powershell
.\Monitor-DiskSpace.ps1 -Verbose
```

### Force an alert (temporarily lower the threshold)
```powershell
# In the script, set:
$ThresholdPercent = 99   # Almost every drive will trigger WARNING
```

### Manually run the scheduled task
```powershell
Start-ScheduledTask -TaskName 'DiskSpaceMonitor'
```

### Check task history
```powershell
Get-ScheduledTaskInfo -TaskName 'DiskSpaceMonitor' |
    Select-Object LastRunTime, LastTaskResult, NextRunTime
```

---

## 5. Viewing Alerts

### Log file
```powershell
Get-Content 'C:\Logs\DiskMonitor\DiskMonitor.log' -Tail 50
```

### CSV history
```powershell
Import-Csv 'C:\Logs\DiskMonitor\DiskMonitor_History.csv' |
    Sort-Object Timestamp -Descending |
    Select-Object -First 20 |
    Format-Table -AutoSize
```

### Windows Event Log
```powershell
Get-EventLog -LogName Application -Source DiskSpaceMonitor -Newest 20 |
    Format-Table TimeGenerated, EntryType, Message -AutoSize
```

---

## 6. Optional: Teams / Slack Webhooks

### Microsoft Teams
1. In Teams, open the channel → **⋯** → **Connectors** → **Incoming Webhook** → **Configure**
2. Copy the webhook URL
3. Paste into `$TeamsWebhookUrl` in the script

### Slack
1. Go to [api.slack.com/apps](https://api.slack.com/apps) → **Create an App** → **Incoming Webhooks**
2. Activate and add to your workspace channel
3. Copy the webhook URL and paste into `$SlackWebhookUrl`

---

## 7. Exit Codes

| Code | Meaning |
|---|---|
| `0` | All drives healthy |
| `1` | One or more drives in WARNING state |

Task Scheduler interprets exit code `0` as success. Non-zero codes can trigger email alerts in the task's own notification settings as a secondary safety net.

---

## 8. Recommended Folder Structure

```
C:\
├── Scripts\
│   └── Monitor-DiskSpace.ps1       ← Main script
├── Secure\
│   └── smtp_cred.xml               ← Encrypted SMTP credential (DPAPI)
└── Logs\
    └── DiskMonitor\
        ├── DiskMonitor.log          ← Appended execution log
        └── DiskMonitor_History.csv  ← Full CSV history
```

Set NTFS permissions on `C:\Secure\` so only the service account has read access.
