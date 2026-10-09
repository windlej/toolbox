# Runbook: Schedule disk space monitoring

Runs `scripts/windows/server/Get-DiskSpaceStatus.ps1` on a schedule so low-space volumes are caught before they fill. Parameters, permissions and examples are in the script header (`Get-Help` or `docs/scripts/Get-DiskSpaceStatus.md`). This runbook covers the setup around it.

## 1. Copy the script and pick folders

Copy the single script to the server, e.g. `D:\Scripts\Get-DiskSpaceStatus.ps1`. Choose a **fixed** output folder, e.g. `D:\Reports`. The script keeps one growing history file there (`Get-DiskSpaceStatus_History.csv`), so the scheduled task must always use the same `-OutputPath` (and `-CustomerName`, if you use it).

## 2. (Optional) Store an SMTP credential

Only needed for authenticated email alerts. Run as the account the task will run under; the file can only be read by that account on that machine.

```powershell
New-Item -ItemType Directory -Path D:\Secure -Force
Get-Credential | Export-Clixml -Path D:\Secure\smtp_cred.xml
```

Restrict NTFS permissions on `D:\Secure` to that account.

## 3. Test with a dry run

```powershell
.\Get-DiskSpaceStatus.ps1 -OutputPath D:\Reports -ThresholdPercent 15 -WhatIf
```

`-WhatIf` checks the disks and writes the log but sends no alerts and doesn't append to the history.

Run once elevated without `-WhatIf` so the Event Log source gets created, or pass `-SkipEventLog`.

## 4. Register the scheduled task

```powershell
$args = '-NoProfile -ExecutionPolicy Bypass -File "D:\Scripts\Get-DiskSpaceStatus.ps1" -OutputPath "D:\Reports" -ThresholdPercent 15'
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $args
$trigger = New-ScheduledTaskTrigger -Daily -At 6am
Register-ScheduledTask -TaskName 'Disk Space Status' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest
```

Add alert parameters to `$args` as needed, e.g. `-SmtpServer smtp.contoso.com -From monitor@contoso.com -To admin@contoso.com -SmtpCredentialPath "D:\Secure\smtp_cred.xml"`, or `-TeamsWebhookUrl <url>`. A task running as SYSTEM can't read a credential file created by another user; run the task as the same account that created it.

The task result is 0 when all drives are healthy and 1 when any drive is below the threshold, so Task Scheduler or an RMM can alert on failure.

## 5. Check results

```powershell
Get-Content (Get-ChildItem D:\Reports\Get-DiskSpaceStatus_*.log | Sort-Object LastWriteTime | Select-Object -Last 1) -Tail 50
Import-Csv D:\Reports\Get-DiskSpaceStatus_History.csv | Sort-Object Timestamp -Descending | Select-Object -First 20 | Format-Table
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Task runs but nothing is written | `-OutputPath` missing; a scheduled task can't answer the prompt. |
| No email | `-SmtpServer`, `-From` and `-To` must all be supplied; check the log for the SMTP error. |
| Credential file fails to load | It was created by a different user or on a different machine. Recreate it as the task account. |
| Event Log warning in the log | The event source doesn't exist yet. Run once elevated, or use `-SkipEventLog`. |
