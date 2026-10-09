# Bug Report (running)

Bugs found but not fixed, plus a short log of what was fixed. Add new entries at the bottom of **Open**. Each entry is written so it can be handed to a subagent as-is: it names the file, the symptom, the suggested fix and how to check it.

Rules for whoever picks one up: read `docs/DESIGN-GUIDE.md` first, fix only that entry, one commit per script, update comment-based help if behavior changes, and move the entry to **Fixed** with the commit hash. `pwsh` may not be available; if so, say what could not be verified.

## Open

### BUG-001: Test-DomainHealth NTP Warn details print as a space-joined array
- **File:** `scripts/windows/active-directory/Test-DomainHealth.ps1` (`Test-NtpSync`, Warn branch)
- **Symptom:** `Details = $w32tm` stores the raw `w32tm` output array, so the HTML cell shows all lines joined by spaces.
- **Suggested fix:** `Details = (($w32tm | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) -join '; ')`.
- **Verify:** read-through only unless pwsh is available; confirm the Warn row renders one readable line.
- **Severity:** Low (cosmetic)

### BUG-002: Test-DomainHealth `Test-FsmoRoles` try/catch is dead code
- **File:** `scripts/windows/active-directory/Test-DomainHealth.ps1` (`Test-FsmoRoles`)
- **Symptom:** After the FSMO fix the function only reads properties from objects passed in, so the `catch` can never run. A null role holder would still report Pass.
- **Suggested fix:** Either drop the try/catch, or return Warn/Fail when any of the five role properties is empty.
- **Verify:** read-through; check that a missing role holder is not reported as Pass.
- **Severity:** Low

### BUG-003: Test-DomainHealth skips all remaining checks for an unreachable DC without noting it in the summary
- **File:** `scripts/windows/active-directory/Test-DomainHealth.ps1` (DC loop)
- **Symptom:** A DC that fails ping gets one Connectivity Fail row and no Netlogon, dcdiag, replication or NTP rows, so the Total Checks count differs per DC and nothing says the other checks were skipped.
- **Suggested fix:** Make the Details text say "Unreachable; remaining checks skipped" (smallest change), or add Skipped rows.
- **Verify:** read-through.
- **Severity:** Low (design decision; confirm with owner before changing)

### BUG-004: Test-EntraConnectHealth `Get-ADConnectServer` hides Graph failures and relies on a strict-mode error
- **File:** `scripts/windows/azure/Test-EntraConnectHealth.ps1` (`Get-ADConnectServer`)
- **Symptom:** `Invoke-MgGraphRequest ... -ErrorAction SilentlyContinue` swallows a failed call, so `$Org` is null and the function only returns `$null` because `$Org.value[0]` throws under strict mode and is caught. The real error is never logged, and a Graph failure looks the same as "status unknown".
- **Suggested fix:** Use `-ErrorAction Stop`, log the exception with `Write-Log ... 'WARN'` in the `catch`, and return `$null` there.
- **Verify:** read-through; confirm a 403 (missing scope) produces a WARN naming the error.
- **Severity:** Low

### BUG-005: Test-EntraConnectHealth lacks `$ErrorActionPreference = 'Stop'` and uses SilentlyContinue for the Az checks
- **File:** `scripts/windows/azure/Test-EntraConnectHealth.ps1` (script scope; Tenant Discovery and Subscription Access checks)
- **Symptom:** Design guide §7 wants `Set-StrictMode` plus `$ErrorActionPreference = 'Stop'`. The script sets only strict mode, and `Get-AzTenant`/`Get-AzSubscription` use `-ErrorAction SilentlyContinue`, so their `catch` blocks never run. A failure shows as "No tenants found" or "0 subscriptions accessible" instead of the real error.
- **Suggested fix:** Add `$ErrorActionPreference = 'Stop'` after `Set-StrictMode`, and change those two calls to `-ErrorAction Stop` so the existing catch blocks record the message. Re-check that the Graph helpers still degrade to WARN rather than aborting.
- **Verify:** read-through; check every try/catch still behaves as intended under Stop.
- **Severity:** Medium (misleading results)

### BUG-006: Get-PasswordPolicyReport hides a failed fine-grained policy read
- **File:** `scripts/windows/active-directory/Get-PasswordPolicyReport.ps1` (`Get-ADFineGrainedPasswordPolicy ... -ErrorAction SilentlyContinue`)
- **Symptom:** Without rights to read the Password Settings Container the call fails silently, so the report shows no fine-grained policies and nothing says they could not be read. That looks the same as "none defined".
- **Suggested fix:** Use `-ErrorAction Stop` in a try/catch; on failure `Write-Log ... 'WARN'` and show "Could not read (insufficient rights?)" in the report instead of an empty section.
- **Verify:** read-through; run as a non-admin and confirm a WARN and the note appear.
- **Severity:** Medium (misleading result)

### BUG-007: Get-PasswordPolicyReport has no try/catch around the AD calls
- **File:** `scripts/windows/active-directory/Get-PasswordPolicyReport.ps1` (`Get-ADDomain`, `Get-ADDefaultDomainPasswordPolicy`, `Get-ADUser`, report write)
- **Symptom:** Design guide §7 wants connections and writes wrapped with a clear message. A failure (no domain, no rights, unwritable output folder) ends as a raw terminating error and the log has no ERROR line.
- **Suggested fix:** Wrap the AD reads and the `Out-File`/`Export-Csv` writes in try/catch, `Write-Log ... 'ERROR'`, then rethrow.
- **Verify:** read-through.
- **Severity:** Low

### BUG-008: Get-PasswordPolicyReport writes AD values into HTML without encoding
- **File:** `scripts/windows/active-directory/Get-PasswordPolicyReport.ps1` (`$HtmlUserRows`, fine-grained policy names)
- **Symptom:** Name, SamAccountName and policy names are inserted raw. A value containing `<`, `&` or markup breaks or injects into the report.
- **Suggested fix:** Wrap each inserted value in `[System.Net.WebUtility]::HtmlEncode(...)` (available in 5.1 without extra modules).
- **Verify:** read-through; confirm a name like `A&B <x>` renders literally.
- **Severity:** Low

### BUG-009: Remove-StaleADComputer does not handle protected-from-accidental-deletion accounts
- **File:** `scripts/windows/active-directory/Remove-StaleADComputer.ps1` (delete block)
- **Symptom:** A computer object with "Protect object from accidental deletion" set fails to delete. It is caught and reported as `DeleteFailed`, but the report and `-WhatIf` don't warn in advance, so a dry run shows a planned `Delete` that will fail.
- **Suggested fix:** Read `ProtectedFromAccidentalDeletion` (add it to `-Properties`). If set, report `DeleteSkippedProtected` and log a WARN. Optionally add an opt-in switch that clears the flag first (behind `ShouldProcess`).
- **Verify:** read-through; confirm a protected account shows as skipped in `-WhatIf`.
- **Severity:** Low

### BUG-010: Remove-StaleADComputer child-object check is one level deep and failures surface as DeleteFailed
- **File:** `scripts/windows/active-directory/Remove-StaleADComputer.ps1` (`Get-ADObject -SearchScope OneLevel`)
- **Symptom:** The child count only covers direct children, so the `-WhatIf` figure can understate what `-DeleteChildObjects` removes. If the child check itself errors, the row is `DeleteFailed` although nothing was attempted.
- **Suggested fix:** Use `-SearchScope Subtree` and subtract the computer itself (or filter on `DistinguishedName -ne`). Report a distinct `ChildCheckFailed` action.
- **Verify:** read-through; compare the count with a computer that has nested child objects.
- **Severity:** Low

### BUG-011: Remove-StaleADComputer unused `-Properties` entries
- **File:** `scripts/windows/active-directory/Remove-StaleADComputer.ps1` (`$queryParams.Properties`)
- **Symptom:** `Description` and `IPv4Address` are requested but never used. `IPv4Address` triggers a DNS lookup per computer, which slows large runs.
- **Suggested fix:** Drop both, or add them to the report.
- **Verify:** read-through.
- **Severity:** Low (performance)

### BUG-012: Get-PrivilegedGroupChange "Baseline not found" message is misleading when both switches are used
- **File:** `scripts/windows/active-directory/Get-PrivilegedGroupChange.ps1` (`elseif ($CompareWithBaseline)` branch)
- **Symptom:** With `-CompareWithBaseline -UpdateBaseline` and no existing baseline, the WARN says to "run with -UpdateBaseline first", although the same run creates it.
- **Suggested fix:** If `$UpdateBaseline` is set, log INFO "No baseline yet; creating it. No comparison possible on this run."
- **Verify:** read-through.
- **Severity:** Low (cosmetic)

### BUG-014: Get-PrivilegedGroupChange hides AD read failures
- **File:** `scripts/windows/active-directory/Get-PrivilegedGroupChange.ps1` (`Get-PrivilegedMembers`)
- **Symptom:** `Get-ADGroup`, `Get-ADGroupMember` and `Get-ADPrincipalGroupMembership` use `-ErrorAction SilentlyContinue`. A group that cannot be read, or a missing group, is skipped without a log line. Worse, a failed membership read looks like "no members", so a later `-CompareWithBaseline` reports every member as Removed, and `-UpdateBaseline` saves a baseline that lacks them.
- **Suggested fix:** Use `-ErrorAction Stop` and log a WARN per group that is missing or unreadable. Consider skipping the baseline update when any group failed.
- **Verify:** read-through; confirm a nonexistent group name in `-ProtectedGroups` logs a WARN (some default names, e.g. Organization Management, legitimately don't exist in every domain).
- **Severity:** Medium (can corrupt the baseline)

### BUG-015: Get-PrivilegedGroupChange and Get-ADGroupMembershipReport write AD values into HTML without encoding
- **File:** `scripts/windows/active-directory/Get-PrivilegedGroupChange.ps1` (`$HtmlRows`, `$HtmlChangeRows`), `scripts/windows/active-directory/Get-ADGroupMembershipReport.ps1` (`$HtmlRows`)
- **Symptom:** Names, titles and departments are inserted raw; markup in a value breaks or injects into the report. Same issue as BUG-008.
- **Suggested fix:** Wrap each inserted value in `[System.Net.WebUtility]::HtmlEncode(...)`. One commit per script.
- **Verify:** read-through; confirm `A&B <x>` renders literally.
- **Severity:** Low

### BUG-018: Test-BackupStatus reads Windows Server Backup properties that may not exist
- **File:** `scripts/windows/server/Test-BackupStatus.ps1` (`Test-WbadminBackup`: `SnapshotFailed`, `SystemState`, `BackupSize`)
- **Symptom:** Under `Set-StrictMode -Version Latest`, reading a property that a backup set object lacks throws. The call is outside the try/catch, so one odd set aborts the script. Remote results are deserialized objects, which makes missing properties more likely.
- **Suggested fix:** Check with `$Backup.PSObject.Properties['Name']` before reading, or move the loop into a try/catch that reports the set as Failed with the error text.
- **Verify:** read-through; needs a host with Windows Server Backup to confirm which properties exist.
- **Severity:** Medium (can abort the run)

### BUG-019: Get-HyperVInventory disk sizes use the local machine for remote hosts
- **File:** `scripts/windows/server/Get-HyperVInventory.ps1` (`Get-Item $Path` under `-IncludeStorage`)
- **Symptom:** The VHD path belongs to the Hyper-V host, but `Get-Item` runs locally. For a remote host the file isn't found, and `SilentlyContinue` turns that into a size of 0 (or `N/A`). `Get-Item` also isn't `-LiteralPath`, so paths with `[` `]` fail.
- **Suggested fix:** Use `Get-VHD -ComputerName $HostName -Path $Path` and its `FileSize`, or build the `\\host\X$\...` admin-share path. Use `-LiteralPath` if `Get-Item` stays.
- **Verify:** read-through; run against a remote host with `-IncludeStorage`.
- **Severity:** Medium (wrong data for remote hosts)

### BUG-020: Get-PatchComplianceReport `-KbIds` values are matched as regular expressions
- **File:** `scripts/windows/server/Get-PatchComplianceReport.ps1` (`$_.Title -match $Kb`)
- **Symptom:** `-match` treats the KB string as a regex. Normal KB IDs are safe, but a value containing `.`, `(` or `+` matches the wrong titles or throws.
- **Suggested fix:** Use `[regex]::Escape($Kb)` (or `-like "*$Kb*"` with wildcard escaping).
- **Verify:** read-through.
- **Severity:** Low

### BUG-021: Get-PatchComplianceReport local-machine check for `-IncludeRebootStatus` misses the FQDN
- **File:** `scripts/windows/server/Get-PatchComplianceReport.ps1` (`Get-PatchStatus`, reboot check)
- **Symptom:** Only `$env:COMPUTERNAME`, `localhost` and `.` run locally. The local FQDN or `127.0.0.1` goes through `Invoke-Command`, which fails when WinRM is not enabled (PendingReboot is then blank with a WARN).
- **Suggested fix:** Reuse the `Test-LocalComputer` helper from `Get-EventLogAnomaly.ps1` (commit `397fe65`), pasted in per design guide §10.
- **Verify:** read-through.
- **Severity:** Low

### BUG-022: Get-FileServerPermissionReport share query excludes admin shares, so `IsSpecial` is always false
- **File:** `scripts/windows/server/Get-FileServerPermissionReport.ps1` (`Get-ShareReport`, `-Filter "Type = 0"`)
- **Symptom:** `Win32_Share` Type 0 is disk shares only. ADMIN$, IPC$ and C$ have other types, so the `IsSpecial` regex never matches.
- **Suggested fix:** Drop the filter and let `IsSpecial` mark them, or remove `IsSpecial`. Decide which with the owner.
- **Verify:** read-through.
- **Severity:** Low

### BUG-023: Get-FileServerPermissionReport `-ReportUnusedShares` lists all shares, not unused ones
- **File:** `scripts/windows/server/Get-FileServerPermissionReport.ps1`
- **Symptom:** The name implies unused shares are identified. The script only lists shares with their permissions (help now says so).
- **Suggested fix:** Either rename the switch (keep the old name as an alias) to something like `-IncludeShares`, or add a usage check (for example `Get-SmbOpenFile`/session data).
- **Verify:** read-through.
- **Severity:** Low (naming/design decision)

### BUG-024: Get-FileServerPermissionReport uses `-Path` for file lookups, so `[` `]` in names misbehave
- **File:** `scripts/windows/server/Get-FileServerPermissionReport.ps1` (`Get-Acl`, `Get-Item`, `Get-ChildItem` in `Get-PermissionReport`)
- **Symptom:** Wildcard characters in folder names make the cmdlets match the wrong items or none. `Get-Item ... SilentlyContinue` then returns null.
- **Suggested fix:** Use `-LiteralPath` on all three calls.
- **Verify:** read-through; scan a folder named `Reports [2024]`.
- **Severity:** Low

### BUG-025: Get-FileServerPermissionReport local-account filter uses an unescaped computer name in a regex
- **File:** `scripts/windows/server/Get-FileServerPermissionReport.ps1` (`-match "^$env:COMPUTERNAME\\"`)
- **Symptom:** Computer names can contain `-` and other regex-sensitive characters. It also only filters the machine running the script, not a remote UNC path's host.
- **Suggested fix:** Use `[regex]::Escape($env:COMPUTERNAME)`.
- **Verify:** read-through.
- **Severity:** Low

### BUG-026: Test-AzureStorageExposure sorts the report by RiskLevel alphabetically
- **File:** `scripts/windows/azure/Test-AzureStorageExposure.ps1` (`Sort-Object RiskLevel, SubscriptionName`)
- **Symptom:** Order is High, Low, Medium instead of High, Medium, Low.
- **Suggested fix:** Sort on a severity rank, as `Get-AzureNsgRiskReport.ps1` now does.
- **Verify:** read-through.
- **Severity:** Low

### BUG-027: Get-AzureVMInventory matches disks to VMs with a regex
- **File:** `scripts/windows/azure/Get-AzureVMInventory.ps1` (`$_.ManagedBy -match $VM.Id`)
- **Symptom:** The VM resource ID is used as a regex pattern. Also, `ManagedBy` can be null for unattached disks.
- **Suggested fix:** Compare with `-eq` (case-insensitive), or use `[regex]::Escape`.
- **Verify:** read-through.
- **Severity:** Low

### BUG-028: Get-AzureSubscriptionReport hides role assignment errors and counts only two roles
- **File:** `scripts/windows/azure/Get-AzureSubscriptionReport.ps1` (`Get-AzRoleAssignment -ErrorAction SilentlyContinue`)
- **Symptom:** A failed read gives Owners/Contributors of 0 with no warning. User Access Administrator is not counted.
- **Suggested fix:** Catch and log the error; decide whether to add the third role.
- **Verify:** read-through.
- **Severity:** Low

### BUG-029: Azure scripts do not set `$ErrorActionPreference = 'Stop'`
- **File:** `Get-AzureSubscriptionReport.ps1`, `Get-AzureRbacReport.ps1`, `Test-AzureBackupCompliance.ps1` (and possibly the other scripts in `scripts/windows/azure/`)
- **Symptom:** Violates DESIGN-GUIDE section 7. They set only `Set-StrictMode`, so non-terminating errors are not caught by their try/catch blocks.
- **Suggested fix:** Add the setting, then review every `SilentlyContinue` call that relied on the old behaviour.
- **Verify:** read-through.
- **Severity:** Low

### BUG-030: Get-AzureRbacReport attributes inherited assignments to the first subscription that returned them
- **File:** `scripts/windows/azure/Get-AzureRbacReport.ps1`
- **Symptom:** After de-duplication, a management-group or root assignment shows the subscription name of whichever subscription was scanned first.
- **Suggested fix:** Blank `SubscriptionName` for assignments above subscription scope.
- **Verify:** read-through.
- **Severity:** Low

### BUG-031: Set-AzureVMAutoShutdown schedule payload and resource name differ from the documented schema
- **File:** `scripts/windows/azure/Set-AzureVMAutoShutdown.ps1` (`Set-AutoShutdownSchedule`)
- **Symptom:** The properties have no `status`, set `enabled = "true"` (a string), have no `targetResourceId`, and send `timeInMinutes` as a string. The resource name is the fixed `shutdown-computevm` rather than `shutdown-computevm-<vmName>`, and the API version is `2017-04-26-preview` while Microsoft Learn lists `2018-09-15`. "Applied" may not mean a working schedule.
- **Suggested fix:** Compare against https://learn.microsoft.com/en-us/azure/templates/microsoft.devtestlab/schedules. Use `status = 'Enabled'`, `targetResourceId = $VMId`, numeric `timeInMinutes`, and the documented name and API version. Update `Get-ExistingAutoShutdown` to read the same resource name.
- **Verify:** needs a lab subscription: apply to one VM, then confirm Auto-shutdown shows enabled at the right time in the portal.
- **Severity:** Medium (may silently create nothing useful)

### BUG-032: Set-AzureVMAutoShutdown treats a disabled schedule as enabled
- **File:** `scripts/windows/azure/Set-AzureVMAutoShutdown.ps1` (`Get-ExistingAutoShutdown`)
- **Symptom:** `Enabled` is computed from `taskType -eq "ComputeVmShutdownTask"`, which is true for disabled schedules too, so VMs with a disabled schedule are reported as having auto-shutdown and are never fixed.
- **Suggested fix:** Use `$Properties.status -eq 'Enabled'`.
- **Verify:** needs a VM with a disabled schedule.
- **Severity:** Medium (misleading result)

### BUG-033: Set-AzureResourceTag report shows the full resource type
- **File:** `scripts/windows/azure/Set-AzureResourceTag.ps1` (`$TypeShort = $Type -replace 'Microsoft\.\w+\.', ''`)
- **Symptom:** The pattern expects a dot after the provider, but types look like `Microsoft.Compute/virtualMachines`, so nothing is replaced and the report shows the full string.
- **Suggested fix:** `$Type -replace '^Microsoft\.\w+/', ''` (or `($Type -split '/')[-1]`).
- **Verify:** read-through.
- **Severity:** Low (cosmetic)

### BUG-034: Set-AzureResourceTag hides resource listing failures
- **File:** `scripts/windows/azure/Set-AzureResourceTag.ps1` (`Get-ResourcesByType`, `Get-AzResource -ErrorAction SilentlyContinue`)
- **Symptom:** A failed listing (no rights, throttling) looks like a subscription with no resources of that type, so the report can show full compliance for resources that were never checked.
- **Suggested fix:** Use `-ErrorAction Stop`, and in the `catch` log a WARN naming the subscription and type and return `@()`.
- **Verify:** read-through; run as an account without Reader on one subscription and confirm a WARN.
- **Severity:** Medium (misleading result)

### BUG-035: Set-MailboxLitigationHold treats a failed mailbox read as "hold off"
- **File:** `scripts/windows/exchange/Set-MailboxLitigationHold.ps1` (`Get-MailboxHoldStatus` catch block, MAIN loop)
- **Symptom:** When `Get-Mailbox` throws, the function returns `CurrentStatus = "Error"` with `LitigationHoldEnabled = $null`. The MAIN loop only skips `Not Found`, so `-EnableHold` then tries to set a hold on that mailbox and records "Failed" (same class as the fixed not-found case). The exception text is also never logged.
- **Suggested fix:** Log the exception with `Write-Log ... 'WARN'` in the catch, and in the MAIN loop treat `CurrentStatus -eq 'Error'` like `Not Found` (action "Error", skip).
- **Verify:** read-through; confirm an errored mailbox is not passed to `Set-LitigationHold` and shows in the summary.
- **Severity:** Medium (wrong action attempted on a legal-hold script)

### BUG-036: Get-MailboxForwardingRule hides lookup errors
- **File:** `scripts/windows/exchange/Get-MailboxForwardingRule.ps1` (`Get-MailboxForwarding`, `Get-InboxRuleForwarding`)
- **Symptom:** `-ErrorAction SilentlyContinue` plus a bare `catch { return @() }` means a mailbox or rule list that cannot be read looks the same as one with no forwarding, so a security sweep can report clean for mailboxes it never checked.
- **Suggested fix:** Use `-ErrorAction Stop`; in the catch, `Write-Log ... 'WARN'` naming the mailbox and return `@()`. Optionally count unreadable mailboxes in the summary. Keep "not found" quiet if wanted.
- **Verify:** read-through; run against a UPN that does not exist and one without rights, and confirm a WARN for each.
- **Severity:** Medium (misleading result)

### BUG-037: New-SharedMailboxFromCsv hides a failed -HideFromGAL
- **File:** `scripts/windows/exchange/New-SharedMailboxFromCsv.ps1` (`New-SharedMailbox`, `Set-Mailbox -HiddenFromAddressListsEnabled ... -ErrorAction SilentlyContinue`)
- **Symptom:** If hiding the new mailbox fails (for example the mailbox is not yet visible after creation), the script still records the create as Success and the mailbox stays visible in the address list.
- **Suggested fix:** Use `-ErrorAction Stop` in its own try/catch; on failure `Write-Log ... 'WARN'` and add a `HideFromGAL` result row with status Failed, without failing the create.
- **Verify:** read-through; confirm a failure produces a Failed row while the Create row stays Success.
- **Severity:** Low

## Fixed

_Historical: the rows below are kept as a record. The e-mail alerting they mention (`-AlertEmailTo`, `-From`, `-SmtpServer`, `SmtpClient`) was later removed from these scripts because they are only run ad hoc._

| ID | Script | Summary | Commit |
|---|---|---|---|
| (pre-log) | `Remove-StaleADComputer.ps1` | Opt-in `-IncludeNeverLoggedOn` (age from whenCreated); child objects skipped by default, `-DeleteChildObjects` to remove them | `e1149cb` |
| (pre-log) | `Test-DomainHealth.ps1` | FSMO check, dcdiag Details, NTP `.Trim()` on array, unused `$Issues` | `7596b45` |
| (pre-log) | `Test-EntraConnectHealth.ps1` | Fake `Test-AzADServicePrincipalCredential` check replaced with `Get-AzContext`; Graph sign-in (`Organization.Read.All`, `-SkipGraphConnect`); unused `$AADConnect` removed | `bbbdafb` |
| (pre-log) | `Get-PasswordPolicyReport.ps1` | Null expiry no longer shown as EXPIRED (new `NO_EXPIRY_DATE` status); Critical default 7, Critical must be lower than Warning, range validation | `6955462` |
| (pre-log) | `Get-PrivilegedGroupChange.ps1` | Comparison now runs before `-UpdateBaseline`; `Send-MailMessage` replaced with `SmtpClient`; new `-From`, `-SmtpServer` has no default, alerts need all of `-AlertEmailTo`/`-From`/`-SmtpServer` | `90f3bd2` |
| (pre-log) | `Get-ADGroupMembershipReport.ps1` | `-GroupNameFilter` escaped and passed via `-LDAPFilter` (`*` stays a wildcard) | `8eb8353` |
| (pre-log) | `Get-HyperVInventory.ps1` | Uptime now `$VM.Uptime` (stray `(Get-Date) - Ticks` expression removed) | `06ee97f` |
| (pre-log) | `Test-BackupStatus.ps1` | `Get-WBBackupSet` run via `Invoke-Command` for remote targets; new `-From`, required with `-AlertEmailTo` | `a71d283` |
| (pre-log) | `Test-ServiceHealth.ps1` | Services read via CIM (works in PowerShell 7); `-ShowAllServices` implemented; new `-From`, required with `-AlertEmailTo` | `eec8794` |
| (pre-log) | `Get-PatchComplianceReport.ps1` | Reboot check runs on the target (`Invoke-Command`); `-KbIds` results added as "KB Check" column; `$HistoryCount` initialised | `bb004e4` |
| (pre-log) | `Get-FileServerPermissionReport.ps1` | Share list added to HTML and a `_Shares` CSV; share ACLs read with `Get-SmbShareAccess`; null `$Item` guarded | `c569449` |
| (pre-log) | `Get-EventLogAnomaly.ps1` | New `Test-LocalComputer`: localhost, `.`, loopback and local FQDN are treated as local | `397fe65` |
| BUG (azure) | `Get-AzureSubscriptionReport.ps1` | SQL column printed VM counts; `-SubscriptionIds` implemented; unused `-IncludeSpending` removed | `b835721` |
| BUG (azure) | `Get-AzureRbacReport.ps1` | Scope derived from each assignment; rows de-duplicated by role assignment ID | `6b59a64` |
| BUG (azure) | `Get-AzureNsgRiskReport.ps1` | Sorted by severity, not alphabetically | `9668b93` |
| BUG (azure) | `Get-AzureVMInventory.ps1` | PrivateIP read from NICs; unused Region removed; costs labelled as estimates (CSV columns renamed `Estimated*`); `Az.Network` now required | `897da2d` |
| BUG (azure) | `Test-AzureStorageExposure.ps1` | HTTPSNotRequired only raises risk, never lowers High | `873b2e2` |
| BUG (azure) | `Test-AzureBackupCompliance.ps1` | VMs matched to backup items by resource ID; `Set-AzRecoveryServicesVaultContext` removed; unreadable vault now warns | `9734546` |
| BUG (azure) | `Set-AzureResourceTag.ps1` | `-RequiredTags` optional with its default (was Mandatory plus default); `-EnforcedTagValues` must be `Tag=Value` and its tags must be in `-RequiredTags`, else the script stops; values may contain `=` | `8deafef` |
| BUG (azure) | `Set-AzureVMAutoShutdown.ps1` | `-DefaultShutdownTime` default `1900` (HHmm, per Microsoft Learn) with `ValidatePattern` | `5ac089e` |

## Not verified (needs pwsh)

- `Test-DomainHealth.ps1`: run once against a lab domain and confirm one FSMO row, populated dcdiag Details on failure, and a single-line NTP source.
- `tools/Build-Catalog.ps1` has not been re-run since the `Test-DomainHealth` description change, so `docs/scripts/Test-DomainHealth.md` is stale.
- `Test-EntraConnectHealth.ps1`: run against a lab tenant and confirm the Az check passes with a session and fails without one, that `Connect-MgGraph` prompts once (or reuses a session), and that `-SkipGraphConnect` reports sync as undetermined. The catalog (`docs/scripts/Test-EntraConnectHealth.md`) is stale after the 1.2 header change.
- `Remove-StaleADComputer.ps1`: run `-DeleteComputers -WhatIf` against a lab domain with a disabled computer that has child objects (e.g. a BitLocker recovery object). Confirm it is skipped by default and shown as `Delete (with N child object(s))` with `-DeleteChildObjects`. Confirm `-IncludeNeverLoggedOn` finds an old, never-logged-on account (this also tests the `Created` term in the server-side filter). Its catalog page is stale after the 1.1 header change.
- `Get-PasswordPolicyReport.ps1`: run with `-AuditUsers` against a lab domain and confirm a user with no expiry shows `NO_EXPIRY_DATE`, that WARNING/CRITICAL fire at the new defaults, and that `-PasswordAgeCriticalDays 30 -PasswordAgeWarningDays 30` stops with the error. Its catalog page is stale after the 1.1 header change.
- `Get-PrivilegedGroupChange.ps1`: in a lab, run `-UpdateBaseline`, add a test user to a monitored group, then run `-CompareWithBaseline -UpdateBaseline` and confirm the user shows as Added and the baseline is replaced afterwards. Its catalog page is stale after the 1.1 header change.
- `Get-ADGroupMembershipReport.ps1`: confirm `-GroupNameFilter 'SG-*'` and the default `*` still match, and that a value such as `a'b(c)` returns no groups without an error. Its catalog page is stale after the help change.
- `Get-HyperVInventory.ps1`: run against a host with running and stopped VMs and confirm the Uptime column shows `Xd Xh Xm` for running VMs and `N/A` for stopped ones.
- `Test-BackupStatus.ps1`: run `-CheckWbadmin` against a remote server with WinRM and Windows Server Backup, and against the local machine. Confirm the sets are listed with sensible properties (see BUG-018). Its catalog page is stale after the help change.
- `Test-ServiceHealth.ps1`: run in both Windows PowerShell 5.1 and PowerShell 7, locally and against a remote server. Confirm Health and StartType match `Get-Service`, and that `-ShowAllServices` lists every service. Its catalog page is stale after the help change.
- `Get-PatchComplianceReport.ps1`: run with `-IncludeRebootStatus -KbIds <a KB>` against the local machine and a remote server with WinRM. Confirm PendingReboot reflects the remote host and the KB Check column shows a date or "Not found". Its catalog page is stale after the help change.
- `Get-FileServerPermissionReport.ps1`: run with `-ReportUnusedShares -ExportCsv` on a file server. Confirm the share table and `_Shares` CSV list share permissions as `Account=Allow:Full`, and that a missing path no longer throws on `$Item.Name`. Its catalog page is stale after the help change.
- `Get-EventLogAnomaly.ps1`: run with `-ComputerName localhost`, `.`, and the local FQDN and confirm each is queried without a remote call (no RPC/firewall errors). Its catalog page is stale after the help change.
- Azure scripts (the six fixed in `b835721`..`9734546`): none were run. Check on a lab subscription that the RBAC report shows one row per assignment with correct ScopeType, that VM inventory shows IP addresses, and that `Test-AzureBackupCompliance.ps1` finds `VirtualMachineId` (or `SourceResourceId`) on backup items; if neither exists every VM shows UNPROTECTED. Their catalog pages are stale after the help changes.
- `Set-AzureResourceTag.ps1`: on a lab subscription, run without `-RequiredTags` (default tags apply), with `-EnforcedTagValues Foo=bar` (must stop, Foo not required), and with `-RequiredTags Environment -EnforcedTagValues Environment=Prod`. Its catalog page is stale after the 1.2 header change.
- `Set-AzureVMAutoShutdown.ps1`: confirm `-DefaultShutdownTime 19:00` is rejected, `1900` is accepted, and that a real apply produces an enabled schedule (see BUG-031). Its catalog page is stale after the 1.2 header change.
