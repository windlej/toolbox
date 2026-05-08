# Toolbox — Infrastructure Automation & Engineering

A collection of production-ready PowerShell scripts for managing Microsoft 365, Exchange Online, Azure, Active Directory, and Windows Server environments. Built from real-world administration scenarios — not theoretical examples.

---

## Script Inventory

### Microsoft 365 / Identity

| Script | Description |
|---|---|
| `m365/BulkUserOnboarding.ps1` | CSV-driven user provisioning with license assignment and group membership |
| `m365/BulkUserOffboarding.ps1` | Block sign-in, revoke sessions, remove licenses, convert mailbox to shared, set OneDrive retention |
| `m365/conditional-access-audit.ps1` | Export CA policies, resolve named locations, flag risky/misconfigured policies |
| `m365/MFAEnforcementReport.ps1` | Check per-user MFA registration and CA policy coverage |
| `m365/StaleUserDetection.ps1` | Find inactive users by sign-in activity, optional disable |
| `m365/GuestAccountAudit.ps1` | List guests with invitation details, stale detection, optional removal/blocking |
| `m365/LicenseOptimizationReport.ps1` | SKU utilization analysis, inactive license holders, monthly cost breakdown |
| `m365/SecureScoreReporting.ps1` | Current secure score with control-level category breakdown |
| `m365/RiskySignInParser.ps1` | Identity Protection risk detections by type/level via Graph API |
| `m365/PrivilegedRoleAudit.ps1` | Directory role + unified role assignments, PIM eligibility audit |

### Exchange Online

| Script | Description |
|---|---|
| `exchange/MailboxPermissionAudit.ps1` | FullAccess/SendAs/SendOnBehalf permission enumeration across mailboxes |
| `exchange/InboxRuleExfiltrationDetection.ps1` | Flag inbox rules matching forwarding/redirect/deletion patterns |
| `exchange/ForwardingRuleDetection.ps1` | Detect mailbox-level and inbox-rule forwarding, internal vs external |
| `exchange/SharedMailboxAutoProvision.ps1` | Create shared mailboxes from CSV with delegate permissions |
| `exchange/MailboxSizeGrowthReport.ps1` | Size/item count with configurable thresholds, archive sizing |
| `exchange/LitigationHoldEnablement.ps1` | Enable/disable/report litigation hold with duration |
| `exchange/TransportRuleExportImport.ps1` | Export transport rules to XML, bulk import with duplicate detection |

### Azure / Cloud

| Script | Description |
|---|---|
| `azure/AzureVMInventoryCostEstimator.ps1` | Multi-subscription VM scan with size-based cost estimates |
| `azure/ResourceTaggingEnforcement.ps1` | Required tag audit, optional auto-apply missing tags |
| `azure/NSGAudit.ps1` | Detect overly permissive NSG rules (any-source, any-port, any-protocol) |
| `azure/AzureBackupComplianceCheck.ps1` | VM backup coverage report across subscriptions |
| `azure/AzureADConnectHealthCheck.ps1` | Connectivity validation, tenant discovery, sync status |
| `azure/SubscriptionAuditReport.ps1` | Per-subscription resource/RBAC/resource group inventory |
| `azure/StorageAccountPublicExposureCheck.ps1` | Blob public access, firewall rules, TLS version, private endpoints |
| `azure/RBACAuditScript.ps1` | Owner/Contributor assignments at subscription and RG scope |
| `azure/AzureVMAutoShutdownScheduler.ps1` | Audit existing schedules, auto-apply shutdown policies |

### Active Directory

| Script | Description |
|---|---|
| `active-directory/AD-StaleComputerCleanup.ps1` | Find stale computers by last logon, optional disable/delete |
| `active-directory/GPO-BackupExport.ps1` | Backup all GPOs with timestamped HTML report |
| `active-directory/DomainHealthCheck.ps1` | Dcdiag + repadmin + NTP/FSMO/service check per domain controller |
| `active-directory/OU-StructureDoc.ps1` | Recursive OU hierarchy with object counts, GPO inheritance |
| `active-directory/AD-GroupMembershipAudit.ps1` | Group member enumeration with recursive expansion |
| `active-directory/PrivilegedAccountMonitor.ps1` | Baseline comparison + change detection for privileged groups |
| `active-directory/PasswordPolicyChecker.ps1` | Domain/FGPP policy report with per-user password compliance |

### Windows Server

| Script | Description |
|---|---|
| `server/DiskSpaceMonitor.ps1` | Multi-server disk check with thresholds, email alert |
| `server/EventLogAnomalyParser.ps1` | Error/critical event parser with burst and repeat detection |
| `server/event-log-anomaly.ps1` | XPath-filtered log query with anomaly enrichment engine |
| `server/ServiceHealthMonitor.ps1` | Critical service status check, auto-start stopped detection |
| `server/PatchComplianceReport.ps1` | WUA-based patch history, compliance window, pending reboot |
| `server/BackupVerification.ps1` | Wbadmin + file path backup validation with age alerting |
| `server/HyperV-VMInventory.ps1` | VM discovery with state/vCPU/memory/uptime/snapshot reporting |
| `server/FileServerPermissionAudit.ps1` | NTFS ACL scanner with explicit/deny/fullcontrol analysis |
| `server/monitor-disk-space.ps1` | Configurable disk monitor with Event Log, email, Teams, Slack alerts |

### Security / Email

| Script | Description |
|---|---|
| `security/EmailAuth-Audit.ps1` | SPF/DKIM/DMARC audit with HTML/CSV/Excel export |

---

## Repository Structure

```
toolbox/
├── docs/                         # Runbooks, architecture, best practices
├── scripts/powershell/
│   ├── m365/                     # Microsoft 365 / Entra ID automation
│   ├── exchange/                 # Exchange Online management
│   ├── azure/                    # Azure administration and governance
│   ├── active-directory/         # On-prem AD management
│   ├── server/                   # Windows Server infrastructure
│   └── security/                 # Security auditing tools
├── templates/                    # Incident response, onboarding, change management
├── lab/                          # Topologies, configs, experiments
├── projects/                     # Full deployments, case studies
└── .github/workflows/            # CI/CD pipelines
```

---

## Requirements

Each script documents its dependencies in the header, but common requirements include:

- **Microsoft Graph** — `Microsoft.Graph` module (used across m365/ scripts)
- **Exchange Online** — `ExchangeOnlineManagement` module (exchange/ scripts)
- **Azure** — `Az` modules (azure/ scripts)
- **Active Directory** — `ActiveDirectory` RSAT module (active-directory/ scripts)
- **Hyper-V** — Hyper-V PowerShell module (server/ scripts)

Run scripts with `-WhatIf` (or equivalent switch) for dry-run testing before production use.

---

## Engineering Approach

- **Automation First** — Any task performed more than once should be scripted
- **Test Before Production** — Validate with `-WhatIf` switches in every destructive script
- **Structured Output** — All scripts produce HTML reports (plus optional CSV), never just console text
- **Fail Gracefully** — Error handling throughout; no silent failures
- **Real-World Context** — Scenarios based on actual multi-tenant enterprise environments

---

## Intended Audience

- Engineers managing Microsoft enterprise environments
- IT professionals building out automation toolkits
- Anyone evaluating infrastructure engineering capability

---

## Ongoing Development

Continuously updated as new problems are encountered and solved. Not intended to be perfect — intended to reflect real growth and iteration.
