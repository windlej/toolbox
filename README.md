# Toolbox — Infrastructure Automation & Engineering

PowerShell scripts for managing Microsoft 365, Exchange Online, Azure, Active Directory, and Windows Server. Built from real-world administration scenarios.

## Repository Structure

```
toolbox/
├── docs/runbooks/               # Step-by-step operational procedures
├── docs/architecture/           # Design decisions and environment layouts
├── scripts/powershell/
│   ├── m365/                    # User lifecycle, CA, MFA, secure score, licensing
│   ├── exchange/                # Mailbox permissions, rules, transport, litigation hold
│   ├── azure/                   # VM inventory, RBAC, NSG, backup, tagging, storage
│   ├── active-directory/        # Domain health, GPO, OU, group audit, stale cleanup
│   ├── server/                  # Disk, event log, services, patches, backups, Hyper-V
│   └── security/                # Email auth (SPF/DKIM/DMARC) auditing
├── templates/                   # Incident response, onboarding, change management
├── lab/                         # Topologies, configs, experiments
├── projects/                    # Full deployments, case studies
└── .github/workflows/           # CI/CD pipelines
```

## Requirements

All scripts document dependencies in their headers. Common prerequisites:

- **Microsoft Graph** — `Microsoft.Graph` module
- **Exchange Online** — `ExchangeOnlineManagement` module
- **Azure** — `Az` modules
- **Active Directory** — `ActiveDirectory` RSAT module
- **Hyper-V** — Hyper-V PowerShell module

Use `-WhatIf` for dry-run testing before production use.

## Engineering Approach

- **Automation First** — Any repeated task should be scripted
- **Test Before Production** — Dry-run switches on every destructive script
- **Structured Output** — HTML reports + optional CSV, never just console text
- **Fail Gracefully** — Error handling throughout
