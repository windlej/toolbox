# Toolbox: Infrastructure Automation & Engineering

Customer-agnostic scripts for Microsoft 365, Exchange Online, Azure, Active Directory, Windows servers and endpoints, plus network and Python tooling. Every script works for any customer: nothing customer-specific lives in this repo, and reports are written to a folder you choose, outside the repo.

## Quick start

```powershell
# One-time: where reports go (any folder outside this repo)
setx TOOLBOX_REPORT_DIR "D:\Reports"

# Browse and run scripts interactively (PowerShell 5.1+, arrow-key menus on 7+)
./toolbox.ps1
```

Or run a script directly. Every script documents itself:

```powershell
Get-Help .\scripts\windows\m365\Get-StaleUserAccount.ps1 -Full
.\scripts\windows\m365\Get-StaleUserAccount.ps1 -InactiveDays 90 -CustomerName Contoso
```

**Browse the catalog:** [docs/CATALOG.md](docs/CATALOG.md) lists every script with what it does, when to use it, and whether it is read-only. Each script has its own page under `docs/scripts/`.

## Layout

```
toolbox/
├── scripts/
│   ├── windows/        # PowerShell, runs on Windows
│   │   ├── active-directory/   m365/   exchange/   azure/
│   │   └── server/   endpoint/   security/
│   ├── network/        # bash, runs from macOS/Linux (e.g. ssh-check.sh)
│   └── python/         # Python, runs from macOS/Linux
├── docs/
│   ├── DESIGN-GUIDE.md # the rules every script follows
│   ├── CATALOG.md      # generated from script headers
│   ├── RENAME-MAP.md   # old script names -> current names
│   ├── scripts/        # generated per-script pages
│   └── runbooks/ architecture/ troubleshooting/
├── tools/              # Build-Catalog.ps1, Test-ScriptStandards.ps1, dev helpers
├── templates/  lab/  projects/
└── toolbox.ps1         # interactive launcher
```

## How scripts behave

- **Read-only by default.** Anything that changes state needs an explicit switch and supports `-WhatIf`.
- **Reports go where you say:** `-OutputPath`, else `$env:TOOLBOX_REPORT_DIR`, else a prompt. `-CustomerName` adds a per-customer subfolder. Nothing is written into the repo.
- **No customer data in the repo:** customer-specific values are parameters or input files that live outside it. Examples use `contoso.com` only.
- **Self-contained:** a script can be copied alone onto a customer server and run.
- **Documented in the script:** the header has the synopsis, parameters, examples, required permissions, when to use it, and whether it changes anything.

## Requirements

Dependencies are declared in each script's `#Requires` line and shown by the launcher. Common ones:

| Area | Module |
|---|---|
| Microsoft 365 / Entra | `Microsoft.Graph` |
| Exchange Online | `ExchangeOnlineManagement` |
| Azure | `Az` |
| Active Directory | `ActiveDirectory` (RSAT) |
| Hyper-V | `Hyper-V` |

## Adding or changing a script

Read [docs/DESIGN-GUIDE.md](docs/DESIGN-GUIDE.md), then:

```powershell
pwsh ./tools/Test-ScriptStandards.ps1   # naming, header, output rules, hardcoded values
pwsh ./tools/Build-Catalog.ps1          # regenerate docs/CATALOG.md and docs/scripts/
```

Commit the regenerated docs with the script.
