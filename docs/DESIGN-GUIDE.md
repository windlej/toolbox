# Toolbox Design Guide

The rules every script in this repo follows. The goal: any script can be copied to any customer's machine, run, and leave behind a report in a place you choose, without exposing who the customer is.

`tools/Test-ScriptStandards.ps1` enforces the mechanical parts of this guide.

## 1. Where scripts live

| Path | Runs on | Language |
|---|---|---|
| `scripts/windows/<domain>/` | Windows (customer servers and endpoints) | PowerShell |
| `scripts/network/` | macOS / Linux (your workstation) | bash |
| `scripts/python/<domain>/` | macOS / Linux | Python |

Windows domains: `active-directory`, `m365`, `exchange`, `azure`, `server`, `endpoint`, `security`. Add a new domain folder only when three or more scripts belong in it.

## 2. Naming

- **PowerShell:** approved `Verb-Noun`, PascalCase, e.g. `Get-StaleUserAccount.ps1`. Check verbs with `Get-Verb`. Use a singular noun.
- **bash:** `kebab-case.sh`. **Python:** `snake_case.py`.
- Never put a customer, tenant, or person's name in a file name.

## 3. Header

Every PowerShell script starts with `#Requires`, then comment-based help, then `[CmdletBinding()]` and `param()`.

```powershell
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Users

<#
.SYNOPSIS
One line: what it does.

.DESCRIPTION
What it checks or changes, and what the output contains.

.PARAMETER OutputPath
Folder for reports. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.EXAMPLE
.\Get-StaleUserAccount.ps1 -InactiveDays 90 -OutputPath D:\Reports

.EXAMPLE
.\Get-StaleUserAccount.ps1 -InactiveDays 60 -CustomerName Contoso -OutputPath D:\Reports

.NOTES
Platform:     Windows
Permissions:  Graph scopes User.Read.All, AuditLog.Read.All
When to use:  Quarterly access review, license cleanup, or before an offboarding sweep.
Safety:       Read-only
Version:      1.0
#>
```

`Safety:` is one of `Read-only`, `Changes data (supports -WhatIf)`, or `Destructive (supports -WhatIf)`.

Bash and Python scripts carry the same labels (`Synopsis`, `Platform`, `Permissions`, `When to use`, `Safety`, `Examples`) in a leading comment block or docstring.

`tools/Build-Toolbox.ps1` (the picker) and `tools/Build-Catalog.ps1` read these headers. **The header is the documentation**: if it's wrong, the catalog is wrong.

## 4. No customer data in the repo

- No tenant names, domains, IPs, hostnames, UNC paths, user names, or email addresses.
- Customer-specific values come in as parameters or input files stored outside the repo.
- Examples use `contoso.com`, `fabrikam.net`, and RFC 5737 addresses (`192.0.2.x`) only.
- Test output is never committed (`.gitignore` blocks `Reports/`, `*.csv`, `*.xlsx`).

## 5. Output

- Every script that produces files has `-OutputPath`. If it's omitted, use `$env:TOOLBOX_REPORT_DIR`. If that's also unset, prompt, and never fall back to the current directory or the script folder.
- Optional `-CustomerName` adds a `<OutputPath>\<CustomerName>\` subfolder.
- File names: `<ScriptName>_<yyyyMMdd_HHmmss>.<ext>`. No fixed names that overwrite earlier runs.
- HTML is the primary report; CSV is optional. Console-only output is not enough for audit scripts.
- Output is never written inside the repo.

Standard snippet (paste into each script; the linter checks for `Resolve-OutputPath`):

```powershell
function Resolve-OutputPath {
    param([string]$Path, [string]$CustomerName)
    if (-not $Path) { $Path = $env:TOOLBOX_REPORT_DIR }
    if (-not $Path) { $Path = Read-Host 'Output folder for reports' }
    if (-not $Path) { throw 'An output path is required.' }
    if ($CustomerName) { $Path = Join-Path $Path $CustomerName }
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    (Resolve-Path -LiteralPath $Path).Path
}
```

## 6. Safety

- Read-only is the default. Anything that changes state needs an explicit switch (e.g. `-RemoveStaleGuests`).
- State-changing scripts use `[CmdletBinding(SupportsShouldProcess)]` and call `$PSCmdlet.ShouldProcess()`. Don't define your own `-WhatIf` switch.
- Show what will change before changing it. Bulk scripts need `-WhatIf` support.
- Never write plaintext passwords or secrets to output files.

## 7. Robustness

- `Set-StrictMode -Version Latest` and `$ErrorActionPreference = 'Stop'`.
- Wrap connections and writes in try/catch with a clear message. Don't use `-ErrorAction SilentlyContinue` to hide failures; use it only for expected "not found" lookups.
- Connect helpers take a `-SkipConnect` style switch when a session may already exist.
- Check required modules up front and fail with the install command.

## 8. Logging

Use a `Write-Log` function (timestamp, level `INFO`/`WARN`/`ERROR`) that writes to the console and to `<OutputPath>\<ScriptName>_<timestamp>.log`. Avoid bare `Write-Host` for results.

## 9. Parameters

- No `Read-Host` for inputs. The only allowed prompt is the output-path fallback.
- Common names: `-OutputPath`, `-CustomerName`, `-ComputerName` (string array, defaults to local machine on server scripts), `-SkipConnect`, `-Credential`.
- Use `[ValidateSet]`, `[ValidateRange]`, and `Mandatory` where they help.

## 10. Self-contained

Scripts get copied alone onto customer servers, so they must not depend on other files in this repo. Shared snippets (`Resolve-OutputPath`, `Write-Log`) are pasted in, not imported.

## 11. Documentation

- The header is the source. `tools/Build-Catalog.ps1` generates `docs/CATALOG.md` and `docs/scripts/<Name>.md` from it. Don't edit those by hand.
- Hand-written runbooks (`docs/runbooks/`) are only for procedures that span several scripts or need judgment. They link to scripts by their current names.
- Renames are recorded in `docs/RENAME-MAP.md`.

## 12. Checklist before committing a script

- [ ] Verb-Noun name, in the right folder
- [ ] Header has every label in §3, 2+ examples
- [ ] `-OutputPath` and `Resolve-OutputPath` (if it writes files)
- [ ] No customer values, no hardcoded paths
- [ ] `SupportsShouldProcess` if it changes anything
- [ ] `pwsh tools/Test-ScriptStandards.ps1` passes
- [ ] `pwsh tools/Build-Catalog.ps1` re-run and the result committed
