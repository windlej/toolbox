# Test Report: verification pass on `restructure`

- **Date:** 2026-10-09
- **Branch / commit:** `restructure` at `9c93084` (working tree had one uncommitted change, `docs/BUGS.md`, which this pass did not touch)
- **Tooling:** PowerShell 7.6.6 on macOS, PSScriptAnalyzer 1.25.0
- **Scope:** report only. Nothing was fixed. The one working-tree change from this pass is this file.
- **Not covered:** Windows PowerShell 5.1 was not available. The 5.1 encoding finding (P1) is a simulation (Windows-1252 decode plus the PowerShell parser), not a run on 5.1.

## Summary

| # | Check | Result |
|---|---|---|
| 1 | Parse all `.ps1` under `scripts/`, `tools/` and `toolbox.ps1` (54 files) | **Pass**, 0 parse errors under PowerShell 7 |
| 2a | `Test-ScriptStandards.ps1 -Strict` | **Pass**, 50 scripts checked, 0 errors, 0 warnings |
| 2b | `Invoke-ScriptAnalyzer` over `scripts/` (all severities) | 326 findings: **0 Error**, 304 Warning, 22 Information |
| 3 | `Get-Help -Full` on 50 `scripts/windows` scripts | **Pass**: synopsis, description, five `.NOTES` labels, 2+ examples and every parameter description render on all 50 |
| 4 | `param()` vs `.PARAMETER` | **Pass**: no real mismatches (4 hits, all benign, see below) |
| 5 | Catalog and `docs/scripts` vs scripts | **Pass**: 51 scripts, 51 catalog rows, 51 pages, no missing or extra names. Regenerating the catalog in a scratch copy gives output identical to the committed docs. **1 broken link** |
| 6 | `toolbox.ps1` catalog | **Pass**: `Get-ScriptCatalog` returns 51 entries, none with an empty Description, WhenToUse, Permissions, Safety or Platform. **1 bug**: non-interactive run never exits |
| 7 | Customer-data scan | **Clean** for every listed term, in the working tree and in all 102 commits on all branches |

## Prioritized findings

### P1: Fix before shipping to Windows

**P1-1. Four scripts fail to parse under Windows PowerShell 5.1 if saved without a BOM.**
Windows PowerShell 5.1 reads a BOM-less file as the system ANSI code page (Windows-1252 on a US system). The UTF-8 bytes of `—` (E2 80 94), `–` (E2 80 93) and `─` (E2 94 80) then contain 0x93 and 0x94, which are curly double quotes, and PowerShell treats those as string delimiters. I decoded every BOM-less file with non-ASCII characters as Windows-1252 and parsed it:

| File | Result when read as Windows-1252 | Where the non-ASCII sits |
|---|---|---|
| `toolbox.ps1` | **18 parse errors** (first at line 116, the `─` rule string) | strings: box-drawing, `—`, `·`, arrows |
| `scripts/windows/server/Start-SqlServiceMonitor.ps1` | **12 parse errors** (first at line 164) | strings: `—` at lines 67, 69, 94, 96, 164, 186 and others |
| `scripts/windows/server/Get-EventLogAnomaly.ps1` | **2 parse errors** (line 596, plus a missing `}` at 417) | strings: `—`, `–`, `→`, `─`, `━`, `█` |
| `scripts/windows/server/Get-DiskSpaceStatus.ps1` | 0 errors in simulation | `─` (960 of them), mostly in comment banners; any in output strings would print garbled |
| 7 Exchange scripts (`Get-MailboxForwardingRule`, `Get-MailboxPermissionReport`, `Get-MailboxSizeReport`, `Get-SuspiciousInboxRule`, `Invoke-TransportRuleTransfer`, `New-SharedMailboxFromCsv`, `Set-MailboxLitigationHold`) | 0 errors | one `# ── MAIN ──` comment line near the end of each file |

The analyzer flags this as `PSUseBOMForUnicodeEncodedFile` on 10 files. It is the only analyzer rule that predicts a real failure. `Test-ScriptStandards -Strict` does not check encoding, and the PowerShell 7 parse in step 1 cannot see it, so everything looks green on a Mac.
Suggested fix (not applied): either save the 11 files as UTF-8 with BOM, or replace the non-ASCII characters in code and string literals with ASCII. Then add an encoding check to `Test-ScriptStandards.ps1`.

### P2: Real defects, lower blast radius

**P2-1. `toolbox.ps1` loops forever when stdin is closed.**
`pwsh ./toolbox.ps1 < /dev/null` prints "Invalid selection. Try again." repeatedly and never exits (killed by a 20 s alarm). `Read-Host` returns `$null` at EOF and `Show-NumberedMenu` treats that as invalid input and re-prompts. It prints "TERM environment variable not set" and falls back to the numbered menu. Anything that runs it unattended, or a closed pipe, will hang. Fix idea: treat `$null` from `Read-Host` as Back/Exit.

**P2-2. Four declared parameters are never used (dead).**
Confirmed by AST walk (no reference besides the declaration, none via `$PSBoundParameters`):
- `Get-AzureNsgRiskReport.ps1`: `-NSGName` (line 111), `-ResourceGroup` (line 112). These look like filters, so the script reports every NSG whatever the user passes.
- `Set-AzureVMAutoShutdown.ps1`: `-Location` (line 133)
- `Get-SuspiciousInboxRule.ps1`: `-MaxRuleReportLength` (line 76)

These are documented in `.PARAMETER` and shown in the catalog, so they promise behavior the scripts do not have. The other 36 `PSReviewUnusedParameter` hits are false positives: the parameter is read inside a nested function or script block, which the rule does not follow. The check for them was "referenced at least once beyond the declaration". Whether each reference actually does the job was not verified.

**P2-3. Leftover alert and scheduling wording in `Start-SqlServiceMonitor`.**
The recent commits removed alerting and scheduled-task wording from several scripts. `Start-SqlServiceMonitor.ps1` still says "alerts if any fail to start" (line 6), "writes an alert to the Event Log" (line 10), "suitable for a scheduled task or RMM monitor" (line 14), "Scheduled runs must pass -OutputPath" (line 27) and "as a scheduled task, ... raise an alert" (line 41). These flow into `docs/CATALOG.md:92` and `docs/scripts/Start-SqlServiceMonitor.md`. The code at line 196 still builds an `ALERT` message, so this may be intended (an Event Log entry), but the docs should match the other scripts.

**P2-4. Broken link.**
`docs/runbooks/conditional-access-audit-README.md` links to `LICENSE`, which does not exist in the repo. 54 relative links were checked and 1 is broken. No in-page anchors are broken. External links were listed but not fetched.

### P3: Lint noise and consistency

**P3-1. Analyzer results (scripts/ only, 326 findings, 0 errors).**
By rule:

| Count | Severity | Rule | Assessment |
|---:|---|---|---|
| 134 | Warning | `PSAvoidUsingWriteHost` | By design for console status output; all 50 PowerShell scripts hit it. Biggest: `Get-EventLogAnomaly` 18, `Get-ConditionalAccessReport` 18, `Get-RiskySignInReport` 9 |
| 50 | Warning | `PSAvoidOverwritingBuiltInCmdlets` | Every script defines `Write-Log`. `Write-Log` is not a cmdlet in PowerShell 7.6.6 (`Get-Command Write-Log` finds nothing). The rule uses a bundled Windows profile, so this is noise, but a different name would silence 50 hits |
| 40 | Warning | `PSReviewUnusedParameter` | 4 real, 36 false positives (see P2-2) |
| 25 | Warning | `PSUseSingularNouns` | Helper function names (`Get-ResourceCounts`, `Export-TransportRules` and others) |
| 15 | Warning | `PSShouldProcess` | False positive in practice. Helper functions call `$PSCmdlet.ShouldProcess` without their own `[CmdletBinding(SupportsShouldProcess)]`. I tested it: it works through dynamic scoping from the script's `$PSCmdlet`, and `-WhatIf` is honored. Fragile, but functional |
| 13 | Warning | `PSUseShouldProcessForStateChangingFunctions` | Same helper functions; style only |
| 10 | Warning | `PSUseBOMForUnicodeEncodedFile` | **Real, see P1-1** |
| 10 | Warning | `PSUseDeclaredVarsMoreThanAssignments` | Dead variables: `SPFPresent`, `SPFRecord`, `MailPlatform` (`Test-EmailAuthentication`), `Mailbox` (`New-SharedMailboxFromCsv`), `InheritanceEnabled`, `DepthIndent` (`Get-FileServerPermissionReport`), `RebootBadge` (`Get-PatchComplianceReport`) and 3 more |
| 4 | Warning | `PSAvoidUsingEmptyCatchBlock` | `Test-EmailAuthentication.ps1` lines 121, 150, 164; `Set-AzureVMAutoShutdown.ps1` line 126 |
| 3 | Warning | `PSUseApprovedVerbs` | All in `Invoke-M365SecurityBaseline.ps1` (`Run-*` helpers) |
| 22 | Information | `PSAvoidUsingPositionalParameters` | `Invoke-M365SecurityBaseline` 14, `Compare-ADUserGroupMembership` 8 |

By script, the top six: `Get-EventLogAnomaly` 32, `Invoke-M365SecurityBaseline` 25, `Get-ConditionalAccessReport` 21, `Invoke-UserOffboarding` 13, `Invoke-UserOnboarding` 12 and `New-SharedMailboxFromCsv` 11. Full per-script and per-rule breakdown is reproducible with `Invoke-ScriptAnalyzer -Path scripts -Recurse`. `tools/` and `toolbox.ps1` were not analyzed.

**P3-2. The standards tool does not enforce the fifth `.NOTES` label.**
`tools/Test-ScriptStandards.ps1` (line 41) requires `Platform:`, `Permissions:`, `When to use:` and `Safety:`. `Version:` is present in all 50 scripts today, but nothing would catch a missing one.

**P3-3. Help-comment oddities (harmless).**
- `Get-DiskSpaceStatus.ps1` has `.PARAMETER WhatIf` and `.PARAMETER Verbose` entries (lines 43, 48). Both are common parameters, not declared in `param()`.
- `Get-ConditionalAccessReport.ps1` has a `.PARAMETER LocationMap` and `.PARAMETER Policy` block inside a nested function's own help (line 220). My check picked these up as extra entries; they match that function's params.

**P3-4. Safety strings are free text.**
`toolbox.ps1` shows 7 distinct Safety values. Three are one-offs: "Read-only on inputs; writes one new file", "Changes data (starts stopped services; supports -WhatIf)" and the long "Read-only by default. AddOnly/RemoveOnly/Mirror ..." string. Fine for people, awkward if you ever filter on it.

**P3-5. Banner grammar.** `toolbox.ps1` prints "(1 scripts)" for the Network and Security categories.

### Customer-data scan (step 7)

- **Terms:** `whmc`, `othello`, `whitman`, `10.111`, `162.248`, `172.25`, `172.27`, `JeremiahWindle`: **0 hits** in the working tree, in commit messages, and in the content of every commit on every branch (`git log --all -G`). I also searched `jeremiah` and `windle` case-insensitively: 0 hits.
- **`onmicrosoft.com`:** 0 hits other than contoso/fabrikam (and 0 in history).
- **IPs:** one address in the entire repo, `192.0.2.10` (RFC 5737 documentation range) in `scripts/network/ssh-check.sh:13`.
- **Email addresses:** all `@contoso.com` or `@contoso.local`.
- **Domains:** only `contoso.com` (31), `fabrikam.net` (10), `contoso.local`, plus `example.com`, `domain.local`, `domain.internal` and `contoso.internal` as placeholders. Public Microsoft endpoints were excluded. `msappproxy.net` (2) is a Microsoft service domain.
- **GUIDs:** only `00000000-0000-0000-0000-000000000000` placeholders. No SIDs, UNC paths to real hosts, or `DC=` strings other than `DC=contoso,DC=com`.
- **Secrets:** no hard-coded credentials. The one match, `Invoke-UserOnboarding.ps1:164`, generates a random temporary password.
- **Note:** "Tegria" (employer name) appears about 20 times as the name of the built-in baseline in `Invoke-M365SecurityBaseline.ps1` (`-Baseline Tegria`, `Run-TegriaBaseline`, ...) and its generated docs. It is not on your list. Decide whether it counts as customer data for this repo.
- **Limits:** the scan is text-based. A real name that is not on your list, or one written in a form I did not pattern (for example a bare hostname like `fs01`), would not be caught. The `lab/`, `projects/` and `templates/` folders contain only `.gitkeep` files.

## What was verified clean

- All 54 `.ps1` files parse under PowerShell 7.
- `Get-Help -Full` renders for all 50 `scripts/windows` scripts with a synopsis, description, `Platform`, `Permissions`, `When to use`, `Safety` and `Version` notes, and 2 or more examples. Every parameter in `Get-Help` has a rendered description.
- Every `param()` entry has a `.PARAMETER` and every `.PARAMETER` has a `param()` entry (apart from the benign cases in P3-3).
- `docs/CATALOG.md` has 51 rows and `docs/scripts/` has 51 pages. They match the 50 `.ps1` files plus `ssh-check.sh`, and every row's target file exists.
- `Get-ScriptCatalog` finds all 51 scripts in 8 categories. Description, WhenToUse, Permissions, Safety and Platform are non-empty for each, and each PowerShell script has at least one example.

## Method notes

- The `Get-ScriptCatalog` check dot-sourced a scratch copy of `toolbox.ps1` with its three entry-point lines removed, so the menu never ran. The scratch copy and the Build-Catalog regeneration lived in the session scratchpad, not the repo.
- The `.NOTES` check reads the alert text that `Get-Help` returns, so it tests what a user sees rather than the raw comment.
- `docs/BUGS.md` already lists BUG-001 to BUG-040. None of the findings above duplicate an entry I read; I did not search the file for each one.
