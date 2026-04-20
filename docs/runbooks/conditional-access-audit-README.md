# 🔐 Entra Conditional Access Auditor

> Production-ready PowerShell audit script for Microsoft Entra Conditional Access policies — built entirely on the **Microsoft Graph PowerShell SDK**. No deprecated AzureAD or MSOnline modules.

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)](https://github.com/PowerShell/PowerShell)
[![Graph SDK](https://img.shields.io/badge/Microsoft.Graph-Identity.SignIns-0078d4?logo=microsoft)](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Graph Version](https://img.shields.io/badge/Graph%20API-v1.0-orange)](https://learn.microsoft.com/en-us/graph/overview)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Files](#-output-files)
- [Risk Rules](#-risk-rules)
- [Permissions](#-permissions)
- [Example Output](#-example-output)
- [FAQ](#-faq)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

This script performs a comprehensive audit of all **Conditional Access (CA) policies** in a Microsoft Entra (Azure AD) tenant. It exports full policy details, resolves Named Location GUIDs to human-readable names, and applies a **six-rule risk analysis engine** to flag weak or misconfigured policies.

Designed for:
- 🛡️ Security engineers conducting Zero Trust posture reviews
- 🧑‍💼 Identity architects validating CA policy coverage
- 🔎 Compliance teams auditing MFA enforcement and device posture
- 🚨 Incident responders assessing authentication controls

---

## ✨ Features

| Feature | Details |
|---|---|
| **Full policy export** | All CA policies exported to JSON (raw, depth-10) and CSV (flattened) |
| **Named Location resolution** | GUIDs automatically resolved to display names |
| **Risk analysis engine** | Six severity-weighted rules covering MFA, device compliance, scope, and state |
| **Structured findings report** | Separate CSV with `RuleId`, `Severity`, `Finding`, and `Recommendation` |
| **Console summary dashboard** | Live counts by state, MFA coverage %, and findings by severity |
| **Least-privilege auth** | Uses `Policy.Read.All` only — no write permissions required |
| **Auto module install** | Installs `Microsoft.Graph.Identity.SignIns` automatically if missing |
| **No legacy modules** | Zero dependency on deprecated `AzureAD` or `MSOnline` cmdlets |
| **Automation-ready** | `-SkipConnect` flag supports Managed Identity and service principal contexts |

---

## 📦 Prerequisites

- **PowerShell** 5.1 or later (PowerShell 7+ recommended)
- **Internet access** to PSGallery (for auto-install) and Microsoft Graph endpoints
- A Microsoft Entra account with sufficient permissions (see [Permissions](#-permissions))

The script will automatically install the required module if it is not present:

```
Microsoft.Graph.Identity.SignIns
```

---

## 🚀 Installation

Clone the repository or download the script directly:

```bash
git clone https://github.com/your-org/entra-ca-auditor.git
cd entra-ca-auditor
```

Or download the script file directly:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/your-org/entra-ca-auditor/main/Audit-ConditionalAccess.ps1" `
                  -OutFile "Audit-ConditionalAccess.ps1"
```

---

## 💻 Usage

### Basic — Interactive login, output to script directory

```powershell
.\Audit-ConditionalAccess.ps1
```

### Specify tenant ID and custom output folder

```powershell
.\Audit-ConditionalAccess.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
                               -OutputPath "C:\CAReports"
```

### Automation — Use a pre-authenticated context (Managed Identity / service principal)

```powershell
# Authenticate externally first, then skip the Connect step
Connect-MgGraph -Identity   # or Connect-MgGraph -ClientSecretCredential ...
.\Audit-ConditionalAccess.ps1 -SkipConnect -OutputPath "C:\CAReports"
```

### Parameters

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `-OutputPath` | `string` | No | Script directory | Folder where all output files are written |
| `-TenantId` | `string` | No | *(prompts)* | Entra tenant ID for authentication |
| `-SkipConnect` | `switch` | No | `false` | Skip `Connect-MgGraph` and use existing context |

---

## 📁 Output Files

Three files are produced in the output directory:

### `CA-Policies.json`
Full raw Graph API response for every policy, serialized at depth 10. Suitable for archival, diffing between audit runs, or feeding into downstream tooling (Sentinel, Splunk, etc.).

```json
[
  {
    "Id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "DisplayName": "Require MFA for All Users",
    "State": "enabled",
    "Conditions": { ... },
    "GrantControls": { ... },
    "SessionControls": { ... },
    ...
  }
]
```

### `CA-Policies.csv`
One row per policy with all nested fields flattened into columns. Named Location GUIDs are resolved to display names. Ready to open directly in Excel or import into a SIEM.

**Columns include:**
`PolicyId` · `DisplayName` · `State` · `IncludeUsers` · `ExcludeUsers` · `IncludeGroups` · `ExcludeGroups` · `IncludeApplications` · `IncludeLocations` · `IncludePlatforms` · `SignInRiskLevels` · `UserRiskLevels` · `GrantBuiltInControls` · `GrantOperator` · `SessionSignInFrequencyValue` · `CreatedDateTime` · `ModifiedDateTime` · *(and more)*

### `CA-RiskyFindings.csv`
One row per finding, sorted **High → Medium → Low**, then by policy name.

| Column | Description |
|---|---|
| `PolicyName` | Display name of the affected policy |
| `PolicyId` | GUID of the policy |
| `PolicyState` | Current state (enabled / disabled / reportOnly) |
| `RuleId` | Rule identifier (e.g. `RULE-03`) |
| `Severity` | `High` · `Medium` · `Low` |
| `Finding` | Human-readable description of the issue |
| `Recommendation` | Actionable remediation guidance |

---

## 🚨 Risk Rules

The audit engine evaluates every policy against six rules:

| Rule | Severity | Trigger Condition |
|---|---|---|
| **RULE-01** | 🟡 Medium | Policy state is `disabled` |
| **RULE-02** | 🟡 Medium | Policy is in `report-only` mode (not enforcing) |
| **RULE-03** | 🔴 High | No MFA requirement and no Authentication Strength configured |
| **RULE-04** | 🔴 High | Targets `All Users` with zero user/group exclusions (lockout risk) |
| **RULE-05** | 🔵 Low | Overly broad: All Users + All Apps with no location/platform/risk scoping |
| **RULE-06** | 🟡 Medium | No `compliantDevice` or `domainJoinedDevice` requirement (device posture gap) |

> **Note:** Rules are evaluated against all policies regardless of state, so you can audit both active and inactive configurations.

---

## 🔑 Permissions

This script requires **read-only** access. The minimum required permission is:

| Permission | Type | Justification |
|---|---|---|
| `Policy.Read.All` | Delegated / Application | Read all Conditional Access policies and Named Locations |

To grant admin consent in the Entra portal:
1. Navigate to **Entra ID → App registrations** (if using a service principal)
2. Add the `Policy.Read.All` delegated permission under **Microsoft Graph**
3. Grant admin consent

For interactive use, the `Connect-MgGraph` call will prompt for admin consent on first run if it has not already been granted.

---

## 📊 Example Output

Console summary dashboard printed at completion:

```
───────────────────────────────────────────────────────
  CONDITIONAL ACCESS AUDIT SUMMARY
───────────────────────────────────────────────────────
  Total Policies       : 24
  Enabled              : 18
  Report-Only          : 4
  Disabled             : 2
  Policies with MFA    : 15 (62.5%)
───────────────────────────────────────────────────────
  FINDINGS
  High Severity        : 5
  Medium Severity      : 8
  Low Severity         : 3
  Total Findings       : 16
───────────────────────────────────────────────────────
```

Sample row from `CA-RiskyFindings.csv`:

| PolicyName | RuleId | Severity | Finding | Recommendation |
|---|---|---|---|---|
| Legacy Auth Block | RULE-01 | Medium | Policy is disabled and not enforcing any controls. | Review whether this policy is intentionally disabled. Enable or delete if no longer needed. |
| Require MFA - All Apps | RULE-04 | High | Policy targets All Users with zero user or group exclusions. | Exclude at least one break-glass/emergency-access account or group to prevent lockout. |

---

## ❓ FAQ

**Q: Does this script make any changes to my tenant?**
No. The `Policy.Read.All` scope is strictly read-only. No policies are created, modified, or deleted.

**Q: Can I run this in a CI/CD pipeline or Azure Automation?**
Yes. Use the `-SkipConnect` flag with a pre-authenticated service principal or Managed Identity context. Ensure the identity has `Policy.Read.All` granted via application permissions with admin consent.

**Q: What if I have hundreds of policies?**
`Get-MgIdentityConditionalAccessPolicy -All` handles pagination automatically. The script has been tested with large tenants. Performance is primarily bound by Graph API throttling limits.

**Q: Why is RULE-06 (no device compliance) flagged for every policy?**
RULE-06 fires on all `enabled` policies that lack a device posture control. This is intentional — not every policy needs device compliance (e.g., a policy only applying to low-sensitivity apps). Use the `RuleId` column to filter findings by rule when triaging.

**Q: Can I add custom rules?**
Yes. Add a new `$addFinding` block inside the `Invoke-CaRiskAnalysis` function following the existing pattern. Increment the `RULE-0X` identifier.

---

## 🤝 Contributing

Contributions are welcome! To propose a new risk rule or improvement:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/rule-07-guest-users`
3. Commit your changes with a clear message
4. Open a Pull Request describing the rule logic and its security rationale

Please ensure any new rules include:
- A `RULE-XX` identifier
- A severity classification (`High` / `Medium` / `Low`)
- A clear `Finding` string
- An actionable `Recommendation` string

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

> Built with the [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/) · Follows [Zero Trust](https://learn.microsoft.com/en-us/security/zero-trust/) principles · No deprecated modules
