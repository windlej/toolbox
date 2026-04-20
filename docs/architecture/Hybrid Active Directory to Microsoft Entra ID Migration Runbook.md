# Hybrid Active Directory to Microsoft Entra ID Migration Runbook

> **Version:** 2.0  
> **Last Updated:** April 2026  
> **Maintained by:** Enterprise Identity Engineering  
> **Status:** Production-Ready  

---

## Table of Contents

1. [Overview](#1-overview)
2. [Identity Architecture Options](#2-identity-architecture-options)
3. [Pre-Migration Assessment](#3-pre-migration-assessment)
4. [Prerequisites](#4-prerequisites)
5. [Migration Strategy Design](#5-migration-strategy-design)
6. [Implementation Phases](#6-implementation-phases)
7. [Validation & Testing](#7-validation--testing)
8. [Security Hardening](#8-security-hardening)
9. [Decommissioning Hybrid Components](#9-decommissioning-hybrid-components)
10. [Monitoring & Operations](#10-monitoring--operations)
11. [Common Pitfalls & Lessons Learned](#11-common-pitfalls--lessons-learned)
12. [Appendices](#12-appendices)

---

## 1. Overview

### Purpose

This runbook provides enterprise Microsoft 365 administrators and identity architects with a structured, production-tested methodology for migrating on-premises Active Directory (AD DS) hybrid identities to Microsoft Entra ID (formerly Azure AD). It covers every phase from initial assessment through decommissioning, with a focus on operational safety, minimal user disruption, and modern security posture.

This document is intentionally prescriptive. Where Microsoft documentation presents options without guidance, this runbook makes opinionated recommendations based on current best practice.

> **Terminology Note:** Microsoft rebranded Azure Active Directory to **Microsoft Entra ID** in 2023. This runbook uses Entra ID throughout. All PowerShell modules, portal references, and tooling align with the current Entra ID branding and supported SDK versions. References to "Azure AD" in tool names (e.g., Microsoft Entra Connect, formerly Azure AD Connect) are noted where legacy naming persists in tooling.

---

### Scope

| In Scope | Out of Scope |
|---|---|
| Windows Server AD DS environments with Entra Connect sync | Active Directory Federation Services (AD FS) setup from scratch |
| Hybrid-joined device transitions to Entra ID Join | Third-party IdP migrations (Okta, Ping, etc.) |
| Exchange hybrid coexistence | Exchange on-premises decommission |
| Intune/Autopilot enrollment alignment | Full Intune policy baseline (see separate runbook) |
| Domain conversion (federated → managed) | ADFS farm expansion or ongoing maintenance |
| Cloud-only identity cutover | Multi-forest mergers/acquisitions |

---

### Target Audience

- **Primary:** Enterprise M365 Administrators and Identity Architects
- **Secondary:** Security Engineers involved in Zero Trust implementation
- **Assumed knowledge:** Familiarity with AD DS, Microsoft 365 administration, and basic PowerShell

---

### Supported Migration Patterns

#### Pattern A: Hybrid → Cloud-Managed (Recommended for most enterprises)

The organization retains on-premises AD DS as the source of authority but moves authentication to cloud-managed methods (Password Hash Sync or Pass-through Authentication). Entra Connect continues to sync identities. This is the most common first step and requires the least disruption.

**Best for:** Organizations with significant on-premises infrastructure that cannot immediately decommission AD DS.

#### Pattern B: Hybrid → Cloud-Only

The organization fully severs the dependency on on-premises AD DS. Identities become cloud-only in Entra ID. Entra Connect is eventually decommissioned. This is the end-state for cloud-first organizations.

**Best for:** Organizations with completed workload migration to SaaS/cloud, or greenfield subsidiaries.

#### Pattern C: Staged Migration

A subset of users (a pilot group or business unit) migrates while the rest remain on the existing authentication method. Staged rollout is available natively in Entra Connect for PHS and PTA. This is the operationally safest approach.

**Best for:** Large enterprises, regulated industries, risk-averse change management cultures.

#### Pattern D: Cutover Migration

All users are converted simultaneously. Requires thorough pre-testing and is generally only appropriate for small organizations (< 500 users) or where staged rollout is not technically feasible.

**Best for:** Small organizations, subsidiaries, or isolated test tenants.

---

## 2. Identity Architecture Options

### 2.1 Managed vs. Federated Domains

| Characteristic | Managed Domain | Federated Domain |
|---|---|---|
| Authentication location | Microsoft Entra ID (cloud) | On-premises IdP (AD FS, PingFederate, etc.) |
| Dependency on on-premises | Low (sync only) | High (AD FS farm must be available) |
| MFA enforcement | Entra ID Conditional Access | Complex — often split between on-prem and cloud |
| Token issuance | Entra ID | On-premises STS |
| Recommended for new projects | ✅ Yes | ❌ No (avoid for new deployments) |
| Migration target | Destination | Source (migrate away from this) |

> **Why this matters:** Federated domains introduce an on-premises availability dependency into every cloud authentication flow. If your AD FS farm experiences an outage, cloud sign-ins fail. Moving to a managed domain eliminates this single point of failure and simplifies your security boundary.

---

### 2.2 Authentication Method Comparison

#### Password Hash Sync (PHS)

Entra Connect synchronizes a one-way, salted, iterated hash of the on-premises password hash to Entra ID. The actual password is never sent in cleartext.

**Advantages:**
- Lowest operational complexity
- Works during on-premises outages (cloud sign-in continues)
- Enables **Entra ID Identity Protection** leaked credential detection
- Required for **Seamless SSO** without hardware dependency
- Supports **Entra ID Password Protection** policies

**Disadvantages:**
- Password changes propagate with a sync delay (~2 minutes typical, up to 30 minutes under load)
- Some organizations have compliance concerns (mitigated by the hash-of-hash architecture)

**Recommendation:** PHS is the Microsoft-recommended default for most organizations. Unless a specific compliance or architectural requirement mandates otherwise, choose PHS.

#### Pass-through Authentication (PTA)

Authentication requests are passed to on-premises AD DS via lightweight PTA agents installed on domain-joined servers. Passwords never leave the corporate network.

**Advantages:**
- Real-time password validation against on-premises AD
- Satisfies organizations that require password never leave on-premises boundary
- No password hash stored in cloud

**Disadvantages:**
- On-premises PTA agents must be available for authentication to succeed
- Requires minimum 3 PTA agents for HA (2 agents + 1 spare minimum)
- Does not support Identity Protection leaked credential detection
- Cannot provide authentication during on-premises outage

**Recommendation:** Use PTA only when a documented compliance or legal requirement explicitly prohibits password hashes from being stored in a cloud service. Pair with PHS as a fallback if agents fail.

#### Federation (AD FS / Third-Party IdP)

> ⚠️ **Deprecation Warning:** Microsoft no longer recommends AD FS for new deployments. AD FS is in feature-freeze and will not receive new capabilities. Microsoft's official guidance is to migrate away from federation toward managed authentication (PHS or PTA).

If your organization currently uses AD FS, this runbook includes a conversion path in Phase 2. Do not expand existing AD FS infrastructure. Plan migration to managed authentication.

**Retain federation only if:**
- A third-party application has a hard dependency on WS-Federation or SAML tokens issued by a specific on-premises STS
- The dependency cannot be resolved through application reconfiguration

---

### 2.3 When to Move to Cloud-Only Identity

Consider transitioning users to cloud-only (no on-premises AD DS account) when:

- The user's role has no dependency on on-premises resources (file shares, legacy LOB apps, domain-joined endpoints)
- The user's device is Entra ID Joined (not Hybrid Joined)
- All application access is through SaaS or Entra ID–registered applications
- The organization is decommissioning on-premises data centers

> **Important:** Cloud-only users cannot authenticate to on-premises resources via Kerberos/NTLM unless supplemented by technologies such as Microsoft Entra Domain Services (AADDS). Plan access requirements before converting accounts.

---

## 3. Pre-Migration Assessment

A thorough assessment is the difference between a smooth migration and a production incident. Do not skip or abbreviate this phase.

### 3.1 Environment Discovery Checklist

#### AD Forest & Domain Topology

- [ ] Document all AD forests and domains (number, trust relationships, functional level)
- [ ] Identify which forests/domains are currently synced to Entra ID via Entra Connect
- [ ] Identify any multi-forest topologies and confirm Entra Connect supports the configuration
- [ ] Document domain functional levels (target: Windows Server 2016 or higher)
- [ ] Identify FSMO role holders and document for decommission planning

#### UPN Suffixes

- [ ] List all UPN suffixes registered in AD (`Get-ADForest | Select -Expand UPNSuffixes`)
- [ ] Confirm all UPN suffixes are **verified** in the Microsoft 365 tenant (Microsoft 365 admin center → Settings → Domains)
- [ ] Identify users with non-routable UPN suffixes (e.g., `@contoso.local`, `@contoso.internal`)
- [ ] Identify users whose UPN does not match their primary SMTP address (this causes sign-in confusion)
- [ ] Count users whose `userPrincipalName` contains invalid characters (IdFix will surface these)

> **Why this matters:** Users will sign in to Microsoft 365 with their UPN. A non-routable UPN (`@contoso.local`) cannot be verified in the tenant and cannot be used as a sign-in identifier. These users must have their UPN updated before migration.

#### Identity Source of Authority

- [ ] Confirm whether Exchange on-premises or Exchange Online is the source of authority for mailbox attributes
- [ ] Document any HR systems that write directly to AD (Workday, SAP SuccessFactors, etc.)
- [ ] Identify any provisioning systems that create or manage AD accounts (e.g., Microsoft Identity Manager, SailPoint)
- [ ] Identify service accounts that sync to Entra ID — determine if they should be excluded from sync

#### Group Types and Usage

- [ ] Inventory AD security groups, distribution groups, and mail-enabled security groups
- [ ] Identify groups used for M365 licensing assignment
- [ ] Identify groups used in Conditional Access policies
- [ ] Document nested group depth (deep nesting can cause sync and policy evaluation issues)
- [ ] Identify groups with more than 50,000 members (these have sync limitations)

#### Application Dependencies

- [ ] Inventory all applications authenticating against AD DS (Kerberos, NTLM, LDAP)
- [ ] Identify applications using legacy authentication protocols (Basic Auth, NTLM over HTTP, legacy SMTP AUTH)
- [ ] Identify service accounts with passwords set to never expire
- [ ] Identify applications with hard-coded user credentials or service account dependencies
- [ ] Inventory all ADFS relying party trusts if AD FS is present

---

### 3.2 Assessment Tooling

#### Microsoft Entra Connect Health

Entra Connect Health provides monitoring and health insights for your Entra Connect synchronization infrastructure.

**Setup:**
1. In the Microsoft Entra admin center, navigate to **Entra ID** → **Monitoring & health** → **Connect Health**
2. Download and install the Entra Connect Health agent on each Entra Connect server
3. Review the health dashboard for sync errors, latency alerts, and configuration warnings before proceeding

**Key reports to review:**
- Sync error report (objects failing to sync)
- Duplicate attribute report (conflicting UPNs or proxy addresses)
- AD DS connector account permissions

#### IdFix

IdFix is a Microsoft tool that scans on-premises AD for objects that will cause sync errors with Entra ID.

**Download:** [https://github.com/microsoft/idfix](https://github.com/microsoft/idfix)

**Common issues IdFix detects:**
- Duplicate `proxyAddresses` values
- Duplicate `userPrincipalName` values
- Invalid characters in UPN, display name, or mail attributes
- Non-routable UPN suffixes
- Objects with blank `mail` attribute where one is expected

**Process:**
1. Run IdFix against each AD domain
2. Export the error report to CSV
3. Prioritize **ERROR** items (these will block sync) over **WARNING** items
4. Use IdFix's built-in remediation or fix manually via PowerShell/ADUC
5. Re-run IdFix after remediation to confirm clean

> **Do not proceed to Phase 1 until IdFix produces zero ERROR-level results.**

---

### 3.3 Risk Identification

| Risk Category | Indicators | Mitigation |
|---|---|---|
| Legacy authentication | Apps using Basic Auth, SMTP AUTH, IMAP/POP without modern auth | Inventory and migrate apps; plan legacy auth block |
| Service account exposure | Service accounts synced to cloud with broad permissions | Exclude from sync or convert to workload identities |
| Hard-coded credentials | Scripts, config files, scheduled tasks using UPN/password | Rotate to managed identities or certificate auth |
| Non-routable UPNs | `@domain.local`, `@domain.internal` suffixes | Update UPNs to routable suffix before migration |
| Stale sync objects | Users/groups in AD with no active M365 usage | Clean up before migration reduces noise |
| ADFS hard dependencies | Applications requiring ADFS-specific claims | Inventory relying party trusts; plan app migration |
| Device GPO dependencies | Devices relying on AD GPO for security baseline | Assess Intune/Endpoint policy equivalence |

---

## 4. Prerequisites

### 4.1 Licensing Requirements

| Feature / Capability | Required License |
|---|---|
| Microsoft Entra Connect (sync) | Included with M365 / Entra ID Free |
| Entra Connect Health | Entra ID P1 (or M365 E3/E5) |
| Conditional Access | Entra ID P1 (or M365 E3/E5) |
| Entra ID Identity Protection | Entra ID P2 (or M365 E5) |
| Privileged Identity Management (PIM) | Entra ID P2 (or M365 E5) |
| Entra ID Governance (access reviews, entitlement mgmt) | Entra ID Governance add-on |
| Passwordless authentication (FIDO2, WHfB) | Entra ID P1 |
| Staged Rollout | Entra ID P1 |

> Confirm licensing is assigned before enabling features. Enabling a P2 feature without licenses does not immediately fail but will generate license compliance alerts and may result in feature degradation.

---

### 4.2 Required Roles and Permissions

#### Microsoft Entra ID

| Task | Required Role |
|---|---|
| Configure Entra Connect | Global Administrator (initial setup) |
| Domain conversion (federated → managed) | Global Administrator |
| Conditional Access policy management | Conditional Access Administrator |
| Authentication methods policy | Authentication Policy Administrator |
| User attribute management | User Administrator |
| View sign-in and audit logs | Reports Reader or Security Reader |

> **Principle of Least Privilege:** After initial Entra Connect configuration, operations should use scoped roles. Avoid using Global Administrator for day-to-day operations. Use Privileged Identity Management (PIM) for just-in-time elevation.

#### On-Premises Active Directory

| Task | Required Permission |
|---|---|
| Entra Connect AD DS connector account | See [Microsoft Learn — Entra Connect accounts](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) |
| UPN updates | Account Operators or delegated OU write |
| AD FS domain conversion | Domain Admin (for AD FS removal steps) |

---

### 4.3 Network and Firewall Requirements

Entra Connect requires outbound HTTPS (TCP 443) to:

| Endpoint | Purpose |
|---|---|
| `*.msappproxy.net` | Application Proxy (if used) |
| `*.servicebus.windows.net` | Entra Connect Health telemetry |
| `login.microsoftonline.com` | Authentication |
| `graph.microsoft.com` | Microsoft Graph API |
| `*.blob.core.windows.net` | Connector updates |

For PTA agents specifically, add:
- `*.msappproxy.net` (TCP 443 outbound)

For the complete, current endpoint list, always refer to:  
📎 [Microsoft Learn — Hybrid identity required ports and protocols](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-ports)

> **Proxy environments:** If outbound traffic passes through an authenticated proxy, configure proxy settings in Entra Connect during setup. Authenticated proxies that require NTLM can cause PTA agent registration failures — test and document your proxy configuration before deployment.

---

### 4.4 Clean-Up Requirements

These must be complete before proceeding to Phase 1:

- [ ] All IdFix ERRORs resolved (zero remaining)
- [ ] All users intended for migration have routable UPN suffixes
- [ ] Duplicate `proxyAddresses` resolved
- [ ] Stale computer objects older than 180 days disabled (or excluded from sync scope)
- [ ] Service accounts reviewed — those not requiring cloud sync excluded from sync scope
- [ ] Entra Connect server meets hardware requirements (see current Microsoft Learn spec for version in use)
- [ ] Entra Connect server OS is Windows Server 2016 or higher
- [ ] .NET Framework version meets minimum (verify against current Entra Connect release notes)

---

## 5. Migration Strategy Design

### 5.1 Decision Tree: Hybrid vs. Cloud-Only

```
START: What is your on-premises footprint?
│
├─► Significant on-premises apps, file servers, AD-joined devices
│       └─► HYBRID (remain synced, move to managed auth)
│           └─► Phase out over 12–36 months as workloads migrate
│
├─► Minimal on-premises, primarily SaaS workloads
│       └─► CLOUD-MANAGED (PHS + Entra ID, decommission Entra Connect later)
│
└─► No on-premises infrastructure / greenfield / subsidiary
        └─► CLOUD-ONLY (no Entra Connect, native Entra ID accounts)
```

### 5.2 Authentication Strategy Selection

```
Does your organization have a documented compliance requirement
prohibiting password hashes from being stored in a cloud service?
│
├─► YES → Pass-through Authentication (PTA)
│           └─► Deploy minimum 3 PTA agents for HA
│           └─► Consider PHS as fallback if PTA agents fail
│
└─► NO  → Password Hash Sync (PHS) ← RECOMMENDED DEFAULT
            └─► Enables Identity Protection, leaked cred detection
            └─► Works during on-premises outages
            └─► Lowest operational overhead
```

> **Federation (AD FS):** If currently federated, plan migration to managed (PHS/PTA) within your project timeline. Do not remain on federation as a long-term state unless a specific application dependency forces it.

---

### 5.3 Device Strategy

| Current State | Target State | Path |
|---|---|---|
| On-premises domain joined only | Entra ID Joined | Autopilot reset or re-image |
| Hybrid Entra ID Joined | Entra ID Joined | Staged — unenroll hybrid join, enroll Entra join |
| Hybrid Entra ID Joined | Remain hybrid (interim) | No device change needed; focus on auth migration |
| Unmanaged / BYOD | Entra ID Registered | Intune enrollment via MAM or conditional access |

> **Windows Hello for Business (WHfB):** Deploy WHfB as part of the device migration. WHfB provides phishing-resistant, passwordless sign-in tied to Entra ID. For hybrid environments, Cloud Trust (or Kerberos Trust) is the recommended deployment model — it removes the need for PKI infrastructure (Certificate Trust).

---

### 5.4 Rollback Considerations

Every phase must have a documented rollback procedure before execution.

| Phase | Rollback Trigger | Rollback Action |
|---|---|---|
| PHS enablement | Authentication failures > 5% of pilot group | Disable PHS; remain on existing method |
| Staged rollout | Authentication failures in pilot | Remove users from staged rollout group |
| Domain conversion (fed → managed) | Widespread auth failure | Re-federate domain (see Section 6, Phase 2) |
| Entra Connect decommission | Legacy app auth failure | Re-install Entra Connect from backup config |

> ⛔ **Irreversible Action Warning:** Deleting the Entra Connect service account from AD DS after decommissioning is irreversible. Ensure a minimum 30-day waiting period after decommission before removing any AD DS artifacts.

---

## 6. Implementation Phases

### Phase 1: Preparation

**Objective:** Establish a healthy, validated sync foundation before making any authentication changes.

---

#### Step 1.1 — Install / Upgrade Microsoft Entra Connect

> **Current supported version:** Always install the latest GA release from the Microsoft Download Center. Entra Connect uses auto-upgrade by default for minor versions — ensure this is not disabled.

> ⚠️ **Deprecated:** Microsoft Entra Connect Sync (v1.x, also known as DirSync or AAD Sync) is deprecated. If running any version prior to 2.x, upgrade immediately. DirSync and AAD Sync are end-of-life.

**Fresh installation:**

1. Download the latest Microsoft Entra Connect from: [https://www.microsoft.com/download/details.aspx?id=47594](https://www.microsoft.com/download/details.aspx?id=47594)
2. Run `AzureADConnect.msi` as a local administrator on a dedicated member server (not a domain controller)
3. Select **Express Settings** only for single-forest, single-domain environments. Use **Custom** for everything else.
4. During setup, authenticate with a **Global Administrator** account for the initial Entra ID connection
5. Use a dedicated **AD DS Connector Account** (not Domain Admin) for on-premises connectivity — Entra Connect will create this account automatically or you can pre-stage it
6. Configure **UPN matching** — ensure the `userPrincipalName` attribute maps to the Entra ID sign-in name
7. **Do not enable federation** during setup if you are migrating to managed authentication

**Upgrade from existing Entra Connect:**

1. Back up current configuration: Run `Get-ADSyncServerConfiguration` and export to a safe location
2. Check current version in Add/Remove Programs → Microsoft Azure AD Connect
3. Run the new installer over the existing installation — it upgrades in-place
4. After upgrade, verify sync cycles complete successfully (check Synchronization Service Manager)

---

#### Step 1.2 — Configure Sync Scope Filtering

Apply organizational unit (OU) filtering to limit sync to relevant objects only.

**In Entra Connect wizard:**
1. Open Entra Connect → **Synchronization Service** → **Connectors**
2. Configure OU filtering to exclude:
   - Service account OUs not requiring cloud identity
   - Test/staging OUs
   - Terminated user OUs (or set to disabled state)
   - Computer objects not requiring Hybrid Join (if applicable)

**Best practice filters:**
- Exclude the `CN=Computers` default container if computers are already in managed OUs
- Exclude shared mailbox accounts that are managed solely in Exchange Online
- Exclude break-glass emergency access accounts (these should be cloud-only)

---

#### Step 1.3 — Validate Sync

Before any authentication changes, confirm sync is healthy.

**Checklist:**
- [ ] Synchronization Service Manager shows no connector errors
- [ ] Entra Connect Health dashboard shows green status
- [ ] Run a full sync cycle and confirm object counts are expected:
  ```powershell
  Start-ADSyncSyncCycle -PolicyType Initial
  ```
- [ ] Spot-check 10 pilot users: confirm attributes in Entra ID match AD DS
- [ ] Confirm `ImmutableID` is set correctly on synced users (prevents duplicate object issues)
- [ ] Confirm no objects are stuck in the `Pending Export` or `Export Error` state

---

### Phase 2: Identity Transition

**Objective:** Move authentication from on-premises (federated or legacy) to Entra ID managed authentication.

---

#### Step 2.1 — Enable Password Hash Sync

> If already on PHS, skip to Step 2.3. If on PTA and remaining on PTA, skip Step 2.1.

**Enable PHS in Entra Connect:**

1. Open Entra Connect on the sync server
2. Select **Change user sign-in**
3. Select **Password Hash Synchronization**
4. If prompted, provide Global Administrator credentials for Entra ID
5. Complete the wizard — this enables PHS but does **not** change the authentication method for domains yet

**Verify PHS is syncing:**
- In Entra admin center → **Entra ID** → **Monitoring** → **Audit logs**, filter for "Password hash sync" events
- Use the Entra Connect Health portal to confirm PHS is active

> **Important:** Enabling PHS does not change how users authenticate. Domain conversion (Step 2.3) is what switches authentication. You can safely enable PHS in advance, giving hashes time to sync before the switchover.

---

#### Step 2.2 — Deploy Staged Rollout (Recommended)

Staged Rollout allows you to test cloud authentication with a specific group of users before converting the entire domain. This is the safest approach.

**Requires:** Entra ID P1 licensing

1. In Entra admin center → **Entra ID** → **Authentication methods** → **Authentication strength** — navigate to **Staged rollout**
2. Enable **Password Hash Sync** (or PTA) for staged rollout
3. Add a pilot security group (20–50 users initially)
4. Test sign-in for all pilot users — they will now authenticate via Entra ID instead of AD FS / on-premises
5. Monitor sign-in logs for failures before expanding
6. Expand the group incrementally (25% → 50% → 75% → 100%)
7. Once 100% of users are in staged rollout with no failures, proceed to domain conversion

> **Staged rollout limitations:** Does not support Exchange on-premises hybrid (affects some Outlook desktop scenarios), shared mailboxes sign-in, or external user scenarios. Validate these cases separately.

---

#### Step 2.3 — Convert Federated Domain to Managed

> ⛔ **Irreversible (with caveats):** Domain conversion is reversible (you can re-federate) but is operationally complex. Ensure all pilot testing is complete and rollback plan is documented before proceeding.

**Pre-conversion checklist:**
- [ ] Staged rollout has been running for minimum 5 business days with no auth failures
- [ ] Break-glass accounts are cloud-only and tested
- [ ] Conditional Access policies are tested and not blocking the migration team
- [ ] Help desk is notified and staffed for post-conversion support window
- [ ] Rollback command is documented and tested in a non-production tenant

**Convert domain using Microsoft Graph PowerShell:**

```powershell
# Install Microsoft Graph PowerShell SDK if not already installed
Install-Module Microsoft.Graph -Scope CurrentUser

# Connect with appropriate scopes
Connect-MgGraph -Scopes "Domain.ReadWrite.All"

# Check current domain federation status
Get-MgDomain -DomainId "contoso.com" | Select-Object Id, AuthenticationType

# Convert federated domain to managed
# This is the point of no return for the current authentication session
Update-MgDomain -DomainId "contoso.com" -BodyParameter @{
    authenticationType = "Managed"
}

# Verify conversion
Get-MgDomain -DomainId "contoso.com" | Select-Object Id, AuthenticationType
```

> **Note:** Do not use the deprecated `MSOnline` (`Set-MsolDomainAuthentication`) or `AzureAD` module commands. These modules are deprecated and will be retired. Always use the **Microsoft Graph PowerShell SDK** (`Microsoft.Graph` module).

**Post-conversion validation (within 15 minutes):**
1. Sign out and sign back in as a test user — confirm PHS or PTA authentication works
2. Check Entra ID sign-in logs for the test user — authentication method should show "Password Hash Sync" or "Pass-through Authentication"
3. Validate MFA prompt appears correctly
4. Validate Conditional Access policies apply as expected

---

#### Step 2.4 — Validate Authentication Post-Conversion

Run the following validation scenarios within 1 hour of domain conversion:

| Scenario | Expected Result | Pass/Fail |
|---|---|---|
| Interactive sign-in (browser) | Successful with MFA prompt | |
| Outlook desktop (modern auth) | Silent re-auth or one-time credential prompt | |
| Microsoft Teams desktop | Successful SSO | |
| Mobile device (Authenticator app) | Push notification MFA works | |
| Passwordless sign-in (if deployed) | Works without password | |
| Service account / app registration | No impact (uses client credentials) | |

---

### Phase 3: Device Migration

**Objective:** Transition devices from Hybrid Entra ID Join to Entra ID Join, aligned with modern management.

---

#### Step 3.1 — Assess Current Device State

```powershell
# Run on a domain member to check join type
dsregcmd /status

# Key fields to review:
# AzureAdJoined : YES (Entra joined)
# DomainJoined  : YES (AD joined)
# Both YES = Hybrid joined
# Only AzureAdJoined = Cloud-only (Entra joined)
```

---

#### Step 3.2 — Hybrid Entra ID Join → Entra ID Join

> **Decision point:** Only proceed to Entra ID Join if the device's workloads do not require on-premises Kerberos/NTLM access. If on-premises resources are still required, remain Hybrid Joined until those dependencies are resolved.

**Process for transitioning a device:**

1. Ensure the device is enrolled in Microsoft Intune (for policy continuity)
2. Back up any user data via OneDrive Known Folder Move (confirm it is enabled and syncing)
3. Remove the device from Hybrid Join:
   - Via Intune: Issue a wipe or autopilot reset (preferred for standardization)
   - Manual: `dsregcmd /leave` (removes domain join; requires local admin)
4. Enroll the device as Entra ID Joined:
   - Fresh OS deployment via Windows Autopilot (recommended)
   - Out-of-Box Experience (OOBE) with `Work or School` account sign-in
5. Confirm Intune compliance policy applies post-enrollment
6. Validate user can sign in with Entra ID credentials
7. Validate access to cloud resources (SharePoint, Teams, M365 apps)

---

#### Step 3.3 — Windows Autopilot Considerations

Autopilot streamlines Entra ID Join at scale and should be the primary device enrollment mechanism.

**Prerequisites:**
- Devices are registered in Autopilot (via hardware hash — use `Get-WindowsAutopilotInfo` script)
- Autopilot deployment profile configured in Intune (Entra ID Join, not Hybrid Join)
- Enrollment Status Page (ESP) configured for first-run experience
- A valid Intune compliance policy exists for the device platform

> **Hybrid Autopilot Join:** Windows Autopilot for Hybrid Join is supported but requires the Intune Connector for AD and on-premises line of sight. This is an interim state only — do not design new deployments around Hybrid Autopilot Join if the end-state is cloud-only.

---

#### Step 3.4 — Intune Enrollment Validation

After enrollment:
- [ ] Device appears in Intune portal as **Compliant**
- [ ] Device appears in Entra ID portal with join type **Entra ID Joined**
- [ ] Assigned Intune configuration profiles have applied (Settings Catalog policies)
- [ ] Windows Hello for Business provisioning has completed (if enabled)
- [ ] BitLocker key escrow to Entra ID has completed

---

### Phase 4: Workload Alignment

**Objective:** Confirm cloud workloads recognize and operate correctly with migrated identities.

---

#### Exchange Online

- **Source of Authority:** In hybrid Exchange, on-premises Exchange manages mailbox attributes. After migration to cloud-only, Exchange Online becomes the authoritative source.
- Confirm all users have a valid `UserPrincipalName` that matches their primary SMTP address
- Validate that mailbox licenses are correctly assigned in Entra ID
- If decommissioning Exchange on-premises: follow the [Microsoft Hybrid Decommission wizard](https://learn.microsoft.com/en-us/exchange/decommission-on-premises-exchange)
- Shared mailboxes migrated to Exchange Online should be converted to cloud-only accounts — they do not need Entra Connect sync once fully in EXO

#### SharePoint Online / OneDrive for Business

- SharePoint uses the Entra ID Object ID internally as the user identifier — this persists through domain conversion
- Users may see a one-time re-prompt for credentials post-domain conversion
- OneDrive Known Folder Move should be deployed before any device migration to protect user data
- Validate external sharing links remain functional post-migration
- Confirm SharePoint site permissions (especially those set via on-premises AD security groups) — synced groups from Entra Connect continue to work; groups deleted from sync scope will cause access loss

#### Microsoft Teams

- Teams identity is Entra ID–native and is minimally impacted by auth method changes
- After domain conversion, users may receive a re-authentication prompt in Teams (expected)
- Validate Teams Phone (if deployed) — Direct Routing configurations reference SIP addresses, not auth methods, but validate sign-in for Teams Phone users
- Confirm Teams channel membership for synced groups remains intact post-migration

---

## 7. Validation & Testing

### 7.1 Pilot Group Design

| Criterion | Recommendation |
|---|---|
| Size | 20–50 users for initial pilot; scale to 10% of workforce for extended pilot |
| Composition | Mix of roles: IT staff, power users, executives (with explicit consent), remote workers |
| Device diversity | Include both Hybrid Joined and Entra Joined devices |
| App diversity | Ensure pilot group uses all major application types (browser, desktop, mobile) |
| Geographic distribution | Include users in all major office locations and time zones |
| Executive inclusion | Include at minimum 2 senior stakeholders who can validate experience quality |

---

### 7.2 Authentication Testing Scenarios

Run all the following scenarios for every pilot user before expanding rollout:

| # | Scenario | Steps | Expected Result |
|---|---|---|---|
| 1 | Browser sign-in (Chrome/Edge) | Navigate to portal.office.com, sign in | Redirected to Entra ID login, MFA prompt, successful |
| 2 | Outlook desktop (M365 Apps) | Open Outlook, confirm profile loads | Modern auth sign-in, no Basic Auth prompt |
| 3 | Microsoft Teams desktop | Open Teams, confirm sign-in | SSO via Entra ID, no re-auth required |
| 4 | Mobile (iOS/Android — Authenticator) | Open Microsoft 365 app on mobile | Push MFA prompt, successful sign-in |
| 5 | Password reset | Test SSPR (self-service password reset) flow | User can reset via Entra ID SSPR portal |
| 6 | Conditional Access: Compliant device | Sign in from Intune-enrolled device | Access granted |
| 7 | Conditional Access: Non-compliant device | Sign in from unmanaged device | Blocked or limited per policy |
| 8 | Legacy auth blocked | Attempt IMAP or Basic Auth connection | Blocked (if legacy auth policy applied) |
| 9 | Passwordless (if deployed) | Sign in with Windows Hello or FIDO2 key | Successful without password |
| 10 | Break-glass account | Sign in with cloud-only break-glass account | Successful (validates emergency access) |

---

### 7.3 Conditional Access Validation

Before broad rollout, validate that CA policies behave as designed using the **What If** tool.

**In Entra admin center → Protection → Conditional Access → What If:**
1. Simulate sign-in for a pilot user
2. Test against each CA policy to confirm expected grant/block behavior
3. Confirm MFA registration requirement applies to new users
4. Confirm legacy authentication block policy applies

**Key policies to test:**
- Require MFA for all users (or all users excluding break-glass)
- Require compliant device for M365 app access
- Block legacy authentication
- Sign-in risk policy (if using Identity Protection)

---

## 8. Security Hardening

### 8.1 Conditional Access Policies

Implement the following Conditional Access policies as part of migration. Use **Report-Only mode** for 2 weeks before switching to **Enabled** to validate impact.

| Policy | Configuration | Notes |
|---|---|---|
| Require MFA — All users | Users: All users; Apps: All cloud apps; Grant: Require MFA | Exclude break-glass accounts |
| Block legacy authentication | Conditions: Client apps = Legacy auth clients; Block | Critical — do this early |
| Require compliant or Entra ID Joined device | Apps: M365 core apps; Grant: Compliant OR Entra Joined | Phase in after device migration |
| Admin MFA — Privileged roles | Users: Directory roles (all admins); Apps: All; Grant: Require MFA + Require compliant device | No exclusions |
| Sign-in risk (P2) | Sign-in risk: High; Grant: Require MFA or block | Requires Identity Protection P2 |

> ⚠️ **Deprecated:** Do not use the legacy MFA per-user settings portal (`account.activedirectory.windowsazure.com/usermanagement/mfasettings.aspx`). This portal is deprecated. All MFA enforcement must be done through **Conditional Access** policies. If per-user MFA is currently enabled, migrate to CA-based MFA enforcement before decommissioning.

---

### 8.2 Authentication Methods Policy

Manage authentication methods centrally via the modern **Authentication Methods Policy** (not the legacy Combine Security Information Registration or per-user MFA portal).

**In Entra admin center → Protection → Authentication Methods → Policies:**

Recommended enablement:

| Method | Enable | Notes |
|---|---|---|
| Microsoft Authenticator (Push) | ✅ Yes — All users | Primary MFA method |
| FIDO2 Security Keys | ✅ Yes — Targeted rollout | Phishing-resistant, ideal for admins |
| Windows Hello for Business | ✅ Yes (via Intune) | Configured through Intune, not here |
| Temporary Access Pass | ✅ Yes — Admins / IT | For onboarding and break-glass scenarios |
| Certificate-based auth | Conditional | For smart card environments |
| Voice call | ❌ Disable | Deprecated; not phishing-resistant |
| SMS OTP | ❌ Disable for new deployments | Vulnerable to SIM swap; use Authenticator instead |

> ⚠️ **Deprecated:** The legacy Multi-Factor Authentication service settings (`aka.ms/mfasettings`) and the legacy SSPR portal configuration are being replaced by the unified Authentication Methods Policy. Migrate all method configuration to the modern policy.

---

### 8.3 Disable Legacy Authentication

Legacy authentication (Basic Auth, SMTP AUTH, IMAP/POP without modern auth) is the most common initial access vector in identity attacks.

**Step 1 — Identify legacy auth usage:**
In Entra admin center → **Monitoring** → **Sign-in logs**, filter by **Client app** = Legacy authentication clients. Export and identify users/applications still using legacy auth.

**Step 2 — Migrate or block legacy apps:**
- Exchange Online: Enable Modern Authentication (default since 2017; verify it is on)
- Disable SMTP AUTH for users who do not need it (bulk operations, multifunction printers are the main exception)
- Migrate shared mailbox scripts to OAuth 2.0 using Microsoft Graph

**Step 3 — Block via Conditional Access:**
Create a policy: All users → Legacy auth client apps → **Block**. Put in Report-Only first, monitor for 2 weeks, then enable.

---

### 8.4 Identity Protection Recommendations (Entra ID P2)

| Recommendation | Configuration |
|---|---|
| User risk policy | User risk: High → Require password change (via SSPR) |
| Sign-in risk policy | Sign-in risk: High → Block; Medium → Require MFA |
| MFA registration policy | Require MFA registration for all users (on first sign-in) |
| Risky sign-in alerts | Alert on new high-risk sign-ins (Security Operations) |
| Leaked credential detection | Automatic with PHS enabled — review Risky Users report weekly |

---

## 9. Decommissioning Hybrid Components

### 9.1 Safely Remove Microsoft Entra Connect (Cloud-Only Path)

> ⛔ **Irreversible Action Warning:** Once Entra Connect is uninstalled and the AD DS connector account is removed, synced objects become cloud-only. Some attributes written by Entra Connect (e.g., `ImmutableID`) remain on cloud objects. If you re-install Entra Connect later, it will attempt to re-match objects by `ImmutableID` — this is recoverable but complex. Ensure decommission is final before proceeding.

**Pre-decommission checklist:**
- [ ] All users are successfully authenticating via cloud-managed auth (PHS or PTA)
- [ ] All devices intended for Entra ID Join have been migrated
- [ ] All on-premises application dependencies on AD DS have been resolved or documented
- [ ] Source of authority for all cloud mailboxes is Exchange Online (not on-premises)
- [ ] Entra ID SSPR is enabled and all users have registered (otherwise, password reset will fail post-decommission)
- [ ] Break-glass accounts are cloud-only and tested
- [ ] Minimum 30-day observation period post Phase 3 completion with no issues

**Decommission steps:**

1. In Entra Connect, disable the sync scheduler:
   ```powershell
   Set-ADSyncScheduler -SyncCycleEnabled $false
   ```
2. Verify no sync cycles are running (check Synchronization Service Manager)
3. In Entra admin center, confirm no sync-related alerts
4. Uninstall Microsoft Entra Connect via Add/Remove Programs on the sync server
5. Verify that synced objects in Entra ID retain their `ImmutableID` (they become "cloud-converted" objects, not deleted)
6. After 30 days, disable the AD DS Connector Account in Active Directory
7. After 60 days, if no issues, delete the AD DS Connector Account from Active Directory

---

### 9.2 Remove AD FS (If Present)

> ⛔ **Irreversible Action Warning:** Once AD FS is decommissioned and relying party trusts are removed, any application still pointing to the AD FS endpoint will fail. Ensure all applications have been migrated to Entra ID App registrations before proceeding.

**Pre-decommission checklist:**
- [ ] All domains have been converted from federated to managed (Step 2.3)
- [ ] All application relying party trusts have been migrated to Entra ID Enterprise Applications
- [ ] All users are authenticating via Entra ID (confirmed in sign-in logs for 30+ days)
- [ ] No remaining Conditional Access policies or Named Locations reference ADFS IP ranges
- [ ] WAP (Web Application Proxy) servers are identified for decommission

**Decommission steps:**

1. Remove the Office 365 relying party trust from AD FS:
   - In AD FS Management → Relying Party Trusts → Remove "Microsoft Office 365 Identity Platform"
2. Remove the Entra Connect federation trust:
   ```powershell
   Connect-MgGraph -Scopes "Domain.ReadWrite.All"
   # Verify domain is already managed (not federated) before removing ADFS
   Get-MgDomain -DomainId "contoso.com" | Select AuthenticationType
   ```
3. Remove WAP servers from your DMZ (update firewall rules)
4. Shut down AD FS servers (do not delete VM/OS for 30-day retention)
5. Update DNS to remove AD FS endpoint records
6. After 30-day retention window, decommission AD FS server VMs

---

### 9.3 Remove On-Premises Dependencies

Post-decommission hygiene:

- [ ] Update application configuration files to use Microsoft Graph endpoints (not on-premises LDAP or AD FS endpoints)
- [ ] Update DNS records: remove `enterpriseregistration.contoso.com` CNAME if pointing to on-premises (update to point to `enterpriseregistration.windows.net`)
- [ ] Update DNS records: remove `enterpriseenrollment.contoso.com` if present
- [ ] Review and remove any Group Policy Objects (GPOs) that configured AD FS or hybrid join settings
- [ ] Remove Kerberos-based SSO configuration in Entra Connect if it was enabled (Seamless SSO service account in AD DS)

---

## 10. Monitoring & Operations

### 10.1 Sign-In and Audit Logs

**Entra ID Sign-In Logs** (Entra admin center → Monitoring → Sign-in logs):
- Retain for 30 days (Entra ID Free) or up to 90 days (P1/P2)
- For longer retention, route to **Azure Monitor / Log Analytics** or **Microsoft Sentinel**
- Key filters to monitor post-migration:
  - Authentication method distribution (confirm shift from federated to managed)
  - Legacy auth client app sign-ins (should trend to zero)
  - Failed sign-ins (watch for spikes post-conversion)
  - Conditional Access failure reasons

**Entra ID Audit Logs** (Entra admin center → Monitoring → Audit logs):
- Captures administrative changes (role assignments, policy changes, user creation)
- Export to Log Analytics for long-term retention and alerting

---

### 10.2 Alerting Strategy

Configure the following alerts in Microsoft Sentinel or Azure Monitor:

| Alert | Trigger Condition | Priority |
|---|---|---|
| Break-glass account sign-in | Any sign-in by break-glass account | Critical |
| Global Admin sign-in outside PIM | Global Admin role sign-in without PIM activation | High |
| Legacy auth sign-in | Successful sign-in via legacy client app | High |
| Sign-in from impossible travel | Two sign-ins from geographically separated locations in short time | Medium |
| High-risk user created | Entra ID Identity Protection user risk = High | High |
| Entra Connect sync failure | Sync cycle missed for > 3 hours | Medium |
| Domain federation change | Any change to domain authentication type | Critical |

---

### 10.3 Ongoing Identity Governance

Post-migration, establish the following recurring operations:

| Cadence | Activity |
|---|---|
| Daily | Review Entra ID Identity Protection risky users and sign-ins |
| Weekly | Review Entra Connect sync error report |
| Monthly | Access review of privileged roles (via Entra ID Governance) |
| Quarterly | Review and update Conditional Access policies |
| Quarterly | Review Authentication Methods Policy — disable unused methods |
| Annually | Full identity audit: stale accounts, unused groups, orphaned app registrations |

**Entra ID Governance (Access Reviews):**
Configure access reviews for:
- Members of privileged Entra ID roles (Admin roles)
- Members of sensitive security groups
- Guest (B2B) user access

---

## 11. Common Pitfalls & Lessons Learned

### 11.1 Real-World Failure Scenarios

#### Failure: UPN Mismatch After Domain Conversion

**What happened:** Users' UPNs were `@contoso.local` (non-routable). After domain conversion, they could not sign in because the UPN suffix wasn't a verified domain in the tenant.

**Prevention:** Run IdFix before starting. Update all UPNs to routable suffixes at least 48 hours before migration to allow sync to complete.

---

#### Failure: Break-Glass Account Not Tested

**What happened:** Global Administrator account used for Conditional Access policy management was a synced account. After domain conversion caused a brief auth issue, the admin could not sign in to fix the CA policy.

**Prevention:** Maintain at minimum **two break-glass accounts** that are:
- Cloud-only (not synced from AD)
- Not covered by any Conditional Access policies
- Using a long, complex password (not Passwordless — to avoid token/device dependencies)
- Stored in a physical vault and audited regularly

---

#### Failure: Service Account Locked After PHS Sync

**What happened:** A service account with a complex password had the `userAccountControl` attribute set in a way that caused PHS to fail silently. The application using it continued working on NTLM to on-premises but failed after Entra Connect was decommissioned.

**Prevention:** Inventory all service accounts. Exclude those not needing cloud auth from sync scope. Migrate application authentication to Managed Identities or App Registrations with client certificates.

---

#### Failure: Staged Rollout Not Removed Before Domain Conversion

**What happened:** The team converted the domain to managed while staged rollout was still active for 50% of users. Users in staged rollout continued to work; users outside the staged rollout group could not authenticate (the domain was now managed but their auth wasn't in staged rollout mode).

**Prevention:** Before domain conversion, either: (a) remove all users from staged rollout and disable it, or (b) add all users to the staged rollout group. Never convert a domain while staged rollout is partially active.

---

#### Failure: Conditional Access Policy Applied Too Broadly During Pilot

**What happened:** A "require compliant device" CA policy was enabled in Report-Only mode, then promoted to Enabled — but the Intune enrollment of devices was still in progress. Users with non-enrolled devices were blocked from all M365 apps.

**Prevention:** Sequence your work: enroll devices in Intune → validate compliance → enable device-based CA policies. Never enable device compliance CA policies before device enrollment is complete.

---

#### Failure: SMTP AUTH Still Active for Multi-Function Printers

**What happened:** Legacy auth was blocked via CA policy, but shared MFP devices (printers, scanners) used SMTP AUTH to relay email. After blocking legacy auth, they stopped sending scan-to-email.

**Prevention:** Before blocking legacy auth, audit SMTP AUTH usage. Configure MFPs to use:
- Direct send (no auth, sends directly to EXO MX record)
- SMTP Relay via Exchange Online with a connector (for devices that must use SMTP AUTH, use a dedicated app password or App Registration)

---

### 11.2 Misconfigurations to Avoid

| Misconfiguration | Impact | Prevention |
|---|---|---|
| Enabling Entra Connect on a domain controller | Unsupported; sync failures | Always use a dedicated member server |
| Running two Entra Connect servers in active mode | Duplicate objects, sync conflicts | Only one server in active mode; use staging mode for HA |
| Not configuring OU filtering | Unnecessary objects synced (service accounts, test users) | Configure OU filtering before first sync |
| Setting CA policy to block all users including break-glass | Complete admin lockout | Always exclude break-glass accounts from all CA policies |
| Using deprecated PowerShell modules (MSOnline, AzureAD) in automation | Scripts will fail when modules retire | Migrate all automation to Microsoft Graph PowerShell SDK |
| Not testing SSPR before decommissioning Entra Connect | Users cannot reset passwords post-decommission | Enable and test SSPR before decommission |
| Leaving Seamless SSO Kerberos account in AD after decommission | Potential Kerberos attack surface | Clean up AZUREADSSOACC$ computer object post-decommission |

---

## 12. Appendices

### Appendix A — PowerShell Examples (Microsoft Graph SDK)

> **Note:** All examples use the **Microsoft Graph PowerShell SDK** (`Microsoft.Graph` module). The `MSOnline` and `AzureAD` modules are deprecated and will be retired. Do not use them in new scripts.

#### A.1 — Install and Connect Microsoft Graph PowerShell

```powershell
# Install Microsoft Graph PowerShell SDK
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# Connect with required scopes for identity management
Connect-MgGraph -Scopes @(
    "Directory.Read.All",
    "Directory.ReadWrite.All",
    "Domain.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess",
    "UserAuthenticationMethod.ReadWrite.All"
)

# Verify connection context
Get-MgContext
```

#### A.2 — Enumerate Users with Non-Routable UPN Suffixes

```powershell
Connect-MgGraph -Scopes "User.Read.All"

$nonRoutableUsers = Get-MgUser -All -Property UserPrincipalName, DisplayName, AccountEnabled |
    Where-Object {
        $_.UserPrincipalName -match "@.*\.local$|@.*\.internal$|@.*\.corp$|@.*\.lan$"
    } |
    Select-Object DisplayName, UserPrincipalName, AccountEnabled

$nonRoutableUsers | Export-Csv -Path ".\NonRoutableUPNs.csv" -NoTypeInformation
Write-Host "Found $($nonRoutableUsers.Count) users with non-routable UPN suffixes."
```

#### A.3 — Update UPN Suffix for a User

```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All"

# Update a single user's UPN
$userId = "user@contoso.local"  # Current UPN
$newUPN = "user@contoso.com"    # New routable UPN

Update-MgUser -UserId $userId -UserPrincipalName $newUPN
Write-Host "Updated UPN from $userId to $newUPN"

# Bulk update from CSV
# CSV format: OldUPN, NewUPN
$upnMappings = Import-Csv -Path ".\UPNMappings.csv"
foreach ($mapping in $upnMappings) {
    try {
        Update-MgUser -UserId $mapping.OldUPN -UserPrincipalName $mapping.NewUPN
        Write-Host "SUCCESS: $($mapping.OldUPN) → $($mapping.NewUPN)"
    } catch {
        Write-Warning "FAILED: $($mapping.OldUPN) — $_"
    }
}
```

#### A.4 — Check Domain Authentication Type

```powershell
Connect-MgGraph -Scopes "Domain.Read.All"

# List all domains and their authentication type
Get-MgDomain | Select-Object Id, AuthenticationType, IsVerified, IsDefault |
    Format-Table -AutoSize

# Check a specific domain
Get-MgDomain -DomainId "contoso.com" |
    Select-Object Id, AuthenticationType, IsVerified
```

#### A.5 — Convert Domain from Federated to Managed

```powershell
Connect-MgGraph -Scopes "Domain.ReadWrite.All"

$domainId = "contoso.com"

# Verify current state
$domain = Get-MgDomain -DomainId $domainId
Write-Host "Current authentication type: $($domain.AuthenticationType)"

if ($domain.AuthenticationType -eq "Federated") {
    # Convert to managed — this is the point of no return
    Update-MgDomain -DomainId $domainId -BodyParameter @{
        authenticationType = "Managed"
    }
    
    # Verify conversion
    $updatedDomain = Get-MgDomain -DomainId $domainId
    Write-Host "New authentication type: $($updatedDomain.AuthenticationType)"
} else {
    Write-Host "Domain is already managed. No action required."
}
```

#### A.6 — Export Sign-In Logs for Legacy Authentication Audit

```powershell
Connect-MgGraph -Scopes "AuditLog.Read.All"

# Get sign-ins using legacy auth clients in the last 30 days
$filter = "createdDateTime ge $((Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')) and " +
          "(clientAppUsed eq 'Exchange ActiveSync' or " +
          "clientAppUsed eq 'IMAP4' or " +
          "clientAppUsed eq 'POP3' or " +
          "clientAppUsed eq 'Authenticated SMTP' or " +
          "clientAppUsed eq 'Other clients')"

$legacySignIns = Get-MgAuditLogSignIn -Filter $filter -All |
    Select-Object UserPrincipalName, ClientAppUsed, AppDisplayName, 
                  CreatedDateTime, IpAddress, Status

$legacySignIns | Export-Csv -Path ".\LegacyAuthSignIns.csv" -NoTypeInformation
Write-Host "Found $($legacySignIns.Count) legacy auth sign-in events."
```

#### A.7 — Disable Entra Connect Sync Scheduler (Pre-Decommission)

```powershell
# Run on the Entra Connect server
Import-Module ADSync

# Check current scheduler status
Get-ADSyncScheduler | Select-Object SyncCycleEnabled, CurrentlyRunning, NextSyncCyclePolicyType

# Disable scheduled sync (do NOT disable if still in production!)
Set-ADSyncScheduler -SyncCycleEnabled $false

# Trigger a manual sync cycle (use when scheduler is still enabled)
Start-ADSyncSyncCycle -PolicyType Delta   # Delta sync
Start-ADSyncSyncCycle -PolicyType Initial # Full sync (use with caution)
```

#### A.8 — Validate Entra Connect Health (Sync Errors)

```powershell
# Run on Entra Connect server to check for sync errors
Import-Module ADSync

# Get connector statistics
Get-ADSyncConnector | ForEach-Object {
    $connector = $_
    Write-Host "Connector: $($connector.Name)"
    Get-ADSyncConnectorStatistics -ConnectorName $connector.Name
}

# Get objects in error state
$syncErrors = Get-ADSyncCSObject -DistinguishedName "" -ConnectorName "contoso.com" |
    Where-Object { $_.SyncState -eq "Error" }

Write-Host "Objects in error state: $($syncErrors.Count)"
```

---

### Appendix B — Reference Architecture

#### Architecture 1: Current State — Hybrid with AD FS

```
[Users] → [AD FS / WAP] → [Office 365 / Entra ID]
               ↑
[On-premises AD DS] ←→ [Entra Connect Sync Server] → [Entra ID Tenant]
                                                            ↓
                                                   [Exchange Online]
                                                   [SharePoint Online]
                                                   [Teams]
```

In this architecture, every cloud authentication request is redirected to the on-premises AD FS farm for token issuance. Entra Connect syncs identity objects but authentication authority lives on-premises.

#### Architecture 2: Target State — Cloud-Managed (PHS)

```
[Users] → [Entra ID (cloud)] → [M365 Workloads]
               ↑
[On-premises AD DS] ←→ [Entra Connect Sync Server] → [Entra ID Tenant]
                         (sync only; auth in cloud)
```

Authentication is handled entirely by Entra ID. On-premises AD DS remains the source of authority for identity objects, but has no role in the authentication flow.

#### Architecture 3: End State — Cloud-Only

```
[Users] → [Entra ID (cloud)] → [M365 Workloads]
               ↑
         [Entra ID] (source of authority; no Entra Connect)
```

No on-premises dependency. All identity management is in Entra ID. Devices are Entra ID Joined and managed via Intune.

---

### Appendix C — Reference Links

> All links verified as of April 2026. Microsoft Learn URLs may change — use the title to search if a link is broken.

| Topic | Microsoft Learn URL |
|---|---|
| Microsoft Entra Connect documentation hub | https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/ |
| Entra Connect: Accounts and permissions | https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions |
| Entra Connect: Required ports and protocols | https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-ports |
| Password Hash Synchronization | https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-password-hash-synchronization |
| Pass-through Authentication | https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-pta |
| Staged Rollout | https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-staged-rollout |
| Domain conversion (federated → managed) | https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-post-installation |
| Migrate from AD FS to Entra ID | https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/migrate-from-federation-to-cloud-authentication |
| Conditional Access documentation | https://learn.microsoft.com/en-us/entra/identity/conditional-access/ |
| Authentication Methods Policy | https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods-manage |
| Block legacy authentication | https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication |
| Microsoft Entra Identity Protection | https://learn.microsoft.com/en-us/entra/id-protection/ |
| Windows Hello for Business Cloud Trust | https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/hello-hybrid-cloud-kerberos-trust |
| Microsoft Graph PowerShell SDK | https://learn.microsoft.com/en-us/powershell/microsoftgraph/ |
| IdFix tool | https://github.com/microsoft/idfix |
| Entra Connect Health | https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-azure-ad-connect-health |
| Break-glass emergency access accounts | https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access |
| Autopilot documentation | https://learn.microsoft.com/en-us/autopilot/ |
| Exchange hybrid decommission | https://learn.microsoft.com/en-us/exchange/decommission-on-premises-exchange |

---

### Appendix D — Deprecated Features Reference

The following features are explicitly deprecated and must not be used in new or updated configurations:

| Deprecated Feature | Status | Modern Replacement |
|---|---|---|
| DirSync / AAD Sync (Entra Connect v1.x) | End-of-life | Microsoft Entra Connect v2.x |
| Azure AD Graph API | Retired June 2024 | Microsoft Graph API |
| MSOnline PowerShell module | Retirement in progress | Microsoft Graph PowerShell SDK |
| AzureAD PowerShell module | Retirement in progress | Microsoft Graph PowerShell SDK |
| Per-user MFA (legacy MFA portal) | Deprecated | Conditional Access MFA policies |
| Legacy SSPR configuration portal | Deprecated | Authentication Methods Policy |
| AD FS (for new deployments) | Feature-freeze / wind-down | Entra ID managed authentication (PHS/PTA) |
| Basic Authentication (Exchange Online) | Retired October 2022 | Modern Authentication (OAuth 2.0) |
| Security defaults + per-user MFA mixed | Not supported | Disable security defaults; use Conditional Access |
| Seamless SSO (in isolation) | Not recommended for new deployments | Windows Hello for Business |
| Hybrid Autopilot Join (as end-state) | Interim only | Entra ID Join via Autopilot |

---

*End of Runbook*

---

> **Contributing:** Submit issues and pull requests via GitHub. For urgent security issues, contact the identity engineering team directly.  
> **License:** MIT  
> **Disclaimer:** This runbook represents current best practice as of the publication date. Microsoft product features and recommendations evolve rapidly. Always validate against current Microsoft Learn documentation before executing in a production environment.
