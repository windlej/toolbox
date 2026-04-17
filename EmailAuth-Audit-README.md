📧 **EmailAuth-Audit.ps1**

## Overview
EmailAuth-Audit.ps1 is a PowerShell auditing tool designed to assess email authentication posture across one or more domains. It evaluates the presence and configuration of:

- **SPF** (Sender Policy Framework)
- **DKIM** (DomainKeys Identified Mail)
- **DMARC** (Domain-based Message Authentication, Reporting, and Conformance)

The script produces:

- A **color-coded HTML report** for quick review
- Either a **CSV** or **Excel (.xlsx)** export for tracking, filtering, and remediation work

This tool helps identify domains that are missing records, using weak policies, or misconfigured for modern email security best practices.

## Features

✅ Bulk domain auditing via CSV input

✅ Automatic mail platform detection:

- Microsoft 365
- Google Workspace
- Unknown / custom platforms

✅ SPF detection and record visibility

✅ DKIM selector validation (platform-aware)

✅ DMARC parsing and policy evaluation

✅ DMARC rua email validation

✅ Recommended remediation insights

✅ Color-coded HTML summary (**green / yellow / red**)

✅ User-selectable export format (**CSV or Excel**)

## Requirements

**PowerShell**

- Windows PowerShell 5.1 or newer
- PowerShell 7.x supported

**DNS**

- Access to public DNS resolution (**Resolve-DnsName**)

**Optional (Excel Export Only)**

The Excel export option requires the **ImportExcel** module:

```powershell
Install-Module ImportExcel -Scope CurrentUser
```

If the module is not installed, choose CSV export instead.

## Input CSV Format
Create a CSV file with a single column named **Domain**.

Example:

| CSV    |
|--------|
| Domain |
| example.com |
| contoso.com |
| fabrikam.net |

## How It Works

- Reads domains from the input CSV
- Retrieves DNS TXT records for each domain
- Evaluates:
  - SPF presence and provider includes
  - DMARC record and enforcement policy
  - DKIM selectors based on detected mail platform
- Validates DMARC rua reporting email
- Assigns security status and color coding
- Generates reports in the selected formats

## Output

1️⃣ **HTML Report**

- Human-readable
- Color-coded for rapid assessment
- Ideal for reviews, meetings, and management visibility

**Color Meaning:**

| Color | Meaning                     |
|-------|-----------------------------|
| 🟢    | Secure / Best practice       |
| 🟡    | Present but not fully enforced |
| 🔴    | Missing or misconfigured     |

2️⃣ **Data Export (Your Choice)**

At runtime, you are prompted to select:

- 1 = CSV
- 2 = Excel (.xlsx)

Export includes:

- Domain
- Mail platform detected
- SPF / DKIM / DMARC status
- DMARC policy
- DMARC rua validation status
- Supporting record details

## DMARC Policy Interpretation

| Policy    | Meaning                  |
|-----------|--------------------------|
| none      | Monitoring only          |
| quarantine| Failed mail sent to spam |
| reject    | Failed mail blocked      |

Domains with **p=reject** are considered properly enforced.

## DKIM Selector Detection

The script automatically checks common selectors based on platform:

| Platform      | Selectors Checked           |
|---------------|-----------------------------|
| Microsoft 365 | selector1, selector2        |
| Google Workspace | google                   |
| Unknown       | default, mail, dkim         |

## DMARC RUA Validation Logic

The script inspects the **rua=mailto:** tag and reports:

- ✅ Valid – properly formatted and domain-aligned
- ⚠️ External domain – may require DNS authorization
- ❌ Invalid format
- ❌ Missing

## Usage

- Update paths in the script:
  - `$InputCsv`
  - `$HtmlOutput`

- Run the script:

```powershell
PowerShell .\EmailAuth-Audit.ps1
```

- Choose export format when prompted
- Review the generated HTML and data file

## Intended Use Cases

- Email security assessments
- Domain onboarding reviews
- M365 / Google Workspace migrations
- Periodic compliance audits
- MSP / multi-tenant environments

## Limitations

- DKIM presence depends on known selectors; custom selectors may not be detected
- DMARC rua external authorization is advisory, not fully validated
- DNS propagation delays can affect results

## Recommended Enhancements (Future)

- Automated remediation scripts
- Microsoft Graph DKIM verification
- DMARC aggregate report ingestion
- Scheduled audit mode
- Executive summary export
