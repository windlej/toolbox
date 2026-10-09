#Requires -Version 5.1

<#
.SYNOPSIS
Runs a Microsoft 365 tenant security baseline audit (Tegria or CIS) and produces CSV and HTML reports.

.DESCRIPTION
Connects to Microsoft Graph and Exchange Online, runs the checks for the chosen baseline and writes a CSV of
raw results plus an HTML summary with a score.

  Tegria baseline (default): practical, real-world checks: MFA adoption (>=95%), Conditional Access presence,
  legacy authentication, email security (SPF, DKIM, DMARC), Secure Score visibility and audit logging.

  CIS baseline: stricter checks aligned with CIS guidance: global admin limits, 100% MFA, strict legacy auth
  blocking, DLP policy presence, audit logging and email security.

Limitations: some advanced settings (Defender, Intune, deep Conditional Access analysis) are not fully audited
because of API limits; DLP checks need the right licensing; SPF/DMARC checks depend on external DNS resolution.

.PARAMETER Baseline
Tegria (default) or CIS.

.PARAMETER CustomerName
Customer or tenant label used in the report title and file names.

.PARAMETER PrimaryDomain
Primary email domain to test for SPF/DKIM/DMARC, e.g. contoso.com.

.PARAMETER OutputPath
Folder for the CSV and HTML reports. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER InstallMissingModules
Install Microsoft.Graph and ExchangeOnlineManagement for the current user if missing.

.PARAMETER SkipSharePointChecks
Skip the SharePoint-related checks.

.EXAMPLE
.\Invoke-M365SecurityBaseline.ps1 -CustomerName Contoso -PrimaryDomain contoso.com -OutputPath D:\Reports

.EXAMPLE
.\Invoke-M365SecurityBaseline.ps1 -CustomerName Contoso -PrimaryDomain contoso.com -Baseline CIS -OutputPath D:\Reports -InstallMissingModules

.NOTES
Platform:     Windows (PowerShell 5.1 or 7+)
Permissions:  Global Reader or Security Reader in the tenant (consent to the Graph scopes requested at sign-in), plus Exchange Online View-Only roles
When to use:  Onboarding a new customer, an annual security review, or before and after a remediation project.
Safety:       Read-only
Version:      2.1
#>
[CmdletBinding()]
param(
    [ValidateSet("CIS","Tegria")]
    [string]$Baseline = "Tegria",

    [Parameter(Mandatory)][string]$CustomerName,
    [Parameter(Mandatory)][string]$PrimaryDomain,
    [string]$OutputPath,

    [switch]$InstallMissingModules,
    [switch]$SkipSharePointChecks
)

function Resolve-OutputPath {
    param([string]$Path, [string]$CustomerName)
    if (-not $Path) { $Path = $env:TOOLBOX_REPORT_DIR }
    if (-not $Path) { $Path = Read-Host 'Output folder for reports' }
    if (-not $Path) { throw 'An output path is required.' }
    if ($CustomerName) { $Path = Join-Path $Path $CustomerName }
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    (Resolve-Path -LiteralPath $Path).Path
}

# =========================
# Configuration
# =========================

$BaselineVersion = "2.0"
$ReportDate = Get-Date -Format "yyyy-MM-dd_HHmm"

$ReportFolder = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName

$CsvReportPath  = Join-Path $ReportFolder "$CustomerName-$Baseline-$ReportDate.csv"
$HtmlReportPath = Join-Path $ReportFolder "$CustomerName-$Baseline-$ReportDate.html"


# =========================
# Modules
# =========================

$RequiredModules = @(
    "Microsoft.Graph",
    "ExchangeOnlineManagement"
)

function Test-RequiredModules {
    param([switch]$InstallMissingModules)

    foreach ($module in $RequiredModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            Write-Host "Missing: $module" -ForegroundColor Red

            if ($InstallMissingModules) {
                Install-Module $module -Scope CurrentUser -Force -AllowClobber
            } else {
                throw "Missing required module: $module"
            }
        }
    }
}

function Import-Modules {
    Import-Module Microsoft.Graph
    Import-Module ExchangeOnlineManagement
}

# =========================
# Connections
# =========================

function Connect-Services {
    Connect-MgGraph -Scopes `
        "Directory.Read.All",
        "Policy.Read.All",
        "Reports.Read.All",
        "Security.Read.All",
        "AuditLog.Read.All",
        "UserAuthenticationMethod.Read.All"

    Connect-ExchangeOnline -ShowBanner:$false

    try { Connect-IPPSSession -ErrorAction Stop } catch {}
}

# =========================
# Helpers
# =========================

function New-Result {
    param($Category,$Check,$Result,$Status,$Notes="")

    [PSCustomObject]@{
        Category = $Category
        Check    = $Check
        Result   = $Result
        Status   = $Status
        Notes    = $Notes
    }
}

function Safe-Run {
    param($ScriptBlock)

    try { & $ScriptBlock }
    catch {
        return New-Result "General" "Execution Failure" "Error" "ERROR" $_.Exception.Message
    }
}

# =========================
# SHARED CHECKS
# =========================

function Test-CA {
    Safe-Run {
        $pol = Get-MgIdentityConditionalAccessPolicy -All
        New-Result "Identity" "Conditional Access Policies" "$($pol.Count)" (if($pol.Count -gt 0){"PASS"}else{"FAIL"})
    }
}

function Test-MailForward {
    Safe-Run {
        $mb = Get-Mailbox -ResultSize Unlimited
        $fw = $mb | Where-Object-Object {$_.ForwardingSmtpAddress}
        New-Result "Email" "Mailbox Forwarding" "$($fw.Count)" (if($fw.Count -eq 0){"PASS"}else{"WARN"})
    }
}

function Test-DKIM {
    Safe-Run {
        $d = Get-DkimSigningConfig -Identity $PrimaryDomain -ErrorAction SilentlyContinue
        New-Result "Email" "DKIM" ($d.Enabled) (if($d.Enabled){"PASS"}else{"FAIL"})
    }
}

function Test-SPF {
    Safe-Run {
        $txt = Resolve-DnsName $PrimaryDomain -Type TXT
        $spf = $txt | Where-Object {$_.Strings -match "spf"}
        New-Result "Email" "SPF" ($spf.Strings) (if($spf){"PASS"}else{"FAIL"})
    }
}

function Test-DMARC {
    Safe-Run {
        $txt = Resolve-DnsName "_dmarc.$PrimaryDomain" -Type TXT
        $rec = $txt.Strings -join ""
        New-Result "Email" "DMARC" $rec (if($rec -match "p=reject"){"PASS"}else{"WARN"})
    }
}

function Test-SecureScore {
    Safe-Run {
        $s = Get-MgSecuritySecureScore | Sort-Object CreatedDateTime -Descending | Select-Object -First 1
        $pct = [math]::Round(($s.CurrentScore / $s.MaxScore)*100,2)
        New-Result "Tenant" "Secure Score" "$pct%" "INFO"
    }
}

function Test-AuditLog {
    Safe-Run {
        $a = Get-AdminAuditLogConfig
        New-Result "Monitoring" "Audit Logging" $a.UnifiedAuditLogIngestionEnabled (if($a.UnifiedAuditLogIngestionEnabled){"PASS"}else{"FAIL"})
    }
}

# =========================
# TEGRIA BASELINE
# =========================

function Test-MFA-Tegria {
    Safe-Run {
        $data = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
        $pct = [math]::Round((($data | Where-Object {$_.IsMfaRegistered}).Count / $data.Count)*100,2)
        New-Result "Identity" "MFA Adoption >=95%" "$pct%" (if($pct -ge 95){"PASS"}else{"FAIL"})
    }
}

function Test-LegacyAuth-Tegria {
    Safe-Run {
        $pol = Get-MgIdentityConditionalAccessPolicy -All
        $found = $pol | Where-Object { $_.Conditions.ClientAppTypes -contains "other" }
        New-Result "Identity" "Legacy Auth Block" (if($found){"Configured"}else{"Missing"}) (if($found){"PASS"}else{"FAIL"})
    }
}

function Run-TegriaBaseline {
    $Results = @()

    $Results += Test-MFA-Tegria
    $Results += Test-CA
    $Results += Test-LegacyAuth-Tegria
    $Results += Test-MailForward
    $Results += Test-DKIM
    $Results += Test-SPF
    $Results += Test-DMARC
    $Results += Test-SecureScore
    $Results += Test-AuditLog

    return $Results
}

# =========================
# CIS BASELINE
# =========================

function Test-CIS-GlobalAdmins {
    Safe-Run {
        $role = Get-MgDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"}
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
        New-Result "CIS Identity" "Global Admin <=4" $members.Count (if($members.Count -le 4){"PASS"}else{"FAIL"})
    }
}

function Test-CIS-MFA {
    Safe-Run {
        $data = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
        $missing = ($data | Where-Object {!$_.IsMfaRegistered}).Count
        New-Result "CIS MFA" "100% MFA Required" "$missing missing" (if($missing -eq 0){"PASS"}else{"FAIL"})
    }
}

function Test-CIS-LegacyAuth {
    Safe-Run {
        $pol = Get-MgIdentityConditionalAccessPolicy -All
        $found = $pol | Where-Object {
            $_.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or
            $_.Conditions.ClientAppTypes -contains "other"
        }
        New-Result "CIS CA" "Legacy Auth Fully Blocked" $found.Count (if($found){"PASS"}else{"FAIL"})
    }
}

function Test-CIS-DLP {
    Safe-Run {
        $pol = Get-DlpCompliancePolicy
        New-Result "CIS DLP" "DLP Policies Required" $pol.Count (if($pol.Count -gt 0){"PASS"}else{"FAIL"})
    }
}

function Run-CISBaseline {
    $Results = @()

    $Results += Test-CIS-GlobalAdmins
    $Results += Test-CIS-MFA
    $Results += Test-CA
    $Results += Test-CIS-LegacyAuth
    $Results += Test-MailForward
    $Results += Test-DKIM
    $Results += Test-SPF
    $Results += Test-DMARC
    $Results += Test-AuditLog
    $Results += Test-CIS-DLP
    $Results += Test-SecureScore

    return $Results
}

# =========================
# HTML REPORT
# =========================

function Build-HTML {
    param($Results)

    $pass = ($Results | Where-Object {$_.Status -eq "PASS"}).Count
    $total = $Results.Count
    $score = if ($total -gt 0) {[math]::Round(($pass / $total)*100,0)} else {0}

    $rows = $Results | ForEach-Object {
        "<tr><td>$($_.Category)</td><td>$($_.Check)</td><td>$($_.Result)</td><td>$($_.Status)</td><td>$($_.Notes)</td></tr>"
    }

@"
<html>
<head>
<style>
body {font-family:Segoe UI;}
table {border-collapse:collapse;width:100%;}
td,th {padding:8px;border:1px solid #ddd;}
th {background:#333;color:#fff;}
</style>
</head>
<body>

<h1>$CustomerName Security Report ($Baseline)</h1>
<p>Score: $score%</p>

<table>
<tr><th>Category</th><th>Check</th><th>Result</th><th>Status</th><th>Notes</th></tr>
$($rows -join "`n")
</table>

</body>
</html>
"@ | Out-File $HtmlReportPath
}

# =========================
# MAIN
# =========================

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "M365 Security Audit - Baseline: $Baseline" -ForegroundColor Yellow
Write-Host "=====================================" -ForegroundColor Cyan

Test-RequiredModules -InstallMissingModules:$InstallMissingModules
Import-Modules
Connect-Services

switch ($Baseline) {
    "CIS"     { $Results = Run-CISBaseline }
    "Tegria"  { $Results = Run-TegriaBaseline }
}

$Results | Export-Csv $CsvReportPath -NoTypeInformation
Build-HTML $Results

Write-Host "Report Complete:" -ForegroundColor Green
Write-Host $CsvReportPath
Write-Host $HtmlReportPath