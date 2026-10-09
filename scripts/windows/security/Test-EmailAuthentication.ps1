#Requires -Version 5.1

<#
.SYNOPSIS
Audits SPF, DKIM and DMARC DNS records for a list of domains and writes an HTML report plus optional CSV/Excel.

.DESCRIPTION
Reads a CSV with a 'Domain' column and, for each domain, queries public DNS (Resolve-DnsName) for:
  - SPF: a TXT record starting with v=spf1 (also used to detect Microsoft 365 or Google Workspace as the mail platform)
  - DMARC: the _dmarc TXT record, the policy (reject / quarantine / none) and whether the rua reporting address is valid
  - DKIM: common selectors for the detected platform (selector1/selector2 for Microsoft 365, google for Google
    Workspace, otherwise default/mail/dkim). Only these selectors are tried, so a custom selector shows as "No".
The HTML report shows one coloured row per domain. -Format writes the full results (including the SPF and DMARC
record text) as CSV or Excel next to the report. Only public DNS data is read; nothing is changed.

Input CSV example (first row is the header):
    Domain
    contoso.com
    fabrikam.net

.PARAMETER InputCsv
Path to the CSV file containing a 'Domain' column. Keep this file outside the repository.

.PARAMETER OutputPath
Folder for the report. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER Format
Data export format written next to the HTML report: Csv (default), Xlsx (requires the ImportExcel module) or None.

.EXAMPLE
.\Test-EmailAuthentication.ps1 -InputCsv D:\Input\domains.csv -OutputPath D:\Reports

.EXAMPLE
.\Test-EmailAuthentication.ps1 -InputCsv D:\Input\domains.csv -Format Xlsx -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (uses Resolve-DnsName from the DnsClient module)
Permissions:  Standard user with outbound DNS access; no directory or tenant rights needed
When to use:  Security assessments, onboarding a new customer domain list, or checking spoofing protection before and after a DMARC rollout.
Safety:       Read-only
Version:      1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputCsv,
    [string]$OutputPath,
    [string]$CustomerName,
    [ValidateSet('Csv', 'Xlsx', 'None')]
    [string]$Format = 'Csv'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-OutputPath {
    param([string]$Path, [string]$CustomerName)
    if (-not $Path) { $Path = $env:TOOLBOX_REPORT_DIR }
    if (-not $Path) { $Path = Read-Host 'Output folder for reports' }
    if (-not $Path) { throw 'An output path is required.' }
    if ($CustomerName) { $Path = Join-Path $Path $CustomerName }
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    (Resolve-Path -LiteralPath $Path).Path
}

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 's'), $Level, $Message
    Write-Host $line
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $line }
}

$stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir   = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$htmlPath = Join-Path $outDir "Test-EmailAuthentication_$stamp.html"
$script:LogFile = Join-Path $outDir "Test-EmailAuthentication_$stamp.log"
$dataPath = $null
if ($Format -eq 'Csv')  { $dataPath = Join-Path $outDir "Test-EmailAuthentication_$stamp.csv" }
if ($Format -eq 'Xlsx') { $dataPath = Join-Path $outDir "Test-EmailAuthentication_$stamp.xlsx" }

try {
    if (-not (Test-Path -LiteralPath $InputCsv)) { throw "Input CSV not found: $InputCsv" }

    if ($Format -eq 'Xlsx') {
        if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
            throw "The ImportExcel module is required for -Format Xlsx. Install it with: Install-Module ImportExcel -Scope CurrentUser"
        }
        Import-Module ImportExcel -ErrorAction Stop
    }

    $InputRows = @(Import-Csv -LiteralPath $InputCsv)
    if ($InputRows.Count -eq 0) { throw "Input CSV has no rows: $InputCsv" }
    if (-not $InputRows[0].PSObject.Properties['Domain']) { throw "Input CSV must have a 'Domain' column." }

    $Results = @()

    foreach ($Row in $InputRows) {
        if ([string]::IsNullOrWhiteSpace($Row.Domain)) { continue }
        $Domain = $Row.Domain.Trim()
        Write-Log "Auditing $Domain..."

        # ---------------- SPF + PLATFORM DETECTION ----------------
        $SPFPresent = "No"
        $SPFRecord = ""
        $MailPlatform = "Unknown"

        try {
            Resolve-DnsName $Domain -Type TXT -ErrorAction Stop | ForEach-Object {
                if (-not $_.PSObject.Properties['Strings']) { return }
                $txt = ($_.Strings -join "")
                if ($txt -match "^v=spf1") {
                    $SPFPresent = "Yes"
                    $SPFRecord = $txt
                    if ($txt -match "spf\.protection\.outlook\.com") { $MailPlatform = "Microsoft 365" }
                    elseif ($txt -match "_spf\.google\.com") { $MailPlatform = "Google Workspace" }
                }
            }
        } catch {}

        # ---------------- DMARC + POLICY + RUA ----------------
        $DMARCPresent = "No"
        $DMARCRecord = ""
        $DMARCPolicy = "Missing"
        $RuaStatus = "Missing"

        try {
            $dmarc = Resolve-DnsName "_dmarc.$Domain" -Type TXT -ErrorAction Stop
            $DMARCPresent = "Yes"
            $DMARCRecord = (@($dmarc | ForEach-Object { if ($_.PSObject.Properties['Strings']) { $_.Strings } }) -join "")

            if ($DMARCRecord -match "p=reject") { $DMARCPolicy = "Reject" }
            elseif ($DMARCRecord -match "p=quarantine") { $DMARCPolicy = "Quarantine" }
            elseif ($DMARCRecord -match "p=none") { $DMARCPolicy = "None" }

            if ($DMARCRecord -match "rua=mailto:([^;]+)") {
                $Rua = $Matches[1]
                if ($Rua -match "^[^@]+@[^@]+\.[^@]+$") {
                    if ($Rua.Split("@")[1] -eq $Domain) {
                        $RuaStatus = "Valid"
                    } else {
                        $RuaStatus = "External domain (Auth required)"
                    }
                } else {
                    $RuaStatus = "Invalid format"
                }
            }
        } catch {}

        # ---------------- DKIM AUTO SELECTORS ----------------
        switch ($MailPlatform) {
            "Microsoft 365" { $Selectors = @("selector1","selector2") }
            "Google Workspace" { $Selectors = @("google") }
            default { $Selectors = @("default","mail","dkim") }
        }

        $DKIMFound = @()
        foreach ($sel in $Selectors) {
            try {
                Resolve-DnsName "$sel._domainkey.$Domain" -Type TXT -ErrorAction Stop | Out-Null
                $DKIMFound += $sel
            } catch {}
        }

        $DKIMPresent = if ($DKIMFound) { "Yes" } else { "No" }

        # ---------------- COLOR STATUS ----------------
        $SPFStatusColor = if ($SPFPresent -eq "Yes") { "Green" } else { "Red" }
        $DKIMStatusColor = if ($DKIMPresent -eq "Yes") { "Green" } else { "Red" }
        $DMARCStatusColor = switch ($DMARCPolicy) {
            "Reject" { "Green" }
            "Quarantine" { "Yellow" }
            default { "Red" }
        }

        # ---------------- RESULT OBJECT ----------------
        $Results += [PSCustomObject]@{
            Domain = $Domain
            MailPlatform = $MailPlatform
            SPF = $SPFPresent
            SPF_Record = $SPFRecord
            DKIM = $DKIMPresent
            DKIM_Selectors = ($DKIMFound -join ", ")
            DMARC = $DMARCPresent
            DMARC_Policy = $DMARCPolicy
            DMARC_RUA_Status = $RuaStatus
            SPF_Color = $SPFStatusColor
            DKIM_Color = $DKIMStatusColor
            DMARC_Color = $DMARCStatusColor
        }
    }

    # ---------------- EXPORT DATA ----------------
    if ($Format -eq 'Csv') {
        $Results | Export-Csv -LiteralPath $dataPath -NoTypeInformation -Encoding UTF8
    }
    elseif ($Format -eq 'Xlsx') {
        $Results | Export-Excel -Path $dataPath -AutoSize -BoldTopRow
    }

    # ---------------- HTML REPORT ----------------
    $HtmlRows = $Results | ForEach-Object {
@"
<tr>
<td>$($_.Domain)</td>
<td>$($_.MailPlatform)</td>
<td style='color:$($_.SPF_Color)'>$($_.SPF)</td>
<td style='color:$($_.DKIM_Color)'>$($_.DKIM)</td>
<td style='color:$($_.DMARC_Color)'>$($_.DMARC_Policy)</td>
<td>$($_.DMARC_RUA_Status)</td>
</tr>
"@
    }

    $Html = @"
<html>
<head>
<title>Email Authentication Audit</title>
</head>
<body>
<h1>Email Authentication Audit</h1>
<table border='1' cellpadding='5'>
<tr>
<th>Domain</th><th>Platform</th><th>SPF</th><th>DKIM</th><th>DMARC Policy</th><th>DMARC RUA</th>
</tr>
$($HtmlRows -join "")
</table>
</body>
</html>
"@
    $Html | Out-File -LiteralPath $htmlPath -Encoding UTF8

    Write-Log "Audit complete: $(@($Results).Count) domain(s)."
    Write-Log "HTML: $htmlPath"
    if ($dataPath) { Write-Log "Export: $dataPath" }
}
catch {
    Write-Log "Email authentication audit failed: $_" 'ERROR'
    throw
}
