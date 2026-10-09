# ==========================================
# Advanced Email Authentication Audit Script
# SPF / DKIM / DMARC + HTML + CSV/Excel
# ==========================================

$InputCsv = "C:\Scripts\domains.csv"
$HtmlOutput = "C:\Scripts\DomainEmailAuthAudit.html"
$ExportChoice = Read-Host "Choose export format: 1 = CSV, 2 = Excel"

if ($ExportChoice -eq "1") {
    $DataOutput = "C:\Scripts\DomainEmailAuthAudit.csv"
}
elseif ($ExportChoice -eq "2") {
    $DataOutput = "C:\Scripts\DomainEmailAuthAudit.xlsx"
    Import-Module ImportExcel -ErrorAction Stop
}
else {
    Write-Error "Invalid choice. Exiting."
    return
}

$Results = @()

Import-Csv $InputCsv | ForEach-Object {
    $Domain = $_.Domain.Trim()
    Write-Host "Auditing $Domain..." -ForegroundColor Cyan

    # ---------------- SPF + PLATFORM DETECTION ----------------
    $SPFPresent = "No"
    $SPFRecord = ""
    $MailPlatform = "Unknown"

    try {
        Resolve-DnsName $Domain -Type TXT | ForEach-Object {
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
        $dmarc = Resolve-DnsName "_dmarc.$Domain" -Type TXT
        $DMARCPresent = "Yes"
        $DMARCRecord = ($dmarc.Strings -join "")

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
            Resolve-DnsName "$sel._domainkey.$Domain" -Type TXT | Out-Null
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
if ($ExportChoice -eq "1") {
    $Results | Export-Csv $DataOutput -NoTypeInformation -Encoding UTF8
}
else {
    $Results | Export-Excel $DataOutput -AutoSize -BoldTopRow
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

@"
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
"@ | Out-File $HtmlOutput

Write-Host "Audit Complete!" -ForegroundColor Green
Write-Host "HTML: $HtmlOutput"
Write-Host "Export: $DataOutput"
