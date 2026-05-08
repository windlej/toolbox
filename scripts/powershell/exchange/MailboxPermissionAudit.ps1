param(
    [Parameter(Mandatory = $false)]
    [string[]]$UserPrincipalNames,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\MailboxPermissions_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$CsvExportPath,

    [Parameter(Mandatory = $false)]
    [string]$IncludePermissionTypes = "FullAccess,SendAs,SendOnBehalf",

    [Parameter(Mandatory = $false)]
    [switch]$ShowInherited,

    [Parameter(Mandatory = $false)]
    [switch]$SkipExchangeConnect
)

$Results = [System.Collections.Generic.List[PSObject]]::new()

function Connect-ToExchange {
    try {
        $Module = Get-Module ExchangeOnlineManagement -ListAvailable -ErrorAction SilentlyContinue
        if (-not $Module) {
            Write-Warning "ExchangeOnlineManagement module not found. Install: Install-Module ExchangeOnlineManagement"
            return $false
        }
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Host "Connected to Exchange Online" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Exchange connection failed: $_"
        return $false
    }
}

function Get-MailboxAccessRights {
    param(
        [string]$Identity,
        [string[]]$PermissionTypes
    )

    $Results = @()

    if ($PermissionTypes -contains "FullAccess" -or $PermissionTypes -contains "*") {
        $Permissions = Get-MailboxPermission -Identity $Identity -ErrorAction SilentlyContinue |
            Where-Object { -not $_.IsInherited -or $ShowInherited }
        foreach ($Perm in $Permissions) {
            if ($Perm.User -notlike "NT AUTHORITY\*" -and $Perm.User -notlike "S-1-*" -and $Perm.User -ne "Exchange Servers") {
                $Results += [PSCustomObject]@{
                    Mailbox      = $Identity
                    User         = $Perm.User
                    AccessRights = ($Perm.AccessRights -join ', ')
                    PermissionType = "FullAccess"
                    IsInherited  = $Perm.IsInherited
                    Deny         = $Perm.Deny
                }
            }
        }
    }

    if ($PermissionTypes -contains "SendAs") {
        $SendAsPerms = Get-RecipientPermission -Identity $Identity -ErrorAction SilentlyContinue |
            Where-Object { $_.Trustee -notlike "NT AUTHORITY\*" -and $_.Trustee -ne "Exchange Servers" }
        foreach ($Perm in $SendAsPerms) {
            $Results += [PSCustomObject]@{
                Mailbox      = $Identity
                User         = $Perm.Trustee
                AccessRights = "SendAs"
                PermissionType = "SendAs"
                IsInherited  = $false
                Deny         = $false
            }
        }
    }

    if ($PermissionTypes -contains "SendOnBehalf") {
        $Mailbox = Get-Mailbox -Identity $Identity -ErrorAction SilentlyContinue
        if ($Mailbox.GrantSendOnBehalfTo) {
            foreach ($Delegate in $Mailbox.GrantSendOnBehalfTo) {
                $Results += [PSCustomObject]@{
                    Mailbox      = $Identity
                    User         = $Delegate
                    AccessRights = "SendOnBehalf"
                    PermissionType = "SendOnBehalf"
                    IsInherited  = $false
                    Deny         = $false
                }
            }
        }
    }

    return $Results
}

# ── MAIN ──
Write-Host "=== Mailbox Permission Audit ===" -ForegroundColor Cyan

if ($CsvPath) {
    $CsvData = Import-Csv $CsvPath
    $UserPrincipalNames = $CsvData.UserPrincipalName
}

if (-not $UserPrincipalNames) {
    Write-Host "No specific users specified. Retrieving all mailboxes..." -ForegroundColor Yellow
    $Mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
    $UserPrincipalNames = $Mailboxes.UserPrincipalName
}

Write-Host "Auditing $($UserPrincipalNames.Count) mailboxes..." -ForegroundColor Yellow

$PermTypes = $IncludePermissionTypes -split ','

$i = 0
foreach ($UPN in $UserPrincipalNames) {
    $i++
    if ($i % 50 -eq 0) { Write-Host "  $i / $($UserPrincipalNames.Count)..." -ForegroundColor Gray }
    $Perms = Get-MailboxAccessRights -Identity $UPN -PermissionTypes $PermTypes
    foreach ($Perm in $Perms) {
        $Results.Add($Perm)
    }
}

$TotalPerms = $Results.Count
$MailboxesWithPerms = ($Results | Select-Object -ExpandProperty Mailbox -Unique).Count
$FullAccessCount = ($Results | Where-Object { $_.PermissionType -eq "FullAccess" }).Count
$SendAsCount = ($Results | Where-Object { $_.PermissionType -eq "SendAs" }).Count
$SendOnBehalfCount = ($Results | Where-Object { $_.PermissionType -eq "SendOnBehalf" }).Count

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total Permissions: $TotalPerms" -ForegroundColor White
Write-Host "  FullAccess: $FullAccessCount" -ForegroundColor Yellow
Write-Host "  SendAs: $SendAsCount" -ForegroundColor Yellow
Write-Host "  SendOnBehalf: $SendOnBehalfCount" -ForegroundColor Yellow
Write-Host "Mailboxes with Permissions: $MailboxesWithPerms" -ForegroundColor Gray

$HtmlRows = $Results | Sort-Object Mailbox, User | ForEach-Object {
    $RowClass = if ($_.Deny) { "danger" }
    elseif ($_.PermissionType -eq "FullAccess") { "warning" }
    else { "" }
    "<tr class='$RowClass'>
        <td>$($_.Mailbox)</td>
        <td>$($_.User)</td>
        <td>$($_.AccessRights)</td>
        <td>$($_.PermissionType)</td>
        <td>$($_.IsInherited)</td>
        <td>$($_.Deny)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Mailbox Permission Audit</title>
<style>
body { font-family: 'Segoe UI', sans-serif; margin: 20px; }
h1 { color: #2c3e50; }
.summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
table { border-collapse: collapse; width: 100%; font-size: 12px; }
th { background: #2c3e50; color: white; padding: 8px; text-align: left; }
td { padding: 5px 8px; border-bottom: 1px solid #ddd; }
.danger td { background: #f8d7da; }
.warning td { background: #fff3cd; }
</style></head>
<body>
<h1>Mailbox Permission Audit</h1>
<div class='summary'>
    <strong>Mailboxes:</strong> $($UserPrincipalNames.Count) |
    <strong>With Permissions:</strong> $MailboxesWithPerms |
    <strong>Total ACEs:</strong> $TotalPerms |
    <strong>FullAccess:</strong> $FullAccessCount |
    <strong>SendAs:</strong> $SendAsCount |
    <strong>SendOnBehalf:</strong> $SendOnBehalfCount
</div>
<table>
<tr><th>Mailbox</th><th>User/Group</th><th>Access Rights</th><th>Type</th><th>Inherited</th><th>Deny</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

if ($CsvExportPath) {
    $Results | Export-Csv -Path $CsvExportPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV: $CsvExportPath" -ForegroundColor Green
}
