param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\OnboardingReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(Mandatory = $false)]
    [string]$LogPath = ".\Onboarding_Log.csv",

    [Parameter(Mandatory = $false)]
    [string]$Domain,

    [Parameter(Mandatory = $false)]
    [string]$UsageLocation = "US",

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGraphConnect
)

$Results = [System.Collections.Generic.List[PSObject]]::new()

function Write-Result {
    param($User, $Action, $Status, $Detail)
    $Results.Add([PSCustomObject]@{
        UserPrincipalName = $User
        Action            = $Action
        Status            = $Status
        Detail            = $Detail
        Timestamp         = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    })
}

function Connect-ToGraph {
    $scopes = @(
        'User.ReadWrite.All',
        'Group.ReadWrite.All',
        'Organization.Read.All',
        'Directory.ReadWrite.All'
    )
    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        $ctx = Get-MgContext
        Write-Host "Connected to tenant: $($ctx.TenantId)" -ForegroundColor Green
    } catch {
        throw "Graph authentication failed: $_"
    }
}

function Get-ManagedIdentity {
    param([string]$UserPrincipalName)
    $Username = $UserPrincipalName -split '@'
    $UPN = "$($Username[0])@$Domain"
    $MailNickname = $Username[0]
    return @{ UPN = $UPN; MailNickname = $MailNickname }
}

function New-CloudUser {
    param(
        $CsvRow,
        [string]$DomainName
    )

    $GivenName = $CsvRow.FirstName
    $Surname = $CsvRow.LastName
    $SamName = $CsvRow.Username

    if (-not $SamName) {
        $SamName = ($GivenName.Substring(0, [math]::Min(1, $GivenName.Length)) + $Surname).ToLower()
    }

    $UserPrincipalName = "$SamName@$DomainName"
    $DisplayName = "$GivenName $Surname"

    $TempPassword = "ChangeMe-" + [System.IO.Path]::GetRandomFileName().Replace('.', '') + "1!"

    $PasswordProfile = @{
        Password = $TempPassword
        ForceChangePasswordNextSignIn = $true
    }

    $UserParams = @{
        DisplayName              = $DisplayName
        GivenName                = $GivenName
        Surname                  = $Surname
        MailNickname             = $SamName
        UserPrincipalName        = $UserPrincipalName
        PasswordProfile          = $PasswordProfile
        AccountEnabled           = $true
        UsageLocation            = $UsageLocation
        Department               = $CsvRow.Department
        JobTitle                 = $CsvRow.Title
        CompanyName              = $CsvRow.Company
        EmployeeId               = $CsvRow.EmployeeId
        StreetAddress            = $CsvRow.StreetAddress
        City                     = $CsvRow.City
        State                    = $CsvRow.State
        PostalCode               = $CsvRow.PostalCode
        Country                  = $CsvRow.Country
        MobilePhone              = $CsvRow.MobilePhone
        BusinessPhones           = @($CsvRow.BusinessPhone | Where-Object { $_ })
    }

    if ($WhatIf) {
        Write-Host "[WhatIf] Would create user: $UserPrincipalName" -ForegroundColor Yellow
        Write-Result -User $UserPrincipalName -Action "CreateUser" -Status "WhatIf" -Detail "Would create user with temp password"
        return @{
            UserPrincipalName = $UserPrincipalName
            TempPassword = $TempPassword
        }
    }

    try {
        $NewUser = New-MgUser @UserParams -ErrorAction Stop
        Write-Result -User $UserPrincipalName -Action "CreateUser" -Status "Success" -Detail "User created"
        Write-Host "Created user: $UserPrincipalName" -ForegroundColor Green
        return @{
            UserPrincipalName = $UserPrincipalName
            TempPassword = $TempPassword
        }
    } catch {
        Write-Result -User $UserPrincipalName -Action "CreateUser" -Status "Failed" -Detail $_.Exception.Message
        Write-Warning "Failed to create $UserPrincipalName : $_"
        return $null
    }
}

function Set-License {
    param(
        [string]$UserPrincipalName,
        [string]$SkuPartNumber
    )

    if (-not $SkuPartNumber) { return }

    try {
        $License = @{ SkuId = $null }
        $SubscribedSkus = Get-MgSubscribedSku -ErrorAction Stop
        $TargetSku = $SubscribedSkus | Where-Object { $_.SkuPartNumber -eq $SkuPartNumber }
        if (-not $TargetSku) {
            $Available = $SubscribedSkus | Select-Object -First 10 SkuPartNumber
            Write-Warning "SKU '$SkuPartNumber' not found. Available: $($Available.SkuPartNumber -join ', ')"
            Write-Result -User $UserPrincipalName -Action "AssignLicense" -Status "Failed" -Detail "SKU not found: $SkuPartNumber"
            return
        }
        $License.SkuId = $TargetSku.SkuId

        if ($WhatIf) {
            Write-Host "[WhatIf] Would assign license $SkuPartNumber to $UserPrincipalName" -ForegroundColor Yellow
            Write-Result -User $UserPrincipalName -Action "AssignLicense" -Status "WhatIf" -Detail "Would assign: $SkuPartNumber"
            return
        }

        Set-MgUserLicense -UserId $UserPrincipalName -AddLicenses @($License) -RemoveLicenses @() -ErrorAction Stop
        Write-Result -User $UserPrincipalName -Action "AssignLicense" -Status "Success" -Detail "Assigned: $SkuPartNumber"
        Write-Host "  License $SkuPartNumber assigned" -ForegroundColor Green
    } catch {
        Write-Result -User $UserPrincipalName -Action "AssignLicense" -Status "Failed" -Detail $_.Exception.Message
        Write-Warning "  License assignment failed: $_"
    }
}

function Add-UserToGroups {
    param(
        [string]$UserPrincipalName,
        [string[]]$GroupNames
    )

    if (-not $GroupNames -or $GroupNames.Count -eq 0) { return }

    foreach ($GroupName in $GroupNames) {
        try {
            $Group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
            if (-not $Group) {
                Write-Result -User $UserPrincipalName -Action "AddToGroup" -Status "Failed" -Detail "Group not found: $GroupName"
                continue
            }

            if ($WhatIf) {
                Write-Host "[WhatIf] Would add $UserPrincipalName to $GroupName" -ForegroundColor Yellow
                Write-Result -User $UserPrincipalName -Action "AddToGroup" -Status "WhatIf" -Detail $GroupName
                continue
            }

            New-MgGroupMember -GroupId $Group.Id -DirectoryObjectId (Get-MgUser -UserId $UserPrincipalName).Id -ErrorAction Stop
            Write-Result -User $UserPrincipalName -Action "AddToGroup" -Status "Success" -Detail $GroupName
            Write-Host "  Added to group: $GroupName" -ForegroundColor Green
        } catch {
            Write-Result -User $UserPrincipalName -Action "AddToGroup" -Status "Failed" -Detail "$GroupName : $_"
        }
    }
}

# ── MAIN ──

Write-Host "=== Bulk User Onboarding ===" -ForegroundColor Cyan
Write-Host "CSV: $CsvPath" -ForegroundColor White

if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV file not found: $CsvPath"
    return
}

$Users = Import-Csv $CsvPath
Write-Host "Found $($Users.Count) users to onboard" -ForegroundColor Yellow

if (-not $SkipGraphConnect) {
    Connect-ToGraph
}

if (-not $Domain) {
    try {
        $Org = Get-MgOrganization -ErrorAction Stop
        $Domain = $Org.VerifiedDomains | Where-Object { $_.IsDefault } | Select-Object -ExpandProperty Name
        Write-Host "Using default domain: $Domain" -ForegroundColor Cyan
    } catch {
        Write-Error "Could not determine domain and -Domain not specified"
        return
    }
}

$OnboardedUsers = @()

foreach ($User in $Users) {
    Write-Host "`nProcessing: $($User.FirstName) $($User.LastName)" -ForegroundColor Yellow

    $Created = New-CloudUser -CsvRow $User -DomainName $Domain
    if (-not $Created) { continue }

    $OnboardedUsers += $Created

    $Groups = @()
    if ($User.Groups) { $Groups += $User.Groups -split ';' }
    $DepartmentGroup = $User.Department -replace '\s+', ''
    if ($DepartmentGroup) { $Groups += $DepartmentGroup }

    Add-UserToGroups -UserPrincipalName $Created.UserPrincipalName -GroupNames $Groups

    Start-Sleep -Seconds 2

    Set-License -UserPrincipalName $Created.UserPrincipalName -SkuPartNumber $User.License
}

$Passwords = $OnboardedUsers | ForEach-Object {
    [PSCustomObject]@{
        UserPrincipalName = $_.UserPrincipalName
        TemporaryPassword = $_.TempPassword
    }
}

$CredCsv = $ReportPath -replace '\.html$', '_credentials.csv'
$Passwords | Export-Csv -Path $CredCsv -NoTypeInformation -Encoding UTF8
Write-Host "`nCredentials saved: $CredCsv" -ForegroundColor Green

$SuccessCount = ($Results | Where-Object { $_.Status -eq "Success" }).Count
$FailCount = ($Results | Where-Object { $_.Status -eq "Failed" }).Count
$WhatIfCount = ($Results | Where-Object { $_.Status -eq "WhatIf" }).Count

$HtmlRows = $Results | ForEach-Object {
    $RowClass = switch ($_.Status) {
        "Success" { "" }
        "Failed" { "danger" }
        "WhatIf" { "warning" }
        default { "" }
    }
    "<tr class='$RowClass'>
        <td>$($_.UserPrincipalName)</td>
        <td>$($_.Action)</td>
        <td>$($_.Status)</td>
        <td>$($_.Detail)</td>
        <td>$($_.Timestamp)</td>
    </tr>"
}

$Html = @"
<!DOCTYPE html>
<html>
<head><title>Bulk User Onboarding Report</title>
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
<h1>Bulk User Onboarding Report</h1>
<div class='summary'>
    <strong>CSV:</strong> $CsvPath |
    <strong>Total Users:</strong> $($Users.Count) |
    <strong>Success:</strong> $SuccessCount |
    <strong>Failed:</strong> $FailCount |
    <strong>WhatIf:</strong> $WhatIfCount
</div>
<table>
<tr><th>User</th><th>Action</th><th>Status</th><th>Detail</th><th>Timestamp</th></tr>
$($HtmlRows -join "`n")
</table>
</body></html>
"@

$Html | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report: $ReportPath" -ForegroundColor Green

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Total: $($Users.Count) | Success: $SuccessCount | Failed: $FailCount | WhatIf: $WhatIfCount"
