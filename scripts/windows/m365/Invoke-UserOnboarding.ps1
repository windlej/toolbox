#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users

<#
.SYNOPSIS
Bulk creates Microsoft 365 (Entra ID) cloud users from a CSV, adds them to groups and assigns a license.

.DESCRIPTION
Reads a CSV with one row per new hire and, for each row, creates the cloud user with a generated temporary
password (change required at first sign-in), adds the user to the groups listed in the CSV plus a group named
after the department (spaces removed), and assigns the license (SKU part number) named in the CSV. All
state-changing calls honour -WhatIf and -Confirm. The output is an HTML report with one row per operation
(user, action, status, detail, timestamp) and a log file.

Expected CSV columns: FirstName, LastName and optionally Username, Department, Title, Company, EmployeeId,
StreetAddress, City, State, PostalCode, Country, MobilePhone, BusinessPhone, Groups (semicolon separated)
and License (SKU part number, e.g. ENTERPRISEPACK).

SECURITY: temporary passwords are NOT written anywhere by default. Use -ExportCredentials to save them to a
plaintext CSV in the output folder (<script>_<timestamp>_credentials.csv). That file contains secrets: hand
it over securely, then delete it. Without -ExportCredentials the passwords are lost after the run and the
accounts need a password reset before first use. No credentials are written during -WhatIf.

.PARAMETER CsvPath
INPUT file: CSV of users to create (see DESCRIPTION for the columns).

.PARAMETER OutputPath
Folder for the report and log. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER ExportCredentials
Write the generated temporary passwords to a plaintext credentials CSV in the output folder. Sensitive.

.PARAMETER Domain
Domain used for the new user principal names. Defaults to the tenant's default verified domain.

.PARAMETER UsageLocation
Two-letter country code set as the users' usage location (required before licensing). Default US.

.PARAMETER SkipGraphConnect
Skip Connect-MgGraph (use when a Graph session with suitable scopes already exists).

.EXAMPLE
.\Invoke-UserOnboarding.ps1 -CsvPath D:\Input\newhires.csv -Domain contoso.com -OutputPath D:\Reports -WhatIf

.EXAMPLE
.\Invoke-UserOnboarding.ps1 -CsvPath D:\Input\newhires.csv -Domain fabrikam.net -OutputPath D:\Reports -CustomerName Fabrikam -ExportCredentials

.NOTES
Platform:     Windows (PowerShell 5.1+ with Microsoft Graph PowerShell SDK)
Permissions:  Graph scopes User.ReadWrite.All, Group.ReadWrite.All, Organization.Read.All, Directory.ReadWrite.All (User Administrator and Groups Administrator; License Administrator for licensing)
When to use:  Starting a batch of new employees or a new customer tenant's initial users.
Safety:       Changes data (supports -WhatIf)
Version:      1.1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [string]$OutputPath,

    [string]$CustomerName,

    [switch]$ExportCredentials,

    [string]$Domain,

    [string]$UsageLocation = 'US',

    [switch]$SkipGraphConnect
)

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

$stamp          = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir         = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$ReportPath     = Join-Path $outDir "Invoke-UserOnboarding_$stamp.html"
$CredCsv        = Join-Path $outDir "Invoke-UserOnboarding_${stamp}_credentials.csv"
$script:LogFile = Join-Path $outDir "Invoke-UserOnboarding_$stamp.log"

$Results = [System.Collections.Generic.List[PSObject]]::new()

# Note: the helper functions below are deliberately not advanced functions, so $PSCmdlet resolves to this
# script's own cmdlet context and -WhatIf / -Confirm apply to them.

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

function Get-DeclinedStatus {
    if ($WhatIfPreference) { return 'WhatIf' }
    return 'Skipped'
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
        Write-Log "Connected to tenant: $($ctx.TenantId)"
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

    $TempPassword = 'ChangeMe-' + [System.IO.Path]::GetRandomFileName().Replace('.', '') + '1!'

    $PasswordProfile = @{
        Password                      = $TempPassword
        ForceChangePasswordNextSignIn = $true
    }

    $UserParams = @{
        DisplayName       = $DisplayName
        GivenName         = $GivenName
        Surname           = $Surname
        MailNickname      = $SamName
        UserPrincipalName = $UserPrincipalName
        PasswordProfile   = $PasswordProfile
        AccountEnabled    = $true
        UsageLocation     = $UsageLocation
        Department        = $CsvRow.Department
        JobTitle          = $CsvRow.Title
        CompanyName       = $CsvRow.Company
        EmployeeId        = $CsvRow.EmployeeId
        StreetAddress     = $CsvRow.StreetAddress
        City              = $CsvRow.City
        State             = $CsvRow.State
        PostalCode        = $CsvRow.PostalCode
        Country           = $CsvRow.Country
        MobilePhone       = $CsvRow.MobilePhone
        BusinessPhones    = @($CsvRow.BusinessPhone | Where-Object { $_ })
    }

    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, 'Create user')) {
        $Status = Get-DeclinedStatus
        Write-Result -User $UserPrincipalName -Action 'CreateUser' -Status $Status -Detail 'Would create user with temp password'
        if ($Status -eq 'WhatIf') {
            # Continue the dry run so group and license steps are also reported.
            return @{
                UserPrincipalName = $UserPrincipalName
                TempPassword      = $null
                DryRun            = $true
            }
        }
        return $null
    }

    try {
        $NewUser = New-MgUser @UserParams -ErrorAction Stop
        Write-Result -User $UserPrincipalName -Action 'CreateUser' -Status 'Success' -Detail 'User created'
        Write-Log "Created user: $UserPrincipalName"
        return @{
            UserPrincipalName = $UserPrincipalName
            TempPassword      = $TempPassword
            DryRun            = $false
        }
    } catch {
        Write-Result -User $UserPrincipalName -Action 'CreateUser' -Status 'Failed' -Detail $_.Exception.Message
        Write-Log "Failed to create $UserPrincipalName : $_" 'WARN'
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
        $SubscribedSkus = @(Get-MgSubscribedSku -ErrorAction Stop)
        $TargetSku = $SubscribedSkus | Where-Object { $_.SkuPartNumber -eq $SkuPartNumber }
        if (-not $TargetSku) {
            $Available = @($SubscribedSkus | Select-Object -First 10 SkuPartNumber)
            Write-Log "SKU '$SkuPartNumber' not found. Available: $(($Available | ForEach-Object { $_.SkuPartNumber }) -join ', ')" 'WARN'
            Write-Result -User $UserPrincipalName -Action 'AssignLicense' -Status 'Failed' -Detail "SKU not found: $SkuPartNumber"
            return
        }
        $License.SkuId = $TargetSku.SkuId

        if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, "Assign license $SkuPartNumber")) {
            Write-Result -User $UserPrincipalName -Action 'AssignLicense' -Status (Get-DeclinedStatus) -Detail "Would assign: $SkuPartNumber"
            return
        }

        Set-MgUserLicense -UserId $UserPrincipalName -AddLicenses @($License) -RemoveLicenses @() -ErrorAction Stop | Out-Null
        Write-Result -User $UserPrincipalName -Action 'AssignLicense' -Status 'Success' -Detail "Assigned: $SkuPartNumber"
        Write-Log "  License $SkuPartNumber assigned"
    } catch {
        Write-Result -User $UserPrincipalName -Action 'AssignLicense' -Status 'Failed' -Detail $_.Exception.Message
        Write-Log "  License assignment failed: $_" 'WARN'
    }
}

function Add-UserToGroups {
    param(
        [string]$UserPrincipalName,
        [string[]]$GroupNames
    )

    if (-not $GroupNames -or @($GroupNames).Count -eq 0) { return }

    foreach ($GroupName in $GroupNames) {
        try {
            $Group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
            if (-not $Group) {
                Write-Result -User $UserPrincipalName -Action 'AddToGroup' -Status 'Failed' -Detail "Group not found: $GroupName"
                continue
            }

            if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, "Add to group $GroupName")) {
                Write-Result -User $UserPrincipalName -Action 'AddToGroup' -Status (Get-DeclinedStatus) -Detail $GroupName
                continue
            }

            New-MgGroupMember -GroupId $Group.Id -DirectoryObjectId (Get-MgUser -UserId $UserPrincipalName).Id -ErrorAction Stop
            Write-Result -User $UserPrincipalName -Action 'AddToGroup' -Status 'Success' -Detail $GroupName
            Write-Log "  Added to group: $GroupName"
        } catch {
            Write-Result -User $UserPrincipalName -Action 'AddToGroup' -Status 'Failed' -Detail "$GroupName : $_"
        }
    }
}

# -- MAIN --

try {
    Write-Log '=== Bulk User Onboarding ==='
    Write-Log "CSV: $CsvPath"

    if (-not (Test-Path -LiteralPath $CsvPath)) {
        throw "CSV file not found: $CsvPath"
    }

    $Users = @(Import-Csv -LiteralPath $CsvPath)
    Write-Log "Found $($Users.Count) users to onboard"

    if (-not $SkipGraphConnect) {
        Connect-ToGraph
    }

    if (-not $Domain) {
        try {
            $Org = Get-MgOrganization -ErrorAction Stop
            $Domain = @($Org.VerifiedDomains | Where-Object { $_.IsDefault } | Select-Object -ExpandProperty Name)[0]
            Write-Log "Using default domain: $Domain"
        } catch {
            throw "Could not determine domain and -Domain not specified: $_"
        }
    }

    $OnboardedUsers = @()

    foreach ($User in $Users) {
        Write-Log "Processing: $($User.FirstName) $($User.LastName)"

        $Created = New-CloudUser -CsvRow $User -DomainName $Domain
        if (-not $Created) { continue }

        $OnboardedUsers += $Created

        $Groups = @()
        if ($User.Groups) { $Groups += $User.Groups -split ';' }
        $DepartmentGroup = $User.Department -replace '\s+', ''
        if ($DepartmentGroup) { $Groups += $DepartmentGroup }

        Add-UserToGroups -UserPrincipalName $Created.UserPrincipalName -GroupNames $Groups

        if (-not $Created.DryRun) { Start-Sleep -Seconds 2 }

        Set-License -UserPrincipalName $Created.UserPrincipalName -SkuPartNumber $User.License
    }

    $RealUsers = @($OnboardedUsers | Where-Object { -not $_.DryRun })
    if ($ExportCredentials) {
        if ($RealUsers.Count -gt 0) {
            $Passwords = $RealUsers | ForEach-Object {
                [PSCustomObject]@{
                    UserPrincipalName = $_.UserPrincipalName
                    TemporaryPassword = $_.TempPassword
                }
            }
            $Passwords | Export-Csv -LiteralPath $CredCsv -NoTypeInformation -Encoding UTF8
            Write-Log "Credentials saved (PLAINTEXT passwords, handle securely and delete after use): $CredCsv" 'WARN'
        } else {
            Write-Log '-ExportCredentials specified but no users were created; no credentials file written.' 'WARN'
        }
    } elseif ($RealUsers.Count -gt 0) {
        Write-Log 'Temporary passwords were generated but NOT saved (-ExportCredentials not set). Reset the passwords before the users first sign in.' 'WARN'
    }

    $SuccessCount = @($Results | Where-Object { $_.Status -eq 'Success' }).Count
    $FailCount    = @($Results | Where-Object { $_.Status -eq 'Failed' }).Count
    $WhatIfCount  = @($Results | Where-Object { $_.Status -eq 'WhatIf' }).Count

    $HtmlRows = $Results | ForEach-Object {
        $RowClass = switch ($_.Status) {
            'Success' { '' }
            'Failed'  { 'danger' }
            'WhatIf'  { 'warning' }
            default   { '' }
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

    $Html | Out-File -LiteralPath $ReportPath -Encoding UTF8
    Write-Log "Report: $ReportPath"

    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Total: $($Users.Count) | Success: $SuccessCount | Failed: $FailCount | WhatIf: $WhatIfCount"
}
catch {
    Write-Log "Onboarding failed: $_" 'ERROR'
    throw
}
