#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
Exports every Active Directory user with ~55 properties to a CSV.

.DESCRIPTION
Runs Get-ADUser against the current domain (or a specific server/search base) and writes one CSV row per
user. Date attributes are converted to UTC ISO-8601 strings and multi-valued attributes (MemberOf, Certificates)
are flattened with ';'. Use it as a full point-in-time user snapshot for migrations, audits, or cleanup planning.

.PARAMETER OutputPath
Folder for the CSV. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER SearchBase
Optional distinguished name of an OU to limit the export to.

.PARAMETER Server
Optional domain controller to query.

.EXAMPLE
.\Export-ADUserReport.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Export-ADUserReport.ps1 -OutputPath D:\Reports -CustomerName Contoso -SearchBase "OU=Staff,DC=contoso,DC=com"

.NOTES
Platform:     Windows (RSAT ActiveDirectory module, domain-joined machine)
Permissions:  Domain user with read access to AD (standard users can read most attributes)
When to use:  Before a domain migration or cleanup, for access reviews, or to hand a customer a user list.
Safety:       Read-only
Version:      1.0
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$CustomerName,
    [string]$SearchBase,
    [string]$Server
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

$stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir  = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$csvPath = Join-Path $outDir "Export-ADUserReport_$stamp.csv"
$script:LogFile = Join-Path $outDir "Export-ADUserReport_$stamp.log"

$properties = 'AccountExpirationDate', 'AccountExpires', 'AccountLockoutTime', 'BadLogonCount', 'CannotChangePassword',
    'CanonicalName', 'Certificates', 'City', 'CN', 'Company', 'Country', 'Created', 'Department', 'Description',
    'DisplayName', 'DistinguishedName', 'Division', 'EmailAddress', 'EmployeeID', 'EmployeeNumber', 'Enabled',
    'GivenName', 'Initials', 'IsDeleted', 'LastBadPasswordAttempt', 'LastLogonDate', 'LockedOut', 'Manager',
    'MemberOf', 'Modified', 'Name', 'ObjectCategory', 'ObjectClass', 'ObjectGUID', 'ObjectSID', 'Office',
    'Organization', 'OtherName', 'PasswordExpired', 'PasswordLastSet', 'PasswordNeverExpires', 'PasswordNotRequired',
    'pwdLastSet', 'SamAccountName', 'SamAccountType', 'SID', 'State', 'StreetAddress', 'Surname', 'Title', 'WhenChanged'
$dateProperties = 'AccountExpirationDate', 'AccountLockoutTime', 'Created', 'LastBadPasswordAttempt',
    'LastLogonDate', 'Modified', 'PasswordLastSet', 'WhenChanged'

try {
    $query = @{ Filter = '*'; Properties = $properties }
    if ($SearchBase) { $query.SearchBase = $SearchBase }
    if ($Server)     { $query.Server     = $Server }

    Write-Log 'Querying Active Directory users...'
    $users = @(Get-ADUser @query)
    Write-Log "Found $($users.Count) user(s)."

    $rows = foreach ($user in $users) {
        $row = [ordered]@{}
        foreach ($name in $properties) {
            $value = $null
            if ($user.PSObject.Properties[$name]) { $value = $user.$name }
            if ($name -in $dateProperties -and $value -is [datetime]) {
                $value = $value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
            }
            elseif ($null -ne $value -and $value -isnot [string] -and $value -is [System.Collections.IEnumerable]) {
                $value = (@($value) | ForEach-Object { "$_" }) -join ';'
            }
            $row[$name] = $value
        }
        [pscustomobject]$row
    }

    $rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "Report written: $csvPath"
}
catch {
    Write-Log "Export failed: $_" 'ERROR'
    throw
}
