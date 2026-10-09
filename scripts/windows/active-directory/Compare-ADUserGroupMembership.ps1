#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
Compares AD group membership between a source user and one or more destination users, and optionally syncs it.

.DESCRIPTION
Lists the groups each destination user is missing, has in addition to the source user, and shares with them.
By default it is read-only. Choose a -Mode to add missing groups, remove extra groups, or mirror the source
exactly. Protected groups (Domain Admins, etc.) are never removed. Every comparison result and change is
written to a CSV audit log.

Typical use: "give the new hire the same groups as their colleague" (AddOnly), or "make these accounts match
the template user" (Mirror).

.PARAMETER SourceUser
sAMAccountName of the user to copy from / compare against.

.PARAMETER DestinationUser
One or more sAMAccountNames to compare with the source.

.PARAMETER Mode
Compare (default, read-only), AddOnly, RemoveOnly, or Mirror (add and remove).

.PARAMETER Recursive
Compare effective membership, including groups inherited through nested groups. Default is direct membership.

.PARAMETER ProtectedGroup
Groups that are never removed. Defaults to Domain Admins, Enterprise Admins, Schema Admins, Administrators,
Account Operators and Server Operators.

.PARAMETER OutputPath
Folder for the audit CSV. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.EXAMPLE
.\Compare-ADUserGroupMembership.ps1 -SourceUser jsmith -DestinationUser akim -OutputPath D:\Reports

.EXAMPLE
.\Compare-ADUserGroupMembership.ps1 -SourceUser template.user -DestinationUser newhire1, newhire2 -Mode AddOnly -OutputPath D:\Reports -WhatIf

.NOTES
Platform:     Windows (RSAT ActiveDirectory module)
Permissions:  Read access to AD for Compare; rights to modify group membership for AddOnly, RemoveOnly and Mirror
When to use:  Onboarding a user like an existing one, checking access drift between role-mates, or access reviews.
Safety:       Read-only by default. AddOnly/RemoveOnly/Mirror change group membership (supports -WhatIf and prompts to confirm)
Version:      2.0 (parameterized; replaces the interactive menu tool; -Recursive now resolves nested groups)
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$SourceUser,
    [Parameter(Mandatory)][string[]]$DestinationUser,
    [ValidateSet('Compare', 'AddOnly', 'RemoveOnly', 'Mirror')][string]$Mode = 'Compare',
    [switch]$Recursive,
    [string[]]$ProtectedGroup = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Server Operators'),
    [string]$OutputPath,
    [string]$CustomerName
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

$script:AuditLog = [System.Collections.Generic.List[object]]::new()

function Add-AuditRecord {
    param([string]$Source, [string]$Destination, [string]$Action, [string]$Group, [string]$Status, [string]$Details = '')
    $script:AuditLog.Add([pscustomobject]@{
        Timestamp = Get-Date -Format 's'; SourceUser = $Source; DestinationUser = $Destination
        Action = $Action; Group = $Group; Status = $Status; Details = $Details
    })
}

function Get-ValidatedADUser {
    param([string]$Identity)
    try   { Get-ADUser -Identity $Identity -Properties DisplayName, SamAccountName -ErrorAction Stop }
    catch { Write-Log "User not found: $Identity" 'ERROR'; $null }
}

function ConvertTo-LdapEscaped([string]$Value) {
    $Value -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'
}

function Get-UserGroupName {
    param($User)
    if ($Recursive) {
        # LDAP_MATCHING_RULE_IN_CHAIN returns every group the user belongs to, including through nesting.
        $dn = ConvertTo-LdapEscaped $User.DistinguishedName
        $groups = Get-ADGroup -LDAPFilter "(member:1.2.840.113556.1.4.1941:=$dn)" | Select-Object -ExpandProperty Name
    }
    else {
        $groups = (Get-ADUser -Identity $User -Properties MemberOf).MemberOf | ForEach-Object {
            try { (Get-ADGroup $_).Name } catch { $null }
        }
    }
    @($groups | Where-Object { $_ } | Sort-Object)
}

$stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$csvPath = Join-Path $outDir "Compare-ADUserGroupMembership_$stamp.csv"
$script:LogFile = Join-Path $outDir "Compare-ADUserGroupMembership_$stamp.log"

try {
    $source = Get-ValidatedADUser -Identity $SourceUser
    if (-not $source) { throw "Source user '$SourceUser' not found." }
    $sourceGroups = Get-UserGroupName -User $source
    Write-Log "Source $($source.SamAccountName): $($sourceGroups.Count) group(s) ($(if ($Recursive) { 'effective' } else { 'direct' }) membership)."

    foreach ($destName in $DestinationUser) {
        $dest = Get-ValidatedADUser -Identity $destName
        if (-not $dest) { continue }
        $destGroups = Get-UserGroupName -User $dest

        $missing = @($sourceGroups | Where-Object { $_ -notin $destGroups })
        $extra   = @($destGroups   | Where-Object { $_ -notin $sourceGroups })
        $common  = @($destGroups   | Where-Object { $_ -in $sourceGroups })

        Write-Log "$($source.SamAccountName) -> $($dest.SamAccountName): missing $($missing.Count), extra $($extra.Count), shared $($common.Count)"
        foreach ($g in $missing) { Add-AuditRecord $source.SamAccountName $dest.SamAccountName 'MISSING' $g 'INFO' 'In source, not in destination' }
        foreach ($g in $extra)   { Add-AuditRecord $source.SamAccountName $dest.SamAccountName 'EXTRA'   $g 'INFO' $(if ($g -in $ProtectedGroup) { 'Not in source (protected group)' } else { 'In destination, not in source' }) }
        foreach ($g in $common)  { Add-AuditRecord $source.SamAccountName $dest.SamAccountName 'SHARED'  $g 'INFO' }

        if ($Mode -in 'AddOnly', 'Mirror') {
            foreach ($g in $missing) {
                if (-not $PSCmdlet.ShouldProcess("$($dest.SamAccountName)", "Add to group '$g'")) { continue }
                try {
                    Add-ADGroupMember -Identity $g -Members $dest.SamAccountName -ErrorAction Stop
                    Write-Log "Added $($dest.SamAccountName) to $g"
                    Add-AuditRecord $source.SamAccountName $dest.SamAccountName 'ADD' $g 'SUCCESS'
                }
                catch {
                    Write-Log "Failed adding $($dest.SamAccountName) to ${g}: $($_.Exception.Message)" 'ERROR'
                    Add-AuditRecord $source.SamAccountName $dest.SamAccountName 'ADD' $g 'FAILED' $_.Exception.Message
                }
            }
        }

        if ($Mode -in 'RemoveOnly', 'Mirror') {
            foreach ($g in $extra) {
                if ($g -in $ProtectedGroup) {
                    Write-Log "Skipping protected group: $g" 'WARN'
                    Add-AuditRecord $source.SamAccountName $dest.SamAccountName 'REMOVE' $g 'SKIPPED' 'Protected group'
                    continue
                }
                if (-not $PSCmdlet.ShouldProcess("$($dest.SamAccountName)", "Remove from group '$g'")) { continue }
                try {
                    Remove-ADGroupMember -Identity $g -Members $dest.SamAccountName -Confirm:$false -ErrorAction Stop
                    Write-Log "Removed $($dest.SamAccountName) from $g"
                    Add-AuditRecord $source.SamAccountName $dest.SamAccountName 'REMOVE' $g 'SUCCESS'
                }
                catch {
                    Write-Log "Failed removing $($dest.SamAccountName) from ${g}: $($_.Exception.Message)" 'ERROR'
                    Add-AuditRecord $source.SamAccountName $dest.SamAccountName 'REMOVE' $g 'FAILED' $_.Exception.Message
                }
            }
        }
    }

    if ($script:AuditLog.Count -gt 0) {
        $script:AuditLog | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log "Audit log written: $csvPath"
    }
}
catch {
    Write-Log "Failed: $_" 'ERROR'
    throw
}
