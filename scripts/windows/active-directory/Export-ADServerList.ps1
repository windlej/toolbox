#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
Exports enabled Windows Server computer accounts from AD as a CSV for Devolutions RDM.

.DESCRIPTION
Lists every enabled computer object whose operating system contains "Server", builds an FQDN (DNSHostName,
or Name plus the domain's DNS root as a fallback), and writes a CSV with the columns Name, Host and Entry type
that the RDM Generic CSV import wizard accepts.

.PARAMETER OutputPath
Folder for the CSV. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER EntryType
RDM entry type for each row. Default "Session".

.EXAMPLE
.\Export-ADServerList.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Export-ADServerList.ps1 -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (RSAT ActiveDirectory module)
Permissions:  Domain user (read access to computer objects)
When to use:  Onboarding a new customer into your RDM, or refreshing server entries after changes.
Safety:       Read-only
Version:      1.0
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$CustomerName,
    [string]$EntryType = 'Session'
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

$stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$csvPath = Join-Path $outDir "Export-ADServerList_$stamp.csv"
$script:LogFile = Join-Path $outDir "Export-ADServerList_$stamp.log"

try {
    $domainDnsRoot = (Get-ADDomain).DNSRoot

    $servers = @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties DNSHostName, OperatingSystem |
        Where-Object { $_.OperatingSystem -like '*Server*' } |
        Sort-Object Name |
        ForEach-Object {
            $fqdn = if ([string]::IsNullOrWhiteSpace($_.DNSHostName)) { "$($_.Name).$domainDnsRoot" } else { $_.DNSHostName }
            [pscustomobject]@{
                'Name'       = $_.Name
                'Host'       = $fqdn
                'Entry type' = $EntryType
            }
        })

    $servers | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "Exported $($servers.Count) server(s): $csvPath"
}
catch {
    Write-Log "Export failed: $_" 'ERROR'
    throw
}
