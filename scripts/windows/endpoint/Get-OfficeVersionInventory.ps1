#Requires -Version 5.1

<#
.SYNOPSIS
Inventories the Microsoft Office Click-to-Run version on remote Windows computers.

.DESCRIPTION
Connects with PowerShell remoting to each target computer, reads the Office Click-to-Run configuration key
(ProductReleaseIds, Platform, VersionToReport) and exports one CSV row per computer. Computers that can't be
reached are recorded as "Offline/Error" instead of stopping the run. A summary by product is printed at the end.

By default the target list is every computer in Active Directory (needs the ActiveDirectory module);
pass -ComputerName to scan a specific list instead.

.PARAMETER ComputerName
Computers to scan. If omitted, all AD computer accounts are used.

.PARAMETER Credential
Optional credential for remoting.

.PARAMETER OutputPath
Folder for the CSV. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.EXAMPLE
.\Get-OfficeVersionInventory.ps1 -OutputPath D:\Reports

.EXAMPLE
.\Get-OfficeVersionInventory.ps1 -ComputerName PC01, PC02 -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (PowerShell remoting enabled on targets; RSAT ActiveDirectory if -ComputerName is omitted)
Permissions:  Local administrator on the target computers (typically Domain Admin)
When to use:  Checking Office update channels/versions before a patching or licensing project.
Safety:       Read-only
Version:      1.1 (fixed a truncated Invoke-Command in the original)
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [pscredential]$Credential,
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

$stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$csvPath = Join-Path $outDir "Get-OfficeVersionInventory_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-OfficeVersionInventory_$stamp.log"

if (-not $ComputerName) {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'Provide -ComputerName, or install RSAT ActiveDirectory to scan all AD computers.'
    }
    Import-Module ActiveDirectory
    $ComputerName = Get-ADComputer -Filter * | Sort-Object Name | Select-Object -ExpandProperty Name
}

$probe = {
    $key = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    if (Test-Path $key) {
        $office = Get-ItemProperty $key
        [pscustomobject]@{
            ProductReleaseIds = $office.ProductReleaseIds
            Platform          = $office.Platform
            Version           = $office.VersionToReport
        }
    }
    else {
        [pscustomobject]@{ ProductReleaseIds = 'No ClickToRun'; Platform = ''; Version = '' }
    }
}

$results = [System.Collections.Generic.List[object]]::new()
$total = @($ComputerName).Count

for ($i = 0; $i -lt $total; $i++) {
    $computer = $ComputerName[$i]
    Write-Progress -Activity 'Office inventory' -Status "Checking $computer ($($i + 1) of $total)" -PercentComplete ((($i + 1) / $total) * 100)

    try {
        $invoke = @{ ComputerName = $computer; ScriptBlock = $probe; ErrorAction = 'Stop' }
        if ($Credential) { $invoke.Credential = $Credential }
        $info = Invoke-Command @invoke
        $results.Add([pscustomobject]@{
            ComputerName      = $computer
            Status            = 'Online'
            ProductReleaseIds = $info.ProductReleaseIds
            Platform          = $info.Platform
            Version           = $info.Version
        })
    }
    catch {
        Write-Log "${computer}: $($_.Exception.Message)" 'WARN'
        $results.Add([pscustomobject]@{
            ComputerName = $computer; Status = 'Offline/Error'; ProductReleaseIds = ''; Platform = ''; Version = ''
        })
    }
}
Write-Progress -Activity 'Office inventory' -Completed

$results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
Write-Log "Report written: $csvPath ($total computer(s))"

$results | Group-Object ProductReleaseIds | Sort-Object Count -Descending |
    Select-Object Count, Name | Format-Table -AutoSize
