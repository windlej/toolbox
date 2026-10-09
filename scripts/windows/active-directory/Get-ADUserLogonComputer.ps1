#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
Finds which computers a user has authenticated from, using domain controller Security logs.

.DESCRIPTION
Queries every domain controller for Security events 4624 (logon), 4768 (Kerberos TGT) and 4769 (Kerberos
service ticket) for the given user over the last N days. Results are grouped per device with hit count, last
seen time and source IPs, and exported to CSV. IP-only entries are resolved to host names where DNS allows.

.PARAMETER User
sAMAccountName of the user to trace.

.PARAMETER Days
How many days back to search. Default 7. Large values on busy DCs can be slow, and the Security log must
still hold the events.

.PARAMETER OutputPath
Folder for the CSV. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.PARAMETER GridView
Also open the results in Out-GridView (interactive Windows sessions only).

.EXAMPLE
.\Get-ADUserLogonComputer.ps1 -User jsmith -Days 14 -OutputPath D:\Reports

.EXAMPLE
.\Get-ADUserLogonComputer.ps1 -User jsmith -OutputPath D:\Reports -CustomerName Contoso -GridView

.NOTES
Platform:     Windows (RSAT ActiveDirectory module)
Permissions:  Event Log Readers (or Domain Admin) on every domain controller
When to use:  Investigating an account lockout source, a suspected compromised account, or "where is this user logged in".
Safety:       Read-only
Version:      1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$User,
    [ValidateRange(1, 365)][int]$Days = 7,
    [string]$OutputPath,
    [string]$CustomerName,
    [switch]$GridView
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
$csvPath = Join-Path $outDir "Get-ADUserLogonComputer_$stamp.csv"
$script:LogFile = Join-Path $outDir "Get-ADUserLogonComputer_$stamp.log"

# Event filter uses milliseconds back from now.
$ms = [int64]([timespan]::FromDays($Days).TotalMilliseconds)
$safeUser = [System.Security.SecurityElement]::Escape($User)

$xml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624 or EventID=4768 or EventID=4769) and TimeCreated[timediff(@SystemTime) &lt;= $ms]]]
      and *[EventData[Data[@Name='TargetUserName']='$safeUser']]
    </Select>
  </Query>
</QueryList>
"@

try {
    $dcs = @((Get-ADDomainController -Filter *).HostName)
    Write-Log "Querying $($dcs.Count) domain controller(s) for '$User' over the last $Days day(s)..."

    $raw = foreach ($dc in $dcs) {
        try   { Get-WinEvent -ComputerName $dc -FilterXml $xml -ErrorAction Stop }
        catch {
            # "No events found" is expected on DCs the user never touched.
            if ($_.Exception.Message -match 'No events were found') { Write-Log "${dc}: no matching events" }
            else { Write-Log "${dc}: $($_.Exception.Message)" 'WARN' }
        }
    }

    $rows = foreach ($e in @($raw)) {
        $d = @{}
        ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
        $ip = "$($d['IpAddress'])" -replace '^::ffff:', ''
        [pscustomobject]@{
            Time        = $e.TimeCreated
            EventID     = $e.Id
            Workstation = $d['WorkstationName']
            IpAddress   = $ip
        }
    }

    $devices = @($rows) | ForEach-Object {
        $name = $_.Workstation
        if (-not $name -and $_.IpAddress -and $_.IpAddress -notin '-', '::1', '127.0.0.1') {
            try { $name = [System.Net.Dns]::GetHostEntry($_.IpAddress).HostName } catch { $name = $_.IpAddress }
        }
        [pscustomobject]@{ Device = $name; IpAddress = $_.IpAddress; Time = $_.Time }
    } | Where-Object Device

    $summary = @($devices) | Group-Object Device | ForEach-Object {
        [pscustomobject]@{
            Device   = $_.Name
            Hits     = $_.Count
            LastSeen = ($_.Group.Time | Sort-Object -Descending)[0]
            IPs      = ($_.Group.IpAddress | Sort-Object -Unique) -join ', '
        }
    } | Sort-Object LastSeen -Descending

    $summary | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "Found $(@($summary).Count) device(s). Report written: $csvPath"

    if ($GridView) { $summary | Out-GridView -Title "Logons for $User" }
}
catch {
    Write-Log "Search failed: $_" 'ERROR'
    throw
}
