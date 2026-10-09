#Requires -Version 5.1

<#
.SYNOPSIS
Finds the largest files and duplicate files under a local or UNC path (audit only).

.DESCRIPTION
Scans a folder tree and reports:
  - the N largest files
  - duplicate files, detected by Name, Name+Size, or SHA256 hash (hash mode groups by size first, and hashes in
    parallel on PowerShell 7+)

Both results are exported to CSV. This script never deletes, moves, or modifies the files it scans.

.PARAMETER ScanPath
Folder to scan: a drive root, folder, or UNC path. Default is the system drive root.

.PARAMETER Mode
What to report: Largest, Duplicates, or Both (default).

.PARAMETER MinFileSizeKB
Ignore files smaller than this. Default 1.

.PARAMETER SkipExtension
File extensions to ignore. Default .iso, .zip, .log

.PARAMETER TopLargestCount
How many largest files to report. Default 25.

.PARAMETER DuplicateMode
Name, NameSize (default) or Hash. Hash is the most accurate and the slowest.

.PARAMETER ParallelThrottle
Concurrent hashing threads (PowerShell 7+ only). Default 8.

.PARAMETER OutputPath
Folder for CSV reports. Falls back to $env:TOOLBOX_REPORT_DIR, then prompts.

.PARAMETER CustomerName
Optional. Adds a <OutputPath>\<CustomerName> subfolder.

.EXAMPLE
.\Get-DiskUsageAudit.ps1 -ScanPath D:\ -Mode Largest -OutputPath D:\Reports

.EXAMPLE
.\Get-DiskUsageAudit.ps1 -ScanPath \\fileserver\shares -Mode Duplicates -DuplicateMode Hash -OutputPath D:\Reports -CustomerName Contoso

.NOTES
Platform:     Windows (PowerShell 5.1+; 7+ for parallel hashing)
Permissions:  Read access to the scanned path (local administrator to see all system folders)
When to use:  A volume is filling up and you need to see what is taking space, or to find duplicate data before a migration.
Safety:       Read-only
Version:      2.0 (parameterized; replaces the interactive menu tool)
#>
[CmdletBinding()]
param(
    [string]$ScanPath = [System.IO.Path]::GetPathRoot($env:SystemRoot),
    [ValidateSet('Largest', 'Duplicates', 'Both')][string]$Mode = 'Both',
    [ValidateRange(0, [int]::MaxValue)][int]$MinFileSizeKB = 1,
    [string[]]$SkipExtension = @('.iso', '.zip', '.log'),
    [ValidateRange(1, 10000)][int]$TopLargestCount = 25,
    [ValidateSet('Name', 'NameSize', 'Hash')][string]$DuplicateMode = 'NameSize',
    [ValidateRange(1, 64)][int]$ParallelThrottle = 8,
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

function Format-FileSize {
    param([Int64]$Bytes)
    switch ($Bytes) {
        { $_ -ge 1TB } { return '{0:N2} TB' -f ($Bytes / 1TB) }
        { $_ -ge 1GB } { return '{0:N2} GB' -f ($Bytes / 1GB) }
        { $_ -ge 1MB } { return '{0:N2} MB' -f ($Bytes / 1MB) }
        { $_ -ge 1KB } { return '{0:N2} KB' -f ($Bytes / 1KB) }
        default        { return "$Bytes Bytes" }
    }
}

function Get-FilteredFile {
    $minBytes = [int64]$MinFileSizeKB * 1KB
    $skip = $SkipExtension | ForEach-Object { $_.ToLowerInvariant() }
    $files = [System.Collections.Generic.List[object]]::new()
    $counter = 0

    Write-Log "Scanning $ScanPath ..."
    # Inaccessible folders are expected during a recursive scan; they are skipped, not fatal.
    Get-ChildItem -LiteralPath $ScanPath -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $counter++
        if (($counter % 500) -eq 0) {
            Write-Progress -Activity 'Scanning filesystem' -Status "$counter files scanned..." -PercentComplete -1
        }
        if ($_.Length -lt $minBytes) { return }
        if ($skip -contains $_.Extension.ToLowerInvariant()) { return }
        $files.Add($_)
    }
    Write-Progress -Activity 'Scanning filesystem' -Completed
    Write-Log "Files collected: $($files.Count) (of $counter scanned)"
    , $files
}

function Get-FileHashSafe {
    param([string]$Path)
    try   { (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash }
    catch { Write-Log "Hash failed: $Path" 'WARN'; $null }
}

function Get-LargestFile {
    param([object[]]$Files)
    $Files | Sort-Object Length -Descending | Select-Object -First $TopLargestCount | ForEach-Object {
        [pscustomobject]@{
            FileName     = $_.Name
            SizeBytes    = $_.Length
            SizeReadable = Format-FileSize $_.Length
            Path         = $_.FullName
        }
    }
}

function Find-DuplicateFile {
    param([object[]]$Files)

    $results = [System.Collections.Generic.List[object]]::new()
    $addGroup = {
        param($method, $group, $hash)
        foreach ($file in $group.Group) {
            $results.Add([pscustomobject]@{
                Method       = $method
                DuplicateKey = $group.Name
                FileName     = $file.Name
                SizeBytes    = $file.Length
                SizeReadable = Format-FileSize $file.Length
                Hash         = $hash
                Path         = $file.FullName
            })
        }
    }

    switch ($DuplicateMode) {
        'Name' {
            foreach ($g in ($Files | Group-Object Name | Where-Object Count -gt 1)) { & $addGroup 'Name' $g $null }
        }
        'NameSize' {
            $groups = $Files | Group-Object -Property { "$($_.Name.ToLowerInvariant())|$($_.Length)" } | Where-Object Count -gt 1
            foreach ($g in $groups) { & $addGroup 'Name+Size' $g $null }
        }
        'Hash' {
            # Only files that share a size can be identical, so hash just those.
            $candidates = @($Files | Group-Object Length | Where-Object Count -gt 1 | ForEach-Object { $_.Group })
            Write-Log "Hash mode: $($candidates.Count) candidate file(s) share a size with another file."

            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $throttle = $ParallelThrottle
                $hashed = $candidates | ForEach-Object -Parallel {
                    try {
                        [pscustomobject]@{
                            Name = $_.Name; Path = $_.FullName; Length = $_.Length
                            Hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                        }
                    } catch { $null }
                } -ThrottleLimit $throttle
            }
            else {
                $i = 0
                $hashed = foreach ($file in $candidates) {
                    $i++
                    Write-Progress -Activity 'Hashing files' -Status "$i / $($candidates.Count)" -PercentComplete (($i / $candidates.Count) * 100)
                    $h = Get-FileHashSafe -Path $file.FullName
                    if ($h) { [pscustomobject]@{ Name = $file.Name; Path = $file.FullName; Length = $file.Length; Hash = $h } }
                }
                Write-Progress -Activity 'Hashing files' -Completed
            }

            $dupes = @($hashed) | Where-Object { $_ } | Group-Object Hash | Where-Object { $_.Count -gt 1 -and $_.Name }
            foreach ($g in $dupes) {
                foreach ($f in $g.Group) {
                    $results.Add([pscustomobject]@{
                        Method = 'SHA256'; DuplicateKey = $g.Name; FileName = $f.Name; SizeBytes = $f.Length
                        SizeReadable = Format-FileSize $f.Length; Hash = $f.Hash; Path = $f.Path
                    })
                }
            }
        }
    }
    $results
}

$stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir = Resolve-OutputPath -Path $OutputPath -CustomerName $CustomerName
$script:LogFile = Join-Path $outDir "Get-DiskUsageAudit_$stamp.log"

try {
    if (-not (Test-Path -LiteralPath $ScanPath)) { throw "Scan path not found: $ScanPath" }

    $files = Get-FilteredFile
    if ($files.Count -eq 0) { Write-Log 'No files matched the filters.' 'WARN'; return }

    if ($Mode -in 'Largest', 'Both') {
        $largest = @(Get-LargestFile -Files $files)
        $path = Join-Path $outDir "Get-DiskUsageAudit_Largest_$stamp.csv"
        $largest | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
        Write-Log "Largest files: $($largest.Count) row(s) -> $path"
        $largest | Format-Table FileName, SizeReadable, Path -AutoSize
    }

    if ($Mode -in 'Duplicates', 'Both') {
        $dupes = @(Find-DuplicateFile -Files $files)
        if ($dupes.Count -eq 0) { Write-Log 'No duplicates found.' }
        else {
            $path = Join-Path $outDir "Get-DiskUsageAudit_Duplicates_$stamp.csv"
            $dupes | Sort-Object DuplicateKey | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
            Write-Log "Duplicate files: $($dupes.Count) row(s) -> $path"
        }
    }
}
catch {
    Write-Log "Audit failed: $_" 'ERROR'
    throw
}
