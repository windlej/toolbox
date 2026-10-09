#Requires -Version 5.1

<#
.SYNOPSIS
Creates a folder of random files, some duplicated, for testing Get-DiskUsageAudit.ps1.

.DESCRIPTION
Generates random binary files of random size, and makes copies of some of them (named *_copy1, *_copy2) plus
a few re-used names, so the largest-file and duplicate detection can be tested without touching real data.

.PARAMETER OutputPath
Folder to fill with test files. Created if missing. Use a scratch location, never a customer share.

.PARAMETER FileCount
Number of base files. Default 50.

.PARAMETER MaxCopiesPerFile
Maximum copies per base file. Default 3.

.PARAMETER MaxSizeKB
Largest file size in KB. Default 1024.

.EXAMPLE
.\New-TestFileSet.ps1 -OutputPath D:\Scratch\TestFiles

.EXAMPLE
.\New-TestFileSet.ps1 -OutputPath D:\Scratch\TestFiles -FileCount 200 -MaxSizeKB 4096

.NOTES
Platform:     Windows (works on macOS with PowerShell 7)
Permissions:  Write access to the output folder
When to use:  Testing or demonstrating the disk audit script.
Safety:       Changes data (creates files in -OutputPath only; supports -WhatIf)
Version:      1.0
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$OutputPath,
    [ValidateRange(1, 100000)][int]$FileCount = 50,
    [ValidateRange(1, 20)][int]$MaxCopiesPerFile = 3,
    [ValidateRange(2, 1048576)][int]$MaxSizeKB = 1024
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$chars      = 'abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()
$extensions = '.txt', '.bin', '.dat', '.log'
$rng        = [System.Random]::new()
$generated  = [System.Collections.Generic.List[string]]::new()

function Get-RandomFileName {
    $name = -join (1..12 | ForEach-Object { $chars | Get-Random })
    '{0}{1}' -f $name, (Get-Random -InputObject $extensions)
}

for ($i = 0; $i -lt $FileCount; $i++) {
    # ~20% of the time reuse an earlier name so Name-based duplicate detection has something to find.
    if ($generated.Count -gt 0 -and (Get-Random -Minimum 1 -Maximum 101) -le 20) { $fileName = $generated | Get-Random }
    else { $fileName = Get-RandomFileName; $generated.Add($fileName) }

    $filePath = Join-Path $OutputPath $fileName
    if (-not $PSCmdlet.ShouldProcess($filePath, 'Create random file')) { continue }

    $bytes = New-Object byte[] ((Get-Random -Minimum 1 -Maximum $MaxSizeKB) * 1024)
    $rng.NextBytes($bytes)
    [System.IO.File]::WriteAllBytes($filePath, $bytes)

    $copies = Get-Random -Minimum 1 -Maximum ($MaxCopiesPerFile + 1)
    for ($c = 1; $c -lt $copies; $c++) {
        $copyName = '{0}_copy{1}{2}' -f [System.IO.Path]::GetFileNameWithoutExtension($fileName), $c, [System.IO.Path]::GetExtension($fileName)
        Copy-Item -LiteralPath $filePath -Destination (Join-Path $OutputPath $copyName) -Force
    }
}

Write-Host "Test files created in: $OutputPath"
