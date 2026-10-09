#Requires -Version 5.1

<#
.SYNOPSIS
Generates docs/CATALOG.md and docs/scripts/<Name>.md from script headers.

.DESCRIPTION
Reads the comment-based help of every PowerShell script under scripts/windows (AST only, nothing is run) and
the header block of bash and Python scripts under scripts/network and scripts/python, then writes a catalog
table plus one page per script (synopsis, when to use, permissions, safety, parameters, examples).
Generated files are overwritten; do not edit them by hand.

.PARAMETER RepoRoot
Repository root. Defaults to the parent of this script's folder.

.EXAMPLE
pwsh ./tools/Build-Catalog.ps1

.EXAMPLE
pwsh ./tools/Build-Catalog.ps1 -RepoRoot ~/work/toolbox

.NOTES
Platform:     Windows or macOS (PowerShell 7 recommended)
Permissions:  Write access to the docs folder
When to use:  After adding or editing any script header, before committing.
Safety:       Changes data (overwrites generated docs only)
Version:      1.0
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-Cell([string]$Text) {
    # Table cells: escape pipes and angle brackets so they do not break the table or render as HTML.
    ($Text -replace '\|', '\|' -replace '<', '&lt;' -replace '>', '&gt;')
}

function Get-NoteValue([string]$Notes, [string]$Label) {
    if (-not $Notes) { return '' }
    $m = [regex]::Match($Notes, "(?im)^\s*$([regex]::Escape($Label))\s*(.+?)\s*$")
    if ($m.Success) { $m.Groups[1].Value } else { '' }
}

function Get-ForeignHeader([string]$FilePath) {
    # Header for bash/python: leading comment lines (# ...) or a docstring with "Label: value" lines.
    $lines = Get-Content -LiteralPath $FilePath -TotalCount 40
    [pscustomobject]@{
        Notes = ($lines | ForEach-Object { $_ -replace '^\s*#\s?', '' }) -join "`n"
    }
}

$docsDir    = Join-Path $RepoRoot 'docs'
$pagesDir   = Join-Path $docsDir 'scripts'
$null = New-Item -ItemType Directory -Path $pagesDir -Force
Get-ChildItem -LiteralPath $pagesDir -Filter *.md -File | Remove-Item -Force

$entries = [System.Collections.Generic.List[object]]::new()

# PowerShell
$psRoot = Join-Path (Join-Path $RepoRoot 'scripts') 'windows'
if (Test-Path -LiteralPath $psRoot) {
    foreach ($file in Get-ChildItem -LiteralPath $psRoot -Filter *.ps1 -Recurse -File | Sort-Object FullName) {
        $tokens = $null; $errors = $null
        $ast  = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
        $help = $ast.GetHelpContent()
        $params = @()
        if ($ast.ParamBlock) {
            foreach ($p in $ast.ParamBlock.Parameters) {
                $name = $p.Name.VariablePath.UserPath
                $desc = ''
                if ($help -and $help.Parameters) {
                    $key = $help.Parameters.Keys | Where-Object { $_ -ieq $name } | Select-Object -First 1
                    if ($key) { $desc = ($help.Parameters[$key] -replace '\s*\r?\n\s*', ' ').Trim() }
                }
                $mandatory = [bool]($p.Attributes | Where-Object {
                    $_ -is [System.Management.Automation.Language.AttributeAst] -and $_.TypeName.Name -eq 'Parameter' -and
                    ($_.NamedArguments | Where-Object { $_.ArgumentName -eq 'Mandatory' -and $_.Argument.Extent.Text -ne '$false' })
                })
                $params += [pscustomobject]@{ Name = $name; Type = $p.StaticType.Name; Mandatory = $mandatory; Description = $desc }
            }
        }
        $entries.Add([pscustomobject]@{
            Name        = [IO.Path]::GetFileNameWithoutExtension($file.Name)
            Kind        = 'PowerShell'
            Category    = Split-Path (Split-Path $file.FullName -Parent) -Leaf
            RelPath     = ($file.FullName.Substring($RepoRoot.Length).TrimStart('\', '/') -replace '\\', '/')
            Synopsis    = if ($help) { ($help.Synopsis -replace '\s*\r?\n\s*', ' ').Trim() } else { '' }
            Description = if ($help) { $help.Description.Trim() } else { '' }
            Platform    = Get-NoteValue $help.Notes 'Platform:'
            Permissions = Get-NoteValue $help.Notes 'Permissions:'
            WhenToUse   = Get-NoteValue $help.Notes 'When to use:'
            Safety      = Get-NoteValue $help.Notes 'Safety:'
            Parameters  = $params
            Examples    = @($help.Examples)
        })
    }
}

# bash / python
foreach ($sub in 'network', 'python') {
    $dir = Join-Path (Join-Path $RepoRoot 'scripts') $sub
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    foreach ($file in Get-ChildItem -LiteralPath $dir -Include *.sh, *.py -Recurse -File | Sort-Object FullName) {
        $h = Get-ForeignHeader $file.FullName
        $entries.Add([pscustomobject]@{
            Name        = $file.Name
            Kind        = if ($file.Extension -eq '.sh') { 'bash' } else { 'Python' }
            Category    = $sub
            RelPath     = ($file.FullName.Substring($RepoRoot.Length).TrimStart('\', '/') -replace '\\', '/')
            Synopsis    = (Get-NoteValue $h.Notes 'Synopsis:')
            Description = ''
            Platform    = (Get-NoteValue $h.Notes 'Platform:')
            Permissions = (Get-NoteValue $h.Notes 'Permissions:')
            WhenToUse   = (Get-NoteValue $h.Notes 'When to use:')
            Safety      = (Get-NoteValue $h.Notes 'Safety:')
            Parameters  = @()
            Examples    = @()
        })
    }
}

# Per-script pages
foreach ($e in $entries) {
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# $($e.Name)")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('<!-- Generated by tools/Build-Catalog.ps1. Edit the script header, not this file. -->')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine($e.Synopsis)
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("| | |`n|---|---|")
    [void]$sb.AppendLine("| Location | ``$($e.RelPath)`` |")
    [void]$sb.AppendLine("| Platform | $(ConvertTo-Cell $e.Platform) |")
    [void]$sb.AppendLine("| Permissions | $(ConvertTo-Cell $e.Permissions) |")
    [void]$sb.AppendLine("| Safety | $(ConvertTo-Cell $e.Safety) |")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('## When to use')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine($e.WhenToUse)
    if ($e.Description) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('## Description')
        [void]$sb.AppendLine()
        [void]$sb.AppendLine($e.Description)
    }
    if ($e.Parameters.Count -gt 0) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('## Parameters')
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("| Name | Type | Required | Description |`n|---|---|---|---|")
        foreach ($p in $e.Parameters) {
            [void]$sb.AppendLine("| ``-$($p.Name)`` | $($p.Type) | $(if ($p.Mandatory) { 'Yes' } else { 'No' }) | $(ConvertTo-Cell $p.Description) |")
        }
    }
    if ($e.Examples.Count -gt 0) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('## Examples')
        foreach ($ex in $e.Examples) {
            [void]$sb.AppendLine()
            [void]$sb.AppendLine('```powershell')
            [void]$sb.AppendLine($ex.Trim())
            [void]$sb.AppendLine('```')
        }
    }
    $pageName = ([IO.Path]::GetFileNameWithoutExtension($e.Name)) + $(if ($e.Kind -eq 'PowerShell') { '' } else { "-$($e.Kind.ToLower())" })
    Set-Content -LiteralPath (Join-Path $pagesDir "$pageName.md") -Value $sb.ToString() -Encoding UTF8
}

# Catalog
$cat = [System.Text.StringBuilder]::new()
[void]$cat.AppendLine('# Script Catalog')
[void]$cat.AppendLine()
[void]$cat.AppendLine('<!-- Generated by tools/Build-Catalog.ps1. Edit the script header, not this file. -->')
foreach ($group in $entries | Group-Object { "$($_.Kind)|$($_.Category)" } | Sort-Object Name) {
    $first = $group.Group[0]
    [void]$cat.AppendLine()
    [void]$cat.AppendLine("## $($first.Kind): $($first.Category)")
    [void]$cat.AppendLine()
    [void]$cat.AppendLine("| Script | What it does | When to use | Safety |`n|---|---|---|---|")
    foreach ($e in $group.Group | Sort-Object Name) {
        $pageName = ([IO.Path]::GetFileNameWithoutExtension($e.Name)) + $(if ($e.Kind -eq 'PowerShell') { '' } else { "-$($e.Kind.ToLower())" })
        [void]$cat.AppendLine("| [$($e.Name)](scripts/$pageName.md) | $($e.Synopsis) | $($e.WhenToUse) | $(ConvertTo-Cell $e.Safety) |")
    }
}
Set-Content -LiteralPath (Join-Path $docsDir 'CATALOG.md') -Value $cat.ToString() -Encoding UTF8
Write-Host "Catalog written: $($entries.Count) script(s)."
