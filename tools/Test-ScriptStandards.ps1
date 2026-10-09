#Requires -Version 5.1

<#
.SYNOPSIS
Checks toolbox scripts against docs/DESIGN-GUIDE.md.

.DESCRIPTION
Parses every .ps1 under scripts/windows (AST only, nothing is executed) and reports violations of the
mechanical rules: Verb-Noun naming, help header labels, -OutputPath handling, hardcoded customer-looking
values, Read-Host and custom -WhatIf switches. Exits 1 if any ERROR is found.

.PARAMETER Path
Folder or file to check. Defaults to scripts/windows in this repo.

.PARAMETER Strict
Treat WARN findings as errors.

.EXAMPLE
pwsh ./tools/Test-ScriptStandards.ps1

.EXAMPLE
pwsh ./tools/Test-ScriptStandards.ps1 -Path ./scripts/windows/m365 -Strict

.NOTES
Platform:     Windows or macOS (PowerShell 7 recommended)
Permissions:  None
When to use:  Before committing a new or edited script, and in CI.
Safety:       Read-only
Version:      1.0
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts') 'windows'),
    [switch]$Strict
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$approvedVerbs = (Get-Verb).Verb
$requiredNotes = 'Platform:', 'Permissions:', 'When to use:', 'Safety:'
$writesFiles   = 'Export-Csv|Out-File|Set-Content|Add-Content|Export-Clixml|Export-Excel|\.Save\('

# Patterns that suggest customer or environment data baked into a script.
$hardcoded = @(
    @{ Name = 'hardcoded drive path'; Regex = '(?i)["''](?:[A-Z]):\\(?:Temp|Scripts|Reports|Logs|Users)\\' }
    @{ Name = 'IPv4 address';         Regex = '\b(?!(?:0\.0\.0\.0|127\.0\.0\.1|192\.0\.2\.\d+|198\.51\.100\.\d+|203\.0\.113\.\d+)\b)(?:\d{1,3}\.){3}\d{1,3}\b' }
    @{ Name = 'onmicrosoft tenant';   Regex = '(?i)\b(?!contoso\b|fabrikam\b)[a-z0-9-]+\.onmicrosoft\.com' }
    @{ Name = 'yourdomain placeholder'; Regex = '(?i)yourdomain\.com' }
)

$files = if (Test-Path -LiteralPath $Path -PathType Leaf) { Get-Item -LiteralPath $Path }
         else { Get-ChildItem -LiteralPath $Path -Filter *.ps1 -Recurse -File }

$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding([string]$Level, [string]$File, [string]$Message) {
    $findings.Add([pscustomobject]@{ Level = $Level; File = $File; Message = $Message })
}

foreach ($file in $files) {
    $rel  = $file.FullName
    $base = [IO.Path]::GetFileNameWithoutExtension($file.Name)

    # Naming
    if ($base -notmatch '^([A-Z][a-z]+)-([A-Z][A-Za-z0-9]+)$') {
        Add-Finding 'ERROR' $rel "Name '$base' is not Verb-Noun PascalCase."
    }
    elseif ($approvedVerbs -notcontains $Matches[1]) {
        Add-Finding 'ERROR' $rel "'$($Matches[1])' is not an approved verb (see Get-Verb)."
    }

    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        Add-Finding 'ERROR' $rel "Parse error: $($errors[0].Message) (line $($errors[0].Extent.StartLineNumber))"
        continue
    }
    $text = Get-Content -LiteralPath $file.FullName -Raw

    # Help header
    $help = $ast.GetHelpContent()
    if (-not $help -or [string]::IsNullOrWhiteSpace($help.Synopsis)) {
        Add-Finding 'ERROR' $rel 'Missing comment-based help (.SYNOPSIS).'
    }
    else {
        if ([string]::IsNullOrWhiteSpace($help.Description)) { Add-Finding 'ERROR' $rel 'Missing .DESCRIPTION.' }
        if (-not $help.Examples -or @($help.Examples).Count -lt 2) { Add-Finding 'ERROR' $rel 'Needs at least 2 .EXAMPLE blocks.' }
        foreach ($label in $requiredNotes) {
            if (-not $help.Notes -or $help.Notes -notmatch [regex]::Escape($label)) {
                Add-Finding 'ERROR' $rel ".NOTES is missing '$label'."
            }
        }
    }

    # Script-level structure
    if ($text -notmatch '(?m)^\s*#Requires\b')               { Add-Finding 'WARN' $rel 'No #Requires statement.' }
    if ($text -notmatch '\[CmdletBinding')                    { Add-Finding 'WARN' $rel 'No [CmdletBinding()].' }
    if ($text -notmatch 'Set-StrictMode')                     { Add-Finding 'WARN' $rel 'No Set-StrictMode.' }

    $paramNames = @()
    if ($ast.ParamBlock) { $paramNames = $ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath } }

    # Output handling
    if ($text -match $writesFiles) {
        if ($paramNames -notcontains 'OutputPath')           { Add-Finding 'ERROR' $rel 'Writes files but has no -OutputPath parameter.' }
        if ($text -notmatch 'function\s+Resolve-OutputPath') { Add-Finding 'ERROR' $rel 'Missing the standard Resolve-OutputPath function.' }
    }

    # Custom WhatIf switch / Read-Host
    if ($paramNames -contains 'WhatIf')                      { Add-Finding 'ERROR' $rel 'Defines its own -WhatIf; use SupportsShouldProcess.' }
    $readHosts = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Read-Host' }, $true)
    foreach ($rh in $readHosts) {
        $fn = $rh.Parent
        while ($fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
        if (-not $fn -or $fn.Name -ne 'Resolve-OutputPath') {
            Add-Finding 'WARN' $rel "Read-Host at line $($rh.Extent.StartLineNumber); use a parameter instead."
        }
    }

    # Hardcoded values (skip help comments by checking only non-comment tokens)
    foreach ($tok in $tokens) {
        if ($tok.Kind -eq 'Comment') { continue }
        foreach ($pat in $hardcoded) {
            if ($tok.Text -match $pat.Regex) {
                Add-Finding 'WARN' $rel "Possible $($pat.Name) at line $($tok.Extent.StartLineNumber): $($tok.Text.Trim())"
            }
        }
    }
}

$findings | Sort-Object File, Level | Format-Table Level, @{ n = 'File'; e = { Split-Path $_.File -Leaf } }, Message -AutoSize -Wrap

$errorCount = @($findings | Where-Object { $_.Level -eq 'ERROR' -or ($Strict -and $_.Level -eq 'WARN') }).Count
Write-Host ("Checked {0} script(s): {1} error(s), {2} warning(s)." -f @($files).Count,
    @($findings | Where-Object Level -eq 'ERROR').Count, @($findings | Where-Object Level -eq 'WARN').Count)
if ($errorCount -gt 0) { exit 1 }
