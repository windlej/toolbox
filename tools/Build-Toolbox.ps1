#Requires -Version 5.1

<#
.SYNOPSIS
Builds dist/toolbox.ps1: one self-contained file holding every script plus its description, for machines without the repo.

.DESCRIPTION
Reads the header of every script under scripts/ (PowerShell comment-based help via the AST, bash and Python
header comments), then writes tools/Toolbox.template.ps1 to dist/toolbox.ps1 with the library embedded in it.
Each script is stored gzip-compressed and base64-encoded, so nothing in a script can break the bundle. Nothing
is run. Copy the one resulting file to a jumpbox; it needs no repository, modules or internet access.
The output is ASCII only and saved with a UTF-8 BOM so Windows PowerShell 5.1 reads it correctly.

.PARAMETER RepoRoot
Repository root. Defaults to the parent of this script's folder.

.PARAMETER OutputPath
Where to write the bundle. Default: <RepoRoot>/dist/toolbox.ps1.

.EXAMPLE
pwsh ./tools/Build-Toolbox.ps1

.EXAMPLE
pwsh ./tools/Build-Toolbox.ps1 -OutputPath D:\Jumpbox\toolbox.ps1

.NOTES
Platform:     Windows or macOS (PowerShell 7 recommended)
Permissions:  Write access to the output folder
When to use:  After adding or editing a script or its header, before staging the bundle on the jumpboxes.
Safety:       Changes data (overwrites the bundle file only)
Version:      1.0
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $OutputPath) { $OutputPath = Join-Path (Join-Path $RepoRoot 'dist') 'toolbox.ps1' }

$categoryNames = @{
    'm365'              = 'Microsoft 365 / Identity'
    'exchange'          = 'Exchange Online'
    'azure'             = 'Azure / Cloud'
    'active-directory'  = 'Active Directory'
    'server'            = 'Windows Server'
    'endpoint'          = 'Endpoint / Workstation'
    'security'          = 'Security'
    'network'           = 'Network (bash)'
    'python-automation' = 'Python / Automation'
    'python-networking' = 'Python / Networking'
}

function Get-NoteValue([string]$Notes, [string]$Label) {
    if (-not $Notes) { return '' }
    $m = [regex]::Match($Notes, "(?im)^\s*$([regex]::Escape($Label))\s*(.+?)\s*$")
    if ($m.Success) { $m.Groups[1].Value } else { '' }
}

function ConvertTo-OneLine([string]$Text) { ($Text -replace '\s*\r?\n\s*', ' ').Trim() }

function ConvertTo-Literal([string]$Text) {
    # Single-quoted PowerShell string. Anything outside printable ASCII becomes a [char] concatenation so the
    # bundle stays ASCII.
    $sb = [System.Text.StringBuilder]::new()
    $inQuote = $false
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($ch in $Text.ToCharArray()) {
        if ([int]$ch -ge 32 -and [int]$ch -le 126) {
            if (-not $inQuote) { [void]$sb.Clear(); $inQuote = $true }
            if ($ch -eq "'") { [void]$sb.Append("''") } else { [void]$sb.Append($ch) }
        } else {
            if ($inQuote) { $parts.Add("'" + $sb.ToString() + "'"); $inQuote = $false }
            $parts.Add("[string][char]$([int]$ch)")
        }
    }
    if ($inQuote) { $parts.Add("'" + $sb.ToString() + "'") }
    if ($parts.Count -eq 0) { return "''" }
    if ($parts.Count -eq 1) { return $parts[0] }
    return '(' + ($parts -join ' + ') + ')'
}

function ConvertTo-Packed([string]$Text) {
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
    $ms = [System.IO.MemoryStream]::new()
    $gz = [System.IO.Compression.GZipStream]::new($ms, [System.IO.Compression.CompressionMode]::Compress)
    $gz.Write($bytes, 0, $bytes.Length)
    $gz.Dispose()
    [Convert]::ToBase64String($ms.ToArray())
}

$scriptsRoot = Join-Path $RepoRoot 'scripts'
$entries = [System.Collections.Generic.List[object]]::new()

# PowerShell scripts: one category per folder under scripts/windows.
$psRoot = Join-Path $scriptsRoot 'windows'
if (Test-Path -LiteralPath $psRoot) {
    foreach ($file in Get-ChildItem -LiteralPath $psRoot -Filter *.ps1 -Recurse -File | Sort-Object FullName) {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
        if ($errors) { throw "Parse error in $($file.FullName): $($errors[0].Message)" }
        $help = $ast.GetHelpContent()
        if (-not $help) { throw "No comment-based help in $($file.FullName)" }

        $params = @()
        if ($ast.ParamBlock) {
            foreach ($p in $ast.ParamBlock.Parameters) {
                $pname = $p.Name.VariablePath.UserPath
                $mandatory = [bool]($p.Attributes | Where-Object {
                    $_ -is [System.Management.Automation.Language.AttributeAst] -and $_.TypeName.Name -eq 'Parameter' -and
                    ($_.NamedArguments | Where-Object { $_.ArgumentName -eq 'Mandatory' -and $_.Argument.Extent.Text -ne '$false' })
                })
                $params += "-$pname$(if ($mandatory) { ' (required)' })"
            }
        }

        $modules = @()
        $admin = $false
        if ($ast.ScriptRequirements) {
            $modules = @($ast.ScriptRequirements.RequiredModules | ForEach-Object { $_.Name } | Where-Object { $_ })
            $admin = [bool]$ast.ScriptRequirements.IsElevationRequired
        }
        $example = ''
        if ($help.Examples -and $help.Examples.Count -gt 0) { $example = (($help.Examples[0].Trim() -split '\r?\n')[0]).Trim() }

        $key = Split-Path (Split-Path $file.FullName -Parent) -Leaf
        $entries.Add([pscustomobject]@{
            File = $file; Key = $key; Kind = 'PowerShell'
            Synopsis = ConvertTo-OneLine $help.Synopsis
            When = Get-NoteValue $help.Notes 'When to use:'
            Perms = Get-NoteValue $help.Notes 'Permissions:'
            Safety = Get-NoteValue $help.Notes 'Safety:'
            Platform = Get-NoteValue $help.Notes 'Platform:'
            Modules = (@($modules) + $(if ($admin) { '(run as Administrator)' }) | Where-Object { $_ }) -join ', '
            Params = $params; Example = $example
        })
    }
}

# bash and Python: header comment block with "Label: value" lines.
$foreign = @(
    @{ Dir = 'network'; Filter = '*.sh'; Key = { 'network' }; Kind = 'bash' }
    @{ Dir = 'python';  Filter = '*.py'; Key = { param($f) 'python-' + (Split-Path (Split-Path $f.FullName -Parent) -Leaf) }; Kind = 'Python' }
)
foreach ($src in $foreign) {
    $dir = Join-Path $scriptsRoot $src.Dir
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    foreach ($file in Get-ChildItem -LiteralPath $dir -Filter $src.Filter -Recurse -File | Sort-Object FullName) {
        $header = (Get-Content -LiteralPath $file.FullName -TotalCount 40 | ForEach-Object { $_ -replace '^\s*#\s?', '' }) -join "`n"
        $entries.Add([pscustomobject]@{
            File = $file; Key = (& $src.Key $file); Kind = $src.Kind
            Synopsis = Get-NoteValue $header 'Synopsis:'
            When = Get-NoteValue $header 'When to use:'
            Perms = Get-NoteValue $header 'Permissions:'
            Safety = Get-NoteValue $header 'Safety:'
            Platform = Get-NoteValue $header 'Platform:'
            Modules = ''; Params = @(); Example = ''
        })
    }
}

if ($entries.Count -eq 0) { throw "No scripts found under $scriptsRoot" }

# Data block
$data = [System.Text.StringBuilder]::new()
[void]$data.AppendLine('$Script:Toolbox = @(')
foreach ($e in $entries) {
    $raw = [System.IO.File]::ReadAllText($e.File.FullName)
    $raw = $raw.TrimStart([char]0xFEFF) -replace "`r`n", "`n"
    if ($e.Kind -eq 'PowerShell') { $raw = $raw -replace "`n", "`r`n" }   # Windows line endings for pasted PowerShell
    $lineCount = ($raw -split "`n").Count
    $catName = if ($categoryNames.ContainsKey($e.Key)) { $categoryNames[$e.Key] } else { $e.Key }
    $paramLiterals = ($e.Params | ForEach-Object { ConvertTo-Literal $_ }) -join ', '
    [void]$data.AppendLine('    [pscustomobject]@{')
    [void]$data.AppendLine("        Name = $(ConvertTo-Literal $e.File.Name); Kind = $(ConvertTo-Literal $e.Kind); CategoryName = $(ConvertTo-Literal $catName)")
    [void]$data.AppendLine("        Synopsis = $(ConvertTo-Literal $e.Synopsis)")
    [void]$data.AppendLine("        When = $(ConvertTo-Literal $e.When)")
    [void]$data.AppendLine("        Perms = $(ConvertTo-Literal $e.Perms)")
    [void]$data.AppendLine("        Safety = $(ConvertTo-Literal $e.Safety)")
    [void]$data.AppendLine("        Platform = $(ConvertTo-Literal $e.Platform)")
    [void]$data.AppendLine("        Modules = $(ConvertTo-Literal $e.Modules)")
    [void]$data.AppendLine("        Params = @($paramLiterals)")
    [void]$data.AppendLine("        Example = $(ConvertTo-Literal $e.Example)")
    [void]$data.AppendLine("        Lines = $lineCount")
    [void]$data.AppendLine("        Data = '$(ConvertTo-Packed $raw)'")
    [void]$data.AppendLine('    }')
}
[void]$data.AppendLine(')')

$commit = ''
try { $commit = (& git -C $RepoRoot rev-parse --short HEAD 2>$null) } catch { }
$built = (Get-Date).ToString('yyyy-MM-dd HH:mm') + $(if ($commit) { " ($commit)" })
[void]$data.AppendLine("`$Script:ToolboxBuilt = '$built'")

$template = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Toolbox.template.ps1'))
if ($template -notmatch '(?m)^#__TOOLBOX_DATA__\s*$') { throw 'Placeholder #__TOOLBOX_DATA__ not found in the template.' }
$bundle = [regex]::Replace($template, '(?m)^#__TOOLBOX_DATA__\s*$', { param($m) $data.ToString().TrimEnd() })

if ($bundle -match '[^\x00-\x7F]') { throw 'The bundle contains non-ASCII characters; keep the template ASCII.' }

$outDir = Split-Path -Parent $OutputPath
$null = New-Item -ItemType Directory -Path $outDir -Force
[System.IO.File]::WriteAllText($OutputPath, $bundle, [System.Text.UTF8Encoding]::new($true))

# The bundle must parse.
$tokens = $null; $errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $OutputPath).Path, [ref]$tokens, [ref]$errors)
if ($errors) { throw "Generated bundle does not parse: $($errors[0].Message) (line $($errors[0].Extent.StartLineNumber))" }

$size = [Math]::Round((Get-Item -LiteralPath $OutputPath).Length / 1KB)
Write-Host "Built $OutputPath : $($entries.Count) script(s), $size KB."
