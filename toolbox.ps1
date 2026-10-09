#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Toolbox — interactive TUI launcher for infrastructure automation scripts.
.DESCRIPTION
  Discovers scripts under scripts/ (windows PowerShell by domain, network
  bash, python), reads each script's comment-based help (synopsis, when to
  use, permissions, safety, examples), parses parameters via AST, provides
  interactive parameter input, module dependency checking, and multiple
  execution modes (run, print, clipboard, new process, remote).
.NOTES
  Requires PowerShell 5.1 or later. Arrow-key menus on PS7+, numbered
  fallback on PS5.1. Zero external dependencies for the launcher itself.
  Script documentation comes from the script headers; see docs/DESIGN-GUIDE.md.
#>
[CmdletBinding()]
param()

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

$ScriptRoot = Split-Path -Parent $PSCommandPath
$ScriptsRoot = Join-Path $ScriptRoot "scripts"
$OnWindows = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
$HostProgram = if ($PSVersionTable.PSVersion.Major -ge 7) { "pwsh" } else { "powershell.exe" }

$CategoryNames = @{
    "m365"             = "Microsoft 365 / Identity"
    "exchange"         = "Exchange Online"
    "azure"            = "Azure / Cloud"
    "active-directory" = "Active Directory"
    "server"           = "Windows Server"
    "endpoint"         = "Endpoint / Workstation"
    "security"         = "Security"
    "network"          = "Network (bash, run from macOS/Linux)"
    "python-automation" = "Python / Automation"
    "python-networking" = "Python / Networking"
}

$KnownModuleMap = @{
    "Connect-MgGraph"            = "Microsoft.Graph.Authentication"
    "Connect-ExchangeOnline"     = "ExchangeOnlineManagement"
    "Connect-AzAccount"          = "Az.Accounts"
    "Get-AzVM"                   = "Az.Compute"
    "Get-AzSubscription"         = "Az.Accounts"
    "Get-ADUser"                 = "ActiveDirectory"
    "Get-ADComputer"             = "ActiveDirectory"
    "Get-ADGroup"                = "ActiveDirectory"
    "Get-ADOrganizationalUnit"   = "ActiveDirectory"
    "Get-ADDomain"               = "ActiveDirectory"
    "Get-ADForest"               = "ActiveDirectory"
    "Backup-Gpo"                 = "GroupPolicy"
    "Get-Gpo"                    = "GroupPolicy"
    "Get-VM"                     = "Hyper-V"
    "Get-WBBackupSet"            = "WindowsServerBackup"
    "Get-Mailbox"                = "ExchangeOnlineManagement"
    "New-Mailbox"                = "ExchangeOnlineManagement"
    "Set-Mailbox"                = "ExchangeOnlineManagement"
    "Get-InboxRule"              = "ExchangeOnlineManagement"
    "Get-TransportRule"          = "ExchangeOnlineManagement"
    "New-TransportRule"          = "ExchangeOnlineManagement"
    "Get-MgUser"                 = "Microsoft.Graph.Users"
    "New-MgUser"                 = "Microsoft.Graph.Users"
    "Get-MgGroup"                = "Microsoft.Graph.Groups"
    "Get-MgOrganization"         = "Microsoft.Graph.Identity.DirectoryManagement"
    "Get-MgSubscribedSku"        = "Microsoft.Graph.Identity.DirectoryManagement"
    "Get-MgIdentityConditionalAccessPolicy" = "Microsoft.Graph.Identity.SignIns"
    "Get-MgUserAuthenticationMethod"        = "Microsoft.Graph.Authentication"
    "Invoke-MgGraphRequest"      = "Microsoft.Graph.Authentication"
    "Get-AzRecoveryServicesVault"    = "Az.RecoveryServices"
    "Get-AzNetworkSecurityGroup"     = "Az.Network"
    "Get-AzStorageAccount"           = "Az.Storage"
    "Get-AzRoleAssignment"           = "Az.Resources"
    "Get-AzResource"                 = "Az.Resources"
    "Get-AzResourceGroup"            = "Az.Resources"
    "New-AzResource"                 = "Az.Resources"
    "Set-AzContext"                  = "Az.Accounts"
    "Get-AzContext"                  = "Az.Accounts"
}

# ═══════════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

function Write-Dim {
    Write-Host @Args -ForegroundColor DarkGray
}

function Write-Info {
    Write-Host @Args -ForegroundColor Cyan
}

function Write-Ok {
    Write-Host @Args -ForegroundColor Green
}

function Write-Warn {
    Write-Host @Args -ForegroundColor Yellow
}

function Write-Err {
    Write-Host @Args -ForegroundColor Red
}

function Get-ConsoleWidth {
    # Redirected or detached hosts report a width of 0; fall back to 80 and never go below 40.
    try {
        $W = [Console]::WindowWidth
        if ($W -lt 41) { return 80 }
        return [Math]::Min(($W - 1), 120)
    } catch { return 80 }
}

function Write-Rule {
    Write-Host ("─" * (Get-ConsoleWidth)) -ForegroundColor DarkGray
}

function Center-Text {
    param([string]$Text)
    $Width = Get-ConsoleWidth
    $Pad = [Math]::Max(0, [Math]::Floor(($Width - $Text.Length) / 2))
    return (" " * $Pad) + $Text
}

# ═══════════════════════════════════════════════════════════════════════════════
# AST / SCRIPT CATALOG
# ═══════════════════════════════════════════════════════════════════════════════

function Get-NoteValue {
    param([string]$Notes, [string]$Label)
    if (-not $Notes) { return "" }
    $M = [regex]::Match($Notes, "(?im)^\s*$([regex]::Escape($Label))\s*(.+?)\s*$")
    if ($M.Success) { return $M.Groups[1].Value }
    return ""
}

function Get-ScriptCatalog {
    <#
    .SYNOPSIS
      Walks scripts/windows/<domain>, scripts/network and scripts/python/<domain>,
      and builds a catalog entry per script from its header (comment-based help
      for PowerShell, leading comment block for bash/Python) and the AST.
    #>
    $Catalog = [System.Collections.Generic.List[PSObject]]::new()
    $Sources = [System.Collections.Generic.List[PSObject]]::new()

    $WindowsRoot = Join-Path $ScriptsRoot "windows"
    if (Test-Path $WindowsRoot) {
        foreach ($Folder in (Get-ChildItem $WindowsRoot -Directory | Sort-Object Name)) {
            $Sources.Add([PSCustomObject]@{ Key = $Folder.Name; Dir = $Folder.FullName; Filter = "*.ps1"; Kind = "PowerShell" })
        }
    }
    $NetworkRoot = Join-Path $ScriptsRoot "network"
    if (Test-Path $NetworkRoot) {
        $Sources.Add([PSCustomObject]@{ Key = "network"; Dir = $NetworkRoot; Filter = "*.sh"; Kind = "bash" })
    }
    $PythonRoot = Join-Path $ScriptsRoot "python"
    if (Test-Path $PythonRoot) {
        foreach ($Folder in (Get-ChildItem $PythonRoot -Directory | Sort-Object Name)) {
            $Sources.Add([PSCustomObject]@{ Key = "python-$($Folder.Name)"; Dir = $Folder.FullName; Filter = "*.py"; Kind = "Python" })
        }
    }

    if ($Sources.Count -eq 0) {
        Write-Err "No script folders found under: $ScriptsRoot"
        return $Catalog
    }

    foreach ($Source in $Sources) {
        $CategoryName = $CategoryNames[$Source.Key]
        if (-not $CategoryName) { $CategoryName = $Source.Key }

        foreach ($File in (Get-ChildItem $Source.Dir -Filter $Source.Filter -File | Sort-Object Name)) {
            if ($Source.Kind -eq "PowerShell") {
                $Catalog.Add((Parse-ScriptFile -Path $File.FullName -CategoryKey $Source.Key -CategoryName $CategoryName))
            } else {
                $Catalog.Add((Parse-ForeignScript -Path $File.FullName -CategoryKey $Source.Key -CategoryName $CategoryName -Kind $Source.Kind))
            }
        }
    }

    return $Catalog
}

function Parse-ForeignScript {
    <#
    .SYNOPSIS
      Reads the leading comment block of a bash/Python script for the standard
      labels (Synopsis, Platform, Permissions, When to use, Safety).
    #>
    param([string]$Path, [string]$CategoryKey, [string]$CategoryName, [string]$Kind)

    $FileName = Split-Path $Path -Leaf
    $Header = (Get-Content $Path -TotalCount 40 | ForEach-Object { $_ -replace '^\s*#\s?', '' }) -join "`n"
    $Synopsis = Get-NoteValue $Header "Synopsis:"

    return [PSCustomObject]@{
        Name = $FileName; Path = $Path
        RelativePath = $Path.Substring($ScriptRoot.Length + 1) -replace '\\', '/'
        CategoryKey = $CategoryKey; CategoryName = $CategoryName; Kind = $Kind
        Description = if ($Synopsis) { $Synopsis } else { $FileName }
        WhenToUse = Get-NoteValue $Header "When to use:"
        Permissions = Get-NoteValue $Header "Permissions:"
        Safety = Get-NoteValue $Header "Safety:"
        Platform = Get-NoteValue $Header "Platform:"
        Examples = @()
        Parameters = @(); Dependencies = @(); RequiresAdmin = $false
    }
}

function Parse-ScriptFile {
    <#
    .SYNOPSIS
      Parses a single .ps1 file using the PowerShell AST to extract the header
      (comment-based help), parameters and dependencies.
    #>
    param(
        [string]$Path,
        [string]$CategoryKey,
        [string]$CategoryName
    )

    $FileName = Split-Path $Path -Leaf
    $RelativePath = $Path.Substring($ScriptRoot.Length + 1) -replace '\\', '/'

    $Parameters = @()
    $Dependencies = [System.Collections.Generic.List[string]]::new()
    $RequiresAdmin = $false

    try {
        $Tokens = $null
        $Errors = $null
        $Ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$Tokens, [ref]$Errors)
    } catch {
        return [PSCustomObject]@{
            Name = $FileName; Path = $Path; RelativePath = $RelativePath
            CategoryKey = $CategoryKey; CategoryName = $CategoryName; Kind = "PowerShell"
            Description = "Parse failed"; WhenToUse = ""; Permissions = ""; Safety = ""; Platform = ""; Examples = @()
            Parameters = @(); Dependencies = @(); RequiresAdmin = $false
        }
    }

    # ── Header: comment-based help ──
    $Help = $Ast.GetHelpContent()
    $Description = ""; $Notes = ""; $Examples = @()
    if ($Help) {
        $Description = ($Help.Synopsis -replace '\s*\r?\n\s*', ' ').Trim()
        $Notes = $Help.Notes
        $Examples = @($Help.Examples | ForEach-Object { $_.Trim() })
    }

    # ── Extract parameters from param() block ──
    if ($Ast.ParamBlock) {
        foreach ($ParamAst in $Ast.ParamBlock.Parameters) {
            $ParamName = $ParamAst.Name.VariablePath.UserPath
            $ParamType = "string"
            $IsMandatory = $false
            $DefaultValue = $null
            $ValidateSet = @()
            $HelpText = ""
            $ParameterSetName = ""
            $Position = $null

            if ($ParamAst.StaticType -and $ParamAst.StaticType.Name) {
                $ParamType = $ParamAst.StaticType.Name
            }
            if ($Help -and $Help.Parameters) {
                $HelpKey = $Help.Parameters.Keys | Where-Object { $_ -ieq $ParamName } | Select-Object -First 1
                if ($HelpKey) { $HelpText = ($Help.Parameters[$HelpKey] -replace '\s*\r?\n\s*', ' ').Trim() }
            }

            if ($ParamAst.DefaultValue) {
                try { $DefaultValue = $ParamAst.DefaultValue.SafeGetValue() } catch {}
            }

            foreach ($Attr in $ParamAst.Attributes) {
                if ($Attr -is [System.Management.Automation.Language.AttributeAst]) {
                    if ($Attr.TypeName.Name -eq "Parameter") {
                        foreach ($Arg in $Attr.NamedArguments) {
                            if ($Arg.ArgumentName -eq "Mandatory") {
                                try { $IsMandatory = [bool]$Arg.Argument.SafeGetValue() } catch {}
                            }
                            if ($Arg.ArgumentName -eq "ParameterSetName") {
                                try { $ParameterSetName = [string]$Arg.Argument.SafeGetValue() } catch {}
                            }
                            if ($Arg.ArgumentName -eq "Position") {
                                try { $Position = [int]$Arg.Argument.SafeGetValue() } catch {}
                            }
                        }
                    }
                    if ($Attr.TypeName.Name -eq "ValidateSet") {
                        $ValidateSet = @($Attr.PositionalArguments | ForEach-Object {
                            try { $_.SafeGetValue() } catch {}
                        } | Where-Object { $_ })
                    }
                }
            }

            $Parameters += [PSCustomObject]@{
                Name = $ParamName
                Type = $ParamType
                IsMandatory = $IsMandatory
                DefaultValue = $DefaultValue
                ValidateSet = $ValidateSet
                HelpText = $HelpText
                ParameterSetName = $ParameterSetName
                Position = $Position
            }
        }
    }

    # ── Extract dependencies ──
    # #Requires -Modules / -RunAsAdministrator (cross-version via ScriptRequirements)
    if ($Ast.ScriptRequirements) {
        foreach ($Mod in @($Ast.ScriptRequirements.RequiredModules)) {
            if ($Mod -and $Mod.Name -and $Mod.Name -notin $Dependencies) { $Dependencies.Add($Mod.Name) }
        }
        if ($Ast.ScriptRequirements.IsElevationRequired) { $RequiresAdmin = $true }
    }

    # Import-Module statements
    if ($Ast.EndBlock) {
        $ImportCalls = $Ast.EndBlock.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
            Where-Object { $_.GetCommandName() -eq "Import-Module" }
        foreach ($Call in $ImportCalls) {
            if ($Call.CommandElements.Count -ge 2) {
                try { $ModName = $Call.CommandElements[1].SafeGetValue(); if ($ModName -and $ModName -notin $Dependencies) { $Dependencies.Add($ModName) } } catch {}
            }
        }

        # Known cmdlets → module mapping
        $CmdCalls = $Ast.EndBlock.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
        foreach ($Call in $CmdCalls) {
            $CmdName = $Call.GetCommandName()
            if ($CmdName -and $KnownModuleMap.ContainsKey($CmdName)) {
                $ModName = $KnownModuleMap[$CmdName]
                if ($ModName -notin $Dependencies) { $Dependencies.Add($ModName) }
            }
        }
    }

    return [PSCustomObject]@{
        Name = $FileName
        Path = $Path
        RelativePath = $RelativePath
        CategoryKey = $CategoryKey
        CategoryName = $CategoryName
        Kind = "PowerShell"
        Description = if ($Description) { $Description } else { $FileName -replace '\.ps1$', '' -replace '-', ' ' }
        WhenToUse = Get-NoteValue $Notes "When to use:"
        Permissions = Get-NoteValue $Notes "Permissions:"
        Safety = Get-NoteValue $Notes "Safety:"
        Platform = Get-NoteValue $Notes "Platform:"
        Examples = $Examples
        Parameters = $Parameters
        Dependencies = $Dependencies.ToArray()
        RequiresAdmin = $RequiresAdmin
    }
}

function Get-ScriptParameterString {
    <#
    .SYNOPSIS
      Builds a PowerShell CLI argument string from a params hashtable.
      Handles switches, strings, ints, and arrays.
    #>
    param(
        [PSObject]$ScriptInfo,
        [hashtable]$ParamValues
    )

    $Parts = @()
    $Parts += "& '$($ScriptInfo.Path)'"

    foreach ($Param in $ScriptInfo.Parameters) {
        $Name = $Param.Name
        if (-not $ParamValues.ContainsKey($Name)) { continue }

        $Val = $ParamValues[$Name]
        if ($null -eq $Val -and $Param.IsMandatory) { continue }

        if ($Param.Type -eq "switch" -or $Param.Type -eq "SwitchParameter") {
            if ($Val -eq $true) { $Parts += "-$Name" }
        } elseif ($Param.Type -eq "string") {
            $Parts += "-$Name `"$([System.Management.Automation.Language.CodeGeneration]::EscapeValue($Val))`""
        } elseif ($Param.Type -like "*[]" -and $Val -is [array]) {
            $Quoted = ($Val | ForEach-Object { "`"$_`"" }) -join ","
            $Parts += "-$Name @($Quoted)"
        } else {
            $Parts += "-$Name $Val"
        }
    }

    return $Parts -join " "
}

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

function Test-MissingModules {
    <#
    .SYNOPSIS
      Checks which dependencies are not installed, returns list of missing.
    #>
    param([string[]]$ModuleNames)

    $Missing = [System.Collections.Generic.List[string]]::new()
    foreach ($Module in $ModuleNames) {
        $Available = Get-Module -ListAvailable -Name $Module -ErrorAction SilentlyContinue
        if (-not $Available) {
            # Check for wildcard matching (e.g., Microsoft.Graph.Users may match Microsoft.Graph*)
            $Partial = Get-Module -ListAvailable -Name "$Module*" -ErrorAction SilentlyContinue
            if (-not $Partial) {
                $Missing.Add($Module)
            }
        }
    }
    return $Missing.ToArray()
}

function Install-MissingModules {
    <#
    .SYNOPSIS
      Prompts user to install missing modules from PSGallery. Returns $true if
      all are resolved (either pre-installed or user accepted install).
    #>
    param([string[]]$ModuleNames)

    $Missing = Test-MissingModules -ModuleNames $ModuleNames
    if ($Missing.Count -eq 0) { return $true }

    Write-Warn "`nMissing module(s): $($Missing -join ', ')"

    if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
        Write-Warn "  PSGallery not registered, skipping auto-install."
        Write-Warn "  Run: Register-PSRepository -Default"
        return $false
    }

    $InstallAll = $null
    foreach ($Module in $Missing) {
        $Msg = "  Install '$Module' from PSGallery? [Y/n/a(install all)]: "
        if ($InstallAll -eq $true) {
            $Choice = "y"
        } else {
            $Choice = Read-Host $Msg
            if ($Choice -eq 'a') { $InstallAll = $true; $Choice = "y" }
        }

        if ($Choice -ne "y" -and $Choice -ne "Y" -and $Choice -ne "") {
            Write-Warn "  Skipping '$Module' — script may fail."
            continue
        }

        try {
            Write-Info "  Installing $Module..."
            Install-Module -Name $Module -Scope CurrentUser -Force -Repository PSGallery -AllowClobber -ErrorAction Stop
            Write-Ok "  Installed $Module"
        } catch {
            Write-Err "  Failed to install '$Module': $_"
        }
    }
    return $true
}

# ═══════════════════════════════════════════════════════════════════════════════
# MENU UI
# ═══════════════════════════════════════════════════════════════════════════════

function Test-InteractiveTerminal {
    <#
    .SYNOPSIS
      Detects whether we can use arrow-key navigation. Returns $true if
      $host.UI.RawUI.ReadKey is available and we're not in a constrained
      environment (ISE, VS Code integrated console, non-interactive).
    #>
    if (-not $host.UI.RawUI -or -not $host.UI.RawUI.ReadKey) { return $false }
    if ($host.Name -like "*ISE*") { return $false }
    if ($host.Name -like "*VS Code*") { return $false }
    if (-not [Environment]::UserInteractive) { return $false }
    return $true
}

function Show-Menu {
    <#
    .SYNOPSIS
      Universal menu function — uses arrow keys on PS7+ / PS5.1 with RawUI,
      falls back to numbered Read-Host on constrained hosts.
    .PARAMETER Title
      Title string displayed above the menu.
    .PARAMETER Items
      Array of display strings for each option.
    .PARAMETER InfoPane
      Optional multi-line info displayed alongside the menu.
    .PARAMETER Footer
      Optional footer text shown below the menu.
    .PARAMETER AllowBack
      If $true, adds a "Back" option at the end.
    .PARAMETER DefaultIndex
      Pre-select this item index.
    .OUTPUTS
      Selected index (int), or -1 for Back/Escape.
    #>
    param(
        [string]$Title,
        [string[]]$Items,
        [string[]]$InfoPane,
        [string]$Footer,
        [switch]$AllowBack,
        [int]$DefaultIndex = 0
    )

    if ($AllowBack) { $Items = $Items + @("← Back") }

    if (Test-InteractiveTerminal) {
        return Show-InteractiveMenu -Title $Title -Items $Items -InfoPane $InfoPane -Footer $Footer -DefaultIndex $DefaultIndex -AllowBack:$AllowBack
    } else {
        return Show-NumberedMenu -Title $Title -Items $Items -InfoPane $InfoPane -Footer $Footer -AllowBack:$AllowBack -DefaultIndex $DefaultIndex
    }
}

function Show-InteractiveMenu {
    <#
    .SYNOPSIS
      Arrow-key + Enter interactive menu using RawUI key reading.
      Renders in-place by overwriting lines rather than Clear-Host.
    #>
    param(
        [string]$Title,
        [string[]]$Items,
        [string[]]$InfoPane,
        [string]$Footer,
        [int]$DefaultIndex = 0
    )

    $Sel = [Math]::Max(0, [Math]::Min($DefaultIndex, $Items.Count - 1))
    $Width = Get-ConsoleWidth
    $Top = [Console]::CursorTop
    $InfoLineCount = 0
    $Rendered = $false

    function Render {
        $CurTop = [Console]::CursorTop
        [Console]::SetCursorPosition(0, $Top)

        if ($Title) { Write-Host "  $Title" -ForegroundColor White; Write-Rule }

        if ($InfoPane -and $InfoPane.Count -gt 0) {
            foreach ($Line in $InfoPane) {
                Write-Host $Line -ForegroundColor DarkGray
            }
            Write-Rule
        }

        for ($i = 0; $i -lt $Items.Count; $i++) {
            $Prefix = if ($i -eq $Sel) { " ▸ " } else { "   " }
            $Color = if ($i -eq $Sel) { "Cyan" } else { "Gray" }
            $Line = "$Prefix$($Items[$i])"
            if ($Line.Length -gt $Width) { $Line = $Line.Substring(0, $Width - 3) + "..." }
            Write-Host $Line -ForegroundColor $Color
        }

        if ($Footer) { Write-Dim $Footer }

        $LinesRendered = 2 + $Items.Count
        if ($InfoPane.Count -gt 0) { $LinesRendered += $InfoPane.Count + 1 }
        if ($Footer) { $LinesRendered++ }
        # Clear any leftover lines from previous render
        [Console]::SetCursorPosition(0, $Top + $LinesRendered)
        Write-Host (" " * $Width)
        [Console]::SetCursorPosition(0, $Top)
    }

    Render

    while ($true) {
        $Key = $host.UI.RawUI.ReadKey("IncludeKeyDown,NoEcho")
        $VK = $Key.VirtualKeyCode

        if ($VK -eq 38 -and $Sel -gt 0) { $Sel--; Render }
        elseif ($VK -eq 40 -and $Sel -lt $Items.Count - 1) { $Sel++; Render }
        elseif ($VK -eq 13) { break }
        elseif ($VK -eq 27) { $Sel = -1; break }
    }

    return $Sel
}

function Show-NumberedMenu {
    <#
    .SYNOPSIS
      Fallback numbered list menu for constrained hosts (ISE, VS Code, non-interactive).
    #>
    param(
        [string]$Title,
        [string[]]$Items,
        [string[]]$InfoPane,
        [string]$Footer,
        [switch]$AllowBack,
        [int]$DefaultIndex = 0
    )

    if ($Title) { Write-Host "  $Title" -ForegroundColor White; Write-Rule }

    if ($InfoPane -and $InfoPane.Count -gt 0) {
        foreach ($Line in $InfoPane) { Write-Host $Line -ForegroundColor DarkGray }
        Write-Rule
    }

    $NumberedItems = @()
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $Num = $i + 1
        $NumberedItems += $Num
        $Line = "$Num) $($Items[$i])"
        Write-Host $Line -ForegroundColor Gray
    }

    if ($Footer) { Write-Dim $Footer }

    $Prompt = if ($AllowBack) { "Select [1-$($Items.Count)] or 0 for Back: " } else { "Select [1-$($Items.Count)]: " }
    $Range = if ($AllowBack) { 0..$Items.Count } else { 1..$Items.Count }

    while ($true) {
        $Input = Read-Host "`n$Prompt"
        if ($Input -match "^\d+$") {
            $Num = [int]$Input
            if ($AllowBack -and $Num -eq 0) { return -1 }
            if ($Num -ge 1 -and $Num -le $Items.Count) {
                return $Num - 1
            }
        }
        Write-Err "  Invalid selection. Try again."
    }
}

function Show-YesNo {
    <#
    .SYNOPSIS
      Yes/No prompt with default. Returns $true for Yes, $false for No.
    #>
    param([string]$Prompt, [bool]$Default = $true)
    $Suffix = if ($Default) { "[Y/n]" } else { "[y/N]" }
    $Input = Read-Host "$Prompt $Suffix"
    if ($Input -eq "" -or $Input -eq $null) { return $Default }
    return $Input -match "^[Yy]"
}

function Show-Info {
    <#
    .SYNOPSIS
      Displays an info message and waits for Enter.
    #>
    param([string]$Message, [string]$Color = "DarkGray")
    Write-Host "`n$Message" -ForegroundColor $Color
    Read-Host "Press Enter to continue"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PARAMETER INPUT UI
# ═══════════════════════════════════════════════════════════════════════════════

function Invoke-ParameterInput {
    <#
    .SYNOPSIS
      Walks each parameter of a script and prompts the user for input.
      Validates types, applies defaults, and returns a hashtable of values.
    #>
    param([PSObject]$ScriptInfo)

    $Values = @{}
    $ParamList = $ScriptInfo.Parameters

    if ($ParamList.Count -eq 0) {
        Write-Dim "  No parameters required."
        return $Values
    }

    Write-Host "`n  Parameters for $($ScriptInfo.Name):" -ForegroundColor White
    Write-Rule

    $Required = $ParamList | Where-Object { $_.IsMandatory }
    $Optional = $ParamList | Where-Object { -not $_.IsMandatory }

    if ($Required.Count -gt 0) {
        Write-Host "  Required:" -ForegroundColor Yellow
        foreach ($Param in $Required) {
            $Values[$Param.Name] = Read-ParameterValue -Param $Param
        }
    }

    if ($Optional.Count -gt 0) {
        Write-Host "`n  Optional:" -ForegroundColor DarkGray
        foreach ($Param in $Optional) {
            $Values[$Param.Name] = Read-ParameterValue -Param $Param
        }
    }

    return $Values
}

function Read-ParameterValue {
    <#
    .SYNOPSIS
      Prompts for a single parameter value with type-appropriate UI.
    #>
    param([PSObject]$Param)

    $Label = "$($Param.Name) ($($Param.Type))"
    $DefaultStr = if ($Param.DefaultValue -ne $null) { $Param.DefaultValue.ToString() } else { $null }

    if ($Param.Type -eq "switch" -or $Param.Type -eq "SwitchParameter") {
        $Default = $false
        if ($DefaultStr -match "true|yes|\$true") { $Default = $true }
        $Result = Show-YesNo -Prompt "  $Label" -Default $Default
        return $Result
    }

    if ($Param.ValidateSet.Count -gt 0) {
        return Read-ValidateSetValue -Param $Param -Label $Label -DefaultStr $DefaultStr
    }

    if ($Param.Type -eq "int" -or $Param.Type -eq "Int32") {
        while ($true) {
            $Input = Read-Host "  $Label $(if($DefaultStr){ "[$DefaultStr]" })"
            if ($Input -eq "" -and $DefaultStr) { return [int]$DefaultStr }
            if ($Input -eq "" -and -not $Param.IsMandatory) { return $null }
            if ($Input -match "^\d+$") { return [int]$Input }
            Write-Err "  Enter a valid number."
        }
    }

    if ($Param.Type -like "*[]" -or $Param.Name -like "*Address*" -or $Param.Name -like "*Name*") {
        $Input = Read-Host "  $Label (comma-separated) $(if($DefaultStr){ "[$DefaultStr]" })"
        if ($Input -eq "" -and $DefaultStr) { return @($DefaultStr) }
        if ($Input -eq "" -and -not $Param.IsMandatory) { return @() }
        return ($Input -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    # Default: string
    while ($true) {
        $Prompt = "  $Label$(if($DefaultStr){ " [$DefaultStr]" })"
        $Input = Read-Host $Prompt
        if ($Input -eq "" -and $DefaultStr) { return $DefaultStr }
        if ($Input -eq "" -and -not $Param.IsMandatory) { return $null }
        if ($Input -ne "") { return $Input }
        if ($Param.IsMandatory) { Write-Err "  This parameter is required." }
    }
}

function Read-ValidateSetValue {
    <#
    .SYNOPSIS
      Shows ValidateSet options as a numbered menu, returns selected value.
    #>
    param(
        [PSObject]$Param,
        [string]$Label,
        [string]$DefaultStr
    )

    $Items = $Param.ValidateSet
    if ($DefaultStr -and $Items -notcontains $DefaultStr) { $Items = @($DefaultStr) + $Items }

    Write-Host "  $Label — choose from:" -ForegroundColor DarkGray
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $Marker = if ($Items[$i] -eq $DefaultStr) { " (default)" } else { "" }
        Write-Host "    $($i+1)) $($Items[$i])$Marker" -ForegroundColor Gray
    }

    $Range = 1..$Items.Count
    while ($true) {
        $Input = Read-Host "    Enter number $(if($DefaultStr -and -not $Param.IsMandatory){ "or leave blank for default" })"
        if ($Input -eq "" -and $DefaultStr) { return $DefaultStr }
        if ($Input -eq "" -and -not $Param.IsMandatory) { return $null }
        if ($Input -match "^\d+$" -and [int]$Input -ge 1 -and [int]$Input -le $Items.Count) {
            return $Items[[int]$Input - 1]
        }
        Write-Err "    Invalid selection."
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# EXECUTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

function Select-ExecutionTarget {
    <#
    .SYNOPSIS
      Prompts the user for local or remote execution.
      Returns @{ Type = "Local" } or @{ Type = "Remote"; Computers = @(...) }.
    #>
    $Choice = Show-Menu -Title "Execution Target" -Items @("Local machine", "Remote machine(s)") -AllowBack

    if ($Choice -eq -1) { return $null }
    if ($Choice -eq 0) { return @{ Type = "Local" } }

    $Computers = @()
    $Input = Read-Host "  Enter computer name(s), comma-separated"
    $Computers = $Input -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($Computers.Count -eq 0) {
        Write-Err "  No computers entered. Defaulting to local."
        return @{ Type = "Local" }
    }

    return @{ Type = "Remote"; Computers = $Computers }
}

function Select-ExecutionMode {
    <#
    .SYNOPSIS
      Presents the 4 execution modes and returns the user's choice index.
    #>
    $Modes = @(
        "Run now (current session)",
        "Run now (new $HostProgram process)",
        "Print command to console",
        "Copy command to clipboard"
    )
    $Choice = Show-Menu -Title "Execute" -Items $Modes -Footer "Select how to run the script." -AllowBack
    return $Choice
}

function Invoke-ToolboxScript {
    <#
    .SYNOPSIS
      Orchestrates execution: dependency check, parameter input, target/mode
      selection, and actual execution.
    #>
    param([PSObject]$ScriptInfo)

    # ── Step 1: Check dependencies ──
    $HasComputerName = $ScriptInfo.Parameters.Name -contains "ComputerName" -or
                       $ScriptInfo.Parameters.Name -contains "ComputerNames" -or
                       $ScriptInfo.Parameters.Name -contains "Computer"

    if ($ScriptInfo.Dependencies.Count -gt 0) {
        Write-Host "`n  Checking module dependencies..." -ForegroundColor Yellow
        $Missing = Test-MissingModules -ModuleNames $ScriptInfo.Dependencies
        if ($Missing.Count -gt 0) {
            Write-Warn "  Some modules are missing."
            Install-MissingModules -ModuleNames $Missing | Out-Null
        } else {
            Write-Ok "  All modules available."
        }
    }

    # ── Step 2: Parameter input ──
    $ParamValues = Invoke-ParameterInput -ScriptInfo $ScriptInfo
    if (-not $ParamValues) { return }

    # ── Step 3: Execution target ──
    $Target = Select-ExecutionTarget
    if (-not $Target) { return }

    # Directly populate -ComputerName if the script supports it and remote is chosen
    if ($Target.Type -eq "Remote" -and $HasComputerName) {
        $CompParam = if ($ScriptInfo.Parameters.Name -contains "ComputerName") { "ComputerName" }
                     elseif ($ScriptInfo.Parameters.Name -contains "ComputerNames") { "ComputerNames" }
                     else { "Computer" }
        $ParamValues[$CompParam] = $Target.Computers
        $Target = @{ Type = "Local" }
        Write-Dim "  Script has built-in -$CompParam support. Populating directly."
    }

    # ── Step 4: Execution mode ──
    $Mode = Select-ExecutionMode
    if ($Mode -eq -1) { return }

    # ── Build command string ──
    $CmdString = Get-ScriptParameterString -ScriptInfo $ScriptInfo -ParamValues $ParamValues

    # ── Execute ──
    switch ($Mode) {
        0 { Invoke-LocalRun -ScriptInfo $ScriptInfo -ParamValues $ParamValues -Target $Target }
        1 { Invoke-NewProcess -CmdString $CmdString -Target $Target }
        2 { Invoke-PrintCommand -CmdString $CmdString -Target $Target }
        3 { Invoke-CopyToClipboard -CmdString $CmdString -Target $Target }
    }

    if ($Mode -ge 0 -and $Mode -le 1) {
        Write-Host ""
        Read-Host "Press Enter to return to menu"
    }
}

function Invoke-LocalRun {
    param(
        [PSObject]$ScriptInfo,
        [hashtable]$ParamValues,
        [hashtable]$Target
    )

    Write-Rule
    Write-Info "  Executing: $($ScriptInfo.RelativePath)"
    Write-Rule

    if ($Target.Type -eq "Remote") {
        $ScriptBlock = {
            param($Path, $Params)
            & $Path @Params
        }
        try {
            $Session = New-PSSession -ComputerName $Target.Computers -ErrorAction Stop
            Invoke-Command -Session $Session -ScriptBlock $ScriptBlock -ArgumentList $ScriptInfo.Path, $ParamValues
            Remove-PSSession $Session
        } catch {
            Write-Err "  Remote execution failed: $_"
        }
        return
    }

    try {
        & $ScriptInfo.Path @ParamValues
    } catch {
        Write-Err "  Script execution failed: $_"
        Write-Err "  $($_.ScriptStackTrace)"
    }
}

function Invoke-NewProcess {
    param([string]$CmdString, [hashtable]$Target)

    $ProcessArgs = "-NoProfile -Command $CmdString"
    if ($Target.Type -eq "Remote") {
        $RemoteCmd = "`$session = New-PSSession -ComputerName $($Target.Computers -join ',') -ErrorAction Stop; Invoke-Command -Session `$session -ScriptBlock { $CmdString }; Remove-PSSession `$session"
        $ProcessArgs = "-NoProfile -Command $RemoteCmd"
    }

    Write-Info "  Launching new $HostProgram process..."
    try {
        Start-Process -FilePath $HostProgram -ArgumentList $ProcessArgs -NoNewWindow:$false
    } catch {
        Write-Err "  Failed to launch process: $_"
    }
}

function Invoke-PrintCommand {
    param([string]$CmdString, [hashtable]$Target)

    Write-Host "`n  Command:" -ForegroundColor White
    $FullCmd = if ($Target.Type -eq "Remote") {
        "Invoke-Command -ComputerName $($Target.Computers -join ',') -ScriptBlock { $CmdString }"
    } else {
        $CmdString
    }
    Write-Host $FullCmd -ForegroundColor Cyan
}

function Invoke-CopyToClipboard {
    param([string]$CmdString, [hashtable]$Target)

    $FullCmd = if ($Target.Type -eq "Remote") {
        "Invoke-Command -ComputerName $($Target.Computers -join ',') -ScriptBlock { $CmdString }"
    } else {
        $CmdString
    }

    try {
        if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) {
            $FullCmd | Set-Clipboard
        } else {
            # Fallback for macOS/Linux without Set-Clipboard
            $FullCmd | Clip
        }
        Write-Ok "  Command copied to clipboard."
    } catch {
        Write-Err "  Clipboard unavailable. Command:"
        Write-Host $FullCmd -ForegroundColor Cyan
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════════

function Show-Banner {
    $Version = "1.0.0"
    $Width = Get-ConsoleWidth

    $Top = "╔" + ("═" * ($Width - 2)) + "╗"
    $Pad = $Width - 40
    $TitleLine = "║" + (" " * [Math]::Floor(($Pad)/2)) + "Toolbox v$Version — Infrastructure Automation" + (" " * [Math]::Ceiling(($Pad)/2)) + "║"
    $ScriptCount = (Get-ScriptCatalog).Count
    $StatusLine = "║" + (" " * [Math]::Floor(($Pad)/2)) + "$ScriptCount scripts · 6 categories" + (" " * [Math]::Ceiling(($Pad)/2)) + "║"
    $Bottom = "╚" + ("═" * ($Width - 2)) + "╝"

    Write-Host $Top -ForegroundColor Cyan
    Write-Host $TitleLine -ForegroundColor Cyan
    Write-Host $StatusLine -ForegroundColor Cyan
    Write-Host $Bottom -ForegroundColor Cyan
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ═══════════════════════════════════════════════════════════════════════════════

function Show-MainLoop {
    $Catalog = Get-ScriptCatalog
    if ($Catalog.Count -eq 0) {
        Write-Err "No scripts found under $ScriptsRoot"
        return
    }

    $Categories = $Catalog | Group-Object CategoryKey

    while ($true) {
        $CatItems = foreach ($Cat in $Categories) {
            $DisplayName = $CategoryNames[$Cat.Name]
            if (-not $DisplayName) { $DisplayName = $Cat.Name }
            "$DisplayName ($($Cat.Count) scripts)"
        }

        $CatChoice = Show-Menu -Title "Select Category" -Items $CatItems -Footer "↑↓ navigate · Enter select · Esc exit" -AllowBack

        if ($CatChoice -eq -1) {
            if (Show-YesNo -Prompt "Exit Toolbox?" -Default $false) {
                Write-Info "Goodbye."
                return
            }
            continue
        }

        $CategoryKey = $Categories[$CatChoice].Name
        $Scripts = $Categories[$CatChoice].Group

        while ($true) {
            $ScriptItems = foreach ($S in $Scripts) {
                "$($S.Name)  —  $($S.Description)"
            }

            $ScriptChoice = Show-Menu -Title "$($CategoryNames[$CategoryKey])" -Items $ScriptItems -AllowBack

            if ($ScriptChoice -eq -1) { break }

            $SelectedScript = $Scripts[$ScriptChoice]
            Write-Host ""
            Show-InfoPane -ScriptInfo $SelectedScript
            if ($SelectedScript.Kind -eq "PowerShell") {
                Invoke-ToolboxScript -ScriptInfo $SelectedScript
            } else {
                Invoke-ForeignScript -ScriptInfo $SelectedScript
            }
        }
    }
}

function Invoke-ForeignScript {
    <#
    .SYNOPSIS
      Runs (macOS/Linux) or prints (Windows) a bash/Python script with free-text arguments.
    #>
    param([PSObject]$ScriptInfo)

    $Interpreter = if ($ScriptInfo.Kind -eq "bash") { "bash" } else { "python3" }
    $UserArgs = Read-Host "  Arguments (blank for none; see the header above)"
    $ArgList = if ($UserArgs) { @($UserArgs -split '\s+' | Where-Object { $_ }) } else { @() }
    $Command = "$Interpreter `"$($ScriptInfo.Path)`" $UserArgs".Trim()

    if ($OnWindows) {
        Write-Warn "  $($ScriptInfo.Kind) scripts are meant for macOS/Linux. Command to run there:"
        Write-Host "  $Command"
    } elseif (Show-YesNo -Prompt "Run now?" -Default $true) {
        & $Interpreter $ScriptInfo.Path @ArgList
    } else {
        Write-Host "  $Command"
    }
}

function Show-InfoPane {
    param([PSObject]$ScriptInfo)

    $Width = Get-ConsoleWidth
    Write-Rule
    Write-Host "  Selected: $($ScriptInfo.RelativePath)" -ForegroundColor White
    Write-Dim "  $($ScriptInfo.Description)"
    if ($ScriptInfo.WhenToUse)   { Write-Dim "  When to use:  $($ScriptInfo.WhenToUse)" }
    if ($ScriptInfo.Permissions) { Write-Dim "  Permissions:  $($ScriptInfo.Permissions)" }
    if ($ScriptInfo.Safety)      { Write-Dim "  Safety:       $($ScriptInfo.Safety)" }
    if ($ScriptInfo.Platform)    { Write-Dim "  Platform:     $($ScriptInfo.Platform)" }
    if ($ScriptInfo.Examples.Count -gt 0) {
        Write-Dim "  Example:      $(($ScriptInfo.Examples[0] -split '\r?\n')[0])"
    }
    if ($ScriptInfo.Dependencies.Count -gt 0) {
        Write-Dim "  Dependencies: $($ScriptInfo.Dependencies -join ', ')"
    }
    if ($ScriptInfo.RequiresAdmin) {
        Write-Warn "  Requires: Run as Administrator"
    }
    Write-Rule
}

# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

Clear-Host
Show-Banner
Show-MainLoop
