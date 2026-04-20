#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Microsoft Entra Conditional Access policies using the Microsoft Graph PowerShell SDK.

.DESCRIPTION
    This script connects to Microsoft Graph using least-privileged permissions,
    retrieves all Conditional Access (CA) policies, flattens and exports them to
    JSON and CSV, resolves Named Location GUIDs, and produces a separate risk
    findings report flagging weak or misconfigured policies.

    Concepts covered:
      - Conditional Access policy structure (conditions, grantControls, sessionControls)
      - Named Locations (IP ranges, countries)
      - Risk-based Conditional Access (signInRiskLevels, userRiskLevels)
      - Zero Trust principle: verify explicitly, use least privilege, assume breach

.NOTES
    Required Module : Microsoft.Graph.Identity.SignIns (part of Microsoft.Graph SDK)
    Required Scope  : Policy.Read.All
    Graph Endpoint  : v1.0
    Author          : CA Audit Script
    Version         : 2.0
#>

[CmdletBinding()]
param (
    # Output directory for all report files. Defaults to the script's own folder.
    [string]$OutputPath = $PSScriptRoot,

    # If specified, suppresses the Connect-MgGraph interactive prompt (useful in
    # automation with a pre-authenticated context or Managed Identity).
    [switch]$SkipConnect,

    # Tenant ID for authentication. Optional — MgGraph will prompt if omitted.
    [string]$TenantId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Logging Helper ────────────────────────────────────────────────────

function Write-Log {
    <#
    .SYNOPSIS  Writes a timestamped, colour-coded message to the console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')][string]$Level = 'INFO'
    )
    $ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'INFO'    { 'Cyan'    }
        'WARN'    { 'Yellow'  }
        'ERROR'   { 'Red'     }
        'SUCCESS' { 'Green'   }
    }
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color
}

#endregion

#region ── Module Preflight ──────────────────────────────────────────────────

function Assert-GraphModule {
    <#
    .SYNOPSIS
        Ensures Microsoft.Graph.Identity.SignIns is available.
        Installs from PSGallery for the current user if absent.

    .NOTES
        Microsoft.Graph.Identity.SignIns provides:
          - Get-MgIdentityConditionalAccessPolicy
          - Get-MgIdentityConditionalAccessNamedLocation
    #>
    $moduleName = 'Microsoft.Graph.Identity.SignIns'
    Write-Log "Checking for module: $moduleName"

    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Write-Log "Module '$moduleName' not found. Installing for CurrentUser..." -Level WARN
        try {
            Install-Module -Name $moduleName -Scope CurrentUser -Repository PSGallery `
                           -Force -AllowClobber -ErrorAction Stop
            Write-Log "Module installed successfully." -Level SUCCESS
        }
        catch {
            Write-Log "Failed to install '$moduleName': $_" -Level ERROR
            throw
        }
    }
    else {
        Write-Log "Module '$moduleName' is available." -Level SUCCESS
    }

    Import-Module $moduleName -ErrorAction Stop
}

#endregion

#region ── Authentication ────────────────────────────────────────────────────

function Connect-ToGraph {
    <#
    .SYNOPSIS
        Authenticates to Microsoft Graph with least-privileged scopes.

    .NOTES
        Scope used: Policy.Read.All
          - Grants read access to all Conditional Access policies.
          - Does NOT grant write access (principle of least privilege).

        Graph API version: v1.0
          - Conditional Access policies are fully supported on v1.0.
    #>
    param([string]$TenantId)

    Write-Log "Connecting to Microsoft Graph (scope: Policy.Read.All)..."

    $connectParams = @{
        Scopes     = @('Policy.Read.All')
        NoWelcome  = $true
    }
    if ($TenantId) { $connectParams['TenantId'] = $TenantId }

    try {
        Connect-MgGraph @connectParams -ErrorAction Stop
        $ctx = Get-MgContext
        Write-Log "Connected as: $($ctx.Account) | Tenant: $($ctx.TenantId)" -Level SUCCESS
    }
    catch {
        Write-Log "Graph authentication failed: $_" -Level ERROR
        throw
    }
}

#endregion

#region ── Named Location Resolution ────────────────────────────────────────

function Get-NamedLocationMap {
    <#
    .SYNOPSIS
        Retrieves all Named Locations and returns a GUID-to-Name hashtable.

    .NOTES
        Named Locations in Conditional Access represent:
          - IP range locations (trusted/untrusted networks)
          - Country/region locations
        Resolving GUIDs makes audit reports human-readable.
    #>
    Write-Log "Retrieving Named Locations for GUID resolution..."
    $locationMap = @{}

    try {
        $namedLocations = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop
        foreach ($loc in $namedLocations) {
            $locationMap[$loc.Id] = $loc.DisplayName
        }
        Write-Log "Resolved $($locationMap.Count) Named Location(s)." -Level SUCCESS
    }
    catch {
        Write-Log "Could not retrieve Named Locations (non-fatal): $_" -Level WARN
    }

    return $locationMap
}

#endregion

#region ── Policy Retrieval ──────────────────────────────────────────────────

function Get-AllCaPolicies {
    <#
    .SYNOPSIS
        Retrieves all Conditional Access policies from Microsoft Graph v1.0.

    .NOTES
        Uses -All switch to handle pagination automatically.
        CA policy structure (Graph v1.0 /identity/conditionalAccess/policies):
          - conditions       : who/what/where the policy applies
          - grantControls    : access controls granted (MFA, compliant device, etc.)
          - sessionControls  : session-level controls (app enforced, sign-in frequency, etc.)
    #>
    Write-Log "Retrieving all Conditional Access policies..."
    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        Write-Log "Retrieved $($policies.Count) policy/policies." -Level SUCCESS
        return $policies
    }
    catch {
        Write-Log "Failed to retrieve CA policies: $_" -Level ERROR
        throw
    }
}

#endregion

#region ── Policy Flattening ─────────────────────────────────────────────────

function ConvertTo-FlatPolicy {
    <#
    .SYNOPSIS
        Flattens a single CA policy Graph object into a PSCustomObject for CSV export.

    .PARAMETER Policy
        A policy object returned by Get-MgIdentityConditionalAccessPolicy.

    .PARAMETER LocationMap
        Hashtable mapping Named Location GUIDs to display names.

    .NOTES
        CA policy conditions hierarchy:
          conditions.users       → includeUsers / excludeUsers / includeGroups / excludeGroups
          conditions.applications → includeApplications / excludeApplications
          conditions.locations   → includeLocations / excludeLocations
          conditions.platforms   → includePlatforms / excludePlatforms
          conditions.signInRiskLevels / userRiskLevels → risk-based access control
        GrantControls.operator   → 'AND' (all controls) or 'OR' (any control)
        GrantControls.builtInControls → mfa, compliantDevice, domainJoinedDevice, etc.
    #>
    param(
        [Parameter(Mandatory)]$Policy,
        [hashtable]$LocationMap = @{}
    )

    # ── Helper: resolve a list of location GUIDs to names ──────────────────
    $resolveLocations = {
        param([string[]]$ids)
        if (-not $ids) { return '' }
        ($ids | ForEach-Object { if ($LocationMap[$_]) { $LocationMap[$_] } else { $_ } }) -join '; '
    }

    # ── Helper: safely join array values ───────────────────────────────────
    $join = { param([object[]]$arr) if ($arr) { $arr -join '; ' } else { '' } }

    # ── Conditions shortcuts ────────────────────────────────────────────────
    $cond  = $Policy.Conditions
    $users = $cond.Users
    $apps  = $cond.Applications
    $locs  = $cond.Locations
    $plat  = $cond.Platforms
    $grant = $Policy.GrantControls
    $sess  = $Policy.SessionControls

    [PSCustomObject]@{
        # ── Identity ────────────────────────────────────────────────────────
        PolicyId                    = $Policy.Id
        DisplayName                 = $Policy.DisplayName
        State                       = $Policy.State
        CreatedDateTime             = $Policy.CreatedDateTime
        ModifiedDateTime            = $Policy.ModifiedDateTime

        # ── User Conditions ─────────────────────────────────────────────────
        IncludeUsers                = & $join $users.IncludeUsers
        ExcludeUsers                = & $join $users.ExcludeUsers
        IncludeGroups               = & $join $users.IncludeGroups
        ExcludeGroups               = & $join $users.ExcludeGroups
        IncludeRoles                = & $join $users.IncludeRoles
        ExcludeRoles                = & $join $users.ExcludeRoles

        # ── Application Conditions ──────────────────────────────────────────
        IncludeApplications         = & $join $apps.IncludeApplications
        ExcludeApplications         = & $join $apps.ExcludeApplications
        IncludeUserActions          = & $join $apps.IncludeUserActions

        # ── Location Conditions (GUIDs resolved to names) ───────────────────
        IncludeLocations            = & $resolveLocations $locs.IncludeLocations
        ExcludeLocations            = & $resolveLocations $locs.ExcludeLocations

        # ── Platform Conditions ─────────────────────────────────────────────
        IncludePlatforms            = & $join $plat.IncludePlatforms
        ExcludePlatforms            = & $join $plat.ExcludePlatforms

        # ── Risk Conditions (Zero Trust: risk-based access) ─────────────────
        SignInRiskLevels            = & $join $cond.SignInRiskLevels
        UserRiskLevels              = & $join $cond.UserRiskLevels

        # ── Client App Types ────────────────────────────────────────────────
        ClientAppTypes              = & $join $cond.ClientAppTypes

        # ── Grant Controls ──────────────────────────────────────────────────
        # builtInControls: mfa, compliantDevice, domainJoinedDevice,
        #                  approvedApplication, compliantApplication
        GrantOperator               = $grant.Operator
        GrantBuiltInControls        = & $join $grant.BuiltInControls
        GrantCustomAuthFactors      = & $join $grant.CustomAuthenticationFactors
        GrantTermsOfUse             = & $join $grant.TermsOfUse
        GrantAuthStrengthId         = $grant.AuthenticationStrength.Id

        # ── Session Controls ────────────────────────────────────────────────
        # sessionControls govern token lifetime, app-enforced restrictions, MCAS
        SessionAppEnforcedRestrictions = [bool]$sess.ApplicationEnforcedRestrictions.IsEnabled
        SessionCloudAppSecurity     = $sess.CloudAppSecurity.CloudAppSecurityType
        SessionSignInFrequencyValue = $sess.SignInFrequency.Value
        SessionSignInFrequencyUnit  = $sess.SignInFrequency.Type
        SessionPersistentBrowser    = $sess.PersistentBrowser.Mode
        SessionContinuousAccessEval = $sess.ContinuousAccessEvaluation.Mode
        SessionSecureSignInSession  = $sess.SecureSignInSession.IsEnabled
    }
}

#endregion

#region ── Risk Analysis Engine ──────────────────────────────────────────────

function Invoke-CaRiskAnalysis {
    <#
    .SYNOPSIS
        Evaluates each Conditional Access policy against security best-practice rules
        and returns a collection of finding objects.

    .NOTES
        Risk rules implemented:
          RULE-01 : Policy is Disabled
                    Disabled policies provide zero enforcement. Review if intentional.
          RULE-02 : Policy is in Report-Only mode
                    Report-only policies do not enforce controls. Useful during rollout
                    but should not remain report-only in production indefinitely.
          RULE-03 : No MFA requirement
                    MFA is the single most effective control against credential attacks.
                    Policies lacking 'mfa' in grantControls.builtInControls are flagged.
          RULE-04 : Targets All Users with no exclusions
                    CA policies scoped to 'All' users with no user/group exclusions
                    create broad blast-radius risk if misconfigured.
          RULE-05 : No meaningful conditions defined
                    Policies with 'All' apps and 'All' users but no location, platform,
                    or risk conditions are overly broad and may be poorly understood.
          RULE-06 : No device compliance or hybrid join requirement
                    Zero Trust requires device health verification. Policies missing
                    'compliantDevice' or 'domainJoinedDevice' leave device posture unchecked.
    #>
    param(
        [Parameter(Mandatory)][object[]]$Policies
    )

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($policy in $Policies) {
        $name        = $policy.DisplayName
        $state       = $policy.State
        $cond        = $policy.Conditions
        $users       = $cond.Users
        $apps        = $cond.Applications
        $grant       = $policy.GrantControls
        $controls    = @($grant.BuiltInControls)   # may be $null
        $includeUsers = @($users.IncludeUsers)
        $excludeUsers = @($users.ExcludeUsers)
        $excludeGroups = @($users.ExcludeGroups)

        # ── Helper: add a finding ───────────────────────────────────────────
        $addFinding = {
            param([string]$RuleId, [string]$Severity, [string]$Finding, [string]$Recommendation)
            $findings.Add([PSCustomObject]@{
                PolicyName      = $name
                PolicyId        = $policy.Id
                PolicyState     = $state
                RuleId          = $RuleId
                Severity        = $Severity
                Finding         = $Finding
                Recommendation  = $Recommendation
            })
        }

        # ── RULE-01: Disabled policy ────────────────────────────────────────
        if ($state -eq 'disabled') {
            & $addFinding `
                -RuleId         'RULE-01' `
                -Severity       'Medium' `
                -Finding        'Policy is disabled and not enforcing any controls.' `
                -Recommendation 'Review whether this policy is intentionally disabled. Enable or delete if no longer needed.'
        }

        # ── RULE-02: Report-only mode ───────────────────────────────────────
        if ($state -eq 'enabledForReportingButNotEnforcing') {
            & $addFinding `
                -RuleId         'RULE-02' `
                -Severity       'Medium' `
                -Finding        'Policy is in report-only mode. Controls are NOT enforced.' `
                -Recommendation 'Validate policy impact in Sign-In Logs and transition to Enabled state.'
        }

        # ── RULE-03: No MFA requirement ─────────────────────────────────────
        $hasMfa = $controls -contains 'mfa'
        $hasAuthStrength = $null -ne $grant.AuthenticationStrength.Id
        if (-not $hasMfa -and -not $hasAuthStrength) {
            & $addFinding `
                -RuleId         'RULE-03' `
                -Severity       'High' `
                -Finding        'Policy does not require MFA or an Authentication Strength.' `
                -Recommendation 'Add MFA (or a phishing-resistant Authentication Strength) to grantControls.builtInControls.'
        }

        # ── RULE-04: All users, no exclusions ───────────────────────────────
        $targetsAllUsers = $includeUsers -contains 'All'
        $hasExclusions   = ($excludeUsers.Count -gt 0) -or ($excludeGroups.Count -gt 0)
        if ($targetsAllUsers -and -not $hasExclusions) {
            & $addFinding `
                -RuleId         'RULE-04' `
                -Severity       'High' `
                -Finding        'Policy targets All Users with zero user or group exclusions.' `
                -Recommendation 'Exclude at least one break-glass/emergency-access account or group to prevent lockout.'
        }

        # ── RULE-05: No meaningful conditions ───────────────────────────────
        $allApps      = @($apps.IncludeApplications) -contains 'All'
        $noLocCond    = (-not $cond.Locations.IncludeLocations) -or
                        (@($cond.Locations.IncludeLocations) -contains 'All')
        $noRiskCond   = (-not $cond.SignInRiskLevels) -and (-not $cond.UserRiskLevels)
        $noPlatCond   = (-not $cond.Platforms.IncludePlatforms) -or
                        (@($cond.Platforms.IncludePlatforms) -contains 'all')

        if ($targetsAllUsers -and $allApps -and $noLocCond -and $noRiskCond -and $noPlatCond) {
            & $addFinding `
                -RuleId         'RULE-05' `
                -Severity       'Low' `
                -Finding        'Policy has very broad conditions: All Users, All Apps, no location/platform/risk scoping.' `
                -Recommendation 'Review whether narrower conditions (location, platform, risk level) are appropriate to reduce blast radius.'
        }

        # ── RULE-06: No device compliance / hybrid join ──────────────────────
        $hasDeviceControl = ($controls -contains 'compliantDevice') -or
                            ($controls -contains 'domainJoinedDevice')
        if (-not $hasDeviceControl -and $state -eq 'enabled') {
            & $addFinding `
                -RuleId         'RULE-06' `
                -Severity       'Medium' `
                -Finding        'Policy does not require device compliance or Hybrid Azure AD Join.' `
                -Recommendation 'Consider adding compliantDevice or domainJoinedDevice to enforce device health (Zero Trust device posture).'
        }
    }

    return $findings
}

#endregion

#region ── Summary Statistics ────────────────────────────────────────────────

function Write-AuditSummary {
    <#
    .SYNOPSIS
        Outputs a human-readable summary dashboard to the console.
    #>
    param(
        [object[]]$FlatPolicies,
        [object[]]$Findings
    )

    $total       = $FlatPolicies.Count
    $enabled     = ($FlatPolicies | Where-Object State -eq 'enabled').Count
    $disabled    = ($FlatPolicies | Where-Object State -eq 'disabled').Count
    $reportOnly  = ($FlatPolicies | Where-Object State -eq 'enabledForReportingButNotEnforcing').Count
    $withMfa     = ($FlatPolicies | Where-Object {
                        $_.GrantBuiltInControls -match 'mfa' -or
                        $_.GrantAuthStrengthId  -ne ''
                   }).Count
    $mfaPct      = if ($total -gt 0) { [math]::Round(($withMfa / $total) * 100, 1) } else { 0 }

    $highFindings   = ($Findings | Where-Object Severity -eq 'High').Count
    $medFindings    = ($Findings | Where-Object Severity -eq 'Medium').Count
    $lowFindings    = ($Findings | Where-Object Severity -eq 'Low').Count

    $divider = '─' * 55
    Write-Host ""
    Write-Host $divider                              -ForegroundColor DarkCyan
    Write-Host "  CONDITIONAL ACCESS AUDIT SUMMARY" -ForegroundColor White
    Write-Host $divider                              -ForegroundColor DarkCyan
    Write-Host ("  Total Policies       : {0}"   -f $total)       -ForegroundColor White
    Write-Host ("  Enabled              : {0}"   -f $enabled)     -ForegroundColor Green
    Write-Host ("  Report-Only          : {0}"   -f $reportOnly)  -ForegroundColor Yellow
    Write-Host ("  Disabled             : {0}"   -f $disabled)    -ForegroundColor Red
    Write-Host ("  Policies with MFA    : {0} ({1}%)" -f $withMfa, $mfaPct) -ForegroundColor Cyan
    Write-Host $divider                              -ForegroundColor DarkCyan
    Write-Host "  FINDINGS"                          -ForegroundColor White
    Write-Host ("  High Severity        : {0}"   -f $highFindings)  -ForegroundColor Red
    Write-Host ("  Medium Severity      : {0}"   -f $medFindings)   -ForegroundColor Yellow
    Write-Host ("  Low Severity         : {0}"   -f $lowFindings)   -ForegroundColor Cyan
    Write-Host ("  Total Findings       : {0}"   -f $Findings.Count) -ForegroundColor White
    Write-Host $divider                              -ForegroundColor DarkCyan
    Write-Host ""
}

#endregion

#region ── File Export Helpers ───────────────────────────────────────────────

function Export-ToJson {
    param(
        [Parameter(Mandatory)][object[]]$Data,
        [Parameter(Mandatory)][string]$FilePath
    )
    # Depth 10 ensures no nested Graph object is truncated.
    # Conditional Access policy objects can be 4–6 levels deep.
    $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding utf8 -Force
    Write-Log "JSON export written: $FilePath" -Level SUCCESS
}

function Export-ToCsv {
    param(
        [Parameter(Mandatory)][object[]]$Data,
        [Parameter(Mandatory)][string]$FilePath
    )
    $Data | Export-Csv -Path $FilePath -NoTypeInformation -Encoding utf8 -Force
    Write-Log "CSV export written: $FilePath" -Level SUCCESS
}

#endregion

#region ── MAIN ──────────────────────────────────────────────────────────────

try {
    Write-Log "=== Conditional Access Policy Audit Started ===" -Level INFO

    # ── Step 1: Ensure output directory exists ──────────────────────────────
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Log "Created output directory: $OutputPath"
    }

    $jsonPath     = Join-Path $OutputPath 'CA-Policies.json'
    $csvPath      = Join-Path $OutputPath 'CA-Policies.csv'
    $findingsPath = Join-Path $OutputPath 'CA-RiskyFindings.csv'

    # ── Step 2: Module check ────────────────────────────────────────────────
    Assert-GraphModule

    # ── Step 3: Authenticate ────────────────────────────────────────────────
    if (-not $SkipConnect) {
        $connectArgs = @{}
        if ($TenantId) { $connectArgs['TenantId'] = $TenantId }
        Connect-ToGraph @connectArgs
    }
    else {
        Write-Log "SkipConnect specified — using existing MgGraph context." -Level WARN
        $ctx = Get-MgContext
        if (-not $ctx) {
            throw "No active Microsoft Graph context found. Remove -SkipConnect or run Connect-MgGraph first."
        }
        Write-Log "Using context: $($ctx.Account) | Tenant: $($ctx.TenantId)" -Level INFO
    }

    # ── Step 4: Retrieve Named Locations for GUID resolution ────────────────
    $locationMap = Get-NamedLocationMap

    # ── Step 5: Retrieve all CA policies ────────────────────────────────────
    $rawPolicies = Get-AllCaPolicies

    if ($rawPolicies.Count -eq 0) {
        Write-Log "No Conditional Access policies found in this tenant." -Level WARN
        exit 0
    }

    # ── Step 6: Export full raw objects to JSON (deep, unmodified) ──────────
    # Preserves every nested property exactly as returned by Graph API v1.0.
    Export-ToJson -Data $rawPolicies -FilePath $jsonPath

    # ── Step 7: Flatten each policy for CSV export ───────────────────────────
    Write-Log "Flattening $($rawPolicies.Count) policies for CSV export..."
    $flatPolicies = $rawPolicies | ForEach-Object {
        ConvertTo-FlatPolicy -Policy $_ -LocationMap $locationMap
    }
    Export-ToCsv -Data $flatPolicies -FilePath $csvPath

    # ── Step 8: Run risk analysis ────────────────────────────────────────────
    Write-Log "Running risk analysis against $($rawPolicies.Count) policies..."
    $findings = Invoke-CaRiskAnalysis -Policies $rawPolicies

    if ($findings.Count -gt 0) {
        # Sort findings: High → Medium → Low, then by PolicyName
        $severityOrder = @{ 'High' = 1; 'Medium' = 2; 'Low' = 3 }
        $sortedFindings = $findings | Sort-Object {
            $severityOrder[$_.Severity]
        }, PolicyName

        Export-ToCsv -Data $sortedFindings -FilePath $findingsPath
        Write-Log "$($findings.Count) finding(s) written to: $findingsPath" -Level WARN
    }
    else {
        Write-Log "No risk findings detected. Writing empty findings file." -Level SUCCESS
        [PSCustomObject]@{
            PolicyName     = 'N/A'
            PolicyId       = 'N/A'
            PolicyState    = 'N/A'
            RuleId         = 'N/A'
            Severity       = 'N/A'
            Finding        = 'No risky configurations detected.'
            Recommendation = 'N/A'
        } | Export-Csv -Path $findingsPath -NoTypeInformation -Encoding utf8 -Force
    }

    # ── Step 9: Print summary dashboard ─────────────────────────────────────
    Write-AuditSummary -FlatPolicies $flatPolicies -Findings $findings

    Write-Log "Output files:" -Level INFO
    Write-Log "  JSON (full)    → $jsonPath"
    Write-Log "  CSV  (summary) → $csvPath"
    Write-Log "  CSV  (findings)→ $findingsPath"
    Write-Log "=== Audit Completed Successfully ===" -Level SUCCESS
}
catch {
    Write-Log "FATAL: $($_.Exception.Message)" -Level ERROR
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level ERROR
    exit 1
}
finally {
    # Disconnect only if this script established the connection.
    if (-not $SkipConnect -and (Get-MgContext)) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Disconnected from Microsoft Graph." -Level INFO
    }
}

#endregion
