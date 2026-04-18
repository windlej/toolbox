<#
.SYNOPSIS
    Audits Microsoft Entra ID Conditional Access policies and exports configuration details with identified security risks.

.DESCRIPTION
    This script connects to Microsoft Graph using modern authentication, retrieves all Conditional Access policies,
    analyzes them against security best practices, and exports comprehensive audit reports in CSV, JSON, and HTML formats.
    
    The script identifies risky or weak configurations including missing MFA requirements, legacy authentication exposure,
    disabled policies, and overly permissive grant controls.

.USE CASE
    Ideal for MSPs and enterprises performing regular Conditional Access audits:
    - Quarterly compliance reviews for regulatory requirements
    - Post-incident security assessments
    - Tenant-wide security posture evaluations
    - Proof of secure configuration for customer dashboards
    - Automated compliance reporting pipelines

.REQUIRED PERMISSIONS
    Microsoft Graph API Scopes:
    - Policy.Read.All (read Conditional Access policies)
    
    Azure AD Application Permissions (if using app-only authentication):
    - Application.Read.All
    - Directory.Read.All
    
    Delegated Permissions (if using user authentication):
    - Policy.Read.All
    - Directory.Read.All

.EXAMPLE
    # Interactive authentication
    PS C:\> .\Audit-ConditionalAccessPolicies.ps1 -TenantId "contoso.onmicrosoft.com" -OutputPath "C:\Reports"
    
    # With verbose logging
    PS C:\> .\Audit-ConditionalAccessPolicies.ps1 -TenantId "contoso.onmicrosoft.com" -Verbose
    
    # Filter only enabled policies
    PS C:\> .\Audit-ConditionalAccessPolicies.ps1 -TenantId "contoso.onmicrosoft.com" -EnabledOnly
    
    # Minimal output
    PS C:\> .\Audit-ConditionalAccessPolicies.ps1 -TenantId "contoso.onmicrosoft.com" -QuietMode

.NOTES
    Author: Cloud Engineering Team
    Version: 2.0
    Requires: Microsoft.Graph.Identity.SignIns module v2.0+
    Last Modified: April 2026
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path $env:TEMP "CAPolicy_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss')"),
    
    [Parameter(Mandatory = $false)]
    [switch]$EnabledOnly = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$QuietMode = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipHTMLReport = $false
)

#region Variables
$script:ErrorCount = 0
$script:WarningCount = 0
$script:Policies = @()
$script:RiskAnalysis = @()

$RiskSeverityMap = @{
    'Critical' = 4
    'High'     = 3
    'Medium'   = 2
    'Low'      = 1
}
#endregion

#region Logging Functions
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Verbose')]
        [string]$Level = 'Info'
    )
    
    process {
        if ($QuietMode -and $Level -in @('Info', 'Verbose')) { return }
        
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $color = switch ($Level) {
            'Info'    { 'Cyan' }
            'Warning' { 'Yellow' }
            'Error'   { 'Red' }
            'Success' { 'Green' }
            'Verbose' { 'Gray' }
        }
        
        $output = "[$timestamp] [$Level] $Message"
        Write-Host $output -ForegroundColor $color
        
        if ($Level -eq 'Warning') { $script:WarningCount++ }
        if ($Level -eq 'Error') { $script:ErrorCount++ }
    }
}

function Write-VerboseLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Message
    )
    
    process {
        if ($VerbosePreference -eq 'Continue') {
            Write-Log -Message $Message -Level 'Verbose'
        }
    }
}
#endregion

#region Authentication
function Connect-ToGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )
    
    try {
        Write-Log "Connecting to Microsoft Graph (Tenant: $TenantId)..." -Level 'Info'
        
        $graphScopes = @('Policy.Read.All', 'Directory.Read.All')
        Write-VerboseLog "Required scopes: $($graphScopes -join ', ')"
        
        Connect-MgGraph -TenantId $TenantId -Scopes $graphScopes -NoWelcome -ErrorAction Stop | Out-Null
        
        Write-Log "Successfully authenticated to Microsoft Graph" -Level 'Success'
        Write-VerboseLog "Connected context: $(Get-MgContext | ConvertTo-Json -Depth 1)"
        
        return $true
    }
    catch {
        Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level 'Error'
        throw $_
    }
}
#endregion

#region Policy Retrieval
function Get-ConditionalAccessPolicies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$EnabledOnly
    )
    
    try {
        Write-Log "Retrieving Conditional Access policies..." -Level 'Info'
        
        $allPolicies = Get-MgBetaIdentityConditionalAccessPolicy -All -ErrorAction Stop
        
        if ($null -eq $allPolicies) {
            Write-Log "No Conditional Access policies found in tenant" -Level 'Warning'
            return @()
        }
        
        Write-VerboseLog "Retrieved $($allPolicies.Count) total policies"
        
        if ($EnabledOnly) {
            $policies = $allPolicies | Where-Object { $_.State -eq 'enabled' }
            Write-Log "Filtered to $($policies.Count) enabled policies" -Level 'Info'
        }
        else {
            $policies = $allPolicies
        }
        
        return $policies
    }
    catch {
        Write-Log "Failed to retrieve Conditional Access policies: $($_.Exception.Message)" -Level 'Error'
        throw $_
    }
}
#endregion

#region Risk Analysis
function Analyze-PolicyRisk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $Policy
    )
    
    process {
        Write-VerboseLog "Analyzing policy: $($Policy.DisplayName) (ID: $($Policy.Id))"
        
        $riskFindings = @()
        $riskScore = 0
        $maxRiskScore = 0
        
        # Risk 1: Policy is disabled
        $maxRiskScore += 3
        if ($Policy.State -eq 'disabled') {
            $riskFindings += @{
                Check       = 'Policy Status'
                Severity    = 'High'
                Finding     = 'Policy is disabled'
                Impact      = 'This policy provides no protection in its current state'
                Recommended = 'Enable the policy or document the reason for disablement'
            }
            $riskScore += 3
        }
        
        # Risk 2: No users or groups assigned
        $maxRiskScore += 2
        $hasUsers = $Policy.Conditions.Users.IncludeUsers.Count -gt 0
        $hasGroups = $Policy.Conditions.Users.IncludeGroups.Count -gt 0
        
        if (-not $hasUsers -and -not $hasGroups) {
            $riskFindings += @{
                Check       = 'User/Group Assignment'
                Severity    = 'High'
                Finding     = 'No users or groups assigned'
                Impact      = 'Policy applies to no one and is effectively inactive'
                Recommended = 'Assign target users or groups, or delete the policy'
            }
            $riskScore += 2
        }
        
        # Risk 3: All users included without exclusions
        $maxRiskScore += 1
        $includesAllUsers = $Policy.Conditions.Users.IncludeUsers -contains 'All'
        $hasExclusions = $Policy.Conditions.Users.ExcludeUsers.Count -gt 0 -or $Policy.Conditions.Users.ExcludeGroups.Count -gt 0
        
        if ($includesAllUsers -and -not $hasExclusions) {
            $riskFindings += @{
                Check       = 'User Scope'
                Severity    = 'Medium'
                Finding     = 'All users targeted without exclusions'
                Impact      = 'Policy applies universally; misconfiguration could affect all users'
                Recommended = 'Define exclusions for break-glass or emergency accounts'
            }
            $riskScore += 1
        }
        
        # Risk 4: No applications assigned
        $maxRiskScore += 2
        $hasApps = $Policy.Conditions.Applications.IncludeApplications.Count -gt 0
        
        if (-not $hasApps) {
            $riskFindings += @{
                Check       = 'Application Assignment'
                Severity    = 'High'
                Finding     = 'No applications assigned'
                Impact      = 'Policy applies to no applications and is ineffective'
                Recommended = 'Assign target applications or delete the policy'
            }
            $riskScore += 2
        }
        
        # Risk 5: No conditions defined
        $maxRiskScore += 2
        $hasConditions = ($Policy.Conditions.Applications.IncludeApplications.Count -gt 0) -or
                         ($Policy.Conditions.Users.IncludeUsers.Count -gt 0) -or
                         ($Policy.Conditions.Users.IncludeGroups.Count -gt 0) -or
                         ($null -ne $Policy.Conditions.SignInRiskLevels -and $Policy.Conditions.SignInRiskLevels.Count -gt 0) -or
                         ($null -ne $Policy.Conditions.UserRiskLevels -and $Policy.Conditions.UserRiskLevels.Count -gt 0) -or
                         ($null -ne $Policy.Conditions.Platforms -and $Policy.Conditions.Platforms.Count -gt 0)
        
        if (-not $hasConditions) {
            $riskFindings += @{
                Check       = 'Policy Conditions'
                Severity    = 'High'
                Finding     = 'No conditions defined'
                Impact      = 'Policy has no trigger conditions and cannot function'
                Recommended = 'Define conditions (users, apps, sign-in risk, etc.) or delete the policy'
            }
            $riskScore += 2
        }
        
        # Risk 6: No MFA in grant controls
        $maxRiskScore += 3
        $requiresMFA = $false
        
        if ($Policy.GrantControls.Operator -eq 'AND') {
            $requiresMFA = 'mfa' -in $Policy.GrantControls.BuiltInControls -or
                           'compliantDevice' -in $Policy.GrantControls.BuiltInControls
        }
        elseif ($Policy.GrantControls.Operator -eq 'OR') {
            $requiresMFA = 'mfa' -in $Policy.GrantControls.BuiltInControls -or
                           'compliantDevice' -in $Policy.GrantControls.BuiltInControls
        }
        
        if (-not $requiresMFA -and $null -ne $Policy.GrantControls.BuiltInControls) {
            $riskFindings += @{
                Check       = 'MFA Requirement'
                Severity    = 'High'
                Finding     = 'Grant controls do not require MFA'
                Impact      = 'Users can access protected resources without strong authentication'
                Recommended = 'Add "Require multi-factor authentication" to grant controls'
            }
            $riskScore += 3
        }
        
        # Risk 7: Legacy authentication not explicitly blocked
        $maxRiskScore += 2
        $blocksLegacy = $Policy.GrantControls.BuiltInControls -contains 'blockLegacyAuthentication'
        $targetsCRModernClients = $Policy.Conditions.ClientAppTypes -contains 'mobileAppsAndDesktopClients' -or 
                                  $Policy.Conditions.ClientAppTypes -contains 'other'
        
        if (-not $blocksLegacy -and $targetsCRModernClients) {
            $riskFindings += @{
                Check       = 'Legacy Authentication'
                Severity    = 'Medium'
                Finding     = 'Legacy authentication not blocked'
                Impact      = 'Non-modern authentication methods may bypass protections'
                Recommended = 'Add "Block legacy authentication" control or ensure it is blocked elsewhere'
            }
            $riskScore += 2
        }
        
        # Risk 8: No device compliance requirement
        $maxRiskScore += 2
        $requiresCompliance = 'compliantDevice' -in $Policy.GrantControls.BuiltInControls -or
                              'domainJoinedDevice' -in $Policy.GrantControls.BuiltInControls
        
        if (-not $requiresCompliance -and $null -ne $Policy.GrantControls.BuiltInControls) {
            $riskFindings += @{
                Check       = 'Device Compliance'
                Severity    = 'Medium'
                Finding     = 'No device compliance requirement'
                Impact      = 'Non-compliant or unmanaged devices may access resources'
                Recommended = 'Require compliant or domain-joined devices where appropriate'
            }
            $riskScore += 2
        }
        
        # Risk 9: No sign-in risk or user risk conditions
        $maxRiskScore += 1
        $hasSignInRiskCondition = $null -ne $Policy.Conditions.SignInRiskLevels -and $Policy.Conditions.SignInRiskLevels.Count -gt 0
        $hasUserRiskCondition = $null -ne $Policy.Conditions.UserRiskLevels -and $Policy.Conditions.UserRiskLevels.Count -gt 0
        
        if (-not $hasSignInRiskCondition -and -not $hasUserRiskCondition) {
            $riskFindings += @{
                Check       = 'Risk-Based Conditions'
                Severity    = 'Low'
                Finding     = 'No sign-in risk or user risk conditions'
                Impact      = 'Risk-based access controls are not evaluated'
                Recommended = 'Consider adding risk-based conditions for high-risk scenarios'
            }
            $riskScore += 1
        }
        
        # Risk 10: Weak session controls
        $maxRiskScore += 1
        $hasSessionControls = $null -ne $Policy.SessionControls -and
                              ($Policy.SessionControls.ApplicationEnforcedRestrictions -eq $true -or
                               $Policy.SessionControls.PersistentBrowser -eq $true -or
                               $null -ne $Policy.SessionControls.SignInFrequency)
        
        if (-not $hasSessionControls) {
            $riskFindings += @{
                Check       = 'Session Controls'
                Severity    = 'Low'
                Finding     = 'No or weak session controls configured'
                Impact      = 'Session duration and restrictions are not enforced'
                Recommended = 'Configure session controls such as sign-in frequency or browser restrictions'
            }
            $riskScore += 1
        }
        
        # Determine overall severity
        $severityPercentage = if ($maxRiskScore -gt 0) { [math]::Round(($riskScore / $maxRiskScore) * 100) } else { 0 }
        
        $overallSeverity = if ($riskFindings.Count -eq 0) {
            'Low'
        }
        elseif ($severityPercentage -ge 70) {
            'Critical'
        }
        elseif ($severityPercentage -ge 50) {
            'High'
        }
        elseif ($severityPercentage -ge 30) {
            'Medium'
        }
        else {
            'Low'
        }
        
        return @{
            PolicyId         = $Policy.Id
            DisplayName      = $Policy.DisplayName
            State            = $Policy.State
            CreatedDateTime  = $Policy.CreatedDateTime
            ModifiedDateTime = $Policy.ModifiedDateTime
            OverallSeverity  = $overallSeverity
            FindingsCount    = $riskFindings.Count
            RiskScore        = "$riskScore/$maxRiskScore"
            Findings         = $riskFindings
        }
    }
}
#endregion

#region Export Functions
function Export-ResultsToCSV {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Policies,
        
        [Parameter(Mandatory = $true)]
        [array]$RiskAnalysis,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    try {
        Write-Log "Exporting results to CSV format..." -Level 'Info'
        
        # Policy configurations CSV
        $policiesCSV = @()
        foreach ($policy in $Policies) {
            $policiesCSV += @{
                'Policy ID'           = $policy.Id
                'Display Name'        = $policy.DisplayName
                'State'               = $policy.State
                'Created'             = $policy.CreatedDateTime
                'Modified'            = $policy.ModifiedDateTime
                'Grant Operator'      = $policy.GrantControls.Operator
                'Grant Controls'      = ($policy.GrantControls.BuiltInControls -join '; ')
                'Include Users'       = ($policy.Conditions.Users.IncludeUsers -join '; ')
                'Include Groups'      = ($policy.Conditions.Users.IncludeGroups -join '; ')
                'Exclude Users'       = ($policy.Conditions.Users.ExcludeUsers -join '; ')
                'Exclude Groups'      = ($policy.Conditions.Users.ExcludeGroups -join '; ')
                'Include Applications' = ($policy.Conditions.Applications.IncludeApplications -join '; ')
                'Platforms'           = ($policy.Conditions.Platforms.IncludePlatforms -join '; ')
                'Sign-in Risk Levels' = ($policy.Conditions.SignInRiskLevels -join '; ')
                'User Risk Levels'    = ($policy.Conditions.UserRiskLevels -join '; ')
            }
        }
        $policiesCSV | Export-Csv -Path "$OutputPath\CA_Policies_Configuration.csv" -NoTypeInformation -Force
        Write-VerboseLog "Exported $($policiesCSV.Count) policy configurations to CSV"
        
        # Risk summary CSV
        $riskCSV = @()
        foreach ($risk in $RiskAnalysis) {
            $riskCSV += @{
                'Policy ID'        = $risk.PolicyId
                'Policy Name'      = $risk.DisplayName
                'Policy State'     = $risk.State
                'Overall Severity' = $risk.OverallSeverity
                'Finding Count'    = $risk.FindingsCount
                'Risk Score'       = $risk.RiskScore
                'Findings'         = ($risk.Findings.Finding -join ' | ')
            }
        }
        $riskCSV | Export-Csv -Path "$OutputPath\CA_Policies_RiskSummary.csv" -NoTypeInformation -Force
        Write-VerboseLog "Exported risk summary to CSV"
        
        Write-Log "CSV export completed successfully" -Level 'Success'
    }
    catch {
        Write-Log "Failed to export CSV: $($_.Exception.Message)" -Level 'Error'
        throw $_
    }
}

function Export-ResultsToJSON {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Policies,
        
        [Parameter(Mandatory = $true)]
        [array]$RiskAnalysis,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    
    try {
        Write-Log "Exporting results to JSON format..." -Level 'Info'
        
        $jsonData = @{
            'ExportMetadata' = @{
                'ExportDate'     = Get-Date -Format 'o'
                'TenantId'       = $TenantId
                'PolicyCount'    = $Policies.Count
                'AnalyzedCount'  = $RiskAnalysis.Count
            }
            'Policies'       = $Policies
            'RiskAnalysis'   = $RiskAnalysis
        }
        
        $jsonData | ConvertTo-Json -Depth 10 | Set-Content "$OutputPath\CA_Policies_Complete.json" -Force
        Write-VerboseLog "Exported complete policy and risk data to JSON"
        
        Write-Log "JSON export completed successfully" -Level 'Success'
    }
    catch {
        Write-Log "Failed to export JSON: $($_.Exception.Message)" -Level 'Error'
        throw $_
    }
}

function Export-ResultsToHTML {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$RiskAnalysis,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )
    
    try {
        Write-Log "Generating HTML report..." -Level 'Info'
        
        # Summary statistics
        $totalPolicies = $RiskAnalysis.Count
        $criticalCount = @($RiskAnalysis | Where-Object { $_.OverallSeverity -eq 'Critical' }).Count
        $highCount = @($RiskAnalysis | Where-Object { $_.OverallSeverity -eq 'High' }).Count
        $mediumCount = @($RiskAnalysis | Where-Object { $_.OverallSeverity -eq 'Medium' }).Count
        $lowCount = @($RiskAnalysis | Where-Object { $_.OverallSeverity -eq 'Low' }).Count
        
        $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Conditional Access Policy Audit Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: linear-gradient(135deg, #0078d4 0%, #106ebe 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .summary-card h3 {
            font-size: 2.5em;
            margin: 10px 0;
            font-weight: bold;
        }
        .summary-card p {
            color: #666;
            font-size: 0.95em;
        }
        .critical { color: #d13438; }
        .high { color: #e81123; }
        .medium { color: #ffc107; }
        .low { color: #107c10; }
        .section {
            background: white;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 25px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .section h2 {
            color: #0078d4;
            border-bottom: 3px solid #0078d4;
            padding-bottom: 10px;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        .policy-card {
            border-left: 5px solid #ddd;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 4px;
            background-color: #fafbfc;
        }
        .policy-card.critical { border-left-color: #d13438; background-color: #fff4f4; }
        .policy-card.high { border-left-color: #e81123; background-color: #fff5f5; }
        .policy-card.medium { border-left-color: #ffc107; background-color: #fffbf0; }
        .policy-card.low { border-left-color: #107c10; background-color: #f4fdf4; }
        .policy-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .policy-name {
            font-size: 1.3em;
            font-weight: 600;
            color: #0078d4;
        }
        .severity-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.85em;
        }
        .severity-badge.critical {
            background-color: #d13438;
            color: white;
        }
        .severity-badge.high {
            background-color: #e81123;
            color: white;
        }
        .severity-badge.medium {
            background-color: #ffc107;
            color: #333;
        }
        .severity-badge.low {
            background-color: #107c10;
            color: white;
        }
        .findings {
            margin-top: 15px;
        }
        .finding-item {
            background: white;
            padding: 12px;
            margin: 10px 0;
            border-radius: 4px;
            border-left: 4px solid #ff6b6b;
        }
        .finding-title {
            font-weight: 600;
            color: #333;
            margin-bottom: 5px;
        }
        .finding-impact {
            font-size: 0.9em;
            color: #666;
            margin: 5px 0;
        }
        .finding-recommendation {
            font-size: 0.9em;
            color: #107c10;
            font-style: italic;
            margin-top: 8px;
            padding-top: 8px;
            border-top: 1px solid #eee;
        }
        .metadata {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            font-size: 0.9em;
            color: #666;
            margin-top: 10px;
        }
        .metadata span {
            display: flex;
            justify-content: space-between;
        }
        footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
            margin-top: 40px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th {
            background-color: #f0f0f0;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #0078d4;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #eee;
        }
        tr:hover {
            background-color: #f9f9f9;
        }
        .no-findings {
            padding: 20px;
            background-color: #f0fdf4;
            border-left: 4px solid #107c10;
            border-radius: 4px;
            color: #107c10;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Conditional Access Policy Audit Report</h1>
            <p>Tenant: $TenantId</p>
            <p>Generated: $(Get-Date -Format 'dddd, MMMM dd, yyyy HH:mm:ss')</p>
        </header>
        
        <div class="summary">
            <div class="summary-card">
                <p>Total Policies</p>
                <h3>$totalPolicies</h3>
            </div>
            <div class="summary-card">
                <p>Critical Severity</p>
                <h3 class="critical">$criticalCount</h3>
            </div>
            <div class="summary-card">
                <p>High Severity</p>
                <h3 class="high">$highCount</h3>
            </div>
            <div class="summary-card">
                <p>Medium Severity</p>
                <h3 class="medium">$mediumCount</h3>
            </div>
            <div class="summary-card">
                <p>Low Severity</p>
                <h3 class="low">$lowCount</h3>
            </div>
        </div>
        
        <div class="section">
            <h2>Policy Audit Details</h2>
            <table>
                <thead>
                    <tr>
                        <th>Policy Name</th>
                        <th>State</th>
                        <th>Severity</th>
                        <th>Issues Found</th>
                        <th>Risk Score</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($risk in $RiskAnalysis | Sort-Object -Property @{Expression={$RiskSeverityMap[$_.OverallSeverity]}; Descending=$true}) {
            $html += @"
                    <tr>
                        <td>$($risk.DisplayName)</td>
                        <td>$($risk.State)</td>
                        <td><span class="severity-badge $($risk.OverallSeverity.ToLower())">$($risk.OverallSeverity)</span></td>
                        <td>$($risk.FindingsCount)</td>
                        <td>$($risk.RiskScore)</td>
                    </tr>
"@
        }
        
        $html += @"
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Detailed Findings</h2>
"@
        
        foreach ($risk in $RiskAnalysis | Sort-Object -Property @{Expression={$RiskSeverityMap[$_.OverallSeverity]}; Descending=$true}) {
            $severityClass = $risk.OverallSeverity.ToLower()
            
            $html += @"
            <div class="policy-card $severityClass">
                <div class="policy-header">
                    <div class="policy-name">$($risk.DisplayName)</div>
                    <span class="severity-badge $severityClass">$($risk.OverallSeverity)</span>
                </div>
                <div class="metadata">
                    <span><strong>Policy ID:</strong> $($risk.PolicyId)</span>
                    <span><strong>State:</strong> $($risk.State)</span>
                    <span><strong>Created:</strong> $($risk.CreatedDateTime)</span>
                    <span><strong>Modified:</strong> $($risk.ModifiedDateTime)</span>
                </div>
"@
            
            if ($risk.Findings.Count -eq 0) {
                $html += @"
                <div class="no-findings">
                    ✓ No security risks identified
                </div>
"@
            }
            else {
                $html += @"
                <div class="findings">
"@
                foreach ($finding in $risk.Findings) {
                    $html += @"
                    <div class="finding-item">
                        <div class="finding-title">$($finding.Check)</div>
                        <div class="finding-impact"><strong>Finding:</strong> $($finding.Finding)</div>
                        <div class="finding-impact"><strong>Impact:</strong> $($finding.Impact)</div>
                        <div class="finding-recommendation"><strong>Recommended Action:</strong> $($finding.Recommended)</div>
                    </div>
"@
                }
                $html += @"
                </div>
"@
            }
            
            $html += @"
            </div>
"@
        }
        
        $html += @"
        </div>
        
        <footer>
            <p>This audit report was generated by Conditional Access Policy Audit Script</p>
            <p>For questions or remediation assistance, contact your cloud security team</p>
        </footer>
    </div>
</body>
</html>
"@
        
        $html | Set-Content "$OutputPath\CA_Policies_Audit_Report.html" -Force
        Write-Log "HTML report exported successfully: CA_Policies_Audit_Report.html" -Level 'Success'
    }
    catch {
        Write-Log "Failed to export HTML: $($_.Exception.Message)" -Level 'Error'
        throw $_
    }
}
#endregion

#region Main Execution
function Invoke-ConditionalAccessAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnabledOnly,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipHTMLReport
    )
    
    try {
        # Create output directory
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
            Write-VerboseLog "Created output directory: $OutputPath"
        }
        
        # Connect to Graph
        Connect-ToGraph -TenantId $TenantId
        
        # Retrieve policies
        $policies = Get-ConditionalAccessPolicies -EnabledOnly:$EnabledOnly
        
        if ($policies.Count -eq 0) {
            Write-Log "No Conditional Access policies found to audit" -Level 'Warning'
            return
        }
        
        Write-Log "Analyzing $($policies.Count) Conditional Access policies..." -Level 'Info'
        
        # Analyze each policy
        $riskAnalysis = @()
        foreach ($policy in $policies) {
            $analysis = Analyze-PolicyRisk -Policy $policy
            $riskAnalysis += $analysis
            Write-VerboseLog "Completed analysis for: $($policy.DisplayName)"
        }
        
        # Export results
        Write-Log "Exporting audit results..." -Level 'Info'
        Export-ResultsToCSV -Policies $policies -RiskAnalysis $riskAnalysis -OutputPath $OutputPath
        Export-ResultsToJSON -Policies $policies -RiskAnalysis $riskAnalysis -OutputPath $OutputPath
        
        if (-not $SkipHTMLReport) {
            Export-ResultsToHTML -RiskAnalysis $riskAnalysis -OutputPath $OutputPath -TenantId $TenantId
        }
        
        # Display summary
        Write-Log "`n========== AUDIT SUMMARY ==========" -Level 'Info'
        Write-Log "Total Policies Analyzed: $($riskAnalysis.Count)" -Level 'Info'
        Write-Log "Critical Issues: $(@($riskAnalysis | Where-Object { $_.OverallSeverity -eq 'Critical' }).Count)" -Level 'Info'
        Write-Log "High Issues: $(@($riskAnalysis | Where-Object { $_.OverallSeverity -eq 'High' }).Count)" -Level 'Info'
        Write-Log "Medium Issues: $(@($riskAnalysis | Where-Object { $_.OverallSeverity -eq 'Medium' }).Count)" -Level 'Info'
        Write-Log "Low Issues: $(@($riskAnalysis | Where-Object { $_.OverallSeverity -eq 'Low' }).Count)" -Level 'Info'
        Write-Log "`nOutput Location: $OutputPath" -Level 'Success'
        Write-Log "Generated Files:" -Level 'Info'
        Write-Log "  - CA_Policies_Configuration.csv" -Level 'Info'
        Write-Log "  - CA_Policies_RiskSummary.csv" -Level 'Info'
        Write-Log "  - CA_Policies_Complete.json" -Level 'Info'
        
        if (-not $SkipHTMLReport) {
            Write-Log "  - CA_Policies_Audit_Report.html" -Level 'Info'
        }
        
        Write-Log "===================================`n" -Level 'Info'
        
        # Return summary object
        return @{
            'TotalPolicies'     = $riskAnalysis.Count
            'CriticalCount'     = @($riskAnalysis | Where-Object { $_.OverallSeverity -eq 'Critical' }).Count
            'HighCount'         = @($riskAnalysis | Where-Object { $_.OverallSeverity -eq 'High' }).Count
            'MediumCount'       = @($riskAnalysis | Where-Object { $_.OverallSeverity -eq 'Medium' }).Count
            'LowCount'          = @($riskAnalysis | Where-Object { $_.OverallSeverity -eq 'Low' }).Count
            'OutputPath'        = $OutputPath
            'ErrorCount'        = $script:ErrorCount
            'WarningCount'      = $script:WarningCount
        }
    }
    catch {
        Write-Log "Fatal error during audit execution: $($_.Exception.Message)" -Level 'Error'
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level 'Error'
        throw $_
    }
    finally {
        # Cleanup
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-VerboseLog "Disconnected from Microsoft Graph"
    }
}
#endregion

#region Script Entry Point
try {
    $auditResults = Invoke-ConditionalAccessAudit -TenantId $TenantId -OutputPath $OutputPath `
                                                   -EnabledOnly:$EnabledOnly -SkipHTMLReport:$SkipHTMLReport
    
    exit $auditResults.ErrorCount
}
catch {
    Write-Host "Script execution failed. Please review errors above." -ForegroundColor Red
    exit 1
}
#endregion
