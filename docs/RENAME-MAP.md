# Rename Map

Old script names (before the restructure) and where they live now. Update scheduled tasks and notes that reference the old names.

## From the original toolbox repo

| Old path | New path |
|---|---|
| `scripts/powershell/active-directory/AD-GroupMembershipAudit.ps1` | `scripts/windows/active-directory/Get-ADGroupMembershipReport.ps1` |
| `scripts/powershell/active-directory/AD-StaleComputerCleanup.ps1` | `scripts/windows/active-directory/Remove-StaleADComputer.ps1` |
| `scripts/powershell/active-directory/DomainHealthCheck.ps1` | `scripts/windows/active-directory/Test-DomainHealth.ps1` |
| `scripts/powershell/active-directory/GPO-BackupExport.ps1` | `scripts/windows/active-directory/Backup-GroupPolicy.ps1` |
| `scripts/powershell/active-directory/OU-StructureDoc.ps1` | `scripts/windows/active-directory/Export-OUStructure.ps1` |
| `scripts/powershell/active-directory/PasswordPolicyChecker.ps1` | `scripts/windows/active-directory/Get-PasswordPolicyReport.ps1` |
| `scripts/powershell/active-directory/PrivilegedAccountMonitor.ps1` | `scripts/windows/active-directory/Get-PrivilegedGroupChange.ps1` |
| `scripts/powershell/azure/AzureADConnectHealthCheck.ps1` | `scripts/windows/azure/Test-EntraConnectHealth.ps1` |
| `scripts/powershell/azure/AzureBackupComplianceCheck.ps1` | `scripts/windows/azure/Test-AzureBackupCompliance.ps1` |
| `scripts/powershell/azure/AzureVMAutoShutdownScheduler.ps1` | `scripts/windows/azure/Set-AzureVMAutoShutdown.ps1` |
| `scripts/powershell/azure/AzureVMInventoryCostEstimator.ps1` | `scripts/windows/azure/Get-AzureVMInventory.ps1` |
| `scripts/powershell/azure/NSGAudit.ps1` | `scripts/windows/azure/Get-AzureNsgRiskReport.ps1` |
| `scripts/powershell/azure/RBACAuditScript.ps1` | `scripts/windows/azure/Get-AzureRbacReport.ps1` |
| `scripts/powershell/azure/ResourceTaggingEnforcement.ps1` | `scripts/windows/azure/Set-AzureResourceTag.ps1` |
| `scripts/powershell/azure/StorageAccountPublicExposureCheck.ps1` | `scripts/windows/azure/Test-AzureStorageExposure.ps1` |
| `scripts/powershell/azure/SubscriptionAuditReport.ps1` | `scripts/windows/azure/Get-AzureSubscriptionReport.ps1` |
| `scripts/powershell/exchange/ForwardingRuleDetection.ps1` | `scripts/windows/exchange/Get-MailboxForwardingRule.ps1` |
| `scripts/powershell/exchange/InboxRuleExfiltrationDetection.ps1` | `scripts/windows/exchange/Get-SuspiciousInboxRule.ps1` |
| `scripts/powershell/exchange/LitigationHoldEnablement.ps1` | `scripts/windows/exchange/Set-MailboxLitigationHold.ps1` |
| `scripts/powershell/exchange/MailboxPermissionAudit.ps1` | `scripts/windows/exchange/Get-MailboxPermissionReport.ps1` |
| `scripts/powershell/exchange/MailboxSizeGrowthReport.ps1` | `scripts/windows/exchange/Get-MailboxSizeReport.ps1` |
| `scripts/powershell/exchange/SharedMailboxAutoProvision.ps1` | `scripts/windows/exchange/New-SharedMailboxFromCsv.ps1` |
| `scripts/powershell/exchange/TransportRuleExportImport.ps1` | `scripts/windows/exchange/Invoke-TransportRuleTransfer.ps1` |
| `scripts/powershell/m365/BulkUserOffboarding.ps1` | `scripts/windows/m365/Invoke-UserOffboarding.ps1` |
| `scripts/powershell/m365/BulkUserOnboarding.ps1` | `scripts/windows/m365/Invoke-UserOnboarding.ps1` |
| `scripts/powershell/m365/GuestAccountAudit.ps1` | `scripts/windows/m365/Get-GuestAccountReport.ps1` |
| `scripts/powershell/m365/LicenseOptimizationReport.ps1` | `scripts/windows/m365/Get-LicenseUsageReport.ps1` |
| `scripts/powershell/m365/MFAEnforcementReport.ps1` | `scripts/windows/m365/Get-MfaStatusReport.ps1` |
| `scripts/powershell/m365/PrivilegedRoleAudit.ps1` | `scripts/windows/m365/Get-PrivilegedRoleReport.ps1` |
| `scripts/powershell/m365/RiskySignInParser.ps1` | `scripts/windows/m365/Get-RiskySignInReport.ps1` |
| `scripts/powershell/m365/SecureScoreReporting.ps1` | `scripts/windows/m365/Get-SecureScoreReport.ps1` |
| `scripts/powershell/m365/StaleUserDetection.ps1` | `scripts/windows/m365/Get-StaleUserAccount.ps1` |
| `scripts/powershell/m365/conditional-access-audit.ps1` | `scripts/windows/m365/Get-ConditionalAccessReport.ps1` |
| `scripts/powershell/security/EmailAuth-Audit.ps1` | `scripts/windows/security/Test-EmailAuthentication.ps1` |
| `scripts/powershell/server/BackupVerification.ps1` | `scripts/windows/server/Test-BackupStatus.ps1` |
| `scripts/powershell/server/FileServerPermissionAudit.ps1` | `scripts/windows/server/Get-FileServerPermissionReport.ps1` |
| `scripts/powershell/server/HyperV-VMInventory.ps1` | `scripts/windows/server/Get-HyperVInventory.ps1` |
| `scripts/powershell/server/PatchComplianceReport.ps1` | `scripts/windows/server/Get-PatchComplianceReport.ps1` |
| `scripts/powershell/server/ServiceHealthMonitor.ps1` | `scripts/windows/server/Test-ServiceHealth.ps1` |
| `scripts/powershell/server/event-log-anomaly.ps1` | `scripts/windows/server/Get-EventLogAnomaly.ps1` |
| `scripts/powershell/server/monitor-disk-space.ps1` | `scripts/windows/server/Get-DiskSpaceStatus.ps1` |
| `scripts/powershell/server/DiskSpaceMonitor.ps1` | removed; use `Get-DiskSpaceStatus.ps1` |
| `scripts/powershell/server/EventLogAnomalyParser.ps1` | removed; use `Get-EventLogAnomaly.ps1` |

## Imported from admin-scripts

(filled in when the import commit lands)
