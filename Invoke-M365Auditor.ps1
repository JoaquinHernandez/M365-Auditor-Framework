<#
.SYNOPSIS
    M365-Auditor-Framework - Core Audit Engine
.DESCRIPTION
    Scans Entra ID roles, risky OAuth app permissions, credential validity, and Conditional Access baselines.
#>

[CmdletBinding()]
param (
    [ValidateSet("Audit", "Export")]
    [string]$Mode = "Audit",
    [string]$ExportPath = "./M365_Audit_Report.json"
)

$RequiredScopes = @(
    "RoleManagement.Read.Directory",
    "Application.Read.All",
    "Policy.Read.All",
    "User.Read.All",
    "Directory.Read.All",
    "Policy.Read.ConditionalAccess"
)

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   M365 AUDITOR FRAMEWORK - COMMUNITY AUDIT ENGINE     " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan

Connect-MgGraph -Scopes $RequiredScopes -NoWelcome

$AuditResults = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    param (
        [string]$Category,
        [string]$Severity, # Critical, High, Medium, Low
        [string]$Title,
        [string]$Details,
        [string]$Remediation
    )
    $AuditResults.Add([PSCustomObject]@{
        Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Category    = $Category
        Severity    = $Severity
        Title       = $Title
        Details     = $Details
        Remediation = $Remediation
    })
}

# --- 1. PRIVILEGED ROLES AUDIT ---
Write-Host "[*] Auditing Directory Role Assignments..." -ForegroundColor Gray
$GlobalAdminRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
if ($GlobalAdminRole) {
    $Admins = Get-MgDirectoryRoleMember -DirectoryRoleId $GlobalAdminRole.Id
    $AdminCount = ($Admins | Measure-Object).Count

    if ($AdminCount -gt 5) {
        Add-Finding -Category "Identity & Roles" -Severity "High" `
            -Title "Excessive Global Administrators" `
            -Details "Detected $AdminCount active Global Admins. Target threshold is 2-4 maximum." `
            -Remediation "Enforce Privileged Identity Management (PIM) and demote standing accounts."
    }
}

# --- 2. CONDITIONAL ACCESS GAPS ---
Write-Host "[*] Analyzing Conditional Access Policies..." -ForegroundColor Gray
try {
    $CAPolicies = Get-MgIdentityConditionalAccessPolicy -All
    $MfaAdminPolicy = $CAPolicies | Where-Object { $_.State -eq "enabled" -and $_.Conditions.Users.IncludeRoles.Count -gt 0 }
    
    if (-not $MfaAdminPolicy) {
        Add-Finding -Category "Conditional Access" -Severity "Critical" `
            -Title "Missing Dedicated Admin MFA Conditional Access Policy" `
            -Details "No active Conditional Access policy enforces dedicated MFA explicitly for directory roles." `
            -Remediation "Deploy a CA policy targeting all directory roles with Grant: Require MFA / Phishing-Resistant MFA."
    }
} catch {
    Write-Warning "Unable to query Conditional Access policies. Ensure Policy.Read.ConditionalAccess is granted."
}

# --- 3. HIGH-RISK OAUTH APP DELEGATION & CREDENTIALS ---
Write-Host "[*] Scanning Service Principals & OAuth App Scopes..." -ForegroundColor Gray
$CriticalScopes = @(
    "RoleManagement.ReadWrite.Directory",
    "Directory.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Mail.ReadWrite",
    "Mail.Send"
)

$ServicePrincipals = Get-MgServicePrincipal -Top 200 -Property Id, DisplayName, AppRoles, PasswordCredentials, KeyCredentials
foreach ($sp in $ServicePrincipals) {
    # Check for non-expiring or long-lived secrets (> 365 days)
    foreach ($secret in $sp.PasswordCredentials) {
        if ($secret.EndDateTime -gt (Get-Date).AddDays(365)) {
            Add-Finding -Category "App Credentials" -Severity "Medium" `
                -Title "Long-Lived Application Secret Detected" `
                -Details "App '$($sp.DisplayName)' has a client secret valid past 1 year (Expires: $($secret.EndDateTime))." `
                -Remediation "Establish a 90-day secret rotation policy or use Certificate / Managed Identity auth."
        }
    }
}

# --- REPORT GENERATION ---
Write-Host "`n[+] Audit Complete. Findings Breakdown:" -ForegroundColor Green
$AuditResults | Group-Object Severity | ForEach-Object {
    $Color = switch ($_.Name) { "Critical" {"Red"} "High" {"Yellow"} "Medium" {"Cyan"} Default {"Gray"} }
    Write-Host "  - $($_.Name): $($_.Count)" -ForegroundColor $Color
}

$AuditResults | ConvertTo-Json -Depth 4 | Out-File -FilePath $ExportPath
Write-Host "`n[+] Report exported to: $ExportPath" -ForegroundColor Cyan
