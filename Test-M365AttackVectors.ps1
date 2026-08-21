<#
.SYNOPSIS
    M365-Auditor-Framework - Safe Attack Vector & Pen-Test Simulation
.DESCRIPTION
    Simulates discovery and privilege escalation pathways commonly targeted by adversaries
    (e.g., Illicit App Consent, Directory Enumeration, Role Elevation Paths).
#>

[CmdletBinding()]
param (
    [switch]$SimulateLowPrivUser
)

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host "   M365 AUDITOR - ATTACK SURFACE SIMULATION SUITE     " -ForegroundColor Magenta
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Magenta

$PentestFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Register-Vector {
    param (
        [string]$VectorId,
        [string]$ThreatVector,
        [string]$Status, # VULNERABLE, SECURE, UNTESTED
        [string]$RiskImpact,
        [string]$TechnicalDetail
    )
    $PentestFindings.Add([PSCustomObject]@{
        VectorID        = $VectorId
        ThreatVector    = $ThreatVector
        Status          = $Status
        RiskImpact      = $RiskImpact
        TechnicalDetail = $TechnicalDetail
    })
}

# --- ATTACK VECTOR 1: User App Consent & Rogue App Registration ---
Write-Host "[*] [ATTACK V1] Testing Illicit Consent & App Registration Surface..." -ForegroundColor Yellow
$AuthPolicy = Get-MgPolicyAuthorizationPolicy
if ($AuthPolicy.DefaultUserRolePermissions.AllowedToCreateApps -eq $true) {
    Register-Vector -VectorId "ATK-M365-01" `
        -ThreatVector "Rogue App Registration & OAuth Phishing Infrastructure" `
        -Status "VULNERABLE" `
        -RiskImpact "High" `
        -TechnicalDetail "Low-privilege users can register arbitrary multitenant applications to facilitate internal OAuth phishing."
} else {
    Register-Vector -VectorId "ATK-M365-01" `
        -ThreatVector "Rogue App Registration & OAuth Phishing Infrastructure" `
        -Status "SECURE" `
        -RiskImpact "Low" `
        -TechnicalDetail "Standard users are prevented from creating app registrations."
}

# --- ATTACK VECTOR 2: Unrestricted Directory Reconnaissance by Guests ---
Write-Host "[*] [ATTACK V2] Testing Guest Directory Enumeration Surface..." -ForegroundColor Yellow
if ($AuthPolicy.GuestUserRoleId -ne "10dae51f-b6e1-4b42-bf6c-38e385a6dec7") {
    Register-Vector -VectorId "ATK-M365-02" `
        -ThreatVector "Guest Account Directory Reconnaissance" `
        -Status "VULNERABLE" `
        -RiskImpact "Medium" `
        -TechnicalDetail "Guest accounts can enumerate all tenant users, groups, and directory objects for target mapping."
} else {
    Register-Vector -VectorId "ATK-M365-02" `
        -ThreatVector "Guest Account Directory Reconnaissance" `
        -Status "SECURE" `
        -RiskImpact "Low" `
        -TechnicalDetail "Guest access is locked down to restricted permissions."
}

# --- ATTACK VECTOR 3: Group Ownership to Role Escalation Vector ---
Write-Host "[*] [ATTACK V3] Evaluating Role-Assignable Groups Attack Path..." -ForegroundColor Yellow
try {
    $RoleAssignableGroups = Get-MgGroup -Filter "isAssignableToRole eq true" -Property Id, DisplayName, Owners
    $ExposedGroups = @()
    foreach ($grp in $RoleAssignableGroups) {
        $Owners = Get-MgGroupOwner -GroupId $grp.Id
        if ($Owners.Count -gt 0) {
            $ExposedGroups += $grp.DisplayName
        }
    }

    if ($ExposedGroups.Count -gt 0) {
        Register-Vector -VectorId "ATK-M365-03" `
            -ThreatVector "Privilege Escalation via Role-Assignable Group Ownership" `
            -Status "VULNERABLE" `
            -RiskImpact "Critical" `
            -TechnicalDetail "Found role-assignable groups ($($ExposedGroups -join ', ')). Anyone compromising an owner account can elevate members to admin roles."
    } else {
        Register-Vector -VectorId "ATK-M365-03" `
            -ThreatVector "Privilege Escalation via Role-Assignable Group Ownership" `
            -Status "SECURE" `
            -RiskImpact "Low" `
            -TechnicalDetail "No unmonitored role-assignable groups with loose ownership detected."
    }
} catch {
    Write-Host "[-] Group query skipped or requires elevated directory scope." -ForegroundColor DarkGray
}

# --- ATTACK SURFACE SUMMARY ---
Write-Host "`n[+] Penetration Testing Attack Surface Summary:" -ForegroundColor Magenta
$PentestFindings | Format-Table VectorID, ThreatVector, Status, RiskImpact -AutoSize

$PentestFindings | ConvertTo-Json -Depth 3 | Out-File -FilePath "./pentest_results.json"
Write-Host "[+] Results saved to ./pentest_results.json" -ForegroundColor Green
