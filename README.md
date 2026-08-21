# M365-Auditor-Framework
# 🛡️ M365-Auditor-Framework: Security Auditing & Pentest Simulation Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0%2B-blue)](https://github.com/PowerShell/PowerShell)
[![Platform: M365](https://img.shields.io/badge/Platform-Microsoft%20365%20%7C%20Entra%20ID-orange)](#)

A modular, open-source PowerShell security framework built to audit Microsoft 365 / Entra ID privilege architectures, assess identity attack vectors, and run safe penetration testing simulations against configuration weaknesses.

---

## 🎯 Key Capabilities

- **Privileged Identity Surface:** Audits standing Global Admin roles, inactive role assignments, and PIM misconfigurations.
- **OAuth & Illicit Consent Vectors:** Detects high-risk Graph scopes (`RoleManagement.*`, `Directory.ReadWrite.All`, `Mail.ReadWrite`) across multi-tenant enterprise apps.
- **Penetration Testing Simulation:** Safely assesses if non-admin users or compromised tokens can execute tier-elevation, register rogue applications, or read directory-wide sensitive payloads.
- **CI/CD & SARIF Integration:** Outputs structured JSON and SARIF reports ready for automated compliance pipelines.

---

## 🚀 Quick Start

### 1. Install Required Modules
```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

### 2. Run Comprehensive Audit (Read-Only)
```powershell
./Invoke-M365Auditor.ps1 -Mode Audit -ExportPath "./reports/m365_audit_report.json"
```

### 3. Run Simulated Attack Surface Tests (Pentest Validation)
```powershell
./pentest/Test-M365AttackVectors.ps1 -SimulateLowPrivUser
```

---

## 🔒 Permissions & Safety

All simulated attack checks are executed in a **non-destructive, read/dry-run mode** designed to confirm tenant exposure without modifying live production directory data.

---

## 🤝 Contributing
Pull requests are welcome! Please open an issue first to discuss new check vectors or rule mappings (CIS / CISA ScubaGear).
