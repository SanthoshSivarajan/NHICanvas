# NHICanvas

### Discover and Govern Non-Human Identities

**Author:** Santhosh Sivarajan, Microsoft MVP
**GitHub:** [https://github.com/SanthoshSivarajan/NHICanvas](https://github.com/SanthoshSivarajan/NHICanvas)

---

## Overview

NHICanvas discovers and assesses **every Non-Human Identity (NHI)** across your hybrid environment -- on-premises Active Directory and Entra ID -- in a single script. It inventories service accounts, managed service accounts (gMSA/sMSA/dMSA), computer accounts, KRBTGT, app registrations, service principals, managed identities, and more, with risk scoring for each.

Non-human identities outnumber humans 25-50x in most enterprises and are the #1 identity attack vector. NHICanvas gives you visibility into what you cannot see.

## Dual-Mode Operation

NHICanvas auto-detects your environment and collects from whatever is available:

| Environment | What Gets Collected |
|---|---|
| **On-Prem Only** | AD service accounts, gMSA, sMSA, dMSA, computers, KRBTGT |
| **Cloud Only** | App registrations, service principals, managed identities, credentials |
| **Hybrid (Both)** | Everything + Entra Connect sync accounts cross-referenced |

No hard module requirements -- at least one of ActiveDirectory module or Microsoft.Graph must be available.

## What NHICanvas Discovers

### Active Directory NHIs

| NHI Type | Detection Logic | Risk Scoring |
|---|---|---|
| **Service Accounts (SPN)** | User objects with `servicePrincipalName` set | Critical if AdminCount=1, High if pwd never expires or >365 days old |
| **gMSA** | `objectClass = msDS-GroupManagedServiceAccount` | Low (auto-rotating passwords) |
| **sMSA** | `objectClass = msDS-ManagedServiceAccount` | Medium (single-server) |
| **dMSA** | `objectClass = msDS-DelegatedManagedServiceAccount` (schema 91+) | Low (Server 2025+) |
| **Entra Connect Sync** | Accounts matching `MSOL_*` or `Sync_*` | Critical (high-privilege sync accounts) |
| **KRBTGT** | The Kerberos ticket-granting account | Critical if password >180 days old |
| **Computer Accounts** | All `objectClass = computer` with stale detection | Stale if no logon in 90+ days |
| **Privileged NHIs** | SPN accounts in Domain Admins, Enterprise Admins, etc. | Critical |

### Entra ID NHIs

| NHI Type | Detection Logic | Risk Scoring |
|---|---|---|
| **App Registrations** | All registered apps with credential and permission analysis | High if expired creds or application-level permissions |
| **Service Principals** | Categorized: Microsoft First-Party, Custom, Third-Party, Managed Identity | Varies by category |
| **Managed Identities** | `servicePrincipalType = ManagedIdentity` (System/User-assigned) | Low (recommended approach) |
| **Expired Credentials** | Secrets and certificates already expired | High |
| **Expiring Credentials** | Secrets and certificates expiring within 30 days | Medium |
| **Privileged Apps** | Service principals assigned to directory roles | Critical |
| **Stale Apps** | No sign-in activity in 90+ days (non-Microsoft) | Medium |

### Risk Levels

| Risk | Meaning | Examples |
|---|---|---|
| **Critical** | Immediate action required | Service accounts in Domain Admins, KRBTGT >180d, Entra Connect sync accounts, apps in Global Admin role |
| **High** | Significant risk | Expired credentials, password never expires, application-level Graph permissions |
| **Medium** | Needs attention | Expiring credentials, stale apps, sMSA accounts |
| **Low** | Well-managed | gMSA, dMSA, managed identities (auto-rotating, no manual credentials) |

## Charts (4)

- AD NHI Types (donut)
- Entra Service Principal Categories (donut)
- NHI Risk Distribution (donut)
- Credential Health Status (donut)

## Requirements

- Windows PowerShell 5.1+ or PowerShell 7+
- **ActiveDirectory module** (for on-prem) -- included with RSAT
- **Microsoft.Graph module** (for Entra ID) -- `Install-Module Microsoft.Graph`
- At least one module must be available

## Usage

```powershell
# Run from domain-joined machine with Graph connection (hybrid -- full report)
.\NHICanvas.ps1

# Cloud-only (no AD module needed)
Connect-MgGraph -Scopes "Directory.Read.All","Application.Read.All"
.\NHICanvas.ps1

# On-prem only (no Graph needed)
.\NHICanvas.ps1
```

## License

MIT -- Free to use, modify, and distribute.

## Related Projects

- [ADCanvas](https://github.com/SanthoshSivarajan/ADCanvas) -- Active Directory documentation
- [EntraIDCanvas](https://github.com/SanthoshSivarajan/EntraIDCanvas) -- Entra ID documentation
- [IntuneCanvas](https://github.com/SanthoshSivarajan/IntuneCanvas) -- Intune documentation
- [ZeroTrustCanvas](https://github.com/SanthoshSivarajan/ZeroTrustCanvas) -- Zero Trust posture assessment

---

*Developed by Santhosh Sivarajan, Microsoft MVP*
