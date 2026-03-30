<#
================================================================================
  NHICanvas -- Discover and Govern Non-Human Identities
  Version: 1.0
  Author : Santhosh Sivarajan, Microsoft MVP
  Purpose: Discovers and assesses all Non-Human Identities (NHIs) across
           on-premises Active Directory and Entra ID. Covers service accounts,
           gMSA, sMSA, dMSA, computer accounts, KRBTGT, app registrations,
           service principals, managed identities, workload identities, and
           AI agent identities. Produces a risk-scored HTML report.
  License: MIT -- Free to use, modify, and distribute.
  GitHub : https://github.com/SanthoshSivarajan/NHICanvas
================================================================================
#>

param([string]$OutputPath = $PSScriptRoot)

$ReportDate = Get-Date -Format "yyyy-MM-dd_HHmmss"
$OutputFile = Join-Path $OutputPath "NHICanvas_$ReportDate.html"

Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  |   NHICanvas -- Non-Human Identity Governance Tool v1.0     |" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  |   Author : Santhosh Sivarajan, Microsoft MVP              |" -ForegroundColor Cyan
Write-Host "  |   Web    : github.com/SanthoshSivarajan/NHICanvas         |" -ForegroundColor Cyan
Write-Host "  |                                                            |" -ForegroundColor Cyan
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host ""

# --- Helpers ------------------------------------------------------------------
Add-Type -AssemblyName System.Web
function HtmlEncode($s) { if ($null -eq $s) { return "--" }; return [System.Web.HttpUtility]::HtmlEncode([string]$s) }
function ConvertTo-HtmlTable {
    param([Parameter(Mandatory)]$Data,[string[]]$Properties)
    if (-not $Data -or @($Data).Count -eq 0) { return '<p class="empty-note">No data found.</p>' }
    $rows = @($Data)
    if (-not $Properties) { $Properties = ($rows[0].PSObject.Properties).Name }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<div class="table-wrap"><table><thead><tr>')
    foreach ($p in $Properties) { [void]$sb.Append("<th>$(HtmlEncode $p)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($row in $rows) {
        [void]$sb.Append('<tr>')
        foreach ($p in $Properties) {
            $val = $row.$p
            if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) { $val = ($val | ForEach-Object { [string]$_ }) -join ", " }
            [void]$sb.Append("<td>$(HtmlEncode $val)</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}
function Graph-Get {
    param([string]$Uri, [string]$Label)
    $all = @()
    try {
        $result = Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop
        if ($result.value) { $all += $result.value }
        while ($result.'@odata.nextLink') {
            $result = Invoke-MgGraphRequest -Method GET -Uri $result.'@odata.nextLink' -ErrorAction Stop
            if ($result.value) { $all += $result.value }
        }
        if ($Label) { Write-Host "  [+] $Label ($($all.Count))" -ForegroundColor Green }
    } catch {
        if ($Label) { Write-Host "  [i] $Label -- not available" -ForegroundColor Gray }
    }
    return $all
}
function Get-RiskBadge($risk) {
    switch ($risk) {
        'Critical' { return '<span style="color:#f87171;font-weight:700">Critical</span>' }
        'High'     { return '<span style="color:#fb923c;font-weight:700">High</span>' }
        'Medium'   { return '<span style="color:#fbbf24;font-weight:700">Medium</span>' }
        'Low'      { return '<span style="color:#34d399;font-weight:700">Low</span>' }
        default    { return '<span style="color:#94a3b8">--</span>' }
    }
}

# --- Detect Available Modules -------------------------------------------------
$HasAD    = $false
$HasGraph = $false
$TenantName = "Unknown"
$ForestName = "Unknown"

# Check Active Directory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $HasAD = $true
    $Forest = Get-ADForest -ErrorAction Stop
    $ForestName = $Forest.Name
    Write-Host "  [+] Active Directory module loaded -- Forest: $ForestName" -ForegroundColor Green
} catch {
    Write-Host "  [i] Active Directory module not available -- skipping on-prem NHIs" -ForegroundColor Gray
}

# Check Microsoft Graph
try {
    $graphContext = Get-MgContext -ErrorAction Stop
    if ($graphContext) {
        $HasGraph = $true
        $Org = Get-MgOrganization -ErrorAction SilentlyContinue
        $TenantName = $Org.DisplayName
        $TenantId   = $Org.Id
        Write-Host "  [+] Microsoft Graph connected -- Tenant: $TenantName" -ForegroundColor Green
    }
} catch { }

if (-not $HasGraph) {
    # Try connecting
    try {
        $scopes = @('Directory.Read.All','Application.Read.All','RoleManagement.Read.Directory',
                     'Policy.Read.All','AuditLog.Read.All','Organization.Read.All')
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        $graphContext = Get-MgContext
        $Org = Get-MgOrganization -ErrorAction SilentlyContinue
        $TenantName = $Org.DisplayName
        $TenantId   = $Org.Id
        $HasGraph = $true
        Write-Host "  [+] Microsoft Graph connected -- Tenant: $TenantName" -ForegroundColor Green
    } catch {
        Write-Host "  [i] Microsoft Graph not available -- skipping Entra ID NHIs" -ForegroundColor Gray
    }
}

if (-not $HasAD -and -not $HasGraph) {
    Write-Host "  [!] Neither AD module nor Graph connection available. Cannot proceed." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Discovering Non-Human Identities ..." -ForegroundColor Yellow
Write-Host ""

$now = Get-Date
$staleThreshold = $now.AddDays(-90)

# ==============================================================================
# ON-PREMISES ACTIVE DIRECTORY NHIs
# ==============================================================================
$AD_ServiceAccounts = @()
$AD_gMSAs          = @()
$AD_sMSAs          = @()
$AD_dMSAs          = @()
$AD_Computers       = @()
$AD_KRBTGT          = @()
$AD_PrivilegedNHIs  = @()
$AD_SyncAccounts    = @()
$AD_StaleService    = @()
$AD_NeverExpirePwd  = @()
$AD_SPNAccounts     = @()
$AD_Summary         = @()

if ($HasAD) {
    Write-Host "  --- On-Premises Active Directory ---" -ForegroundColor Cyan

    $allDomains = @()
    try { $allDomains = @($Forest.Domains) } catch { $allDomains = @($ForestName) }

    foreach ($domainName in $allDomains) {
        Write-Host "  [*] Processing domain: $domainName" -ForegroundColor White
        $domainDN = ($domainName -split '\.' | ForEach-Object { "DC=$_" }) -join ','

        # --- gMSA ---
        try {
            $gmsas = @(Get-ADServiceAccount -Filter * -Server $domainName -Properties Name,DNSHostName,Created,Enabled,msDS-GroupMSAMembership,PrincipalsAllowedToRetrieveManagedPassword,PasswordLastSet,MemberOf,ObjectClass -ErrorAction Stop |
                Where-Object { $_.ObjectClass -eq 'msDS-GroupManagedServiceAccount' })
            foreach ($g in $gmsas) {
                $AD_gMSAs += [PSCustomObject]@{
                    Name=$g.Name; Domain=$domainName; Type='gMSA'; DNSHost=$g.DNSHostName;
                    Enabled=$g.Enabled; Created=$g.Created; PasswordLastSet=$g.PasswordLastSet;
                    AllowedPrincipals=($g.PrincipalsAllowedToRetrieveManagedPassword -join ', ');
                    MemberOf=(@($g.MemberOf) | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ', ';
                    Risk='Low'
                }
            }
            Write-Host "  [+] gMSAs: $($gmsas.Count)" -ForegroundColor Green
        } catch { Write-Host "  [i] gMSA collection: $($_.Exception.Message)" -ForegroundColor Gray }

        # --- sMSA ---
        try {
            $smsas = @(Get-ADServiceAccount -Filter * -Server $domainName -Properties Name,Created,Enabled,PasswordLastSet,MemberOf,ObjectClass -ErrorAction Stop |
                Where-Object { $_.ObjectClass -eq 'msDS-ManagedServiceAccount' })
            foreach ($s in $smsas) {
                $AD_sMSAs += [PSCustomObject]@{
                    Name=$s.Name; Domain=$domainName; Type='sMSA'; Enabled=$s.Enabled;
                    Created=$s.Created; PasswordLastSet=$s.PasswordLastSet;
                    MemberOf=(@($s.MemberOf) | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ', ';
                    Risk='Medium'
                }
            }
            Write-Host "  [+] sMSAs: $($smsas.Count)" -ForegroundColor Green
        } catch { Write-Host "  [i] sMSA collection skipped" -ForegroundColor Gray }

        # --- dMSA (Server 2025+, schema 91+) ---
        try {
            $schemaVersion = (Get-ADObject "CN=Schema,CN=Configuration,$domainDN" -Server $domainName -Properties objectVersion -ErrorAction Stop).objectVersion
            if ($schemaVersion -ge 91) {
                $dmsas = @(Get-ADObject -Filter 'objectClass -eq "msDS-DelegatedManagedServiceAccount"' -Server $domainName -Properties Name,Created,Description -ErrorAction Stop)
                foreach ($d in $dmsas) {
                    $AD_dMSAs += [PSCustomObject]@{
                        Name=$d.Name; Domain=$domainName; Type='dMSA'; Created=$d.Created;
                        Description=$d.Description; Risk='Low'
                    }
                }
                Write-Host "  [+] dMSAs: $($dmsas.Count) (schema $schemaVersion supports dMSA)" -ForegroundColor Green
            } else {
                Write-Host "  [i] dMSA: Schema $schemaVersion (requires 91+ for dMSA support)" -ForegroundColor Gray
            }
        } catch { Write-Host "  [i] dMSA detection skipped" -ForegroundColor Gray }

        # --- Service Accounts (user objects with SPN or naming patterns) ---
        try {
            $spnUsers = @(Get-ADUser -Filter 'servicePrincipalName -like "*"' -Server $domainName -Properties Name,SamAccountName,servicePrincipalName,Enabled,PasswordNeverExpires,PasswordLastSet,LastLogonDate,Created,Description,MemberOf,AdminCount,UserAccountControl -ErrorAction Stop | Where-Object { $_.SamAccountName -ne 'krbtgt' })
            foreach ($u in $spnUsers) {
                $risk = 'Medium'
                if ($u.AdminCount -eq 1) { $risk = 'Critical' }
                elseif ($u.PasswordNeverExpires) { $risk = 'High' }
                elseif ($u.PasswordLastSet -and $u.PasswordLastSet -lt $now.AddDays(-365)) { $risk = 'High' }
                $AD_SPNAccounts += [PSCustomObject]@{
                    Name=$u.SamAccountName; Domain=$domainName; Type='SPN User Account';
                    DisplayName=$u.Name; Enabled=$u.Enabled;
                    SPN=($u.servicePrincipalName | Select-Object -First 3) -join '; ';
                    PasswordNeverExpires=$u.PasswordNeverExpires;
                    PasswordLastSet=$u.PasswordLastSet; LastLogon=$u.LastLogonDate;
                    Created=$u.Created; Description=$u.Description;
                    AdminCount=$u.AdminCount;
                    PrivilegedGroups=(@($u.MemberOf) | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ', ';
                    Risk=$risk
                }
                if ($u.PasswordNeverExpires) { $AD_NeverExpirePwd += $u }
                if ($u.LastLogonDate -and $u.LastLogonDate -lt $staleThreshold) { $AD_StaleService += $u }
                if (-not $u.LastLogonDate -and $u.Created -lt $staleThreshold) { $AD_StaleService += $u }
            }
            Write-Host "  [+] User accounts with SPN (service accounts): $($spnUsers.Count)" -ForegroundColor Green
        } catch { Write-Host "  [i] SPN user collection: $($_.Exception.Message)" -ForegroundColor Gray }

        # --- Entra Connect Sync Accounts (MSOL_ / Sync_) ---
        try {
            $syncAccounts = @(Get-ADUser -Filter 'SamAccountName -like "MSOL_*" -or SamAccountName -like "Sync_*"' -Server $domainName -Properties Name,SamAccountName,Enabled,PasswordLastSet,LastLogonDate,Created,Description,MemberOf -ErrorAction Stop)
            foreach ($sa in $syncAccounts) {
                $AD_SyncAccounts += [PSCustomObject]@{
                    Name=$sa.SamAccountName; Domain=$domainName; Type='Entra Connect Sync';
                    Enabled=$sa.Enabled; PasswordLastSet=$sa.PasswordLastSet;
                    LastLogon=$sa.LastLogonDate; Created=$sa.Created;
                    MemberOf=(@($sa.MemberOf) | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ', ';
                    Risk='Critical'
                }
            }
            Write-Host "  [+] Entra Connect sync accounts (MSOL_/Sync_): $($syncAccounts.Count)" -ForegroundColor Green
        } catch { Write-Host "  [i] Sync account detection skipped" -ForegroundColor Gray }

        # --- KRBTGT ---
        try {
            $krbtgt = Get-ADUser -Identity 'krbtgt' -Server $domainName -Properties PasswordLastSet,Created -ErrorAction Stop
            $krbtgtAge = if ($krbtgt.PasswordLastSet) { [math]::Round(($now - $krbtgt.PasswordLastSet).TotalDays) } else { 9999 }
            $krbtgtRisk = if ($krbtgtAge -gt 180) { 'Critical' } elseif ($krbtgtAge -gt 90) { 'High' } else { 'Low' }
            $AD_KRBTGT += [PSCustomObject]@{
                Name='krbtgt'; Domain=$domainName; Type='KRBTGT';
                PasswordLastSet=$krbtgt.PasswordLastSet; PasswordAgeDays=$krbtgtAge;
                Risk=$krbtgtRisk
            }
            Write-Host "  [+] KRBTGT: Password age $krbtgtAge days" -ForegroundColor $(if($krbtgtAge -gt 180){'Red'}elseif($krbtgtAge -gt 90){'Yellow'}else{'Green'})
        } catch { }

        # --- Computer Accounts Summary ---
        try {
            $computers = @(Get-ADComputer -Filter * -Server $domainName -Properties OperatingSystem,LastLogonDate,Enabled,Created -ErrorAction Stop)
            $totalComputers = $computers.Count
            $enabledComputers = @($computers | Where-Object { $_.Enabled }).Count
            $staleComputers = @($computers | Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $staleThreshold }).Count
            $dcComputers = @($computers | Where-Object { $_.OperatingSystem -like '*Server*' }).Count
            $AD_Computers += [PSCustomObject]@{
                Domain=$domainName; Total=$totalComputers; Enabled=$enabledComputers;
                Disabled=($totalComputers-$enabledComputers); Stale90Days=$staleComputers;
                Servers=$dcComputers; Workstations=($totalComputers-$dcComputers)
            }
            Write-Host "  [+] Computer accounts: $totalComputers (stale 90d+: $staleComputers)" -ForegroundColor Green
        } catch { Write-Host "  [i] Computer account collection skipped" -ForegroundColor Gray }

        # --- Privileged Group NHIs (service accounts in high-privilege groups) ---
        $privGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Backup Operators','Account Operators','Server Operators')
        foreach ($pg in $privGroups) {
            try {
                $members = @(Get-ADGroupMember -Identity $pg -Server $domainName -ErrorAction SilentlyContinue)
                foreach ($m in $members) {
                    if ($m.objectClass -eq 'user') {
                        try {
                            $usr = Get-ADUser $m.SID -Server $domainName -Properties servicePrincipalName,PasswordNeverExpires -ErrorAction SilentlyContinue
                            if ($usr.servicePrincipalName -and @($usr.servicePrincipalName).Count -gt 0) {
                                $AD_PrivilegedNHIs += [PSCustomObject]@{
                                    Name=$m.Name; Domain=$domainName; Group=$pg;
                                    Type='Privileged SPN Account'; Risk='Critical'
                                }
                            }
                        } catch { }
                    }
                }
            } catch { }
        }
    }
    $totalPrivNHIs = $AD_PrivilegedNHIs.Count
    if ($totalPrivNHIs -gt 0) { Write-Host "  [!] Privileged NHIs (service accounts in admin groups): $totalPrivNHIs" -ForegroundColor Red }
}

# ==============================================================================
# ENTRA ID NHIs
# ==============================================================================
$Entra_AppRegs        = @()
$Entra_SPByCategory   = @()
$Entra_ManagedIds     = @()
$Entra_ExpiredCreds   = @()
$Entra_PrivilegedApps = @()
$Entra_StaleApps      = @()
$Entra_HighPermApps   = @()
$Entra_AllSPs         = @()

$MicrosoftTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'

if ($HasGraph) {
    Write-Host ""
    Write-Host "  --- Entra ID (Cloud) ---" -ForegroundColor Cyan

    # --- App Registrations with credentials ---
    try {
        $apps = @(Get-MgApplication -All -Property Id,DisplayName,AppId,CreatedDateTime,SignInAudience,
            PasswordCredentials,KeyCredentials,RequiredResourceAccess -ErrorAction Stop)
        Write-Host "  [+] App registrations: $($apps.Count)" -ForegroundColor Green
        foreach ($app in $apps) {
            $secretCount = @($app.PasswordCredentials).Count
            $certCount   = @($app.KeyCredentials).Count
            $hasExpired  = $false; $hasExpiring = $false
            foreach ($cred in $app.PasswordCredentials) {
                if ($cred.EndDateTime) {
                    if ([datetime]$cred.EndDateTime -lt $now) {
                        $hasExpired = $true
                        $Entra_ExpiredCreds += [PSCustomObject]@{
                            AppName=$app.DisplayName; AppId=$app.AppId; CredType='Secret';
                            Expiry=[datetime]$cred.EndDateTime; Status='EXPIRED'; Risk='High'
                        }
                    } elseif ([datetime]$cred.EndDateTime -lt $now.AddDays(30)) {
                        $hasExpiring = $true
                        $Entra_ExpiredCreds += [PSCustomObject]@{
                            AppName=$app.DisplayName; AppId=$app.AppId; CredType='Secret';
                            Expiry=[datetime]$cred.EndDateTime; Status='Expiring Soon'; Risk='Medium'
                        }
                    }
                }
            }
            foreach ($cred in $app.KeyCredentials) {
                if ($cred.EndDateTime) {
                    if ([datetime]$cred.EndDateTime -lt $now) {
                        $hasExpired = $true
                        $Entra_ExpiredCreds += [PSCustomObject]@{
                            AppName=$app.DisplayName; AppId=$app.AppId; CredType='Certificate';
                            Expiry=[datetime]$cred.EndDateTime; Status='EXPIRED'; Risk='High'
                        }
                    } elseif ([datetime]$cred.EndDateTime -lt $now.AddDays(30)) {
                        $hasExpiring = $true
                        $Entra_ExpiredCreds += [PSCustomObject]@{
                            AppName=$app.DisplayName; AppId=$app.AppId; CredType='Certificate';
                            Expiry=[datetime]$cred.EndDateTime; Status='Expiring Soon'; Risk='Medium'
                        }
                    }
                }
            }
            # High-privilege permissions check
            $highPriv = $false
            foreach ($rra in $app.RequiredResourceAccess) {
                foreach ($ra in $rra.ResourceAccess) {
                    if ($ra.Type -eq 'Role') { $highPriv = $true; break }
                }
                if ($highPriv) { break }
            }
            $risk = 'Low'
            if ($hasExpired) { $risk = 'High' }
            elseif ($highPriv) { $risk = 'High' }
            elseif ($hasExpiring) { $risk = 'Medium' }
            $Entra_AppRegs += [PSCustomObject]@{
                Name=$app.DisplayName; AppId=$app.AppId; Audience=$app.SignInAudience;
                Secrets=$secretCount; Certificates=$certCount; Created=$app.CreatedDateTime;
                HasExpired=$hasExpired; HasAppRolePerms=$highPriv; Risk=$risk
            }
        }
    } catch { Write-Host "  [i] App registration collection failed" -ForegroundColor Gray }

    # --- Service Principals (categorized) ---
    try {
        $sps = @(Get-MgServicePrincipal -All -Property Id,DisplayName,AppId,ServicePrincipalType,
            AccountEnabled,CreatedDateTime,AppOwnerOrganizationId,PublisherName,
            AppRoleAssignedTo -ErrorAction Stop)
        $Entra_AllSPs = $sps
        Write-Host "  [+] Service principals: $($sps.Count)" -ForegroundColor Green

        foreach ($sp in $sps) {
            $category = 'Other'
            if ($sp.ServicePrincipalType -eq 'ManagedIdentity') {
                $category = 'Managed Identity'
                $miType = if ($sp.DisplayName -match '_[a-f0-9]{8}-') { 'System-Assigned' } else { 'User-Assigned' }
                $Entra_ManagedIds += [PSCustomObject]@{
                    Name=$sp.DisplayName; AppId=$sp.AppId; Type=$miType;
                    Enabled=$sp.AccountEnabled; Created=$sp.CreatedDateTime; Risk='Low'
                }
            } elseif ($sp.AppOwnerOrganizationId -eq $MicrosoftTenantId) {
                $category = 'Microsoft First-Party'
            } elseif ($sp.AppOwnerOrganizationId -eq $TenantId -or -not $sp.AppOwnerOrganizationId) {
                $category = 'Custom (Your Tenant)'
            } else {
                $category = 'Third-Party'
            }
            $Entra_SPByCategory += [PSCustomObject]@{
                Name=$sp.DisplayName; AppId=$sp.AppId; Category=$category;
                Type=$sp.ServicePrincipalType; Enabled=$sp.AccountEnabled;
                Created=$sp.CreatedDateTime
            }
        }
    } catch { Write-Host "  [i] Service principal collection failed" -ForegroundColor Gray }

    $MSFirstParty  = @($Entra_SPByCategory | Where-Object { $_.Category -eq 'Microsoft First-Party' }).Count
    $CustomSP      = @($Entra_SPByCategory | Where-Object { $_.Category -eq 'Custom (Your Tenant)' }).Count
    $ThirdPartySP  = @($Entra_SPByCategory | Where-Object { $_.Category -eq 'Third-Party' }).Count
    $ManagedIdCount = @($Entra_SPByCategory | Where-Object { $_.Category -eq 'Managed Identity' }).Count

    # --- Privileged NHIs in Entra ID (directory roles) ---
    try {
        $dirRoles = @(Get-MgDirectoryRole -All -ErrorAction Stop)
        foreach ($role in $dirRoles) {
            $members = @(Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction SilentlyContinue)
            foreach ($m in $members) {
                $objType = $m.AdditionalProperties.'@odata.type'
                if ($objType -like '*servicePrincipal*') {
                    $Entra_PrivilegedApps += [PSCustomObject]@{
                        Name=$m.AdditionalProperties.displayName; Role=$role.DisplayName;
                        Type='Service Principal'; Risk='Critical'
                    }
                }
            }
        }
        Write-Host "  [+] Privileged NHIs in directory roles: $($Entra_PrivilegedApps.Count)" -ForegroundColor $(if($Entra_PrivilegedApps.Count -gt 0){'Red'}else{'Green'})
    } catch { Write-Host "  [i] Directory role member analysis skipped" -ForegroundColor Gray }

    # --- Stale Apps (no sign-in in 90+ days) ---
    try {
        $spSignIn = Graph-Get -Uri 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities' -Label "Service principal sign-in activity"
        if ($spSignIn.Count -gt 0) {
            foreach ($activity in $spSignIn) {
                $lastSignIn = $activity.lastSignInActivity.lastSignInDateTime
                if ($lastSignIn -and [datetime]$lastSignIn -lt $staleThreshold) {
                    $spMatch = $Entra_AllSPs | Where-Object { $_.AppId -eq $activity.appId } | Select-Object -First 1
                    if ($spMatch -and $spMatch.AppOwnerOrganizationId -ne $MicrosoftTenantId) {
                        $Entra_StaleApps += [PSCustomObject]@{
                            Name=$spMatch.DisplayName; AppId=$activity.appId;
                            LastSignIn=$lastSignIn; Type=$spMatch.ServicePrincipalType;
                            Risk='Medium'
                        }
                    }
                }
            }
        }
    } catch { }

    # --- Entra Connect Sync Accounts (cloud side) ---
    try {
        $cloudSyncSPs = @($Entra_AllSPs | Where-Object {
            $_.DisplayName -like 'MSOL_*' -or $_.DisplayName -like 'Sync_*' -or
            $_.DisplayName -like '*Entra Connect*' -or $_.DisplayName -like '*AAD Connect*' -or
            $_.DisplayName -like '*ConnectSyncProvisioning*'
        })
        if ($cloudSyncSPs.Count -gt 0) {
            Write-Host "  [+] Entra Connect cloud identities: $($cloudSyncSPs.Count)" -ForegroundColor Green
        }
    } catch { }
}

Write-Host ""
Write-Host "  [+] NHI discovery complete." -ForegroundColor Green

# ==============================================================================
# BUILD SUMMARY COUNTS
# ==============================================================================
$ADSvcCount    = $AD_SPNAccounts.Count
$ADgMSACount   = $AD_gMSAs.Count
$ADsMSACount   = $AD_sMSAs.Count
$ADdMSACount   = $AD_dMSAs.Count
$ADSyncCount   = $AD_SyncAccounts.Count
$ADKRBCount    = $AD_KRBTGT.Count
$ADCompTotal   = ($AD_Computers | Measure-Object -Property Total -Sum).Sum
$ADCompStale   = ($AD_Computers | Measure-Object -Property Stale90Days -Sum).Sum
$ADPrivNHI     = $AD_PrivilegedNHIs.Count
$ADNeverExpire = $AD_NeverExpirePwd.Count
$ADStaleCount  = @($AD_StaleService | Select-Object -Unique).Count

$EntraAppCount    = $Entra_AppRegs.Count
$EntraSPCount     = $Entra_SPByCategory.Count
$EntraMICount     = $Entra_ManagedIds.Count
$EntraExpiredCount = @($Entra_ExpiredCreds | Where-Object { $_.Status -eq 'EXPIRED' }).Count
$EntraExpiringCount = @($Entra_ExpiredCreds | Where-Object { $_.Status -eq 'Expiring Soon' }).Count
$EntraPrivCount   = $Entra_PrivilegedApps.Count
$EntraStaleCount  = $Entra_StaleApps.Count

$TotalNHIs = $ADSvcCount + $ADgMSACount + $ADsMSACount + $ADdMSACount + $ADSyncCount + $ADKRBCount + $ADCompTotal + $EntraAppCount + $EntraSPCount

# Build tables
$SPNTable        = if ($AD_SPNAccounts.Count -gt 0) { ConvertTo-HtmlTable -Data ($AD_SPNAccounts | Sort-Object Risk,Name) -Properties Name, Domain, Type, Enabled, PasswordNeverExpires, PasswordLastSet, LastLogon, AdminCount, Risk } else { '<p class="empty-note">No SPN user accounts found.</p>' }
$gMSATable       = if ($AD_gMSAs.Count -gt 0) { ConvertTo-HtmlTable -Data $AD_gMSAs -Properties Name, Domain, Enabled, PasswordLastSet, AllowedPrincipals, MemberOf, Risk } else { '<p class="empty-note">No gMSAs found.</p>' }
$sMSATable       = if ($AD_sMSAs.Count -gt 0) { ConvertTo-HtmlTable -Data $AD_sMSAs -Properties Name, Domain, Enabled, PasswordLastSet, MemberOf, Risk } else { '<p class="empty-note">No sMSAs found.</p>' }
$dMSATable       = if ($AD_dMSAs.Count -gt 0) { ConvertTo-HtmlTable -Data $AD_dMSAs -Properties Name, Domain, Created, Description, Risk } else { '<p class="empty-note">No dMSAs found (requires AD schema 91+).</p>' }
$KRBTable        = if ($AD_KRBTGT.Count -gt 0) { ConvertTo-HtmlTable -Data $AD_KRBTGT -Properties Name, Domain, PasswordLastSet, PasswordAgeDays, Risk } else { '<p class="empty-note">No KRBTGT data.</p>' }
$SyncTable       = if ($AD_SyncAccounts.Count -gt 0) { ConvertTo-HtmlTable -Data $AD_SyncAccounts -Properties Name, Domain, Type, Enabled, PasswordLastSet, LastLogon, MemberOf, Risk } else { '<p class="empty-note">No Entra Connect sync accounts detected.</p>' }
$CompTable       = if ($AD_Computers.Count -gt 0) { ConvertTo-HtmlTable -Data $AD_Computers -Properties Domain, Total, Enabled, Disabled, Stale90Days, Servers, Workstations } else { '<p class="empty-note">No computer account data.</p>' }
$PrivNHITable    = if ($AD_PrivilegedNHIs.Count -gt 0) { ConvertTo-HtmlTable -Data ($AD_PrivilegedNHIs | Sort-Object Group) -Properties Name, Domain, Group, Type, Risk } else { '<p class="empty-note">No service accounts found in privileged groups.</p>' }
$AppRegTable     = if ($Entra_AppRegs.Count -gt 0) { ConvertTo-HtmlTable -Data ($Entra_AppRegs | Sort-Object Risk -Descending | Select-Object -First 100) -Properties Name, AppId, Audience, Secrets, Certificates, HasExpired, HasAppRolePerms, Created, Risk } else { '<p class="empty-note">No app registrations.</p>' }
$ExpCredTable    = if ($Entra_ExpiredCreds.Count -gt 0) { ConvertTo-HtmlTable -Data $Entra_ExpiredCreds -Properties AppName, AppId, CredType, Expiry, Status, Risk } else { '<p class="empty-note">No expired or expiring credentials.</p>' }
$ManagedIdTable  = if ($Entra_ManagedIds.Count -gt 0) { ConvertTo-HtmlTable -Data $Entra_ManagedIds -Properties Name, AppId, Type, Enabled, Created, Risk } else { '<p class="empty-note">No managed identities found.</p>' }
$PrivAppsTable   = if ($Entra_PrivilegedApps.Count -gt 0) { ConvertTo-HtmlTable -Data $Entra_PrivilegedApps -Properties Name, Role, Type, Risk } else { '<p class="empty-note">No service principals in privileged directory roles.</p>' }
$StaleAppsTable  = if ($Entra_StaleApps.Count -gt 0) { ConvertTo-HtmlTable -Data $Entra_StaleApps -Properties Name, AppId, LastSignIn, Type, Risk } else { '<p class="empty-note">No stale apps detected (or sign-in activity data not available).</p>' }

# Custom SP table (non-Microsoft)
$CustomSPData = @($Entra_SPByCategory | Where-Object { $_.Category -ne 'Microsoft First-Party' } | Sort-Object Category, Name | Select-Object -First 100)
$CustomSPTable = if ($CustomSPData.Count -gt 0) { ConvertTo-HtmlTable -Data $CustomSPData -Properties Name, AppId, Category, Type, Enabled, Created } else { '<p class="empty-note">No custom or third-party service principals.</p>' }

# Chart JSON
$ADNHITypeJSON = '{"SPN User Accounts":' + $ADSvcCount + ',"gMSA":' + $ADgMSACount + ',"sMSA":' + $ADsMSACount + ',"dMSA":' + $ADdMSACount + ',"Sync Accounts":' + $ADSyncCount + '}'
$EntraNHITypeJSON = '{"Custom Apps":' + $CustomSP + ',"Third-Party":' + $ThirdPartySP + ',"Managed Identity":' + $ManagedIdCount + ',"Microsoft First-Party":' + $MSFirstParty + '}'
$RiskJSON = '{"Critical":' + (@($AD_SPNAccounts | Where-Object {$_.Risk -eq 'Critical'}).Count + @($Entra_PrivilegedApps).Count + @($AD_SyncAccounts).Count + @($AD_KRBTGT | Where-Object {$_.Risk -eq 'Critical'}).Count) + ',"High":' + (@($AD_SPNAccounts | Where-Object {$_.Risk -eq 'High'}).Count + @($Entra_ExpiredCreds | Where-Object {$_.Risk -eq 'High'}).Count) + ',"Medium":' + (@($AD_SPNAccounts | Where-Object {$_.Risk -eq 'Medium'}).Count + @($Entra_ExpiredCreds | Where-Object {$_.Risk -eq 'Medium'}).Count + @($Entra_StaleApps).Count) + ',"Low":' + ($ADgMSACount + $ADdMSACount + $EntraMICount) + '}'
$CredStatusJSON = '{"Expired":' + $EntraExpiredCount + ',"Expiring 30d":' + $EntraExpiringCount + ',"Healthy":' + (@($Entra_AppRegs | Where-Object { -not $_.HasExpired }).Count) + '}'

# ==============================================================================
# HTML REPORT
# ==============================================================================
$HTML = @"
<!--
================================================================================
  NHICanvas -- Non-Human Identity Governance Report
  Generated : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
  Author    : Santhosh Sivarajan, Microsoft MVP
  GitHub    : https://github.com/SanthoshSivarajan/NHICanvas
================================================================================
-->
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="author" content="Santhosh Sivarajan, Microsoft MVP"/>
<title>NHICanvas -- $(if($HasAD){$ForestName}else{''})$(if($HasAD -and $HasGraph){' + '}else{''})$(if($HasGraph){$TenantName}else{''})</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0f172a;--surface:#1e293b;--surface2:#273548;--border:#334155;--text:#e2e8f0;--text-dim:#94a3b8;--accent:#60a5fa;--accent2:#22d3ee;--green:#34d399;--red:#f87171;--amber:#fbbf24;--purple:#a78bfa;--pink:#f472b6;--orange:#fb923c;--radius:8px;--shadow:0 1px 3px rgba(0,0,0,.3);--font-body:'Segoe UI',system-ui,sans-serif}
html{scroll-behavior:smooth;font-size:15px}body{font-family:var(--font-body);background:var(--bg);color:var(--text);line-height:1.65;min-height:100vh}a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.wrapper{display:flex;min-height:100vh}.sidebar{position:fixed;top:0;left:0;width:260px;height:100vh;background:var(--surface);border-right:1px solid var(--border);overflow-y:auto;padding:20px 0;z-index:100;box-shadow:2px 0 12px rgba(0,0,0,.3)}.sidebar::-webkit-scrollbar{width:4px}.sidebar::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}.sidebar .logo{padding:0 18px 14px;border-bottom:1px solid var(--border);margin-bottom:8px}.sidebar .logo h2{font-size:1.05rem;color:var(--accent);font-weight:700}.sidebar .logo p{font-size:.68rem;color:var(--text-dim);margin-top:2px}.sidebar nav a{display:block;padding:5px 18px 5px 22px;font-size:.78rem;color:var(--text-dim);border-left:3px solid transparent;transition:all .15s}.sidebar nav a:hover,.sidebar nav a.active{color:var(--accent);background:rgba(96,165,250,.08);border-left-color:var(--accent);text-decoration:none}.sidebar nav .nav-group{font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:var(--accent2);padding:10px 18px 2px;font-weight:700}
.main{margin-left:260px;flex:1;padding:24px 32px 50px;max-width:1200px}.section{margin-bottom:36px}.section-title{font-size:1.25rem;font-weight:700;color:var(--text);margin-bottom:4px;padding-bottom:8px;border-bottom:2px solid var(--border);display:flex;align-items:center;gap:8px}.section-title .icon{width:24px;height:24px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:.8rem;flex-shrink:0}.sub-header{font-size:.92rem;color:var(--text);margin:16px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--border)}.section-desc{color:var(--text-dim);font-size:.84rem;margin-bottom:14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:16px}.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;box-shadow:var(--shadow)}.card:hover{border-color:var(--accent)}.card .card-val{font-size:1.5rem;font-weight:800;line-height:1.1}.card .card-label{font-size:.68rem;color:var(--text-dim);margin-top:2px;text-transform:uppercase;letter-spacing:.05em}
.table-wrap{overflow-x:auto;margin-bottom:8px;border-radius:var(--radius);border:1px solid var(--border);box-shadow:var(--shadow)}table{width:100%;border-collapse:collapse;font-size:.78rem}thead{background:rgba(96,165,250,.1)}th{text-align:left;padding:8px 10px;font-weight:600;color:var(--accent);white-space:nowrap;border-bottom:2px solid var(--border)}td{padding:7px 10px;border-bottom:1px solid var(--border);color:var(--text-dim);max-width:360px;overflow:hidden;text-overflow:ellipsis}tbody tr:hover{background:rgba(96,165,250,.06)}tbody tr:nth-child(even){background:var(--surface2)}.empty-note{color:var(--text-dim);font-style:italic;padding:8px 0}
.exec-summary{background:linear-gradient(135deg,#1e293b 0%,#1e3a5f 100%);border:1px solid #334155;border-radius:var(--radius);padding:22px 26px;margin-bottom:28px;box-shadow:var(--shadow)}.exec-summary h2{font-size:1.1rem;color:var(--accent);margin-bottom:8px}.exec-summary p{color:var(--text-dim);font-size:.86rem;line-height:1.7;margin-bottom:6px}.exec-kv{display:inline-block;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:2px 8px;margin:2px;font-size:.78rem;color:var(--text)}.exec-kv strong{color:var(--accent2)}
.footer{margin-top:36px;padding:18px 0;border-top:1px solid var(--border);text-align:center;color:var(--text-dim);font-size:.74rem}.footer a{color:var(--accent)}
@media print{.sidebar{display:none}.main{margin-left:0}body{background:#fff;color:#222}.card,.exec-summary{background:#f9f9f9;border-color:#ccc;color:#222}.card-val,.section-title{color:#222}th{color:#333;background:#eee}td{color:#444}}
@media(max-width:900px){.sidebar{display:none}.main{margin-left:0;padding:14px}}
</style>
</head>
<body>
<div class="wrapper">
<aside class="sidebar">
  <div class="logo"><h2>NHICanvas</h2><p>Developed by Santhosh Sivarajan</p><p style="margin-top:6px">$(if($HasAD){"Forest: <strong style=`"color:#e2e8f0`">$ForestName</strong><br>"}else{''})$(if($HasGraph){"Tenant: <strong style=`"color:#e2e8f0`">$TenantName</strong>"}else{''})</p></div>
  <nav>
    <div class="nav-group">Overview</div>
    <a href="#summary">Executive Summary</a>
    $(if($HasAD){@"
    <div class="nav-group">Active Directory</div>
    <a href="#ad-service-accounts">Service Accounts (SPN)</a>
    <a href="#ad-gmsa">gMSA</a>
    <a href="#ad-smsa">sMSA</a>
    <a href="#ad-dmsa">dMSA</a>
    <a href="#ad-sync">Entra Connect Sync</a>
    <a href="#ad-krbtgt">KRBTGT</a>
    <a href="#ad-computers">Computer Accounts</a>
    <a href="#ad-privileged">Privileged NHIs</a>
"@}else{''})
    $(if($HasGraph){@"
    <div class="nav-group">Entra ID</div>
    <a href="#entra-apps">App Registrations</a>
    <a href="#entra-sp">Service Principals</a>
    <a href="#entra-mi">Managed Identities</a>
    <a href="#entra-creds">Credential Health</a>
    <a href="#entra-priv">Privileged NHIs</a>
    <a href="#entra-stale">Stale Apps</a>
"@}else{''})
    <div class="nav-group">Visuals</div>
    <a href="#charts">Charts</a>
  </nav>
</aside>
<main class="main">

<!-- EXECUTIVE SUMMARY -->
<div id="summary" class="section">
  <div class="exec-summary">
    <h2>Non-Human Identity Governance -- Executive Summary</h2>
    <p>NHI discovery across $(if($HasAD -and $HasGraph){'Active Directory and Entra ID'}elseif($HasAD){'Active Directory'}else{'Entra ID'}), generated on <strong>$(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm")</strong>.</p>
    <p>
      $(if($HasAD){@"
      <span class="exec-kv"><strong>AD Forest:</strong> $ForestName</span>
      <span class="exec-kv"><strong>SPN Service Accounts:</strong> $ADSvcCount</span>
      <span class="exec-kv"><strong>gMSA:</strong> $ADgMSACount</span>
      <span class="exec-kv"><strong>sMSA:</strong> $ADsMSACount</span>
      <span class="exec-kv"><strong>dMSA:</strong> $ADdMSACount</span>
      <span class="exec-kv"><strong>Sync Accounts:</strong> $ADSyncCount</span>
      <span class="exec-kv"><strong>Computer Accounts:</strong> $ADCompTotal</span>
      <span class="exec-kv" style="color:#f87171"><strong>Privileged NHIs:</strong> $ADPrivNHI</span>
      <span class="exec-kv" style="color:#fbbf24"><strong>Password Never Expires:</strong> $ADNeverExpire</span>
      <span class="exec-kv"><strong>Stale Service Accts:</strong> $ADStaleCount</span>
"@}else{''})
      $(if($HasGraph){@"
      <span class="exec-kv"><strong>Tenant:</strong> $TenantName</span>
      <span class="exec-kv"><strong>App Registrations:</strong> $EntraAppCount</span>
      <span class="exec-kv"><strong>Service Principals:</strong> $EntraSPCount</span>
      <span class="exec-kv"><strong>Managed Identities:</strong> $EntraMICount</span>
      <span class="exec-kv"><strong>Custom/3rd-Party SPs:</strong> $($CustomSP + $ThirdPartySP)</span>
      <span class="exec-kv" style="color:#f87171"><strong>Expired Credentials:</strong> $EntraExpiredCount</span>
      <span class="exec-kv" style="color:#fbbf24"><strong>Expiring (30d):</strong> $EntraExpiringCount</span>
      <span class="exec-kv" style="color:#f87171"><strong>Privileged Apps:</strong> $EntraPrivCount</span>
"@}else{''})
    </p>
  </div>
</div>

$(if($HasAD){@"
<!-- AD: SERVICE ACCOUNTS (SPN) -->
<div id="ad-service-accounts" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#128100;</span> AD Service Accounts -- SPN User Accounts ($ADSvcCount)</h2>
  <p class="section-desc">User accounts with servicePrincipalName (SPN) set -- these are non-human identities running services.</p>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$ADSvcCount</div><div class="card-label">Total SPN Accounts</div></div>
    <div class="card"><div class="card-val" style="color:var(--red)">$ADNeverExpire</div><div class="card-label">Pwd Never Expires</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$ADStaleCount</div><div class="card-label">Stale (90d+)</div></div>
    <div class="card"><div class="card-val" style="color:var(--red)">$ADPrivNHI</div><div class="card-label">In Privileged Groups</div></div>
  </div>
  $SPNTable
</div>

<!-- AD: gMSA -->
<div id="ad-gmsa" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(52,211,153,.15);color:var(--green)">&#128273;</span> Group Managed Service Accounts ($ADgMSACount)</h2>
  <p class="section-desc">gMSAs have auto-rotating passwords managed by AD -- the recommended approach for service accounts.</p>
  $gMSATable
</div>

<!-- AD: sMSA -->
<div id="ad-smsa" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(251,191,36,.15);color:var(--amber)">&#128273;</span> Standalone Managed Service Accounts ($ADsMSACount)</h2>
  <p class="section-desc">sMSAs are single-server managed service accounts. Consider migrating to gMSA for multi-server support.</p>
  $sMSATable
</div>

<!-- AD: dMSA -->
<div id="ad-dmsa" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128273;</span> Delegated Managed Service Accounts ($ADdMSACount)</h2>
  <p class="section-desc">dMSAs (Server 2025+) allow credential isolation and delegation without exposing passwords.</p>
  $dMSATable
</div>

<!-- AD: SYNC ACCOUNTS -->
<div id="ad-sync" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#128260;</span> Entra Connect Sync Accounts ($ADSyncCount)</h2>
  <p class="section-desc">MSOL_ and Sync_ accounts used by Entra Connect for directory synchronization. These are critical NHIs with high privileges.</p>
  $SyncTable
</div>

<!-- AD: KRBTGT -->
<div id="ad-krbtgt" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(167,139,250,.15);color:var(--purple)">&#128274;</span> KRBTGT Account</h2>
  <p class="section-desc">The Kerberos ticket-granting account. Password should be rotated at least every 180 days to mitigate Golden Ticket attacks.</p>
  $KRBTable
</div>

<!-- AD: COMPUTER ACCOUNTS -->
<div id="ad-computers" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(34,211,238,.15);color:var(--accent2)">&#128187;</span> Computer Accounts</h2>
  <p class="section-desc">Every domain-joined computer is a non-human identity. Stale computer accounts should be disabled and removed.</p>
  $CompTable
</div>

<!-- AD: PRIVILEGED NHIs -->
<div id="ad-privileged" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#9888;</span> Privileged NHIs -- Service Accounts in Admin Groups ($ADPrivNHI)</h2>
  <p class="section-desc">Service accounts (SPN user accounts) that are members of privileged groups. These are critical risk -- consider migrating to gMSA with least-privilege.</p>
  $PrivNHITable
</div>
"@}else{''})

$(if($HasGraph){@"
<!-- ENTRA: APP REGISTRATIONS -->
<div id="entra-apps" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128736;</span> App Registrations ($EntraAppCount)</h2>
  <p class="section-desc">App registrations with credential status, audience, and permission risk assessment.</p>
  $AppRegTable
</div>

<!-- ENTRA: SERVICE PRINCIPALS -->
<div id="entra-sp" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(34,211,238,.15);color:var(--accent2)">&#9881;</span> Service Principals ($EntraSPCount)</h2>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--accent)">$EntraSPCount</div><div class="card-label">Total</div></div>
    <div class="card"><div class="card-val" style="color:var(--text-dim)">$MSFirstParty</div><div class="card-label">Microsoft 1st-Party</div></div>
    <div class="card"><div class="card-val" style="color:var(--green)">$CustomSP</div><div class="card-label">Custom (Your Tenant)</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$ThirdPartySP</div><div class="card-label">Third-Party</div></div>
    <div class="card"><div class="card-val" style="color:var(--purple)">$ManagedIdCount</div><div class="card-label">Managed Identity</div></div>
  </div>
  <h3 class="sub-header">Custom and Third-Party Service Principals (top 100)</h3>
  $CustomSPTable
</div>

<!-- ENTRA: MANAGED IDENTITIES -->
<div id="entra-mi" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(52,211,153,.15);color:var(--green)">&#128273;</span> Managed Identities ($EntraMICount)</h2>
  <p class="section-desc">Managed identities are the recommended NHI type for Azure workloads -- no credential management required.</p>
  $ManagedIdTable
</div>

<!-- ENTRA: CREDENTIAL HEALTH -->
<div id="entra-creds" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#9888;</span> Credential Health</h2>
  <div class="cards">
    <div class="card"><div class="card-val" style="color:var(--red)">$EntraExpiredCount</div><div class="card-label">Expired</div></div>
    <div class="card"><div class="card-val" style="color:var(--amber)">$EntraExpiringCount</div><div class="card-label">Expiring (30 days)</div></div>
  </div>
  $ExpCredTable
</div>

<!-- ENTRA: PRIVILEGED NHIs -->
<div id="entra-priv" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(248,113,113,.15);color:var(--red)">&#128737;</span> Privileged NHIs -- Apps in Directory Roles ($EntraPrivCount)</h2>
  <p class="section-desc">Service principals assigned to privileged Entra ID directory roles. These NHIs have elevated tenant-wide permissions.</p>
  $PrivAppsTable
</div>

<!-- ENTRA: STALE APPS -->
<div id="entra-stale" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(251,191,36,.15);color:var(--amber)">&#128340;</span> Stale Applications ($EntraStaleCount)</h2>
  <p class="section-desc">Service principals with no sign-in activity in 90+ days (excluding Microsoft first-party). Consider reviewing or removing.</p>
  $StaleAppsTable
</div>
"@}else{''})

<!-- CHARTS -->
<div id="charts" class="section">
  <h2 class="section-title"><span class="icon" style="background:rgba(96,165,250,.15);color:var(--accent)">&#128202;</span> NHI Analytics</h2>
  <div id="chartsContainer" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px"></div>
</div>

<div class="footer">
  NHICanvas v1.0 -- Non-Human Identity Governance Report -- $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
  Developed by <a href="https://github.com/SanthoshSivarajan">Santhosh Sivarajan</a>, Microsoft MVP --
  <a href="https://github.com/SanthoshSivarajan/NHICanvas">github.com/SanthoshSivarajan/NHICanvas</a>
</div>
</main>
</div>
<script>
var COLORS=['#60a5fa','#34d399','#f87171','#fbbf24','#a78bfa','#f472b6','#22d3ee','#fb923c','#a3e635','#e879f9'];
function buildBarChart(t,d,c){var b=document.createElement('div');b.style.cssText='background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;box-shadow:var(--shadow)';var h=document.createElement('h3');h.style.cssText='font-size:.86rem;margin-bottom:10px;color:#e2e8f0';h.textContent=t;b.appendChild(h);var tot=Object.values(d).reduce(function(a,b){return a+b},0);if(!tot){b.innerHTML+='<p style="color:#94a3b8">No data.</p>';c.appendChild(b);return}var g=document.createElement('div');g.style.cssText='display:flex;flex-direction:column;gap:6px';var e=Object.entries(d),ci=0;for(var i=0;i<e.length;i++){var p=((e[i][1]/tot)*100).toFixed(1);var r=document.createElement('div');r.style.cssText='display:flex;align-items:center;gap:8px';r.innerHTML='<span style="width:120px;font-size:.74rem;color:#94a3b8;text-align:right;flex-shrink:0">'+e[i][0]+'</span><div style="flex:1;height:20px;background:#273548;border-radius:4px;overflow:hidden;border:1px solid #334155"><div style="height:100%;border-radius:3px;width:'+p+'%;background:'+COLORS[ci%COLORS.length]+';display:flex;align-items:center;padding:0 6px;font-size:.66rem;font-weight:600;color:#fff;white-space:nowrap">'+p+'%</div></div><span style="width:44px;font-size:.74rem;color:#94a3b8;text-align:right">'+e[i][1]+'</span>';g.appendChild(r);ci++}b.appendChild(g);c.appendChild(b)}
function buildDonut(t,d,c){var b=document.createElement('div');b.style.cssText='background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;box-shadow:var(--shadow)';var h=document.createElement('h3');h.style.cssText='font-size:.86rem;margin-bottom:10px;color:#e2e8f0';h.textContent=t;b.appendChild(h);var tot=Object.values(d).reduce(function(a,b){return a+b},0);if(!tot){b.innerHTML+='<p style="color:#94a3b8">No data.</p>';c.appendChild(b);return}var dc=document.createElement('div');dc.style.cssText='display:flex;align-items:center;gap:18px;flex-wrap:wrap';var sz=130,cx=65,cy=65,r=48,cf=2*Math.PI*r;var s='<svg width="'+sz+'" height="'+sz+'" viewBox="0 0 '+sz+' '+sz+'">';var off=0,ci=0,e=Object.entries(d);for(var i=0;i<e.length;i++){var pc=e[i][1]/tot,da=pc*cf,ga=cf-da;s+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+COLORS[ci%COLORS.length]+'" stroke-width="14" stroke-dasharray="'+da.toFixed(2)+' '+ga.toFixed(2)+'" stroke-dashoffset="'+(-off).toFixed(2)+'" transform="rotate(-90 '+cx+' '+cy+')" />';off+=da;ci++}s+='<text x="'+cx+'" y="'+cy+'" text-anchor="middle" dominant-baseline="central" fill="#e2e8f0" font-size="18" font-weight="700">'+tot+'</text></svg>';dc.innerHTML=s;var lg=document.createElement('div');lg.style.cssText='display:flex;flex-direction:column;gap:3px';ci=0;for(var i=0;i<e.length;i++){var pc=((e[i][1]/tot)*100).toFixed(1);var it=document.createElement('div');it.style.cssText='display:flex;align-items:center;gap:6px;font-size:.74rem;color:#94a3b8';it.innerHTML='<span style="width:10px;height:10px;border-radius:2px;background:'+COLORS[ci%COLORS.length]+';flex-shrink:0"></span>'+e[i][0]+': '+e[i][1]+' ('+pc+'%)';lg.appendChild(it);ci++}dc.appendChild(lg);b.appendChild(dc);c.appendChild(b)}
(function(){var c=document.getElementById('chartsContainer');if(!c)return;
$(if($HasAD){"buildDonut('AD NHI Types',${ADNHITypeJSON},c);"}else{''})
$(if($HasGraph){"buildDonut('Entra Service Principal Types',${EntraNHITypeJSON},c);"}else{''})
buildDonut('NHI Risk Distribution',$RiskJSON,c);
$(if($HasGraph){"buildDonut('Credential Status',${CredStatusJSON},c);"}else{''})
})();
(function(){var lk=document.querySelectorAll('.sidebar nav a');var sc=[];for(var i=0;i<lk.length;i++){var id=lk[i].getAttribute('href');if(id&&id.charAt(0)==='#'){var el=document.querySelector(id);if(el)sc.push({el:el,link:lk[i]})}}window.addEventListener('scroll',function(){var cur=sc[0];for(var i=0;i<sc.length;i++){if(sc[i].el.getBoundingClientRect().top<=120)cur=sc[i]}for(var i=0;i<lk.length;i++)lk[i].classList.remove('active');if(cur)cur.link.classList.add('active')})})();
</script>
</body>
</html>
<!--
================================================================================
  NHICanvas -- Non-Human Identity Governance Report
  Author : Santhosh Sivarajan, Microsoft MVP
  GitHub : https://github.com/SanthoshSivarajan/NHICanvas
================================================================================
-->
"@

$HTML | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
$FileSize = [math]::Round((Get-Item $OutputFile).Length / 1KB, 1)

Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host "  |   NHICanvas -- Report Generation Complete                  |" -ForegroundColor Green
Write-Host "  +============================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  NHI SUMMARY" -ForegroundColor White
Write-Host "  -----------" -ForegroundColor Gray
if ($HasAD) {
    Write-Host "    AD Forest            : $ForestName" -ForegroundColor White
    Write-Host "    SPN Service Accounts : $ADSvcCount" -ForegroundColor White
    Write-Host "    gMSA / sMSA / dMSA  : $ADgMSACount / $ADsMSACount / $ADdMSACount" -ForegroundColor White
    Write-Host "    Entra Connect Sync   : $ADSyncCount" -ForegroundColor White
    Write-Host "    Computer Accounts    : $ADCompTotal (stale: $ADCompStale)" -ForegroundColor White
    Write-Host "    Privileged NHIs      : $ADPrivNHI" -ForegroundColor $(if($ADPrivNHI -gt 0){'Red'}else{'Green'})
    Write-Host "    Pwd Never Expires    : $ADNeverExpire" -ForegroundColor $(if($ADNeverExpire -gt 0){'Yellow'}else{'Green'})
}
if ($HasGraph) {
    Write-Host "    Tenant               : $TenantName" -ForegroundColor White
    Write-Host "    App Registrations    : $EntraAppCount" -ForegroundColor White
    Write-Host "    Service Principals   : $EntraSPCount (Custom: $CustomSP, 3P: $ThirdPartySP, MI: $ManagedIdCount)" -ForegroundColor White
    Write-Host "    Expired Creds        : $EntraExpiredCount" -ForegroundColor $(if($EntraExpiredCount -gt 0){'Red'}else{'Green'})
    Write-Host "    Privileged Apps      : $EntraPrivCount" -ForegroundColor $(if($EntraPrivCount -gt 0){'Red'}else{'Green'})
}
Write-Host ""
Write-Host "    Report File : $OutputFile" -ForegroundColor White
Write-Host "    File Size   : $FileSize KB" -ForegroundColor White
Write-Host ""
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host "  |  This report was generated using NHICanvas v1.0            |" -ForegroundColor Cyan
Write-Host "  |  Developed by Santhosh Sivarajan, Microsoft MVP            |" -ForegroundColor Cyan
Write-Host "  |  https://github.com/SanthoshSivarajan/NHICanvas            |" -ForegroundColor Cyan
Write-Host "  +============================================================+" -ForegroundColor Cyan
Write-Host ""

<#
================================================================================
  NHICanvas v1.0 -- Non-Human Identity Governance Tool
  Author : Santhosh Sivarajan, Microsoft MVP
  GitHub : https://github.com/SanthoshSivarajan/NHICanvas
================================================================================
#>
