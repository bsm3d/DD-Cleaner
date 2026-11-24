// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the read-only checks of the security audit and the global and per-domain score of the audit.

#include <algorithm>
#include <cmath>
#include <cstdarg>
#include <ctime>
#include <regex>

#include <windows.h>

#include <ddcore/audit.hpp>
#include <ddcore/registry.hpp>
#include <ddcore/sysinfo.hpp>

namespace dd {

namespace {

std::wstring fmt(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    int n = _vscwprintf(format, copy);
    va_end(copy);
    std::wstring out;
    if (n > 0) {
        out.resize((std::size_t)n + 1);
        vswprintf(out.data(), out.size(), format, args);
        out.resize((std::size_t)n);
    }
    va_end(args);
    return out;
}

std::wstring ps_quote(const std::wstring& value) {
    std::wstring out = L"'";
    for (wchar_t c : value) {
        if (c == L'\'') out += L"''";
        else out.push_back(c);
    }
    return out + L"'";
}

const std::wstring LSA_KEY = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
const std::wstring WDIGEST_KEY = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest";
const std::wstring HVCI_KEY = L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity";
const std::wstring NETBIOS_ROOT = L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces";
const unsigned long NETBIOS_DISABLED = 2;
const wchar_t* HKCU_NOTE =
    L" (Setting read from the profile of the user who launched the app as administrator; if elevation used a different account, this profile may differ "
    L"from the logged-on session.)";

bool netbios_iface(const std::wstring& name) {
    static const std::wregex re(LR"(^Tcpip_\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$)");
    return std::regex_match(name, re);
}

PsJson ps_json(const std::wstring& script, unsigned long timeout = 60000) { return system_hooks().ps_json(script, timeout); }

RegistryState reg(const std::wstring& hive, const std::wstring& path, const std::wstring& name) { return system_hooks().registry.read(hive, path, name); }

std::map<std::wstring, RegistryState> netbios_interfaces() {
    std::map<std::wstring, RegistryState> out;   // state.exists == false: value absent = default = enabled
    for (const auto& name : system_hooks().registry.subkeys(L"HKLM", NETBIOS_ROOT)) {
        if (netbios_iface(name)) out[name] = reg(L"HKLM", NETBIOS_ROOT + L"\\" + name, L"NetbiosOptions");
    }
    return out;
}

}  // namespace

int SecurityAuditor::global_score(const std::map<Domain, DomainScore>& scores) {
    double total = 0;
    for (const auto& [domain, weight] : DOMAIN_WEIGHTS) {
        auto it = scores.find(domain);
        if (it != scores.end() && it->second.max_score > 0) total += (double)it->second.current_score / it->second.max_score * weight;
    }
    return (int)std::nearbyint(total);
}

std::vector<Issue> SecurityAuditor::critical_issues(std::size_t limit) const {
    std::vector<Issue> critical;
    for (const auto& i : issues_) {
        if (i.risk == Risk::Critical || i.risk == Risk::High) critical.push_back(i);
    }
    std::stable_sort(critical.begin(), critical.end(), [](const Issue& a, const Issue& b) {
        if (a.risk != b.risk) return a.risk > b.risk;
        return a.score_impact > b.score_impact;
    });
    if (critical.size() > limit) critical.resize(limit);
    return critical;
}

void SecurityAuditor::record_domain(Domain domain, int max_score, const std::vector<Issue>& issues) {
    int lost = 0;
    for (const auto& i : issues) lost += i.score_impact;
    work_issues_.insert(work_issues_.end(), issues.begin(), issues.end());
    DomainScore s;
    s.domain = domain;
    s.current_score = std::max(0, max_score - lost);
    s.max_score = max_score;
    s.issues = issues;
    work_scores_[domain] = s;
}

// region System

bool SecurityAuditor::check_defender(Issue& out) {
    static const wchar_t* script = LR"J(
$r = [ordered]@{ Rtp = $null; DefenderSc = $null; OtherAv = @() }
try { $r.Rtp = [bool](Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled } catch { }
try {
    $av = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
    $def = @($av | Where-Object { $_.pathToSignedProductExe -like 'windowsdefender://*' })
    if ($def.Count) { $r.DefenderSc = (([int]$def[0].productState -band 0x1000) -ne 0) }
    $r.OtherAv = @($av |
        Where-Object { ($_.pathToSignedProductExe -notlike 'windowsdefender://*') -and (([int]$_.productState -band 0x1000) -ne 0) } |
        ForEach-Object { [string]$_.displayName })
} catch { }
$r | ConvertTo-Json -Compress
)J";
    Json data = ps_json(script).data;
    if (!data.is_object()) return false;
    Json rtp = data.get(L"Rtp");
    if (rtp.is_null()) rtp = data.get(L"DefenderSc");   // the Defender module is unavailable: fall back to the Security Center state
    if (!data.get(L"OtherAv").as_list().empty()) return false;   // a third-party antivirus is active
    if (rtp.is_bool() && rtp.flag()) return false;
    const wchar_t* url = L"https://docs.microsoft.com/windows/security/threat-protection/microsoft-defender-antivirus";
    if (rtp.is_null()) {
        out = {L"defender_unknown", L"Antivirus protection cannot be verified",
               L"Could not check Windows Defender status and no other active antivirus was detected.", Domain::System, Risk::Medium, L"❔ Unknown",
               L"Check antivirus protection manually (Windows Security)", 2, L"", L"", false, url};
        return true;
    }
    out = {L"defender_disabled", L"Windows Defender disabled", L"Windows Defender real-time protection is off; your system is vulnerable to malware.",
           Domain::System, Risk::Critical, L"❌ Inactive", L"Enable Windows Defender immediately", 5, L"Set-MpPreference -DisableRealtimeMonitoring $false",
           L"Set-MpPreference -DisableRealtimeMonitoring $true", false, url};
    return true;
}

bool SecurityAuditor::check_firewall(Issue& out) {
    PsJson r = ps_json(LR"J(
$off = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
    Where-Object { $_.Enabled.ToString() -eq 'False' } | ForEach-Object { [string]$_.Name })
ConvertTo-Json -InputObject $off -Compress
)J");
    if (r.rc != 0 || r.data.is_null()) return false;
    auto disabled = r.data.as_list();
    if (disabled.empty()) return false;
    std::wstring names;
    for (std::size_t i = 0; i < disabled.size(); ++i) names += (i ? L", " : L"") + disabled[i].str();
    out = {L"firewall_disabled", fmt(L"Firewall disabled (%zu profile(s))", disabled.size()),
           fmt(L"%zu firewall profile(s) disabled (%ls). The system is exposed to unauthorized network connections.", disabled.size(), names.c_str()),
           Domain::System, Risk::Critical, fmt(L"❌ %zu profile(s) inactive", disabled.size()),
           L"Enable the firewall on all profiles (Domain/Private/Public)", 5, L"Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True", L"", false,
           L"https://docs.microsoft.com/windows/security/threat-protection/windows-firewall"};
    return true;
}

// Last successful Windows Update installation, seconds (UTC); 0 when unknown.
static double last_update_time() {
    Json data = ps_json(LR"J(
$r = [ordered]@{ Date = $null }
try {
    $au = New-Object -ComObject Microsoft.Update.AutoUpdate
    $d = $au.Results.LastInstallationSuccessDate
    if ($d) { $r.Date = ([DateTime]$d).ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }
} catch { }
$r | ConvertTo-Json -Compress
)J").data;
    if (data.is_object() && !data.get(L"Date").str().empty()) {
        std::wstring iso = data.get(L"Date").str();
        double t = parse_time(iso);
        int year = _wtoi(iso.substr(0, 4).c_str());
        if (t > 0 && year >= 2000) return t;
    }
    // Legacy fallback (removed on recent Windows 10 builds)
    RegistryState st = reg(L"HKLM", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\Results\\Install", L"LastSuccessTime");
    if (st.exists && !st.text.empty()) {
        std::wstring iso = st.text;
        std::replace(iso.begin(), iso.end(), L' ', L'T');
        return parse_time(iso);
    }
    return 0;
}

static std::wstring date_of(double seconds) {
    std::time_t t = (std::time_t)seconds;
    std::tm tm{};
    gmtime_s(&tm, &t);
    wchar_t buf[16];
    wcsftime(buf, 16, L"%Y-%m-%d", &tm);
    return buf;
}

bool SecurityAuditor::check_windows_update(Issue& out) {
    double last = last_update_time();
    const wchar_t* url = L"https://support.microsoft.com/windows-update";
    if (last <= 0) {
        out = {L"update_unknown", L"Windows Update: status cannot be verified", L"The date of the last successful update installation could not be determined.",
               Domain::System, Risk::Medium, L"❔ Unknown", L"Check Windows Update manually", 2, L"", L"", false, url};
        return true;
    }
    long long days = std::max(0LL, (long long)std::floor((now_seconds() - last) / 86400));
    if (days > 30) {
        out = {L"update_outdated", fmt(L"Windows updates out of date (%lld days)", days),
               fmt(L"Last update %lld days ago. Known security vulnerabilities are not patched.", days), Domain::System, Risk::High,
               L"⚠️ Last update: " + date_of(last), L"Install available Windows updates", 5, L"", L"", false, url};
        return true;
    }
    return false;
}

bool SecurityAuditor::check_uac(Issue& out) {
    const std::wstring hklm = L"HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    const wchar_t* url = L"https://docs.microsoft.com/windows/security/identity-protection/user-account-control";
    const std::wstring path = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    RegistryState lua = reg(L"HKLM", path, L"EnableLUA"), cpba = reg(L"HKLM", path, L"ConsentPromptBehaviorAdmin"), posd = reg(L"HKLM", path, L"PromptOnSecureDesktop");
    long long level = cpba.exists && cpba.numeric() ? cpba.as_int() : 5;
    if (lua.exists && lua.numeric() && lua.as_int() == 0) {
        out = {L"uac_disabled", L"UAC disabled", L"User Account Control is disabled (EnableLUA=0): all programs run with administrator rights.", Domain::System, Risk::High,
               L"❌ Disabled", L"Re-enable UAC (EnableLUA=1, reboot required)", 3, L"Set-ItemProperty '" + hklm + L"' -Name EnableLUA -Value 1",
               L"Set-ItemProperty '" + hklm + L"' -Name EnableLUA -Value 0", true, url};
        return true;
    }
    if (level == 0) {
        out = {L"uac_low", L"UAC too permissive", L"Current UAC level: 0 (elevate without prompting). Programs can elevate without user confirmation.", Domain::System, Risk::Medium,
               L"⚠️ Silent elevation (0)", L"Restore the default level (5) or higher (2 = always notify)", 3,
               L"Set-ItemProperty '" + hklm + L"' -Name ConsentPromptBehaviorAdmin -Value 5", L"Set-ItemProperty '" + hklm + L"' -Name ConsentPromptBehaviorAdmin -Value 0", false, url};
        return true;
    }
    if ((level == 3 || level == 4 || level == 5) && posd.exists && posd.numeric() && posd.as_int() == 0) {
        out = {L"uac_no_secure_desktop", L"UAC prompt not on secure desktop",
               L"The UAC prompt is not shown on the secure desktop (PromptOnSecureDesktop=0): a program can spoof or tamper with the prompt.", Domain::System, Risk::Low,
               L"⚠️ Secure desktop disabled", L"Show the UAC prompt on the secure desktop", 1, L"Set-ItemProperty '" + hklm + L"' -Name PromptOnSecureDesktop -Value 1",
               L"Set-ItemProperty '" + hklm + L"' -Name PromptOnSecureDesktop -Value 0", false, url};
        return true;
    }
    return false;
}

bool SecurityAuditor::check_memory_integrity(Issue& out) {
    Json data = ps_json(LR"J(
$r = [ordered]@{ Running = $null }
try {
    $d = Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
    $r.Running = (@($d.SecurityServicesRunning) -contains 2)
} catch { }
$r | ConvertTo-Json -Compress
)J").data;
    bool running;
    if (data.is_object() && data.get(L"Running").is_bool()) {
        running = data.get(L"Running").flag();
    } else {   // DeviceGuard WMI class missing: fall back to the configured value
        RegistryState st = reg(L"HKLM", HVCI_KEY, L"Enabled");
        running = st.exists && st.numeric() && st.as_int() == 1;
    }
    if (running) return false;
    out = {L"memory_integrity_off", L"Memory integrity (HVCI) is off",
           L"Kernel code integrity is not enforced by the hypervisor, so a vulnerable or malicious driver can run in the kernel. Windows checks driver compatibility "
           L"when you turn it on from Windows Security; setting the registry value by hand skips that check and can stop devices (or boot) if a driver is "
           L"incompatible, so it is not offered as an action.",
           Domain::System, Risk::Medium, L"⚠️ Off",
           L"Windows Security > Device security > Core isolation > Memory integrity (the Driver Checker tab lists drivers on the Microsoft blocklist)", 3, L"", L"", true,
           L"https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity"};
    return true;
}

bool SecurityAuditor::check_lsass_protection(Issue& out) {
    const wchar_t* url = L"https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection";
    RegistryState ppl = reg(L"HKLM", LSA_KEY, L"RunAsPPL");
    if (ppl.exists && ppl.numeric() && (ppl.as_int() == 1 || ppl.as_int() == 2)) return false;
    RegistryState boot = reg(L"HKLM", LSA_KEY, L"RunAsPPLBoot");
    if (boot.exists && boot.numeric() && (boot.as_int() == 1 || boot.as_int() == 2)) return false;
    if (ppl.exists && ppl.numeric() && ppl.as_int() == 0) {   // explicitly turned off: a confident finding
        out = {L"lsass_unprotected", L"LSA protection is off",
               L"LSASS holds logon credentials in memory and is not a protected process, so tools running as administrator can read it. It is not offered as an action: "
               L"on UEFI PCs the setting is also stored in firmware, so removing the registry value does not undo it.",
               Domain::System, Risk::Medium, L"❌ Off",
               L"Windows Security > Device security > Core isolation > Local Security Authority protection (or RunAsPPL=1, reboot). Check that your security software "
               L"supports it first.",
               2, L"", L"", true, url};
        return true;
    }
    out = {L"lsass_unknown", L"LSA protection cannot be confirmed",
           L"Neither RunAsPPL nor RunAsPPLBoot is set. Recent Windows 11 installs can protect LSASS without this registry value, so this may already be on; it cannot "
           L"be confirmed from the registry alone.",
           Domain::System, Risk::Low, L"❔ Unknown", L"Check Windows Security > Device security > Core isolation > Local Security Authority protection", 1, L"", L"", false, url};
    return true;
}

bool SecurityAuditor::check_wdigest(Issue& out) {
    RegistryState st = reg(L"HKLM", WDIGEST_KEY, L"UseLogonCredential");
    if (!(st.exists && st.numeric() && st.as_int() == 1)) return false;
    out = {L"wdigest_enabled", L"WDigest stores clear-text passwords",
           L"UseLogonCredential=1: your password is kept in clear text in memory and can be stolen by credential dumping tools.", Domain::System, Risk::Critical,
           L"❌ Enabled", L"Set UseLogonCredential=0 (Recommended hardening profile)", 4, L"Set-ItemProperty 'HKLM:\\" + WDIGEST_KEY + L"' -Name UseLogonCredential -Value 0",
           L"Set-ItemProperty 'HKLM:\\" + WDIGEST_KEY + L"' -Name UseLogonCredential -Value 1", false,
           L"https://learn.microsoft.com/security-updates/securityadvisories/2016/2871997"};
    return true;
}

std::vector<Issue> SecurityAuditor::check_risky_services() {
    struct Risky {
        const wchar_t *name, *display;
        int score;
        Risk risk;
    };
    static const Risky risky[] = {{L"RemoteRegistry", L"Remote Registry", 2, Risk::Medium},
                                  {L"TermService", L"Remote Desktop", 2, Risk::High},
                                  {L"TlntSvr", L"Telnet", 2, Risk::Critical},
                                  {L"SNMP", L"SNMP", 1, Risk::Medium}};
    std::vector<Issue> issues;
    std::wstring names;
    for (const auto& r : risky) names += (names.empty() ? L"" : L",") + ps_quote(r.name);
    PsJson r = ps_json(L"$out = @(); foreach ($n in @(" + names + L")) { $s = Get-Service -Name $n -ErrorAction SilentlyContinue; if ($s) { $out += [pscustomobject]@{ Name = "
                       L"[string]$s.Name; Status = $s.Status.ToString() } } }; ConvertTo-Json -InputObject @($out) -Compress");
    if (r.rc != 0 || r.data.is_null()) return issues;
    std::set<std::wstring> running;
    for (const Json& s : r.data.as_list()) {
        if (s.get(L"Status").str() == L"Running") running.insert(lower(s.get(L"Name").str()));
    }
    for (const auto& svc : risky) {
        if (!running.count(lower(svc.name))) continue;
        RegistryState start = reg(L"HKLM", L"SYSTEM\\CurrentControlSet\\Services\\" + std::wstring(svc.name), L"Start");
        static const std::map<int, const wchar_t*> types = {{0, L"Boot"}, {1, L"System"}, {2, L"Automatic"}, {3, L"Manual"}, {4, L"Disabled"}};
        auto t = start.exists && start.numeric() ? types.find((int)start.as_int()) : types.end();
        std::wstring revert_type = t == types.end() ? L"Manual" : t->second;
        std::wstring name = svc.name, display = svc.display;
        issues.push_back({L"service_" + lower(name), L"Risky service running: " + display,
                          L"The " + display + L" service is running and could be exploited to access the system.", Domain::System, svc.risk, L"⚠️ Running",
                          L"Disable the " + display + L" service if not used", svc.score,
                          L"Stop-Service -Name " + name + L" -Force; Set-Service -Name " + name + L" -StartupType Disabled",
                          L"Set-Service -Name " + name + L" -StartupType " + revert_type + L"; Start-Service -Name " + name, false, L""});
    }
    return issues;
}

// endregion

// region Accounts

Json SecurityAuditor::builtin_accounts() {
    PsJson r = ps_json(LR"J(
$out = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-50[01]$' } |
    ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Sid = $_.SID.Value; Enabled = [bool]$_.Enabled } })
ConvertTo-Json -InputObject $out -Compress
)J");
    if (r.rc != 0 || r.data.is_null()) return Json();
    Json result = Json::object();
    for (const Json& acc : r.data.as_list()) {
        std::wstring sid = acc.get(L"Sid").str();
        if (ends_with(sid, L"-500")) result.set(L"admin", acc);
        else if (ends_with(sid, L"-501")) result.set(L"guest", acc);
    }
    return result;
}

bool SecurityAuditor::check_builtin_admin(const Json& builtin, Issue& out) {
    const Json& admin = builtin.get(L"admin");
    if (!admin.is_object() || !admin.get(L"Enabled").flag()) return false;
    std::wstring name = admin.has(L"Name") ? admin.get(L"Name").str() : L"Administrator";
    out = {L"admin_enabled", L"Built-in Administrator account enabled",
           L"The '" + name + L"' account (SID -500) is a prime target for brute-force attacks. Only disable it if another enabled administrator account exists.",
           Domain::Accounts, Risk::Medium, L"⚠️ Enabled", L"Disable the built-in Administrator account", 5,
           L"Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Disable-LocalUser", L"Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Enable-LocalUser", false,
           L"https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/accounts-administrator-account-status"};
    return true;
}

bool SecurityAuditor::check_guest_account(const Json& builtin, Issue& out) {
    const Json& guest = builtin.get(L"guest");
    if (!guest.is_object() || !guest.get(L"Enabled").flag()) return false;
    out = {L"guest_enabled", L"Guest account enabled", L"The Guest account allows unauthenticated access to the system.", Domain::Accounts, Risk::Medium, L"⚠️ Enabled",
           L"Disable the Guest account", 3, L"Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser",
           L"Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Enable-LocalUser", false, L""};
    return true;
}

bool SecurityAuditor::check_autologon(Issue& out) {
    RegistryState st = reg(L"HKLM", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"AutoAdminLogon");
    std::wstring value = st.type == REG_DWORD || st.type == REG_QWORD ? std::to_wstring(st.number) : trim(st.text);
    if (!(st.exists && value == L"1")) return false;
    const std::wstring key = L"HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    out = {L"autologon_enabled", L"Automatic logon enabled", L"The password is stored in plain text in the registry and the session logs on automatically.", Domain::Accounts,
           Risk::Critical, L"❌ Enabled", L"Disable automatic logon immediately", 8, L"Set-ItemProperty '" + key + L"' -Name AutoAdminLogon -Value 0",
           L"Set-ItemProperty '" + key + L"' -Name AutoAdminLogon -Value 1", false,
           L"https://docs.microsoft.com/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon"};
    return true;
}

bool SecurityAuditor::check_screen_lock(Issue& out) {
    RegistryState st = reg(L"HKCU", L"Control Panel\\Desktop", L"ScreenSaveTimeOut");
    if (!st.exists) return false;   // not configured
    std::wstring raw = st.type == REG_DWORD || st.type == REG_QWORD ? std::to_wstring(st.number) : st.text;
    std::wstring trimmed = trim(raw);
    wchar_t* end = nullptr;
    long long seconds = trimmed.empty() ? 0 : wcstoll(trimmed.c_str(), &end, 10);
    if (!trimmed.empty() && (!end || *end)) return false;
    long long minutes = seconds / 60;
    if (minutes > 15 || minutes == 0) {
        out = {L"screen_lock_long", fmt(L"Screen lock timeout too long (%lld min)", minutes),
               L"A session left idle too long is vulnerable to unauthorized physical access." + std::wstring(HKCU_NOTE), Domain::Accounts, Risk::Low,
               fmt(L"⚠️ %lld minutes", minutes), L"Reduce the timeout to 10-15 minutes at most", 3,
               L"Set-ItemProperty 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaveTimeOut -Value 600",
               L"Set-ItemProperty 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaveTimeOut -Value " + ps_quote(raw), false, L""};
        return true;
    }
    return false;
}

bool SecurityAuditor::check_empty_passwords(Issue& out) {
    RegistryState st = reg(L"HKLM", LSA_KEY, L"LimitBlankPasswordUse");
    if (!(st.exists && st.numeric() && st.as_int() == 0)) return false;
    out = {L"blank_passwords_allowed", L"Blank passwords allowed", L"System policy allows accounts without a password, making unauthorized access easier.", Domain::Accounts,
           Risk::High, L"❌ Allowed", L"Block blank passwords", 6, L"Set-ItemProperty 'HKLM:\\" + LSA_KEY + L"' -Name LimitBlankPasswordUse -Value 1",
           L"Set-ItemProperty 'HKLM:\\" + LSA_KEY + L"' -Name LimitBlankPasswordUse -Value 0", false, L""};
    return true;
}

// endregion

// region Network

bool SecurityAuditor::check_rdp_exposure(Issue& out) {
    const std::wstring key = L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server";
    RegistryState st = reg(L"HKLM", key, L"fDenyTSConnections");
    if (!(st.exists && st.numeric() && st.as_int() == 0)) return false;
    out = {L"rdp_exposed", L"RDP exposed (port 3389)", L"Remote Desktop is enabled and can be targeted by brute-force attacks.", Domain::Network, Risk::Critical, L"❌ Exposed",
           L"Disable RDP if not used, or restrict access with the firewall", 8, L"Set-ItemProperty 'HKLM:\\" + key + L"' -Name fDenyTSConnections -Value 1",
           L"Set-ItemProperty 'HKLM:\\" + key + L"' -Name fDenyTSConnections -Value 0", false,
           L"https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/remote-desktop-services"};
    return true;
}

bool SecurityAuditor::check_smb_exposure(Issue& out) {
    PsJson r = ps_json(LR"J(
$n = @(Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special }).Count
ConvertTo-Json -InputObject ([int]$n) -Compress
)J");
    if (r.rc != 0 || !r.data.is_number() || r.data.integer() <= 0) return false;
    long long count = r.data.integer();
    out = {L"smb_shares", fmt(L"%lld active network share(s)", count), fmt(L"%lld network share(s) exposed. Check their permissions and whether they are needed.", count),
           Domain::Network, Risk::Medium, fmt(L"⚠️ %lld share(s)", count), L"Review network shares and remove unnecessary ones", 7, L"", L"", false,
           L"https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-access"};
    return true;
}

bool SecurityAuditor::check_anonymous_sam(Issue& out) {
    RegistryState st = reg(L"HKLM", LSA_KEY, L"RestrictAnonymousSAM");
    if (!(st.exists && st.numeric() && st.as_int() == 0)) return false;
    out = {L"sam_anonymous", L"Anonymous SAM access allowed", L"User accounts can be enumerated without authentication (network reconnaissance).", Domain::Network, Risk::Critical,
           L"❌ Open", L"Block anonymous SAM access immediately", 7, L"Set-ItemProperty 'HKLM:\\" + LSA_KEY + L"' -Name RestrictAnonymousSAM -Value 1",
           L"Set-ItemProperty 'HKLM:\\" + LSA_KEY + L"' -Name RestrictAnonymousSAM -Value 0", false,
           L"https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts"};
    return true;
}

bool SecurityAuditor::check_smb1(Issue& out) {
    PsJson r = ps_json(L"ConvertTo-Json -InputObject ([bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol) -Compress");
    if (!(r.rc == 0 && r.data.is_bool() && r.data.flag())) return false;
    out = {L"smb1_enabled", L"SMBv1 server is enabled", L"SMBv1 is the protocol exploited by WannaCry and EternalBlue. This PC still accepts it from the network.", Domain::Network,
           Risk::High, L"❌ Enabled", L"Turn the SMBv1 server off (Recommended hardening profile). Connecting to an old NAS as a client is not affected.", 6,
           L"Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force", L"Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force", false,
           L"https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"};
    return true;
}

bool SecurityAuditor::check_netbios(Issue& out) {
    auto interfaces = netbios_interfaces();
    std::size_t enabled = 0;
    for (const auto& [name, st] : interfaces) {
        if (!(st.exists && st.numeric() && (unsigned long)st.as_int() == NETBIOS_DISABLED)) ++enabled;
    }
    if (!enabled) return false;
    out = {L"netbios_enabled", fmt(L"NetBIOS over TCP/IP enabled on %zu interface(s)", enabled),
           L"NetBIOS lets other machines discover this PC by name and enables name spoofing attacks. Modern networks use DNS; only very old devices or workgroup "
           L"browsing need it.",
           Domain::Network, Risk::Low, fmt(L"⚠️ %zu/%zu interface(s)", enabled, interfaces.size()),
           L"Disable NetBIOS over TCP/IP (Strict hardening profile; reconnect the network or reboot afterwards)", 2, L"", L"", true,
           L"https://learn.microsoft.com/windows-server/networking/technologies/wins/wins-top"};
    return true;
}

bool SecurityAuditor::check_ntlmv2(Issue& out) {
    // Value absent = Windows 10 default = 3 (send NTLMv2 only), considered fine. Levels 0-2 send LM/NTLMv1 -> issue. Level 5 (refuse
    // LM/NTLM) is only offered by the Strict profile (compatibility risk).
    RegistryState st = reg(L"HKLM", LSA_KEY, L"LmCompatibilityLevel");
    if (!st.exists || !st.numeric()) return false;
    long long level = st.as_int();
    if (level >= 3) return false;
    const std::wstring lsa = L"HKLM:\\" + LSA_KEY;
    out = {L"ntlm_weak", fmt(L"Weak authentication protocol (level %lld)", level), L"NTLMv1 or LM is allowed. These protocols are vulnerable to relay and cracking attacks.",
           Domain::Network, Risk::High, fmt(L"⚠️ Level %lld/5", level), L"Send NTLMv2 only (level 3, Windows default) or higher (5 = Strict profile)", 8,
           L"Set-ItemProperty '" + lsa + L"' -Name LmCompatibilityLevel -Value 3", L"Set-ItemProperty '" + lsa + L"' -Name LmCompatibilityLevel -Value " + ps_quote(std::to_wstring(level)),
           false, L"https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level"};
    return true;
}

// endregion

// region Data

bool SecurityAuditor::check_bitlocker(Issue& out, bool& unavailable) {
    std::wstring drive = system_root().substr(0, 2);
    PsJson r = ps_json(LR"J(
$v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
[pscustomobject]@{ Status = $v.VolumeStatus.ToString(); Protection = $v.ProtectionStatus.ToString() } | ConvertTo-Json -Compress
)J");
    if (r.rc != 0 || !r.data.is_object()) {
        unavailable = true;   // the cmdlet is missing: nothing to enable, nothing to penalise
        return false;
    }
    const wchar_t* url = L"https://docs.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-overview";
    std::wstring status = r.data.get(L"Status").str(), protection = r.data.get(L"Protection").str();
    if (status != L"FullyEncrypted") {
        out = {L"bitlocker_disabled", L"BitLocker off on " + drive + L"\\", L"The system drive is not encrypted. If the device is stolen, all data is accessible.", Domain::Data,
               Risk::High, L"❌ Not encrypted", L"Enable BitLocker on the system volume", 10,
               L"Enable-BitLocker -MountPoint " + drive + L" -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest", L"", true, url};
        return true;
    }
    if (protection == L"Off") {
        out = {L"bitlocker_suspended", L"BitLocker protection suspended on " + drive + L"\\", L"The drive is encrypted but protection is suspended (key stored in clear on the disk).",
               Domain::Data, Risk::Medium, L"⚠️ Suspended", L"Resume BitLocker protection", 5, L"Resume-BitLocker -MountPoint " + drive, L"", false, url};
        return true;
    }
    return false;
}

bool SecurityAuditor::check_restore_points(Issue& out) {
    PsJson r = ps_json(LR"J(
$lim = (Get-Date).AddDays(-7)
$n = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue |
    Where-Object { $_.ConvertToDateTime($_.CreationTime) -gt $lim }).Count
ConvertTo-Json -InputObject ([int]$n) -Compress
)J");
    if (!(r.rc == 0 && r.data.is_number() && r.data.integer() == 0)) return false;
    out = {L"no_restore_point", L"No recent restore point",
           L"No restore point in the last 7 days (or System Protection is off). Configuration could be lost if something goes wrong.", Domain::Data, Risk::Medium,
           L"⚠️ None (< 7 days)", L"Create a system restore point", 5, L"Checkpoint-Computer -Description 'DD Cleaner Security Audit' -RestorePointType MODIFY_SETTINGS", L"", false, L""};
    return true;
}

bool SecurityAuditor::check_windows_backup(Issue& out) {
    RegistryState st = reg(L"HKCU", L"Software\\Microsoft\\Windows\\CurrentVersion\\BackupRestore\\FileHistory", L"Enabled");
    if (st.exists && st.numeric() && st.as_int() == 1) return false;
    out = {L"backup_disabled", L"File History disabled", L"No automatic backup is configured. Data could be lost after a failure." + std::wstring(HKCU_NOTE), Domain::Data, Risk::Low,
           L"❌ Inactive", L"Set up Windows File History", 5, L"", L"", false, L"https://support.microsoft.com/windows-backup"};
    return true;
}

// endregion

// region The whole audit

int SecurityAuditor::run_full_audit(const Progress& progress) {
    std::lock_guard<std::mutex> guard(lock_);
    work_issues_.clear();   // fresh results for this run: nothing is published until the end
    work_scores_.clear();
    auto step = [&](const wchar_t* text) {
        if (progress) progress(text);
    };
    auto add = [](std::vector<Issue>& list, bool found, Issue& issue) {
        if (found) list.push_back(issue);
    };
    Issue issue;

    step(L"Auditing system security...");
    std::vector<Issue> system;
    add(system, check_defender(issue), issue);
    add(system, check_firewall(issue), issue);
    add(system, check_windows_update(issue), issue);
    add(system, check_uac(issue), issue);
    for (auto& i : check_risky_services()) system.push_back(i);
    add(system, check_memory_integrity(issue), issue);
    add(system, check_lsass_protection(issue), issue);
    add(system, check_wdigest(issue), issue);
    record_domain(Domain::System, SYSTEM_MAX_SCORE, system);

    step(L"Auditing accounts security...");
    std::vector<Issue> accounts;
    Json builtin = builtin_accounts();
    add(accounts, check_builtin_admin(builtin, issue), issue);
    add(accounts, check_guest_account(builtin, issue), issue);
    add(accounts, check_autologon(issue), issue);
    add(accounts, check_screen_lock(issue), issue);
    add(accounts, check_empty_passwords(issue), issue);
    record_domain(Domain::Accounts, 25, accounts);

    step(L"Auditing network security...");
    std::vector<Issue> network;
    add(network, check_rdp_exposure(issue), issue);
    add(network, check_smb_exposure(issue), issue);
    add(network, check_anonymous_sam(issue), issue);
    add(network, check_ntlmv2(issue), issue);
    add(network, check_smb1(issue), issue);
    add(network, check_netbios(issue), issue);
    record_domain(Domain::Network, NETWORK_MAX_SCORE, network);

    step(L"Auditing data security...");
    std::vector<Issue> data;
    int data_max = 20;
    bool bitlocker_unavailable = false;
    // BitLocker is not counted at all where it cannot exist (Windows Home, or no BitLocker cmdlet): the maximum drops by those 10 points,
    // so the domain is judged on what the PC can actually do.
    RegistryState edition = reg(L"HKLM", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"EditionID");
    if (edition.exists && starts_with(lower(edition.text), L"core")) {
        bitlocker_unavailable = true;
    } else {
        add(data, check_bitlocker(issue, bitlocker_unavailable), issue);
    }
    if (bitlocker_unavailable) data_max -= 10;
    add(data, check_restore_points(issue), issue);
    add(data, check_windows_backup(issue), issue);
    record_domain(Domain::Data, data_max, data);

    int score = global_score(work_scores_);
    issues_ = work_issues_;   // publish at the end (a reader holding the previous results never sees them change)
    scores_ = work_scores_;
    return score;
}

// endregion

}  // namespace dd
