// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the security audit classes and helpers that the audit checks and the hardening step call.

#include <ddcore/audit.hpp>

#include <algorithm>
#include <cmath>
#include <cstdarg>
#include <regex>

#include <windows.h>

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

// A PowerShell single-quoted literal
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
const std::wstring UAC_KEY = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
const unsigned long NETBIOS_DISABLED = 2;   // NetbiosOptions: 0 = from DHCP, 1 = enabled, 2 = disabled
const wchar_t* HKCU_NOTE =
    L" (Setting read from the profile of the user who launched the app as administrator; if elevation used a different account, this profile may differ "
    L"from the logged-on session.)";

bool netbios_iface(const std::wstring& name) {
    static const std::wregex re(LR"(^Tcpip_\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$)");
    return std::regex_match(name, re);
}

bool local_sid(const std::wstring& sid) {
    static const std::wregex re(LR"(^S-1-5-21(-\d+)+$)");
    return std::regex_match(sid, re);
}

bool safe_service_name(const std::wstring& n) {
    static const std::wregex re(LR"(^[A-Za-z0-9_.-]+$)");
    return std::regex_match(n, re);
}

std::string dword_bytes(unsigned long v) { return std::string(reinterpret_cast<const char*>(&v), 4); }
std::string qword_bytes(unsigned long long v) { return std::string(reinterpret_cast<const char*>(&v), 8); }
std::string string_bytes(const std::wstring& s) { return std::string(reinterpret_cast<const char*>(s.c_str()), (s.size() + 1) * sizeof(wchar_t)); }

std::wstring hex_of(const std::string& raw) {
    wchar_t two[3];
    std::wstring out;
    for (unsigned char c : raw) {
        swprintf(two, 3, L"%02x", c);
        out += two;
    }
    return out;
}

bool unhex(const std::wstring& text, std::string& out) {
    if (text.size() % 2) return false;
    out.clear();
    for (std::size_t i = 0; i < text.size(); i += 2) {
        wchar_t* end = nullptr;
        std::wstring pair = text.substr(i, 2);
        unsigned long v = wcstoul(pair.c_str(), &end, 16);
        if (!end || *end) return false;
        out.push_back((char)v);
    }
    return true;
}

const std::map<int, const wchar_t*>& start_type_ps() {
    static const std::map<int, const wchar_t*> m = {{0, L"Boot"}, {1, L"System"}, {2, L"Automatic"}, {3, L"Manual"}, {4, L"Disabled"}};
    return m;
}
const std::map<int, const wchar_t*>& start_type_sc() {
    static const std::map<int, const wchar_t*> m = {{0, L"boot"}, {1, L"system"}, {2, L"auto"}, {3, L"demand"}, {4, L"disabled"}};
    return m;
}

}  // namespace

// region Names

const wchar_t* risk_name(Risk r) {
    switch (r) {
        case Risk::Low: return L"Low";
        case Risk::Medium: return L"Medium";
        case Risk::High: return L"High";
        case Risk::Critical: return L"Critical";
    }
    return L"";
}
const wchar_t* domain_name(Domain d) {
    switch (d) {
        case Domain::System: return L"System";
        case Domain::Accounts: return L"Accounts";
        case Domain::Network: return L"Network";
        case Domain::Data: return L"Data";
    }
    return L"";
}
const wchar_t* profile_name(Profile p) {
    switch (p) {
        case Profile::Basic: return L"Basic";
        case Profile::Recommended: return L"Recommended";
        case Profile::Strict: return L"Strict";
    }
    return L"";
}

// Older backups stored the names in French; member names are accepted too.
static std::wstring legacy_key(const std::wstring& text) {
    static const std::map<std::wstring, std::wstring> legacy = {
        {L"Faible", L"LOW"}, {L"Moyen", L"MEDIUM"}, {L"Élevé", L"HIGH"}, {L"Critique", L"CRITICAL"}, {L"Système", L"SYSTEM"},
        {L"Comptes", L"ACCOUNTS"}, {L"Réseau", L"NETWORK"}, {L"Données", L"DATA"}, {L"Basique", L"BASIC"}, {L"Recommandé", L"RECOMMENDED"}};
    std::wstring t = trim(text);
    auto it = legacy.find(t);
    if (it != legacy.end()) return it->second;
    for (auto& c : t) c = (wchar_t)towupper(c);
    return t;
}

bool parse_risk(const std::wstring& text, Risk& out) {
    static const std::map<std::wstring, Risk> m = {{L"LOW", Risk::Low}, {L"MEDIUM", Risk::Medium}, {L"HIGH", Risk::High}, {L"CRITICAL", Risk::Critical}};
    auto it = m.find(legacy_key(text));
    if (it == m.end()) return false;
    out = it->second;
    return true;
}
bool parse_domain(const std::wstring& text, Domain& out) {
    static const std::map<std::wstring, Domain> m = {{L"SYSTEM", Domain::System}, {L"ACCOUNTS", Domain::Accounts}, {L"NETWORK", Domain::Network}, {L"DATA", Domain::Data}};
    auto it = m.find(legacy_key(text));
    if (it == m.end()) return false;
    out = it->second;
    return true;
}
bool parse_profile(const std::wstring& text, Profile& out) {
    static const std::map<std::wstring, Profile> m = {{L"BASIC", Profile::Basic}, {L"RECOMMENDED", Profile::Recommended}, {L"STRICT", Profile::Strict}};
    auto it = m.find(legacy_key(text));
    if (it == m.end()) return false;
    out = it->second;
    return true;
}

double DomainScore::percentage() const { return max_score > 0 ? (double)current_score / max_score * 100 : 0.0; }

std::wstring DomainScore::status() const {
    double pct = percentage();
    if (pct >= 85) return L"\U0001F7E2 Excellent";
    if (pct >= 70) return L"\U0001F7E1 Fair";
    if (pct >= 50) return L"\U0001F7E0 Medium";
    return L"\U0001F534 Critical";
}

const std::map<Domain, int> DOMAIN_WEIGHTS = {{Domain::System, 25}, {Domain::Accounts, 25}, {Domain::Network, 30}, {Domain::Data, 20}};

// endregion

// region Hooks

bool RegistryState::numeric() const {
    if (!exists) return false;
    if (type == REG_DWORD || type == REG_QWORD) return true;
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        std::wstring t = trim(text);
        if (t.empty()) return false;
        wchar_t* end = nullptr;
        wcstoll(t.c_str(), &end, 10);
        return end && !*end;
    }
    return false;
}

long long RegistryState::as_int() const {
    if (type == REG_DWORD || type == REG_QWORD) return (long long)number;
    return wcstoll(trim(text).c_str(), nullptr, 10);
}

static RegistryState real_read(const std::wstring& hive, const std::wstring& path, const std::wstring& name) {
    RegistryState st;
    RegKey key = RegKey::open(hive, path);
    for (const RegValue& v : key.values()) {
        if (v.name != name) continue;
        st.exists = true;
        st.type = v.type;
        st.text = v.text;
        st.raw = v.raw;
        st.number = v.type == REG_QWORD ? v.qword : v.dword;
        break;
    }
    return st;
}

RegistryState read_registry_state(const std::wstring& hive, const std::wstring& path, const std::wstring& name) {
    return system_hooks().registry.read(hive, path, name);
}

SystemHooks& system_hooks() {
    static SystemHooks hooks = [] {
        SystemHooks h;
        h.ps_json = [](const std::wstring& script, unsigned long timeout) { return run_powershell_rc(script, timeout); };
        h.ps = [](const std::wstring& script) { return run_powershell_rc(script, 60000).rc; };
        h.run_exe = [](const std::vector<std::wstring>& argv) {
            ProcOptions o;
            o.timeout_ms = 60000;
            ProcResult r = run_process(argv, o);
            return r.started && !r.timed_out ? r.code : -1;
        };
        h.remote_session = [] {
            std::wstring session = env_var(L"SESSIONNAME");
            for (auto& c : session) c = (wchar_t)towupper(c);
            return starts_with(session, L"RDP-") || GetSystemMetrics(SM_REMOTESESSION) != 0;
        };
        h.registry.read = real_read;
        h.registry.write = [](const std::wstring& hive, const std::wstring& path, const std::wstring& name, unsigned long type, const std::string& bytes) {
            RegKey key = RegKey::create(hive, path);
            return key.valid() && key.set_value(name, type, bytes) == ERROR_SUCCESS;
        };
        h.registry.remove = [](const std::wstring& hive, const std::wstring& path, const std::wstring& name) {
            RegKey key = RegKey::open_write(hive, path);
            if (!key.valid()) return true;   // no key: nothing to delete
            LONG rc = key.delete_value(name);
            return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND;
        };
        h.registry.subkeys = [](const std::wstring& hive, const std::wstring& path) { return RegKey::open(hive, path).subkeys(); };
        h.registry.key_exists = [](const std::wstring& hive, const std::wstring& path) { return RegKey::open(hive, path).valid(); };
        return h;
    }();
    return hooks;
}

// endregion

}  // namespace dd
