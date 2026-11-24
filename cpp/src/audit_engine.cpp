// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the hardening engine: the built-in actions, the JSON snapshot, the application of changes and the exact revert.

#include <algorithm>
#include <regex>

#include <windows.h>

#include <ddcore/audit.hpp>
#include <ddcore/registry.hpp>

namespace dd {

namespace {

std::wstring ps_quote(const std::wstring& value) {
    std::wstring out = L"'";
    for (wchar_t c : value) {
        if (c == L'\'') out += L"''";
        else out.push_back(c);
    }
    return out + L"'";
}

const std::wstring LSA = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
const std::wstring UAC = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
const std::wstring WDIGEST = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest";
const std::wstring NETBIOS_ROOT = L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces";
const unsigned long NETBIOS_DISABLED = 2;
const std::wstring SYSTEM_RESTORE_KEY = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore";

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
        std::wstring pair = text.substr(i, 2);
        wchar_t* end = nullptr;
        unsigned long v = wcstoul(pair.c_str(), &end, 16);
        if (!end || *end) return false;
        out.push_back((char)v);
    }
    return true;
}

const std::map<int, const wchar_t*>& start_type_sc() {
    static const std::map<int, const wchar_t*> m = {{0, L"boot"}, {1, L"system"}, {2, L"auto"}, {3, L"demand"}, {4, L"disabled"}};
    return m;
}

PsJson ps_json(const std::wstring& script, unsigned long timeout = 60000) { return system_hooks().ps_json(script, timeout); }
int ps(const std::wstring& script) { return system_hooks().ps(script); }

// A registry value as it goes into a backup
Json encode_state(const RegistryState& st) {
    Json o = Json::object();
    o.set(L"exists", Json::boolean(st.exists));
    if (!st.exists) return o;
    o.set(L"type", Json::number((double)st.type));
    if (st.type == REG_DWORD || st.type == REG_QWORD) {
        o.set(L"data", Json::number((double)st.number));
    } else if (st.type == REG_SZ || st.type == REG_EXPAND_SZ) {
        o.set(L"data", Json::string(st.text));
    } else {
        Json h = Json::object();
        h.set(L"hex", Json::string(hex_of(st.raw)));
        o.set(L"data", h);
    }
    return o;
}

Action registry_action(const wchar_t* id, const wchar_t* title, const wchar_t* hive, const std::wstring& key, std::vector<ActionValue> values) {
    Action a;
    a.id = id;
    a.title = title;
    a.kind = L"registry";
    a.hive = hive;
    a.key = key;
    a.values = std::move(values);
    return a;
}

Action simple_action(const wchar_t* id, const wchar_t* title, const wchar_t* kind) {
    Action a;
    a.id = id;
    a.title = title;
    a.kind = kind;
    return a;
}

const std::map<std::wstring, Action>& action_defs() {
    static const std::map<std::wstring, Action> defs = [] {
        std::map<std::wstring, Action> d;
        auto add = [&](Action a) { d[a.id] = std::move(a); };
        add(simple_action(L"defender_enable", L"Enable Defender", L"defender"));
        add(simple_action(L"firewall_enable", L"Enable firewall", L"firewall"));
        Action guest = simple_action(L"guest_disable", L"Disable Guest account", L"account");
        guest.rid = 501;
        add(guest);
        add(registry_action(L"autologon_disable", L"Disable automatic logon", L"HKLM", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                            {{L"AutoAdminLogon", REG_SZ, L"0", 0}}));
        add(registry_action(L"sam_restrict", L"Block anonymous SAM access", L"HKLM", LSA, {{L"RestrictAnonymousSAM", REG_DWORD, L"", 1}}));
        Action admin = simple_action(L"admin_disable", L"Disable built-in Administrator", L"account");
        admin.rid = 500;
        add(admin);
        add(registry_action(L"rdp_disable", L"Disable RDP", L"HKLM", L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", {{L"fDenyTSConnections", REG_DWORD, L"", 1}}));
        add(registry_action(L"ntlmv2_enforce", L"Enforce NTLMv2 (refuse LM/NTLM)", L"HKLM", LSA, {{L"LmCompatibilityLevel", REG_DWORD, L"", 5}}));
        add(registry_action(L"uac_max", L"UAC maximum level", L"HKLM", UAC,   // 2 = Always notify, consent on the secure desktop
                            {{L"ConsentPromptBehaviorAdmin", REG_DWORD, L"", 2}, {L"PromptOnSecureDesktop", REG_DWORD, L"", 1}}));
        Action remote = simple_action(L"remote_registry_disable", L"Disable Remote Registry", L"service");
        remote.service = L"RemoteRegistry";
        remote.start = 4;
        remote.stop = true;
        add(remote);
        add(registry_action(L"wdigest_disable", L"Stop WDigest keeping clear-text passwords", L"HKLM", WDIGEST, {{L"UseLogonCredential", REG_DWORD, L"", 0}}));
        add(simple_action(L"smb1_disable", L"Turn the SMBv1 server off", L"smb1"));   // server side only: connecting to an old NAS keeps working
        add(simple_action(L"netbios_disable", L"Disable NetBIOS over TCP/IP", L"netbios"));
        return d;
    }();
    return defs;
}

const std::vector<std::wstring>& basic_ids() {
    static const std::vector<std::wstring> v = {L"defender_enable", L"firewall_enable", L"guest_disable", L"autologon_disable"};
    return v;
}
const std::vector<std::wstring>& recommended_ids() {
    static const std::vector<std::wstring> v = [] {
        auto r = basic_ids();
        for (const wchar_t* id : {L"sam_restrict", L"admin_disable", L"wdigest_disable", L"smb1_disable"}) r.push_back(id);
        return r;
    }();
    return v;
}
// RDP disable, LmCompatibilityLevel=5 and NetBIOS off can lock users out / break legacy NAS and workgroup browsing: Strict only
const std::vector<std::wstring>& strict_ids() {
    static const std::vector<std::wstring> v = [] {
        auto r = recommended_ids();
        for (const wchar_t* id : {L"rdp_disable", L"ntlmv2_enforce", L"uac_max", L"remote_registry_disable", L"netbios_disable"}) r.push_back(id);
        return r;
    }();
    return v;
}

const std::set<std::wstring>& revertible() {
    static const std::set<std::wstring> s = {L"applied", L"failed"};
    return s;
}

std::vector<std::pair<std::wstring, std::wstring>> state_pairs(const Json& state_map) {
    std::vector<std::pair<std::wstring, std::wstring>> out;
    for (const auto& [k, v] : state_map.members()) out.emplace_back(k, v.dump());
    return out;
}

}  // namespace

// region Definitions

const Action* find_action(const std::wstring& id) {
    auto it = action_defs().find(id);
    return it == action_defs().end() ? nullptr : &it->second;
}

int profile_action_count(Profile profile) {
    return (int)(profile == Profile::Basic ? basic_ids() : profile == Profile::Recommended ? recommended_ids() : strict_ids()).size();
}

std::vector<Action> profile_actions(Profile profile) {
    const auto& ids = profile == Profile::Basic ? basic_ids() : profile == Profile::Recommended ? recommended_ids() : strict_ids();
    std::vector<Action> out;
    for (const auto& id : ids) out.push_back(action_defs().at(id));
    return out;
}

// endregion

// region Backup files

Json Backup::to_json() const {
    Json root = Json::object();
    root.set(L"version", Json::number(version));
    root.set(L"created", Json::string(created));
    root.set(L"profile", Json::string(profile));
    Json rp = Json::object();
    rp.set(L"ok", Json::boolean(restore_point_ok));
    rp.set(L"message", Json::string(restore_point_message));
    root.set(L"restore_point", rp);
    Json list = Json::array();
    for (const auto& e : entries) {
        Json o = Json::object();
        o.set(L"id", Json::string(e.id));
        o.set(L"title", Json::string(e.title));
        o.set(L"kind", Json::string(e.kind));
        o.set(L"before", e.before);
        o.set(L"status", Json::string(e.status));
        o.set(L"message", Json::string(e.message));
        list.push(o);
    }
    root.set(L"entries", list);
    if (!reverted.empty()) root.set(L"reverted", Json::string(reverted));
    return root;
}

bool Backup::from_json(const Json& data, Backup& out) {
    if (!data.is_object() || !data.get(L"entries").is_array()) return false;
    out = Backup();
    out.version = (int)data.get(L"version").integer(1);
    out.created = data.get(L"created").str();
    out.profile = data.get(L"profile").str();
    out.restore_point_ok = data.get(L"restore_point").get(L"ok").flag();
    out.restore_point_message = data.get(L"restore_point").get(L"message").str();
    out.reverted = data.get(L"reverted").str();
    for (const Json& e : data.get(L"entries").items()) {
        if (!e.is_object()) continue;
        out.entries.push_back({e.get(L"id").str(), e.get(L"title").str(), e.get(L"kind").str(), e.get(L"before"), e.get(L"status").str(), e.get(L"message").str()});
    }
    return true;
}

std::wstring hardening_backup_dir() { return data_subdir(L"hardening_backups"); }

std::vector<std::wstring> list_hardening_backups() {
    std::vector<Entry> files;
    std::vector<Entry> matching;
    if (!list_dir(hardening_backup_dir(), files)) return {};
    for (const Entry& f : files) {
        if (!f.is_dir() && starts_with(f.name, L"hardening_backup_") && ends_with(f.name, L".json")) matching.push_back(f);
    }
    std::stable_sort(matching.begin(), matching.end(), [](const Entry& a, const Entry& b) { return a.modified > b.modified; });
    std::vector<std::wstring> out;
    for (const auto& f : matching) out.push_back(f.path);
    return out;
}

bool HardeningEngine::save_backup(const std::wstring& path, const Backup& backup) {
    std::wstring tmp = path + L".tmp";
    if (!write_file(tmp, utf8(backup.to_json().dump(true)))) return false;
    if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        delete_file(tmp);
        return false;
    }
    return true;
}

bool HardeningEngine::load_backup(const std::wstring& path, Backup& out) {
    std::string bytes;
    Json data;
    if (!read_file(path, bytes) || !try_parse_json(wide(bytes), data)) return false;
    return Backup::from_json(data, out);
}

std::wstring HardeningEngine::write_new_backup(const Backup& backup) {
    std::wstring dir = hardening_backup_dir();
    if (!is_dir(dir)) return L"";
    std::wstring stamp = timestamp(), path = join(dir, L"hardening_backup_" + stamp + L".json");
    for (int suffix = 1; lexists(path); ++suffix) path = join(dir, L"hardening_backup_" + stamp + L"_" + std::to_wstring(suffix) + L".json");
    return save_backup(path, backup) ? path : L"";
}

std::wstring HardeningEngine::find_backup_with(const std::wstring& action_id) {
    std::vector<std::wstring> candidates;
    if (!last_backup_path.empty() && is_file(last_backup_path)) candidates.push_back(last_backup_path);
    for (const auto& p : list_hardening_backups()) {
        if (std::find(candidates.begin(), candidates.end(), p) == candidates.end()) candidates.push_back(p);
    }
    for (const auto& path : candidates) {
        Backup b;
        if (!load_backup(path, b)) continue;
        for (const auto& e : b.entries) {
            if (e.id == action_id && revertible().count(e.status)) return path;
        }
    }
    return L"";
}

// endregion

// region Restore point

bool HardeningEngine::create_restore_point(const std::wstring& description) {
    std::lock_guard<std::recursive_mutex> guard(lock_);
    last_restore_point_ok = false;
    last_restore_point_message.clear();
    std::wstring safe;
    for (wchar_t c : description) {
        if ((c < 128 && iswalnum(c)) || c == L' ' || c == L'_' || c == L'.' || c == L'-') safe.push_back(c);
    }
    if (safe.size() > 200) safe.resize(200);
    if (safe.empty()) safe = L"DD Cleaner";

    // Windows throttles restore point creation to one per 24 h: lift it for this call and put the previous value (or its absence) back
    Json before;
    bool lifted = false;
    RegistryState previous = system_hooks().registry.read(L"HKLM", SYSTEM_RESTORE_KEY, L"SystemRestorePointCreationFrequency");
    if (system_hooks().registry.write(L"HKLM", SYSTEM_RESTORE_KEY, L"SystemRestorePointCreationFrequency", REG_DWORD, dword_bytes(0))) {
        before = encode_state(previous);
        lifted = true;
    }
    std::wstring script =
        L"$r = [ordered]@{ Created = $false; Before = 0; After = 0; Warning = ''; Error = '' };"
        L"try {"
        L" $b = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object SequenceNumber);"
        L" if ($b.Count) { $r.Before = [int]$b[-1].SequenceNumber };"
        L" Checkpoint-Computer -Description " + ps_quote(safe) +
        L" -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop -WarningAction SilentlyContinue -WarningVariable wv;"
        L" $r.Warning = (@($wv) | ForEach-Object { $_.ToString() }) -join ' ';"
        L" $a = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object SequenceNumber);"
        L" if ($a.Count) { $r.After = [int]$a[-1].SequenceNumber };"
        L" $r.Created = ($r.After -gt $r.Before)"
        L"} catch { $r.Error = $_.Exception.Message };"
        L"$r | ConvertTo-Json -Compress;"
        L"if ($r.Created) { exit 0 } else { exit 1 }";
    PsJson result = ps_json(script, 300000);
    if (lifted) restore_reg_value(L"HKLM", SYSTEM_RESTORE_KEY, L"SystemRestorePointCreationFrequency", before);

    const Json& data = result.data;
    if (result.rc == -1 && data.is_null()) {
        last_restore_point_message = L"Timed out or PowerShell unavailable while creating the restore point.";
    } else if (!data.is_object()) {
        last_restore_point_message = L"Unexpected response from Checkpoint-Computer (code " + std::to_wstring(result.rc) + L").";
    } else if (result.rc == 0 && data.get(L"Created").flag()) {
        last_restore_point_ok = true;
        last_restore_point_message = L"Restore point created.";
    } else if (!data.get(L"Error").str().empty()) {
        last_restore_point_message = L"Restore point creation failed (System Protection disabled?): " + data.get(L"Error").str();
    } else if (!data.get(L"Warning").str().empty()) {
        last_restore_point_message = L"Windows did not create a restore point: limit of one per 24 h (a recent one already exists). Details: " + data.get(L"Warning").str();
    } else {
        last_restore_point_message = L"No new restore point detected after Checkpoint-Computer.";
    }
    return last_restore_point_ok;
}

// endregion

// region Snapshot, prechecks, apply

Json HardeningEngine::snapshot(const Action& action) {
    const std::wstring& kind = action.kind;
    Json out = Json::object();
    if (kind == L"registry") {
        Json values = Json::object();
        for (const auto& v : action.values) values.set(v.name, encode_state(system_hooks().registry.read(action.hive, action.key, v.name)));
        out.set(L"values", values);
        return out;
    }
    if (kind == L"service") {
        RegistryState start = system_hooks().registry.read(L"HKLM", L"SYSTEM\\CurrentControlSet\\Services\\" + action.service, L"Start");
        if (!start.exists) {
            out.set(L"exists", Json::boolean(false));
            return out;
        }
        RegistryState delayed = system_hooks().registry.read(L"HKLM", L"SYSTEM\\CurrentControlSet\\Services\\" + action.service, L"DelayedAutostart");
        Json running;
        PsJson r = ps_json(L"$s = Get-Service -Name " + ps_quote(action.service) + L" -ErrorAction Stop;ConvertTo-Json -InputObject $s.Status.ToString() -Compress");
        if (r.rc == 0 && r.data.is_string()) running = Json::boolean(r.data.str() == L"Running");
        out.set(L"exists", Json::boolean(true));
        out.set(L"start", Json::number((double)start.as_int()));
        out.set(L"delayed", delayed.exists ? Json::number((double)delayed.as_int()) : Json());
        out.set(L"running", running);
        return out;
    }
    if (kind == L"account") {
        PsJson r = ps_json(L"$u = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-" + std::to_wstring(action.rid) +
                           L"$' } | Select-Object -First 1;if ($u) { [pscustomobject]@{ Sid = $u.SID.Value; Enabled = [bool]$u.Enabled } | ConvertTo-Json -Compress } else { 'null' }");
        if (r.rc != 0) throw std::runtime_error("Get-LocalUser failed");
        if (!r.data.is_object()) {
            out.set(L"sid", Json());
            out.set(L"enabled", Json());
            return out;
        }
        out.set(L"sid", r.data.get(L"Sid"));
        out.set(L"enabled", Json::boolean(r.data.get(L"Enabled").flag()));
        return out;
    }
    if (kind == L"defender") {
        PsJson r = ps_json(L"ConvertTo-Json -InputObject ([bool](Get-MpPreference -ErrorAction Stop).DisableRealtimeMonitoring) -Compress");
        if (r.rc != 0 || !r.data.is_bool()) throw std::runtime_error("Get-MpPreference failed");
        out.set(L"disable_realtime_monitoring", r.data);
        return out;
    }
    if (kind == L"firewall") {
        PsJson r = ps_json(L"$p = @(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Enabled = "
                           L"$_.Enabled.ToString() } });ConvertTo-Json -InputObject $p -Compress");
        if (r.rc != 0 || r.data.is_null()) throw std::runtime_error("Get-NetFirewallProfile failed");
        Json profiles = Json::array();
        for (const Json& p : r.data.as_list()) {
            Json o = Json::object();
            o.set(L"name", p.get(L"Name"));
            o.set(L"enabled", p.get(L"Enabled"));
            profiles.push(o);
        }
        out.set(L"profiles", profiles);
        return out;
    }
    if (kind == L"smb1") {
        PsJson r = ps_json(L"ConvertTo-Json -InputObject ([bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol) -Compress");
        if (r.rc != 0 || !r.data.is_bool()) throw std::runtime_error("Get-SmbServerConfiguration failed");
        out.set(L"enabled", r.data);
        return out;
    }
    if (kind == L"netbios") {
        Json interfaces = Json::object();
        for (const auto& name : system_hooks().registry.subkeys(L"HKLM", NETBIOS_ROOT)) {
            if (netbios_iface(name)) interfaces.set(name, encode_state(system_hooks().registry.read(L"HKLM", NETBIOS_ROOT + L"\\" + name, L"NetbiosOptions")));
        }
        out.set(L"interfaces", interfaces);
        return out;
    }
    throw std::runtime_error("Unknown action kind: " + utf8(kind));
}

std::wstring HardeningEngine::builtin_admin_safety(const std::wstring& admin_sid) {
    PsJson r = ps_json(LR"J(
$r = [ordered]@{ CurrentSid = $null; Members = @(); EnabledLocal = @(); GroupOk = $false }
$r.CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$r.EnabledLocal = @(Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object { $_.SID.Value })
try {
    $r.Members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.SID.Value })
    $r.GroupOk = $true
} catch {
    try {
        $name = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $g = [ADSI]("WinNT://$env:COMPUTERNAME/$name,group")
        $r.Members = @($g.Invoke('Members') | ForEach-Object {
            $bytes = $_.GetType().InvokeMember('objectSid', 'GetProperty', $null, $_, $null)
            (New-Object Security.Principal.SecurityIdentifier($bytes, 0)).Value })
        $r.GroupOk = $true
    } catch { }
}
$r | ConvertTo-Json -Compress
)J");
    if (r.rc != 0 || !r.data.is_object()) return L"safety check failed (administrator accounts)";
    if (r.data.get(L"CurrentSid").str() == admin_sid) return L"it is the account currently in use";
    if (!r.data.get(L"GroupOk").flag()) return L"could not list the Administrators group";
    std::set<std::wstring> enabled;
    for (const Json& e : r.data.get(L"EnabledLocal").as_list()) enabled.insert(e.str());
    bool other = false;
    for (const Json& m : r.data.get(L"Members").as_list()) {
        std::wstring sid = m.str();
        if (!sid.empty() && sid != admin_sid && enabled.count(sid)) other = true;
    }
    return other ? L"" : L"it is the only enabled local administrator account";
}

std::wstring HardeningEngine::precheck(const Action& action, const Json& before) {
    const std::wstring& kind = action.kind;
    if (action.id == L"rdp_disable" && system_hooks().remote_session()) return L"Remote Desktop session in progress (disabling it would cut off access)";
    if (kind == L"account") {
        if (before.get(L"sid").is_null() || before.get(L"sid").str().empty()) return L"account not found";
        if (!before.get(L"enabled").flag()) return L"account already disabled";
        if (action.rid == 500) return builtin_admin_safety(before.get(L"sid").str());
    }
    if (kind == L"service" && !before.get(L"exists").flag()) return L"service not installed";
    if (kind == L"smb1" && before.get(L"enabled").is_bool() && !before.get(L"enabled").flag()) return L"the SMBv1 server is already off";
    if (kind == L"netbios") {
        const Json& interfaces = before.get(L"interfaces");
        if (!interfaces.is_object() || interfaces.size() == 0) return L"no network interface found";
        bool all_off = true;
        for (const auto& [name, st] : interfaces.members()) all_off &= st.is_object() && st.get(L"exists").flag() && st.get(L"data").integer(-1) == (long long)NETBIOS_DISABLED;
        if (all_off) return L"NetBIOS is already disabled on every interface";
    }
    return L"";
}

bool HardeningEngine::apply_action(const Action& action, const Json& before) {
    const std::wstring& kind = action.kind;
    auto& registry = system_hooks().registry;
    if (kind == L"registry") {
        for (const auto& v : action.values) {
            std::string bytes = v.type == REG_DWORD ? dword_bytes(v.number) : string_bytes(v.text);
            if (!registry.write(action.hive, action.key, v.name, v.type, bytes)) return false;
        }
        for (const auto& v : action.values) {
            RegistryState st = registry.read(action.hive, action.key, v.name);
            if (!st.exists) return false;
            if (v.type == REG_DWORD ? !(st.numeric() && (unsigned long)st.as_int() == v.number) : st.text != v.text) return false;
        }
        return true;
    }
    if (kind == L"service") {
        if (!safe_service_name(action.service)) return false;
        auto type = start_type_sc().find(action.start);
        if (type == start_type_sc().end()) return false;
        if (system_hooks().run_exe({join(system32(), L"sc.exe"), L"config", action.service, L"start=", type->second}) != 0) return false;
        if (action.stop) ps(L"Stop-Service -Name " + ps_quote(action.service) + L" -Force -ErrorAction Stop");   // disabled even if it cannot be stopped now
        return true;
    }
    if (kind == L"account") {
        std::wstring sid = before.get(L"sid").str();
        if (!local_sid(sid)) return false;
        return ps(L"Disable-LocalUser -SID " + ps_quote(sid) + L" -ErrorAction Stop") == 0;
    }
    if (kind == L"defender") {
        PsJson r = ps_json(L"Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop;ConvertTo-Json -InputObject ([bool](Get-MpPreference).DisableRealtimeMonitoring) -Compress");
        return r.rc == 0 && r.data.is_bool() && !r.data.flag();   // Tamper Protection may silently ignore the change: verify
    }
    if (kind == L"firewall") return ps(L"Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop") == 0;
    if (kind == L"smb1") {
        PsJson r = ps_json(L"Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false -ErrorAction Stop;"
                           L"ConvertTo-Json -InputObject ([bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol) -Compress");
        return r.rc == 0 && r.data.is_bool() && !r.data.flag();   // verified, not assumed
    }
    if (kind == L"netbios") {
        std::vector<std::wstring> names;
        for (const auto& [name, st] : before.get(L"interfaces").members()) {
            if (netbios_iface(name)) names.push_back(name);
        }
        for (const auto& name : names) registry.write(L"HKLM", NETBIOS_ROOT + L"\\" + name, L"NetbiosOptions", REG_DWORD, dword_bytes(NETBIOS_DISABLED));
        if (names.empty()) return false;
        for (const auto& name : names) {
            RegistryState st = registry.read(L"HKLM", NETBIOS_ROOT + L"\\" + name, L"NetbiosOptions");
            if (!(st.exists && st.numeric() && (unsigned long)st.as_int() == NETBIOS_DISABLED)) return false;
        }
        return true;
    }
    return false;
}

ApplyResult HardeningEngine::apply_profile(Profile profile, const std::vector<std::wstring>& custom_actions, bool create_restore, bool require_restore) {
    std::lock_guard<std::recursive_mutex> guard(lock_);
    last_skipped.clear();
    last_backup_path.clear();
    std::vector<Action> actions = profile_actions(profile);
    if (!custom_actions.empty()) {
        std::vector<Action> kept;
        for (const auto& a : actions) {
            if (std::find(custom_actions.begin(), custom_actions.end(), a.id) != custom_actions.end()) kept.push_back(a);
        }
        actions = kept;
    }
    ApplyResult result;
    if (require_restore && !create_restore) {
        result.failures = 1;
        result.errors.push_back(L"Aborted: restore point not created. Restore point not requested.");
        return result;
    }

    // 1. Snapshot the current state and write the JSON backup (mandatory, before touching anything)
    Backup backup;
    backup.created = timestamp();
    backup.profile = profile_name(profile);
    backup.restore_point_message = L"pending";
    for (const auto& a : actions) {
        BackupEntry e{a.id, a.title, a.kind, Json(), L"pending", L""};
        try {
            e.before = snapshot(a);
        } catch (const std::exception& ex) {
            e.status = L"snapshot_failed";
            e.message = wide(ex.what());
        }
        backup.entries.push_back(e);
    }
    std::wstring path = write_new_backup(backup);
    if (path.empty()) {
        result.failures = (int)std::max<std::size_t>(1, actions.size());
        result.errors.push_back(L"Aborted: could not write the JSON backup to the protected backup folder (no changes applied).");
        return result;
    }
    last_backup_path = path;

    // 2. Restore point (best effort unless required)
    bool restore_ok = false;
    if (create_restore) {
        restore_ok = create_restore_point();
    } else {
        last_restore_point_ok = false;
        last_restore_point_message = L"Restore point not requested.";
    }
    backup.restore_point_ok = restore_ok;
    backup.restore_point_message = last_restore_point_message;
    if (!restore_ok) {
        if (require_restore) {
            result.failures = 1;
            result.errors.push_back(L"Aborted: restore point not created. " + last_restore_point_message);
            delete_file(path);
            last_backup_path.clear();
            return result;
        }
        result.errors.push_back(L"Warning: " + last_restore_point_message);
    }
    if (!save_backup(path, backup)) {
        result.failures = (int)std::max<std::size_t>(1, actions.size());
        result.errors.push_back(L"Aborted: the JSON backup " + path + L" can no longer be written (no changes applied).");
        return result;
    }

    // 3. Apply
    for (std::size_t i = 0; i < actions.size(); ++i) {
        const Action& action = actions[i];
        BackupEntry& entry = backup.entries[i];
        if (entry.status == L"snapshot_failed") {
            ++result.failures;
            result.errors.push_back(L"Not applied (could not read initial state): " + action.title);
            continue;
        }
        std::wstring skip = precheck(action, entry.before);
        if (!skip.empty()) {
            entry.status = L"skipped";
            entry.message = skip;
            last_skipped.push_back(action.title + L": " + skip);
            result.errors.push_back(L"Skipped: " + action.title + L" - " + skip);
            save_backup(path, backup);
            continue;
        }
        // Marked as attempted before touching anything (crash-safe revert). If that cannot be recorded, stop: a change without its marker
        // could not be reverted.
        entry.status = L"failed";
        if (!save_backup(path, backup)) {
            entry.status = L"pending";
            int remaining = (int)(actions.size() - i);
            result.failures += remaining;
            result.errors.push_back(L"Aborted: backup " + path + L" became unwritable; " + std::to_wstring(remaining) + L" remaining action(s) not applied.");
            break;
        }
        try {
            if (apply_action(action, entry.before)) {
                ++result.success;
                entry.status = L"applied";
            } else {
                ++result.failures;
                result.errors.push_back(L"Failed: " + action.title);
            }
        } catch (const std::exception& ex) {
            ++result.failures;
            entry.message = wide(ex.what());
            result.errors.push_back(L"Error applying " + action.title + L": " + wide(ex.what()));
        }
        save_backup(path, backup);
    }
    return result;
}

// endregion

// region Revert

bool HardeningEngine::restore_reg_value(const std::wstring& hive, const std::wstring& path, const std::wstring& name, const Json& state, int expected_type) {
    auto& registry = system_hooks().registry;
    if (!state.get(L"exists").flag()) return registry.remove(hive, path, name);
    int vtype = (int)state.get(L"type").integer(-1);
    if (expected_type >= 0 && vtype != expected_type) throw std::runtime_error(utf8(name) + ": type " + std::to_string(vtype) + " in the backup, " + std::to_string(expected_type) + " expected");
    const Json& data = state.get(L"data");
    if (vtype == REG_DWORD) {
        long long v = data.integer(-1);
        if (v < 0 || v > 0xFFFFFFFFLL) throw std::runtime_error(utf8(name) + ": DWORD out of range");
        return registry.write(hive, path, name, REG_DWORD, dword_bytes((unsigned long)v));
    }
    if (vtype == REG_QWORD) return registry.write(hive, path, name, REG_QWORD, qword_bytes((unsigned long long)data.integer()));
    if (vtype == REG_SZ || vtype == REG_EXPAND_SZ) return registry.write(hive, path, name, (unsigned long)vtype, string_bytes(data.str()));
    throw std::runtime_error(utf8(name) + ": unsupported value type " + std::to_string(vtype));
}

bool HardeningEngine::revert_entry(const BackupEntry& entry) {
    const Action* action = find_action(entry.id);   // the definition comes from the catalogue, never from the backup
    if (!action || !entry.before.is_object()) return false;
    const Json& before = entry.before;
    const std::wstring& kind = action->kind;
    auto& registry = system_hooks().registry;
    try {
        if (kind == L"registry") {
            int restored = 0;
            for (const auto& v : action->values) {
                if (before.get(L"values").has(v.name)) {
                    restore_reg_value(action->hive, action->key, v.name, before.get(L"values").get(v.name), (int)v.type);
                    ++restored;
                }
            }
            return restored > 0;   // nothing restored is not a successful undo
        }
        if (kind == L"service") {
            int start = (int)before.get(L"start").integer(-1);
            if (!before.get(L"exists").flag() || !start_type_sc().count(start)) return false;
            std::wstring arg = (start == 2 && before.get(L"delayed").integer(-1) == 1) ? L"delayed-auto" : start_type_sc().at(start);
            if (system_hooks().run_exe({join(system32(), L"sc.exe"), L"config", action->service, L"start=", arg}) != 0) return false;
            if (before.get(L"running").is_bool() && before.get(L"running").flag()) ps(L"Start-Service -Name " + ps_quote(action->service) + L" -ErrorAction Stop");
            return true;
        }
        if (kind == L"account") {
            std::wstring sid = before.get(L"sid").str();
            if (!local_sid(sid) || !ends_with(sid, L"-" + std::to_wstring(action->rid))) return false;
            return ps(std::wstring(before.get(L"enabled").flag() ? L"Enable-LocalUser" : L"Disable-LocalUser") + L" -SID " + ps_quote(sid) + L" -ErrorAction Stop") == 0;
        }
        if (kind == L"defender") {
            const Json& v = before.get(L"disable_realtime_monitoring");
            if (!v.is_bool()) return false;
            return ps(std::wstring(L"Set-MpPreference -DisableRealtimeMonitoring $") + (v.flag() ? L"true" : L"false") + L" -ErrorAction Stop") == 0;
        }
        if (kind == L"firewall") {
            std::wstring commands;
            for (const Json& p : before.get(L"profiles").as_list()) {
                std::wstring name = p.get(L"name").str(), enabled = p.get(L"enabled").str();
                bool known_name = name == L"Domain" || name == L"Private" || name == L"Public";
                bool known_value = enabled == L"True" || enabled == L"False" || enabled == L"NotConfigured";
                if (known_name && known_value) commands += (commands.empty() ? L"" : L";") + std::wstring(L"Set-NetFirewallProfile -Profile ") + name + L" -Enabled " + enabled + L" -ErrorAction Stop";
            }
            return !commands.empty() && ps(commands) == 0;
        }
        if (kind == L"smb1") {
            const Json& v = before.get(L"enabled");
            if (!v.is_bool()) return false;
            return ps(std::wstring(L"Set-SmbServerConfiguration -EnableSMB1Protocol $") + (v.flag() ? L"true" : L"false") + L" -Force -Confirm:$false -ErrorAction Stop") == 0;
        }
        if (kind == L"netbios") {
            int restored = 0;
            for (const auto& [name, state] : before.get(L"interfaces").members()) {
                if (!netbios_iface(name) || !state.is_object()) continue;   // a backup cannot name another key
                std::wstring path = NETBIOS_ROOT + L"\\" + name;
                if (!registry.key_exists(L"HKLM", path)) continue;           // the adapter may have been removed: its key is never re-created
                restore_reg_value(L"HKLM", path, L"NetbiosOptions", state, REG_DWORD);
                ++restored;
            }
            return restored > 0;
        }
    } catch (const std::exception&) {
    }
    return false;
}

bool HardeningEngine::revert_action(const std::wstring& action_id) {
    std::lock_guard<std::recursive_mutex> guard(lock_);
    std::wstring path = find_backup_with(action_id);
    Backup backup;
    if (path.empty() || !load_backup(path, backup)) return false;
    bool ok = false;
    for (auto it = backup.entries.rbegin(); it != backup.entries.rend(); ++it) {
        if (it->id == action_id && revertible().count(it->status)) {
            ok = revert_entry(*it);
            it->status = ok ? L"reverted" : L"revert_failed";
            break;
        }
    }
    save_backup(path, backup);
    return ok;
}

std::pair<int, int> HardeningEngine::revert_backup(const std::wstring& path) {
    std::lock_guard<std::recursive_mutex> guard(lock_);
    Backup backup;
    if (!load_backup(path, backup)) return {0, 1};
    int ok = 0, failed = 0;
    for (auto it = backup.entries.rbegin(); it != backup.entries.rend(); ++it) {
        if (!revertible().count(it->status)) continue;
        if (revert_entry(*it)) {
            ++ok;
            it->status = L"reverted";
        } else {
            ++failed;
            it->status = L"revert_failed";
        }
    }
    backup.reverted = timestamp();
    save_backup(path, backup);
    return {ok, failed};
}

std::pair<int, int> HardeningEngine::revert_last() {
    std::lock_guard<std::recursive_mutex> guard(lock_);
    std::wstring path;
    if (!last_backup_path.empty() && is_file(last_backup_path)) {
        path = last_backup_path;
    } else {
        auto backups = list_hardening_backups();
        if (!backups.empty()) path = backups[0];
    }
    if (path.empty()) return {0, 0};
    return revert_backup(path);
}

// endregion

}  // namespace dd
