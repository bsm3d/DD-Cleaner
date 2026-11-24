// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the advanced tweaks catalogue: the safe and recommended presets and the exact revert of each change.

#include <ddcore/tweaks.hpp>

#include <algorithm>
#include <regex>
#include <stdexcept>

#include <windows.h>

#include <ddcore/audit.hpp>

namespace dd {

namespace {

const std::wstring WSH = L"HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings";

Tweak t(const wchar_t* category, const wchar_t* name, const std::wstring& command, const wchar_t* description, const wchar_t* risk) {
    return {category, name, command, description, risk};
}

std::wstring reg_add(const std::wstring& key, const wchar_t* value, int data) {
    return L"reg add \"" + key + L"\" /v " + value + L" /t REG_DWORD /d " + std::to_wstring(data) + L" /f";
}

std::vector<Tweak> safe_tweaks() {
    return {
        t(L"Telemetry", L"Disable DiagTrack", L"sc config DiagTrack start= disabled", L"Disable Connected User Experiences and Telemetry service", L"Low"),
        t(L"Telemetry", L"Disable dmwappushservice", L"sc config dmwappushservice start= disabled", L"Disable WAP Push Message Routing Service", L"Low"),
        t(L"Files", L"Unassociate .js", L"assoc .js=", L"Remove .js file association (block direct execution)", L"Low"),
        t(L"Files", L"Unassociate .vbs", L"assoc .vbs=", L"Remove .vbs file association (block direct execution)", L"Low"),
        t(L"Files", L"Unassociate .jse", L"assoc .jse=", L"Remove .jse file association (block direct execution)", L"Low"),
        t(L"Files", L"Unassociate .wsf", L"assoc .wsf=", L"Remove .wsf file association (block direct execution)", L"Low"),
        t(L"Files", L"Unassociate .vbe", L"assoc .vbe=", L"Remove .vbe file association (encoded VBScript)", L"Low"),
        t(L"Files", L"Unassociate .hta", L"assoc .hta=", L"Remove .hta file association (HTML applications run with full rights)", L"Low"),
    };
}

std::vector<Tweak> medium_tweaks() {
    auto v = safe_tweaks();
    v.push_back(t(L"Services", L"Disable RemoteRegistry", L"sc config RemoteRegistry start= disabled", L"Disable remote registry access service", L"Medium"));
    v.push_back(t(L"Services", L"Disable RemoteAccess", L"sc config RemoteAccess start= disabled", L"Disable Routing and Remote Access service", L"Medium"));
    v.push_back(t(L"Registry", L"Disable WSH", reg_add(WSH, L"Enabled", 0), L"Disable Windows Script Host (JScript/VBScript)", L"Medium"));
    v.push_back(t(L"Registry", L"WSH: ignore user settings", reg_add(WSH, L"IgnoreUserSettings", 1),
                  L"Without this, a program running as the user can turn WSH back on through HKCU", L"Medium"));
    v.push_back(t(L"Registry", L"WSH: log security failures", reg_add(WSH, L"LogSecurityFailures", 1), L"Write an event when a blocked script tries to run", L"Low"));
    return v;
}

std::vector<Tweak> aggressive_tweaks() {
    auto v = medium_tweaks();
    v.push_back(t(L"Services", L"Disable Xbox services", L"sc config XblAuthManager start= disabled", L"Disable Xbox Live Auth Manager (gaming)", L"High"));
    v.push_back(t(L"Services", L"Disable Xbox GameSave", L"sc config XblGameSave start= disabled", L"Disable Xbox Live Game Save service", L"High"));
    v.push_back(t(L"Privacy", L"Disable Windows Feedback", reg_add(L"HKCU\\Software\\Microsoft\\Siuf\\Rules", L"NumberOfSIUFInPeriod", 0),
                  L"Disable Windows Feedback notifications", L"Medium"));
    return v;
}

const std::map<int, const wchar_t*>& service_start_names() {
    static const std::map<int, const wchar_t*> m = {{0, L"boot"}, {1, L"system"}, {2, L"auto"}, {3, L"demand"}, {4, L"disabled"}};
    return m;
}

bool is_ws(wchar_t c) { return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n'; }

long long to_int(const Json& v) {
    if (v.is_number()) return v.integer();
    if (v.is_string()) {
        std::wstring s = trim(v.str());
        wchar_t* end = nullptr;
        long long n = wcstoll(s.c_str(), &end, 10);
        if (s.empty() || !end || *end) throw std::invalid_argument("not a number");
        return n;
    }
    if (v.is_bool()) return v.flag() ? 1 : 0;
    throw std::invalid_argument("not a number");
}

std::wstring quote_for_split(const std::wstring& arg) {
    bool needs = arg.empty() || arg.find_first_of(L" \t\"") != std::wstring::npos;
    return needs ? L"\"" + arg + L"\"" : arg;
}

void append_exact(std::vector<std::pair<std::wstring, std::wstring>>& commands, const std::wstring& label, const std::vector<std::wstring>& argv) {
    std::wstring cmd;
    for (const auto& a : argv) cmd += (cmd.empty() ? L"" : L" ") + quote_for_split(a);
    // Commands are stored as strings and split again by hardening_argv(): refuse any value (quote, backslash before a quote, newline...)
    // that would split into other arguments than the intended ones.
    bool exact = false;
    try {
        exact = shlex_split(cmd) == argv;
    } catch (const std::invalid_argument&) {
    }
    for (const auto& a : argv) {
        if (a.find_first_of(std::wstring(L"\r\n") + std::wstring(1, L'\0')) != std::wstring::npos) exact = false;
    }
    if (!exact) throw std::invalid_argument("unsafe characters in " + utf8(label));
    commands.emplace_back(label, cmd);
}

const wchar_t* reg_type_name(unsigned long type) {
    switch (type) {
        case REG_SZ: return L"REG_SZ";
        case REG_EXPAND_SZ: return L"REG_EXPAND_SZ";
        case REG_DWORD: return L"REG_DWORD";
        case REG_QWORD: return L"REG_QWORD";
    }
    return L"";
}

std::wstring hex_text(const std::string& raw) {
    wchar_t two[3];
    std::wstring out;
    for (unsigned char c : raw) {
        swprintf(two, 3, L"%02x", c);
        out += two;
    }
    return out;
}

}  // namespace

// region Catalogue

const std::vector<std::wstring>& tweak_preset_names() {
    static const std::vector<std::wstring> v = {L"Safe (Recommended)", L"Medium", L"Aggressive", L"Custom"};
    return v;
}

std::vector<Tweak> tweak_preset(const std::wstring& name) {
    if (name == L"Safe (Recommended)") return safe_tweaks();
    if (name == L"Medium") return medium_tweaks();
    if (name == L"Aggressive" || name == L"Custom") return aggressive_tweaks();   // "Custom" lists every tweak, unchecked
    return {};
}

const std::vector<std::pair<std::wstring, std::wstring>>& win10_default_restore() {
    static const std::vector<std::pair<std::wstring, std::wstring>> v = {
        {L"Re-enable DiagTrack", L"sc config DiagTrack start= auto"},
        {L"Re-enable dmwappushservice", L"sc config dmwappushservice start= demand"},
        {L"Reset RemoteRegistry (Win10 default: disabled)", L"sc config RemoteRegistry start= disabled"},
        {L"Reset RemoteAccess (Win10 default: disabled)", L"sc config RemoteAccess start= disabled"},
        {L"Re-enable XblAuthManager", L"sc config XblAuthManager start= demand"},
        {L"Re-enable XblGameSave", L"sc config XblGameSave start= demand"},
        {L"Re-enable WSH", L"reg delete \"" + WSH + L"\" /v Enabled /f"},
        {L"Restore .js association", L"assoc .js=JSFile"},
        {L"Restore .vbs association", L"assoc .vbs=VBSFile"},
        {L"Restore .jse association", L"assoc .jse=JSEFile"},
        {L"Restore .wsf association", L"assoc .wsf=WSFFile"},
        {L"Restore .vbe association", L"assoc .vbe=VBEFile"},
        {L"Restore .hta association", L"assoc .hta=htafile"},
        {L"Re-enable WSH user settings", L"reg delete \"" + WSH + L"\" /v IgnoreUserSettings /f"},
        {L"Remove WSH failure logging", L"reg delete \"" + WSH + L"\" /v LogSecurityFailures /f"},
    };
    return v;
}

// endregion

// region Parsing

std::vector<std::wstring> shlex_split(const std::wstring& text) {
    std::vector<std::wstring> tokens;
    std::wstring cur;
    bool in_token = false;
    std::size_t i = 0, n = text.size();
    while (i < n) {
        wchar_t c = text[i++];
        if (is_ws(c)) {
            if (in_token) tokens.push_back(cur);
            cur.clear();
            in_token = false;
        } else if (c == L'\\') {
            if (i >= n) throw std::invalid_argument("No escaped character");
            cur.push_back(text[i++]);
            in_token = true;
        } else if (c == L'\'') {
            in_token = true;
            for (;;) {
                if (i >= n) throw std::invalid_argument("No closing quotation");
                wchar_t q = text[i++];
                if (q == L'\'') break;
                cur.push_back(q);
            }
        } else if (c == L'"') {
            in_token = true;
            for (;;) {
                if (i >= n) throw std::invalid_argument("No closing quotation");
                wchar_t q = text[i++];
                if (q == L'"') break;
                if (q == L'\\') {
                    if (i >= n) throw std::invalid_argument("No escaped character");
                    wchar_t next = text[i];
                    if (next == L'"' || next == L'\\') {
                        cur.push_back(next);
                        ++i;
                    } else {
                        cur.push_back(L'\\');   // the backslash stays, the next character is read normally
                    }
                } else {
                    cur.push_back(q);
                }
            }
        } else {
            cur.push_back(c);
            in_token = true;
        }
    }
    if (in_token) tokens.push_back(cur);
    return tokens;
}

std::wstring normalize_registry_path(const std::wstring& path) {
    std::wstring p = trim(path);
    while (!p.empty() && p.front() == L'\\') p.erase(0, 1);
    while (!p.empty() && p.back() == L'\\') p.pop_back();
    for (std::size_t at; (at = p.find(L"\\\\")) != std::wstring::npos;) p.erase(at, 1);
    if (p.empty()) return L"";
    std::size_t slash = p.find(L'\\');
    std::wstring hive = p.substr(0, slash), rest = slash == std::wstring::npos ? L"" : p.substr(slash + 1);
    for (auto& c : hive) c = (wchar_t)towupper(c);
    static const std::map<std::wstring, std::wstring> aliases = {
        {L"HKLM", L"HKEY_LOCAL_MACHINE"}, {L"HKEY_LOCAL_MACHINE", L"HKEY_LOCAL_MACHINE"}, {L"HKCU", L"HKEY_CURRENT_USER"},
        {L"HKEY_CURRENT_USER", L"HKEY_CURRENT_USER"}, {L"HKCR", L"HKEY_CLASSES_ROOT"}, {L"HKEY_CLASSES_ROOT", L"HKEY_CLASSES_ROOT"},
        {L"HKU", L"HKEY_USERS"}, {L"HKEY_USERS", L"HKEY_USERS"}};
    auto it = aliases.find(hive);
    if (it != aliases.end()) hive = it->second;
    return rest.empty() ? hive : hive + L"\\" + rest;
}

std::wstring open_in_editor(const std::wstring& command) {
    std::vector<std::wstring> parts;
    try {
        parts = shlex_split(command);
    } catch (const std::invalid_argument&) {
        return command;
    }
    static const std::wregex re(LR"(^\.[A-Za-z0-9]{1,10}=$)");
    if (parts.size() == 2 && lower(parts[0]) == L"assoc" && std::regex_match(parts[1], re)) return L"assoc " + parts[1] + L"txtfile";   // Notepad
    return command;
}

std::vector<std::wstring> hardening_argv(const std::wstring& command) {
    std::vector<std::wstring> parts;
    try {
        parts = shlex_split(command);
    } catch (const std::invalid_argument& e) {
        throw;
    }
    if (parts.empty()) throw std::invalid_argument("Empty command");
    std::wstring tool = lower(parts[0]);
    std::vector<std::wstring> rest(parts.begin() + 1, parts.end());
    std::vector<std::wstring> argv;
    if (tool == L"sc" || tool == L"sc.exe") {
        argv = {sys_exe(L"sc.exe")};
    } else if (tool == L"reg" || tool == L"reg.exe") {
        argv = {sys_exe(L"reg.exe")};
    } else if (tool == L"assoc") {
        argv = {sys_exe(L"cmd.exe"), L"/d", L"/c", L"assoc"};   // assoc is a cmd.exe builtin, not an executable
    } else {
        throw std::invalid_argument("Command not allowed: " + utf8(parts[0]));
    }
    argv.insert(argv.end(), rest.begin(), rest.end());
    return argv;
}

TweakTarget parse_target(const std::wstring& command) {
    TweakTarget target;
    target.kind = L"unknown";
    std::vector<std::wstring> parts;
    try {
        parts = shlex_split(command);
    } catch (const std::invalid_argument&) {
        return target;
    }
    std::wstring tool = parts.empty() ? L"" : lower(parts[0]);
    if ((tool == L"sc" || tool == L"sc.exe") && parts.size() >= 3 && lower(parts[1]) == L"config") {
        target.kind = L"service";
        target.service = parts[2];
    } else if ((tool == L"reg" || tool == L"reg.exe") && parts.size() >= 3) {
        target.kind = L"reg";
        target.key = parts[2];
        auto v = std::find(parts.begin(), parts.end(), L"/v");
        if (v != parts.end() && v + 1 != parts.end()) {
            target.value = *(v + 1);
            target.has_value = true;
        }
    } else if (tool == L"assoc" && parts.size() >= 2) {
        target.kind = L"assoc";
        target.ext = parts[1].substr(0, parts[1].find(L'='));
    }
    return target;
}

AllowedTargets allowed_targets() {
    AllowedTargets allowed;
    std::vector<std::wstring> commands;
    for (const auto& tw : tweak_preset(L"Custom")) commands.push_back(tw.command);
    for (const auto& pair : win10_default_restore()) commands.push_back(pair.second);
    for (const auto& cmd : commands) {
        TweakTarget target = parse_target(cmd);
        if (target.kind == L"service") allowed.services.insert(lower(target.service));
        else if (target.kind == L"reg") allowed.registry.insert({lower(normalize_registry_path(target.key)), lower(target.has_value ? target.value : L"")});
        else if (target.kind == L"assoc") allowed.assocs.insert(lower(target.ext));
    }
    return allowed;
}

// endregion

// region Snapshot

Json read_reg_value(const std::wstring& key, const std::wstring& value, bool has_value) {
    std::wstring full = normalize_registry_path(key);
    std::size_t slash = full.find(L'\\');
    std::wstring hive_name = full.substr(0, slash), sub = slash == std::wstring::npos ? L"" : full.substr(slash + 1);
    std::wstring hive = hive_name == L"HKEY_LOCAL_MACHINE" ? L"HKLM" : hive_name == L"HKEY_CURRENT_USER" ? L"HKCU" : L"";
    Json out = Json::object();
    out.set(L"exists", Json::boolean(false));
    if (hive.empty()) return out;   // the catalogue only touches HKLM and HKCU
    RegistryState st = system_hooks().registry.read(hive, sub, has_value ? value : L"");
    if (!st.exists) return out;
    out.set(L"exists", Json::boolean(true));
    out.set(L"type", Json::number((double)st.type));
    if (st.type == REG_DWORD || st.type == REG_QWORD) out.set(L"data", Json::number((double)st.number));
    else if (st.type == REG_SZ || st.type == REG_EXPAND_SZ) out.set(L"data", Json::string(st.text));
    else out.set(L"data", Json::string(hex_text(st.raw)));   // never reverted: only the types above are accepted
    return out;
}

Json snapshot_entries(const std::vector<std::pair<std::wstring, std::wstring>>& tweaks, const RegistryReader& reader) {
    Json entries = Json::array();
    for (const auto& [name, cmd] : tweaks) {
        TweakTarget target = parse_target(cmd);
        Json e = Json::object();
        e.set(L"name", Json::string(name));
        e.set(L"command", Json::string(cmd));
        e.set(L"kind", Json::string(target.kind));
        if (target.kind == L"service") {
            e.set(L"service", Json::string(target.service));
            std::wstring base = L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\" + target.service;
            e.set(L"start", reader(base, L"Start", true));
            e.set(L"delayed", reader(base, L"DelayedAutostart", true));
        } else if (target.kind == L"reg") {
            e.set(L"key", Json::string(target.key));
            e.set(L"value", target.has_value ? Json::string(target.value) : Json());
            e.set(L"state", reader(target.key, target.value, target.has_value));
        } else if (target.kind == L"assoc") {
            e.set(L"ext", Json::string(target.ext));
            e.set(L"state", reader(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\" + target.ext, L"", false));
        }
        entries.push(e);
    }
    return entries;
}

std::wstring snapshot_tweaks(const std::vector<std::pair<std::wstring, std::wstring>>& tweaks, const std::wstring& folder, const RegistryReader& reader) {
    if (!make_dirs(folder)) return L"";
    std::wstring stamp = timestamp(), path = join(folder, L"tweaks_backup_" + stamp + L".json");
    for (int suffix = 1; lexists(path); ++suffix) path = join(folder, L"tweaks_backup_" + stamp + L"_" + std::to_wstring(suffix) + L".json");
    Json root = Json::object();
    root.set(L"created", Json::string(stamp));
    root.set(L"entries", snapshot_entries(tweaks, reader));
    return write_file(path, utf8(root.dump(true))) ? path : L"";
}

// endregion

// region Revert

std::vector<std::pair<std::wstring, std::wstring>> revert_commands(const Json& entries, std::vector<std::wstring>* ignored) {
    AllowedTargets allowed = allowed_targets();
    static const std::wregex progid_re(LR"(^[A-Za-z0-9._-]{1,64}$)");
    std::vector<std::pair<std::wstring, std::wstring>> commands;
    for (const Json& e : entries.as_list()) {
        if (!e.is_object()) continue;
        std::wstring kind = e.get(L"kind").str();
        try {
            if (kind == L"service") {
                std::wstring svc = e.get(L"service").str();
                if (!allowed.services.count(lower(svc))) throw std::invalid_argument("service not in catalogue: " + utf8(svc));
                const Json& start = e.get(L"start");
                if (!start.get(L"exists").flag()) continue;
                long long code = to_int(start.get(L"data"));
                auto it = service_start_names().find((int)code);
                if (code < 0 || it == service_start_names().end()) throw std::invalid_argument("invalid start type " + std::to_string(code));
                std::wstring name = it->second;
                const Json& delayed = e.get(L"delayed");
                if (name == L"auto" && delayed.get(L"exists").flag() && to_int(delayed.get(L"data")) == 1) name = L"delayed-auto";
                append_exact(commands, L"Restore " + svc + L" (" + name + L")", {L"sc", L"config", svc, L"start=", name});
            } else if (kind == L"reg") {
                std::wstring key = e.get(L"key").str();
                bool has_value = e.get(L"value").is_string() && !e.get(L"value").str().empty();
                std::wstring value = has_value ? e.get(L"value").str() : L"";
                std::wstring checked = normalize_registry_path(key);
                if (!allowed.registry.count({lower(checked), lower(value)})) throw std::invalid_argument("registry value not in catalogue: " + utf8(key));
                std::vector<std::wstring> v = has_value ? std::vector<std::wstring>{L"/v", value} : std::vector<std::wstring>{L"/ve"};
                const Json& st = e.get(L"state");
                std::wstring label = checked + L" " + (has_value ? value : L"(default)");
                if (!st.get(L"exists").flag()) {
                    std::vector<std::wstring> argv = {L"reg", L"delete", checked};
                    argv.insert(argv.end(), v.begin(), v.end());
                    argv.push_back(L"/f");
                    append_exact(commands, L"Remove " + label, argv);
                    continue;
                }
                long long vtype = st.get(L"type").integer(-1);
                std::wstring data;
                if (vtype == REG_DWORD || vtype == REG_QWORD) {
                    data = std::to_wstring(to_int(st.get(L"data")));
                } else if (vtype == REG_SZ || vtype == REG_EXPAND_SZ) {
                    data = st.get(L"data").str();
                    if (data.find(L'"') != std::wstring::npos || data.find(L'\n') != std::wstring::npos) throw std::invalid_argument("string data contains quotes/newlines");
                } else {
                    throw std::invalid_argument("unsupported value type " + std::to_string(vtype));
                }
                std::vector<std::wstring> argv = {L"reg", L"add", checked};
                argv.insert(argv.end(), v.begin(), v.end());
                for (const auto& piece : {std::wstring(L"/t"), std::wstring(reg_type_name((unsigned long)vtype)), std::wstring(L"/d"), data, std::wstring(L"/f")}) argv.push_back(piece);
                append_exact(commands, L"Restore " + label, argv);
            } else if (kind == L"assoc") {
                std::wstring ext = e.get(L"ext").str();
                if (!allowed.assocs.count(lower(ext))) throw std::invalid_argument("extension not in catalogue: " + utf8(ext));
                const Json& st = e.get(L"state");
                std::wstring progid = st.get(L"exists").flag() ? st.get(L"data").str() : L"";
                if (!progid.empty() && !std::regex_match(progid, progid_re)) throw std::invalid_argument("invalid ProgID " + utf8(progid));
                append_exact(commands, L"Restore " + ext + L" association", {L"assoc", ext + L"=" + progid});
            }
        } catch (const std::invalid_argument& err) {
            if (ignored) ignored->push_back(e.get(L"name").str() + L": " + wide(err.what()));
        }
    }
    return commands;
}

std::vector<std::pair<std::wstring, std::wstring>> revert_commands_from_snapshot(const std::wstring& snapshot_file) {
    std::string bytes;
    Json data;
    if (!read_file(snapshot_file, bytes)) throw std::runtime_error("cannot read " + utf8(snapshot_file));
    if (!try_parse_json(wide(bytes), data)) throw std::runtime_error("not valid JSON: " + utf8(snapshot_file));
    return revert_commands(data.is_object() ? data.get(L"entries") : Json());
}

// endregion

// region Run

TweakRunResult run_tweaks(const std::vector<std::pair<std::wstring, std::wstring>>& tweaks, const std::function<void(const std::wstring&)>& emit, const Stop& stop,
                          const std::function<ProcResult(const std::vector<std::wstring>&)>& runner) {
    TweakRunResult result;
    auto say = [&](const std::wstring& s) {
        if (emit) emit(s);
    };
    for (const auto& [name, cmd] : tweaks) {
        if (stop && stop()) break;
        say(L"\n> " + name + L"\n$ " + cmd + L"\n");
        try {
            std::vector<std::wstring> argv = hardening_argv(cmd);
            ProcResult r;
            if (runner) {
                r = runner(argv);
            } else {
                ProcOptions o;
                o.timeout_ms = 60000;
                o.stop = stop;
                r = run_process(argv, o);
            }
            if (!r.started) throw std::runtime_error("could not start " + utf8(argv[0]));
            if (r.timed_out) {
                say(L"❌ ERROR: Command timeout (60s)\n");
                ++result.failed;
                continue;
            }
            std::wstring output = trim(r.output);
            say((output.empty() ? L"Command completed" : output) + L"\n");
            if (r.code == 0) {
                say(L"✅ Success\n");
                ++result.ok;
            } else {
                say(L"⚠️ Exit code: " + std::to_wstring(r.code) + L"\n");
                ++result.failed;
            }
        } catch (const std::exception& ex) {
            say(L"❌ ERROR: " + wide(ex.what()) + L"\n");
            ++result.failed;
        }
    }
    return result;
}

// endregion

// region Telemetry

const std::vector<std::wstring>& telemetry_keywords() {
    static const std::vector<std::wstring> v = {L"microsoft", L"windows", L"msft", L"msn.", L"live.com", L"bing.", L"office", L"skype", L"msedge",
                                                L"azure", L"xbox", L"telemetry", L"watson", L"vortex", L"events.data", L"settings-win",
                                                L"smartscreen", L"wns.", L"msftncsi", L"aria.", L"onedrive", L"visualstudio", L"trafficmanager.net"};
    return v;
}

// One locale-independent snapshot: established TCP connections, DNS cache, process names
const wchar_t* const TELEMETRY_SCRIPT =
    LR"J($c = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' } | Select-Object RemoteAddress, RemotePort, OwningProcess; )J"
    LR"J($d = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Data } | Select-Object Entry, Data; )J"
    LR"J($p = Get-Process -ErrorAction SilentlyContinue | Select-Object Id, ProcessName; )J"
    LR"J(@{ conn = @($c); dns = @($d); proc = @($p) } | ConvertTo-Json -Depth 3 -Compress)J";

void telemetry_add_sample(TelemetryState& state, const Json& sample) {
    for (const Json& rec : sample.get(L"dns").as_list()) {
        std::wstring data = rec.get(L"Data").str(), entry = rec.get(L"Entry").str();
        if (!data.empty() && !entry.empty()) state.ip_names[data].insert(lower(entry));
    }
    for (const Json& rec : sample.get(L"proc").as_list()) {
        if (rec.get(L"Id").is_null()) continue;
        std::wstring name = rec.get(L"ProcessName").str();
        state.proc_names[(int)rec.get(L"Id").integer()] = name.empty() ? L"?" : name;
    }
    for (const Json& rec : sample.get(L"conn").as_list()) {
        if (!rec.is_object()) continue;
        std::wstring ip = rec.get(L"RemoteAddress").str();
        auto names = state.ip_names.find(ip);
        if (names == state.ip_names.end()) continue;
        for (const auto& host : names->second) {
            for (const auto& k : telemetry_keywords()) {
                if (host.find(k) != std::wstring::npos) {
                    state.hits[(int)rec.get(L"OwningProcess").integer(0)].insert({ip, host});
                    break;
                }
            }
        }
    }
}

TelemetryResult telemetry_result(const TelemetryState& state, int samples) {
    TelemetryResult r;
    r.samples = samples;
    for (const auto& [pid, pairs] : state.hits) {
        TelemetryHit h;
        h.pid = pid;
        auto it = state.proc_names.find(pid);
        h.process = it == state.proc_names.end() ? L"PID " + std::to_wstring(pid) : it->second;
        h.connections.assign(pairs.begin(), pairs.end());
        std::sort(h.connections.begin(), h.connections.end());
        r.hits.push_back(h);
    }
    std::stable_sort(r.hits.begin(), r.hits.end(), [](const TelemetryHit& a, const TelemetryHit& b) { return a.connections.size() > b.connections.size(); });
    return r;
}

std::wstring TelemetryResult::report() const {
    std::wstring out = L"\n\U0001F4CA Results (" + std::to_wstring(samples) + L" samples):\n" + std::wstring(60, L'=') + L"\n\n";
    if (hits.empty()) {
        out += L"✅ No connection to Microsoft/telemetry hosts detected (connections whose name is not in the DNS cache cannot be identified).\n";
        return out;
    }
    out += std::to_wstring(hits.size()) + L" process(es) connected to Microsoft/telemetry hosts:\n\n";
    for (const auto& h : hits) {
        out += L"\U0001F538 " + h.process + L" (PID " + std::to_wstring(h.pid) + L"): " + std::to_wstring(h.connections.size()) + L" connection(s)\n";
        for (std::size_t i = 0; i < h.connections.size() && i < 5; ++i) out += L"   └─ " + h.connections[i].second + L" (" + h.connections[i].first + L")\n";
        if (h.connections.size() > 5) out += L"   └─ ... and " + std::to_wstring(h.connections.size() - 5) + L" more\n";
        out += L"\n";
    }
    return out;
}

namespace {
struct SampleTimeout {};

// Waits in small slices so Stop is honoured
void wait_ms(unsigned long ms, const Stop& stop) {
    ULONGLONG until = GetTickCount64() + ms;
    while (GetTickCount64() < until && !(stop && stop())) Sleep(50);
}
}  // namespace

TelemetryResult telemetry_scan(unsigned long duration_ms, unsigned long interval_ms, const Stop& stop, const TelemetrySampler& sampler, const std::function<void(const std::wstring&)>& emit) {
    auto say = [&](const std::wstring& s) {
        if (emit) emit(s);
    };
    TelemetrySampler sample = sampler;
    if (!sample) {
        sample = [] {
            ProcOptions o;
            o.timeout_ms = 20000;
            o.merge_stderr = false;
            ProcResult r = run_powershell(TELEMETRY_SCRIPT, o);
            if (!r.started) throw std::runtime_error("PowerShell could not start");
            if (r.timed_out) throw SampleTimeout();
            if (trim(r.output).empty()) return Json::object();
            Json data;
            if (!try_parse_json(r.output, data)) throw std::runtime_error("the sample could not be read");
            return data;
        };
    }
    TelemetryState state;
    int samples = 0;
    ULONGLONG end = GetTickCount64() + duration_ms;
    while (GetTickCount64() < end && !(stop && stop())) {
        ++samples;
        Json data;
        try {
            data = sample();
        } catch (const SampleTimeout&) {
            say(L"⚠️ Sample timed out, continuing...\n");
            continue;
        } catch (const std::exception& e) {
            say(L"⚠️ Sample error: " + wide(e.what()) + L"\n");
            wait_ms(interval_ms, stop);
            continue;
        }
        telemetry_add_sample(state, data);
        wait_ms(interval_ms, stop);
    }
    return telemetry_result(state, samples);
}

// endregion

}  // namespace dd
