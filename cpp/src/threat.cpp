// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the malware hunt: the sets of suspicious system and service names and the command line pattern matching.

#include <ddcore/threat.hpp>

#include <algorithm>
#include <array>
#include <regex>

#include <windows.h>

#include <ddcore/dead_registry.hpp>
#include <ddcore/inspect.hpp>
#include <ddcore/proc.hpp>
#include <ddcore/registry.hpp>
#include <ddcore/startup.hpp>
#include <ddcore/traffic.hpp>

namespace dd {

namespace {

const std::wstring SERVICES_KEY = L"SYSTEM\\CurrentControlSet\\Services";
const std::wstring WINLOGON = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
const std::wstring IFEO = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
const std::wstring WINDOWS_NT_WINDOWS = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
const std::wstring SESSION_MANAGER = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager";
const std::wstring INTERNET_SETTINGS = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
const std::wstring POLICIES_RUN = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run";

const std::set<std::wstring>& accessibility_programs() {
    static const std::set<std::wstring> s = {L"sethc.exe", L"utilman.exe", L"osk.exe", L"narrator.exe", L"magnify.exe", L"displayswitch.exe", L"atbroker.exe"};
    return s;
}
const std::set<std::wstring>& known_system_programs() {
    static const std::set<std::wstring> s = {L"svchost.exe", L"lsass.exe", L"csrss.exe", L"smss.exe", L"wininit.exe", L"services.exe", L"winlogon.exe",
                                             L"explorer.exe", L"taskhostw.exe", L"dllhost.exe", L"conhost.exe", L"spoolsv.exe", L"searchindexer.exe",
                                             L"runtimebroker.exe", L"sihost.exe", L"fontdrvhost.exe", L"ctfmon.exe", L"audiodg.exe", L"dwm.exe", L"taskmgr.exe"};
    return s;
}
const std::set<std::wstring>& no_path_ok() {
    static const std::set<std::wstring> s = {L"system", L"registry", L"memcompression", L"secure system", L"smss.exe", L"csrss.exe", L"wininit.exe",
                                             L"services.exe", L"lsass.exe", L"system idle process", L"[system process]", L"vmmem", L"vmmemwsl"};
    return s;
}

struct CommandPattern {
    std::wregex regex;
    const wchar_t* reason;
    int severity;
};

const std::vector<CommandPattern>& command_patterns() {
    const auto flags = std::regex::icase | std::regex::ECMAScript;
    static const std::vector<CommandPattern> p = {
        {std::wregex(LR"(-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,})", flags), L"encoded PowerShell command", SEV_SUSPICIOUS},
        {std::wregex(LR"(frombase64string|invoke-expression|\biex\b|downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient)", flags),
         L"PowerShell downloads or runs text as code", SEV_SUSPICIOUS},
        {std::wregex(LR"((mshta|wscript|cscript|regsvr32|rundll32|bitsadmin|certutil)\b.*https?://)", flags), L"script host or LOLBin fetching a URL", SEV_SUSPICIOUS},
        {std::wregex(LR"(certutil.*-urlcache|bitsadmin.*/transfer)", flags), L"download through a Windows tool", SEV_SUSPICIOUS},
        {std::wregex(LR"(regsvr32.*scrobj\.dll|mshta\s+(vbscript|javascript))", flags), L"script run through a Windows tool", SEV_SUSPICIOUS},
        {std::wregex(LR"(-w(indowstyle)?\s+hidden|-nop\b.*-w\b|-noprofile.*hidden)", flags), L"hidden window", SEV_LOOK},
    };
    return p;
}

const std::wregex& security_sites() {
    static const std::wregex r(LR"((avast|avg\.|kaspersky|bitdefender|eset\.|norton|mcafee|malwarebytes|sophos|clamav|virustotal|defender|windowsupdate|update\.microsoft|symantec|trendmicro|f-secure))",
                               std::regex::icase);
    return r;
}
const std::wregex& sensitive_sites() {
    static const std::wregex r(LR"((microsoft|windows|google|paypal|bank|login|accounts\.|apple|amazon|facebook|steam|github))", std::regex::icase);
    return r;
}

// the values of a registry key by name (nothing when the key is missing)
struct Values {
    bool exists = false;
    std::map<std::wstring, RegValue> by_name;
    bool has(const std::wstring& n) const { return by_name.count(n) > 0; }
    std::wstring text(const std::wstring& n, const std::wstring& fallback = L"") const {
        auto it = by_name.find(n);
        return it != by_name.end() && it->second.is_text() ? it->second.text : fallback;
    }
    bool is_text(const std::wstring& n) const { return has(n) && by_name.at(n).is_text(); }
    bool dword_is(const std::wstring& n, DWORD v) const {
        auto it = by_name.find(n);
        return it != by_name.end() && it->second.type == REG_DWORD && it->second.dword == v;
    }
    std::wstring shown(const std::wstring& n) const {
        auto it = by_name.find(n);
        return it == by_name.end() ? L"" : it->second.shown;
    }
};

Values values_of(const std::wstring& hive, const std::wstring& path) {
    Values v;
    RegKey key = RegKey::open(hive, path);
    if (!key.valid()) return v;
    v.exists = true;
    for (auto& val : key.values()) v.by_name.emplace(val.name, val);
    return v;
}

std::wstring path_key(const std::wstring& path) { return normcase(path); }

}  // namespace

bool HuntFinding::dead() const {
    for (const auto& f : flags) {
        if (f == L"Program not found" || f == L"Automatic service whose program is missing") return true;
    }
    return false;
}

// region Shared checks

std::wstring risky_location(const std::wstring& path) {
    static const wchar_t* risky[] = {L"\\appdata\\local\\temp\\", L"\\windows\\temp\\", L"\\users\\public\\", L"\\downloads\\", L"\\$recycle.bin\\"};
    std::wstring low = path.empty() ? L"" : normcase(absolute(path));
    std::wstring temp = normcase(absolute(temp_dir())) + L"\\";
    bool hit = starts_with(low, temp);
    for (const wchar_t* marker : risky) hit |= (low + L"\\").find(marker) != std::wstring::npos;
    return hit ? L"Runs from a temporary, download or public folder" : L"";
}

std::vector<std::pair<std::wstring, int>> suspicious_command(const std::wstring& command) {
    std::vector<std::pair<std::wstring, int>> found;
    for (const auto& p : command_patterns()) {
        if (std::regex_search(command, p.regex)) found.emplace_back(p.reason, p.severity);
    }
    return found;
}

bool judge_in_windows(const std::wstring& path) { return starts_with(normcase(path), normcase(system_root()) + L"\\"); }

std::vector<std::wstring> hijackable_prefixes(const std::wstring& command_in) {
    std::wstring command = trim(expand_env(command_in));
    if (command.empty() || command[0] == L'"') return {};
    static const std::wregex program(LR"(([A-Za-z]:\\.*?\.(?:exe|bat|cmd|com))(?=\s|$))", std::regex::icase);
    std::wsmatch m;
    if (!std::regex_search(command, m, program) || m.position(0) != 0 || m[1].str().find(L' ') == std::wstring::npos) return {};
    std::wstring full = m[1];
    std::vector<std::wstring> planted;
    for (std::size_t i = 0; i < full.size(); ++i) {
        if (full[i] != L' ') continue;
        std::wstring p = full.substr(0, i) + L".exe";
        // a standard user cannot create files in a drive root by default, so only deeper folders count
        if (dir_name(dir_name(p)) != dir_name(p)) planted.push_back(p);
    }
    return planted;
}

FileJudge::FileJudge(SignerOf signer_of, PackedOf packed_of, WritableOf writable_of)
    : signer_of_(std::move(signer_of)), packed_of_(std::move(packed_of)), writable_of_(std::move(writable_of)) {
    if (!signer_of_) signer_of_ = [](const std::wstring& p) { return inspect_pe(p).signer; };
    if (!packed_of_) packed_of_ = [](const std::wstring& p) { return inspect(p).packed; };
    if (!writable_of_) writable_of_ = [](const std::wstring& folder) {
        bool ok = true;
        auto w = unprivileged_writers(folder, &ok);
        return ok && !w.empty();
    };
}

static bool file_too_big(const std::wstring& path) {
    Entry e;
    return !stat_path(path, e) || e.size > MAX_SIGNED_SIZE;
}

std::wstring FileJudge::signer(const std::wstring& path) {
    std::wstring key = path_key(path);
    auto it = signers_.find(key);
    if (it == signers_.end()) it = signers_.emplace(key, file_too_big(path) ? L"" : signer_of_(path)).first;
    return it->second;
}

bool FileJudge::unsigned_file(const std::wstring& path) {
    std::wstring ext = extension(path);
    if (in_windows(path) || !(ext == L".exe" || ext == L".dll" || ext == L".scr" || ext == L".com" || ext == L".sys")) return false;
    Entry e;
    if (!stat_path(path, e) || e.size > MAX_SIGNED_SIZE) return false;
    return signer(path).empty();
}

bool FileJudge::packed(const std::wstring& path) {
    std::wstring key = path_key(path);
    auto it = packed_.find(key);
    if (it == packed_.end()) it = packed_.emplace(key, packed_of_(path)).first;
    return it->second;
}

bool FileJudge::writable_folder(const std::wstring& path) {
    std::wstring folder = dir_name(path), key = path_key(folder);
    auto it = writable_.find(key);
    if (it == writable_.end()) it = writable_.emplace(key, writable_of_(folder)).first;
    return it->second;
}

std::pair<std::vector<std::wstring>, int> program_flags(const std::wstring& path, FileJudge& judge, bool elevated) {
    std::vector<std::wstring> flags;
    int severity = SEV_INFO;
    std::wstring reason = risky_location(path);
    if (!reason.empty()) {
        flags.push_back(reason);
        severity = SEV_SUSPICIOUS;
    }
    if (judge.unsigned_file(path)) {
        flags.push_back(L"Not signed");
        severity = std::max(severity, SEV_LOOK);
        if (judge.packed(path)) {
            flags.push_back(L"High entropy (possibly packed)");
            severity = SEV_SUSPICIOUS;
        }
    }
    if (elevated && !judge.in_windows(path) && judge.writable_folder(path)) {
        flags.push_back(L"Its folder can be changed by standard users");
        severity = SEV_SUSPICIOUS;
    }
    return {flags, severity};
}

// endregion

// region Services

std::vector<ServiceEntry> read_services() {
    std::vector<ServiceEntry> services;
    RegKey root = RegKey::open(L"HKLM", SERVICES_KEY);
    for (const auto& name : root.subkeys()) {
        Values v = values_of(L"HKLM", SERVICES_KEY + L"\\" + name);
        if (!v.exists) continue;
        auto type = v.by_name.find(L"Type");
        if (type == v.by_name.end() || type->second.type != REG_DWORD || !(type->second.dword & 0x30) || !v.is_text(L"ImagePath")) continue;
        ServiceEntry s;
        s.name = name;
        s.display = v.text(L"DisplayName");
        s.image = v.text(L"ImagePath");
        auto start = v.by_name.find(L"Start");
        if (start != v.by_name.end() && start->second.type == REG_DWORD) {
            s.has_start = true;
            s.start = start->second.dword;
        }
        s.account = v.text(L"ObjectName");
        s.dll = values_of(L"HKLM", SERVICES_KEY + L"\\" + name + L"\\Parameters").text(L"ServiceDll");
        services.push_back(std::move(s));
    }
    return services;
}

std::vector<HuntFinding> check_services(const std::vector<ServiceEntry>& services, FileJudge& judge, const Stop& stop) {
    std::vector<HuntFinding> findings;
    for (const ServiceEntry& svc : services) {
        if (stop()) break;
        if (!svc.has_start || svc.start < 0 || svc.start > 3) continue;   // disabled
        std::wstring image = trim(expand_env(svc.image));
        std::wstring target = command_path(image);
        if (!svc.dll.empty()) {
            std::wstring dll = strip_quotes(trim(expand_env(svc.dll)));
            if (is_file(dll)) target = dll;
        }
        std::vector<std::wstring> flags;
        int severity = SEV_INFO;
        if (target.empty()) {
            if (svc.start == 2 && check_target(image).state == TargetState::Missing) {
                flags.push_back(L"Automatic service whose program is missing");
                severity = SEV_LOOK;
            }
        } else {
            if (judge.in_windows(target)) continue;   // catalog-signed Windows program
            bool elevated = lower(svc.account).find(L"system") != std::wstring::npos || svc.account.empty();
            auto pf = program_flags(target, judge, elevated);
            flags = pf.first;
            severity = pf.second;
        }
        if (!(!target.empty() && judge.in_windows(target))) {
            bool writable = false;
            for (const auto& p : hijackable_prefixes(image)) writable |= judge.writable_folder(p);
            if (writable) {
                flags.push_back(L"Unquoted path with spaces and a writable folder on the way (can be hijacked)");
                severity = std::max(severity, SEV_SUSPICIOUS);
            }
        }
        for (const auto& [reason, level] : suspicious_command(image)) {
            flags.push_back(reason);
            severity = std::max(severity, level);
        }
        if (!flags.empty()) {
            HuntFinding f;
            f.category = L"Service";
            f.title = svc.display.empty() ? svc.name : svc.display;
            f.detail = image;
            f.severity = severity;
            f.path = target;
            f.location = L"HKLM\\" + SERVICES_KEY + L"\\" + svc.name;
            f.flags = flags;
            f.removal = {L"service", {svc.name}};
            findings.push_back(std::move(f));
        }
    }
    return findings;
}

// endregion

// region Scheduled tasks and WMI

static const wchar_t* TASKS_PS = LR"J(
$t = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
    $a = @($_.Actions)[0]
    [pscustomobject]@{ Name = $_.TaskName; Path = $_.TaskPath; Exec = [string]$a.Execute; Args = [string]$a.Arguments;
                       User = [string]$_.Principal.UserId; Level = $_.Principal.RunLevel.ToString() }
}
ConvertTo-Json -InputObject @($t) -Compress
)J";

static const wchar_t* WMI_PS = LR"J(
$c = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{ Kind = $_.CimClass.CimClassName; Name = [string]$_.Name; Cmd = [string]$_.CommandLineTemplate;
                       Exe = [string]$_.ExecutablePath; Script = [string]$_.ScriptText }
}
ConvertTo-Json -InputObject @($c) -Compress
)J";

static std::vector<Json> objects_of(const Json& data) {
    std::vector<Json> out;
    for (const Json& d : data.as_list()) {
        if (d.is_object() && d.size() > 0) out.push_back(d);
    }
    return out;
}

std::vector<HuntFinding> check_tasks(FileJudge& judge, const Json* injected, const Stop& stop) {
    Json data = injected ? *injected : run_powershell_json(TASKS_PS, 60000);
    std::vector<HuntFinding> findings;
    for (const Json& t : objects_of(data)) {
        if (stop()) break;
        if (t.get(L"Exec").str().empty()) continue;
        std::wstring exe = strip_quotes(trim(expand_env(t.get(L"Exec").str())));
        std::wstring command = trim(L"\"" + exe + L"\" " + t.get(L"Args").str());
        std::wstring target = is_file(exe) ? exe : command_path(command);
        bool highest = t.get(L"Level").str() == L"Highest";
        bool elevated = highest || lower(t.get(L"User").str()).find(L"system") != std::wstring::npos;
        std::vector<std::wstring> flags;
        int severity = SEV_INFO;
        if (!target.empty() && !judge.in_windows(target)) {
            auto pf = program_flags(target, judge, elevated);
            flags = pf.first;
            severity = pf.second;
        } else if (target.empty() && check_target(command).state == TargetState::Missing) {
            flags = {L"Program not found"};
            severity = SEV_LOOK;
        }
        for (const auto& [reason, level] : suspicious_command(command)) {
            flags.push_back(reason);
            severity = std::max(severity, level);
        }
        if (!flags.empty()) {
            std::wstring who = (t.get(L"User").str().empty() ? L"task" : t.get(L"User").str()) + (highest ? L" (highest privileges)" : L"");
            HuntFinding f;
            f.category = L"Scheduled task";
            f.title = t.get(L"Name").str();
            f.detail = command;
            f.severity = severity;
            f.path = target;
            f.location = L"Task Scheduler " + t.get(L"Path").str() + L" as " + who;
            f.flags = flags;
            std::wstring task_path = t.has(L"Path") ? t.get(L"Path").str() : L"\\";
            f.removal = {L"task", {t.get(L"Name").str(), task_path}};
            findings.push_back(std::move(f));
        }
    }
    return findings;
}

std::vector<HuntFinding> check_wmi(const Json* injected) {
    Json data = injected ? *injected : run_powershell_json(WMI_PS, 60000);
    std::vector<HuntFinding> findings;
    for (const Json& c : objects_of(data)) {
        std::wstring kind = c.get(L"Kind").str(), name = c.get(L"Name").str();
        if (kind == L"NTEventLogEventConsumer" || name == L"SCM Event Log Consumer") continue;   // installed by Windows
        std::wstring action = !c.get(L"Cmd").str().empty() ? c.get(L"Cmd").str() : !c.get(L"Exe").str().empty() ? c.get(L"Exe").str() : c.get(L"Script").str().substr(0, 200);
        int severity = (kind == L"CommandLineEventConsumer" || kind == L"ActiveScriptEventConsumer") ? SEV_SUSPICIOUS : SEV_LOOK;
        HuntFinding f;
        f.category = L"WMI subscription";
        f.title = name.empty() ? kind : name;
        f.detail = action;
        f.severity = severity;
        f.location = L"root\\subscription (" + kind + L")";
        f.flags = {L"Permanent WMI event consumer"};
        findings.push_back(std::move(f));
    }
    return findings;
}

// endregion

// region Hijacked Windows settings

std::vector<HuntFinding> check_hijacks() {
    std::vector<HuntFinding> findings;
    auto add = [&](const std::wstring& title, const std::wstring& detail, int severity, const std::wstring& location,
                   const std::vector<std::wstring>& flags, const std::wstring& path = L"", HuntRemoval removal = {}) {
        HuntFinding f;
        f.category = L"Windows setting";
        f.title = title;
        f.detail = detail;
        f.severity = severity;
        f.path = path;
        f.location = location;
        f.flags = flags;
        f.removal = std::move(removal);
        findings.push_back(std::move(f));
    };

    Values winlogon = values_of(L"HKLM", WINLOGON);
    std::wstring shell = trim(winlogon.is_text(L"Shell") ? winlogon.text(L"Shell") : (winlogon.has(L"Shell") ? winlogon.shown(L"Shell") : L"explorer.exe"));
    if (lower(shell) != L"explorer.exe") add(L"Winlogon Shell", shell, SEV_SUSPICIOUS, L"HKLM\\" + WINLOGON, {L"Not the usual explorer.exe"});
    std::wstring userinit = lower(trim([&] {
        std::wstring u = trim(winlogon.shown(L"Userinit"));
        while (!u.empty() && u.back() == L',') u.pop_back();
        return u;
    }()));
    if (!userinit.empty() && userinit != lower(join(system32(), L"userinit.exe"))) {
        add(L"Winlogon Userinit", winlogon.shown(L"Userinit"), SEV_SUSPICIOUS, L"HKLM\\" + WINLOGON, {L"Starts something besides userinit.exe"});
    }
    Values user_logon = values_of(L"HKCU", WINLOGON);
    if (user_logon.has(L"Shell") && !user_logon.shown(L"Shell").empty()) {
        add(L"Winlogon Shell (current user)", user_logon.shown(L"Shell"), SEV_SUSPICIOUS, L"HKCU\\" + WINLOGON, {L"A per-user shell replaces explorer.exe"});
    }

    RegKey ifeo = RegKey::open(L"HKLM", IFEO);
    for (const auto& program : ifeo.subkeys()) {
        Values v = values_of(L"HKLM", IFEO + L"\\" + program);
        if (!v.is_text(L"Debugger") || trim(v.text(L"Debugger")).empty() || lower(v.text(L"Debugger")).find(L"vsjitdebugger") != std::wstring::npos) continue;
        std::wstring debugger = v.text(L"Debugger");
        std::wstring target = command_path(debugger);
        bool blocked = !target.empty() && judge_in_windows(target) && !accessibility_programs().count(lower(program));
        add(L"Debugger set for " + program, debugger, blocked ? SEV_LOOK : SEV_SUSPICIOUS, L"HKLM\\" + IFEO + L"\\" + program,
            {blocked ? L"The program is blocked from starting (a privacy tweak does this)"
                     : L"Another program starts instead (accessibility tools are a classic target)"},
            L"", {L"regvalue", {L"HKLM", IFEO + L"\\" + program, L"Debugger"}});
    }

    Values windows = values_of(L"HKLM", WINDOWS_NT_WINDOWS);
    std::wstring appinit = trim(windows.shown(L"AppInit_DLLs"));
    if (!appinit.empty()) {
        bool loaded = windows.dword_is(L"LoadAppInit_DLLs", 1);
        add(L"AppInit_DLLs", appinit, loaded ? SEV_SUSPICIOUS : SEV_LOOK, L"HKLM\\" + WINDOWS_NT_WINDOWS,
            {loaded ? L"Loaded into every program" : L"Set but not enabled"});
    }

    for (const auto& [name, value] : values_of(L"HKLM", SESSION_MANAGER + L"\\AppCertDlls").by_name) {
        add(L"AppCertDlls", name + L" = " + value.shown, SEV_SUSPICIOUS, L"HKLM\\" + SESSION_MANAGER + L"\\AppCertDlls",
            {L"A DLL is loaded into every process that starts programs"});
    }
    std::wstring boot_text = values_of(L"HKLM", SESSION_MANAGER).shown(L"BootExecute");
    if (!trim(boot_text).empty() && lower(trim(boot_text)) != L"autocheck autochk *") {
        add(L"BootExecute", boot_text, SEV_SUSPICIOUS, L"HKLM\\" + SESSION_MANAGER, {L"Runs before Windows starts"});
    }

    for (const wchar_t* hive : {L"HKLM", L"HKCU"}) {
        Values processor = values_of(hive, L"SOFTWARE\\Microsoft\\Command Processor");
        if (processor.is_text(L"AutoRun") && !trim(processor.text(L"AutoRun")).empty()) {
            add(L"Command Prompt AutoRun", processor.text(L"AutoRun"), SEV_LOOK, std::wstring(hive) + L"\\SOFTWARE\\Microsoft\\Command Processor",
                {L"Runs every time a Command Prompt opens"});
        }
        for (const auto& [name, value] : values_of(hive, POLICIES_RUN).by_name) {
            if (value.is_text() && !trim(value.text).empty()) {
                add(L"Policy startup: " + name, value.text, SEV_LOOK, std::wstring(hive) + L"\\" + POLICIES_RUN, {L"Starts at logon from a policy key"},
                    command_path(value.text), {L"regvalue", {hive, POLICIES_RUN, name}});
            }
        }
    }
    Values desktop = values_of(L"HKCU", L"Control Panel\\Desktop");
    if (desktop.is_text(L"SCRNSAVE.EXE") && !trim(desktop.text(L"SCRNSAVE.EXE")).empty() &&
        !starts_with(lower(command_path(desktop.text(L"SCRNSAVE.EXE"))), lower(system_root()))) {
        add(L"Screen saver", desktop.text(L"SCRNSAVE.EXE"), SEV_LOOK, L"HKCU\\Control Panel\\Desktop", {L"A screen saver outside Windows is a program"},
            command_path(desktop.text(L"SCRNSAVE.EXE")));
    }

    Values exe_open = values_of(L"HKLM", L"SOFTWARE\\Classes\\exefile\\shell\\open\\command");
    if (exe_open.is_text(L"") && trim(exe_open.text(L"")) != L"\"%1\" %*") {
        add(L"How .exe files open", exe_open.text(L""), SEV_SUSPICIOUS, L"HKLM\\SOFTWARE\\Classes\\exefile\\shell\\open\\command",
            {L"Every program is started through something else"});
    }
    return findings;
}

// endregion

// region Hosts, proxy, browser extensions

std::vector<HuntFinding> check_hosts(const std::wstring& path_in) {
    std::wstring path = path_in.empty() ? join(join(join(system32(), L"drivers"), L"etc"), L"hosts") : path_in;
    std::string bytes;
    std::vector<HuntFinding> findings;
    if (!read_file(path, bytes, 8 * 1024 * 1024)) return findings;
    static const std::set<std::wstring> loopback = {L"127.0.0.1", L"0.0.0.0", L"::1", L"::"};
    int number = 0;
    for (const auto& raw : split(wide(bytes), L'\n')) {
        ++number;
        std::wstring line = raw.substr(0, raw.find(L'#'));
        std::vector<std::wstring> parts;
        std::wstring token;
        for (wchar_t c : line + L" ") {
            if (iswspace(c)) {
                if (!token.empty()) parts.push_back(token);
                token.clear();
            } else {
                token.push_back(c);
            }
        }
        if (parts.size() < 2) continue;
        const std::wstring& address = parts[0];
        for (std::size_t i = 1; i < parts.size(); ++i) {
            const std::wstring& name = parts[i];
            HuntFinding f;
            f.category = L"Hosts file";
            f.title = name;
            f.detail = address + L" " + name;
            f.location = path + L", line " + std::to_wstring(number);
            if (loopback.count(address)) {
                if (!std::regex_search(name, security_sites())) continue;
                f.severity = SEV_SUSPICIOUS;
                f.flags = {L"Blocks a security or update site"};
            } else if (starts_with(address, L"::")) {
                continue;
            } else {
                f.severity = std::regex_search(name, sensitive_sites()) || std::regex_search(name, security_sites()) ? SEV_SUSPICIOUS : SEV_LOOK;
                f.flags = {L"Sends " + name + L" to " + address};
            }
            findings.push_back(std::move(f));
        }
    }
    return findings;
}

std::vector<HuntFinding> check_proxy() {
    Values v = values_of(L"HKCU", INTERNET_SETTINGS);
    std::vector<HuntFinding> findings;
    if (v.dword_is(L"ProxyEnable", 1) && !trim(v.text(L"ProxyServer")).empty()) {
        HuntFinding f;
        f.category = L"Proxy";
        f.title = L"Browser proxy is on";
        f.detail = v.text(L"ProxyServer");
        f.severity = SEV_LOOK;
        f.location = L"HKCU\\" + INTERNET_SETTINGS;
        f.flags = {L"All web traffic goes through this server"};
        findings.push_back(std::move(f));
    }
    if (!trim(v.text(L"AutoConfigURL")).empty()) {
        HuntFinding f;
        f.category = L"Proxy";
        f.title = L"Proxy auto-configuration script";
        f.detail = v.text(L"AutoConfigURL");
        f.severity = SEV_LOOK;
        f.location = L"HKCU\\" + INTERNET_SETTINGS;
        f.flags = {L"A script decides where web traffic goes"};
        findings.push_back(std::move(f));
    }
    return findings;
}

namespace {

std::wstring read_json_text(const std::wstring& path, Json& out) {
    std::string bytes;
    if (!read_file(path, bytes, 16 * 1024 * 1024)) return L"missing";
    std::size_t skip = bytes.size() >= 3 && (unsigned char)bytes[0] == 0xEF && (unsigned char)bytes[1] == 0xBB && (unsigned char)bytes[2] == 0xBF ? 3 : 0;
    return try_parse_json(wide(bytes.substr(skip)), out) ? L"" : L"invalid";
}

std::wstring extension_name(const std::wstring& folder, const Json& manifest) {
    std::wstring name = manifest.get(L"name").str();
    static const std::wregex msg(LR"(__MSG_(.+)__)");
    std::wsmatch m;
    if (!std::regex_match(name, m, msg)) return name;
    std::wstring default_locale = manifest.has(L"default_locale") ? manifest.get(L"default_locale").str() : L"en";
    for (const std::wstring& locale : {default_locale, std::wstring(L"en"), std::wstring(L"en_US")}) {
        Json messages;
        if (!read_json_text(join(join(join(folder, L"_locales"), locale), L"messages.json"), messages).empty() || !messages.is_object()) continue;
        std::wstring wanted = lower(m[1]);
        for (const auto& [k, v] : messages.members()) {
            if (lower(k) == wanted && v.has(L"message")) return v.get(L"message").str();
        }
    }
    return name;
}

}  // namespace

std::vector<HuntFinding> check_extensions(const std::wstring& local_app_data) {
    static const std::pair<const wchar_t*, const wchar_t*> browsers[] = {{L"Chrome", L"Google\\Chrome\\User Data"},
                                                                       {L"Edge", L"Microsoft\\Edge\\User Data"},
                                                                       {L"Brave", L"BraveSoftware\\Brave-Browser\\User Data"}};
    static const std::set<std::wstring> broad_hosts = {L"<all_urls>", L"*://*/*", L"http://*/*", L"https://*/*"};
    static const std::set<std::wstring> sensitive = {L"cookies", L"webRequest", L"webRequestBlocking", L"history", L"nativeMessaging", L"debugger",
                                                     L"clipboardRead", L"management", L"proxy", L"declarativeNetRequest"};
    std::wstring base = local_app_data.empty() ? known_folder(0x1C) : local_app_data;
    std::vector<HuntFinding> findings;
    auto sorted_names = [](const std::wstring& folder) {
        std::vector<Entry> entries;
        list_dir(folder, entries);
        std::vector<Entry> dirs;
        for (auto& e : entries) {
            if (e.is_dir()) dirs.push_back(e);
        }
        std::sort(dirs.begin(), dirs.end(), [](const Entry& a, const Entry& b) { return a.name < b.name; });
        return dirs;
    };
    for (const auto& [browser, relative] : browsers) {
        std::wstring data = join(base, relative);
        if (!is_dir(data)) continue;
        for (const Entry& profile : sorted_names(data)) {
            std::wstring extensions = join(profile.path, L"Extensions");
            if (!is_dir(extensions) || !(profile.name == L"Default" || starts_with(profile.name, L"Profile "))) continue;
            for (const Entry& ext : sorted_names(extensions)) {
                auto versions = sorted_names(ext.path);
                if (versions.empty()) continue;
                std::wstring folder = versions.back().path;   // newest by name, like sorted(..., reverse=True)[0]
                Json manifest;
                if (!read_json_text(join(folder, L"manifest.json"), manifest).empty() || !manifest.is_object()) continue;
                std::set<std::wstring> permissions, hosts;
                for (const Json& p : manifest.get(L"permissions").is_array() ? manifest.get(L"permissions").items() : std::vector<Json>{}) {
                    if (p.is_string()) permissions.insert(p.str());
                }
                hosts = permissions;
                for (const Json& p : manifest.get(L"host_permissions").is_array() ? manifest.get(L"host_permissions").items() : std::vector<Json>{}) {
                    if (p.is_string()) hosts.insert(p.str());
                }
                if (manifest.get(L"content_scripts").is_array()) {
                    for (const Json& script : manifest.get(L"content_scripts").items()) {
                        if (!script.is_object()) continue;
                        for (const Json& m : script.get(L"matches").is_array() ? script.get(L"matches").items() : std::vector<Json>{}) {
                            if (m.is_string()) hosts.insert(m.str());
                        }
                    }
                }
                bool broad = false;
                for (const auto& h : hosts) broad |= broad_hosts.count(h) > 0;
                std::vector<std::wstring> risky;
                for (const auto& p : permissions) {
                    if (sensitive.count(p)) risky.push_back(p);
                }
                std::vector<std::wstring> flags;
                int severity = SEV_INFO;
                if (broad && !risky.empty()) {
                    std::wstring list;
                    for (std::size_t i = 0; i < risky.size(); ++i) list += (i ? L", " : L"") + risky[i];
                    flags.push_back(L"Reads every site and can use: " + list);
                    severity = SEV_LOOK;
                }
                std::wstring title = extension_name(folder, manifest);
                HuntFinding f;
                f.category = L"Browser extension";
                f.title = title.empty() ? ext.name : title;
                f.detail = std::wstring(browser) + L" (" + profile.name + L"), version " + (manifest.has(L"version") ? manifest.get(L"version").str() : L"?") + L", id " + ext.name;
                f.severity = severity;
                f.location = folder;
                f.flags = flags;
                findings.push_back(std::move(f));
            }
        }
    }
    return findings;
}

// endregion

std::vector<HuntFinding> collect_persistence(const Stop& stop, const Progress& progress, FileJudge* judge_in) {
    FileJudge own;
    FileJudge& judge = judge_in ? *judge_in : own;
    struct Step {
        const wchar_t* label;
        std::function<std::vector<HuntFinding>()> run;
    };
    std::vector<Step> steps = {{L"services", [&] { return check_services(read_services(), judge, stop); }},
                               {L"scheduled tasks", [&] { return check_tasks(judge, nullptr, stop); }},
                               {L"Windows settings", [&] { return check_hijacks(); }},
                               {L"WMI subscriptions", [&] { return check_wmi(); }},
                               {L"hosts file", [&] { return check_hosts(); }},
                               {L"proxy", [&] { return check_proxy(); }},
                               {L"browser extensions", [&] { return check_extensions(); }}};
    std::vector<HuntFinding> findings;
    for (const auto& step : steps) {
        if (stop()) break;
        if (progress) progress(std::wstring(L"Checking ") + step.label + L"...");
        for (auto& f : step.run()) findings.push_back(std::move(f));
    }
    std::stable_sort(findings.begin(), findings.end(), [](const HuntFinding& a, const HuntFinding& b) {
        if (a.severity != b.severity) return a.severity > b.severity;
        if (a.category != b.category) return a.category < b.category;
        return lower(a.title) < lower(b.title);
    });
    return findings;
}

// region Running processes

double sequence_ratio(const std::wstring& a, const std::wstring& b) {
    // difflib: the longest matching block first (earliest in a, then in b), then the same on both sides of it
    struct Block {
        std::size_t i, j, n;
    };
    auto longest = [&](std::size_t alo, std::size_t ahi, std::size_t blo, std::size_t bhi) {
        std::size_t best_i = alo, best_j = blo, best_size = 0;
        std::map<std::size_t, std::size_t> j2len;
        for (std::size_t i = alo; i < ahi; ++i) {
            std::map<std::size_t, std::size_t> next;
            for (std::size_t j = blo; j < bhi; ++j) {
                if (a[i] != b[j]) continue;
                std::size_t k = (j > blo && j2len.count(j - 1) ? j2len[j - 1] : 0) + 1;
                next[j] = k;
                if (k > best_size) {
                    best_i = i + 1 - k;
                    best_j = j + 1 - k;
                    best_size = k;
                }
            }
            j2len = std::move(next);
        }
        return Block{best_i, best_j, best_size};
    };
    std::vector<std::array<std::size_t, 4>> queue = {{0, a.size(), 0, b.size()}};
    std::size_t matches = 0;
    while (!queue.empty()) {
        auto [alo, ahi, blo, bhi] = queue.back();
        queue.pop_back();
        Block m = longest(alo, ahi, blo, bhi);
        if (!m.n) continue;
        matches += m.n;
        if (alo < m.i && blo < m.j) queue.push_back({alo, m.i, blo, m.j});
        if (m.i + m.n < ahi && m.j + m.n < bhi) queue.push_back({m.i + m.n, ahi, m.j + m.n, bhi});
    }
    std::size_t total = a.size() + b.size();
    return total ? 2.0 * (double)matches / (double)total : 1.0;
}

std::wstring lookalike(const std::wstring& name) {
    std::wstring low = lower(name);
    if (known_system_programs().count(low) || low.size() < 8) return L"";
    for (const auto& known : known_system_programs()) {
        if (known.size() >= 8 && sequence_ratio(low, known) >= 0.85) return known;
    }
    return L"";
}

ProcessFinding judge_process(int pid, const std::wstring& name, const std::wstring& path, int internet, FileJudge& judge) {
    ProcessFinding finding;
    finding.pid = pid;
    finding.name = name;
    finding.path = path;
    finding.connections = internet;
    auto& flags = finding.flags;
    int severity = SEV_INFO;
    std::wstring low = lower(name);
    if (path.empty()) {
        if (!no_path_ok().count(low) && pid > 4) flags.push_back(L"Program path hidden (protected or access denied)");
        finding.severity = SEV_INFO;
        return finding;
    }
    std::wstring folder = normcase(dir_name(path));
    std::set<std::wstring> expected = {normcase(system32()), normcase(join(system_root(), L"SysWOW64")), normcase(system_root())};
    if (known_system_programs().count(low) && !expected.count(folder)) {
        flags.push_back(L"Named like a Windows program but not in the Windows folder");
        severity = SEV_SUSPICIOUS;
    }
    std::wstring imitated = lookalike(name);
    if (!imitated.empty()) {
        flags.push_back(L"Name looks like " + imitated);
        severity = SEV_SUSPICIOUS;
    }
    if (!is_file(path)) {
        flags.push_back(L"Program file no longer exists on disk");
        severity = SEV_SUSPICIOUS;
    } else {
        std::wstring reason = risky_location(path);
        if (!reason.empty()) {
            flags.push_back(reason);
            severity = SEV_SUSPICIOUS;
        }
        finding.signer = judge.in_windows(path) ? L"" : judge.signer(path);
        if (judge.unsigned_file(path)) {
            flags.push_back(L"Not signed");
            severity = std::max(severity, SEV_LOOK);
            if (judge.packed(path)) {
                flags.push_back(L"High entropy (possibly packed)");
                severity = std::max(severity, SEV_LOOK);
            }
            if (internet) {
                flags.push_back(L"Unsigned and connected to the Internet (" + std::to_wstring(internet) + L")");
                severity = SEV_SUSPICIOUS;
            }
        }
    }
    finding.severity = severity;
    return finding;
}

std::vector<ProcessFinding> scan_processes(const Stop& stop, const Progress& progress, FileJudge* judge_in) {
    FileJudge own;
    FileJudge& judge = judge_in ? *judge_in : own;
    std::map<int, int> internet;
    for (const auto& c : list_connections()) {
        if (c.protocol == L"TCP" && c.state == L"Established" && remote_kind(c.remote_addr) == L"Internet") ++internet[c.pid];
    }
    std::vector<ProcessFinding> findings;
    auto processes = process_names();
    int index = 0;
    for (const auto& [pid, name] : processes) {
        ++index;
        if (stop()) break;
        if (pid == 0 || pid == 4) continue;
        if (progress && index % 20 == 0) progress(L"Checking processes... " + std::to_wstring(index) + L"/" + std::to_wstring(processes.size()));
        findings.push_back(judge_process(pid, name, process_path(pid), internet.count(pid) ? internet[pid] : 0, judge));
    }
    std::stable_sort(findings.begin(), findings.end(), [](const ProcessFinding& a, const ProcessFinding& b) {
        if (a.severity != b.severity) return a.severity > b.severity;
        std::wstring la = lower(a.name), lb = lower(b.name);
        return la != lb ? la < lb : a.pid < b.pid;
    });
    return findings;
}

std::vector<std::wstring> program_paths(const std::vector<HuntFinding>& persistence, const std::vector<ProcessFinding>& processes) {
    std::set<std::wstring> paths;
    for (const auto& p : processes) {
        if (!p.path.empty()) paths.insert(p.path);
    }
    for (const auto& f : persistence) {
        if (!f.path.empty()) paths.insert(f.path);
    }
    std::vector<std::wstring> out;
    for (const auto& p : paths) {
        if (is_file(p)) out.push_back(p);
    }
    std::sort(out.begin(), out.end(), [](const std::wstring& a, const std::wstring& b) { return lower(a) < lower(b); });
    return out;
}

// endregion

// region Removal

bool removable(const HuntFinding& f) { return f.removal.valid() && (f.removal.kind == L"task" || f.removal.kind == L"service" || f.removal.kind == L"regvalue"); }

std::wstring describe(const HuntFinding& f) {
    const auto& r = f.removal;
    if (r.kind == L"task") return L"Delete the scheduled task " + r.args[0] + L" (saved as an XML file first)";
    if (r.kind == L"service") return L"Delete the service " + r.args[0] + L" (its registry key is saved first)";
    if (r.kind == L"regvalue") return L"Delete the value " + (r.args[2].empty() ? L"(default)" : r.args[2]) + L" in " + r.args[0] + L"\\" + r.args[1] + L" (saved first)";
    return L"Cannot be removed from here";
}

static bool value_allowed(const std::wstring& key, const std::wstring& value) {
    std::wstring low = lower(key);
    std::wstring ifeo = lower(IFEO) + L"\\", policies = lower(POLICIES_RUN);
    if (starts_with(low, ifeo) || low == ifeo.substr(0, ifeo.size() - 1)) return lower(value) == L"debugger";
    if (starts_with(low, policies) || low == policies) return true;
    return false;
}

static int delete_service_with_sc(const std::wstring& name) {
    ProcOptions o;
    o.timeout_ms = 60000;
    ProcResult r = run_process({sys_exe(L"sc.exe"), L"delete", name}, o);
    return r.started ? r.code : -1;
}

HuntRemovalResult remove_findings(const std::vector<HuntFinding>& findings, const std::wstring& folder_in, const Stop& stop,
                                  const std::function<int(const std::wstring&)>& delete_service) {
    HuntRemovalResult result;
    std::wstring folder = folder_in.empty() ? data_subdir(L"hunt_backups") : folder_in;
    std::wstring stamp = timestamp();
    int index = 0;
    for (const HuntFinding& f : findings) {
        ++index;
        if (stop()) {
            result.failed.emplace_back(f, L"Stopped");
            continue;
        }
        if (!removable(f)) {
            result.failed.emplace_back(f, L"This entry cannot be removed from here");
            continue;
        }
        make_dirs(folder);
        wchar_t number[16];
        swprintf(number, 16, L"%02d", index);
        std::wstring prefix = join(folder, stamp + L"_" + number + L"_");
        std::wstring error;
        const auto& r = f.removal;
        if (r.kind == L"task") {
            std::wstring backup = prefix + L"task_" + safe_name(r.args[0]) + L".xml";
            error = export_and_remove_task(r.args[0], r.args.size() > 1 ? r.args[1] : L"\\", backup);
            if (is_file(backup)) result.backups.push_back(backup);
        } else if (r.kind == L"service") {
            const std::wstring& name = r.args[0];
            static const std::wregex valid(LR"([A-Za-z0-9_.@\- ]{1,256})");
            if (!std::regex_match(name, valid)) {
                error = L"Unusual service name: refused";
            } else if (!f.path.empty() && judge_in_windows(f.path)) {
                error = L"A service of Windows itself is never removed from here";
            } else {
                std::wstring backup = prefix + L"service_" + safe_name(name) + L".reg";
                std::wstring problem = export_key(L"HKLM", SERVICES_KEY + L"\\" + name, backup);
                if (!problem.empty()) {
                    error = L"Backup failed, nothing removed: " + problem;
                } else {
                    result.backups.push_back(backup);
                    int code = delete_service ? delete_service(name) : delete_service_with_sc(name);
                    if (code == 1072) result.reboot = true;   // ERROR_SERVICE_MARKED_FOR_DELETE
                    else if (code != 0 && code != 1060) error = L"sc delete failed (code " + std::to_wstring(code) + L"): run as administrator";
                }
            }
        } else {
            const std::wstring &hive = r.args[0], &key = r.args[1], &value = r.args[2];
            if ((hive != L"HKLM" && hive != L"HKCU") || !value_allowed(key, value)) {
                error = L"This registry value is not one that can be removed from here";
            } else if (RegKey::open(hive, key).valid()) {
                std::wstring tail = key.substr(key.find_last_of(L'\\') == std::wstring::npos ? 0 : key.find_last_of(L'\\') + 1);
                std::wstring backup = prefix + L"value_" + safe_name(tail) + L".reg";
                std::wstring problem = export_key(hive, key, backup);
                if (!problem.empty()) {
                    error = L"Backup failed, nothing removed: " + problem;
                } else {
                    result.backups.push_back(backup);
                    RegKey k = RegKey::open_write(hive, key);
                    LONG rc = k.valid() ? k.delete_value(value) : ERROR_ACCESS_DENIED;
                    if (rc == ERROR_ACCESS_DENIED) error = L"Access denied: run as administrator";
                    else if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND) error = L"Windows error " + std::to_wstring(rc);
                }
            }   // else: already gone
        }
        if (error.empty()) result.removed.push_back(f);
        else result.failed.emplace_back(f, error);
    }
    return result;
}

// endregion

}  // namespace dd
