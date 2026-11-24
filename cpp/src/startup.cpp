// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the startup entries: their severity, the shortcut target resolution and the inspection of Run keys.

#include <ddcore/startup.hpp>

#include <algorithm>
#include <set>

#include <windows.h>
#include <objbase.h>
#include <shlobj.h>

#include <ddcore/dead_registry.hpp>
#include <ddcore/inspect.hpp>
#include <ddcore/json.hpp>
#include <ddcore/proc.hpp>
#include <ddcore/registry.hpp>

namespace dd {

const wchar_t* FLAG_MISSING = L"File not found";
const wchar_t* FLAG_WRITABLE = L"Folder writable by standard users";
const wchar_t* FLAG_UNSIGNED = L"Not signed (or signed by catalog)";
const wchar_t* FLAG_PACKED = L"High entropy (possibly packed or encrypted)";

namespace {

const wchar_t* PATHEXT[] = {L".exe", L".com", L".bat", L".cmd"};   // what Windows tries for a name with none
const int CSIDL_USER_STARTUP_ID = 0x07, CSIDL_ALL_STARTUP_ID = 0x18;
const std::wstring VIEW32 = L" (32-bit)";
const std::wstring TASK_PREFIX = L"Task Scheduler ";

// path, or path+each of PATHEXT, whichever file exists first ("" if none does)
std::wstring with_pathext(const std::wstring& path) {
    if (is_file(path)) return path;
    if (!extension(path).empty()) return L"";   // an explicit (wrong) extension is not re-guessed
    for (const wchar_t* ext : PATHEXT) {
        if (is_file(path + ext)) return path + ext;
    }
    return L"";
}

std::wstring bare_name_location(const std::wstring& name) {
    for (const auto& folder : {system32(), system_root()}) {
        std::wstring found = with_pathext(join(folder, name));
        if (!found.empty()) return found;
    }
    return L"";
}

// A relative path is never resolved: it would be looked up in the current folder.
std::wstring existing_file(const std::wstring& candidate) {
    return is_absolute(candidate) ? with_pathext(candidate) : L"";
}

struct RunKey {
    const wchar_t *hive, *key, *scope;
    bool view32;
};
const RunKey RUN_KEYS[] = {
    {L"HKLM", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"All users", false},
    {L"HKLM", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"All users", false},
    {L"HKLM", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"All users", true},
    {L"HKCU", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"Current user", false},
    {L"HKCU", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"Current user", false},
};

const wchar_t* TASKS_PS =
    LR"(
$t = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' -and
    @($_.Triggers | Where-Object { $_.CimClass.CimClassName -in 'MSFT_TaskLogonTrigger', 'MSFT_TaskBootTrigger' }).Count -gt 0
} | ForEach-Object {
    $a = @($_.Actions)[0]
    [pscustomobject]@{ Name = $_.TaskName; Path = $_.TaskPath; Exec = [string]$a.Execute; Args = [string]$a.Arguments;
                       User = [string]$_.Principal.UserId; Level = $_.Principal.RunLevel.ToString() }
}
ConvertTo-Json -InputObject @($t) -Compress
)";

}  // namespace

int StartupEntry::severity() const {
    if (std::find(flags.begin(), flags.end(), FLAG_WRITABLE) != flags.end() || dangerous_content) return 2;
    return flags.empty() ? 0 : 1;
}

std::wstring command_path(const std::wstring& command_in) {
    std::wstring command = trim(expand_env(command_in));
    if (command.empty()) return L"";
    if (command[0] == L'"') {
        std::size_t end = command.find(L'"', 1);
        std::wstring candidate = end != std::wstring::npos ? command.substr(1, end - 1) : command.substr(1);
        std::wstring found = existing_file(candidate);
        if (!found.empty()) return found;
        return dir_name(candidate).empty() ? bare_name_location(candidate) : L"";
    }
    std::vector<std::wstring> tokens = split(command, L' ');
    for (std::size_t count = tokens.size(); count > 0; --count) {
        std::wstring candidate;
        for (std::size_t i = 0; i < count; ++i) candidate += (i ? L" " : L"") + tokens[i];
        std::wstring found = existing_file(candidate);
        if (!found.empty()) return found;
    }
    const std::wstring& first = tokens[0];
    return dir_name(first).empty() ? bare_name_location(first) : L"";
}

std::vector<StartupEntry> read_run_keys() {
    std::vector<StartupEntry> entries;
    for (const RunKey& rk : RUN_KEYS) {
        RegKey key = RegKey::open(rk.hive, rk.key, rk.view32);
        if (!key.valid()) continue;
        for (const RegValue& v : key.values()) {
            if (!v.is_text() || trim(v.text).empty()) continue;
            StartupEntry e;
            e.name = v.name.empty() ? L"(default)" : v.name;
            e.command = v.text;
            e.location = std::wstring(rk.hive) + L"\\" + rk.key + (rk.view32 ? VIEW32 : L"");
            e.kind = L"Registry";
            e.scope = rk.scope;
            entries.push_back(std::move(e));
        }
    }
    return entries;
}

std::vector<StartupEntry> read_startup_folders() {
    std::vector<StartupEntry> entries;
    const std::pair<const wchar_t*, int> folders[] = {{ALL_USERS, CSIDL_ALL_STARTUP_ID}, {CURRENT_USER, CSIDL_USER_STARTUP_ID}};
    for (const auto& [scope, csidl] : folders) {
        std::wstring folder = known_folder(csidl);
        std::vector<Entry> files;
        if (folder.empty() || !list_dir(folder, files)) continue;
        std::sort(files.begin(), files.end(), [](const Entry& a, const Entry& b) { return lower(a.name) < lower(b.name); });
        for (const Entry& f : files) {
            if (lower(f.name) == L"desktop.ini" || f.is_dir()) continue;
            StartupEntry e;
            e.name = f.name;
            e.command = f.path;
            e.location = folder;
            e.kind = L"Folder";
            e.scope = scope;
            e.path = f.path;
            entries.push_back(std::move(e));
        }
    }
    return entries;
}

std::vector<StartupEntry> read_logon_tasks() {
    std::vector<StartupEntry> entries;
    ProcOptions o;
    o.timeout_ms = 60000;
    ProcResult r = run_powershell(TASKS_PS, o);
    Json data;
    if (!r.ok() || trim(r.output).empty() || !try_parse_json(r.output, data)) return entries;
    for (const Json& t : data.as_list()) {
        std::wstring exec = t.get(L"Exec").str();
        if (!t.is_object() || exec.empty()) continue;
        std::wstring args = t.get(L"Args").str();
        std::wstring command = (exec.find(L' ') != std::wstring::npos && exec[0] != L'"') ? L"\"" + exec + L"\" " + args : exec + L" " + args;
        command = trim(command);
        std::wstring who = t.get(L"User").str();
        std::wstring highest = t.get(L"Level").str() == L"Highest" ? L" (highest privileges)" : L"";
        StartupEntry e;
        e.name = t.get(L"Name").str();
        e.command = command;
        e.location = TASK_PREFIX + t.get(L"Path").str();
        e.kind = L"Task";
        e.scope = (who.empty() ? L"task" : who) + highest;
        entries.push_back(std::move(e));
    }
    return entries;
}

// The target of a .lnk through the shell's own COM object.
static std::wstring shortcut_target(const std::wstring& link) {
    std::wstring target;
    HRESULT init = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    IShellLinkW* shell = nullptr;
    if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&shell))) {
        IPersistFile* file = nullptr;
        if (SUCCEEDED(shell->QueryInterface(IID_IPersistFile, (void**)&file))) {
            if (SUCCEEDED(file->Load(link.c_str(), STGM_READ))) {
                wchar_t path[MAX_PATH * 2] = {0};
                if (SUCCEEDED(shell->GetPath(path, MAX_PATH * 2, nullptr, SLGP_RAWPATH))) target = path;
            }
            file->Release();
        }
        shell->Release();
    }
    if (SUCCEEDED(init)) CoUninitialize();
    return target;
}

void resolve_shortcuts(std::vector<StartupEntry>& entries) {
    for (auto& e : entries) {
        if (e.kind != L"Folder" || extension(e.path) != L".lnk") continue;
        std::wstring target = shortcut_target(e.path);
        if (target.empty()) continue;
        e.command += L"  ->  " + target;
        e.path = is_file(target) ? target : L"";
    }
}

void inspect_entry(StartupEntry& entry) {
    if (entry.kind != L"Folder" || entry.path.empty()) {
        if (entry.kind != L"Folder") entry.path = command_path(entry.command);
    }
    entry.exists = !entry.path.empty() && is_file(entry.path);
    entry.flags.clear();
    if (!entry.exists) {
        entry.flags.push_back(FLAG_MISSING);
        return;
    }
    std::wstring ext = extension(entry.path);
    if (ext == L".exe" || ext == L".dll" || ext == L".scr" || ext == L".com" || ext == L".sys") {
        PEInfo info = inspect_pe(entry.path);
        entry.signer = info.signer;
        bool in_windows = starts_with(normcase(entry.path), normcase(system_root()) + L"\\");
        if (info.signer.empty() && info.error.empty() && !in_windows) entry.flags.push_back(FLAG_UNSIGNED);   // Windows files are signed by catalog
    }
    FileInspection inspection = inspect(entry.path);
    if (!inspection.mismatch.empty()) {
        entry.flags.push_back(inspection.mismatch);
        entry.true_type = inspection.true_type;
        entry.dangerous_content = inspection.dangerous;
    }
    if (inspection.packed) entry.flags.push_back(FLAG_PACKED);
    // what runs for everybody (or with the highest privileges) must not be replaceable by a standard user
    if (entry.scope == ALL_USERS || lower(entry.scope).find(L"highest") != std::wstring::npos) {
        bool ok = true;
        auto writers = unprivileged_writers(dir_name(entry.path), &ok);
        if (ok && !writers.empty()) entry.flags.push_back(FLAG_WRITABLE);
    }
}

std::vector<StartupEntry> collect_startup(const Stop& stop,
                                          const std::function<void(std::size_t, std::size_t, const std::wstring&)>& progress) {
    std::vector<StartupEntry> entries = read_run_keys();
    for (auto& e : read_startup_folders()) entries.push_back(std::move(e));
    for (auto& e : read_logon_tasks()) entries.push_back(std::move(e));
    resolve_shortcuts(entries);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        if (stop()) break;
        if (progress) progress(i + 1, entries.size(), entries[i].name);
        inspect_entry(entries[i]);
    }
    return entries;
}

// region Removal

static const wchar_t* TASK_SCRIPT_TEXT = LR"(
$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__')) | ConvertFrom-Json
try {
    $xml = Export-ScheduledTask -TaskName $p.name -TaskPath $p.path -ErrorAction Stop
    [IO.File]::WriteAllText($p.file, $xml, [Text.Encoding]::Unicode)
    Unregister-ScheduledTask -TaskName $p.name -TaskPath $p.path -Confirm:$false -ErrorAction Stop
    ConvertTo-Json -Compress -InputObject @{ ok = $true; error = '' }
} catch {
    ConvertTo-Json -Compress -InputObject @{ ok = $false; error = [string]$_.Exception.Message }
}
)";

static std::string base64_text(const std::string& in) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (std::size_t i = 0; i < in.size(); i += 3) {
        unsigned v = (unsigned char)in[i] << 16 | (i + 1 < in.size() ? (unsigned char)in[i + 1] << 8 : 0) |
                     (i + 2 < in.size() ? (unsigned char)in[i + 2] : 0);
        out += tbl[(v >> 18) & 63];
        out += tbl[(v >> 12) & 63];
        out += i + 1 < in.size() ? tbl[(v >> 6) & 63] : '=';
        out += i + 2 < in.size() ? tbl[v & 63] : '=';
    }
    return out;
}

std::wstring export_and_remove_task(const std::wstring& name, const std::wstring& task_path, const std::wstring& backup) {
    Json payload = Json::object();
    payload.set(L"name", Json::string(name));
    payload.set(L"path", Json::string(task_path.empty() ? L"\\" : task_path));
    payload.set(L"file", Json::string(backup));
    std::wstring script = TASK_SCRIPT_TEXT;
    script.replace(script.find(L"__PAYLOAD__"), 11, wide(base64_text(utf8(payload.dump()))));
    ProcOptions o;
    o.timeout_ms = 60000;
    ProcResult r = run_powershell(script, o);
    Json answer;
    if (!r.started || !try_parse_json(r.output, answer) || !answer.is_object()) {
        return L"The task could not be removed (administrator rights are needed)";
    }
    if (!answer.get(L"ok").flag()) {
        std::wstring error = trim(answer.get(L"error").str());
        return error.empty() ? L"The task could not be removed" : error;
    }
    if (!is_file(backup)) return L"The task was removed but its backup file was not written";
    return L"";
}

namespace {

struct Removal {
    enum Kind { None, RegValue, File, Task } kind = None;
    std::wstring a, b, c;   // regvalue: hive, key, value name; file: path; task: name, task path
};

Removal removal_target(const StartupEntry& e) {
    Removal t;
    if (e.kind == L"Registry") {
        bool view32 = ends_with(e.location, VIEW32);
        std::wstring loc = view32 ? e.location.substr(0, e.location.size() - VIEW32.size()) : e.location;
        std::size_t slash = loc.find(L'\\');
        if (slash == std::wstring::npos) return t;
        std::wstring hive = loc.substr(0, slash), key = loc.substr(slash + 1);
        bool known = false;
        for (const RunKey& rk : RUN_KEYS) {
            if (hive == rk.hive && lower(key) == lower(rk.key) && rk.view32 == view32) known = true;
        }
        if (!known) return t;
        if (view32) key = L"SOFTWARE\\WOW6432Node\\" + key.substr(9);   // the 32-bit view of HKLM\SOFTWARE
        t.kind = Removal::RegValue;
        t.a = hive;
        t.b = key;
        t.c = e.name == L"(default)" ? L"" : e.name;
    } else if (e.kind == L"Folder" && !e.location.empty() && e.name == base_name(e.name)) {
        t.kind = Removal::File;
        t.a = join(e.location, e.name);
    } else if (e.kind == L"Task" && starts_with(e.location, TASK_PREFIX) && !e.name.empty()) {
        t.kind = Removal::Task;
        t.a = e.name;
        t.b = e.location.substr(TASK_PREFIX.size());
        if (t.b.empty()) t.b = L"\\";
    }
    return t;
}

std::wstring remove_task(const Removal& t, const std::wstring& backup, StartupRemoval& result) {
    std::wstring error = export_and_remove_task(t.a, t.b, backup);
    if (is_file(backup)) result.backups.push_back(backup);
    return error;
}

std::wstring remove_value(const Removal& t, const std::wstring& backup, StartupRemoval& result) {
    if (!RegKey::open(t.a, t.b).valid()) return L"";   // the key is already gone
    std::wstring ignored;
    bool present = false;
    for (const RegValue& v : RegKey::open(t.a, t.b).values()) {
        if (v.name == t.c) present = true;
    }
    if (!present) return L"";   // the value is already gone
    std::wstring problem = export_key(t.a, t.b, backup);
    if (!problem.empty()) return L"Backup failed, nothing removed: " + problem;
    result.backups.push_back(backup);
    RegKey key = RegKey::open_write(t.a, t.b);
    LONG rc = key.valid() ? key.delete_value(t.c) : ERROR_ACCESS_DENIED;
    if (rc == ERROR_ACCESS_DENIED) return L"Access denied: run as administrator";
    return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND ? L"" : L"Windows error " + std::to_wstring(rc);
}

std::wstring remove_file(const std::wstring& path, const std::wstring& backup, StartupRemoval& result) {
    std::set<std::wstring> allowed;
    for (int csidl : {CSIDL_ALL_STARTUP_ID, CSIDL_USER_STARTUP_ID}) {
        std::wstring f = known_folder(csidl);
        if (!f.empty()) allowed.insert(normcase(f));
    }
    if (!allowed.count(normcase(dir_name(path)))) return L"This file is not in a Startup folder: refused";
    if (!lexists(path)) return L"";   // already gone
    Entry info;
    if (!stat_path(path, info) || info.is_link() || info.is_dir()) return L"Not a regular file: refused";
    if (!move_file(path, backup)) return GetLastError() == ERROR_ACCESS_DENIED ? L"Access denied: run as administrator" : L"The file could not be moved";
    result.backups.push_back(backup);   // the backup and the removal at once: moving it back restores the entry
    return L"";
}

}  // namespace

bool removable(const StartupEntry& e) { return removal_target(e).kind != Removal::None; }

bool needs_admin(const StartupEntry& e) {
    Removal t = removal_target(e);
    if (t.kind == Removal::None) return false;
    if (t.kind == Removal::RegValue) return t.a == L"HKLM";
    if (t.kind == Removal::File) return e.scope == ALL_USERS;
    return true;
}

std::wstring describe(const StartupEntry& e) {
    Removal t = removal_target(e);
    switch (t.kind) {
        case Removal::RegValue:
            return L"Delete the value " + (t.c.empty() ? L"(default)" : t.c) + L" in " + t.a + L"\\" + t.b + L" (the key is saved first)";
        case Removal::File: return L"Move " + t.a + L" to the backups folder";
        case Removal::Task: return L"Delete the scheduled task " + t.b + t.a + L" (saved as an XML file first)";
        default: return L"Cannot be removed from here";
    }
}

StartupRemoval remove_entries(const std::vector<StartupEntry>& entries, const std::wstring& folder_in, const Stop& stop) {
    StartupRemoval result;
    std::wstring folder = folder_in.empty() ? data_subdir(L"startup_backups") : folder_in;
    std::wstring stamp = timestamp();
    int index = 0;
    for (const StartupEntry& e : entries) {
        ++index;
        if (stop()) {
            result.failed.emplace_back(e, L"Stopped");
            continue;
        }
        Removal t = removal_target(e);
        if (t.kind == Removal::None) {
            result.failed.emplace_back(e, L"This entry cannot be removed from here");
            continue;
        }
        make_dirs(folder);
        wchar_t number[16];
        swprintf(number, 16, L"%02d", index);
        std::wstring prefix = join(folder, stamp + L"_" + number + L"_");
        std::wstring error;
        if (t.kind == Removal::RegValue) error = remove_value(t, prefix + L"value_" + safe_name(e.name) + L".reg", result);
        else if (t.kind == Removal::File) error = remove_file(t.a, prefix + base_name(t.a), result);
        else error = remove_task(t, prefix + L"task_" + safe_name(e.name) + L".xml", result);
        if (error.empty()) result.removed.push_back(e);
        else result.failed.emplace_back(e, error);
    }
    return result;
}

// endregion

}  // namespace dd
