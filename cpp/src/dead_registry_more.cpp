// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements more registry presets, the wildcard search and the deletion of registry entries with backups first.

#include <ddcore/dead_registry.hpp>

#include <algorithm>
#include <cwchar>
#include <map>
#include <regex>

#include <ddcore/garbage.hpp>
#include <ddcore/proc.hpp>
#include <ddcore/registry.hpp>

namespace dd {

std::wstring RegEntry::display_name() const {
    if (is_key) return base_name(key);
    return value.empty() ? L"(default)" : value;
}

namespace {

const std::wstring STARTUP_APPROVED = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved";
const double OLD_VENDOR_DAYS = 180;

bool is_guid_name(const std::wstring& name) {
    static const std::wregex guid(LR"(^\{?[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\}?$)", std::regex::icase);
    return std::regex_match(name, guid);
}

// (existing, missing) program paths found in the string values of a key and its sub-keys (shallow)
std::pair<int, int> paths_inside(const std::wstring& hive, const std::wstring& path, int depth, int& budget) {
    RegKey key = RegKey::open(hive, path);
    if (!key.valid()) return {0, 0};
    std::vector<RegValue> values = key.values();
    std::vector<std::wstring> children = depth < 2 ? key.subkeys() : std::vector<std::wstring>{};
    int ok = 0, missing = 0;
    static const std::wregex drive_path(LR"(^"?[A-Za-z]:\\)");
    for (const RegValue& v : values) {
        if (budget <= 0) break;
        if (!v.is_text() || !std::regex_search(trim(v.text), drive_path)) continue;
        --budget;
        TargetState st = check_target(v.text, ends_with(trim(v.text), L"\\")).state;
        ok += st == TargetState::Ok;
        missing += st == TargetState::Missing;
    }
    for (const auto& child : children) {
        if (budget <= 0) break;
        auto [a, b] = paths_inside(hive, path + L"\\" + child, depth + 1, budget);
        ok += a;
        missing += b;
    }
    return {ok, missing};
}

void sort_entries(std::vector<RegEntry>& entries) {
    std::stable_sort(entries.begin(), entries.end(), [](const RegEntry& a, const RegEntry& b) {
        if (a.category != b.category) return a.category < b.category;
        std::wstring la = lower(a.location()), lb = lower(b.location());
        return la != lb ? la < lb : lower(a.value) < lower(b.value);
    });
}

}  // namespace

// region Presets

std::vector<RegEntry> usage_history() {
    static const std::pair<const wchar_t*, const wchar_t*> keys[] = {
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", L"Run box history"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", L"Explorer address bar history"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", L"Recent documents"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery", L"Explorer search history"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU", L"Open and Save dialog history"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU", L"Last folders used by programs"},
        {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist", L"Program launch counters"},
        {L"SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLs", L"Typed web addresses"}};
    std::vector<RegEntry> found;
    for (const auto& [path, label] : keys) {
        RegKey key = RegKey::open(L"HKCU", path);
        if (!key.valid()) continue;
        std::size_t subkeys = key.subkeys().size(), values = key.values().size();
        if (subkeys || values) {
            found.push_back({L"HKCU", path, L"", true, L"Usage history", std::wstring(label) + L": Windows recreates it when needed",
                             std::to_wstring(values) + L" value(s), " + std::to_wstring(subkeys) + L" sub-key(s)", L"High"});
        }
    }
    return found;
}

std::vector<RegEntry> orphan_startup_toggles() {
    const std::wstring run64 = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    const std::wstring run32 = L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run";
    std::map<std::wstring, std::wstring> folders = {{L"HKLM", known_folder(0x18)}, {L"HKCU", known_folder(0x07)}};
    std::vector<RegEntry> found;
    for (const wchar_t* hive : {L"HKCU", L"HKLM"}) {
        for (const wchar_t* sub : {L"Run", L"Run32", L"StartupFolder"}) {
            std::wstring path = STARTUP_APPROVED + L"\\" + sub;
            RegKey toggles = RegKey::open(hive, path);
            if (!toggles.valid()) continue;
            std::vector<std::wstring> names;
            for (const auto& v : toggles.values()) names.push_back(v.name);
            std::set<std::wstring> existing;
            if (!wcscmp(sub, L"StartupFolder")) {
                std::vector<Entry> files;
                const std::wstring& folder = folders[hive];
                if (folder.empty() || !list_dir(folder, files)) continue;
                for (const auto& f : files) existing.insert(lower(f.name));
            } else {
                RegKey run = RegKey::open(hive, !wcscmp(sub, L"Run") ? run64 : run32);
                for (const auto& v : run.values()) existing.insert(lower(v.name));
            }
            for (const auto& name : names) {
                if (!existing.count(lower(name))) {
                    found.push_back({hive, path, name, false, L"Orphan startup toggle",
                                     L"No startup entry of this name exists any more", L"", L"High"});
                }
            }
        }
    }
    return found;
}

std::vector<RegEntry> dead_com_registrations(const Stop& stop, std::size_t limit) {
    const std::pair<const wchar_t*, const wchar_t*> roots[] = {{L"HKLM", L"SOFTWARE\\Classes\\CLSID"},
                                                              {L"HKLM", L"SOFTWARE\\WOW6432Node\\Classes\\CLSID"},
                                                              {L"HKCU", L"SOFTWARE\\Classes\\CLSID"}};
    std::vector<RegEntry> found;
    for (const auto& [hive, base] : roots) {
        RegKey root = RegKey::open(hive, base);
        if (!root.valid()) continue;
        for (const auto& guid : root.subkeys()) {
            if (stop() || found.size() >= limit) return found;
            std::vector<Target> states;
            for (const wchar_t* server : {L"InprocServer32", L"LocalServer32"}) {
                RegKey key = RegKey::open(hive, std::wstring(base) + L"\\" + guid + L"\\" + server);
                if (!key.valid()) continue;
                std::wstring def;
                key.get_text(L"", def);
                states.push_back(trim(def).empty() ? Target{L"", TargetState::Unknown} : check_target(trim(def)));
            }
            bool all_missing = !states.empty() && std::all_of(states.begin(), states.end(), [](const Target& t) {
                return t.state == TargetState::Missing;
            });
            if (all_missing) {
                found.push_back({hive, std::wstring(base) + L"\\" + guid, L"", true, L"COM registration",
                                 L"Registered file not found: " + states[0].path, guid, L"Medium"});
            }
        }
    }
    return found;
}

std::vector<RegEntry> orphan_vendor_keys(const std::set<std::wstring>& markers, const Stop& stop, double now_in, std::size_t limit) {
    static const std::set<std::wstring> skip = {L"classes", L"policies", L"wow6432node", L"clients", L"registeredapplications",
                                                L"odbc", L"partner", L"setup", L"appdatalow", L"cryptography", L"mozillaplugins",
                                                L"dolby", L"intel", L"nvidia corporation", L"realtek", L"amd", L"asus", L"khronos",
                                                L"vulkankhr", L"oem", L"defaultuserenvironment"};
    const std::pair<const wchar_t*, const wchar_t*> roots[] = {{L"HKCU", L"SOFTWARE"}, {L"HKLM", L"SOFTWARE"},
                                                              {L"HKLM", L"SOFTWARE\\WOW6432Node"}};
    double now = now_in < 0 ? now_seconds() : now_in;
    std::vector<RegEntry> found;
    for (const auto& [hive, base] : roots) {
        RegKey root = RegKey::open(hive, base);
        if (!root.valid()) continue;
        for (const auto& name : root.subkeys()) {
            if (stop() || found.size() >= limit) return found;
            std::wstring low = lower(name), norm = norm_key(name);
            if (skip.count(low) || is_guid_name(name) || starts_with(norm, L"microsoft") || starts_with(norm, L"windows") ||
                is_covered(name, markers))
                continue;
            std::wstring path = std::wstring(base) + L"\\" + name;
            RegKey key = RegKey::open(hive, path);
            if (!key.valid()) continue;
            double age_days = (now - key.last_write()) / 86400;
            int budget = 300;
            auto [ok, missing] = paths_inside(hive, path, 0, budget);
            if (ok) continue;   // it names a file that is still there: in use
            if (missing) {
                found.push_back({hive, path, L"", true, L"Leftover of an old program",
                                 L"No installed program matches; the " + std::to_wstring(missing) + L" file(s) it names are gone",
                                 name, L"High"});
            } else if (age_days >= OLD_VENDOR_DAYS) {
                found.push_back({hive, path, L"", true, L"Leftover of an old program",
                                 L"No installed program matches; untouched for " + std::to_wstring((int)age_days) + L" days", name,
                                 L"Medium"});
            }
        }
    }
    return found;
}

const std::vector<RegPreset>& reg_presets() {
    static const std::vector<RegPreset> presets = {
        {L"uninstall", L"Dead uninstall entries",
         L"Programs listed in Add/Remove Programs whose files, uninstaller and icon are gone.", L"Safe",
         [](const Stop&) { return dead_uninstall_entries(); }},
        {L"app_paths", L"Dead App Paths", L"Shortcuts to programs (Run box, Start) whose program is gone.", L"Safe",
         [](const Stop&) { return dead_app_paths(); }},
        {L"startup", L"Dead startup entries", L"Run keys that start a program which no longer exists.", L"Safe",
         [](const Stop&) { return dead_startup_entries(); }},
        {L"traces", L"Cached traces of removed programs",
         L"Program name cache, compatibility flags and shared-DLL counters of files that are gone.", L"Safe",
         [](const Stop&) { return dead_cached_traces(); }},
        {L"approved", L"Orphan startup toggles",
         L"On/off switches of Task Manager's Startup tab for entries that no longer exist.", L"Safe",
         [](const Stop&) { return orphan_startup_toggles(); }},
        {L"history", L"Usage history lists",
         L"Recent documents, Run box, Explorer address bar and searches, Open/Save dialogs, launch counters. Windows recreates them.",
         L"Safe", [](const Stop&) { return usage_history(); }},
        {L"com", L"COM registrations with a missing file",
         L"Classes registered by programs that were removed. Thousands can pile up; deleting a live one breaks that program, so check the file path.",
         L"Check", [](const Stop& stop) { return dead_com_registrations(stop); }},
        {L"vendors", L"Leftovers of old programs",
         L"Vendor keys (HKCU/HKLM SOFTWARE) that no installed program claims. Portable tools you copied yourself look the same: read each line.",
         L"Review", [](const Stop& stop) { return orphan_vendor_keys(installed_markers(), stop); }},
    };
    return presets;
}

RegScan scan_presets(const std::vector<std::wstring>& ids, const Stop& stop, const Progress& progress) {
    RegScan scan;
    for (const auto& preset : reg_presets()) {
        if (std::find(ids.begin(), ids.end(), preset.id) == ids.end()) continue;
        if (stop()) break;
        if (progress) progress(L"Checking: " + preset.label + L"...");
        for (auto& e : preset.run(stop)) scan.entries.push_back(std::move(e));
    }
    sort_entries(scan.entries);
    return scan;
}

// endregion

// region Wildcard search

RegScan search_registry(const std::wstring& patterns, bool names, bool value_names, bool value_data, const Stop& stop,
                        const Progress& progress, std::size_t limit) {
    Matcher match(patterns);
    RegScan scan;
    struct Node {
        std::wstring hive, path;
        int depth;
    };
    std::vector<Node> stack = {{L"HKLM", L"SOFTWARE", 0}, {L"HKCU", L"SOFTWARE", 0}};
    while (!stack.empty() && !stop()) {
        Node node = stack.back();
        stack.pop_back();
        RegKey key = RegKey::open(node.hive, node.path);
        if (!key.valid()) continue;
        ++scan.keys_seen;
        if (progress && scan.keys_seen % 2000 == 0) {
            progress(L"Searching the registry... " + std::to_wstring(scan.keys_seen) + L" keys looked at, " +
                     std::to_wstring(scan.entries.size()) + L" found");
        }
        std::vector<std::wstring> children = key.subkeys();
        std::vector<RegValue> values;
        if (value_names || value_data) values = key.values();
        for (const RegValue& v : values) {
            std::wstring shown = v.shown.substr(0, 200);
            if (value_names && match(v.name, node.hive + L"\\" + node.path + L"\\" + v.name)) {
                scan.entries.push_back({node.hive, node.path, v.name, false, L"Value name", L"Value name matches", shown});
            } else if (value_data && !v.shown.empty() && match(v.shown, v.shown)) {
                scan.entries.push_back({node.hive, node.path, v.name, false, L"Value data", L"Value data matches", shown});
            }
        }
        std::vector<Node> subfolders;
        for (const auto& child : children) {
            std::wstring child_path = node.path + L"\\" + child;
            if (names && match(child, node.hive + L"\\" + child_path)) {
                scan.entries.push_back({node.hive, child_path, L"", true, L"Key name", L"Key name matches", L""});
            } else if (node.depth < 64) {
                subfolders.push_back({node.hive, child_path, node.depth + 1});
            }
        }
        stack.insert(stack.end(), subfolders.rbegin(), subfolders.rend());
        if (scan.entries.size() >= limit) {
            scan.truncated = true;
            scan.entries.resize(limit);
            break;
        }
    }
    return scan;
}

// endregion

// region Deleting

namespace {

std::wstring normal_key(std::wstring path) {
    path = lower(path);
    if (starts_with(path, L"software\\wow6432node\\")) path = L"software\\" + path.substr(21);
    while (!path.empty() && path.back() == L'\\') path.pop_back();
    return path;
}

const std::set<std::wstring>& protected_keys() {
    static const std::set<std::wstring> keys = {
        L"software", L"software\\classes", L"software\\classes\\clsid", L"software\\classes\\interface",
        L"software\\classes\\typelib", L"software\\classes\\appid", L"software\\clients", L"software\\microsoft",
        L"software\\microsoft\\windows", L"software\\microsoft\\windows\\currentversion",
        L"software\\microsoft\\windows\\currentversion\\run", L"software\\microsoft\\windows\\currentversion\\runonce",
        L"software\\microsoft\\windows\\currentversion\\uninstall", L"software\\microsoft\\windows\\currentversion\\app paths",
        L"software\\microsoft\\windows\\currentversion\\explorer", L"software\\microsoft\\windows nt",
        L"software\\microsoft\\windows nt\\currentversion", L"software\\policies", L"software\\registeredapplications"};
    return keys;
}

const std::vector<std::wstring>& blocked_prefixes() {
    static const std::vector<std::wstring> prefixes = {
        L"software\\microsoft\\windows nt\\currentversion\\winlogon", L"software\\microsoft\\windows nt\\currentversion\\svchost",
        L"software\\microsoft\\windows nt\\currentversion\\profilelist",
        L"software\\microsoft\\windows nt\\currentversion\\image file execution options",
        L"software\\microsoft\\cryptography", L"software\\microsoft\\windows\\currentversion\\policies",
        L"software\\microsoft\\windows\\currentversion\\component based servicing", L"software\\microsoft\\windows defender",
        L"software\\microsoft\\security center", L"software\\policies"};
    return prefixes;
}

}  // namespace

std::wstring registry_protected_reason(const RegEntry& e) {
    if (e.hive != L"HKLM" && e.hive != L"HKCU") return L"Unknown registry hive";
    std::wstring key = normal_key(e.key);
    if (key != L"software" && !starts_with(key, L"software\\")) return L"Only keys under SOFTWARE can be deleted here";
    for (const auto& p : blocked_prefixes()) {
        if (key == p || starts_with(key, p + L"\\")) return L"Security or system area";
    }
    if (e.is_key) {
        std::size_t depth = (std::size_t)std::count(key.begin(), key.end(), L'\\');
        if (protected_keys().count(key) || depth < 1 || ends_with(key, L"\\wow6432node")) return L"Core Windows key";
    }
    return L"";
}

std::wstring export_key(const std::wstring& hive, const std::wstring& path, const std::wstring& file) {
    ProcOptions o;
    o.timeout_ms = 120000;
    ProcResult r = run_process({sys_exe(L"reg.exe"), L"export", hive + L"\\" + path, file, L"/y", L"/reg:64"}, o);
    if (!r.started) return L"reg.exe could not be started";
    if (r.code != 0) {
        std::wstring text = trim(r.output);
        return text.empty() ? L"reg export failed" : text.substr(0, 200);
    }
    return L"";
}

RegDeleteResult delete_entries(const std::vector<RegEntry>& entries, const std::wstring& folder_in, const Stop& stop) {
    RegDeleteResult result;
    std::wstring folder = folder_in.empty() ? data_subdir(L"garbage_backups") : folder_in;
    std::wstring stamp = timestamp();
    std::map<std::wstring, std::wstring> backed_up;   // hive\key -> "" or error
    for (const RegEntry& e : entries) {
        if (stop()) {
            result.failed.emplace_back(e, L"Stopped");
            continue;
        }
        std::wstring reason = registry_protected_reason(e);
        if (!reason.empty()) {
            result.failed.emplace_back(e, reason);
            continue;
        }
        if (!RegKey::open(e.hive, e.key).valid()) {
            result.deleted.push_back(e);   // already gone
            continue;
        }
        std::wstring slot = e.hive + L"\\" + lower(e.key);
        if (!backed_up.count(slot)) {
            make_dirs(folder);
            wchar_t number[16];
            swprintf(number, 16, L"%03zu", backed_up.size() + 1);
            std::wstring file = join(folder, stamp + L"_" + number + L"_" + e.hive + L"_" + safe_name(e.key) + L".reg");
            backed_up[slot] = export_key(e.hive, e.key, file);
            if (backed_up[slot].empty()) result.backups.push_back(file);
        }
        if (!backed_up[slot].empty()) {
            result.failed.emplace_back(e, L"Backup failed, nothing deleted: " + backed_up[slot]);
            continue;
        }
        LONG rc;
        if (e.is_key) {
            rc = RegKey::delete_tree(e.hive, e.key);
        } else {
            RegKey key = RegKey::open_write(e.hive, e.key);
            rc = key.valid() ? key.delete_value(e.value) : ERROR_ACCESS_DENIED;
            if (rc == ERROR_FILE_NOT_FOUND) rc = ERROR_SUCCESS;   // removed meanwhile
        }
        if (rc == ERROR_ACCESS_DENIED) {
            result.failed.emplace_back(e, e.hive == L"HKLM" ? L"Access denied: run as administrator" : L"Access denied");
            continue;
        }
        if (rc != ERROR_SUCCESS) {
            result.failed.emplace_back(e, L"Windows error " + std::to_wstring(rc));
            continue;
        }
        result.deleted.push_back(e);
    }
    return result;
}

// endregion

}  // namespace dd
