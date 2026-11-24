// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the search for registry entries of missing programs: dead values, run paths and their base keys.

#include <ddcore/dead_registry.hpp>

#include <algorithm>
#include <functional>
#include <regex>

#include <ddcore/registry.hpp>
#include <ddcore/startup.hpp>

namespace dd {

namespace {

const std::wstring CURRENT = L"Microsoft\\Windows\\CurrentVersion";

struct Base {
    const wchar_t* hive;
    std::wstring path;
};

std::vector<Base> uninstall_paths() {
    return {{L"HKLM", L"SOFTWARE\\" + CURRENT + L"\\Uninstall"},
            {L"HKLM", L"SOFTWARE\\WOW6432Node\\" + CURRENT + L"\\Uninstall"},
            {L"HKCU", L"SOFTWARE\\" + CURRENT + L"\\Uninstall"}};
}

std::vector<Base> app_paths() {
    return {{L"HKLM", L"SOFTWARE\\" + CURRENT + L"\\App Paths"},
            {L"HKLM", L"SOFTWARE\\WOW6432Node\\" + CURRENT + L"\\App Paths"},
            {L"HKCU", L"SOFTWARE\\" + CURRENT + L"\\App Paths"}};
}

struct RunPath {
    const wchar_t* hive;
    const wchar_t* path;
};
const RunPath RUN_PATHS[] = {
    {L"HKLM", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
    {L"HKLM", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
    {L"HKLM", L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"},
    {L"HKCU", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
    {L"HKCU", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
};

using Values = std::vector<std::pair<std::wstring, std::wstring>>;

Values text_values(const RegKey& key) {
    Values out;
    for (const RegValue& v : key.values()) {
        if (v.is_text()) out.emplace_back(v.name, v.text);
    }
    return out;
}

std::wstring find(const Values& values, const std::wstring& name) {
    for (const auto& [n, v] : values) {
        if (n == name) return v;
    }
    return L"";
}

// "C:\x\app.exe,0" -> "C:\x\app.exe"
std::wstring strip_icon_index(const std::wstring& text) {
    static const std::wregex index(LR"(,\s*-?\d+$)");
    return std::regex_replace(trim(text), index, L"");
}

bool judgeable(const std::wstring& path) {
    if (path.empty() || !is_absolute(path) || starts_with(path, L"\\\\")) return false;
    return is_dir(path.substr(0, 2) + L"\\");   // an unplugged disk proves nothing
}

}  // namespace

Target check_target(const std::wstring& command_in, bool is_folder) {
    std::wstring command = trim(expand_env(command_in));
    if (command.empty()) return {L"", TargetState::Unknown};
    std::wstring candidate;
    if (is_folder) {
        candidate = strip_quotes(command);
    } else if (command[0] == L'"') {
        std::size_t end = command.find(L'"', 1);
        candidate = end != std::wstring::npos ? command.substr(1, end - 1) : command.substr(1);
    } else {
        std::wstring found = command_path(command);
        if (!found.empty()) {
            candidate = found;
        } else {
            static const std::wregex program(LR"(^([A-Za-z]:\\.*?\.(?:exe|bat|cmd|com|msi|ico|dll|lnk|cpl|scr))(?=[\s,"]|$))",
                                             std::regex::icase);
            std::wsmatch m;
            if (std::regex_search(command, m, program)) candidate = m[1];
        }
    }
    candidate = trim(candidate);
    if (candidate.empty() || !judgeable(candidate)) return {candidate, TargetState::Unknown};
    std::wstring windows = normcase(system_root()) + L"\\";
    if (starts_with(normcase(candidate), windows)) return {candidate, TargetState::Unknown};
    bool present = is_folder ? is_dir(candidate) : (exists(candidate) || !command_path(candidate).empty());
    return {candidate, present ? TargetState::Ok : TargetState::Missing};
}

std::vector<RegEntry> dead_uninstall_entries() {
    std::vector<RegEntry> found;
    for (const auto& base : uninstall_paths()) {
        RegKey root = RegKey::open(base.hive, base.path);
        if (!root.valid()) continue;
        for (const auto& sub : root.subkeys()) {
            RegKey key = RegKey::open(base.hive, base.path + L"\\" + sub);
            if (!key.valid()) continue;
            Values values = text_values(key);
            std::wstring title = trim(find(values, L"DisplayName"));
            if (title.empty()) continue;
            std::vector<Target> judged;
            auto consider = [&](const Target& t) {
                if (t.state != TargetState::Unknown) judged.push_back(t);
            };
            if (!trim(find(values, L"InstallLocation")).empty()) consider(check_target(find(values, L"InstallLocation"), true));
            for (const wchar_t* name : {L"UninstallString", L"QuietUninstallString"}) {
                if (!trim(find(values, name)).empty()) consider(check_target(find(values, name)));
            }
            // a missing icon alone proves nothing: it only counts next to a missing folder or uninstaller
            std::wstring icon = strip_icon_index(find(values, L"DisplayIcon"));
            Target icon_check = icon.empty() ? Target{L"", TargetState::Unknown} : check_target(icon);
            if (!judged.empty() && icon_check.state != TargetState::Unknown) judged.push_back(icon_check);
            bool all_missing = !judged.empty() && std::all_of(judged.begin(), judged.end(), [](const Target& t) {
                return t.state == TargetState::Missing;
            });
            if (all_missing) {
                found.push_back({base.hive, base.path + L"\\" + sub, L"", true, L"Uninstall entry",
                                 L"Program, uninstaller and icon are gone (" + judged[0].path + L")", title});
            }
        }
    }
    return found;
}

std::vector<RegEntry> dead_app_paths() {
    std::vector<RegEntry> found;
    for (const auto& base : app_paths()) {
        RegKey root = RegKey::open(base.hive, base.path);
        if (!root.valid()) continue;
        for (const auto& sub : root.subkeys()) {
            RegKey key = RegKey::open(base.hive, base.path + L"\\" + sub);
            if (!key.valid()) continue;
            Target t = check_target(find(text_values(key), L""));
            if (t.state == TargetState::Missing) {
                found.push_back({base.hive, base.path + L"\\" + sub, L"", true, L"App Paths entry",
                                 L"Program not found: " + t.path, sub});
            }
        }
    }
    return found;
}

std::vector<RegEntry> dead_startup_entries() {
    std::vector<RegEntry> found;
    for (const RunPath& rp : RUN_PATHS) {
        RegKey key = RegKey::open(rp.hive, rp.path);
        if (!key.valid()) continue;
        for (const auto& [name, value] : text_values(key)) {
            Target t = check_target(value);
            if (t.state == TargetState::Missing) {
                found.push_back({rp.hive, rp.path, name, false, L"Startup entry", L"Program not found: " + t.path, value});
            }
        }
    }
    return found;
}

static void dead_value_names(const std::wstring& hive, const std::wstring& path, const std::wstring& category,
                             const std::function<std::wstring(const std::wstring&)>& name_to_path,
                             std::vector<RegEntry>& found) {
    RegKey key = RegKey::open(hive, path);
    if (!key.valid()) return;
    for (const RegValue& v : key.values()) {
        std::wstring candidate = name_to_path(v.name);
        if (candidate.empty()) continue;
        Target t = check_target(L"\"" + candidate + L"\"");
        if (t.state == TargetState::Missing) {
            found.push_back({hive, path, v.name, false, category, L"File not found: " + t.path, L""});
        }
    }
}

std::vector<RegEntry> dead_cached_traces() {
    std::vector<RegEntry> found;
    static const std::wregex mui(LR"(^(.*?\.exe)\.(?:FriendlyAppName|ApplicationCompany)$)", std::regex::icase);
    static const std::wregex drive_path(LR"(^[A-Za-z]:\\)");
    auto mui_path = [](const std::wstring& name) -> std::wstring {
        std::wsmatch m;
        return std::regex_match(name, m, mui) ? m[1].str() : L"";
    };
    auto plain_path = [](const std::wstring& name) -> std::wstring {
        return std::regex_search(name, drive_path) ? name : L"";
    };
    dead_value_names(L"HKCU", L"SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
                     L"Program name cache", mui_path, found);
    const std::pair<const wchar_t*, const wchar_t*> compat[] = {
        {L"HKCU", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store"},
        {L"HKCU", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Persisted"},
        {L"HKCU", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers"},
        {L"HKLM", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers"}};
    for (const auto& [hive, path] : compat) dead_value_names(hive, path, L"Compatibility entry", plain_path, found);
    for (const wchar_t* path : {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SharedDLLs",
                                L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\SharedDLLs"}) {
        dead_value_names(L"HKLM", path, L"Shared DLL entry", plain_path, found);
    }
    return found;
}

std::vector<RegEntry> scan_dead(const Stop& stop, const Progress& progress) {
    std::vector<RegEntry> entries;
    const std::pair<const wchar_t*, std::vector<RegEntry> (*)()> steps[] = {
        {L"Add/Remove Programs entries", dead_uninstall_entries}, {L"App Paths", dead_app_paths},
        {L"startup entries", dead_startup_entries}, {L"cached program traces", dead_cached_traces}};
    for (const auto& [label, function] : steps) {
        if (stop()) break;
        if (progress) progress(std::wstring(L"Checking ") + label + L"...");
        for (auto& e : function()) entries.push_back(std::move(e));
    }
    std::stable_sort(entries.begin(), entries.end(), [](const RegEntry& a, const RegEntry& b) {
        if (a.category != b.category) return a.category < b.category;
        std::wstring la = lower(a.location()), lb = lower(b.location());
        return la != lb ? la < lb : lower(a.value) < lower(b.value);
    });
    return entries;
}

std::set<std::wstring> installed_markers() {
    std::set<std::wstring> markers;
    auto add = [&](const std::wstring& text, bool words = false) {
        std::wstring n = norm_key(text);
        if (!n.empty()) markers.insert(n);
        if (!words) return;
        std::wstring word;
        auto flush = [&] {
            std::wstring w = norm_key(word);
            if (w.size() >= 4) markers.insert(w);
            word.clear();
        };
        for (wchar_t c : text) {
            if (c < 128 && iswalnum(c)) word.push_back(c);
            else flush();
        }
        flush();
    };
    for (const auto& base : uninstall_paths()) {
        RegKey root = RegKey::open(base.hive, base.path);
        if (!root.valid()) continue;
        for (const auto& sub : root.subkeys()) {
            RegKey key = RegKey::open(base.hive, base.path + L"\\" + sub);
            if (!key.valid()) continue;
            Values values = text_values(key);
            add(sub);
            add(find(values, L"DisplayName"), true);
            add(find(values, L"Publisher"), true);
            std::wstring location = trim(find(values, L"InstallLocation"));
            location = strip_quotes(location);
            while (!location.empty() && location.back() == L'\\') location.pop_back();
            if (!location.empty()) add(base_name(location));
            for (const wchar_t* field : {L"UninstallString", L"DisplayIcon"}) {
                Target t = check_target(strip_icon_index(find(values, field)));
                if (!t.path.empty()) add(base_name(dir_name(t.path)));
            }
        }
    }
    for (const auto& base : app_paths()) {
        RegKey root = RegKey::open(base.hive, base.path);
        if (!root.valid()) continue;
        for (const auto& sub : root.subkeys()) {
            std::size_t dot = sub.find_last_of(L'.');
            add(dot == std::wstring::npos || dot == 0 ? sub : sub.substr(0, dot));
        }
    }
    std::set<std::wstring> kept;
    for (const auto& m : markers) {
        if (m.size() >= 3) kept.insert(m);
    }
    return kept;
}

}  // namespace dd
