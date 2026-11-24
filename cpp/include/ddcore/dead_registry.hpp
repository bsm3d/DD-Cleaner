// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the search for registry entries of programs that are gone, a look-only scan, and the types of its results.

#pragma once

#include <functional>
#include <set>
#include <utility>
#include <string>
#include <vector>

#include <ddcore/common.hpp>

namespace dd {

struct RegEntry {
    std::wstring hive;        // HKLM | HKCU
    std::wstring key;         // key path below the hive
    std::wstring value;       // value name
    bool is_key = true;       // the entry is the key itself
    std::wstring category, reason, data;
    std::wstring confidence;  // High | Medium for guesses (history, vendor keys), "" when the entry is certain
    std::wstring location() const { return hive + L"\\" + key; }
    std::wstring display_name() const;
};

struct RegScan {
    std::vector<RegEntry> entries;
    bool truncated = false;
    std::size_t keys_seen = 0;
};

enum class TargetState { Ok, Missing, Unknown };
struct Target {
    std::wstring path;
    TargetState state;
};

// The program a command line runs: Missing only when it is gone from a connected drive; Unknown for relative or
// network paths, or files inside Windows (msiexec and friends say nothing about the program).
Target check_target(const std::wstring& command, bool is_folder = false);

std::vector<RegEntry> dead_uninstall_entries();
std::vector<RegEntry> dead_app_paths();
std::vector<RegEntry> dead_startup_entries();
std::vector<RegEntry> dead_cached_traces();
std::vector<RegEntry> scan_dead(const Stop& stop = never, const Progress& progress = nullptr);

std::vector<RegEntry> usage_history();
std::vector<RegEntry> orphan_startup_toggles();
std::vector<RegEntry> dead_com_registrations(const Stop& stop = never, std::size_t limit = 2000);
std::vector<RegEntry> orphan_vendor_keys(const std::set<std::wstring>& markers, const Stop& stop = never, double now = -1,
                                         std::size_t limit = 500);

struct RegPreset {
    std::wstring id, label, description, risk;   // risk: Safe | Check | Review
    std::function<std::vector<RegEntry>(const Stop&)> run;
};
const std::vector<RegPreset>& reg_presets();
RegScan scan_presets(const std::vector<std::wstring>& ids, const Stop& stop = never, const Progress& progress = nullptr);

// Keys, value names and string value data matching a word or wildcard (the pattern language of the file search), under
// HKCU\SOFTWARE and HKLM\SOFTWARE. A matching key is listed once, not its content.
RegScan search_registry(const std::wstring& patterns, bool names = true, bool value_names = true, bool value_data = true,
                        const Stop& stop = never, const Progress& progress = nullptr, std::size_t limit = 3000);

// Deleting: every key about to change is exported to a .reg file first; an entry whose backup failed is left alone.
std::wstring registry_protected_reason(const RegEntry& entry);   // "" when allowed
std::wstring export_key(const std::wstring& hive, const std::wstring& path, const std::wstring& file);   // "" or an error
struct RegDeleteResult {
    std::vector<RegEntry> deleted;
    std::vector<std::pair<RegEntry, std::wstring>> failed;
    std::vector<std::wstring> backups;
};
RegDeleteResult delete_entries(const std::vector<RegEntry>& entries, const std::wstring& folder = L"",
                               const Stop& stop = never);

// Normalized names an installed program can be recognised by (title, publisher, folder, key name, App Paths).
std::set<std::wstring> installed_markers();

}  // namespace dd
