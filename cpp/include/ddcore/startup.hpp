// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the list of programs that start by themselves, the shortcut and command lookup, and the removal with a backup.

#pragma once

#include <string>
#include <vector>

#include <ddcore/common.hpp>

namespace dd {

constexpr const wchar_t* ALL_USERS = L"All users";
constexpr const wchar_t* CURRENT_USER = L"Current user";

struct StartupEntry {
    std::wstring name, command, location;
    std::wstring kind;    // Registry | Folder | Task
    std::wstring scope;   // All users | Current user | account of the task
    std::wstring path;    // the program file, when it could be located
    bool exists = false;
    std::wstring signer;
    std::wstring true_type;       // the file's real type from its bytes, when it clashes with the extension
    bool dangerous_content = false;
    std::vector<std::wstring> flags;
    // 0 = nothing to say, 1 = look at it, 2 = runs for everyone from a writable folder, or an executable hiding under
    // another extension
    int severity() const;
};

extern const wchar_t* FLAG_MISSING;
extern const wchar_t* FLAG_WRITABLE;
extern const wchar_t* FLAG_UNSIGNED;
extern const wchar_t* FLAG_PACKED;

// The program file named by a command line ("" when it cannot be found). Quotes, %VARIABLES% and unquoted paths
// with spaces are handled; a bare name is only looked up in the Windows folders.
std::wstring command_path(const std::wstring& command);

std::vector<StartupEntry> read_run_keys();
std::vector<StartupEntry> read_startup_folders();
std::vector<StartupEntry> read_logon_tasks();          // PowerShell: Get-ScheduledTask
void resolve_shortcuts(std::vector<StartupEntry>& entries);   // the program behind each .lnk of a Startup folder
void inspect_entry(StartupEntry& entry);               // path, exists, signer, real type, flags
std::vector<StartupEntry> collect_startup(const Stop& stop = never,
                                          const std::function<void(std::size_t, std::size_t, const std::wstring&)>& progress = nullptr);

// region Removal
struct StartupRemoval {
    std::vector<StartupEntry> removed;
    std::vector<std::pair<StartupEntry, std::wstring>> failed;
    std::vector<std::wstring> backups;
};
bool removable(const StartupEntry& entry);
bool needs_admin(const StartupEntry& entry);
std::wstring describe(const StartupEntry& entry);   // what removing it does, for a confirmation window
// A Run value is exported to a .reg file first, a task to an XML file, a Startup-folder file is moved to the backups
// folder. If the backup fails nothing is removed.
StartupRemoval remove_entries(const std::vector<StartupEntry>& entries, const std::wstring& folder = L"",
                              const Stop& stop = never);
// Save a scheduled task as an XML file, then delete it (PowerShell). "" or an error message; nothing is deleted without the backup.
std::wstring export_and_remove_task(const std::wstring& name, const std::wstring& task_path, const std::wstring& backup);
// endregion

}  // namespace dd
