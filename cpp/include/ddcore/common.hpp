// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares shared low-level helpers for strings, Windows paths and directory listing, used by the other ddcore modules.

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace dd {

using Stop = std::function<bool()>;
using Progress = std::function<void(const std::wstring&)>;

inline bool never() { return false; }

// region Strings
std::wstring wide(const std::string& utf8);
std::string utf8(const std::wstring& text);
std::wstring lower(std::wstring text);
std::wstring trim(const std::wstring& text);
std::wstring strip_quotes(const std::wstring& text);
bool starts_with(const std::wstring& text, const std::wstring& prefix);
bool ends_with(const std::wstring& text, const std::wstring& suffix);
std::vector<std::wstring> split(const std::wstring& text, wchar_t separator);
// Lower-case letters and digits only: how program and folder names are compared.
std::wstring norm_key(const std::wstring& text);
std::wstring human_size(std::uint64_t size);
// endregion

// region Paths
std::wstring system_root();                         // from the API, never from %SystemRoot%
std::wstring system32();
std::wstring known_folder(int csidl);               // from the shell API, never from the environment
std::wstring temp_dir();
std::wstring exe_dir();
std::wstring expand_env(const std::wstring& text);  // %VARIABLE% expansion
std::wstring normcase(const std::wstring& path);    // lower case, backslashes, no trailing slash
std::wstring base_name(const std::wstring& path);
std::wstring dir_name(const std::wstring& path);
std::wstring extension(const std::wstring& path);   // with the dot, lower case
std::wstring join(const std::wstring& folder, const std::wstring& name);
bool is_absolute(const std::wstring& path);
std::wstring absolute(const std::wstring& path);    // only the folder part is resolved (keeps "nul" a plain name)
std::wstring long_path(const std::wstring& path);   // \\?\ form, reaches files named like devices
bool is_reserved_name(const std::wstring& path);
bool exists(const std::wstring& path);              // follows links
bool lexists(const std::wstring& path);             // does not
bool is_file(const std::wstring& path);
bool is_dir(const std::wstring& path);
// endregion

// region Files and data folder
// Where the program keeps its data (settings, backups, quarantine, downloaded lists): %APPDATA%\BSM\DDCleaner, or the
// folder named by DDCLEANER_HOME (tests, portable use). Created on demand.
std::wstring data_dir();
std::wstring data_subdir(const std::wstring& name);   // data_dir()\name, created
bool make_dirs(const std::wstring& path);
bool read_file(const std::wstring& path, std::string& bytes, std::size_t max_bytes = 256u * 1024 * 1024);
bool read_file_head(const std::wstring& path, std::string& bytes, std::size_t count);   // the first `count` bytes only
bool write_file(const std::wstring& path, const std::string& bytes);
bool move_file(const std::wstring& from, const std::wstring& to);
bool delete_file(const std::wstring& path);
std::wstring timestamp();                              // YYYYMMDD_HHMMSS, for backup names
std::wstring safe_name(const std::wstring& text, std::size_t keep = 60);   // [^A-Za-z0-9._-]+ -> _, last `keep` characters
std::wstring env_var(const std::wstring& name);
// endregion

// region Directory listing
constexpr unsigned long ATTR_SYSTEM = 0x4;
constexpr unsigned long ATTR_DIRECTORY = 0x10;
constexpr unsigned long ATTR_REPARSE = 0x400;

struct Entry {
    std::wstring name;
    std::wstring path;
    unsigned long attributes = 0;
    std::uint64_t size = 0;
    double modified = 0;   // seconds since 1970
    long long mtime_ns = 0;   // the same, in nanoseconds (100 ns steps): exact comparison of a file that did not change
    bool is_dir() const { return attributes & ATTR_DIRECTORY; }
    bool is_link() const { return attributes & ATTR_REPARSE; }
};

// Content of a folder (no "." and ".."). False when it cannot be opened.
bool list_dir(const std::wstring& folder, std::vector<Entry>& out);
bool stat_path(const std::wstring& path, Entry& out);  // lstat: a link is described, not followed
double now_seconds();
std::wstring format_date(double seconds);              // YYYY-MM-DD

// Size of the files inside a folder (links are not followed).
std::uint64_t folder_size(const std::wstring& path, const Stop& stop = never, std::size_t max_files = 300000);

std::vector<std::wstring> fixed_drives();
struct DriveUsage {
    std::wstring root;
    std::uint64_t total = 0, used = 0, free = 0;
};
std::vector<DriveUsage> drive_usage(const std::vector<std::wstring>& roots);
// endregion

}  // namespace dd
