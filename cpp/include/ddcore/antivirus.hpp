// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the ClamAV integration: install detection, scan commands and output, quarantine list, scan planning and protection settings.

// Intégration ClamAV : détection de l'installation, commandes et sortie, liste de quarantaine, planification pour que plusieurs clamscan se partagent le travail.
// clamscan.exe et freshclam.exe viennent seulement de C:\Program Files\ClamAV (ou x86), et seulement si le dossier est protégé contre l'écriture sans admin.
// Base, quarantaine et manifeste vivent dans le dossier de données du programme.
#pragma once

#include <functional>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <ddcore/common.hpp>
#include <ddcore/json.hpp>

namespace dd {

// region Folders and install
std::wstring clam_dir();
std::wstring database_dir();
std::wstring quarantine_dir();
std::wstring freshclam_conf_path();
std::wstring update_log_path();

struct ClamInstall {
    std::wstring folder, clamscan, freshclam;
};
// True with the install, or false with the reason. Only protected Program Files folders are accepted.
bool find_clam_install(ClamInstall& install, std::wstring& reason);
// endregion

// region Signature database
struct DatabaseInfo {
    bool ready = false;
    long long signatures = 0;
    double built = 0;   // seconds since 1970, 0 = unknown
    int age_days() const;   // -1 when unknown
};
double parse_build_time(const std::wstring& text);   // '11 Oct 2026 08-00 +0000' -> seconds, 0 when it is not a date
DatabaseInfo read_database_info(const std::wstring& folder = L"");
std::wstring write_freshclam_conf(const std::wstring& conf = L"", const std::wstring& database = L"", const std::wstring& log = L"");
std::vector<std::wstring> build_update_command(const ClamInstall& install, const std::wstring& conf, const std::wstring& database);
// endregion

// region Scan command and output
constexpr int FLAG_ARCHIVES = 1, FLAG_HEURISTICS = 2, FLAG_PUA = 4, FLAG_THOROUGH = 8;

struct ScanOptions {
    bool quarantine = true, archives = true, pua = false, thorough = false;
    bool fast = false;         // no archives, no heuristics: much quicker, catches less
    int max_filesize_mb = 100;
    bool use_cache = true;
    int cache_days = 7;
    int threads = 0;           // 0 = automatic
    bool effective_archives() const { return archives && !fast; }
    int flags() const;         // what this scan checks, as the bits stored in the cache
};

struct ScanCommandOptions {
    bool quarantine = true, archives = true, detect_pua = false, thorough = false, fast = false;
    int max_filesize_mb = 100;
    std::wstring database, clam_folder, file_list;
};
// Command line for clamscan. Targets must be absolute paths (a relative one starting with '-' would be read as an option).
// Throws std::invalid_argument.
std::vector<std::wstring> build_scan_command(const ClamInstall& install, const std::vector<std::wstring>& targets, const ScanCommandOptions& options);

struct ScanLine {
    std::wstring kind;   // found | moved | ok | skip | error | summary | other
    std::wstring a, b;   // found: path, threat; moved: path, stored; ok/skip: path; error: line; summary: key, value; other: line
};
ScanLine parse_scan_line(const std::wstring& line);
std::wstring format_duration(double seconds);
std::wstring shorten(const std::wstring& text, std::size_t limit = 100);
// endregion

// region Quarantine
struct QuarantineEntry {
    std::wstring original, stored, threat, date;
};
extern const wchar_t* UNKNOWN_ORIGIN;

void record_quarantine(const std::wstring& original, const std::wstring& stored, const std::wstring& threat, const std::wstring& folder = L"");
std::vector<QuarantineEntry> list_quarantine(const std::wstring& folder = L"");
std::wstring restore_quarantined(const QuarantineEntry& entry, const std::wstring& folder = L"");   // "" or an error message
std::wstring delete_quarantined(const QuarantineEntry& entry, const std::wstring& folder = L"");
// endregion

// region Scan cache
// Memory of what ClamAV already found clean, so the next scan can skip files that did not change. A file is skipped only when ALL
// of this holds: it was reported clean by a scan, its size and modification time (to the nanosecond) are the same, that scan used
// at least the same options as the one being planned, and the result is recent.
class ScanCache {
public:
    explicit ScanCache(const std::wstring& path);   // a damaged file is replaced by an empty cache
    bool is_clean(const std::wstring& key, std::uint64_t size, long long mtime_ns, int flags, double max_age_days, double now = -1) const;
    std::size_t count() const;
    struct Row {
        std::wstring key;
        std::uint64_t size;
        long long mtime_ns;
    };
    // Files about to be scanned: a pending entry is never skipped; it becomes clean only if the scan reports the file clean, and
    // only for the size and time seen BEFORE the scan.
    void mark_pending(const std::vector<Row>& rows);
    void mark_clean(const std::vector<std::wstring>& keys, int flags, double now = -1);
    std::size_t prune(double older_than_days, double now = -1);
    void clear();
    bool save();
    static constexpr std::size_t BATCH = 2000;
    static std::wstring key_of(const std::wstring& path);   // case-insensitive, normalized

private:
    struct Value {
        std::uint64_t size = 0;
        long long mtime_ns = 0;
        bool clean = false;
        int flags = 0;
        double scanned = 0;
    };
    std::wstring path_;
    std::unordered_map<std::wstring, Value> rows_;
    bool dirty_ = false;
};
// endregion

// region Plan and run
struct ScanPlan {
    std::vector<std::wstring> lists;   // one file list per clamscan process
    std::size_t to_scan = 0;
    std::size_t skipped = 0;           // unchanged files the cache knows are clean
    std::size_t seen = 0;
};
constexpr int MAX_THREADS = 8;
unsigned long long free_memory();   // bytes (a large default when it cannot be read)
int thread_count(int requested, int cpus = 0, long long free_ram = -1);
ScanPlan make_plan(const std::vector<std::wstring>& targets, const ScanOptions& options, ScanCache* cache, const std::wstring& workdir,
                   const std::wstring& exclude_folder = L"", int max_threads = 1, const Stop& stop = never, const Progress& progress = nullptr);
int combine_codes(const std::vector<int>& codes);   // 1 if any found something, else the worst error, else 0

struct ScanEvents {
    std::function<void(const std::vector<std::wstring>&)> lines;                                  // decoded output lines, in batches
    std::function<void(std::size_t to_scan, std::size_t skipped, std::size_t processes)> planned;
    Progress progress;                                                                            // what the listing is doing
};
// A scan shared between several clamscan processes. Returns one exit code for the whole scan: 0 clean, 1 something found, 2 stopped,
// -1 when nothing could start. `lines` may be called from several threads (calls are serialized).
int run_clam_scan(const ClamInstall& install, const std::vector<std::wstring>& targets, const ScanOptions& options, const ScanEvents& events,
                  const Stop& stop = never, const std::wstring& database = L"", const std::wstring& clam_folder = L"", const std::wstring& workdir = L"");
// freshclam, or any single command: streams its lines, returns the exit code (-1 if it could not start).
int run_streaming(const std::vector<std::wstring>& command, const std::function<void(const std::vector<std::wstring>&)>& lines, const Stop& stop = never);
// endregion

// region Protection settings
struct ProtectionSettings {
    bool watch_enabled = false;
    std::vector<std::wstring> folders;
    int scan_hours = 0;           // quick scan every N hours while the program is open (0 = never)
    double last_quick_scan = 0;
};
std::wstring protection_settings_path();
ProtectionSettings load_protection_settings(const std::wstring& path = L"");
std::wstring save_protection_settings(const ProtectionSettings& settings, const std::wstring& path = L"");   // "" or an error
bool scan_is_due(const ProtectionSettings& settings, double now = -1);

// Reports files that appeared (or were replaced) in the watched folders and have stopped changing: a file is reported once its size
// and modification time are the same on two polls in a row. Files already there when watching starts are not reported.
class FolderWatcher {
public:
    explicit FolderWatcher(const std::vector<std::wstring>& folders, int max_depth = 3, std::size_t max_files = 20000);
    void prime();
    std::vector<std::wstring> poll();

private:
    using Signature = std::pair<std::uint64_t, long long>;
    std::map<std::wstring, Signature> listing() const;
    std::vector<std::wstring> folders_;
    int max_depth_;
    std::size_t max_files_;
    std::map<std::wstring, Signature> known_, pending_;
};

// YARA rules next to the signature database
std::wstring rules_dir();
std::vector<std::wstring> list_rule_files(const std::wstring& folder = L"");
std::wstring check_rule_text(const std::wstring& source);   // "" when the file looks like a YARA rule file, else the reason
std::wstring check_rule_with_clamav(const ClamInstall& install, const std::wstring& source);
std::wstring add_rule_file(const std::wstring& source, const std::wstring& folder = L"", const ClamInstall* install = nullptr);
std::wstring remove_rule_file(const std::wstring& name, const std::wstring& folder = L"");
// endregion

}  // namespace dd
