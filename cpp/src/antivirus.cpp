// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the ClamAV integration: install detection, database age, scan options, output parsing and quarantine.

#include <ddcore/antivirus.hpp>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <ctime>
#include <memory>
#include <mutex>
#include <regex>
#include <stdexcept>
#include <thread>

#include <windows.h>

#include <ddcore/inspect.hpp>
#include <ddcore/proc.hpp>

namespace dd {

// region Folders and install

std::wstring clam_dir() { return join(data_dir(), L"clamav"); }
std::wstring database_dir() { return join(clam_dir(), L"database"); }
std::wstring quarantine_dir() { return join(clam_dir(), L"quarantine"); }
std::wstring freshclam_conf_path() { return join(clam_dir(), L"freshclam.conf"); }
std::wstring update_log_path() { return join(clam_dir(), L"freshclam.log"); }

bool find_clam_install(ClamInstall& install, std::wstring& reason) {
    std::vector<std::wstring> unprotected;
    for (int csidl : {0x26, 0x2A}) {   // Program Files, Program Files (x86): from the API, never from %ProgramFiles%
        std::wstring base = known_folder(csidl);
        if (base.empty()) continue;
        std::wstring folder = join(base, L"ClamAV"), scan = join(folder, L"clamscan.exe"), fresh = join(folder, L"freshclam.exe");
        if (!is_file(scan) || !is_file(fresh)) continue;
        auto problems = folder_risk(folder);
        if (!problems.empty()) {
            unprotected.insert(unprotected.end(), problems.begin(), problems.end());
            continue;
        }
        install = {folder, scan, fresh};
        reason.clear();
        return true;
    }
    if (!unprotected.empty()) {
        reason = L"ClamAV was found but its folder is not protected, so it is not used:";
        for (const auto& p : unprotected) reason += L"\n" + p;
    } else {
        reason = L"ClamAV is not installed in C:\\Program Files\\ClamAV.";
    }
    return false;
}

// endregion

// region Signature database

int DatabaseInfo::age_days() const { return built > 0 ? (int)((now_seconds() - built) / 86400) : -1; }

double parse_build_time(const std::wstring& text) {
    static const std::wregex pattern(LR"(\s*(\d{1,2}) ([A-Za-z]{3}) (\d{4}) (\d{1,2})-(\d{2}))");
    static const std::map<std::wstring, int> months = {{L"jan", 0}, {L"feb", 1}, {L"mar", 2}, {L"apr", 3}, {L"may", 4}, {L"jun", 5},
                                                       {L"jul", 6}, {L"aug", 7}, {L"sep", 8}, {L"oct", 9}, {L"nov", 10}, {L"dec", 11}};
    std::wsmatch m;
    if (!std::regex_search(text, m, pattern) || m.position(0) != 0) return 0;
    auto month = months.find(lower(m[2]));
    if (month == months.end()) return 0;
    std::tm tm{};
    tm.tm_mday = std::stoi(m[1]);
    tm.tm_mon = month->second;
    tm.tm_year = std::stoi(m[3]) - 1900;
    tm.tm_hour = std::stoi(m[4]);
    tm.tm_min = std::stoi(m[5]);
    if (tm.tm_mday < 1 || tm.tm_mday > 31 || tm.tm_hour > 23 || tm.tm_min > 59) return 0;
    tm.tm_isdst = -1;
    return (double)std::mktime(&tm);
}

DatabaseInfo read_database_info(const std::wstring& folder_in) {
    static const std::set<std::wstring> suffixes = {L".cvd", L".cld", L".cud", L".hdb", L".hsb", L".ndb", L".ldb", L".mdb", L".msb", L".fp", L".sfp", L".yar", L".yara"};
    std::wstring folder = folder_in.empty() ? database_dir() : folder_in;
    DatabaseInfo info;
    std::vector<Entry> files;
    if (!list_dir(folder, files)) return info;
    for (const Entry& f : files) {
        std::wstring suffix = extension(f.name);
        if (!suffixes.count(suffix) || suffix == L".yar" || suffix == L".yara" || f.is_dir()) continue;   // custom YARA rules alone are not a signature database
        info.ready = true;
        if (suffix != L".cvd" && suffix != L".cld") continue;
        std::string bytes;
        if (!read_file_head(f.path, bytes, 512)) continue;
        // only the header is needed: the first 512 bytes
        std::wstring header = wide(bytes.substr(0, 512));
        auto parts = split(header, L':');
        if (parts.size() < 4 || parts[0] != L"ClamAV-VDB") continue;
        bool digits = !parts[3].empty();
        for (wchar_t c : parts[3]) digits &= c >= L'0' && c <= L'9';
        if (digits) info.signatures += std::stoll(parts[3]);
        double built = parse_build_time(parts[1]);
        if (built <= 0) built = f.modified;
        if (info.built == 0 || built > info.built) info.built = built;
    }
    return info;
}

std::wstring write_freshclam_conf(const std::wstring& conf_in, const std::wstring& database_in, const std::wstring& log_in) {
    std::wstring conf = conf_in.empty() ? freshclam_conf_path() : conf_in;
    std::wstring database = database_in.empty() ? database_dir() : database_in;
    std::wstring log = log_in.empty() ? update_log_path() : log_in;
    make_dirs(database);
    make_dirs(dir_name(conf));
    write_file(conf, utf8(L"DatabaseDirectory " + database + L"\nUpdateLogFile " + log + L"\nDatabaseMirror database.clamav.net\nConnectTimeout 30\nReceiveTimeout 120\n"));
    return conf;
}

std::vector<std::wstring> build_update_command(const ClamInstall& install, const std::wstring& conf, const std::wstring& database) {
    return {install.freshclam, L"--config-file=" + conf, L"--datadir=" + database, L"--stdout", L"--show-progress"};
}

// endregion

// region Scan command and output

int ScanOptions::flags() const {
    int bits = 0;
    if (effective_archives()) bits |= FLAG_ARCHIVES;
    if (!fast) bits |= FLAG_HEURISTICS;
    if (pua) bits |= FLAG_PUA;
    if (thorough) bits |= FLAG_THOROUGH;
    return bits;
}

// Python's re.escape: the folder is given to clamscan as a regular expression
static std::wstring regex_escape(const std::wstring& text) {
    static const std::wstring special = L"()[]{}?*+-|^$\\.&~# \t\n\r\v\f";
    std::wstring out;
    for (wchar_t c : text) {
        if (special.find(c) != std::wstring::npos) out.push_back(L'\\');
        out.push_back(c);
    }
    return out;
}

std::vector<std::wstring> build_scan_command(const ClamInstall& install, const std::vector<std::wstring>& targets, const ScanCommandOptions& o) {
    if (targets.empty() && o.file_list.empty()) throw std::invalid_argument("Nothing to scan.");
    for (const auto& t : targets) {
        if (!is_absolute(t)) throw std::invalid_argument(utf8(L"Not an absolute path: " + t));
    }
    std::wstring database = o.database.empty() ? database_dir() : o.database;
    std::wstring clam_folder = o.clam_folder.empty() ? clam_dir() : o.clam_folder;
    int max_mb = std::min(std::max(o.max_filesize_mb, 1), 4000);
    int scan_mb = std::max(max_mb * (o.thorough ? 8 : 4), o.thorough ? 1000 : 400);
    std::vector<std::wstring> cmd = {install.clamscan, L"--database=" + database, L"--recursive", L"--follow-dir-symlinks=0", L"--follow-file-symlinks=0",
                                     L"--stdout", std::wstring(L"--heuristic-alerts=") + (o.fast ? L"no" : L"yes"),
                                     std::wstring(L"--phishing-scan-urls=") + (o.fast ? L"no" : L"yes"), L"--max-filesize=" + std::to_wstring(max_mb) + L"M",
                                     L"--max-scansize=" + std::to_wstring(scan_mb) + L"M",
                                     // never scan our own database and quarantine (the quarantine holds known malware)
                                     L"--exclude-dir=" + regex_escape(clam_folder)};
    if (!o.archives || o.fast) cmd.push_back(L"--scan-archive=no");
    if (o.detect_pua) cmd.push_back(L"--detect-pua=yes");
    if (o.thorough) {
        for (const wchar_t* f : {L"--alert-broken=yes", L"--alert-broken-media=yes", L"--alert-encrypted=yes", L"--alert-macros=yes", L"--alert-exceeds-max=yes", L"--max-recursion=20", L"--max-files=100000"})
            cmd.push_back(f);
    }
    if (o.quarantine) cmd.push_back(L"--move=" + join(clam_folder, L"quarantine"));
    if (!o.file_list.empty()) cmd.push_back(L"--file-list=" + o.file_list);
    cmd.insert(cmd.end(), targets.begin(), targets.end());
    return cmd;
}

ScanLine parse_scan_line(const std::wstring& line) {
    static const std::map<std::wstring, std::wstring> summary_keys = {{L"Known viruses", L"signatures"}, {L"Engine version", L"engine"}, {L"Scanned directories", L"dirs"},
                                                                     {L"Scanned files", L"files"}, {L"Infected files", L"infected"}, {L"Data scanned", L"data"}, {L"Time", L"time"}};
    static const std::set<std::wstring> ignored = {L"Empty file", L"Symbolic link", L"Excluded"};
    if (ends_with(line, L" FOUND")) {
        std::wstring body = line.substr(0, line.size() - 6);
        std::size_t at = body.rfind(L": ");
        if (at == std::wstring::npos) return {L"found", L"", body};
        return {L"found", body.substr(0, at), body.substr(at + 2)};
    }
    static const std::wregex moved(LR"(^(.*): moved to '(.*)'$)");
    std::wsmatch m;
    if (std::regex_match(line, m, moved)) return {L"moved", m[1], m[2]};
    if (ends_with(line, L": OK")) return {L"ok", line.substr(0, line.size() - 4), L""};
    static const std::wregex other(LR"(^(Data read|Start Date|End Date):)");
    if (starts_with(line, L"-----") || std::regex_search(line, other)) return {L"other", L"", L""};
    std::size_t colon = line.rfind(L": ");
    if (colon != std::wstring::npos && ignored.count(line.substr(colon + 2))) return {L"skip", line.substr(0, colon), L""};
    if (ends_with(line, L" ERROR")) return {L"error", line, L""};
    std::size_t first = line.find(L": ");
    if (first != std::wstring::npos) {
        auto key = summary_keys.find(line.substr(0, first));
        if (key != summary_keys.end()) return {L"summary", key->second, trim(line.substr(first + 2))};
    }
    return {L"other", line, L""};
}

std::wstring format_duration(double seconds_in) {
    long long seconds = (long long)seconds_in, hours = seconds / 3600, rest = seconds % 3600, minutes = rest / 60, secs = rest % 60;
    wchar_t buf[64];
    if (hours) swprintf(buf, 64, L"%lld h %02lld min %02lld s", hours, minutes, secs);
    else swprintf(buf, 64, L"%lld min %02lld s", minutes, secs);
    return buf;
}

std::wstring shorten(const std::wstring& text, std::size_t limit) {
    if (text.size() <= limit) return text;
    std::size_t keep = (limit - 3) / 2;
    return text.substr(0, keep) + L"..." + text.substr(text.size() - keep);
}

// endregion

// region Quarantine

const wchar_t* UNKNOWN_ORIGIN = L"(unknown location)";

namespace {

const wchar_t* MANIFEST_NAME = L"manifest.json";

std::wstring real_path(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return absolute(path);
    wchar_t buf[4096];
    DWORD n = GetFinalPathNameByHandleW(h, buf, 4096, FILE_NAME_NORMALIZED);
    CloseHandle(h);
    if (!n || n >= 4096) return absolute(path);
    std::wstring out = buf;
    if (starts_with(out, L"\\\\?\\") && !starts_with(out, L"\\\\?\\UNC\\")) out = out.substr(4);
    return out;
}

bool inside(const std::wstring& path, const std::wstring& folder) {
    std::wstring p = normcase(real_path(path)), f = normcase(real_path(folder));
    return starts_with(p, f + L"\\") || p == f;
}

Json read_manifest(const std::wstring& folder) {
    std::string bytes;
    Json data;
    Json list = Json::array();
    if (!read_file(join(folder, MANIFEST_NAME), bytes) || !try_parse_json(wide(bytes), data) || !data.is_array()) return list;
    for (const Json& e : data.items()) {
        if (e.is_object()) list.push(e);
    }
    return list;
}

// Atomic: write a temporary file then replace, so a crash never leaves half a JSON (which would be read as an empty list and
// overwritten, losing every original path).
void write_manifest(const std::wstring& folder, const Json& entries) {
    make_dirs(folder);
    std::wstring final_path = join(folder, MANIFEST_NAME), temp = final_path + L".tmp";
    if (write_file(temp, utf8(entries.dump(true)))) MoveFileExW(temp.c_str(), final_path.c_str(), MOVEFILE_REPLACE_EXISTING);
}

std::wstring minutes_stamp(double seconds) {
    std::time_t t = (std::time_t)seconds;
    std::tm tm{};
    localtime_s(&tm, &t);
    wchar_t buf[32];
    wcsftime(buf, 32, L"%Y-%m-%d %H:%M", &tm);
    return buf;
}

void forget(const std::wstring& folder, const std::wstring& stored) {
    Json kept = Json::array();
    Json manifest = read_manifest(folder);   // a named value: a range-for over a temporary would read freed memory
    for (const Json& e : manifest.items()) {
        if (normcase(e.get(L"stored").str()) != normcase(stored)) kept.push(e);
    }
    write_manifest(folder, kept);
}

}  // namespace

void record_quarantine(const std::wstring& original, const std::wstring& stored, const std::wstring& threat, const std::wstring& folder_in) {
    std::wstring folder = folder_in.empty() ? quarantine_dir() : folder_in;
    std::wstring path = join(folder, MANIFEST_NAME);
    Entry info;
    if (stat_path(path, info) && read_manifest(folder).size() == 0 && info.size > 2) {
        MoveFileExW(path.c_str(), (path + L".corrupt").c_str(), MOVEFILE_REPLACE_EXISTING);   // unreadable manifest: keep it aside instead of overwriting it
    }
    Json entries = read_manifest(folder);
    Json e = Json::object();
    e.set(L"original", Json::string(original));
    e.set(L"stored", Json::string(stored));
    e.set(L"threat", Json::string(threat));
    e.set(L"date", Json::string(minutes_stamp(now_seconds())));
    entries.push(e);
    write_manifest(folder, entries);
}

std::vector<QuarantineEntry> list_quarantine(const std::wstring& folder_in) {
    std::wstring folder = folder_in.empty() ? quarantine_dir() : folder_in;
    std::vector<QuarantineEntry> result;
    if (!is_dir(folder)) return result;
    std::set<std::wstring> known;
    Json manifest = read_manifest(folder);   // a named value: a range-for over a temporary would read freed memory
    for (const Json& e : manifest.items()) {
        std::wstring stored = e.get(L"stored").str();
        if (is_file(stored) && inside(stored, folder)) {
            result.push_back({e.has(L"original") ? e.get(L"original").str() : UNKNOWN_ORIGIN, stored, e.has(L"threat") ? e.get(L"threat").str() : L"?", e.get(L"date").str()});
            known.insert(normcase(real_path(stored)));
        }
    }
    std::vector<Entry> files;
    list_dir(folder, files);
    std::sort(files.begin(), files.end(), [](const Entry& a, const Entry& b) { return a.name < b.name; });
    for (const Entry& f : files) {
        if (f.name == MANIFEST_NAME || f.is_dir() || known.count(normcase(real_path(f.path)))) continue;
        result.push_back({UNKNOWN_ORIGIN, f.path, L"?", minutes_stamp(f.modified)});
    }
    return result;
}

std::wstring restore_quarantined(const QuarantineEntry& entry, const std::wstring& folder_in) {
    std::wstring folder = folder_in.empty() ? quarantine_dir() : folder_in;
    if (!inside(entry.stored, folder) || !is_file(entry.stored)) return L"The quarantined file is no longer in the quarantine folder.";
    if (entry.original == UNKNOWN_ORIGIN || !is_absolute(entry.original)) return L"The original location is unknown: the file cannot be restored automatically.";
    if (lexists(entry.original)) return L"A file already exists at " + entry.original + L".";
    make_dirs(dir_name(entry.original));
    if (!move_file(entry.stored, entry.original)) return L"The file could not be moved back (error " + std::to_wstring(GetLastError()) + L").";
    forget(folder, entry.stored);
    return L"";
}

std::wstring delete_quarantined(const QuarantineEntry& entry, const std::wstring& folder_in) {
    std::wstring folder = folder_in.empty() ? quarantine_dir() : folder_in;
    if (!inside(entry.stored, folder)) return L"The file is not in the quarantine folder.";
    if (!delete_file(entry.stored) && GetLastError() != ERROR_FILE_NOT_FOUND) return L"The file could not be deleted (error " + std::to_wstring(GetLastError()) + L").";
    forget(folder, entry.stored);
    return L"";
}

// endregion

// region Scan cache

std::wstring ScanCache::key_of(const std::wstring& path) { return normcase(absolute(path)); }

ScanCache::ScanCache(const std::wstring& path) : path_(path) {
    make_dirs(dir_name(path));
    std::string bytes;
    if (!read_file(path, bytes, 2048ULL * 1024 * 1024)) return;
    std::size_t pos = 0;
    while (pos < bytes.size()) {
        std::size_t end = bytes.find('\n', pos);
        if (end == std::string::npos) end = bytes.size();
        std::string line = bytes.substr(pos, end - pos);
        pos = end + 1;
        std::vector<std::string> f;
        std::size_t start = 0;
        for (;;) {
            std::size_t tab = line.find('\t', start);
            if (tab == std::string::npos) {
                f.push_back(line.substr(start));
                break;
            }
            f.push_back(line.substr(start, tab - start));
            start = tab + 1;
        }
        if (f.size() != 6) continue;   // a damaged line is dropped, the rest is kept
        try {
            Value v;
            v.size = std::stoull(f[1]);
            v.mtime_ns = std::stoll(f[2]);
            v.clean = f[3] == "1";
            v.flags = std::stoi(f[4]);
            v.scanned = std::stod(f[5]);
            rows_[wide(f[0])] = v;
        } catch (const std::exception&) {
        }
    }
}

bool ScanCache::is_clean(const std::wstring& key, std::uint64_t size, long long mtime_ns, int flags, double max_age_days, double now_in) const {
    auto it = rows_.find(key);
    if (it == rows_.end()) return false;
    const Value& v = it->second;
    double now = now_in < 0 ? now_seconds() : now_in;
    return v.clean && v.size == size && v.mtime_ns == mtime_ns && (v.flags & flags) == flags && now - v.scanned <= max_age_days * 86400;
}

std::size_t ScanCache::count() const {
    std::size_t n = 0;
    for (const auto& kv : rows_) n += kv.second.clean;
    return n;
}

void ScanCache::mark_pending(const std::vector<Row>& rows) {
    for (const Row& r : rows) rows_[r.key] = Value{r.size, r.mtime_ns, false, 0, 0};
    dirty_ = true;
}

void ScanCache::mark_clean(const std::vector<std::wstring>& keys, int flags, double now_in) {
    double now = now_in < 0 ? now_seconds() : now_in;
    for (const auto& k : keys) {
        auto it = rows_.find(k);
        if (it != rows_.end() && !it->second.clean) {
            it->second.clean = true;
            it->second.flags = flags;
            it->second.scanned = now;
        }
    }
    dirty_ = true;
}

std::size_t ScanCache::prune(double older_than_days, double now_in) {
    double now = now_in < 0 ? now_seconds() : now_in, limit = now - older_than_days * 86400;
    std::size_t removed = 0;
    for (auto it = rows_.begin(); it != rows_.end();) {
        if (!it->second.clean || it->second.scanned < limit) {
            it = rows_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    if (removed) dirty_ = true;
    return removed;
}

void ScanCache::clear() {
    rows_.clear();
    dirty_ = true;
}

bool ScanCache::save() {
    if (!dirty_) return true;
    std::string out;
    out.reserve(rows_.size() * 100);
    char numbers[160];
    for (const auto& [key, v] : rows_) {
        out += utf8(key);
        snprintf(numbers, sizeof(numbers), "\t%llu\t%lld\t%d\t%d\t%.0f\n", (unsigned long long)v.size, v.mtime_ns, v.clean ? 1 : 0, v.flags, v.scanned);
        out += numbers;
    }
    std::wstring temp = path_ + L".tmp";
    if (!write_file(temp, out)) return false;
    if (!MoveFileExW(temp.c_str(), path_.c_str(), MOVEFILE_REPLACE_EXISTING)) return false;
    dirty_ = false;
    return true;
}

// endregion

// region Plan and run

unsigned long long free_memory() {
    MEMORYSTATUSEX status{};
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) return status.ullAvailPhys;
    return 16ULL * 1024 * 1024 * 1024;
}

int thread_count(int requested, int cpus_in, long long free_ram_in) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    int cpus = cpus_in > 0 ? cpus_in : (int)si.dwNumberOfProcessors;
    if (cpus < 2 && cpus_in <= 0) cpus = std::max(cpus, 2);
    long long free_ram = free_ram_in < 0 ? (long long)free_memory() : free_ram_in;
    const long long ram_per_process = (long long)(1.3 * 1024 * 1024 * 1024), reserve = 4LL * 1024 * 1024 * 1024;
    long long by_memory = std::max(1LL, (free_ram - reserve) / ram_per_process);
    int wanted = requested > 0 ? requested : std::max(1, cpus / 2);
    return (int)std::max(1LL, std::min<long long>({wanted, MAX_THREADS, cpus, by_memory}));
}

ScanPlan make_plan(const std::vector<std::wstring>& targets, const ScanOptions& options, ScanCache* cache, const std::wstring& workdir,
                   const std::wstring& exclude_folder, int max_threads_in, const Stop& stop, const Progress& progress) {
    const std::size_t MIN_FILES_PER_PROCESS = 500, PROGRESS_EVERY = 5000;
    make_dirs(workdir);
    std::size_t max_threads = (std::size_t)std::max(1, max_threads_in);
    std::vector<std::wstring> names;
    std::vector<std::string> buffers(max_threads);   // clamscan reads UTF-8
    for (std::size_t i = 0; i < max_threads; ++i) names.push_back(join(workdir, L"files_" + std::to_wstring(i) + L".txt"));
    ScanPlan plan;
    std::uint64_t max_bytes = (std::uint64_t)options.max_filesize_mb * 1024 * 1024;
    std::wstring exclude = exclude_folder.empty() ? L"" : normcase(absolute(exclude_folder));
    int flags = options.flags();
    std::vector<ScanCache::Row> pending;
    bool use_cache = cache != nullptr && options.use_cache;

    auto consider = [&](const std::wstring& path, std::uint64_t size, long long mtime_ns) {
        ++plan.seen;
        if (size == 0 || size > max_bytes) return;   // clamscan ignores them too
        std::wstring key = ScanCache::key_of(path);
        if (use_cache && cache->is_clean(key, size, mtime_ns, flags, options.cache_days)) {
            ++plan.skipped;
        } else {
            buffers[plan.to_scan % max_threads] += utf8(path) + "\n";
            ++plan.to_scan;
            if (use_cache) {
                pending.push_back({key, size, mtime_ns});
                if (pending.size() >= ScanCache::BATCH) {
                    cache->mark_pending(pending);
                    pending.clear();
                }
            }
        }
        if (progress && plan.seen % PROGRESS_EVERY == 0) {
            progress(L"Listing files... " + std::to_wstring(plan.seen) + L" seen, " + std::to_wstring(plan.to_scan) + L" to scan, " + std::to_wstring(plan.skipped) + L" unchanged");
        }
    };

    std::vector<std::wstring> stack;
    for (const auto& target : targets) {
        Entry info;
        if (!stat_path(target, info)) continue;
        if (info.is_dir()) stack.push_back(target);
        else consider(target, info.size, info.mtime_ns);
    }
    std::vector<Entry> entries;
    while (!stack.empty() && !stop()) {
        std::wstring folder = stack.back();
        stack.pop_back();
        if (!list_dir(folder, entries)) continue;
        for (const Entry& e : entries) {
            if (e.is_link()) continue;
            if (e.is_dir()) {
                std::wstring low = normcase(e.path);
                if (exclude.empty() || (low != exclude && !starts_with(low, exclude + L"\\"))) stack.push_back(e.path);
            } else {
                consider(e.path, e.size, e.mtime_ns);
            }
        }
    }
    if (use_cache && !pending.empty()) cache->mark_pending(pending);

    std::size_t used = std::max<std::size_t>(1, std::min<std::size_t>(max_threads, plan.to_scan / MIN_FILES_PER_PROCESS));
    for (std::size_t extra = used; extra < max_threads; ++extra) buffers[extra % used] += buffers[extra];   // too few files for all the processes: merge the extra lists
    for (std::size_t i = 0; i < used; ++i) {
        if (buffers[i].empty()) continue;
        write_file(names[i], buffers[i]);
        plan.lists.push_back(names[i]);
    }
    return plan;
}

int combine_codes(const std::vector<int>& codes) {
    for (int c : codes) {
        if (c == 1) return 1;
    }
    for (int c : codes) {
        if (c != 0 && c != 1) return c;
    }
    return 0;
}

namespace {

struct Emitter {
    std::mutex lock;
    std::function<void(const std::vector<std::wstring>&)> sink;
    void emit(const std::vector<std::wstring>& batch) {
        if (batch.empty() || !sink) return;
        std::lock_guard<std::mutex> g(lock);
        sink(batch);
    }
};

}  // namespace

int run_streaming(const std::vector<std::wstring>& command, const std::function<void(const std::vector<std::wstring>&)>& lines, const Stop& stop) {
    ProcOptions o;
    o.timeout_ms = 0;
    o.encoding = Encoding::Utf8;
    o.stop = stop;
    std::vector<std::wstring> batch;
    ULONGLONG last = GetTickCount64();
    o.on_line = [&](const std::wstring& line) {
        batch.push_back(line);
        if (batch.size() >= 200 || GetTickCount64() - last > 100) {
            if (lines) lines(batch);
            batch.clear();
            last = GetTickCount64();
        }
    };
    ProcResult r = run_process(command, o);
    if (!batch.empty() && lines) lines(batch);
    if (!r.started) {
        if (lines) lines({L"Could not start " + base_name(command[0])});
        return -1;
    }
    return r.code;
}

int run_clam_scan(const ClamInstall& install, const std::vector<std::wstring>& targets, const ScanOptions& options, const ScanEvents& events,
                  const Stop& stop, const std::wstring& database_in, const std::wstring& clam_folder_in, const std::wstring& workdir_in) {
    std::wstring database = database_in.empty() ? database_dir() : database_in;
    std::wstring clam_folder = clam_folder_in.empty() ? clam_dir() : clam_folder_in;
    std::wstring workdir = workdir_in.empty() ? join(clam_folder, L"work") : workdir_in;
    std::unique_ptr<ScanCache> cache;
    if (options.use_cache) {
        cache = std::make_unique<ScanCache>(join(clam_folder, L"scan_cache.dat"));
        cache->prune(std::max(options.cache_days * 4, 30));
    }
    auto cleanup = [&] {
        std::vector<Entry> files;
        if (list_dir(workdir, files)) {
            for (const auto& f : files) delete_file(f.path);
        }
        RemoveDirectoryW(workdir.c_str());
    };
    cleanup();
    int threads = thread_count(options.threads);
    ScanPlan plan = make_plan(targets, options, cache.get(), workdir, clam_folder, threads, stop, events.progress);
    if (events.planned) events.planned(plan.to_scan, plan.skipped, plan.lists.size());
    if (cache) cache->save();
    if (stop()) {
        cleanup();
        return 2;
    }
    if (plan.lists.empty()) {
        cleanup();
        return 0;   // nothing new to scan
    }
    // clamscan --move refuses a folder that does not exist yet (first scan after an install)
    if (options.quarantine) make_dirs(join(clam_folder, L"quarantine"));
    std::vector<std::vector<std::wstring>> commands;
    for (const auto& list : plan.lists) {
        ScanCommandOptions c;
        c.quarantine = options.quarantine;
        c.archives = options.archives;
        c.max_filesize_mb = options.max_filesize_mb;
        c.detect_pua = options.pua;
        c.thorough = options.thorough;
        c.database = database;
        c.clam_folder = clam_folder;
        c.fast = options.fast;
        c.file_list = list;
        commands.push_back(build_scan_command(install, {}, c));
    }

    Emitter emitter;
    emitter.sink = events.lines;
    std::mutex clean_lock;
    std::vector<std::wstring> clean_keys;
    int flags = options.flags();
    std::vector<int> codes(commands.size(), -1);
    std::atomic<bool> start_failed{false};
    std::vector<std::thread> workers;
    for (std::size_t i = 0; i < commands.size(); ++i) {
        workers.emplace_back([&, i] {
            ProcOptions o;
            o.timeout_ms = 0;
            o.encoding = Encoding::Utf8;
            o.stop = [&] { return stop() || start_failed.load(); };
            std::vector<std::wstring> batch;
            ULONGLONG last = GetTickCount64();
            auto flush = [&] {
                if (batch.empty()) return;
                if (cache) {
                    std::lock_guard<std::mutex> g(clean_lock);
                    for (const auto& line : batch) {
                        ScanLine parsed = parse_scan_line(line);
                        if (parsed.kind == L"ok") clean_keys.push_back(ScanCache::key_of(parsed.a));
                    }
                    if (clean_keys.size() >= ScanCache::BATCH) {
                        cache->mark_clean(clean_keys, flags);
                        clean_keys.clear();
                    }
                }
                emitter.emit(batch);
                batch.clear();
                last = GetTickCount64();
            };
            o.on_line = [&](const std::wstring& line) {
                batch.push_back(line);
                if (batch.size() >= 200 || GetTickCount64() - last > 100) flush();
            };
            ProcResult r = run_process(commands[i], o);
            flush();
            if (!r.started) {
                emitter.emit({L"Could not start " + base_name(commands[i][0])});
                start_failed = true;
            }
            codes[i] = r.started ? r.code : -1;
        });
    }
    for (auto& w : workers) w.join();
    if (cache) {
        std::lock_guard<std::mutex> g(clean_lock);
        if (!clean_keys.empty()) cache->mark_clean(clean_keys, flags);
        cache->save();
    }
    cleanup();
    if (start_failed) return -1;
    if (stop()) return 2;
    return combine_codes(codes);
}

// endregion

// region Protection settings

std::wstring protection_settings_path() { return join(clam_dir(), L"protection.json"); }

ProtectionSettings load_protection_settings(const std::wstring& path_in) {
    ProtectionSettings s;
    std::string bytes;
    Json data;
    if (!read_file(path_in.empty() ? protection_settings_path() : path_in, bytes) || !try_parse_json(wide(bytes), data) || !data.is_object()) return s;
    if (data.get(L"folders").is_array()) {
        for (const Json& f : data.get(L"folders").items()) {
            if (f.is_string() && is_absolute(f.str())) s.folders.push_back(f.str());
        }
    }
    s.scan_hours = (int)std::max(0LL, std::min(data.get(L"scan_hours").integer(0), 24LL * 30));
    s.last_quick_scan = data.get(L"last_quick_scan").num(0);
    s.watch_enabled = data.get(L"watch_enabled").flag();
    return s;
}

std::wstring save_protection_settings(const ProtectionSettings& s, const std::wstring& path_in) {
    std::wstring path = path_in.empty() ? protection_settings_path() : path_in, temp = path + L".tmp";
    Json j = Json::object();
    j.set(L"watch_enabled", Json::boolean(s.watch_enabled));
    Json folders = Json::array();
    for (const auto& f : s.folders) folders.push(Json::string(f));
    j.set(L"folders", folders);
    j.set(L"scan_hours", Json::number(s.scan_hours));
    j.set(L"last_quick_scan", Json::number(s.last_quick_scan));
    make_dirs(dir_name(path));
    if (!write_file(temp, utf8(j.dump(true))) || !MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        return L"The protection settings could not be saved (error " + std::to_wstring(GetLastError()) + L").";
    }
    return L"";
}

bool scan_is_due(const ProtectionSettings& s, double now_in) {
    double now = now_in < 0 ? now_seconds() : now_in;
    return s.scan_hours > 0 && now - s.last_quick_scan >= s.scan_hours * 3600.0;
}

FolderWatcher::FolderWatcher(const std::vector<std::wstring>& folders, int max_depth, std::size_t max_files) : max_depth_(max_depth), max_files_(max_files) {
    for (const auto& f : folders) {
        if (is_absolute(f)) folders_.push_back(f);
    }
}

std::map<std::wstring, FolderWatcher::Signature> FolderWatcher::listing() const {
    static const std::set<std::wstring> partial = {L".crdownload", L".part", L".partial", L".tmp", L".download", L".opdownload", L".temp"};
    std::map<std::wstring, Signature> found;
    std::vector<std::pair<std::wstring, int>> stack;
    for (const auto& f : folders_) {
        if (is_dir(f)) stack.push_back({f, 0});
    }
    std::vector<Entry> entries;
    while (!stack.empty() && found.size() < max_files_) {
        auto [folder, depth] = stack.back();
        stack.pop_back();
        if (!list_dir(folder, entries)) continue;
        for (const Entry& e : entries) {
            if (e.is_link()) continue;
            if (e.is_dir()) {
                if (depth < max_depth_) stack.push_back({e.path, depth + 1});
            } else if (!partial.count(extension(e.name)) && !starts_with(e.name, L"~$")) {
                found[e.path] = {e.size, e.mtime_ns};
            }
        }
    }
    return found;
}

void FolderWatcher::prime() {
    known_ = listing();
    pending_.clear();
}

std::vector<std::wstring> FolderWatcher::poll() {
    auto current = listing();
    std::vector<std::wstring> ready;
    for (const auto& [path, sig] : current) {
        auto k = known_.find(path);
        if (k != known_.end() && k->second == sig) continue;
        auto p = pending_.find(path);
        if (p != pending_.end() && p->second == sig) {
            ready.push_back(path);
            known_[path] = sig;
            pending_.erase(p);
        } else {
            pending_[path] = sig;
        }
    }
    for (auto it = pending_.begin(); it != pending_.end();) it = current.count(it->first) ? std::next(it) : pending_.erase(it);
    for (auto it = known_.begin(); it != known_.end();) it = current.count(it->first) ? std::next(it) : known_.erase(it);
    std::sort(ready.begin(), ready.end(), [](const std::wstring& a, const std::wstring& b) { return lower(a) < lower(b); });
    return ready;
}

std::wstring rules_dir() { return database_dir(); }

std::vector<std::wstring> list_rule_files(const std::wstring& folder_in) {
    std::wstring folder = folder_in.empty() ? rules_dir() : folder_in;
    std::vector<Entry> files;
    std::vector<std::wstring> names;
    if (!list_dir(folder, files)) return names;
    for (const Entry& f : files) {
        std::wstring ext = extension(f.name);
        if ((ext == L".yar" || ext == L".yara") && !f.is_dir()) names.push_back(f.name);
    }
    std::sort(names.begin(), names.end());
    return names;
}

std::wstring check_rule_text(const std::wstring& source) {
    const std::size_t max_bytes = 5 * 1024 * 1024;
    std::wstring ext = extension(source);
    if (ext != L".yar" && ext != L".yara") return L"A YARA rule file ends in .yar or .yara.";
    Entry info;
    if (!stat_path(source, info)) return L"The file cannot be read as text.";
    if (info.size == 0 || info.size > max_bytes) return L"The file must be between 1 byte and 5 MB.";
    std::string data;
    if (!read_file(source, data, max_bytes)) return L"The file cannot be read as text.";
    std::size_t skip = data.size() >= 3 && (unsigned char)data[0] == 0xEF && (unsigned char)data[1] == 0xBB && (unsigned char)data[2] == 0xBF ? 3 : 0;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, data.data() + skip, (int)(data.size() - skip), nullptr, 0) == 0) return L"The file cannot be read as text: not valid UTF-8.";
    if (data.find('\0') != std::string::npos || data.find("rule ") == std::string::npos) return L"No YARA rule found in this file.";
    return L"";
}

std::wstring check_rule_with_clamav(const ClamInstall& install, const std::wstring& source) {
    std::wstring work = join(temp_dir(), L"ddc_rule_" + std::to_wstring(GetCurrentProcessId()) + L"_" + std::to_wstring(GetTickCount64()));
    make_dirs(work);
    std::wstring copy = join(work, base_name(source)), sample = join(work, L"sample.txt");
    auto cleanup = [&] {
        delete_file(copy);
        delete_file(sample);
        RemoveDirectoryW(work.c_str());
    };
    if (!CopyFileW(source.c_str(), copy.c_str(), FALSE)) {
        cleanup();
        return L"The rule file could not be copied.";
    }
    write_file(sample, "harmless text\n");
    ProcOptions o;
    o.timeout_ms = 120000;
    o.encoding = Encoding::Utf8;
    ProcResult r = run_process({install.clamscan, L"--database=" + work, L"--stdout", sample}, o);
    cleanup();
    if (!r.started) return L"clamscan could not be started";
    static const std::wregex loaded_re(LR"(Known viruses:\s*(\d+))");
    std::wsmatch m;
    // a broken rule file does not make clamscan fail: it loads nothing and says so in a warning
    if ((r.code == 0 || r.code == 1) && std::regex_search(r.output, m, loaded_re) && std::stoi(m[1]) > 0 && r.output.find(L"failed to parse") == std::wstring::npos) return L"";
    for (const auto& line : split(r.output, L'\n')) {
        std::wstring low = lower(line);
        if (low.find(L"error") != std::wstring::npos || low.find(L"failed") != std::wstring::npos || low.find(L"can't") != std::wstring::npos) return trim(line).substr(0, 300);
    }
    return L"clamscan loaded no rule from this file";
}

std::wstring add_rule_file(const std::wstring& source, const std::wstring& folder_in, const ClamInstall* install) {
    std::wstring folder = folder_in.empty() ? rules_dir() : folder_in;
    std::wstring problem = check_rule_text(source);
    if (!problem.empty()) return problem;
    std::wstring name = base_name(source);
    if (lexists(join(folder, name))) return L"A rule file named " + name + L" is already installed. Remove it first.";
    if (install) {
        problem = check_rule_with_clamav(*install, source);
        if (!problem.empty()) return L"ClamAV cannot load this file: " + problem;
    }
    make_dirs(folder);
    std::wstring temp = join(folder, name + L".tmp");
    if (!CopyFileW(source.c_str(), temp.c_str(), FALSE) || !MoveFileExW(temp.c_str(), join(folder, name).c_str(), MOVEFILE_REPLACE_EXISTING)) {
        return L"The rule file could not be installed (error " + std::to_wstring(GetLastError()) + L").";
    }
    return L"";
}

std::wstring remove_rule_file(const std::wstring& name, const std::wstring& folder_in) {
    std::wstring folder = folder_in.empty() ? rules_dir() : folder_in;
    auto installed = list_rule_files(folder);
    if (name != base_name(name) || std::find(installed.begin(), installed.end(), name) == installed.end()) return L"This is not an installed rule file.";
    if (!delete_file(join(folder, name))) return L"The rule file could not be removed (error " + std::to_wstring(GetLastError()) + L").";
    return L"";
}

// endregion

}  // namespace dd
