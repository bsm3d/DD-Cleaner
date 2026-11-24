// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the garbage search: the built-in presets, the confidence ordering and the matching of leftover items.

#include <ddcore/garbage.hpp>

#include <algorithm>
#include <atomic>
#include <mutex>
#include <stdexcept>
#include <thread>

#include <windows.h>
#include <shellapi.h>

namespace dd {

namespace {

const int CSIDL_VALUES[] = {0x05, 0x10, 0x0D, 0x0E, 0x1A, 0x1C, 0x23, 0x26, 0x27, 0x28, 0x2A};
const int CSIDL_PROFILE = 0x28, CSIDL_ROAMING = 0x1A, CSIDL_LOCAL = 0x1C, CSIDL_PROGRAMDATA = 0x23,
          CSIDL_PROGRAMFILES = 0x26, CSIDL_PROGRAMFILES86 = 0x2A;

const std::set<std::wstring>& skipped_folders() {
    static const std::set<std::wstring> s{L"$recycle.bin", L"system volume information"};
    return s;
}

// Folders of AppData / ProgramData / Program Files that belong to Windows or are shared
const std::set<std::wstring>& keep_folders() {
    static const std::set<std::wstring> s{
        L"microsoft", L"windows", L"packages", L"temp", L"programs", L"comms", L"connecteddevicesplatform",
        L"d3dscache", L"publishers", L"history", L"placeholdertilelogger", L"commonfiles", L"windowsapps",
        L"windowsnt", L"windowspowershell", L"modifiablewindowsapps", L"internetexplorer", L"windowsdefender",
        L"windowsmail", L"windowsmediaplayer", L"windowsphotoviewer", L"windowsportabledevices",
        L"windowssecurity", L"windowssidebar", L"referenceassemblies", L"msbuild", L"dotnet",
        L"uninstallinformation", L"packagecache", L"ssh", L"regid199106commicrosoft", L"usoprivate",
        L"usoshared", L"softwaredistribution", L"storage"};
    return s;
}

bool has_keep_prefix(const std::wstring& key) { return starts_with(key, L"microsoft") || starts_with(key, L"windows"); }

bool is_pe_suffix(const std::wstring& ext) {
    return ext == L".exe" || ext == L".dll" || ext == L".scr" || ext == L".com" || ext == L".sys";
}

double age_cutoff(double min_age_days, double now) {
    if (min_age_days <= 0) return 1e18;
    return (now < 0 ? now_seconds() : now) - min_age_days * 86400;
}

std::wstring slashes_to_backslashes(std::wstring s) {
    std::replace(s.begin(), s.end(), L'/', L'\\');
    return s;
}

std::vector<std::wstring> outermost(const std::vector<std::wstring>& folders) {
    std::set<std::wstring> unique;
    for (const auto& f : folders) unique.insert(absolute(f));
    std::vector<std::wstring> sorted(unique.begin(), unique.end());
    std::stable_sort(sorted.begin(), sorted.end(),
                     [](const std::wstring& a, const std::wstring& b) { return a.size() < b.size(); });
    std::vector<std::wstring> kept;
    for (const auto& folder : sorted) {
        std::wstring low = normcase(folder);
        bool covered = false;
        for (const auto& k : kept) {
            std::wstring kl = normcase(k);
            std::wstring prefix = kl;
            while (!prefix.empty() && prefix.back() == L'\\') prefix.pop_back();
            if (low == kl || starts_with(low, prefix + L"\\")) {
                covered = true;
                break;
            }
        }
        if (!covered) kept.push_back(folder);
    }
    return kept;
}

}  // namespace

const wchar_t* confidence_name(Confidence c) {
    switch (c) {
        case Confidence::High: return L"High";
        case Confidence::Medium: return L"Medium";
        case Confidence::Low: return L"Low";
        default: return L"";
    }
}

static int confidence_order(Confidence c) {
    switch (c) {
        case Confidence::High: return 0;
        case Confidence::Medium: return 1;
        case Confidence::Low: return 2;
        default: return 3;
    }
}

const std::vector<Preset>& presets() {
    static const std::vector<Preset> list = {
        {L"Temporary files", L"*.tmp;*.temp;*.swp;*.swo;*.orig;*.rej"},
        {L"Office and editor lock files", L"~$*;.~lock.*;*.lck"},
        {L"Incomplete downloads", L"*.crdownload;*.part;*.partial;*.download;*.opdownload"},
        {L"Backups and old copies", L"*.bak;*.old;*.backup;*~"},
        {L"Duplicate copies", L"* - Copy*;* - Copie*;Copie de *;* (1).*;* (2).*"},
        {L"Crash dumps and error reports",
         L"*.dmp;*.mdmp;*.stackdump;hs_err_pid*;\"npm-debug.log\";\"yarn-error.log\";\"pip-log.txt\""},
        {L"Log files", L"*.log;*.etl"},
        {L"System thumbnails and junk", L"\"Thumbs.db\";\"ehthumbs.db\";\".DS_Store\";\"__MACOSX\";._*;*.chk"},
        {L"Python caches",
         L"\"__pycache__\";*.pyc;*.pyo;\".pytest_cache\";\".mypy_cache\";\".ruff_cache\";\".ipynb_checkpoints\";"
         L"\".tox\";\".hypothesis\";*.egg-info"},
        {L"IDE project folders", L"\".vscode\";\".idea\";\".vs\";\".history\""},
        {L"Browser and Electron caches",
         L"\"Cache\";\"Code Cache\";\"GPUCache\";\"GrShaderCache\";\"ShaderCache\";\"DawnCache\""},
        {L"Installers and disk images", L"*setup*.exe;*install*.exe;*.msi;*.iso;*.dmg"},
        {L"AI tool leftovers", L"tmpclaude-*;\"nul\";.aider.tags.cache*;\".aider.chat.history.md\";\".aider.input.history\""},
    };
    return list;
}

// region Patterns

bool wildcard_match(const std::wstring& p, const std::wstring& t) {
    std::size_t pi = 0, ti = 0, star = std::wstring::npos, mark = 0;
    while (ti < t.size()) {
        if (pi < p.size() && (p[pi] == L'?' || p[pi] == t[ti])) {
            ++pi;
            ++ti;
        } else if (pi < p.size() && p[pi] == L'*') {
            star = pi++;
            mark = ti;
        } else if (star != std::wstring::npos) {
            pi = star + 1;
            ti = ++mark;
        } else {
            return false;
        }
    }
    while (pi < p.size() && p[pi] == L'*') ++pi;
    return pi == p.size();
}

Matcher::Matcher(const std::wstring& text) {
    for (const auto& raw : split(text, L';')) {
        std::wstring term = trim(raw);
        if (term.empty()) continue;
        bool exact = term.size() >= 2 && term.front() == L'"' && term.back() == L'"';
        if (exact) term = term.substr(1, term.size() - 2);
        else if (term.find_first_of(L"*?") == std::wstring::npos) term = L"*" + term + L"*";
        bool on_path = term.find_first_of(L"\\/") != std::wstring::npos;
        rules_.push_back({lower(on_path ? slashes_to_backslashes(term) : term), on_path});
    }
    if (rules_.empty()) throw std::invalid_argument("Enter a word or a wildcard pattern, for example *.vscode");
}

bool Matcher::operator()(const std::wstring& name, const std::wstring& path) const {
    std::wstring low_name, low_path;
    for (const Rule& r : rules_) {
        if (r.on_path) {
            if (low_path.empty()) low_path = lower(slashes_to_backslashes(path));
            if (wildcard_match(r.pattern, low_path)) return true;
        } else {
            if (low_name.empty()) low_name = lower(name);
            if (wildcard_match(r.pattern, low_name)) return true;
        }
    }
    return false;
}

// endregion

// region Locations

std::vector<std::wstring> search_roots(Where where, const std::wstring& custom) {
    std::vector<std::wstring> roots;
    switch (where) {
        case Where::Profile: roots = {known_folder(CSIDL_PROFILE)}; break;
        case Where::AppData:
            roots = {known_folder(CSIDL_ROAMING), known_folder(CSIDL_LOCAL), known_folder(CSIDL_PROGRAMDATA), temp_dir()};
            break;
        case Where::Drives: roots = fixed_drives(); break;
        case Where::Custom: roots = {custom}; break;
    }
    std::vector<std::wstring> existing;
    for (const auto& r : roots) {
        if (!r.empty() && is_dir(r)) existing.push_back(r);
    }
    return outermost(existing);
}

bool is_kept_folder(const std::wstring& name, bool dir) { return dir && ends_with(name, L"~"); }

// endregion

// region Search

FileScan search_files(const std::wstring& patterns, const std::vector<std::wstring>& roots, const Stop& stop,
                      const Progress& progress, std::size_t limit, double min_age_days, double now) {
    Matcher match(patterns);
    double cutoff = age_cutoff(min_age_days, now);
    FileScan scan;
    std::wstring windows = normcase(system_root());
    std::vector<std::wstring> stack(roots.rbegin(), roots.rend());
    std::vector<Entry> entries;
    while (!stack.empty() && !stop()) {
        std::wstring folder = stack.back();
        stack.pop_back();
        ++scan.folders_seen;
        if (progress && scan.folders_seen % 400 == 0) {
            progress(L"Searching... " + std::to_wstring(scan.folders_seen) + L" folders looked at, " +
                     std::to_wstring(scan.items.size()) + L" found");
        }
        if (!list_dir(folder, entries)) continue;
        std::vector<std::wstring> subfolders;
        for (const Entry& e : entries) {
            if (e.is_link()) continue;   // links are never listed or crossed
            bool dir = e.is_dir();
            if (!is_kept_folder(e.name, dir) && match(e.name, e.path)) {
                if (e.modified > cutoff) continue;
                std::uint64_t size = dir ? folder_size(e.path, stop) : e.size;
                scan.items.push_back({e.path, dir ? Kind::Folder : Kind::File, size, e.modified, L"Matches the search"});
                if (scan.items.size() >= limit) {
                    scan.truncated = true;
                    return scan;
                }
            } else if (dir && !skipped_folders().count(lower(e.name)) && normcase(e.path) != windows) {
                subfolders.push_back(e.path);
            }
        }
        stack.insert(stack.end(), subfolders.rbegin(), subfolders.rend());
    }
    return scan;
}

// endregion

// region Leftovers

std::vector<LeftoverParent> leftover_parents() {
    return {{L"AppData\\Roaming", known_folder(CSIDL_ROAMING), false},
            {L"AppData\\Local", known_folder(CSIDL_LOCAL), false},
            {L"ProgramData", known_folder(CSIDL_PROGRAMDATA), false},
            {L"Program Files", known_folder(CSIDL_PROGRAMFILES), true},
            {L"Program Files (x86)", known_folder(CSIDL_PROGRAMFILES86), true}};
}

bool is_covered(const std::wstring& folder_name, const std::set<std::wstring>& markers) {
    std::wstring key = norm_key(folder_name);
    // too short to judge counts as covered: better to miss a leftover than to accuse a live program
    if (key.size() < 3 || keep_folders().count(key) || markers.count(key)) return true;
    for (const auto& m : markers) {
        if (m.size() >= 5 && key.find(m) != std::wstring::npos) return true;
        if (key.size() >= 5 && m.find(key) != std::wstring::npos) return true;
    }
    return false;
}

// A folder too big to look through counts as having a program file: a wrong "nothing left" would be the worst mistake.
static bool has_program_files(const std::wstring& folder, const Stop& stop, long budget = 60000) {
    std::vector<std::wstring> stack{folder};
    std::vector<Entry> entries;
    while (!stack.empty() && !stop()) {
        if (budget <= 0) return true;
        std::wstring current = stack.back();
        stack.pop_back();
        if (!list_dir(current, entries)) continue;
        for (const Entry& e : entries) {
            --budget;
            if (e.is_dir() && !e.is_link()) stack.push_back(e.path);
            else if (!e.is_dir() && is_pe_suffix(extension(e.name))) return true;
        }
    }
    return false;
}

FileScan find_leftovers(const std::set<std::wstring>& markers, const Stop& stop, const Progress& progress,
                        const std::vector<LeftoverParent>* parents_in, double now_in, double min_age_days) {
    std::vector<LeftoverParent> parents = parents_in ? *parents_in : leftover_parents();
    double now = now_in < 0 ? now_seconds() : now_in;
    double cutoff = age_cutoff(min_age_days, now);
    FileScan scan;
    for (const auto& parent : parents) {
        if (parent.folder.empty() || !is_dir(parent.folder)) continue;
        if (progress) progress(L"Looking at " + parent.label + L"...");
        std::vector<Entry> entries;
        if (!list_dir(parent.folder, entries)) continue;
        std::sort(entries.begin(), entries.end(),
                  [](const Entry& a, const Entry& b) { return lower(a.name) < lower(b.name); });
        for (const Entry& e : entries) {
            if (stop()) return scan;
            if (!e.is_dir() || (e.attributes & (ATTR_REPARSE | ATTR_SYSTEM))) continue;
            std::wstring key = norm_key(e.name);
            if (key.size() < 3 || keep_folders().count(key) || has_keep_prefix(key) || ends_with(e.name, L"~")) continue;
            ++scan.folders_seen;
            if (e.modified > cutoff) continue;
            bool covered = is_covered(e.name, markers);
            double age_days = (now - e.modified) / 86400;
            Confidence confidence;
            std::wstring reason;
            if (parent.program_files) {
                if (!has_program_files(e.path, stop)) {
                    confidence = Confidence::High;
                    reason = parent.label + L": no program file left inside";
                } else if (covered) {
                    continue;
                } else {
                    confidence = Confidence::Low;
                    reason = parent.label + L": not listed in installed programs (portable or manual copy?)";
                }
            } else if (covered) {
                continue;
            } else if (age_days >= OLD_FOLDER_DAYS) {
                confidence = Confidence::Medium;
                reason = parent.label + L": no installed program matches, last changed " + format_date(e.modified);
            } else {
                confidence = Confidence::Low;
                reason = parent.label + L": no installed program matches, changed recently";
            }
            scan.items.push_back({e.path, Kind::Folder, folder_size(e.path, stop), e.modified, reason, confidence});
        }
    }
    std::stable_sort(scan.items.begin(), scan.items.end(), [](const GarbageItem& a, const GarbageItem& b) {
        int ca = confidence_order(a.confidence), cb = confidence_order(b.confidence);
        return ca != cb ? ca < cb : a.size > b.size;
    });
    return scan;
}

// endregion

// region Summaries

FileScan merge_scans(const FileScan& first, const FileScan& second) {
    std::vector<GarbageItem> order;
    std::map<std::wstring, std::size_t> index;
    auto add = [&](const GarbageItem& item, bool replace_if_confident) {
        std::wstring key = normcase(item.path);
        auto it = index.find(key);
        if (it == index.end()) {
            index[key] = order.size();
            order.push_back(item);
        } else if (replace_if_confident && item.confidence != Confidence::None) {
            order[it->second] = item;
        }
    };
    for (const auto& i : first.items) add(i, false);
    for (const auto& i : second.items) add(i, true);
    FileScan merged;
    merged.items = order;
    merged.truncated = first.truncated || second.truncated;
    merged.folders_seen = first.folders_seen + second.folders_seen;
    return merged;
}

std::wstring categorize(const GarbageItem& item) {
    if (item.confidence != Confidence::None) {
        return L"Leftover folders (" + lower(confidence_name(item.confidence)) + L" confidence)";
    }
    static std::vector<std::pair<std::wstring, Matcher>>* matchers = [] {
        auto* v = new std::vector<std::pair<std::wstring, Matcher>>();
        for (const auto& p : presets()) v->emplace_back(p.name, Matcher(p.patterns));
        return v;
    }();
    std::wstring name = base_name(item.path);
    for (const auto& [label, match] : *matchers) {
        if (match(name, item.path)) return label;
    }
    return L"Other matches";
}

bool is_likely(const GarbageItem& item) { return item.confidence != Confidence::Low; }

std::vector<CategoryTotal> summarize(const std::vector<GarbageItem>& items) {
    std::map<std::wstring, CategoryTotal> totals;
    for (const auto& item : items) {
        std::wstring c = categorize(item);
        auto& t = totals.try_emplace(c, CategoryTotal{c, 0, 0}).first->second;
        ++t.count;
        t.bytes += item.size;
    }
    std::vector<CategoryTotal> out;
    for (auto& kv : totals) out.push_back(kv.second);
    std::stable_sort(out.begin(), out.end(), [](const CategoryTotal& a, const CategoryTotal& b) { return a.bytes > b.bytes; });
    return out;
}

std::map<std::wstring, std::uint64_t> size_by_drive(const std::vector<GarbageItem>& items) {
    std::map<std::wstring, std::uint64_t> totals;
    for (const auto& item : items) {
        if (item.path.size() >= 2 && item.path[1] == L':') {
            totals[lower(item.path.substr(0, 2))] += item.size;
        }
    }
    return totals;
}

std::uint64_t FolderUsage::total() const {
    std::uint64_t sum = loose_files;
    for (const auto& f : folders) sum += f.second;
    return sum;
}

FolderUsage folder_usage(const std::wstring& root, const Stop& stop, const Progress& progress, unsigned workers) {
    FolderUsage result;
    result.root = root;
    std::vector<Entry> entries;
    if (!list_dir(root, entries)) return result;
    std::vector<std::wstring> children;
    for (const Entry& e : entries) {
        if (e.is_link()) continue;
        if (e.is_dir()) children.push_back(e.path);
        else result.loose_files += e.size;
    }
    std::vector<std::uint64_t> sizes(children.size(), 0);
    std::atomic<std::size_t> next{0}, done{0};
    std::mutex progress_lock;
    auto work = [&] {
        for (std::size_t i; (i = next++) < children.size();) {
            sizes[i] = folder_size(children[i], stop, 2000000);
            std::size_t d = ++done;
            if (progress) {
                std::lock_guard<std::mutex> g(progress_lock);
                progress(L"Measuring folders... " + std::to_wstring(d) + L"/" + std::to_wstring(children.size()));
            }
        }
    };
    std::vector<std::thread> pool;
    for (unsigned i = 0; i < std::max(1u, workers); ++i) pool.emplace_back(work);
    for (auto& t : pool) t.join();
    for (std::size_t i = 0; i < children.size(); ++i) result.folders.emplace_back(children[i], sizes[i]);
    result.truncated = stop();
    std::stable_sort(result.folders.begin(), result.folders.end(),
                     [](const auto& a, const auto& b) { return a.second > b.second; });
    return result;
}

// endregion

// region Deleting

std::wstring protected_reason(const std::wstring& path) {
    if (path.empty() || !is_absolute(path)) return L"Not an absolute path";
    std::wstring full = normcase(absolute(path));
    if (dir_name(full) == full || (full.size() <= 3 && full.size() >= 2 && full[1] == L':')) return L"Drive root";
    if (is_dir(path) && is_kept_folder(base_name(path), true)) {
        return L"Folder ending with ~ (a Unity package folder such as Samples~): kept";
    }
    std::wstring windows = normcase(system_root());
    if (full == windows || starts_with(full, windows + L"\\")) return L"Inside the Windows folder";
    std::vector<std::wstring> essential;
    for (int code : CSIDL_VALUES) {
        std::wstring f = known_folder(code);
        if (!f.empty()) essential.push_back(normcase(absolute(f)));
    }
    essential.push_back(normcase(absolute(exe_dir())));
    essential.push_back(windows);
    essential.push_back(normcase(absolute(temp_dir())));
    for (const auto& e : essential) {
        if (e == full || starts_with(e, full + L"\\")) {
            return L"Essential folder (profile, Documents, Program Files, AppData or this program)";
        }
    }
    Entry info;
    if (stat_path(is_reserved_name(path) ? long_path(path) : path, info) && info.is_link()) return L"Link or junction";
    return L"";
}

std::wstring recycle_path(const std::wstring& path) {
    std::wstring source = absolute(path);
    source.push_back(L'\0');   // the API wants a double NUL
    SHFILEOPSTRUCTW op{};
    op.wFunc = FO_DELETE;
    op.pFrom = source.c_str();
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    int code = SHFileOperationW(&op);
    if (code || op.fAnyOperationsAborted) {
        return L"Windows could not move it to the Recycle Bin (code " + std::to_wstring(code) + L")";
    }
    return L"";
}

static std::wstring last_error_text(DWORD code) {
    wchar_t* buf = nullptr;
    DWORD n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, code, 0, (LPWSTR)&buf, 0, nullptr);
    std::wstring text = n ? trim(std::wstring(buf, n)) : L"error " + std::to_wstring(code);
    if (buf) LocalFree(buf);
    return text;
}

static DWORD remove_tree(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        DWORD e = GetLastError();
        return (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) ? 0 : e;
    }
    if (attrs & FILE_ATTRIBUTE_READONLY) SetFileAttributesW(path.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        if (!(attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {   // a link is removed itself, its target is never entered
            std::vector<Entry> entries;
            list_dir(path, entries);
            for (const Entry& e : entries) {
                DWORD rc = remove_tree(e.path);
                if (rc) return rc;
            }
        }
        return RemoveDirectoryW(path.c_str()) ? 0 : GetLastError();
    }
    return DeleteFileW(path.c_str()) ? 0 : GetLastError();
}

static std::wstring remove_for_good(const std::wstring& path) {
    std::wstring target = is_reserved_name(path) ? long_path(path) : path;
    DWORD rc = remove_tree(target);
    return rc ? last_error_text(rc) : L"";
}

DeleteResult delete_items(const std::vector<GarbageItem>& items, bool permanent, const Stop& stop,
                          const std::function<std::wstring(const std::wstring&)>& recycle) {
    DeleteResult result;
    for (const auto& item : items) {
        if (stop()) {
            result.failed.emplace_back(item, L"Stopped");
            continue;
        }
        std::wstring reason = protected_reason(item.path);
        if (!reason.empty()) {
            result.failed.emplace_back(item, reason);
            continue;
        }
        bool reserved = is_reserved_name(item.path);
        if (!lexists(reserved ? long_path(item.path) : item.path)) {
            result.deleted.push_back(item);   // already gone
            continue;
        }
        std::wstring error = (permanent || reserved) ? remove_for_good(item.path) : recycle(item.path);
        if (!error.empty()) {
            result.failed.emplace_back(item, error);
            continue;
        }
        result.deleted.push_back(item);
        result.freed += item.size;
    }
    return result;
}

// endregion

}  // namespace dd
