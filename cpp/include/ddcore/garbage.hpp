// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the leftover file search and the deletion of exact items to the Recycle Bin, with its presets and matcher.

// Garbage left on disk: wildcard search, leftovers of programs that are no longer installed, and deletion.
// Searching never changes anything. Deleting only touches the exact items passed, sends them to the Recycle Bin
// unless told otherwise, and refuses essential folders.
#pragma once

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <ddcore/common.hpp>

namespace dd {

enum class Kind { File, Folder };
enum class Confidence { None, High, Medium, Low };

const wchar_t* confidence_name(Confidence c);

struct GarbageItem {
    std::wstring path;
    Kind kind = Kind::File;
    std::uint64_t size = 0;
    double modified = 0;
    std::wstring reason;
    Confidence confidence = Confidence::None;   // leftovers only
};

struct FileScan {
    std::vector<GarbageItem> items;
    bool truncated = false;
    std::size_t folders_seen = 0;
};

struct DeleteResult {
    std::vector<GarbageItem> deleted;
    std::vector<std::pair<GarbageItem, std::wstring>> failed;
    std::uint64_t freed = 0;
};

struct Preset {
    const wchar_t* name;
    const wchar_t* patterns;
};
const std::vector<Preset>& presets();

enum class Where { Profile, AppData, Drives, Custom };
constexpr std::size_t SEARCH_LIMIT = 5000;
constexpr double OLD_FOLDER_DAYS = 90;

// region Patterns
// 'a;b;c'. A word alone means "contains", * and ? are wildcards, "name" in quotes is an exact name. A term with a
// slash is matched against the whole path, the others against the file or folder name.
class Matcher {
public:
    explicit Matcher(const std::wstring& text);   // throws std::invalid_argument when empty
    bool operator()(const std::wstring& name, const std::wstring& path) const;

private:
    struct Rule {
        std::wstring pattern;   // lower case
        bool on_path;
    };
    std::vector<Rule> rules_;
};

// Case-insensitive wildcard match of the whole text ('*' any run, '?' one character).
bool wildcard_match(const std::wstring& lower_pattern, const std::wstring& lower_text);
// endregion

std::vector<std::wstring> search_roots(Where where, const std::wstring& custom = L"");

bool is_kept_folder(const std::wstring& name, bool is_dir);   // a folder ending with '~' is never garbage

FileScan search_files(const std::wstring& patterns, const std::vector<std::wstring>& roots,
                      const Stop& stop = never, const Progress& progress = nullptr,
                      std::size_t limit = SEARCH_LIMIT, double min_age_days = 0, double now = -1);

// Leftovers: folders of AppData, ProgramData and Program Files that no installed program claims.
struct LeftoverParent {
    std::wstring label, folder;
    bool program_files;
};
std::vector<LeftoverParent> leftover_parents();
bool is_covered(const std::wstring& folder_name, const std::set<std::wstring>& markers);
FileScan find_leftovers(const std::set<std::wstring>& markers, const Stop& stop = never,
                        const Progress& progress = nullptr, const std::vector<LeftoverParent>* parents = nullptr,
                        double now = -1, double min_age_days = 0);

FileScan merge_scans(const FileScan& first, const FileScan& second);
std::wstring categorize(const GarbageItem& item);
bool is_likely(const GarbageItem& item);   // counted as space that can really be freed
struct CategoryTotal {
    std::wstring category;
    std::size_t count;
    std::uint64_t bytes;
};
std::vector<CategoryTotal> summarize(const std::vector<GarbageItem>& items);
std::map<std::wstring, std::uint64_t> size_by_drive(const std::vector<GarbageItem>& items);

struct FolderUsage {
    std::wstring root;
    std::vector<std::pair<std::wstring, std::uint64_t>> folders;   // biggest first
    std::uint64_t loose_files = 0;
    bool truncated = false;
    std::uint64_t total() const;
};
FolderUsage folder_usage(const std::wstring& root, const Stop& stop = never, const Progress& progress = nullptr,
                         unsigned workers = 8);

// Why this path must never be deleted from here ("" when it is allowed).
std::wstring protected_reason(const std::wstring& path);
std::wstring recycle_path(const std::wstring& path);   // "" or an error message

DeleteResult delete_items(const std::vector<GarbageItem>& items, bool permanent = false,
                          const Stop& stop = never,
                          const std::function<std::wstring(const std::wstring&)>& recycle = recycle_path);

}  // namespace dd
