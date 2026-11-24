// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Self-contained tests of the core: a temporary folder tree is built, then searched and deleted, with the string and pattern checks.

#include <cstdio>
#include <stdexcept>

#include <windows.h>

#include <ddcore/dead_registry.hpp>
#include <ddcore/garbage.hpp>
#include <ddcore/startup.hpp>

using namespace dd;

static int failures = 0, checks = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        ++checks;                                                                \
        if (!(cond)) {                                                           \
            ++failures;                                                          \
            std::fprintf(stderr, "FAILED %s:%d  %s\n", __FILE__, __LINE__, #cond); \
        }                                                                        \
    } while (0)

// A failed check that later code depends on stops the test instead of crashing it.
#define REQUIRE(cond)                                                              \
    do {                                                                           \
        ++checks;                                                                  \
        if (!(cond)) {                                                             \
            ++failures;                                                            \
            std::fprintf(stderr, "FAILED %s:%d  %s\n", __FILE__, __LINE__, #cond); \
            return;                                                                \
        }                                                                          \
    } while (0)

static void touch(const std::wstring& path, const std::string& text = "x") {
    std::wstring folder = dir_name(path.rfind(L"\\\\?\\", 0) == 0 ? path.substr(4) : path);
    CreateDirectoryW(folder.c_str(), nullptr);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, text.data(), (DWORD)text.size(), &written, nullptr);
    CloseHandle(h);
}

static GarbageItem folder_item(const std::wstring& path) {
    GarbageItem item;
    item.path = path;
    item.kind = Kind::Folder;
    return item;
}

static void test_strings() {
    CHECK(norm_key(L"Foo-Bar 2.0!") == L"foobar20");
    CHECK(human_size(512) == L"512 B");
    CHECK(human_size(2048) == L"2.0 KB");
    CHECK(base_name(L"C:\\a\\b.txt") == L"b.txt");
    CHECK(dir_name(L"C:\\a\\b.txt") == L"C:\\a");
    CHECK(dir_name(L"C:\\a") == L"C:\\");
    CHECK(extension(L"x\\File.TMP") == L".tmp");
    CHECK(is_reserved_name(L"C:\\x\\nul"));
    CHECK(is_reserved_name(L"C:\\x\\COM3.txt"));
    CHECK(!is_reserved_name(L"C:\\x\\null.txt"));
}

static void test_patterns() {
    CHECK(wildcard_match(L"*.tmp", L"a.tmp"));
    CHECK(!wildcard_match(L"*.tmp", L"a.tmp2"));
    CHECK(wildcard_match(L"a?c", L"abc"));
    CHECK(wildcard_match(L"*", L""));
    Matcher m(L"*.tmp;\"Thumbs.db\";cache");
    CHECK(m(L"FILE.TMP", L"C:\\FILE.TMP"));
    CHECK(m(L"thumbs.db", L"C:\\thumbs.db"));
    CHECK(!m(L"mythumbs.db", L"C:\\mythumbs.db"));   // quoted means exact name
    CHECK(m(L"mycache1", L"C:\\mycache1"));          // a word alone means contains
    CHECK(!m(L"other", L"C:\\other"));
    Matcher on_path(L"*\\sub\\*.log");
    CHECK(on_path(L"a.log", L"C:\\x\\sub\\a.log"));
    CHECK(on_path(L"a.log", L"C:/x/sub/a.log"));
    bool threw = false;
    try { Matcher empty(L" ; "); } catch (const std::invalid_argument&) { threw = true; }
    CHECK(threw);
}

static void test_search_and_delete() {
    std::wstring root = temp_dir() + L"\\ddcore_test_" + std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(root.c_str(), nullptr);
    touch(root + L"\\keep.txt");
    touch(root + L"\\a.tmp", "12345");
    touch(root + L"\\sub\\b.tmp", "123");
    touch(root + L"\\sub\\__pycache__\\x.pyc", "1234567890");
    touch(root + L"\\Samples~\\c.dat");   // a folder ending with ~ is never garbage itself

    FileScan scan = search_files(L"*.tmp;\"__pycache__\"", {root});
    CHECK(scan.items.size() == 3);
    std::uint64_t total = 0;
    for (const auto& i : scan.items) total += i.size;
    CHECK(total == 5 + 3 + 10);
    CHECK(search_files(L"samples*", {root}).items.empty());   // the folder is never listed

    FileScan limited = search_files(L"*.tmp", {root}, never, nullptr, 1);
    CHECK(limited.truncated && limited.items.size() == 1);

    FileScan none = search_files(L"*.tmp", {root}, never, nullptr, SEARCH_LIMIT, 30);
    CHECK(none.items.empty());   // everything is newer than 30 days

    CHECK(!summarize(scan.items).empty());
    CHECK(summarize(scan.items)[0].category == L"Python caches");

    CHECK(!protected_reason(L"C:\\").empty());
    CHECK(!protected_reason(system_root()).empty());
    CHECK(!protected_reason(L"relative\\path").empty());
    CHECK(!protected_reason(root + L"\\Samples~").empty());
    CHECK(protected_reason(root + L"\\a.tmp").empty());

    DeleteResult refused = delete_items({folder_item(L"C:\\")});
    CHECK(refused.deleted.empty() && refused.failed.size() == 1);

    DeleteResult r = delete_items(scan.items, true);
    CHECK(r.failed.empty());
    CHECK(r.freed == 18);
    CHECK(!lexists(root + L"\\a.tmp"));
    CHECK(!lexists(root + L"\\sub\\__pycache__"));
    CHECK(lexists(root + L"\\keep.txt"));
    CHECK(lexists(root + L"\\Samples~\\c.dat"));

    // a file named like a device can only be reached by its extended-length path
    touch(L"\\\\?\\" + root + L"\\nul", "junk");
    FileScan dev = search_files(L"\"nul\"", {root});
    CHECK(dev.items.size() == 1);
    DeleteResult d = delete_items(dev.items, false);
    CHECK(d.failed.empty());
    CHECK(!lexists(L"\\\\?\\" + root + L"\\nul"));

    DeleteResult again = delete_items(scan.items, true);
    CHECK(again.deleted.size() == scan.items.size());   // already gone counts as done

    delete_items({folder_item(root)}, true);
    CHECK(!lexists(root));
}

static void test_usage() {
    std::wstring root = temp_dir() + L"\\ddcore_usage_" + std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(root.c_str(), nullptr);
    touch(root + L"\\loose.bin", std::string(100, 'a'));
    touch(root + L"\\big\\a.bin", std::string(5000, 'a'));
    touch(root + L"\\big\\deep\\b.bin", std::string(3000, 'a'));
    touch(root + L"\\small\\c.bin", std::string(10, 'a'));
    FolderUsage u = folder_usage(root);
    REQUIRE(u.folders.size() == 2);
    CHECK(u.folders[0].first == root + L"\\big" && u.folders[0].second == 8000);   // biggest first, subfolders counted
    CHECK(u.folders[1].second == 10);
    CHECK(u.loose_files == 100);
    CHECK(u.total() == 8110);
    CHECK(folder_size(root) == 8110);
    auto drives = drive_usage(fixed_drives());
    CHECK(!drives.empty());
    for (const auto& d : drives) CHECK(d.used + d.free == d.total);
    delete_items({folder_item(root)}, true);
}

static void test_leftovers() {
    std::wstring root = temp_dir() + L"\\ddcore_left_" + std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(root.c_str(), nullptr);
    touch(root + L"\\Gone Program\\data.bin");
    touch(root + L"\\Live Program\\data.bin");
    touch(root + L"\\Emptied\\readme.txt");
    std::vector<LeftoverParent> parents = {{L"Test", root, false}};
    double now = now_seconds() + 200 * 86400;   // everything looks old
    FileScan scan = find_leftovers({L"liveprogram"}, never, nullptr, &parents, now);
    bool gone = false, live = false;
    for (const auto& i : scan.items) {
        if (i.path.find(L"Gone Program") != std::wstring::npos) gone = true;
        if (i.path.find(L"Live Program") != std::wstring::npos) live = true;
    }
    CHECK(gone);
    CHECK(!live);
    CHECK(is_covered(L"Live Program", {L"liveprogram"}));
    CHECK(is_covered(L"ab", {}));            // too short to judge
    CHECK(is_covered(L"Microsoft", {}));     // Windows folder
    CHECK(!is_covered(L"Gone Program", {L"liveprogram"}));
    // Program Files style: no program file inside means High confidence
    std::vector<LeftoverParent> pf_parents = {{L"Program Files", root, true}};
    FileScan pf = find_leftovers({}, never, nullptr, &pf_parents, now);
    for (const auto& i : pf.items) CHECK(i.confidence == Confidence::High);
    delete_items({folder_item(root)}, true);
}

static void test_registry_and_startup() {
    CHECK(check_target(L"").state == TargetState::Unknown);
    CHECK(check_target(L"relative\\x.exe").state == TargetState::Unknown);
    CHECK(check_target(L"\"C:\\definitely\\not\\here\\app.exe\"").state == TargetState::Missing);
    CHECK(check_target(system32() + L"\\cmd.exe").state == TargetState::Unknown);   // inside Windows: no verdict
    CHECK(check_target(exe_dir(), true).state == TargetState::Ok);
    CHECK(check_target(L"\"\\\\server\\share\\a.exe\"").state == TargetState::Unknown);

    // command lines
    CHECK(command_path(L"\"" + system32() + L"\\cmd.exe\" /c echo") == system32() + L"\\cmd.exe");
    CHECK(command_path(system32() + L"\\cmd.exe /c echo") == system32() + L"\\cmd.exe");
    CHECK(lower(command_path(L"notepad")) == lower(system32() + L"\\notepad.exe"));
    CHECK(command_path(L"nothing-like-this") == L"");
    CHECK(command_path(L"relative\\cmd.exe") == L"");

    // the real machine: these must simply run and return sane data
    auto markers = installed_markers();
    CHECK(!markers.empty());
    for (const auto& m : markers) CHECK(m.size() >= 3);
    auto dead = scan_dead();
    for (const auto& e : dead) CHECK(!e.category.empty() && !e.hive.empty());
    auto entries = collect_startup();
    for (const auto& e : entries) CHECK(!e.name.empty());
    std::printf("  machine: %zu markers, %zu dead registry entries, %zu startup entries\n", markers.size(), dead.size(),
                entries.size());
}

int run_second_layer_tests();
int run_sysinfo_tests();
int run_driver_tests();
int run_blocklist_tests();
int run_firewall_tests();
int run_traffic_tests();
int run_hunt_tests();
int run_antivirus_tests();
int run_online_tests();
int run_audit_tests();
int run_tweaks_tests();
int run_secrets_tests();

int main() {
    test_strings();
    test_patterns();
    test_search_and_delete();
    test_usage();
    test_leftovers();
    test_registry_and_startup();
    std::printf("%d checks, %d failed\n", checks, failures);
    failures += run_second_layer_tests();
    failures += run_sysinfo_tests();
    failures += run_driver_tests();
    failures += run_blocklist_tests();
    failures += run_firewall_tests();
    failures += run_traffic_tests();
    failures += run_hunt_tests();
    failures += run_antivirus_tests();
    failures += run_online_tests();
    failures += run_audit_tests();
    failures += run_tweaks_tests();
    failures += run_secrets_tests();
    return failures ? 1 : 0;
}
