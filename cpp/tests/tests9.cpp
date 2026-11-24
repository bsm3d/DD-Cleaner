// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Tests the ClamAV integration: commands, output parsing, quarantine, scan cache, scan plan, YARA rules and a real scan.

#include <cstdio>
#include <stdexcept>

#include <windows.h>

#include <ddcore/antivirus.hpp>

using namespace dd;

static int failures = 0, checks = 0;

#define CHECK(cond)                                                                \
    do {                                                                           \
        ++checks;                                                                  \
        if (!(cond)) {                                                             \
            ++failures;                                                            \
            std::fprintf(stderr, "FAILED %s:%d  %s\n", __FILE__, __LINE__, #cond); \
        }                                                                          \
    } while (0)

static std::wstring work(const wchar_t* name) {
    std::wstring dir = join(exe_dir(), std::wstring(name) + L"_" + std::to_wstring(GetCurrentProcessId()));
    make_dirs(dir);
    return dir;
}

static void remove_tree_files(const std::wstring& dir) {
    std::vector<Entry> entries;
    if (list_dir(dir, entries)) {
        for (const auto& e : entries) {
            if (e.is_dir()) remove_tree_files(e.path);
            else {
                SetFileAttributesW(e.path.c_str(), FILE_ATTRIBUTE_NORMAL);
                delete_file(e.path);
            }
        }
    }
    RemoveDirectoryW(dir.c_str());
}

static bool has(const std::vector<std::wstring>& list, const std::wstring& item) {
    for (const auto& x : list) {
        if (x == item) return true;
    }
    return false;
}

static void test_output_parsing() {
    auto found = parse_scan_line(L"C:\\Users\\me\\Downloads\\bad.exe: Win.Test.EICAR_HDB-1 FOUND");
    CHECK(found.kind == L"found" && found.a == L"C:\\Users\\me\\Downloads\\bad.exe" && found.b == L"Win.Test.EICAR_HDB-1");
    auto moved = parse_scan_line(L"C:\\x\\bad.exe: moved to 'D:\\q\\bad.exe'");
    CHECK(moved.kind == L"moved" && moved.a == L"C:\\x\\bad.exe" && moved.b == L"D:\\q\\bad.exe");
    CHECK(parse_scan_line(L"C:\\x\\fine.txt: OK").kind == L"ok" && parse_scan_line(L"C:\\x\\fine.txt: OK").a == L"C:\\x\\fine.txt");
    CHECK(parse_scan_line(L"C:\\x\\empty.txt: Empty file").kind == L"skip");
    CHECK(parse_scan_line(L"C:\\x\\link: Symbolic link").kind == L"skip");
    CHECK(parse_scan_line(L"C:\\x\\locked.bin: Access denied ERROR").kind == L"error");
    auto summary = parse_scan_line(L"Scanned files: 1234");
    CHECK(summary.kind == L"summary" && summary.a == L"files" && summary.b == L"1234");
    CHECK(parse_scan_line(L"Known viruses: 8700000").a == L"signatures" && parse_scan_line(L"Infected files: 2").a == L"infected");
    CHECK(parse_scan_line(L"----------- SCAN SUMMARY -----------").kind == L"other" && parse_scan_line(L"----------- SCAN SUMMARY -----------").a.empty());
    CHECK(parse_scan_line(L"Start Date: 2026:11:21 10:00:00").a.empty() && parse_scan_line(L"Data read: 1.00 MB").a.empty());
    CHECK(parse_scan_line(L"LibClamAV Warning: something").kind == L"other");
    auto path_with_colon = parse_scan_line(L"C:\\a: b\\c.exe: Some.Threat FOUND");
    CHECK(path_with_colon.a == L"C:\\a: b\\c.exe" && path_with_colon.b == L"Some.Threat");   // the threat is after the LAST ": "

    CHECK(format_duration(75) == L"1 min 15 s" && format_duration(3725) == L"1 h 02 min 05 s" && format_duration(5) == L"0 min 05 s");
    CHECK(shorten(L"short") == L"short" && shorten(std::wstring(300, L'a'), 11) == L"aaaa...aaaa");
    CHECK(parse_build_time(L"11 Oct 2026 08-00 +0000") > 0 && parse_build_time(L"garbage") == 0 && parse_build_time(L"11 Xyz 2026 08-00") == 0);
    CHECK(parse_build_time(L"12 Oct 2026 08-00") - parse_build_time(L"11 Oct 2026 08-00") == 86400);
}

static void test_commands() {
    ClamInstall install{L"C:\\Program Files\\ClamAV", L"C:\\Program Files\\ClamAV\\clamscan.exe", L"C:\\Program Files\\ClamAV\\freshclam.exe"};
    ScanCommandOptions o;
    o.database = L"D:\\db";
    o.clam_folder = L"D:\\Data (x)\\clam";
    auto cmd = build_scan_command(install, {L"C:\\Users\\me"}, o);
    CHECK(cmd[0] == install.clamscan && has(cmd, L"--database=D:\\db") && has(cmd, L"--recursive") && has(cmd, L"--stdout"));
    CHECK(has(cmd, L"--follow-dir-symlinks=0") && has(cmd, L"--follow-file-symlinks=0"));
    CHECK(has(cmd, L"--heuristic-alerts=yes") && has(cmd, L"--phishing-scan-urls=yes") && has(cmd, L"--max-filesize=100M") && has(cmd, L"--max-scansize=400M"));
    CHECK(has(cmd, L"--exclude-dir=D:\\\\Data\\ \\(x\\)\\\\clam"));   // the folder is a regular expression: escaped like re.escape
    CHECK(has(cmd, L"--move=D:\\Data (x)\\clam\\quarantine") && cmd.back() == L"C:\\Users\\me");
    CHECK(!has(cmd, L"--scan-archive=no") && !has(cmd, L"--detect-pua=yes"));

    o.fast = true;
    o.quarantine = false;
    o.detect_pua = true;
    auto fast = build_scan_command(install, {L"C:\\a", L"D:\\b"}, o);
    CHECK(has(fast, L"--heuristic-alerts=no") && has(fast, L"--phishing-scan-urls=no") && has(fast, L"--scan-archive=no") && has(fast, L"--detect-pua=yes"));
    bool has_move = false;
    for (const auto& a : fast) has_move |= starts_with(a, L"--move=");
    CHECK(!has_move && fast[fast.size() - 2] == L"C:\\a" && fast.back() == L"D:\\b");

    ScanCommandOptions t;
    t.thorough = true;
    t.max_filesize_mb = 50;
    t.database = L"D:\\db";
    t.clam_folder = L"D:\\c";
    auto thorough = build_scan_command(install, {L"C:\\a"}, t);
    CHECK(has(thorough, L"--alert-encrypted=yes") && has(thorough, L"--alert-macros=yes") && has(thorough, L"--max-recursion=20") && has(thorough, L"--max-scansize=1000M"));
    t.max_filesize_mb = 99999;
    CHECK(has(build_scan_command(install, {L"C:\\a"}, t), L"--max-filesize=4000M"));   // capped
    t.max_filesize_mb = 0;
    CHECK(has(build_scan_command(install, {L"C:\\a"}, t), L"--max-filesize=1M"));

    ScanCommandOptions list;
    list.database = L"D:\\db";
    list.clam_folder = L"D:\\c";
    list.file_list = L"D:\\work\\files_0.txt";
    auto from_list = build_scan_command(install, {}, list);
    CHECK(has(from_list, L"--file-list=D:\\work\\files_0.txt") && from_list.back() == L"--file-list=D:\\work\\files_0.txt");

    auto throws = [&](const std::vector<std::wstring>& targets) {
        try {
            build_scan_command(install, targets, ScanCommandOptions{});
        } catch (const std::invalid_argument&) {
            return true;
        }
        return false;
    };
    CHECK(throws({}) && throws({L"relative\\path"}) && throws({L"--database=evil"}));   // an option-looking path is never a target

    auto update = build_update_command(install, L"D:\\c\\freshclam.conf", L"D:\\db");
    CHECK(update[0] == install.freshclam && has(update, L"--config-file=D:\\c\\freshclam.conf") && has(update, L"--datadir=D:\\db") && has(update, L"--stdout"));

    ScanOptions so;
    CHECK(so.flags() == (FLAG_ARCHIVES | FLAG_HEURISTICS));
    so.fast = true;
    CHECK(so.flags() == 0);
    so.fast = false;
    so.pua = so.thorough = true;
    CHECK(so.flags() == (FLAG_ARCHIVES | FLAG_HEURISTICS | FLAG_PUA | FLAG_THOROUGH));
    CHECK(combine_codes({0, 0}) == 0 && combine_codes({0, 1, 2}) == 1 && combine_codes({0, 2, 50}) == 2 && combine_codes({}) == 0);
    CHECK(thread_count(0, 8, 64LL << 30) == 4 && thread_count(16, 8, 64LL << 30) == 8 && thread_count(4, 2, 64LL << 30) == 2);
    CHECK(thread_count(8, 16, 5LL << 30) == 1);   // low memory: one process (each holds the signatures in memory)
    CHECK(thread_count(100, 64, 100LL << 30) == MAX_THREADS);
    CHECK(free_memory() > 0);
}

static void test_database_and_conf() {
    std::wstring dir = work(L"av_db");
    CHECK(!read_database_info(dir).ready && !read_database_info(dir + L"_missing").ready);
    write_file(join(dir, L"rules.yar"), "rule x { condition: true }");
    CHECK(!read_database_info(dir).ready);   // YARA rules alone are not a signature database
    write_file(join(dir, L"main.cvd"), "ClamAV-VDB:11 Oct 2026 08-00 +0000:63:6200000:1:abc:sig:builder:1\0padding");
    write_file(join(dir, L"daily.cld"), "ClamAV-VDB:13 Nov 2026 07-00 +0000:28000:2500000:1:abc:sig:builder:1");
    write_file(join(dir, L"custom.hdb"), "d41d8cd98f00b204e9800998ecf8427e:0:Test");
    DatabaseInfo info = read_database_info(dir);
    CHECK(info.ready && info.signatures == 6200000 + 2500000);
    CHECK(info.built == parse_build_time(L"13 Nov 2026 07-00") && info.age_days() >= 0);
    write_file(join(dir, L"bad.cvd"), "not a clamav file");
    CHECK(read_database_info(dir).signatures == 6200000 + 2500000);

    std::wstring conf = join(dir, L"freshclam.conf");
    CHECK(write_freshclam_conf(conf, join(dir, L"db"), join(dir, L"fresh.log")) == conf);
    std::string text;
    read_file(conf, text);
    CHECK(text.find("DatabaseMirror database.clamav.net") != std::string::npos && text.find("DatabaseDirectory " + utf8(join(dir, L"db"))) != std::string::npos);
    CHECK(is_dir(join(dir, L"db")));
    remove_tree_files(dir);
}

static void test_quarantine() {
    std::wstring dir = work(L"av_quarantine");
    std::wstring origin = work(L"av_origin");
    CHECK(list_quarantine(dir).empty());
    std::wstring stored1 = join(dir, L"a.exe"), stored2 = join(dir, L"b.exe"), stored3 = join(dir, L"stranger.bin");
    write_file(stored1, "one");
    write_file(stored2, "two");
    write_file(stored3, "three");
    record_quarantine(join(origin, L"a.exe"), stored1, L"Test.Threat.A", dir);
    record_quarantine(join(origin, L"b.exe"), stored2, L"Test.Threat.B", dir);
    auto list = list_quarantine(dir);
    if (list.size() != 3) {
        for (const auto& e : list) std::fprintf(stderr, "  entry: %ls | %ls | %ls\n", e.original.c_str(), e.stored.c_str(), e.threat.c_str());
    }
    CHECK(list.size() == 3);   // two recorded, one file found in the folder without an entry
    CHECK(list[0].threat == L"Test.Threat.A" && list[0].original == join(origin, L"a.exe") && list[0].date.size() == 16);
    CHECK(list[2].original == UNKNOWN_ORIGIN && list[2].stored == stored3 && list[2].threat == L"?");

    // restoring: the file goes back, its entry is forgotten; an existing file is never overwritten
    CHECK(restore_quarantined(list[0], dir).empty() && is_file(join(origin, L"a.exe")) && !is_file(stored1));
    CHECK(list_quarantine(dir).size() == 2);
    write_file(stored1, "again");
    record_quarantine(join(origin, L"a.exe"), stored1, L"Test.Threat.A", dir);
    auto again = list_quarantine(dir);
    QuarantineEntry blocked;
    for (const auto& e : again) {
        if (e.stored == stored1) blocked = e;
    }
    CHECK(restore_quarantined(blocked, dir).find(L"already exists") != std::wstring::npos && is_file(stored1));
    CHECK(restore_quarantined(list[2], dir).find(L"unknown") != std::wstring::npos);   // no recorded origin: not restored by guessing

    // an entry pointing outside the quarantine folder is refused (a tampered manifest must not move or delete other files)
    QuarantineEntry outside{origin + L"\\victim.txt", origin + L"\\victim.txt", L"x", L""};
    write_file(outside.stored, "precious");
    CHECK(!restore_quarantined(outside, dir).empty() && !delete_quarantined(outside, dir).empty() && is_file(outside.stored));
    // ... also through a path that only looks inside
    QuarantineEntry dotdot{origin + L"\\victim.txt", dir + L"\\..\\" + base_name(origin) + L"\\victim.txt", L"x", L""};
    CHECK(!delete_quarantined(dotdot, dir).empty() && is_file(outside.stored));

    CHECK(delete_quarantined(list[1], dir).empty() && !is_file(stored2));
    CHECK(list_quarantine(dir).size() == 2);
    CHECK(delete_quarantined(list[1], dir).empty());   // already gone is fine

    // a corrupt manifest is kept aside, never overwritten
    write_file(join(dir, L"manifest.json"), "{ this is not json at all");
    record_quarantine(L"C:\\x\\c.exe", join(dir, L"c.exe"), L"T", dir);
    CHECK(is_file(join(dir, L"manifest.json.corrupt")));
    remove_tree_files(dir);
    remove_tree_files(origin);
}

static void test_cache_and_plan() {
    std::wstring dir = work(L"av_cache");
    std::wstring cache_file = join(dir, L"cache.dat");
    {
        ScanCache cache(cache_file);
        CHECK(!cache.is_clean(L"c:\\a", 10, 5, FLAG_ARCHIVES, 7));
        cache.mark_pending({{L"c:\\a", 10, 5}, {L"c:\\b", 20, 6}});
        CHECK(!cache.is_clean(L"c:\\a", 10, 5, 0, 7) && cache.count() == 0);   // pending is never skipped
        cache.mark_clean({L"c:\\a", L"c:\\unknown"}, FLAG_ARCHIVES | FLAG_HEURISTICS, 1000.0);
        CHECK(cache.count() == 1);
        CHECK(cache.is_clean(L"c:\\a", 10, 5, FLAG_ARCHIVES, 7, 1000.0 + 86400));
        CHECK(cache.is_clean(L"c:\\a", 10, 5, FLAG_ARCHIVES | FLAG_HEURISTICS, 7, 1000.0));
        CHECK(!cache.is_clean(L"c:\\a", 11, 5, FLAG_ARCHIVES, 7, 1000.0));                        // the size changed
        CHECK(!cache.is_clean(L"c:\\a", 10, 6, FLAG_ARCHIVES, 7, 1000.0));                        // the time changed
        CHECK(!cache.is_clean(L"c:\\a", 10, 5, FLAG_PUA, 7, 1000.0));                             // a weaker scan does not vouch for a stronger one
        CHECK(!cache.is_clean(L"c:\\a", 10, 5, FLAG_ARCHIVES, 7, 1000.0 + 8 * 86400));            // too old
        cache.mark_clean({L"c:\\a"}, 0, 5000.0);                                                  // already clean: not re-marked with other flags
        CHECK(cache.is_clean(L"c:\\a", 10, 5, FLAG_ARCHIVES, 7, 1000.0));
        CHECK(cache.save());
    }
    {
        ScanCache reloaded(cache_file);
        CHECK(reloaded.count() == 1 && reloaded.is_clean(L"c:\\a", 10, 5, FLAG_ARCHIVES, 7, 1000.0));
        CHECK(reloaded.prune(30, 1000.0 + 40 * 86400) == 2);   // the stale clean entry and the pending one
        CHECK(reloaded.count() == 0);
        reloaded.mark_pending({{L"c:\\z", 1, 1}});
        reloaded.clear();
        CHECK(reloaded.count() == 0 && reloaded.save());
    }
    write_file(cache_file, "garbage without tabs\nc:\\ok\t1\t2\t1\t3\t100\nmore garbage\t1\n");
    ScanCache damaged(cache_file);
    CHECK(damaged.count() == 1);   // damaged lines are dropped, the good one kept
    CHECK(ScanCache::key_of(L"C:\\Users\\Me\\..\\Me\\File.TXT") == L"c:\\users\\me\\file.txt");

    // the plan: a tree of files, one of them known clean and unchanged
    std::wstring tree = join(dir, L"tree");
    make_dirs(join(tree, L"sub"));
    make_dirs(join(tree, L"clam"));
    for (int i = 0; i < 6; ++i) write_file(join(tree, L"f" + std::to_wstring(i) + L".txt"), "data" + std::to_string(i));
    write_file(join(tree, L"sub\\deep.txt"), "deep");
    write_file(join(tree, L"empty.txt"), "");                        // clamscan ignores empty files
    write_file(join(tree, L"big.bin"), std::string(3 * 1024 * 1024, 'x'));   // over the 1 MB limit used below
    write_file(join(tree, L"clam\\excluded.txt"), "excluded");        // inside the excluded folder
    ScanOptions options;
    options.max_filesize_mb = 1;
    ScanCache cache(join(dir, L"plan_cache.dat"));
    std::wstring workdir = join(dir, L"work");
    ScanPlan first = make_plan({tree}, options, &cache, workdir, join(tree, L"clam"), 3);
    CHECK(first.seen == 9);   // everything but the excluded folder is seen
    CHECK(first.to_scan == 7 && first.skipped == 0);                  // 6 files + deep.txt: not empty, not too big
    CHECK(first.lists.size() == 1);                                    // far fewer than 500 files per process: one list
    std::string listed;
    read_file(first.lists[0], listed);
    CHECK(listed.find("deep.txt") != std::string::npos && listed.find("excluded.txt") == std::string::npos && listed.find("big.bin") == std::string::npos &&
          listed.find("empty.txt") == std::string::npos);
    // after a clean scan of two of them, the next plan skips those
    std::vector<std::wstring> clean = {ScanCache::key_of(join(tree, L"f0.txt")), ScanCache::key_of(join(tree, L"f1.txt"))};
    cache.mark_clean(clean, options.flags());
    ScanPlan second = make_plan({tree}, options, &cache, workdir, join(tree, L"clam"), 3);
    CHECK(second.skipped == 2 && second.to_scan == 5);
    write_file(join(tree, L"f0.txt"), "changed contents");   // a modified file is scanned again
    ScanPlan third = make_plan({tree}, options, &cache, workdir, join(tree, L"clam"), 3);
    CHECK(third.skipped == 1 && third.to_scan == 6);
    ScanOptions no_cache = options;
    no_cache.use_cache = false;
    CHECK(make_plan({tree}, no_cache, &cache, workdir, join(tree, L"clam"), 3).skipped == 0);
    // a single file and a missing target
    ScanPlan single = make_plan({join(tree, L"f2.txt"), join(tree, L"nope")}, no_cache, nullptr, workdir, L"", 1);
    CHECK(single.to_scan == 1 && single.lists.size() == 1);
    // many files: several lists
    std::wstring many = join(dir, L"many");
    make_dirs(many);
    for (int i = 0; i < 1200; ++i) write_file(join(many, L"m" + std::to_wstring(i) + L".txt"), "x");
    ScanPlan wide_plan = make_plan({many}, no_cache, nullptr, workdir, L"", 4);
    CHECK(wide_plan.to_scan == 1200 && wide_plan.lists.size() == 2);   // 1200 / 500 files per process = 2 processes
    std::size_t lines = 0;
    for (const auto& l : wide_plan.lists) {
        std::string t;
        read_file(l, t);
        for (char c : t) lines += c == '\n';
    }
    CHECK(lines == 1200);
    Stop stop_now = [] { return true; };
    CHECK(make_plan({tree}, no_cache, nullptr, workdir, L"", 2, stop_now).to_scan <= 1);   // stopped at once
    remove_tree_files(dir);
}

static void test_settings_and_watcher() {
    std::wstring dir = work(L"av_settings");
    std::wstring path = join(dir, L"protection.json");
    CHECK(!load_protection_settings(path).watch_enabled && load_protection_settings(path).folders.empty());
    ProtectionSettings s;
    s.watch_enabled = true;
    s.folders = {L"C:\\Users\\me\\Downloads", L"D:\\Share"};
    s.scan_hours = 12;
    s.last_quick_scan = 1000;
    CHECK(save_protection_settings(s, path).empty());
    ProtectionSettings back = load_protection_settings(path);
    CHECK(back.watch_enabled && back.folders == s.folders && back.scan_hours == 12 && back.last_quick_scan == 1000);
    CHECK(scan_is_due(back, 1000 + 12 * 3600) && !scan_is_due(back, 1000 + 12 * 3600 - 1));
    ProtectionSettings never_scan;
    CHECK(!scan_is_due(never_scan, 1e12));
    // damaged or hostile settings: relative folders dropped, hours clamped, bad types ignored
    write_file(path, "{\"watch_enabled\": true, \"folders\": [\"relative\", 5, \"C:\\\\ok\"], \"scan_hours\": 100000, \"last_quick_scan\": \"x\"}");
    ProtectionSettings hostile = load_protection_settings(path);
    CHECK(hostile.watch_enabled && hostile.folders.size() == 1 && hostile.folders[0] == L"C:\\ok" && hostile.scan_hours == 24 * 30 && hostile.last_quick_scan == 0);
    write_file(path, "[1, 2, 3]");
    CHECK(!load_protection_settings(path).watch_enabled);
    write_file(path, "not json");
    CHECK(load_protection_settings(path).folders.empty());

    // the watcher reports a file only once it stopped changing
    std::wstring watched = join(dir, L"watched");
    make_dirs(join(watched, L"sub"));
    write_file(join(watched, L"old.txt"), "already here");
    FolderWatcher watcher({watched, L"relative"});
    watcher.prime();
    CHECK(watcher.poll().empty());
    write_file(join(watched, L"new.txt"), "fresh");
    write_file(join(watched, L"sub\\deep.txt"), "deep");
    write_file(join(watched, L"download.crdownload"), "partial");
    write_file(join(watched, L"~$lock.docx"), "lock");
    CHECK(watcher.poll().empty());                    // first sight: not reported yet
    auto ready = watcher.poll();                       // unchanged since the last poll: reported
    CHECK(ready.size() == 2 && ready[0] == join(watched, L"new.txt") && ready[1] == join(watched, L"sub\\deep.txt"));
    CHECK(watcher.poll().empty());                    // reported once
    write_file(join(watched, L"new.txt"), "replaced with other content");
    CHECK(watcher.poll().empty());
    CHECK(watcher.poll().size() == 1);                // a replaced file is reported again
    delete_file(join(watched, L"new.txt"));
    CHECK(watcher.poll().empty());
    remove_tree_files(dir);
}

static void test_yara() {
    std::wstring dir = work(L"av_yara");
    std::wstring rules = join(dir, L"rules");
    std::wstring good = join(dir, L"good.yar");
    write_file(good, "rule demo { strings: $a = \"x\" condition: $a }");
    CHECK(check_rule_text(good).empty());
    write_file(join(dir, L"not_yara.txt"), "rule x { }");
    CHECK(!check_rule_text(join(dir, L"not_yara.txt")).empty());
    write_file(join(dir, L"empty.yar"), "");
    CHECK(check_rule_text(join(dir, L"empty.yar")).find(L"between 1 byte and 5 MB") != std::wstring::npos);
    write_file(join(dir, L"binary.yar"), std::string("rule \0 x", 8));
    CHECK(check_rule_text(join(dir, L"binary.yar")).find(L"No YARA rule") != std::wstring::npos);
    write_file(join(dir, L"norule.yar"), "just some text");
    CHECK(check_rule_text(join(dir, L"norule.yar")).find(L"No YARA rule") != std::wstring::npos);
    write_file(join(dir, L"latin.yar"), "rule caf\xe9 { condition: true }");   // not valid UTF-8
    CHECK(!check_rule_text(join(dir, L"latin.yar")).empty());
    CHECK(!check_rule_text(join(dir, L"missing.yar")).empty());

    CHECK(list_rule_files(rules).empty());
    CHECK(add_rule_file(good, rules).empty() && is_file(join(rules, L"good.yar")));
    CHECK(add_rule_file(good, rules).find(L"already installed") != std::wstring::npos);
    CHECK(list_rule_files(rules).size() == 1 && list_rule_files(rules)[0] == L"good.yar");
    CHECK(!remove_rule_file(L"..\\good.yar", rules).empty() && !remove_rule_file(L"other.yar", rules).empty() && is_file(join(rules, L"good.yar")));
    CHECK(remove_rule_file(L"good.yar", rules).empty() && list_rule_files(rules).empty());
    remove_tree_files(dir);
}

static void test_real_clamav() {
    ClamInstall install;
    std::wstring reason;
    bool found = find_clam_install(install, reason);
    if (!found) {
        std::printf("  (ClamAV: %ls)\n", reason.c_str());
        return;
    }
    CHECK(is_file(install.clamscan) && is_file(install.freshclam));
    std::wstring database = join(dir_name(dir_name(exe_dir())), L"clamav\\database");
    if (!read_database_info(database).ready) {
        std::printf("  (ClamAV is installed but no signature database was found in %ls)\n", database.c_str());
        return;
    }
    DatabaseInfo info = read_database_info(database);
    std::wstring tree = work(L"av_real");
    for (int i = 0; i < 30; ++i) write_file(join(tree, L"clean" + std::to_wstring(i) + L".txt"), "this is perfectly harmless text number " + std::to_string(i));
    ScanOptions options;
    options.quarantine = false;
    options.fast = true;
    options.threads = 1;
    options.use_cache = true;
    std::vector<std::wstring> lines;
    std::size_t planned_scan = 0, planned_skipped = 0;
    ScanEvents events;
    events.lines = [&](const std::vector<std::wstring>& batch) { lines.insert(lines.end(), batch.begin(), batch.end()); };
    events.planned = [&](std::size_t scan, std::size_t skipped, std::size_t) {
        planned_scan = scan;
        planned_skipped = skipped;
    };
    std::wstring clam_folder = join(tree, L"clam_state");
    make_dirs(clam_folder);
    ULONGLONG started = GetTickCount64();
    int code = run_clam_scan(install, {tree}, options, events, never, database, clam_folder);
    double seconds = (double)(GetTickCount64() - started) / 1000.0;
    int oks = 0;
    long long files = -1, infected = -1;
    for (const auto& l : lines) {
        ScanLine p = parse_scan_line(l);
        oks += p.kind == L"ok";
        if (p.kind == L"summary" && p.a == L"files") files = std::stoll(p.b);
        if (p.kind == L"summary" && p.a == L"infected") infected = std::stoll(p.b);
    }
    CHECK(code == 0);
    CHECK(planned_scan == 30 && planned_skipped == 0);
    CHECK(oks == 30 && files == 30 && infected == 0);
    // the second scan skips everything that was reported clean
    lines.clear();
    int again = run_clam_scan(install, {tree}, options, events, never, database, clam_folder);
    CHECK(again == 0 && planned_scan == 0 && planned_skipped == 30 && lines.empty());
    // stop: nothing runs
    CHECK(run_clam_scan(install, {tree}, ScanOptions{false, true, false, false, true, 100, false, 7, 1}, events, [] { return true; }, database, clam_folder) == 2);
    std::printf("  real clamscan: %lld signatures, scanned 30 files in %.1f s (second scan skipped them all)\n", info.signatures, seconds);
    remove_tree_files(tree);
}

int run_antivirus_tests() {
    test_output_parsing();
    test_commands();
    test_database_and_conf();
    test_quarantine();
    test_cache_and_plan();
    test_settings_and_watcher();
    test_yara();
    test_real_clamav();
    std::printf("antivirus: %d checks, %d failed\n", checks, failures);
    return failures;
}
