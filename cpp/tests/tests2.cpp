// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Tests the process launcher, JSON, registry writing and deletion with backups, and startup entry removal.

#include <cstdio>
#include <stdexcept>

#include <windows.h>

#include <ddcore/common.hpp>
#include <ddcore/dead_registry.hpp>
#include <ddcore/inspect.hpp>
#include <ddcore/json.hpp>
#include <ddcore/proc.hpp>
#include <ddcore/registry.hpp>
#include <ddcore/startup.hpp>

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

static void test_json() {
    Json j = parse_json(L"\ufeff {\"a\": [1, 2.5, \"x\\n\\u00e9\", null, true], \"b\": {\"c\": \"d\"}, \"n\": 12} ");
    CHECK(j.get(L"a").size() == 5);
    CHECK(j.get(L"a").at(1).num() == 2.5);
    CHECK(j.get(L"a").at(2).str() == L"x\n\u00e9");
    CHECK(j.get(L"a").at(3).is_null());
    CHECK(j.get(L"a").at(4).flag());
    CHECK(j.get(L"b").get(L"c").str() == L"d");
    CHECK(j.get(L"n").integer() == 12 && j.get(L"n").str() == L"12");
    CHECK(j.get(L"missing").get(L"deeper").is_null());
    CHECK(Json().as_list().empty());
    CHECK(j.get(L"b").as_list().size() == 1);   // a single object is a list of one (PowerShell's ConvertTo-Json)
    CHECK(j.get(L"a").as_list().size() == 5);
    Json round;
    CHECK(try_parse_json(j.dump(), round) && round.get(L"b").get(L"c").str() == L"d");
    Json bad;
    CHECK(!try_parse_json(L"{\"a\": ", bad));
    CHECK(!try_parse_json(L"[1,]x", bad));
    Json built = Json::object();
    built.set(L"k", Json::string(L"quote\" back\\slash"));
    Json again = parse_json(built.dump(true));
    CHECK(again.get(L"k").str() == L"quote\" back\\slash");
}

static void test_proc() {
    ProcResult r = run_process({sys_exe(L"cmd.exe"), L"/c", L"echo", L"hello world"});
    CHECK(r.ok());
    CHECK(r.output.find(L"hello world") != std::wstring::npos);

    std::vector<std::wstring> lines;
    ProcOptions streaming;
    streaming.on_line = [&](const std::wstring& line) { lines.push_back(line); };
    run_process({sys_exe(L"cmd.exe"), L"/c", L"echo one& echo two& echo three"}, streaming);
    CHECK(lines.size() == 3 && lines[0] == L"one" && lines[2] == L"three");

    ProcResult failing = run_process({sys_exe(L"cmd.exe"), L"/c", L"exit 7"});
    CHECK(failing.started && failing.code == 7 && !failing.ok());

    ProcResult missing = run_process({L"C:\\definitely\\not\\here.exe"});
    CHECK(!missing.started);

    ProcOptions quick;
    quick.timeout_ms = 300;
    ProcResult slow = run_process({sys_exe(L"ping.exe"), L"-n", L"6", L"127.0.0.1"}, quick);
    CHECK(slow.timed_out);

    bool stop_now = false;
    ProcOptions stoppable;
    stoppable.stop = [&] { return stop_now; };
    stoppable.on_line = [&](const std::wstring&) { stop_now = true; };
    ProcResult stopped = run_process({sys_exe(L"ping.exe"), L"-n", L"6", L"127.0.0.1"}, stoppable);
    CHECK(stopped.stopped);

    CHECK(quote_arg(L"plain") == L"plain");
    CHECK(quote_arg(L"has space") == L"\"has space\"");
    CHECK(quote_arg(L"say \"hi\"") == L"\"say \\\"hi\\\"\"");
    CHECK(quote_arg(L"C:\\dir with space\\") == L"\"C:\\dir with space\\\\\"");

    bool poisoned = false;
    for (const auto& e : safe_environment()) {
        if (starts_with(lower(e), L"psmodulepath=") && e.find(L"WindowsPowerShell\\v1.0\\Modules") == std::wstring::npos) poisoned = true;
    }
    CHECK(!poisoned);

    ProcResult ps = run_powershell(L"ConvertTo-Json -Compress -InputObject @{ a = 'caf\u00e9'; n = 3 }");
    Json parsed;
    CHECK(ps.ok() && try_parse_json(ps.output, parsed));
    CHECK(parsed.get(L"a").str() == L"caf\u00e9" && parsed.get(L"n").integer() == 3);
}

static void test_files_and_data_dir() {
    SetEnvironmentVariableW(L"DDCLEANER_HOME", (temp_dir() + L"\\ddcore_home_" + std::to_wstring(GetCurrentProcessId())).c_str());
    std::wstring dir = data_subdir(L"backups");
    CHECK(is_dir(dir));
    CHECK(write_file(join(dir, L"a.txt"), "hello\r\nbytes"));
    std::string back;
    CHECK(read_file(join(dir, L"a.txt"), back) && back == "hello\r\nbytes");
    CHECK(move_file(join(dir, L"a.txt"), join(dir, L"b.txt")) && !lexists(join(dir, L"a.txt")));
    CHECK(!read_file(join(dir, L"a.txt"), back));
    CHECK(safe_name(L"HKCU\\Software\\My App!") == L"HKCU_Software_My_App_");
    CHECK(safe_name(L"abcdef", 3) == L"def");
    CHECK(timestamp().size() == 15);
    CHECK(sha256_bytes("abc") == L"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
    std::wstring file = join(dir, L"b.txt");
    CHECK(sha256_file(file) == sha256_bytes("hello\r\nbytes"));
    delete_file(file);
}

static void test_registry_delete() {
    std::wstring base = L"SOFTWARE\\DDCoreTest" + std::to_wstring(GetCurrentProcessId());
    HKEY k = nullptr;
    RegCreateKeyExW(HKEY_CURRENT_USER, (base + L"\\child\\deeper").c_str(), 0, nullptr, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, nullptr, &k, nullptr);
    if (k) {
        RegSetValueExW(k, L"v", 0, REG_SZ, (const BYTE*)L"data", 10);
        RegCloseKey(k);
    }
    RegCreateKeyExW(HKEY_CURRENT_USER, base.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, nullptr, &k, nullptr);
    if (k) {
        RegSetValueExW(k, L"keepme", 0, REG_SZ, (const BYTE*)L"needle-value", 26);
        RegSetValueExW(k, L"drop", 0, REG_SZ, (const BYTE*)L"x", 4);
        RegCloseKey(k);
    }
    std::wstring folder = temp_dir() + L"\\ddcore_regbackup_" + std::to_wstring(GetCurrentProcessId());

    // search finds keys, value names and value data
    RegScan scan = search_registry(L"needle-value", false, false, true);
    bool found_data = false;
    for (const auto& e : scan.entries) found_data |= e.hive == L"HKCU" && e.key == base && e.value == L"keepme";
    CHECK(found_data);
    RegScan by_key = search_registry(L"\"deeper\"", true, false, false);
    bool found_key = false;
    for (const auto& e : by_key.entries) found_key |= e.is_key && e.key == base + L"\\child\\deeper";
    CHECK(found_key);

    RegEntry core{L"HKLM", L"SOFTWARE\\Microsoft", L"", true};
    CHECK(!registry_protected_reason(core).empty());
    RegEntry outside{L"HKCU", L"System\\CurrentControlSet", L"", true};
    CHECK(!registry_protected_reason(outside).empty());
    RegEntry winlogon{L"HKLM", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"Shell", false};
    CHECK(!registry_protected_reason(winlogon).empty());
    RegEntry bad_hive{L"HKCR", L"SOFTWARE\\x", L"", true};
    CHECK(!registry_protected_reason(bad_hive).empty());
    CHECK(registry_protected_reason(RegEntry{L"HKCU", base, L"", true}).empty());

    // delete a value, then the whole tree: each with a backup
    RegEntry value{L"HKCU", base, L"drop", false};
    RegEntry tree{L"HKCU", base + L"\\child", L"", true};
    RegDeleteResult r = delete_entries({core, value, tree}, folder);
    CHECK(r.deleted.size() == 2 && r.failed.size() == 1);
    CHECK(r.backups.size() == 2);
    for (const auto& b : r.backups) CHECK(is_file(b) && b.find(L".reg") != std::wstring::npos);
    CHECK(RegKey::open(L"HKCU", base).valid());
    CHECK(!RegKey::open(L"HKCU", base + L"\\child").valid());
    bool drop_gone = true;
    for (const auto& v : RegKey::open(L"HKCU", base).values()) drop_gone &= v.name != L"drop";
    CHECK(drop_gone);
    RegDeleteResult again = delete_entries({tree}, folder);
    CHECK(again.deleted.size() == 1 && again.failed.empty());   // already gone counts as done

    RegKey::delete_tree(L"HKCU", base);
    CHECK(!RegKey::open(L"HKCU", base).valid());
    for (const auto& b : r.backups) delete_file(b);
    RemoveDirectoryW(folder.c_str());
}

static void test_startup_removal() {
    std::wstring name = L"DDCoreTest" + std::to_wstring(GetCurrentProcessId());
    const std::wstring run_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    {
        RegKey k = RegKey::open_write(L"HKCU", run_key);
        if (!k.valid()) return;
        CHECK(k.set_text(name, L"\"C:\\definitely\\not\\here\\app.exe\" /go") == ERROR_SUCCESS);
    }
    std::wstring startup_dir = known_folder(0x07);
    std::wstring startup_file = join(startup_dir, name + L".txt");
    CHECK(write_file(startup_file, "test"));

    std::vector<StartupEntry> all = collect_startup();
    StartupEntry reg_entry, file_entry;
    for (const auto& e : all) {
        if (e.name == name) reg_entry = e;
        if (e.name == name + L".txt") file_entry = e;
    }
    CHECK(reg_entry.name == name && file_entry.name == name + L".txt");
    CHECK(!reg_entry.exists && reg_entry.severity() >= 1);   // the program is missing
    CHECK(removable(reg_entry) && removable(file_entry));
    CHECK(!needs_admin(reg_entry) && !needs_admin(file_entry));   // current user's Run key and Startup folder
    CHECK(describe(reg_entry).find(L"Delete the value") == 0);

    StartupEntry foreign = reg_entry;
    foreign.location = L"HKCU\\SOFTWARE\\Somewhere\\Else";
    CHECK(!removable(foreign));
    StartupEntry sneaky = file_entry;
    sneaky.name = L"..\\..\\evil.txt";
    CHECK(!removable(sneaky));

    std::wstring folder = temp_dir() + L"\\ddcore_startupbackup_" + std::to_wstring(GetCurrentProcessId());
    StartupRemoval r = remove_entries({reg_entry, file_entry, foreign}, folder);
    CHECK(r.removed.size() == 2 && r.failed.size() == 1);
    CHECK(r.backups.size() == 2);
    CHECK(!lexists(startup_file));
    bool gone = true;
    for (const auto& v : RegKey::open(L"HKCU", run_key).values()) gone &= v.name != name;
    CHECK(gone);
    bool saved_reg = false, saved_file = false;
    for (const auto& b : r.backups) {
        saved_reg |= ends_with(b, L".reg") && is_file(b);
        saved_file |= ends_with(b, L".txt") && is_file(b);
    }
    CHECK(saved_reg && saved_file);   // both can be put back
    for (const auto& b : r.backups) delete_file(b);
    RemoveDirectoryW(folder.c_str());
}

static void test_inspection() {
    std::wstring cmd = system32() + L"\\cmd.exe";
    FileInspection fi = inspect(cmd);
    CHECK(fi.kind == L"executable" && fi.mismatch.empty() && !fi.dangerous);
    CHECK(fi.entropy > 4 && fi.entropy < 8);

    std::wstring tmp = temp_dir() + L"\\ddcore_inspect_" + std::to_wstring(GetCurrentProcessId());
    make_dirs(tmp);
    std::string pe_bytes;
    read_file(cmd, pe_bytes);
    write_file(join(tmp, L"invoice.pdf"), pe_bytes.substr(0, 4096));   // an executable wearing a document name
    FileInspection masked = inspect(join(tmp, L"invoice.pdf"));
    CHECK(masked.kind == L"executable" && masked.dangerous && !masked.mismatch.empty());
    write_file(join(tmp, L"notes.txt"), "just some plain text here\r\n");
    FileInspection text = inspect(join(tmp, L"notes.txt"));
    CHECK(text.kind == L"text" && text.mismatch.empty());
    write_file(join(tmp, L"empty.bin"), "");
    CHECK(inspect(join(tmp, L"empty.bin")).error == L"empty file");
    CHECK(inspect(join(tmp, L"nope.bin")).error == L"cannot open the file");
    delete_file(join(tmp, L"invoice.pdf"));
    delete_file(join(tmp, L"notes.txt"));
    delete_file(join(tmp, L"empty.bin"));
    RemoveDirectoryW(tmp.c_str());

    PEInfo info = inspect_pe(cmd);
    CHECK(!info.file_version.empty());
    CHECK(info.strings.count(L"OriginalFilename") > 0);
    PEInfo signed_exe = inspect_pe(system32() + L"\\WindowsPowerShell\\v1.0\\powershell.exe");
    CHECK(signed_exe.error.empty());   // Windows files are signed by catalog: no embedded signature is expected

    // a folder only administrators can change, and one everybody can
    bool ok = false;
    CHECK(unprivileged_writers(system32(), &ok).empty() && ok);
    std::wstring open_dir = temp_dir();
    auto writers = unprivileged_writers(open_dir, &ok);
    CHECK(ok && !writers.empty());   // the user's temp folder is writable by the user
    CHECK(!folder_risk(open_dir).empty() && folder_risk(system32()).empty());
    CHECK(current_user_sid().find(L"S-1-5-21") == 0 || !current_user_sid().empty());
}

int run_second_layer_tests() {
    test_json();
    test_proc();
    test_files_and_data_dir();
    test_registry_delete();
    test_startup_removal();
    test_inspection();
    std::printf("second layer: %d checks, %d failed\n", checks, failures);
    return failures;
}
