// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Tests driver packages: parsing, judging, removal with backups through a fake pnputil, and leftovers.

#include <cstdio>
#include <stdexcept>

#include <windows.h>

#include <ddcore/drivers.hpp>

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

static const wchar_t* ENUM_OUTPUT =
    L"Microsoft PnP Utility\r\n\r\n"
    L"Published Name:     oem12.inf\r\n"
    L"Original Name:      netcam.inf\r\n"
    L"Provider Name:      Acme\r\n"
    L"Class Name:         Camera\r\n"
    L"Class GUID:         {CA3E7AB9-B4C3-4AE6-8251-579EF933890F}\r\n"
    L"Driver Version:     10/21/2021 1.2.3.4\r\n"
    L"Signer Name:        Microsoft Windows Hardware Compatibility Publisher\r\n\r\n"
    L"Published Name:     oem13.inf\r\n"
    L"Original Name:      netcam.inf\r\n"
    L"Provider Name:      Acme\r\n"
    L"Class Name:         Camera\r\n"
    L"Class GUID:         {CA3E7AB9-B4C3-4AE6-8251-579EF933890F}\r\n"
    L"Driver Version:     03/02/2023 1.10.0.0\r\n"
    L"Signer Name:        Microsoft Windows Hardware Compatibility Publisher\r\n\r\n"
    L"Published Name:     oem14.inf\r\n"
    L"Original Name:      gone.inf\r\n"
    L"Provider Name:      Old Inc\r\n"
    L"Class Name:         Printer\r\n"
    L"Class GUID:         {4d36e979-e325-11ce-bfc1-08002be10318}\r\n"
    L"Driver Version:     01/01/2019 2.0.0.0\r\n\r\n"
    L"Published Name:     oem15.inf\r\n"
    L"Original Name:      storage.inf\r\n"
    L"Provider Name:      Disk Co\r\n"
    L"Class Name:         HDC\r\n"
    L"Class GUID:         {4d36e96a-e325-11ce-bfc1-08002be10318}\r\n"
    L"Driver Version:     01/01/2020 3.0.0.0\r\n\r\n"
    L"Published Name:     oem16.inf\r\n"
    L"Original Name:      mouse.inf\r\n"
    L"Provider Name:      Mice\r\n"
    L"Class Name:         Mouse\r\n"
    L"Class GUID:         {4d36e96f-e325-11ce-bfc1-08002be10318}\r\n"
    L"Driver Version:     01/01/2020 4.0.0.0\r\n\r\n"
    L"Published Name:     notoem.inf\r\nOriginal Name: x\r\nProvider Name: x\r\nClass Name: x\r\nClass GUID: x\r\nDriver Version: 1/1/2000 1.0\r\n";

static std::vector<Binding> bindings() {
    return {{L"Webcam", L"oem13.inf", true, L"Camera", L"USB\\CAM1"},          // the new camera driver is in use
            {L"Old webcam", L"oem12.inf", false, L"Camera", L"USB\\CAM0"},     // the old one only by an unplugged device
            {L"Gone printer", L"oem14.inf", false, L"Printer", L"USB\\PRN1"},  // only a device that is not connected
            {L"Mouse", L"oem16.inf", true, L"Mouse", L"HID\\MOUSE1"}};
}

static void test_parse_and_judge() {
    auto packages = parse_enum_drivers(ENUM_OUTPUT);
    CHECK(packages.size() == 5);   // "notoem.inf" is not a published name
    CHECK(packages[0].published == L"oem12.inf" && packages[0].original == L"netcam.inf" && packages[0].provider == L"Acme");
    CHECK(packages[0].class_guid == L"{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}" && packages[0].version == L"1.2.3.4" && packages[0].date == L"10/21/2021");
    CHECK(packages[0].signer.find(L"Microsoft") == 0 && packages[2].signer.empty());
    CHECK((packages[1].version_key() == std::vector<long>{1, 10, 0, 0}));   // 1.10 is newer than 1.2: numeric, not text

    auto candidates = find_unused(packages, bindings());
    // oem13 and oem16 are in use, oem15 is a core class: oem12 (older) and oem14 (device gone) are offered
    CHECK(candidates.size() == 2);
    const Candidate* old = nullptr;
    const Candidate* gone = nullptr;
    for (const auto& c : candidates) {
        if (c.package.published == L"oem12.inf") old = &c;
        if (c.package.published == L"oem14.inf") gone = &c;
    }
    CHECK(old && old->category == DriverCategory::Old && std::wstring(category_risk(old->category)) == L"Safe");
    CHECK(old && old->reason == L"A newer version (1.10.0.0, oem13.inf) is installed");
    CHECK(old && old->ghost_ids.size() == 1 && old->ghost_ids[0] == L"USB\\CAM0");
    CHECK(gone && gone->category == DriverCategory::Gone && gone->reason == L"Only used by devices that are not connected: Gone printer");

    auto all = list_all(packages, bindings());
    CHECK(all.size() == 5);
    int used = 0, protect = 0;
    for (const auto& c : all) {
        used += c.category == DriverCategory::Used;
        protect += c.category == DriverCategory::Protected;
        if (c.category == DriverCategory::Protected) CHECK(!c.removable() && std::wstring(category_risk(c.category)) == L"Locked");
        if (c.category == DriverCategory::Used) CHECK(c.in_use() && std::wstring(category_risk(c.category)) == L"Danger");
    }
    CHECK(used == 2 && protect == 1);

    bool threw = false;
    try {
        find_unused(packages, {{L"x", L"oem12.inf", false, L"", L""}});   // no connected device could be read
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
    CHECK(parse_bindings(parse_json(L"{\"Name\":\"A\",\"Inf\":\"OEM5.INF\",\"Present\":true,\"Id\":\"X\"}"))[0].inf == L"oem5.inf");
    CHECK(is_published_name(L"OEM7.inf") && !is_published_name(L"oem.inf") && !is_published_name(L"net.inf"));
}

static void test_removal_with_backups() {
    auto packages = parse_enum_drivers(ENUM_OUTPUT);
    auto candidates = find_unused(packages, bindings());
    std::wstring folder = temp_dir() + L"\\ddcore_drvbackup_" + std::to_wstring(GetCurrentProcessId());

    std::vector<std::wstring> calls;
    Pnputil fake = [&](const std::vector<std::wstring>& args, std::wstring& out) {
        calls.push_back(args[0] + L" " + args[1]);
        if (args[0] == L"/export-driver") {
            write_file(join(args[2], L"driver.sys"), "x");   // the backup copy
            return 0;
        }
        out = L"";
        return args[1] == L"oem14.inf" ? 5 : 0;   // Windows refuses to delete oem14
    };
    DriverRemoval r = remove_packages(candidates, folder, fake);
    CHECK(r.removed.size() == 1 && r.removed[0].package.published == L"oem12.inf");
    CHECK(r.failed.size() == 1 && r.failed[0].second == L"Windows refused: the driver is in use");
    CHECK(r.backups.size() == 2);
    for (const auto& b : r.backups) CHECK(is_file(join(b, L"driver.sys")));
    // order: the files are exported before anything is deleted
    CHECK(calls[0].find(L"/export-driver") == 0 && calls[1].find(L"/delete-driver") == 0);

    // a backup that fails stops the removal
    Pnputil broken = [&](const std::vector<std::wstring>& args, std::wstring&) {
        calls.push_back(args[0]);
        return args[0] == L"/export-driver" ? 1 : 0;
    };
    calls.clear();
    DriverRemoval nothing = remove_packages(candidates, folder, broken);
    CHECK(nothing.removed.empty() && nothing.failed.size() == 2);
    for (const auto& c : calls) CHECK(c != L"/delete-driver");

    // a core driver is refused whatever the caller passes
    Candidate core;
    core.package = packages[3];
    core.category = DriverCategory::None;
    CHECK(remove_packages({core}, folder, fake).failed.size() == 1);
    Candidate fake_name;
    fake_name.package = packages[0];
    fake_name.package.published = L"..\\evil.inf";
    CHECK(remove_packages({fake_name}, folder, fake).failed.size() == 1);

    bool stop_now = true;
    CHECK(remove_packages(candidates, folder, fake, [&] { return stop_now; }).failed.size() == 2);

    std::vector<Entry> entries;
    list_dir(folder, entries);
    for (const auto& e : entries) {
        std::vector<Entry> inner;
        list_dir(e.path, inner);
        for (const auto& f : inner) delete_file(f.path);
        RemoveDirectoryW(e.path.c_str());
    }
    RemoveDirectoryW(folder.c_str());
}

static void test_complete_uninstall() {
    std::wstring tmp = temp_dir() + L"\\ddcore_infs_" + std::to_wstring(GetCurrentProcessId());
    make_dirs(tmp);
    write_file(join(tmp, L"a.inf"), "[Strings]\r\n[Svc]\r\nAddService = MyDrv, 0x2, Svc_Inst ; comment\r\n; AddService = Commented\r\n  addservice=\"Second_One\"\r\nAddService = MyDrv\r\n");
    auto services = inf_services(join(tmp, L"a.inf"));
    CHECK((services == std::vector<std::wstring>{L"MyDrv", L"Second_One"}));

    // UTF-16 with a BOM
    std::wstring wide_text = L"\ufeffAddService = Wide_Svc, 0x2\r\n";
    write_file(join(tmp, L"w.inf"), std::string(reinterpret_cast<const char*>(wide_text.data()), wide_text.size() * 2));
    CHECK(inf_services(join(tmp, L"w.inf")).size() == 1 && inf_services(join(tmp, L"w.inf"))[0] == L"Wide_Svc");
    CHECK(inf_services(join(tmp, L"missing.inf")).empty());

    write_file(join(tmp, L"std.inf"), "AddService = Inbox_Svc\r\n");
    write_file(join(tmp, L"oem99.inf"), "AddService = Oem_Svc\r\n");
    auto inbox = inbox_services(tmp);
    CHECK(inbox.count(L"inbox_svc") == 1 && inbox.count(L"oem_svc") == 0);   // only Windows' own INFs

    // resolving a driver file
    CHECK(resolve_driver_file(L"\\SystemRoot\\System32\\drivers\\x.sys") == join(system_root(), L"System32\\drivers\\x.sys"));
    CHECK(resolve_driver_file(L"\\??\\C:\\Windows\\System32\\drivers\\y.sys") == L"C:\\Windows\\System32\\drivers\\y.sys");
    CHECK(resolve_driver_file(L"System32\\drivers\\z.sys") == join(system_root(), L"System32\\drivers\\z.sys"));
    CHECK(resolve_driver_file(L"") == L"");

    // which services may be offered
    std::wstring drv = L"\\SystemRoot\\System32\\drivers\\x.sys";
    CHECK(leftover_problem(L"Good_Drv", true, 1, 3, drv).empty());
    CHECK(!leftover_problem(L"bad name!", true, 1, 3, drv).empty());
    CHECK(!leftover_problem(L"Missing", false, 1, 3, drv).empty());
    CHECK(leftover_problem(L"Svc", true, 16, 3, drv) == L"Not a driver service");
    CHECK(leftover_problem(L"Boot", true, 1, 0, drv) == L"A boot-start driver: never touched");
    CHECK(leftover_problem(L"Away", true, 1, 3, L"C:\\Program Files\\x\\a.sys") == L"Its file is not in System32\\drivers");

    // uninstall with a fake pnputil: a used driver is removed with /uninstall /force and its unplugged device entry is cleaned
    auto packages = parse_enum_drivers(ENUM_OUTPUT);
    auto all = list_all(packages, bindings());
    std::vector<Candidate> chosen;
    for (const auto& c : all) {
        if (c.package.published == L"oem16.inf" || c.package.published == L"oem12.inf" || c.package.published == L"oem15.inf") chosen.push_back(c);
    }
    std::vector<std::wstring> calls;
    Pnputil fake = [&](const std::vector<std::wstring>& args, std::wstring& out) {
        std::wstring line;
        for (const auto& a : args) line += a + L" ";
        calls.push_back(line);
        if (args[0] == L"/export-driver") write_file(join(args[2], L"d.sys"), "x");
        out = L"";
        return args[0] == L"/delete-driver" && args[1] == L"oem12.inf" ? 3010 : 0;
    };
    std::set<std::wstring> inbox_empty;
    std::wstring folder = temp_dir() + L"\\ddcore_uninst_" + std::to_wstring(GetCurrentProcessId());
    UninstallResult r = uninstall_completely(chosen, packages, folder, fake, &inbox_empty);
    CHECK(r.removed.size() == 2 && r.failed.size() == 1);        // oem15 is a core driver
    CHECK(r.reboot);                                             // 3010 and an in-use driver
    CHECK(r.ghosts_removed == 1);                                // the unplugged device of oem12
    bool forced = false, removed_device = false;
    for (const auto& c : calls) {
        forced |= c.find(L"/delete-driver oem16.inf /uninstall /force") == 0;
        removed_device |= c.find(L"/remove-device USB\\CAM0") == 0;
    }
    CHECK(forced && removed_device);
    for (const auto& c : calls) CHECK(c.find(L"oem15.inf") == std::wstring::npos);   // never touched

    std::vector<Entry> entries;
    list_dir(folder, entries);
    for (const auto& e : entries) {
        std::vector<Entry> inner;
        list_dir(e.path, inner);
        for (const auto& f : inner) delete_file(f.path);
        RemoveDirectoryW(e.path.c_str());
    }
    RemoveDirectoryW(folder.c_str());
    for (const wchar_t* n : {L"a.inf", L"w.inf", L"std.inf", L"oem99.inf"}) delete_file(join(tmp, n));
    RemoveDirectoryW(tmp.c_str());

    // a service that does not exist is not a leftover; a plain system driver still declared elsewhere is skipped
    auto found = find_driver_leftovers({{L"DefinitelyNotAService_ddcore", L"oem1.inf"}}, {});
    CHECK(found.empty());
}

static void test_real_machine() {
    std::vector<Package> packages;
    try {
        packages = list_packages();
    } catch (const std::exception&) {
    }
    CHECK(!packages.empty());
    for (const auto& p : packages) CHECK(is_published_name(p.published) && !p.original.empty());
    auto bound = read_bindings();
    CHECK(!bound.empty());
    std::size_t unused = 0;
    try {
        unused = find_unused(packages, bound).size();
    } catch (const std::exception&) {
    }
    std::printf("  machine: %zu third-party driver packages, %zu bindings, %zu unused\n", packages.size(), bound.size(), unused);
}

int run_driver_tests() {
    test_parse_and_judge();
    test_removal_with_backups();
    test_complete_uninstall();
    test_real_machine();
    std::printf("drivers: %d checks, %d failed\n", checks, failures);
    return failures;
}
