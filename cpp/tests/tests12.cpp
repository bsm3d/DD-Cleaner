// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Tests the advanced tweaks: catalogue, command splitting, snapshot, revert allow-list, runner and telemetry scan.

#include <cstdio>
#include <filesystem>

#include <windows.h>

#include <ddcore/audit.hpp>
#include <ddcore/tweaks.hpp>

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

namespace {

using Pairs = std::vector<std::pair<std::wstring, std::wstring>>;

Json state_missing() {
    Json s = Json::object();
    s.set(L"exists", Json::boolean(false));
    return s;
}
Json state_dword(unsigned long v) {
    Json s = Json::object();
    s.set(L"exists", Json::boolean(true));
    s.set(L"type", Json::number((double)REG_DWORD));
    s.set(L"data", Json::number((double)v));
    return s;
}
Json state_text(const std::wstring& v) {
    Json s = Json::object();
    s.set(L"exists", Json::boolean(true));
    s.set(L"type", Json::number((double)REG_SZ));
    s.set(L"data", Json::string(v));
    return s;
}

void test_catalogue() {
    CHECK(tweak_preset(L"Safe (Recommended)").size() == 8);
    CHECK(tweak_preset(L"Medium").size() == 13);
    CHECK(tweak_preset(L"Aggressive").size() == 16 && tweak_preset(L"Custom").size() == 16);
    CHECK(tweak_preset(L"nope").empty());
    CHECK(tweak_preset_names().size() == 4);
    CHECK(win10_default_restore().size() == 15);
    for (const auto& t : tweak_preset(L"Custom")) CHECK(!hardening_argv(t.command).empty());   // every catalogue command is runnable
}

void test_shlex() {
    auto s = shlex_split(L"sc config DiagTrack start= disabled");
    CHECK(s.size() == 5 && s[4] == L"disabled");
    s = shlex_split(L"reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\" /v Enabled /f");
    CHECK(s.size() == 6 && s[2] == L"HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings");   // a backslash inside quotes stays
    s = shlex_split(L"a \"b \\\" c\" 'd \\ e' f\\ g");
    CHECK(s.size() == 4 && s[1] == L"b \" c" && s[2] == L"d \\ e" && s[3] == L"f g");
    s = shlex_split(L"x \"\" y");
    CHECK(s.size() == 3 && s[1].empty());   // an empty quoted argument is kept
    CHECK(shlex_split(L"   ").empty());
    bool threw = false;
    try {
        shlex_split(L"a \"b");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    CHECK(threw);
    threw = false;
    try {
        shlex_split(L"a\\");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    CHECK(threw);
}

void test_argv() {
    auto a = hardening_argv(L"sc config X start= disabled");
    CHECK(a.size() == 5 && ends_with(lower(a[0]), L"\\system32\\sc.exe"));
    a = hardening_argv(L"REG.EXE delete K /f");
    CHECK(ends_with(lower(a[0]), L"\\system32\\reg.exe"));
    a = hardening_argv(L"assoc .js=");
    CHECK(a.size() == 5 && ends_with(lower(a[0]), L"\\cmd.exe") && a[1] == L"/d" && a[2] == L"/c" && a[3] == L"assoc" && a[4] == L".js=");
    for (const wchar_t* bad : {L"powershell -c x", L"cmd /c dir", L"del C:\\x", L"C:\\evil.exe", L""}) {
        bool threw = false;
        try {
            hardening_argv(bad);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        CHECK(threw);
    }
    CHECK(open_in_editor(L"assoc .js=") == L"assoc .js=txtfile");
    CHECK(open_in_editor(L"assoc .js=JSFile") == L"assoc .js=JSFile");
    CHECK(open_in_editor(L"sc config X start= disabled") == L"sc config X start= disabled");
    CHECK(open_in_editor(L"assoc .toolongextension1=") == L"assoc .toolongextension1=");
}

void test_paths_and_targets() {
    CHECK(normalize_registry_path(L"hklm\\Software\\") == L"HKEY_LOCAL_MACHINE\\Software");
    CHECK(normalize_registry_path(L"  HKCU\\\\A\\\\B ") == L"HKEY_CURRENT_USER\\A\\B");
    CHECK(normalize_registry_path(L"HKU") == L"HKEY_USERS" && normalize_registry_path(L"") == L"");
    CHECK(normalize_registry_path(L"Other\\x") == L"OTHER\\x");
    TweakTarget t = parse_target(L"sc config DiagTrack start= disabled");
    CHECK(t.kind == L"service" && t.service == L"DiagTrack");
    t = parse_target(L"reg add \"HKLM\\A\" /v Enabled /t REG_DWORD /d 0 /f");
    CHECK(t.kind == L"reg" && t.key == L"HKLM\\A" && t.has_value && t.value == L"Enabled");
    t = parse_target(L"reg delete HKLM\\A /ve /f");
    CHECK(t.kind == L"reg" && !t.has_value);
    t = parse_target(L"assoc .js=JSFile");
    CHECK(t.kind == L"assoc" && t.ext == L".js");
    CHECK(parse_target(L"del x").kind == L"unknown" && parse_target(L"a \"b").kind == L"unknown");
    AllowedTargets allowed = allowed_targets();
    CHECK(allowed.services.count(L"diagtrack") && allowed.services.count(L"xblgamesave") && !allowed.services.count(L"spooler"));
    CHECK(allowed.assocs.count(L".hta") && allowed.assocs.size() == 6);
    CHECK(allowed.registry.count({L"hkey_local_machine\\software\\microsoft\\windows script host\\settings", L"enabled"}));
    CHECK(allowed.registry.count({L"hkey_current_user\\software\\microsoft\\siuf\\rules", L"numberofsiufinperiod"}));
}

// A fake reader: values by (key|value), everything else missing
RegistryReader fake_reader(std::map<std::wstring, Json> values) {
    return [values](const std::wstring& key, const std::wstring& value, bool) {
        auto it = values.find(lower(normalize_registry_path(key) + L"|" + value));
        return it == values.end() ? state_missing() : it->second;
    };
}

void test_snapshot_and_revert() {
    std::wstring services = L"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\";
    std::map<std::wstring, Json> values;
    values[lower(services + L"DiagTrack|Start")] = state_dword(2);
    values[lower(services + L"DiagTrack|DelayedAutostart")] = state_dword(1);
    values[lower(services + L"RemoteRegistry|Start")] = state_dword(3);
    values[lower(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\.js|")] = state_text(L"JSFile");
    // WSH Enabled: absent. IgnoreUserSettings: present with 0
    values[lower(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings|IgnoreUserSettings")] = state_dword(0);
    RegistryReader reader = fake_reader(values);

    Pairs tweaks;
    for (const wchar_t* name : {L"Disable DiagTrack", L"Disable RemoteRegistry", L"Unassociate .js", L"Disable WSH", L"WSH: ignore user settings"}) {
        for (const auto& t : tweak_preset(L"Custom")) {
            if (t.name == name) tweaks.emplace_back(t.name, t.command);
        }
    }
    CHECK(tweaks.size() == 5);
    Json entries = snapshot_entries(tweaks, reader);
    CHECK(entries.as_list().size() == 5 && entries.at(0).get(L"kind").str() == L"service" && entries.at(0).get(L"start").get(L"data").integer() == 2);

    std::vector<std::wstring> ignored;
    Pairs cmds = revert_commands(entries, &ignored);
    CHECK(ignored.empty() && cmds.size() == 5);
    CHECK(cmds[0].second == L"sc config DiagTrack start= delayed-auto");     // automatic (delayed start) comes back as it was
    CHECK(cmds[1].second == L"sc config RemoteRegistry start= demand");
    CHECK(cmds[2].second == L"assoc .js=JSFile");
    CHECK(cmds[3].second.find(L"reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\" /v Enabled /f") == 0);   // it was absent: removed
    CHECK(cmds[4].second.find(L"reg add ") == 0 && cmds[4].second.find(L"/t REG_DWORD /d 0 /f") != std::wstring::npos);
    for (const auto& c : cmds) CHECK(!hardening_argv(c.second).empty());   // everything produced can be run

    // file round trip
    std::wstring dir = join(exe_dir(), L"tweaks_backup_" + std::to_wstring(GetCurrentProcessId()));
    std::wstring file = snapshot_tweaks(tweaks, dir, reader);
    CHECK(!file.empty() && is_file(file) && starts_with(base_name(file), L"tweaks_backup_"));
    CHECK(revert_commands_from_snapshot(file).size() == 5);
    std::wstring second = snapshot_tweaks(tweaks, dir, reader);
    CHECK(!second.empty() && second != file);   // two snapshots in the same second never collide
    bool threw = false;
    try {
        revert_commands_from_snapshot(join(dir, L"missing.json"));
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
    CHECK(write_file(join(dir, L"junk.json"), "{ not json"));
    threw = false;
    try {
        revert_commands_from_snapshot(join(dir, L"junk.json"));
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
    CHECK(write_file(join(dir, L"array.json"), "[1,2]") && revert_commands_from_snapshot(join(dir, L"array.json")).empty());
    std::filesystem::remove_all(dir);
}

Json entry(const wchar_t* kind) {
    Json e = Json::object();
    e.set(L"name", Json::string(L"tampered"));
    e.set(L"kind", Json::string(kind));
    return e;
}

void test_tampered_entries() {
    Json entries = Json::array();
    Json svc = entry(L"service");   // a service that is not in the catalogue
    svc.set(L"service", Json::string(L"Spooler"));
    svc.set(L"start", state_dword(2));
    entries.push(svc);
    Json inj = entry(L"service");   // an injection through the name
    inj.set(L"service", Json::string(L"DiagTrack & calc"));
    inj.set(L"start", state_dword(2));
    entries.push(inj);
    Json bad_start = entry(L"service");
    bad_start.set(L"service", Json::string(L"DiagTrack"));
    bad_start.set(L"start", state_dword(9));
    entries.push(bad_start);
    Json reg = entry(L"reg");   // a registry value that is not in the catalogue
    reg.set(L"key", Json::string(L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"));
    reg.set(L"value", Json::string(L"x"));
    reg.set(L"state", state_dword(1));
    entries.push(reg);
    Json quotes = entry(L"reg");   // a catalogue value, but string data that would split into other arguments
    quotes.set(L"key", Json::string(L"HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings"));
    quotes.set(L"value", Json::string(L"Enabled"));
    quotes.set(L"state", state_text(L"x\" /d evil"));
    entries.push(quotes);
    Json binary = entry(L"reg");
    binary.set(L"key", Json::string(L"HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings"));
    binary.set(L"value", Json::string(L"Enabled"));
    Json bin = Json::object();
    bin.set(L"exists", Json::boolean(true));
    bin.set(L"type", Json::number(3));
    bin.set(L"data", Json::string(L"00ff"));
    binary.set(L"state", bin);
    entries.push(binary);
    Json assoc = entry(L"assoc");
    assoc.set(L"ext", Json::string(L".exe"));
    assoc.set(L"state", state_text(L"exefile"));
    entries.push(assoc);
    Json progid = entry(L"assoc");   // a catalogue extension, but a ProgID that is not a ProgID
    progid.set(L"ext", Json::string(L".js"));
    progid.set(L"state", state_text(L"JS File & calc"));
    entries.push(progid);
    entries.push(Json::string(L"not an object"));
    Json missing = entry(L"service");   // the service had no Start value: nothing to restore, and nothing wrong
    missing.set(L"service", Json::string(L"DiagTrack"));
    missing.set(L"start", state_missing());
    entries.push(missing);

    std::vector<std::wstring> ignored;
    Pairs cmds = revert_commands(entries, &ignored);
    CHECK(cmds.empty());
    CHECK(ignored.size() == 8);
}

void test_runner() {
    std::vector<std::wstring> seen, said;
    auto runner = [&](const std::vector<std::wstring>& argv) {
        seen.push_back(argv[0]);
        ProcResult r;
        r.started = true;
        r.code = argv.back() == L"fail" ? 5 : 0;
        r.output = L"  done  \n";
        return r;
    };
    Pairs tweaks = {{L"one", L"sc config DiagTrack start= disabled"}, {L"two", L"sc config X fail"}, {L"three", L"powershell x"}};
    TweakRunResult res = run_tweaks(tweaks, [&](const std::wstring& s) { said.push_back(s); }, nullptr, runner);
    CHECK(res.ok == 1 && res.failed == 2 && seen.size() == 2);   // the disallowed command never reaches the runner
    std::wstring all;
    for (const auto& s : said) all += s;
    CHECK(all.find(L"> one\n$ sc config DiagTrack start= disabled\ndone\n\u2705 Success") != std::wstring::npos);
    CHECK(all.find(L"Exit code: 5") != std::wstring::npos && all.find(L"Command not allowed: powershell") != std::wstring::npos);
    // stopping ends the run
    int calls = 0;
    run_tweaks(tweaks, nullptr, [&] { return calls++ > 0; }, runner);
    CHECK(calls == 2);
}

Json dns(const wchar_t* entry_name, const wchar_t* ip) {
    Json d = Json::object();
    d.set(L"Entry", Json::string(entry_name));
    d.set(L"Data", Json::string(ip));
    return d;
}
Json conn(const wchar_t* ip, int pid) {
    Json c = Json::object();
    c.set(L"RemoteAddress", Json::string(ip));
    c.set(L"OwningProcess", Json::number(pid));
    return c;
}
Json proc(int id, const wchar_t* name) {
    Json p = Json::object();
    p.set(L"Id", Json::number(id));
    p.set(L"ProcessName", Json::string(name));
    return p;
}

Json sample() {
    Json s = Json::object();
    Json d = Json::array(), c = Json::array(), p = Json::array();
    d.push(dns(L"Vortex.Data.Microsoft.com", L"20.1.1.1"));
    d.push(dns(L"watson.events.data.microsoft.com", L"20.1.1.2"));
    d.push(dns(L"example.org", L"93.184.216.34"));
    c.push(conn(L"20.1.1.1", 100));
    c.push(conn(L"20.1.1.2", 100));
    c.push(conn(L"93.184.216.34", 200));
    c.push(conn(L"20.9.9.9", 300));   // not in the DNS cache: cannot be identified
    p.push(proc(100, L"svchost"));
    p.push(proc(200, L"browser"));
    s.set(L"dns", d);
    s.set(L"conn", c);
    s.set(L"proc", p);
    return s;
}

void test_telemetry() {
    TelemetryState state;
    telemetry_add_sample(state, sample());
    telemetry_add_sample(state, sample());   // the same sample again adds nothing
    TelemetryResult r = telemetry_result(state, 2);
    CHECK(r.hits.size() == 1 && r.hits[0].pid == 100 && r.hits[0].process == L"svchost" && r.hits[0].connections.size() == 2);
    CHECK(r.hits[0].connections[0].first == L"20.1.1.1" && r.hits[0].connections[0].second == L"vortex.data.microsoft.com");
    std::wstring text = r.report();
    CHECK(text.find(L"Results (2 samples)") != std::wstring::npos && text.find(L"svchost (PID 100): 2 connection(s)") != std::wstring::npos);
    CHECK(text.find(L"browser") == std::wstring::npos);
    CHECK(TelemetryResult().report().find(L"No connection to Microsoft/telemetry hosts") != std::wstring::npos);

    // the scan loop, with a scripted sampler (the second call fails, the first and third work)
    int calls = 0;
    std::vector<std::wstring> said;
    TelemetryResult scanned = telemetry_scan(400, 1, nullptr,
                                             [&]() -> Json {
                                                 if (++calls == 2) throw std::runtime_error("boom");
                                                 return sample();
                                             },
                                             [&](const std::wstring& s) { said.push_back(s); });
    CHECK(calls >= 3 && scanned.samples == calls && scanned.hits.size() == 1);
    CHECK(!said.empty() && said[0].find(L"Sample error: boom") != std::wstring::npos);
    // a stop request ends it at once
    int n = 0;
    telemetry_scan(60000, 1, [&] { return ++n > 3; }, [] { return sample(); });
    CHECK(n < 100);
}

}  // namespace

int run_tweaks_tests() {
    int start_checks = checks, start_failures = failures;
    test_catalogue();
    test_shlex();
    test_argv();
    test_paths_and_targets();
    test_snapshot_and_revert();
    test_tampered_entries();
    test_runner();
    test_telemetry();
    std::printf("tweaks: %d checks, %d failed\n", checks - start_checks, failures - start_failures);
    return failures;
}
