// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Tests the security audit and the hardening against a fake system, so no real registry or PowerShell is touched.

#include <cstdio>
#include <filesystem>

#include <windows.h>

#include <ddcore/audit.hpp>
#include <ddcore/json.hpp>

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

struct Fake {
    std::map<std::wstring, RegistryState> regs;
    std::vector<std::wstring> ps_calls;
    std::vector<std::vector<std::wstring>> exe_calls;
    bool remote = false;
    bool fail_writes = false;
    int writes = 0;

    std::map<std::wstring, std::wstring> original;   // lower-case key path -> path as written (the real registry keeps the case)
    static std::wstring key(const std::wstring& h, const std::wstring& p, const std::wstring& n) { return lower(h + L"|" + p + L"|" + n); }
    void note(const std::wstring& h, const std::wstring& p) { original[lower(h + L"|" + p)] = p; }
    void set_dword(const std::wstring& h, const std::wstring& p, const std::wstring& n, unsigned long v) {
        RegistryState s;
        s.exists = true;
        s.type = REG_DWORD;
        s.number = v;
        note(h, p);
        regs[key(h, p, n)] = s;
    }
    unsigned long dword(const std::wstring& h, const std::wstring& p, const std::wstring& n) { return (unsigned long)regs[key(h, p, n)].number; }
    bool has(const std::wstring& h, const std::wstring& p, const std::wstring& n) { return regs.count(key(h, p, n)) && regs[key(h, p, n)].exists; }
};

Fake* fake = nullptr;
SystemHooks saved;

void install(Fake& f) {
    fake = &f;
    SystemHooks& h = system_hooks();
    saved = h;
    h.ps_json = [](const std::wstring& script, unsigned long) {
        fake->ps_calls.push_back(script);
        return PsJson();
    };
    h.ps = [](const std::wstring& script) {
        fake->ps_calls.push_back(script);
        return 0;
    };
    h.run_exe = [](const std::vector<std::wstring>& argv) {
        fake->exe_calls.push_back(argv);
        return 0;
    };
    h.remote_session = [] { return fake->remote; };
    h.registry.read = [](const std::wstring& hive, const std::wstring& path, const std::wstring& name) {
        auto it = fake->regs.find(Fake::key(hive, path, name));
        return it == fake->regs.end() ? RegistryState() : it->second;
    };
    h.registry.write = [](const std::wstring& hive, const std::wstring& path, const std::wstring& name, unsigned long type, const std::string& bytes) {
        if (fake->fail_writes) return false;
        ++fake->writes;
        RegistryState s;
        s.exists = true;
        s.type = type;
        s.raw = bytes;
        if (type == REG_DWORD && bytes.size() == 4) {
            unsigned long v;
            memcpy(&v, bytes.data(), 4);
            s.number = v;
        } else if (type == REG_SZ || type == REG_EXPAND_SZ) {
            s.text = std::wstring(reinterpret_cast<const wchar_t*>(bytes.data()), bytes.size() / 2 - 1);
        }
        fake->note(hive, path);
        fake->regs[Fake::key(hive, path, name)] = s;
        return true;
    };
    h.registry.remove = [](const std::wstring& hive, const std::wstring& path, const std::wstring& name) {
        fake->regs.erase(Fake::key(hive, path, name));
        return true;
    };
    h.registry.subkeys = [](const std::wstring& hive, const std::wstring& path) {
        std::vector<std::wstring> out;
        std::wstring prefix = lower(hive + L"|" + path + L"\\");
        std::set<std::wstring> seen;
        for (const auto& kv : fake->regs) {
            if (!starts_with(kv.first, prefix)) continue;
            std::wstring rest = kv.first.substr(prefix.size());
            std::size_t bar = rest.find(L'|');
            std::size_t slash = rest.find(L'\\');
            std::wstring sub = rest.substr(0, std::min(bar, slash));
            if (!seen.insert(sub).second) continue;
            auto orig = fake->original.find(lower(hive + L"|" + path + L"\\" + sub));
            out.push_back(orig == fake->original.end() ? sub : base_name(orig->second));
        }
        return out;
    };
    h.registry.key_exists = [](const std::wstring& hive, const std::wstring& path) {
        std::wstring prefix = lower(hive + L"|" + path + L"|");
        for (const auto& kv : fake->regs) {
            if (starts_with(kv.first, prefix)) return true;
        }
        return false;
    };
}

void uninstall() {
    system_hooks() = saved;
    fake = nullptr;
}

const std::wstring LSA = L"SYSTEM\\CurrentControlSet\\Control\\Lsa";
const std::wstring WDIGEST = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest";
const std::wstring NB = L"SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces";
const std::wstring IFACE1 = L"Tcpip_{0A1B2C3D-0000-1111-2222-333344445555}";
const std::wstring IFACE2 = L"Tcpip_{0A1B2C3D-0000-1111-2222-333344446666}";

std::vector<std::wstring> homes;

std::wstring fresh_home(const wchar_t* name) {
    std::wstring dir = join(exe_dir(), std::wstring(name) + L"_" + std::to_wstring(GetCurrentProcessId()));
    make_dirs(dir);
    homes.push_back(dir);
    SetEnvironmentVariableW(L"DDCLEANER_HOME", dir.c_str());
    return dir;
}

void test_names() {
    CHECK(std::wstring(risk_name(Risk::Critical)) == L"Critical" && std::wstring(domain_name(Domain::Network)) == L"Network");
    Risk r;
    Domain d;
    Profile p;
    CHECK(parse_risk(L"high", r) && r == Risk::High);
    CHECK(parse_risk(L"\u00c9lev\u00e9", r) && r == Risk::High);   // older backups: French
    CHECK(parse_domain(L"R\u00e9seau", d) && d == Domain::Network);
    CHECK(parse_profile(L"Recommand\u00e9", p) && p == Profile::Recommended);
    CHECK(!parse_profile(L"nonsense", p) && !parse_risk(L"", r));
    CHECK(profile_action_count(Profile::Basic) == 4 && profile_action_count(Profile::Recommended) == 8 && profile_action_count(Profile::Strict) == 13);
    CHECK(profile_actions(Profile::Strict).size() == 13);
    CHECK(find_action(L"sam_restrict") && !find_action(L"evil"));
    CHECK(find_action(L"admin_disable")->rid == 500 && find_action(L"guest_disable")->rid == 501);
}

void test_scores() {
    DomainScore s;
    s.max_score = 30;
    s.current_score = 30;
    CHECK(s.status().find(L"Excellent") != std::wstring::npos);
    s.current_score = 22;
    CHECK(s.status().find(L"Fair") != std::wstring::npos);
    s.current_score = 16;
    CHECK(s.status().find(L"Medium") != std::wstring::npos);
    s.current_score = 5;
    CHECK(s.status().find(L"Critical") != std::wstring::npos);
    std::map<Domain, DomainScore> all;
    for (auto& [dom, w] : DOMAIN_WEIGHTS) {
        DomainScore x;
        x.domain = dom;
        x.max_score = 10;
        x.current_score = 10;
        all[dom] = x;
    }
    CHECK(SecurityAuditor::global_score(all) == 100);
    all[Domain::Network].current_score = 0;   // 30 of 100 lost
    CHECK(SecurityAuditor::global_score(all) == 70);
}

void test_registry_state() {
    RegistryState s;
    CHECK(!s.numeric());
    s.exists = true;
    s.type = REG_SZ;
    s.text = L" 5 ";
    CHECK(s.numeric() && s.as_int() == 5);
    s.text = L"abc";
    CHECK(!s.numeric());
    s.type = REG_DWORD;
    s.number = 7;
    CHECK(s.numeric() && s.as_int() == 7);
}

void test_apply_and_revert_registry() {
    fresh_home(L"audit_home1");
    Fake f;
    f.set_dword(L"HKLM", LSA, L"RestrictAnonymousSAM", 0);   // present before: must come back as 0
    // WDigest value absent before: must be absent again after the revert
    install(f);
    HardeningEngine engine;
    ApplyResult res = engine.apply_profile(Profile::Recommended, {L"sam_restrict", L"wdigest_disable"}, false, false);
    CHECK(res.success == 2 && res.failures == 0);
    CHECK(f.dword(L"HKLM", LSA, L"RestrictAnonymousSAM") == 1);
    CHECK(f.has(L"HKLM", WDIGEST, L"UseLogonCredential") && f.dword(L"HKLM", WDIGEST, L"UseLogonCredential") == 0);
    CHECK(!engine.last_backup_path.empty() && is_file(engine.last_backup_path));
    CHECK(list_hardening_backups().size() == 1);

    Backup b;
    std::string bytes;
    Json data;
    CHECK(read_file(engine.last_backup_path, bytes) && try_parse_json(wide(bytes), data) && Backup::from_json(data, b));
    CHECK(b.entries.size() == 2 && b.entries[0].status == L"applied" && b.entries[1].status == L"applied");
    CHECK(!b.restore_point_ok);

    auto undone = engine.revert_last();
    CHECK(undone.first == 2 && undone.second == 0);
    CHECK(f.dword(L"HKLM", LSA, L"RestrictAnonymousSAM") == 0);
    CHECK(!f.has(L"HKLM", WDIGEST, L"UseLogonCredential"));
    Backup after;
    CHECK(engine.load_backup(engine.last_backup_path, after) && after.entries[0].status == L"reverted" && !after.reverted.empty());
    auto again = engine.revert_last();   // nothing left to revert
    CHECK(again.first == 0 && again.second == 0);
    uninstall();
}

void test_revert_single_action() {
    fresh_home(L"audit_home2");
    Fake f;
    f.set_dword(L"HKLM", LSA, L"LmCompatibilityLevel", 3);
    install(f);
    HardeningEngine engine;
    ApplyResult res = engine.apply_profile(Profile::Strict, {L"ntlmv2_enforce"}, false, false);
    CHECK(res.success == 1 && f.dword(L"HKLM", LSA, L"LmCompatibilityLevel") == 5);
    CHECK(engine.revert_action(L"ntlmv2_enforce") && f.dword(L"HKLM", LSA, L"LmCompatibilityLevel") == 3);
    CHECK(!engine.revert_action(L"ntlmv2_enforce"));   // already reverted
    CHECK(!engine.revert_action(L"no_such_action"));
    uninstall();
}

void test_netbios() {
    fresh_home(L"audit_home3");
    Fake f;
    f.set_dword(L"HKLM", NB + L"\\" + IFACE1, L"NetbiosOptions", 0);
    f.set_dword(L"HKLM", NB + L"\\" + IFACE2, L"NetbiosOptions", 1);
    f.set_dword(L"HKLM", NB + L"\\NotAnInterface", L"NetbiosOptions", 1);   // never touched
    install(f);
    HardeningEngine engine;
    ApplyResult res = engine.apply_profile(Profile::Strict, {L"netbios_disable"}, false, false);
    CHECK(res.success == 1);
    CHECK(f.dword(L"HKLM", NB + L"\\" + IFACE1, L"NetbiosOptions") == 2 && f.dword(L"HKLM", NB + L"\\" + IFACE2, L"NetbiosOptions") == 2);
    CHECK(f.dword(L"HKLM", NB + L"\\NotAnInterface", L"NetbiosOptions") == 1);
    CHECK(engine.revert_last().first == 1);
    CHECK(f.dword(L"HKLM", NB + L"\\" + IFACE1, L"NetbiosOptions") == 0 && f.dword(L"HKLM", NB + L"\\" + IFACE2, L"NetbiosOptions") == 1);
    // already disabled everywhere: skipped, recorded, nothing written
    f.set_dword(L"HKLM", NB + L"\\" + IFACE1, L"NetbiosOptions", 2);
    f.set_dword(L"HKLM", NB + L"\\" + IFACE2, L"NetbiosOptions", 2);
    f.writes = 0;
    ApplyResult skipped = engine.apply_profile(Profile::Strict, {L"netbios_disable"}, false, false);
    CHECK(skipped.success == 0 && skipped.failures == 0 && f.writes == 0 && engine.last_skipped.size() == 1);
    uninstall();
}

void test_prechecks_and_aborts() {
    fresh_home(L"audit_home4");
    Fake f;
    f.set_dword(L"HKLM", L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", L"fDenyTSConnections", 0);
    f.remote = true;
    install(f);
    HardeningEngine engine;
    ApplyResult res = engine.apply_profile(Profile::Strict, {L"rdp_disable"}, false, false);
    CHECK(res.success == 0 && engine.last_skipped.size() == 1);   // a remote session must not be cut off
    CHECK(f.dword(L"HKLM", L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", L"fDenyTSConnections") == 0);

    // a restore point required but not requested: abort, change nothing
    f.remote = false;
    f.writes = 0;
    ApplyResult aborted = engine.apply_profile(Profile::Strict, {L"rdp_disable"}, false, true);
    CHECK(aborted.failures == 1 && f.writes == 0 && aborted.errors[0].find(L"Aborted") == 0);

    // a failing write is a failure, not a success
    f.fail_writes = true;
    ApplyResult failed = engine.apply_profile(Profile::Strict, {L"rdp_disable"}, false, false);
    CHECK(failed.success == 0 && failed.failures == 1);
    f.fail_writes = false;
    uninstall();
}

void test_tampered_backup() {
    fresh_home(L"audit_home5");
    Fake f;
    install(f);
    HardeningEngine engine;
    // an entry naming an id that is not in the catalogue, and an entry whose type does not match the catalogue
    Backup b;
    b.created = L"x";
    b.entries.push_back({L"evil", L"evil", L"registry", Json::object(), L"applied", L""});
    Json before = Json::object();
    Json values = Json::object();
    Json bad = Json::object();
    bad.set(L"exists", Json::boolean(true));
    bad.set(L"type", Json::number((double)REG_SZ));
    bad.set(L"data", Json::string(L"C:\\evil.exe"));
    values.set(L"RestrictAnonymousSAM", bad);
    before.set(L"values", values);
    b.entries.push_back({L"sam_restrict", L"sam", L"registry", before, L"applied", L""});
    std::wstring path = join(hardening_backup_dir(), L"hardening_backup_tampered.json");
    CHECK(write_file(path, utf8(b.to_json().dump(true))));
    auto r = engine.revert_backup(path);
    CHECK(r.first == 0 && r.second == 2);
    CHECK(!f.has(L"HKLM", LSA, L"RestrictAnonymousSAM"));   // nothing was written
    uninstall();
}

void test_service_and_scripts() {
    fresh_home(L"audit_home6");
    Fake f;
    f.set_dword(L"HKLM", L"SYSTEM\\CurrentControlSet\\Services\\RemoteRegistry", L"Start", 3);
    install(f);
    HardeningEngine engine;
    ApplyResult res = engine.apply_profile(Profile::Strict, {L"remote_registry_disable"}, false, false);
    CHECK(res.success == 1 && f.exe_calls.size() == 1);
    CHECK(f.exe_calls[0].size() == 5 && f.exe_calls[0][1] == L"config" && f.exe_calls[0][2] == L"RemoteRegistry" && f.exe_calls[0][4] == L"disabled");
    CHECK(ends_with(lower(f.exe_calls[0][0]), L"\\system32\\sc.exe"));
    f.exe_calls.clear();
    CHECK(engine.revert_last().first == 1 && f.exe_calls.size() == 1 && f.exe_calls[0][4] == L"demand");
    uninstall();
}

}  // namespace

int run_audit_tests() {
    int start_checks = checks, start_failures = failures;
    test_names();
    test_scores();
    test_registry_state();
    test_apply_and_revert_registry();
    test_revert_single_action();
    test_netbios();
    test_prechecks_and_aborts();
    test_tampered_backup();
    test_service_and_scripts();
    for (const auto& h : homes) std::filesystem::remove_all(h);
    std::printf("audit: %d checks, %d failed\n", checks - start_checks, failures - start_failures);
    return failures;
}
