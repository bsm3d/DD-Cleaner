// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Tests the inventory and health evaluators on fake data, and a read of the real machine.

#include <cstdio>

#include <ddcore/sysinfo.hpp>

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

static bool has_detail(const HealthItem& item, const std::wstring& part) {
    for (const auto& d : item.details) {
        if (d.find(part) != std::wstring::npos) return true;
    }
    return false;
}

static void test_parsers() {
    long long code = 0;
    CHECK(parse_bugcheck(L"0x0000009f (0x3, 0xffff)", code) && code == 0x9F);
    CHECK(parse_bugcheck(L"159", code) && code == 159);
    CHECK(!parse_bugcheck(L"", code) && !parse_bugcheck(L"abc", code));
    CHECK(bugcheck_name(0x9F) == L"DRIVER_POWER_STATE_FAILURE" && bugcheck_name(0x12345).empty());
    CHECK(parse_time(L"2026-11-21T10:00:00") - parse_time(L"2026-11-21T09:50:00") == 600);
    CHECK(parse_time(L"2026-11-22T00:00:00") - parse_time(L"2026-11-21T00:00:00") == 86400);
    CHECK(parse_time(L"nonsense") == 0);

    // a CPER record: signature, a notification GUID at offset 80 and a STORPORT section naming the driver
    std::vector<unsigned char> raw(128, 0);
    memcpy(raw.data(), "CPER", 4);
    const unsigned char pci[16] = {0x1f, 0xc0, 0x93, 0xcf, 0x16, 0x1a, 0xfc, 0x4d, 0xb8, 0xbc, 0x9c, 0x4d, 0xaf, 0x67, 0xc1, 0x04};
    memcpy(raw.data() + 80, pci, 16);
    auto to_text = [](const std::vector<unsigned char>& bytes) {
        std::wstring t;
        for (auto b : bytes) t += std::to_wstring(b) + L" ";
        return t;
    };
    WheaRecord rec;
    CHECK(decode_whea_record(to_text(raw), rec) && rec.source == L"PCI Express" && rec.driver.empty());
    const char* section = "STORPORT";
    raw.insert(raw.end(), section, section + 8);
    for (char c : std::string("stornvme")) {
        raw.push_back((unsigned char)c);
        raw.push_back(0);
    }
    raw.push_back(0);
    for (char c : std::string("Samsung SSD 980")) raw.push_back((unsigned char)c);
    CHECK(decode_whea_record(to_text(raw), rec));
    CHECK(rec.source == L"Storage controller (storport)" && rec.driver == L"stornvme" && rec.device == L"Samsung SSD 980");
    CHECK(!decode_whea_record(L"1 2 3", rec) && !decode_whea_record(L"not numbers", rec));
}

static void test_disks_and_volumes() {
    CHECK(evaluate_disks(Json())[0].status == Status::Unknown);
    Json data = parse_json(LR"J({"disks":[
        {"DeviceId":"0","Name":"Fast SSD","Media":"SSD","Bus":"NVMe","Serial":"S1","Health":"Healthy","Status":"OK","Size":1000000000000,
         "Reliability":{"Temperature":75,"TemperatureMax":80,"Wear":10,"ReadErrorsUncorrected":0,"WriteErrorsUncorrected":0,"PowerOnHours":500}},
        {"DeviceId":"1","Name":"Old HDD","Media":"HDD","Bus":"SATA","Serial":"S2","Health":"Unhealthy","Status":"Degraded","Size":2000000000000,"Reliability":null},
        {"DeviceId":"2","Name":"Worn","Media":"SSD","Bus":"SATA","Serial":"S3","Health":"Healthy","Status":"OK","Size":500000000000,
         "Reliability":{"Temperature":30,"Wear":95}}],
        "smart":[{"Instance":"disk1","PredictFailure":true}]})J");
    auto items = evaluate_disks(data);
    CHECK(items.size() == 4);
    CHECK(items[0].status == Status::Warning && has_detail(items[0], L"Temperature is high"));   // 75 >= 70 for an SSD
    CHECK(items[0].title == L"Fast SSD (SSD, NVMe, 1000 GB)");
    CHECK(items[1].status == Status::Critical && has_detail(items[1], L"not available"));
    CHECK(items[2].status == Status::Critical && has_detail(items[2], L"Wear: 95 %"));
    CHECK(items[3].status == Status::Critical && items[3].title.find(L"SMART predicts a failure on 1") == 0);
    Json no_smart = parse_json(LR"J({"disks":[],"smart":null})J");
    auto none = evaluate_disks(no_smart);
    CHECK(none.size() == 1 && none[0].status == Status::Info);   // SMART unreadable, no disks listed -> only the SMART note

    auto vols = evaluate_volumes({{L"C:\\", 1000000000000ull, 40000000000ull, true},    // 4 %: critical
                                  {L"D:\\", 1000000000000ull, 80000000000ull, false},   // 8 %: warning
                                  {L"E:\\", 1000000000000ull, 500000000000ull, false}});
    CHECK(vols[0].status == Status::Critical && has_detail(vols[0], L"updates need several GB"));
    CHECK(vols[1].status == Status::Warning);
    CHECK(vols[2].status == Status::Ok && vols[2].title == L"E:\\ 500.0 GB free of 1000 GB (50 %)");
}

static void test_stability_and_crashes() {
    CHECK(evaluate_stability(parse_json(LR"J({"stability":{"Current":8.2,"Minimum":5.0,"Samples":10}})J")).status == Status::Ok);
    CHECK(evaluate_stability(parse_json(LR"J({"stability":{"Current":5.0,"Minimum":2.0}})J")).status == Status::Warning);
    CHECK(evaluate_stability(parse_json(LR"J({"stability":{"Current":2.0,"Minimum":1.0}})J")).status == Status::Critical);
    CHECK(evaluate_stability(parse_json(LR"J({"stability":null})J")).status == Status::Unknown);

    Json events = parse_json(LR"J({
      "bugchecks":[{"Time":"2026-11-10T10:00:00","Props":["0x0000009f (0x3)"]},{"Time":"2026-11-11T10:00:00","Props":["0x0000009f"]}],
      "kernel_power":[{"Time":"2026-11-10T10:03:00","Props":["159"]},{"Time":"2026-11-15T08:00:00","Props":["0"]},{"Time":"2026-11-16T08:00:00","Props":["0"]},
                      {"Time":"2026-11-18T12:00:00","Props":["278"]}],
      "whea":[{"Id":18,"Level":2,"Time":"2026-11-12T09:00:00","Props":["x","y"],"Message":"A fatal hardware error"}],
      "storage":[{"Id":153,"Provider":"disk","Level":3,"Time":"2026-11-13T09:00:00","Props":[],"Message":"The IO operation at Disk 1 was retried"}]})J");
    Json disks = parse_json(LR"J({"disks":[{"DeviceId":"1","Name":"Old HDD","Serial":"S2"}]})J");
    auto items = evaluate_crashes(events, {1.0, 2.0}, disks);
    // 2 bug checks + 1 Kernel-Power 41 with a code that is NOT within 10 minutes of one = 3 blue screens -> critical
    CHECK(items[0].category == L"Crashes" && items[0].status == Status::Critical && items[0].title.find(L"3 blue screen(s)") == 0);
    CHECK(has_detail(items[0], L"0x9F DRIVER_POWER_STATE_FAILURE: 2 time(s)"));
    CHECK(has_detail(items[0], L"0x116"));   // 278 = 0x116
    CHECK(has_detail(items[0], L"2 crash dump(s)"));
    CHECK(items[1].title.find(L"2 unexpected shutdown(s)") == 0 && items[1].status == Status::Warning);
    CHECK(items[2].category == L"Hardware" && items[2].status == Status::Critical);
    bool storage_with_hint = false;
    for (const auto& i : items) {
        if (i.category == L"Storage" && has_detail(i, L"'Disk 1' in the events = Old HDD (serial S2)")) storage_with_hint = true;
    }
    CHECK(storage_with_hint);

    Json quiet = parse_json(LR"J({"bugchecks":[],"kernel_power":[],"whea":[],"storage":[],"app_crashes":[]})J");
    auto calm = evaluate_crashes(quiet, {}, disks);
    CHECK(calm.size() == 3);
    for (const auto& i : calm) CHECK(i.status == Status::Ok);
    CHECK(evaluate_crashes(Json(), {}, disks)[0].status == Status::Unknown);

    HealthItem app;
    CHECK(evaluate_app_crashes(parse_json(LR"J({"app_crashes":[]})J"), app) && app.status == Status::Ok);
    std::wstring many = LR"J({"app_crashes":[)J";
    for (int i = 0; i < 11; ++i) many += std::wstring(i ? L"," : L"") + LR"J({"Id":1000,"Props":["bad.exe"]})J";
    many += LR"J(,{"Id":1002,"Props":["slow.exe"]}]})J";
    CHECK(evaluate_app_crashes(parse_json(many), app) && app.status == Status::Warning);
    CHECK(app.details[0] == L"bad.exe: 11 crash(es)" && app.details[1] == L"slow.exe: 1 hang(s)");
    CHECK(!evaluate_app_crashes(Json(), app));
}

static void test_reviewed_marker() {
    forget_health_reviewed();
    CHECK(health_reviewed_at() == 0);
    CHECK(mark_health_reviewed());
    double t = health_reviewed_at();
    CHECK(t > 1.6e9 && t <= now_seconds() + 1);
    CHECK(minidumps().empty() || minidumps().front() >= t);   // nothing older than the marker counts
    std::vector<std::wstring> report;
    CHECK(clear_event_logs({L"System;x"}, report) == L"" && report.size() == 1 && report[0].find(L"refused") != std::wstring::npos);
    forget_health_reviewed();
    CHECK(health_reviewed_at() == 0);
}

static void test_uptime_and_report() {
    auto fresh = evaluate_uptime(3 * 86400 + 5 * 3600, {});
    CHECK(fresh.size() == 1 && fresh[0].status == Status::Ok && fresh[0].title == L"Up for 3 day(s) 5 h");
    auto stale = evaluate_uptime(40 * 86400, {L"Windows Update is waiting for a restart"});
    CHECK(stale.size() == 2 && stale[0].status == Status::Warning && stale[1].title == L"A restart is pending");

    auto report = build_report(Json(), Json(), {}, 100, {}, {});
    CHECK(report[0].status == Status::Unknown);   // disks unreadable
    CHECK(severity(Status::Critical) > severity(Status::Warning) && severity(Status::Warning) > severity(Status::Unknown));
    LoadResult low{{0.2}, {0.4}}, moderate{{1.5}, {0.4}}, high{{0.5}, {4.0}};
    CHECK(low.verdict().find(L"Low") == 0);
    CHECK(moderate.verdict().find(L"Moderate") == 0);
    CHECK(high.verdict().find(L"High") == 0);
}

static void test_real_machine() {
    auto programs = installed_programs();
    CHECK(!programs.empty());
    for (const auto& p : programs) CHECK(!p.name.empty());
    auto gpus = graphics_cards();
    auto activation = windows_activation();
    CHECK(activation.valid && !activation.edition.empty() && activation.partial_key.size() <= 5);
    auto volumes = fixed_volumes();
    CHECK(!volumes.empty());
    CHECK(uptime_seconds() > 0);
    std::printf("  machine: %zu programs, %zu GPU(s), activation %ls (%ls)\n", programs.size(), gpus.size(),
                activation.status.c_str(), activation.edition.c_str());
}

int run_sysinfo_tests() {
    test_parsers();
    test_disks_and_volumes();
    test_stability_and_crashes();
    test_uptime_and_report();
    test_reviewed_marker();
    test_real_machine();
    std::printf("sysinfo: %d checks, %d failed\n", checks, failures);
    return failures;
}
