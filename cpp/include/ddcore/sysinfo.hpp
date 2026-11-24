// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the system inventory, graphics and activation data, DPC and ISR load, and the health report evaluators.

// The collectors (PowerShell/CIM, event logs, registry) return plain data; the evaluators turn it into HealthItems and never touch the system.
// So they can be tested with fake data.
#pragma once

#include <map>
#include <string>
#include <vector>

#include <ddcore/common.hpp>
#include <ddcore/json.hpp>

namespace dd {

// region Inventory
struct Program {
    std::wstring name, version, publisher, scope, location;
};
std::vector<Program> installed_programs();

struct Gpu {
    std::wstring name, driver_version, driver_date;
    double vram_gb = 0;
    std::wstring resolution;
};
std::map<std::wstring, std::uint64_t> gpu_memory_by_name();
std::vector<Gpu> graphics_cards();

struct Activation {
    std::wstring edition, build, status, channel, partial_key;   // the last five characters of the key, never the key
    bool licensed = false;
    bool valid = false;
};
Activation windows_activation();

struct LoadResult {
    std::vector<double> dpc, isr;
    double worst() const;
    std::wstring verdict() const;
};
LoadResult measure_dpc_isr(int samples = 5);   // throws std::runtime_error when the counters cannot be read
// endregion

// region Health
enum class Status { Ok, Info, Warning, Critical, Unknown };
int severity(Status s);   // ok 0, info 1, unknown 2, warning 3, critical 4
const wchar_t* status_name(Status s);

struct HealthItem {
    std::wstring category;
    Status status = Status::Ok;
    std::wstring title;
    std::vector<std::wstring> details;
};

constexpr int PERIOD_DAYS = 30;

std::wstring bugcheck_name(long long code);                    // "" when unknown
bool parse_bugcheck(const std::wstring& text, long long& code);   // '0x0000009f (0x..., ...)' or '159'
double parse_time(const std::wstring& iso);                     // seconds, 0 when not a date ("2026-11-21T10:00:00")
struct WheaRecord {
    std::wstring source, driver, device;
};
bool decode_whea_record(const std::wstring& text, WheaRecord& out);

struct Volume {
    std::wstring root;
    std::uint64_t total = 0, free = 0;
    bool system = false;
};

std::vector<Volume> fixed_volumes();
double uptime_seconds();
std::vector<std::wstring> pending_reboot_reasons();
std::vector<double> minidumps(int days = PERIOD_DAYS);   // modification times, newest first

// "Reviewed" marker: the events and crash dumps older than it no longer count in the report (nothing is deleted).
double health_reviewed_at();          // epoch seconds, 0 = never
bool mark_health_reviewed();
void forget_health_reviewed();
// Saves each log to a .evtx backup, then clears it (needs administrator rights). Returns the logs that were NOT cleared.
std::wstring clear_event_logs(const std::vector<std::wstring>& logs, std::vector<std::wstring>& report);

Json collect_disks();                    // null when PowerShell failed
Json collect_events(int days = PERIOD_DAYS);

std::vector<HealthItem> evaluate_disks(const Json& data);
std::vector<HealthItem> evaluate_volumes(const std::vector<Volume>& volumes);
HealthItem evaluate_stability(const Json& events);
std::vector<HealthItem> evaluate_crashes(const Json& events, const std::vector<double>& dumps, const Json& disks);
bool evaluate_app_crashes(const Json& events, HealthItem& out);
std::vector<HealthItem> evaluate_uptime(double seconds, const std::vector<std::wstring>& reboot_reasons);
std::vector<std::wstring> disk_numbers_hint(const std::wstring& text, const Json& disks);

std::vector<HealthItem> build_report(const Json& disks, const Json& events, const std::vector<Volume>& volumes, double up_seconds,
                                     const std::vector<std::wstring>& reboot_reasons, const std::vector<double>& dumps);
std::vector<HealthItem> run_health_check(const Progress& progress = nullptr);
// endregion

}  // namespace dd
