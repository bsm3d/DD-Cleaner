// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the system inventory counters, the health evaluators and the disk, stability and crash checks.

#include <ddcore/sysinfo.hpp>

#include <algorithm>
#include <cmath>
#include <cstdarg>
#include <regex>
#include <set>
#include <stdexcept>
#include <tuple>

#include <windows.h>

#include <ddcore/proc.hpp>
#include <ddcore/registry.hpp>

namespace dd {

namespace {

std::wstring fmt(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    int n = _vscwprintf(format, copy);
    va_end(copy);
    std::wstring out;
    if (n > 0) {
        out.resize((std::size_t)n + 1);
        vswprintf(out.data(), out.size(), format, args);
        out.resize((std::size_t)n);
    }
    va_end(args);
    return out;
}

// Counter of strings keeping first-seen order; most_common is stable on ties, like Python's Counter.
template <typename Key>
struct Counter {
    std::vector<std::pair<Key, int>> items;
    void add(const Key& key) {
        for (auto& it : items) {
            if (it.first == key) {
                ++it.second;
                return;
            }
        }
        items.emplace_back(key, 1);
    }
    std::vector<std::pair<Key, int>> most_common(std::size_t limit = (std::size_t)-1) const {
        auto sorted = items;
        std::stable_sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        if (sorted.size() > limit) sorted.resize(limit);
        return sorted;
    }
};

std::wstring or_text(const std::wstring& value, const wchar_t* fallback) { return value.empty() ? fallback : value; }

std::map<std::wstring, RegValue> values_by_name(const RegKey& key) {
    std::map<std::wstring, RegValue> m;
    for (auto& v : key.values()) m.emplace(v.name, v);
    return m;
}

}  // namespace

// region Installed programs

static std::wstring program_folder(const std::wstring& install_location, const std::vector<std::wstring>& commands) {
    std::wstring folder = strip_quotes(trim(install_location));
    while (!folder.empty() && folder.back() == L'\\') folder.pop_back();
    if (!folder.empty() && is_absolute(folder)) return folder;
    static const std::wregex program(LR"(^\s*"?([A-Za-z]:\\[^"]*?\.(?:exe|ico|dll|msi)))", std::regex::icase);
    for (const auto& command : commands) {
        std::wsmatch m;
        if (std::regex_search(command, m, program)) {
            std::wstring parent = dir_name(m[1]);
            if (!starts_with(normcase(parent), normcase(system_root()))) return parent;
        }
    }
    return L"";
}

std::vector<Program> installed_programs() {
    struct Source {
        const wchar_t* hive;
        bool view32;
        const wchar_t* scope;
    };
    const Source sources[] = {{L"HKLM", false, L"All users"}, {L"HKLM", true, L"All users (32-bit)"}, {L"HKCU", false, L"Current user"}};
    const std::wstring uninstall = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    std::map<std::pair<std::wstring, std::wstring>, Program> found;
    for (const Source& src : sources) {
        RegKey root = RegKey::open(src.hive, uninstall, src.view32);
        if (!root.valid()) continue;
        for (const auto& sub : root.subkeys()) {
            RegKey key = RegKey::open(src.hive, uninstall + L"\\" + sub, src.view32);
            if (!key.valid()) continue;
            auto v = values_by_name(key);
            auto text = [&](const wchar_t* name) { return v.count(name) && v[name].is_text() ? v[name].text : std::wstring(); };
            std::wstring name = trim(text(L"DisplayName"));
            if (name.empty()) continue;
            if ((v.count(L"SystemComponent") && v[L"SystemComponent"].type == REG_DWORD && v[L"SystemComponent"].dword == 1) ||
                !text(L"ParentKeyName").empty())
                continue;
            if (starts_with(name, L"KB") || starts_with(name, L"Update for") || starts_with(name, L"Security Update")) continue;
            Program p{name, text(L"DisplayVersion"), text(L"Publisher"), src.scope,
                      program_folder(text(L"InstallLocation"), {text(L"DisplayIcon"), text(L"UninstallString")})};
            found.emplace(std::make_pair(lower(name), p.version), p);   // the first source wins
        }
    }
    std::vector<Program> out;
    for (auto& kv : found) out.push_back(kv.second);
    std::stable_sort(out.begin(), out.end(), [](const Program& a, const Program& b) { return lower(a.name) < lower(b.name); });
    return out;
}

// endregion

// region Graphics cards and activation

std::map<std::wstring, std::uint64_t> gpu_memory_by_name() {
    std::map<std::wstring, std::uint64_t> result;
    const std::wstring base = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}";
    RegKey root = RegKey::open(L"HKLM", base);
    if (!root.valid()) return result;
    for (const auto& sub : root.subkeys()) {
        RegKey key = RegKey::open(L"HKLM", base + L"\\" + sub);
        if (!key.valid()) continue;
        auto v = values_by_name(key);
        if (!v.count(L"DriverDesc") || !v[L"DriverDesc"].is_text()) continue;
        const std::wstring& desc = v[L"DriverDesc"].text;
        for (const wchar_t* name : {L"HardwareInformation.qwMemorySize", L"HardwareInformation.MemorySize"}) {
            auto it = v.find(name);
            if (it == v.end()) continue;
            std::uint64_t size = it->second.type == REG_QWORD ? it->second.qword : it->second.type == REG_DWORD ? it->second.dword : 0;
            if (size > 0) result[desc] = std::max(result[desc], size);
        }
    }
    return result;
}

static const wchar_t* GPU_PS =
    L"$g = @(Get-CimInstance Win32_VideoController | ForEach-Object { [pscustomobject]@{ "
    L"Name = $_.Name; Driver = $_.DriverVersion; "
    L"Date = if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { '' }; "
    L"Ram = [uint64]$_.AdapterRAM; W = $_.CurrentHorizontalResolution; H = $_.CurrentVerticalResolution; "
    L"Hz = $_.CurrentRefreshRate } }); ConvertTo-Json -InputObject $g -Compress";

std::vector<Gpu> graphics_cards() {
    Json data = run_powershell_json(GPU_PS);
    auto memory = gpu_memory_by_name();
    std::vector<Gpu> cards;
    for (const Json& g : data.as_list()) {
        if (!g.is_object()) continue;
        std::wstring name = g.get(L"Name").str();
        double vram = std::max<double>(g.get(L"Ram").num(), (double)memory[name]);
        std::wstring resolution;
        if (g.get(L"W").integer())
            resolution = fmt(L"%lldx%lld @ %ls Hz", g.get(L"W").integer(), g.get(L"H").integer(), g.get(L"Hz").str().c_str());
        cards.push_back({name, g.get(L"Driver").str(), g.get(L"Date").str(), std::round(vram / 1073741824.0 * 10) / 10, resolution});
    }
    return cards;
}

static const wchar_t* ACTIVATION_PS =
    L"$l = Get-CimInstance SoftwareLicensingProduct | Where-Object { $_.PartialProductKey -and $_.ApplicationID -eq "
    L"'55c92734-d682-4d71-983e-d6ec3f16059f' } | Select-Object -First 1; "
    L"$o = Get-CimInstance Win32_OperatingSystem; "
    L"[pscustomobject]@{ Edition = $o.Caption; Build = $o.BuildNumber; Status = if ($l) { [int]$l.LicenseStatus } else { -1 }; "
    L"Channel = if ($l) { [string]$l.ProductKeyChannel } else { '' }; "
    L"Partial = if ($l) { [string]$l.PartialProductKey } else { '' } } | ConvertTo-Json -Compress";

Activation windows_activation() {
    Json data = run_powershell_json(ACTIVATION_PS);
    Activation a;
    if (!data.is_object()) return a;
    static const std::map<int, const wchar_t*> names = {{0, L"Unlicensed"}, {1, L"Licensed"}, {2, L"Initial grace period"},
                                                       {3, L"Additional grace period"}, {4, L"Non-genuine grace period"},
                                                       {5, L"Notification"}, {6, L"Extended grace period"}};
    int status = (int)data.get(L"Status").integer(-1);
    auto it = names.find(status);
    a.valid = true;
    a.edition = data.get(L"Edition").str();
    a.build = data.get(L"Build").str();
    a.status = it == names.end() ? L"Unknown" : it->second;
    a.licensed = status == 1;
    a.channel = data.get(L"Channel").str();
    a.partial_key = data.get(L"Partial").str();
    return a;
}

// endregion

// region DPC / ISR load

double LoadResult::worst() const {
    double w = 0;
    for (double d : dpc) w = std::max(w, d);
    for (double i : isr) w = std::max(w, i);
    return w;
}

std::wstring LoadResult::verdict() const {
    double w = worst();
    if (w < 1.0) return L"Low: nothing in the drivers is holding the processor.";
    if (w < 3.0) return L"Moderate: fine for most work, watch it if audio crackles.";
    return L"High: a driver is using a lot of processor time in interrupts; real-time audio may crackle. "
           L"Update the network, audio and graphics drivers, and test with a tool such as LatencyMon.";
}

LoadResult measure_dpc_isr(int samples) {
    std::wstring script =
        L"$d = @(); $i = @(); for ($n = 0; $n -lt " + std::to_wstring(samples) +
        L"; $n++) { $p = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter \"Name='_Total'\"; "
        L"$d += [double]$p.PercentDPCTime; $i += [double]$p.PercentInterruptTime; Start-Sleep -Seconds 1 }; "
        L"[pscustomobject]@{ Dpc = $d; Isr = $i } | ConvertTo-Json -Compress";
    Json data = run_powershell_json(script, (unsigned long)(samples + 60) * 1000);
    if (!data.is_object()) throw std::runtime_error("The processor counters could not be read.");
    auto numbers = [](const Json& v) {
        std::vector<double> out;
        for (const Json& x : v.as_list()) {
            if (x.is_number()) out.push_back(x.num());
        }
        return out;
    };
    return {numbers(data.get(L"Dpc")), numbers(data.get(L"Isr"))};
}

// endregion

// region Health: helpers

int severity(Status s) {
    switch (s) {
        case Status::Ok: return 0;
        case Status::Info: return 1;
        case Status::Unknown: return 2;
        case Status::Warning: return 3;
        case Status::Critical: return 4;
    }
    return 0;
}

const wchar_t* status_name(Status s) {
    switch (s) {
        case Status::Ok: return L"ok";
        case Status::Info: return L"info";
        case Status::Unknown: return L"unknown";
        case Status::Warning: return L"warning";
        case Status::Critical: return L"critical";
    }
    return L"";
}

static Status worse(Status a, Status b) { return severity(a) >= severity(b) ? a : b; }

std::wstring bugcheck_name(long long code) {
    static const std::map<long long, const wchar_t*> names = {
        {0x0A, L"IRQL_NOT_LESS_OR_EQUAL"}, {0x19, L"BAD_POOL_HEADER"}, {0x1A, L"MEMORY_MANAGEMENT"},
        {0x1E, L"KMODE_EXCEPTION_NOT_HANDLED"}, {0x3B, L"SYSTEM_SERVICE_EXCEPTION"}, {0x50, L"PAGE_FAULT_IN_NONPAGED_AREA"},
        {0x7E, L"SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"}, {0x7F, L"UNEXPECTED_KERNEL_MODE_TRAP"},
        {0x9F, L"DRIVER_POWER_STATE_FAILURE"}, {0xA0, L"INTERNAL_POWER_ERROR"}, {0xC2, L"BAD_POOL_CALLER"},
        {0xD1, L"DRIVER_IRQL_NOT_LESS_OR_EQUAL"}, {0xEF, L"CRITICAL_PROCESS_DIED"}, {0xF4, L"CRITICAL_OBJECT_TERMINATION"},
        {0x101, L"CLOCK_WATCHDOG_TIMEOUT"}, {0x116, L"VIDEO_TDR_FAILURE"}, {0x117, L"VIDEO_TDR_TIMEOUT_DETECTED"},
        {0x119, L"VIDEO_SCHEDULER_INTERNAL_ERROR"}, {0x124, L"WHEA_UNCORRECTABLE_ERROR"}, {0x133, L"DPC_WATCHDOG_VIOLATION"},
        {0x139, L"KERNEL_SECURITY_CHECK_FAILURE"}, {0x13A, L"KERNEL_MODE_HEAP_CORRUPTION"},
        {0x154, L"UNEXPECTED_STORE_EXCEPTION"}, {0x1E0, L"HYPERVISOR_ERROR"}, {0xC000021A, L"STATUS_SYSTEM_PROCESS_TERMINATED"}};
    auto it = names.find(code);
    return it == names.end() ? L"" : it->second;
}

bool parse_bugcheck(const std::wstring& text, long long& code) {
    std::wstring t = trim(text);
    std::size_t cut = t.find_first_of(L" (");
    if (cut != std::wstring::npos) t = t.substr(0, cut);
    if (t.empty()) return false;
    wchar_t* end = nullptr;
    bool hex = t.size() > 2 && t[0] == L'0' && (t[1] == L'x' || t[1] == L'X');
    long long v = wcstoll(t.c_str(), &end, hex ? 16 : 10);
    if (!end || *end != 0 || end == t.c_str()) return false;
    code = v;
    return true;
}

double parse_time(const std::wstring& iso) {
    int y, mo, d, h, mi, s;
    if (swscanf(iso.c_str(), L"%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &s) != 6) return 0;
    // days since 1970 (civil-from-days inverse), enough for differences
    y -= mo <= 2;
    long era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    long days = era * 146097 + (long)doe - 719468;
    return (double)days * 86400 + h * 3600 + mi * 60 + s;
}

bool decode_whea_record(const std::wstring& text, WheaRecord& out) {
    std::vector<unsigned char> raw;
    for (const auto& part : split(trim(text), L' ')) {
        if (part.empty()) continue;
        wchar_t* end = nullptr;
        long v = wcstol(part.c_str(), &end, 10);
        if (!end || *end != 0 || v < 0 || v > 255) return false;
        raw.push_back((unsigned char)v);
    }
    if (raw.size() < 128 || memcmp(raw.data(), "CPER", 4) != 0) return false;
    static const std::map<std::wstring, const wchar_t*> kinds = {
        {L"e8f56ffe-919c-4cc5-ba88-65abe14913bb", L"Machine check (CPU)"},
        {L"2dce8bb1-bdd7-450e-b9ad-9cf4ebd4f890", L"Corrected machine check (CPU)"},
        {L"4e292f96-d843-4a55-a8c2-d481f27ebeee", L"Corrected platform error"},
        {L"cf93c01f-1a16-4dfc-b8bc-9c4daf67c104", L"PCI Express"},
        {L"5bad89ff-b7e6-42c9-814a-cf2485d6e98a", L"Non-maskable interrupt"},
        {L"3d61a466-ab40-409a-a698-f362d464b38f", L"Error from the previous boot"},
        {L"0033f803-2e70-4e88-992c-6f26daf3db7a", L"Device driver report"}};
    // the notification type is a GUID stored little-endian at offset 80
    const unsigned char* g = raw.data() + 80;
    wchar_t guid[40];
    swprintf(guid, 40, L"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", g[3], g[2], g[1], g[0], g[5], g[4], g[7],
             g[6], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
    auto kind = kinds.find(guid);
    out = {};
    out.source = kind == kinds.end() ? L"Hardware" : kind->second;
    const char* needle = "STORPORT";
    auto pos = std::search(raw.begin(), raw.end(), needle, needle + 8);
    if (pos != raw.end()) {
        std::size_t start = (std::size_t)(pos - raw.begin()) + 8;
        std::vector<unsigned char> section(raw.begin() + start, raw.begin() + std::min(raw.size(), start + 256));
        out.source = L"Storage controller (storport)";
        // first run of three or more UTF-16 printable characters is the driver name
        std::size_t i = 0, wide_end = 0;
        bool have_wide = false;
        for (; i + 1 < section.size(); ++i) {
            std::size_t j = i, count = 0;
            while (j + 1 < section.size() && section[j] >= 0x21 && section[j] <= 0x7e && section[j + 1] == 0) {
                j += 2;
                ++count;
            }
            if (count >= 3) {
                for (std::size_t k = i; k < j; k += 2) out.driver.push_back((wchar_t)section[k]);
                wide_end = j;
                have_wide = true;
                break;
            }
        }
        std::size_t from = have_wide ? wide_end : 0;
        std::wstring words, run;
        auto flush = [&] {
            if (run.size() >= 3) {
                std::wstring w = trim(run);
                if (!w.empty()) words += (words.empty() ? L"" : L" ") + w;
            }
            run.clear();
        };
        for (std::size_t k = from; k < section.size(); ++k) {
            if (section[k] >= 0x20 && section[k] <= 0x7e) run.push_back((wchar_t)section[k]);
            else flush();
        }
        flush();
        out.device = words.substr(0, 80);
    }
    return true;
}

// endregion

// region Health: collectors

static const wchar_t* DISKS_PS = LR"(
$out = foreach ($d in Get-PhysicalDisk) {
  $rel = $null
  try {
    $c = $d | Get-StorageReliabilityCounter -ErrorAction Stop
    $rel = [pscustomobject]@{ Temperature = $c.Temperature; TemperatureMax = $c.TemperatureMax; Wear = $c.Wear;
      ReadErrorsUncorrected = $c.ReadErrorsUncorrected; WriteErrorsUncorrected = $c.WriteErrorsUncorrected;
      PowerOnHours = $c.PowerOnHours }
  } catch {}
  [pscustomobject]@{ DeviceId = [string]$d.DeviceId; Name = $d.FriendlyName; Media = [string]$d.MediaType;
    Bus = [string]$d.BusType; Serial = ([string]$d.SerialNumber).Trim(); Health = [string]$d.HealthStatus;
    Status = (@($d.OperationalStatus) | ForEach-Object { [string]$_ }) -join ', '; Size = [int64]$d.Size;
    Reliability = $rel }
}
$smart = $null
try {
  $smart = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop |
    ForEach-Object { [pscustomobject]@{ Instance = $_.InstanceName; PredictFailure = [bool]$_.PredictFailure } })
} catch {}
[pscustomobject]@{ disks = @($out); smart = $smart } | ConvertTo-Json -Depth 5 -Compress
)";

static const wchar_t* EVENTS_PS = LR"(
$since = (Get-Date).AddDays(-__DAYS__)
$reviewed = __REVIEWED__
if ($reviewed -gt 0) {
  $r = [DateTimeOffset]::FromUnixTimeSeconds([long]$reviewed).LocalDateTime
  if ($r -gt $since) { $since = $r }
}
function Get-Ev([string]$log, [string[]]$providers, $ids, $levels, [int]$max, [bool]$withMessage) {
  $all = @()
  foreach ($p in $providers) {
    $f = @{ LogName = $log; ProviderName = $p; StartTime = $since }
    if ($ids) { $f.Id = $ids }
    if ($levels) { $f.Level = $levels }
    try {
      $all += @(Get-WinEvent -FilterHashtable $f -MaxEvents $max -ErrorAction Stop | ForEach-Object {
        $msg = ''
        if ($withMessage -and $_.Message) { $msg = ($_.Message -split "`r?`n")[0] }
        [pscustomobject]@{ Id = $_.Id; Provider = $_.ProviderName; Level = [int]$_.Level;
          Time = $_.TimeCreated.ToString('s');
          Props = @($_.Properties | Select-Object -First 8 | ForEach-Object { [string]$_.Value });
          Message = $msg }
      })
    } catch {}
  }
  return ,$all
}
$stability = $null
try {
  $m = @(Get-CimInstance Win32_ReliabilityStabilityMetrics -ErrorAction Stop |
    Where-Object { $_.TimeGenerated -ge $since } | Sort-Object TimeGenerated -Descending)
  if ($m.Count) {
    $stability = [pscustomobject]@{ Current = [double]$m[0].SystemStabilityIndex;
      Minimum = [double](($m | Measure-Object SystemStabilityIndex -Minimum).Minimum); Samples = $m.Count }
  }
} catch {}
[pscustomobject]@{
  bugchecks = Get-Ev 'System' @('Microsoft-Windows-WER-SystemErrorReporting') @(1001) $null 200 $false
  kernel_power = Get-Ev 'System' @('Microsoft-Windows-Kernel-Power') @(41) $null 200 $false
  whea = Get-Ev 'System' @('Microsoft-Windows-WHEA-Logger') $null $null 500 $true
  storage = Get-Ev 'System' @('disk', 'Ntfs', 'Microsoft-Windows-Ntfs', 'stornvme', 'storahci', 'volmgr') $null @(1, 2, 3) 500 $true
  app_crashes = Get-Ev 'Application' @('Application Error', 'Application Hang') @(1000, 1002) $null 3000 $false
  stability = $stability
} | ConvertTo-Json -Depth 5 -Compress
)";

Json collect_disks() {
    Json data = run_powershell_json(DISKS_PS, 120000);
    return data.is_object() ? data : Json();
}

// region Reviewed marker and event log clearing

static std::wstring reviewed_path() { return join(data_dir(), L"health_reviewed.txt"); }

double health_reviewed_at() {
    std::string bytes;
    if (!read_file(reviewed_path(), bytes, 64)) return 0;
    try {
        double t = std::stod(bytes);
        return t > 0 && t <= now_seconds() + 60 ? t : 0;
    } catch (...) {
        return 0;
    }
}

bool mark_health_reviewed() {
    make_dirs(data_dir());
    return write_file(reviewed_path(), std::to_string((long long)now_seconds()));
}

void forget_health_reviewed() { DeleteFileW(reviewed_path().c_str()); }

std::wstring clear_event_logs(const std::vector<std::wstring>& logs, std::vector<std::wstring>& report) {
    std::wstring dir = data_subdir(L"eventlog_backups"), stamp = timestamp();
    std::wstring failed;
    for (const std::wstring& log : logs) {
        // only plain log names: nothing else is handed to wevtutil
        bool plain = !log.empty();
        for (wchar_t c : log) plain = plain && (iswalnum(c) || c == L'-' || c == L' ' || c == L'/' || c == L'_');
        if (!plain) {
            report.push_back(log + L": refused (not a plain log name)");
            continue;
        }
        std::wstring safe = log;
        for (wchar_t& c : safe) if (c == L'/' || c == L' ') c = L'_';
        std::wstring file = join(dir, safe + L"_" + stamp + L".evtx");
        ProcOptions o;
        o.timeout_ms = 120000;
        ProcResult copy = run_process({sys_exe(L"wevtutil.exe"), L"epl", log, file}, o);
        if (!copy.ok()) {   // never clear what could not be saved first
            report.push_back(log + L": not cleared, the backup failed");
            failed += log + L" ";
            continue;
        }
        ProcResult clear = run_process({sys_exe(L"wevtutil.exe"), L"cl", log}, o);
        if (clear.ok()) report.push_back(log + L": cleared, backup in " + file);
        else {
            report.push_back(log + L": could not be cleared (administrator rights needed)");
            failed += log + L" ";
        }
    }
    return failed;
}

// endregion

Json collect_events(int days) {
    std::wstring script = EVENTS_PS;
    script.replace(script.find(L"__DAYS__"), 8, std::to_wstring(days));
    script.replace(script.find(L"__REVIEWED__"), 12, std::to_wstring((long long)health_reviewed_at()));
    Json data = run_powershell_json(script, 180000);
    return data.is_object() ? data : Json();
}

std::vector<Volume> fixed_volumes() {
    std::vector<Volume> volumes;
    std::wstring system_drive = lower(system_root().substr(0, 2)) + L"\\";
    for (const auto& d : drive_usage(fixed_drives())) {
        volumes.push_back({d.root, d.total, d.free, lower(d.root) == system_drive});
    }
    return volumes;
}

double uptime_seconds() { return (double)GetTickCount64() / 1000.0; }

std::vector<std::wstring> pending_reboot_reasons() {
    std::vector<std::wstring> reasons;
    if (RegKey::open(L"HKLM", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending").valid())
        reasons.push_back(L"Windows component servicing (updates or features) is waiting for a restart");
    if (RegKey::open(L"HKLM", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired").valid())
        reasons.push_back(L"Windows Update is waiting for a restart");
    RegKey session = RegKey::open(L"HKLM", L"SYSTEM\\CurrentControlSet\\Control\\Session Manager");
    for (const RegValue& v : session.values()) {
        if (v.name == L"PendingFileRenameOperations" && v.type == REG_MULTI_SZ && !v.shown.empty())
            reasons.push_back(L"Files are waiting to be replaced at the next restart (installer or update)");
    }
    return reasons;
}

std::vector<double> minidumps(int days) {
    std::vector<double> dates;
    std::vector<Entry> files;
    if (!list_dir(join(system_root(), L"Minidump"), files)) return dates;
    double since = std::max(now_seconds() - days * 86400.0, health_reviewed_at());
    for (const Entry& f : files) {
        if (ends_with(lower(f.name), L".dmp") && f.modified >= since) dates.push_back(f.modified);
    }
    std::sort(dates.begin(), dates.end(), std::greater<double>());
    return dates;
}

// endregion

// region Health: evaluators

std::vector<HealthItem> evaluate_disks(const Json& data) {
    if (!data.is_object()) return {{L"Disks", Status::Unknown, L"Disk health could not be read", {}}};
    std::vector<HealthItem> items;
    for (const Json& d : data.get(L"disks").as_list()) {
        double size_gb = d.get(L"Size").num() / 1e9;
        std::wstring name_text = d.get(L"Name").str();
        if (name_text.empty()) name_text = L"Disk " + d.get(L"DeviceId").str();
        std::wstring name = fmt(L"%ls (%ls, %ls, %.0f GB)", name_text.c_str(), or_text(d.get(L"Media").str(), L"?").c_str(),
                                or_text(d.get(L"Bus").str(), L"?").c_str(), size_gb);
        std::wstring health = or_text(d.get(L"Health").str(), L"Unknown");
        Status status = health == L"Healthy" ? Status::Ok : health == L"Unhealthy" ? Status::Critical : Status::Warning;
        std::vector<std::wstring> details = {L"Windows health: " + health + L", status: " + or_text(d.get(L"Status").str(), L"?")};
        const Json& rel = d.get(L"Reliability");
        if (rel.is_object()) {
            long long temp = rel.get(L"Temperature").integer();
            if (temp) {
                std::wstring tmax = rel.get(L"TemperatureMax").integer() ? rel.get(L"TemperatureMax").str() : L"?";
                details.push_back(fmt(L"Temperature: %lld °C (max seen %ls °C)", temp, tmax.c_str()));
                int limit = d.get(L"Media").str() == L"HDD" ? 55 : 70;
                if (temp >= limit) {
                    status = worse(status, Status::Warning);
                    details.push_back(fmt(L"Temperature is high (≥ %d °C): check cooling", limit));
                }
            }
            long long wear = rel.get(L"Wear").integer();
            if (wear) {
                details.push_back(fmt(L"Wear: %lld %% of rated endurance used", wear));
                if (wear >= 90) status = Status::Critical;
                else if (wear >= 70) status = worse(status, Status::Warning);
            }
            long long errors = rel.get(L"ReadErrorsUncorrected").integer() + rel.get(L"WriteErrorsUncorrected").integer();
            if (errors) {
                status = worse(status, Status::Warning);
                details.push_back(fmt(L"Uncorrected read/write errors: %lld", errors));
            }
            if (rel.get(L"PowerOnHours").integer()) details.push_back(fmt(L"Power-on time: %lld h", rel.get(L"PowerOnHours").integer()));
        } else {
            details.push_back(L"Temperature/wear counters: not available (administrator rights or driver support needed)");
        }
        items.push_back({L"Disks", status, name, details});
    }
    const Json& smart = data.get(L"smart");
    if (smart.is_null()) {
        items.push_back({L"Disks", Status::Info, L"SMART failure prediction not readable",
                         {L"Needs administrator rights (or not supported by the disk driver)."}});
    } else {
        std::vector<std::wstring> failing;
        for (const Json& s : smart.as_list()) {
            if (s.get(L"PredictFailure").flag()) failing.push_back(s.get(L"Instance").str());
        }
        if (!failing.empty()) {
            std::vector<std::wstring> details = {L"Back up your data now and replace the disk."};
            details.insert(details.end(), failing.begin(), failing.end());
            items.push_back({L"Disks", Status::Critical, fmt(L"SMART predicts a failure on %zu disk(s)", failing.size()), details});
        }
    }
    if (items.empty()) items.push_back({L"Disks", Status::Unknown, L"No disk reported", {}});
    return items;
}

std::vector<HealthItem> evaluate_volumes(const std::vector<Volume>& volumes) {
    std::vector<HealthItem> items;
    for (const Volume& v : volumes) {
        if (!v.total) continue;
        double pct = 100.0 * v.free / v.total, free_gb = v.free / 1e9;
        Status status = Status::Ok;
        if (pct < 5 || free_gb < 5) status = Status::Critical;
        else if (pct < 10 || free_gb < 15) status = Status::Warning;
        std::wstring label = fmt(L"%ls %.1f GB free of %.0f GB (%.0f %%)", v.root.c_str(), free_gb, v.total / 1e9, pct);
        std::vector<std::wstring> details;
        if (v.system && status != Status::Ok) details.push_back(L"System drive: updates need several GB free.");
        items.push_back({L"Free space", status, label, details});
    }
    return items;
}

HealthItem evaluate_stability(const Json& events) {
    const Json& stab = events.get(L"stability");
    if (!stab.is_object()) {
        return {L"Stability", Status::Unknown, L"Reliability index not available",
                {L"Windows computes it hourly (service 'RacTask'); it may be disabled on this PC."}};
    }
    if (!stab.get(L"Current").is_number() || !stab.get(L"Minimum").is_number()) {
        return {L"Stability", Status::Unknown, L"Reliability index not readable", {}};
    }
    double current = stab.get(L"Current").num(), minimum = stab.get(L"Minimum").num();
    Status status = current >= 7 ? Status::Ok : current >= 3 ? Status::Warning : Status::Critical;
    return {L"Stability", status, fmt(L"Windows reliability index: %.1f / 10", current),
            {fmt(L"Lowest in the last %d days: %.1f", PERIOD_DAYS, minimum),
             L"It drops with every crash, failed update and unexpected shutdown (see below). "
             L"Details: Control Panel > Security and Maintenance > View reliability history."}};
}

std::vector<std::wstring> disk_numbers_hint(const std::wstring& text, const Json& disks) {
    std::map<std::wstring, Json> by_id;
    for (const Json& d : disks.get(L"disks").as_list()) by_id[d.get(L"DeviceId").str()] = d;
    static const std::wregex number(LR"(\b(?:Disk|Disque|Datenträger)\s+(\d+)\b)", std::regex::icase);
    std::set<std::wstring> numbers;
    for (std::wsregex_iterator it(text.begin(), text.end(), number), end; it != end; ++it) numbers.insert((*it)[1]);
    std::vector<std::pair<long, std::wstring>> ordered;
    for (const auto& n : numbers) ordered.emplace_back(wcstol(n.c_str(), nullptr, 10), n);
    std::sort(ordered.begin(), ordered.end());
    std::vector<std::wstring> hints;
    for (const auto& [_, n] : ordered) {
        auto it = by_id.find(n);
        if (it == by_id.end()) continue;
        hints.push_back(L"'Disk " + n + L"' in the events = " + it->second.get(L"Name").str() + L" (serial " +
                        or_text(it->second.get(L"Serial").str(), L"?") + L")");
    }
    return hints;
}

static std::wstring iso_to_text(std::wstring t) {
    std::replace(t.begin(), t.end(), L'T', L' ');
    return t;
}

static std::vector<std::wstring> sorted_times_desc(std::vector<std::wstring> times, std::size_t limit) {
    std::sort(times.begin(), times.end(), std::greater<std::wstring>());
    if (times.size() > limit) times.resize(limit);
    for (auto& t : times) t = iso_to_text(t);
    return times;
}

std::vector<HealthItem> evaluate_crashes(const Json& events, const std::vector<double>& dumps, const Json& disks) {
    if (!events.is_object()) return {{L"Crashes", Status::Unknown, L"Event logs could not be read", {}}};
    std::vector<HealthItem> items;

    struct Blue {
        std::wstring time;
        bool has_code;
        long long code;
    };
    std::vector<Blue> blue_screens;
    std::vector<std::wstring> bsod_times, hard_resets;
    for (const Json& e : events.get(L"bugchecks").as_list()) {
        long long code = 0;
        bool has = parse_bugcheck(e.get(L"Props").at(0).str(), code);
        blue_screens.push_back({e.get(L"Time").str(), has, code});
        bsod_times.push_back(e.get(L"Time").str());
    }
    // Kernel-Power 41 with a bug check code duplicates a blue screen; with 0 it is a power loss or forced reset
    for (const Json& e : events.get(L"kernel_power").as_list()) {
        long long code = 0;
        std::wstring first = e.get(L"Props").at(0).str(L"0");
        if (!parse_bugcheck(first.empty() ? L"0" : first, code)) code = 0;
        if (code) {
            double t = parse_time(e.get(L"Time").str());
            bool near_bsod = false;
            for (const auto& b : bsod_times) {
                double bt = parse_time(b);
                if (t && bt && std::fabs(t - bt) < 600) near_bsod = true;
            }
            if (!near_bsod) blue_screens.push_back({e.get(L"Time").str(), true, code});
        } else {
            hard_resets.push_back(e.get(L"Time").str());
        }
    }

    if (!blue_screens.empty()) {
        Status status = blue_screens.size() >= 3 ? Status::Critical : Status::Warning;
        Counter<std::pair<bool, long long>> codes;
        for (const auto& b : blue_screens) codes.add({b.has_code, b.code});
        std::vector<std::wstring> details;
        for (const auto& [key, n] : codes.most_common()) {
            std::wstring code_text = key.first ? fmt(L"0x%llX", key.second) : L"?";
            std::wstring name = key.first ? bugcheck_name(key.second) : L"";
            details.push_back(code_text + L" " + name + L": " + std::to_wstring(n) + L" time(s)");
        }
        std::vector<std::wstring> times;
        for (const auto& b : blue_screens) times.push_back(b.time);
        for (auto& t : sorted_times_desc(times, 10)) details.push_back(t);
        if (!dumps.empty()) details.push_back(fmt(L"%zu crash dump(s) in %ls", dumps.size(), join(system_root(), L"Minidump").c_str()));
        items.push_back({L"Crashes", status, fmt(L"%zu blue screen(s) in %d days", blue_screens.size(), PERIOD_DAYS), details});
    } else {
        items.push_back({L"Crashes", Status::Ok, fmt(L"No blue screen in %d days", PERIOD_DAYS), {}});
    }

    if (!hard_resets.empty()) {
        Status status = hard_resets.size() >= 2 ? Status::Warning : Status::Info;
        std::vector<std::wstring> details = {
            L"Power loss, reset button, forced power-off or a complete freeze (no blue screen). "
            L"Frequent ones point to power supply, overheating or hardware issues."};
        for (auto& t : sorted_times_desc(hard_resets, 10)) details.push_back(t);
        items.push_back({L"Crashes", status, fmt(L"%zu unexpected shutdown(s) in %d days", hard_resets.size(), PERIOD_DAYS), details});
    }

    // WHEA records raised by the storage stack (storport) name a disk: report them with storage
    struct StorageKey {
        std::wstring device, driver;
        bool fatal;
        bool operator==(const StorageKey& o) const { return device == o.device && driver == o.driver && fatal == o.fatal; }
    };
    Counter<StorageKey> whea_storage;
    std::vector<std::pair<StorageKey, std::wstring>> whea_storage_times;
    std::vector<std::pair<Json, WheaRecord>> whea_other;
    for (const Json& e : events.get(L"whea").as_list()) {
        WheaRecord record;
        bool decoded = e.get(L"Props").size() > 1 && decode_whea_record(e.get(L"Props").at(1).str(), record);
        long long level = e.get(L"Level").integer();
        if (decoded && (!record.driver.empty() || record.source.find(L"storport") != std::wstring::npos)) {
            StorageKey key{or_text(record.device, L"?"), or_text(record.driver, L"?"), level == 1 || level == 2};
            whea_storage.add(key);
            whea_storage_times.emplace_back(key, e.get(L"Time").str());
        } else {
            whea_other.emplace_back(e, decoded ? record : WheaRecord{});
        }
    }

    if (!whea_other.empty()) {
        std::vector<std::wstring> fatal_times;
        Counter<std::tuple<long long, std::wstring, std::wstring>> by_kind;
        for (const auto& [e, r] : whea_other) {
            long long level = e.get(L"Level").integer();
            if (level == 1 || level == 2) fatal_times.push_back(e.get(L"Time").str());
            by_kind.add({e.get(L"Id").integer(), r.source, e.get(L"Message").str()});
        }
        Status status = fatal_times.empty() ? Status::Warning : Status::Critical;
        std::vector<std::wstring> details = {
            L"Reported by the CPU, memory or PCIe devices. Errors that repeat announce failing "
            L"hardware, overclocking or unstable settings (voltages, memory profile)."};
        for (const auto& [key, n] : by_kind.most_common(8)) {
            const auto& [id, source, message] = key;
            details.push_back(fmt(L"Event %lld × %d%ls: %ls", id, n, source.empty() ? L"" : (L" (" + source + L")").c_str(),
                                  message.c_str()));
        }
        for (auto& t : sorted_times_desc(fatal_times, 10)) details.push_back(t);
        items.push_back({L"Hardware", status, fmt(L"%zu hardware error report(s) (WHEA) in %d days", whea_other.size(), PERIOD_DAYS), details});
    } else {
        items.push_back({L"Hardware", Status::Ok, fmt(L"No CPU / memory / PCIe error report (WHEA) in %d days", PERIOD_DAYS), {}});
    }

    std::wstring storage_text;
    for (const Json& e : events.get(L"storage").as_list()) storage_text += e.get(L"Message").str() + L" ";
    if (!storage_text.empty()) storage_text.pop_back();
    for (const auto& [key, n] : whea_storage.most_common()) {
        std::vector<Json> same_model;
        std::wstring device_compact = key.device;
        device_compact.erase(std::remove(device_compact.begin(), device_compact.end(), L' '), device_compact.end());
        for (const Json& d : disks.get(L"disks").as_list()) {
            std::wstring name = d.get(L"Name").str();
            name.erase(std::remove(name.begin(), name.end(), L' '), name.end());
            if (key.device != L"?" && starts_with(name, device_compact)) same_model.push_back(d);
        }
        std::vector<std::wstring> details = {
            L"The disk stopped responding and was reset by its controller. Check the data and power cables, "
            L"then the disk itself (manufacturer tool). Back up its data.",
            L"Windows logs this as a 'fatal hardware error' (WHEA event 1) although the PC usually keeps running."};
        if (same_model.size() > 1) {
            std::wstring joined;
            for (std::size_t i = 0; i < same_model.size(); ++i) {
                joined += (i ? L", " : L"") + fmt(L"Disk %ls (serial %ls)", same_model[i].get(L"DeviceId").str().c_str(),
                                                  or_text(same_model[i].get(L"Serial").str(), L"?").c_str());
            }
            details.push_back(L"Several disks have this model: " + joined);
        }
        for (auto& h : disk_numbers_hint(storage_text, disks)) details.push_back(h);
        int shown = 0;
        for (const auto& [k, t] : whea_storage_times) {
            if (k == key && shown++ < 10) details.push_back(iso_to_text(t));
        }
        items.push_back({L"Storage", key.fatal ? Status::Critical : Status::Warning,
                         L"Disk " + key.device + L": " + std::to_wstring(n) + (key.fatal ? L" fatal " : L" ") +
                             L"device error(s) reported by " + key.driver,
                         details});
    }

    std::vector<Json> storage = events.get(L"storage").as_list();
    if (!storage.empty()) {
        bool errors = false;
        Counter<std::tuple<std::wstring, long long, std::wstring>> by_src;
        for (const Json& e : storage) {
            long long level = e.get(L"Level").integer();
            errors |= level == 1 || level == 2;
            by_src.add({e.get(L"Provider").str(), e.get(L"Id").integer(), e.get(L"Message").str()});
        }
        std::vector<std::wstring> details = {
            L"Bad blocks, I/O retries, disks disappearing or file system corruption. Run 'chkdsk' if NTFS reports corruption."};
        std::wstring all_messages;
        for (const auto& [key, n] : by_src.most_common(8)) {
            const auto& [provider, id, message] = key;
            details.push_back(fmt(L"%ls %lld × %d: %ls", provider.c_str(), id, n, message.c_str()));
        }
        for (const auto& [key, n] : by_src.items) all_messages += std::get<2>(key) + L" ";
        if (!all_messages.empty()) all_messages.pop_back();
        for (auto& h : disk_numbers_hint(all_messages, disks)) details.push_back(h);
        items.push_back({L"Storage", errors ? Status::Warning : Status::Info,
                         fmt(L"%zu disk / file system warning(s) in %d days", storage.size(), PERIOD_DAYS), details});
    } else {
        items.push_back({L"Storage", Status::Ok, fmt(L"No disk or file system error in %d days", PERIOD_DAYS), {}});
    }
    return items;
}

bool evaluate_app_crashes(const Json& events, HealthItem& out) {
    if (!events.is_object()) return false;
    std::vector<Json> crashes = events.get(L"app_crashes").as_list();
    if (crashes.empty()) {
        out = {L"Applications", Status::Ok, fmt(L"No application crash in %d days", PERIOD_DAYS), {}};
        return true;
    }
    Counter<std::pair<std::wstring, bool>> counts;   // (application, is a hang)
    for (const Json& e : crashes) {
        std::wstring app = or_text(e.get(L"Props").at(0).str(), L"?");
        counts.add({app, e.get(L"Id").integer() == 1002});
    }
    auto ranked = counts.most_common();
    Status status = ranked[0].second >= 10 ? Status::Warning : Status::Info;
    std::vector<std::wstring> details;
    for (std::size_t i = 0; i < ranked.size() && i < 10; ++i) {
        const auto& [key, n] = ranked[i];
        details.push_back(key.second ? fmt(L"%ls: %d hang(s)", key.first.c_str(), n) : fmt(L"%ls: %d crash(es)", key.first.c_str(), n));
    }
    out = {L"Applications", status, fmt(L"%zu application crash(es) / hang(s) in %d days", crashes.size(), PERIOD_DAYS), details};
    return true;
}

std::vector<HealthItem> evaluate_uptime(double seconds, const std::vector<std::wstring>& reboot_reasons) {
    std::vector<HealthItem> items;
    long long total = (long long)seconds;
    long long days = total / 86400, hours = (total % 86400) / 3600;
    std::vector<std::wstring> details;
    if (days >= 30) details.push_back(L"A restart every few weeks applies updates and frees leaked resources.");
    items.push_back({L"System", days >= 30 ? Status::Warning : Status::Ok, fmt(L"Up for %lld day(s) %lld h", days, hours), details});
    if (!reboot_reasons.empty()) items.push_back({L"System", Status::Warning, L"A restart is pending", reboot_reasons});
    return items;
}

std::vector<HealthItem> build_report(const Json& disks, const Json& events, const std::vector<Volume>& volumes, double up_seconds,
                                     const std::vector<std::wstring>& reboot_reasons, const std::vector<double>& dumps) {
    std::vector<HealthItem> items;
    auto add = [&](std::vector<HealthItem> more) {
        for (auto& i : more) items.push_back(std::move(i));
    };
    add(evaluate_disks(disks));
    add(evaluate_volumes(volumes));
    items.push_back(evaluate_stability(events));
    add(evaluate_crashes(events, dumps, disks));
    HealthItem app;
    if (evaluate_app_crashes(events, app)) items.push_back(app);
    add(evaluate_uptime(up_seconds, reboot_reasons));
    return items;
}

std::vector<HealthItem> run_health_check(const Progress& progress) {
    auto step = [&](const std::wstring& text) {
        if (progress) progress(text);
    };
    step(L"Reading disk health...");
    Json disks = collect_disks();
    step(fmt(L"Reading event logs (%d days)...", PERIOD_DAYS));
    Json events = collect_events();
    step(L"Checking free space and pending restart...");
    return build_report(disks, events, fixed_volumes(), uptime_seconds(), pending_reboot_reasons(), minidumps());
}

// endregion

}  // namespace dd
