// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the advanced security tweaks: their catalogue, command building, state snapshots and the exact revert.

// Advanced tweaks: catalogue, command building, snapshot and exact revert, runner, telemetry scan.
// Revert trusts only the built-in catalogue: snapshot entries whose target is not in it, or malformed, are ignored.
#pragma once

#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <ddcore/common.hpp>
#include <ddcore/json.hpp>
#include <ddcore/proc.hpp>

namespace dd {

struct Tweak {
    std::wstring category, name, command, description, risk;
};

// "Safe (Recommended)" | "Medium" | "Aggressive" | "Custom" (every tweak)
const std::vector<std::wstring>& tweak_preset_names();
std::vector<Tweak> tweak_preset(const std::wstring& name);   // empty when unknown
// Windows 10 defaults, used only when no snapshot exists: (label, command)
const std::vector<std::pair<std::wstring, std::wstring>>& win10_default_restore();

// POSIX shell-style split (what Python's shlex.split does): quotes, backslash escapes. Throws std::invalid_argument on an open quote.
std::vector<std::wstring> shlex_split(const std::wstring& text);
// "HKLM\Software\" -> "HKEY_LOCAL_MACHINE\Software"
std::wstring normalize_registry_path(const std::wstring& path);

// 'assoc .js=' (remove the association) becomes 'assoc .js=txtfile': a double click shows the script in Notepad. Anything else is unchanged.
std::wstring open_in_editor(const std::wstring& command);
// Command string -> argv with absolute system binaries. Only sc / reg / assoc. Throws std::invalid_argument otherwise.
std::vector<std::wstring> hardening_argv(const std::wstring& command);

struct TweakTarget {
    std::wstring kind;   // service | reg | assoc | unknown
    std::wstring service, key, value, ext;
    bool has_value = false;
};
TweakTarget parse_target(const std::wstring& command);

struct AllowedTargets {
    std::set<std::wstring> services, assocs;
    std::set<std::pair<std::wstring, std::wstring>> registry;   // (normalized key, value), lower case
};
AllowedTargets allowed_targets();

// One registry value as saved: {"exists": false} or {"exists": true, "type": n, "data": ...}
using RegistryReader = std::function<Json(const std::wstring& key, const std::wstring& value, bool has_value)>;
Json read_reg_value(const std::wstring& key, const std::wstring& value, bool has_value);

Json snapshot_entries(const std::vector<std::pair<std::wstring, std::wstring>>& tweaks, const RegistryReader& reader = read_reg_value);
// Writes tweaks_backup_<timestamp>.json into the folder. Empty string = failure (applying must be aborted).
std::wstring snapshot_tweaks(const std::vector<std::pair<std::wstring, std::wstring>>& tweaks, const std::wstring& folder,
                             const RegistryReader& reader = read_reg_value);

// Commands that put back a recorded state. Untrusted or malformed entries are skipped (their names go to `ignored`).
std::vector<std::pair<std::wstring, std::wstring>> revert_commands(const Json& entries, std::vector<std::wstring>* ignored = nullptr);
// Throws std::runtime_error when the file cannot be read or parsed.
std::vector<std::pair<std::wstring, std::wstring>> revert_commands_from_snapshot(const std::wstring& snapshot_file);

// Runs the commands one by one (no shell, 60 s each) and reports each result through `emit`.
struct TweakRunResult {
    int ok = 0, failed = 0;
};
TweakRunResult run_tweaks(const std::vector<std::pair<std::wstring, std::wstring>>& tweaks, const std::function<void(const std::wstring&)>& emit,
                          const Stop& stop = nullptr, const std::function<ProcResult(const std::vector<std::wstring>&)>& runner = nullptr);

// Telemetry scan: samples established connections and the DNS cache, reports the processes talking to Microsoft hosts.
struct TelemetryHit {
    int pid = 0;
    std::wstring process;
    std::vector<std::pair<std::wstring, std::wstring>> connections;   // (ip, host), sorted
};
struct TelemetryResult {
    int samples = 0;
    std::vector<TelemetryHit> hits;   // the busiest first
    std::wstring report() const;
};
const std::vector<std::wstring>& telemetry_keywords();
extern const wchar_t* const TELEMETRY_SCRIPT;
// One sample is {"conn": [...], "dns": [...], "proc": [...]}; the default sampler runs PowerShell.
using TelemetrySampler = std::function<Json()>;
TelemetryResult telemetry_scan(unsigned long duration_ms, unsigned long interval_ms, const Stop& stop = nullptr, const TelemetrySampler& sampler = nullptr,
                               const std::function<void(const std::wstring&)>& emit = nullptr);
// Folds one sample into the running state (exposed for tests).
struct TelemetryState {
    std::map<std::wstring, std::set<std::wstring>> ip_names;
    std::map<int, std::wstring> proc_names;
    std::map<int, std::set<std::pair<std::wstring, std::wstring>>> hits;
};
void telemetry_add_sample(TelemetryState& state, const Json& sample);
TelemetryResult telemetry_result(const TelemetryState& state, int samples);

}  // namespace dd
