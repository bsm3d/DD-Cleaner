// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the online services: API keys, VirusTotal look-ups, the route to a destination and the freed-space summary.

// API keys: one file in the data folder, never logged, never shown in full, sent only to their own service.
// VirusTotal: a look-up sends only the SHA-256. Sending a file shares it with everyone on VirusTotal and cannot be undone.
// So sending is limited to programs and scripts (archives with a warning), and only once the user has asked.
#pragma once

#include <functional>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <ddcore/common.hpp>
#include <ddcore/net.hpp>

namespace dd {

// region API keys
struct Provider {
    std::wstring id, label, purpose, get_it, format_hint;
    bool testable = true;
};
extern const Provider VIRUSTOTAL_PROVIDER;
const Provider* find_provider(const std::wstring& id);

using Http = std::function<HttpResponse(const HttpRequest&)>;   // replaceable in tests

std::wstring api_keys_path();
std::wstring get_api_key(const std::wstring& provider_id, const std::wstring& path = L"");
std::wstring validate_api_key(const std::wstring& provider_id, const std::wstring& key);   // "" when it has the right shape
std::wstring set_api_key(const std::wstring& provider_id, const std::wstring& key, const std::wstring& path = L"");   // empty key removes; "" or an error
std::wstring api_key_status(const std::wstring& provider_id, const std::wstring& path = L"");   // "Saved (ends with abcd)" | "No key saved"
std::wstring check_api_key(const std::wstring& provider_id, const std::wstring& key, const Http& http = nullptr);   // "" when the service accepts it
// endregion

// region VirusTotal
class VtError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct VtReport {
    bool found = false;
    std::wstring sha256;
    int malicious = 0, suspicious = 0, harmless = 0, undetected = 0;
    std::vector<std::wstring> names;
    std::wstring label, type;
    std::wstring status = L"completed";   // queued | in-progress | completed (a fresh upload takes a few minutes)
    int total() const { return malicious + suspicious + harmless + undetected; }
    std::wstring link() const;
    std::wstring verdict() const;
    int severity() const;   // 0 clean, 1 a few engines (often false positives), 2 several engines, -1 no verdict yet
};

struct VtResult {
    std::wstring path, sha256;
    bool has_report = false;
    VtReport report;
    std::wstring error;
    bool uploaded = false;
};

constexpr std::uint64_t VT_MAX_UPLOAD = 32ull * 1024 * 1024;   // the plain upload endpoint refuses more
constexpr double VT_REQUEST_GAP_SECONDS = 15;                    // the free key allows 4 requests per minute
constexpr double VT_ANALYSIS_WAIT_SECONDS = 360;

using Sleeper = std::function<void(double seconds)>;
VtReport vt_lookup(const std::wstring& sha256, const std::wstring& key, const Http& http = nullptr);   // throws VtError
std::wstring upload_problem(const std::wstring& path);   // why this file must not be sent ("" when it may be offered to the user)
std::wstring upload_warning(const std::wstring& path);
std::wstring vt_upload(const std::wstring& path, const std::wstring& key, const Http& http = nullptr);   // analysis id; throws VtError
VtReport wait_for_analysis(const std::wstring& analysis_id, const std::wstring& sha256, const std::wstring& key, const Http& http = nullptr,
                           const Stop& stop = never, const Sleeper& sleep = nullptr, double waited = VT_ANALYSIS_WAIT_SECONDS,
                           double step = VT_REQUEST_GAP_SECONDS);
// Look each file up by hash, one request every REQUEST_GAP_SECONDS (free key quota). Nothing is uploaded.
std::vector<VtResult> check_files(const std::vector<std::wstring>& paths, const std::wstring& key, const Http& http = nullptr, const Progress& progress = nullptr,
                                  const Stop& stop = never, const Sleeper& sleep = nullptr);
VtResult submit_file(const std::wstring& path, const std::wstring& key, const Http& http = nullptr, const Progress& progress = nullptr,
                     const Stop& stop = never, const Sleeper& sleep = nullptr);
// endregion

// region Route (tracert)
constexpr int MAX_HOPS = 30;
constexpr int PROBE_TIMEOUT_MS = 1000;
constexpr const wchar_t* VIRUSTOTAL_GUI = L"https://www.virustotal.com/gui/";

std::wstring public_address(const std::wstring& text);              // the normalized text of a public IP address, "" for anything else
std::vector<std::wstring> public_addresses(const std::vector<std::wstring>& addresses);   // sorted: IPv4 first
std::wstring valid_host(const std::wstring& name);                  // the lower-case host name, "" when it is not a plain Internet name
std::vector<std::wstring> valid_hosts(const std::vector<std::wstring>& names);
std::wstring site_url(const std::wstring& host);                    // https://host/ or ""
std::wstring reputation_url(const std::wstring& target);            // VirusTotal page about an address or a host name ("" otherwise)
std::vector<std::wstring> build_trace_command(const std::wstring& address);   // tracert, without name lookups, to a public address; throws std::invalid_argument

struct Hop {
    int number = 0;
    std::vector<std::wstring> times;   // "12 ms", "<1 ms" or "*" for each probe
    std::wstring address;              // "" when the router did not answer
    std::wstring summary() const;
};
// One line of tracert output, whatever the language of Windows. False for header, footer and error lines.
bool parse_hop(const std::wstring& line, Hop& out);
// endregion

// region What the Garbage page freed
struct GarbageEntry {
    double t = 0;
    long long bytes = 0, files = 0, registry = 0;
};
struct GarbageTotals {
    long long deletions = 0, bytes = 0, files = 0, registry = 0;
};
std::wstring garbage_stats_path();
std::vector<GarbageEntry> load_garbage_stats(const std::wstring& path = L"");
std::wstring record_garbage_stat(long long freed_bytes, long long files = 0, long long registry = 0, const std::wstring& path = L"", double now = -1);
GarbageTotals garbage_totals(const std::vector<GarbageEntry>& entries);
// (day as YYYY-MM-DD, bytes freed) for each of the last `days` days, oldest first, zeros included.
std::vector<std::pair<std::wstring, long long>> garbage_per_day(const std::vector<GarbageEntry>& entries, int days = 30, double now = -1);
// endregion

}  // namespace dd
