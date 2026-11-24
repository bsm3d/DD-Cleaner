// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the online services: API key storage, VirusTotal polling with a stop flag, and the freed-space summary.

#include <ddcore/online.hpp>

#include <algorithm>
#include <ctime>
#include <regex>

#include <windows.h>
#include <bcrypt.h>

#include <ddcore/inspect.hpp>
#include <ddcore/ip.hpp>
#include <ddcore/json.hpp>

namespace dd {

namespace {

std::wstring atomic_json_write(const std::wstring& path, const Json& j, bool pretty) {
    std::wstring temp = path + L".tmp";
    make_dirs(dir_name(path));
    if (!write_file(temp, utf8(j.dump(pretty))) || !MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        return L"The file could not be saved (error " + std::to_wstring(GetLastError()) + L").";
    }
    return L"";
}

bool read_json(const std::wstring& path, Json& out) {
    std::string bytes;
    return read_file(path, bytes) && try_parse_json(wide(bytes), out);
}

}  // namespace

// region API keys

const Provider VIRUSTOTAL_PROVIDER = {
    L"virustotal", L"VirusTotal",
    L"Second opinion on suspicious programs. A lookup sends only the file's SHA-256; sending a file for analysis needs your confirmation each time. "
    L"The free key allows 4 requests per minute.",
    L"https://www.virustotal.com/gui/my-apikey", L"64 letters and digits (hexadecimal)", true};

const Provider* find_provider(const std::wstring& id) { return id == VIRUSTOTAL_PROVIDER.id ? &VIRUSTOTAL_PROVIDER : nullptr; }

std::wstring api_keys_path() { return join(data_dir(), L"api_keys.json"); }

static std::map<std::wstring, std::wstring> read_keys(const std::wstring& path) {
    std::map<std::wstring, std::wstring> keys;
    Json data;
    if (!read_json(path.empty() ? api_keys_path() : path, data) || !data.get(L"keys").is_object()) return keys;
    for (const auto& [k, v] : data.get(L"keys").members()) {
        if (v.is_string()) keys[k] = trim(v.str());
    }
    return keys;
}

std::wstring get_api_key(const std::wstring& id, const std::wstring& path) {
    auto keys = read_keys(path);
    auto it = keys.find(id);
    return it == keys.end() ? L"" : it->second;
}

std::wstring validate_api_key(const std::wstring& id, const std::wstring& key) {
    const Provider* p = find_provider(id);
    if (!p) return L"Unknown service.";
    std::wstring k = trim(key);
    bool hex = k.size() == 64;
    for (wchar_t c : k) hex &= (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F');
    return hex ? L"" : L"A " + p->label + L" API key is " + p->format_hint + L".";
}

std::wstring set_api_key(const std::wstring& id, const std::wstring& key_in, const std::wstring& path_in) {
    std::wstring key = trim(key_in);
    if (!key.empty()) {
        std::wstring problem = validate_api_key(id, key);
        if (!problem.empty()) return problem;
    }
    std::wstring path = path_in.empty() ? api_keys_path() : path_in;
    auto keys = read_keys(path);
    if (!key.empty()) keys[id] = key;
    else keys.erase(id);
    Json stored = Json::object();
    for (const auto& [k, v] : keys) stored.set(k, Json::string(v));
    Json root = Json::object();
    root.set(L"keys", stored);
    return atomic_json_write(path, root, true);   // the message never contains a key
}

std::wstring api_key_status(const std::wstring& id, const std::wstring& path) {
    std::wstring key = get_api_key(id, path);
    return key.empty() ? L"No key saved" : L"Saved (ends with " + key.substr(key.size() > 4 ? key.size() - 4 : 0) + L")";
}

std::wstring check_api_key(const std::wstring& id, const std::wstring& key_in, const Http& http) {
    std::wstring key = trim(key_in);
    if (key.empty()) return L"No key to test.";
    if (id != VIRUSTOTAL_PROVIDER.id) return L"This service cannot be tested.";
    try {
        vt_lookup(L"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", key, http);   // the empty file
        return L"";
    } catch (const std::exception& e) {
        return wide(e.what());
    }
}

// endregion

// region VirusTotal

namespace {

const wchar_t* VT_API = L"https://www.virustotal.com/api/v3";

HttpResponse send(const Http& http, const HttpRequest& req) {
    if (http) return http(req);
    return http_request(req);
}

std::pair<int, Json> vt_call(const std::wstring& method, const std::wstring& path, const std::wstring& key, const std::string& body,
                             const std::wstring& content_type, const Http& http) {
    HttpRequest req;
    req.url = std::wstring(VT_API) + path;
    req.method = method;
    req.headers[L"x-apikey"] = key;
    req.headers[L"accept"] = L"application/json";
    req.headers[L"User-Agent"] = L"DDCleaner/3.0";
    if (!content_type.empty()) req.headers[L"content-type"] = content_type;
    req.body = body;
    req.timeout_ms = 120000;
    req.max_bytes = 8 * 1024 * 1024;
    HttpResponse res = send(http, req);
    if (!res.ok && res.status == 0) throw VtError(utf8(L"Cannot reach VirusTotal: " + res.error));
    Json data;
    if (!res.body.empty()) try_parse_json(wide(res.body), data);
    if (res.status == 401) throw VtError("VirusTotal refused the API key.");
    if (res.status == 429) throw VtError("VirusTotal quota reached (the free key allows 4 requests per minute, 500 per day). Try later.");
    if (res.status >= 500) throw VtError("VirusTotal is not available (error " + std::to_string(res.status) + ").");
    return {res.status, data.is_object() ? data : Json()};
}

VtReport make_report(const std::wstring& sha256, const Json& attributes, const std::wstring& status = L"completed") {
    VtReport r;
    r.found = true;
    r.sha256 = sha256;
    const Json& stats = attributes.get(L"last_analysis_stats").is_object() ? attributes.get(L"last_analysis_stats") : attributes.get(L"stats");
    r.malicious = (int)stats.get(L"malicious").integer();
    r.suspicious = (int)stats.get(L"suspicious").integer();
    r.harmless = (int)stats.get(L"harmless").integer();
    r.undetected = (int)stats.get(L"undetected").integer();
    std::vector<Json> all = {attributes.get(L"meaningful_name")};
    for (const Json& n : attributes.get(L"names").as_list()) all.push_back(n);
    for (const Json& n : all) {
        if (n.is_string() && std::find(r.names.begin(), r.names.end(), n.str()) == r.names.end() && r.names.size() < 5) r.names.push_back(n.str());
    }
    r.label = attributes.get(L"popular_threat_classification").get(L"suggested_threat_label").str();
    r.type = attributes.get(L"type_description").str();
    r.status = status;
    return r;
}

std::wstring random_hex() {
    unsigned char b[16];
    BCryptGenRandom(nullptr, b, sizeof(b), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    wchar_t hex[3];
    std::wstring out;
    for (unsigned char c : b) {
        swprintf(hex, 3, L"%02x", c);
        out += hex;
    }
    return out;
}

void sleep_checking(double seconds, const Stop& stop, const Sleeper& sleep) {
    if (sleep) {
        sleep(seconds);
        return;
    }
    for (double waited = 0; waited < seconds && !stop(); waited += 0.1) Sleep(100);
}

}  // namespace

std::wstring VtReport::link() const { return std::wstring(VIRUSTOTAL_GUI) + L"file/" + sha256; }

std::wstring VtReport::verdict() const {
    if (!found) return L"Unknown to VirusTotal";
    if (status != L"completed") return L"Analysis in progress";
    int flagged = malicious + suspicious;
    std::wstring text = std::to_wstring(flagged) + L"/" + std::to_wstring(total()) + L" engines flag it";
    return text + (!label.empty() && flagged ? L" (" + label + L")" : L"");
}

int VtReport::severity() const {
    if (!found || status != L"completed") return -1;
    if (malicious >= 3) return 2;
    return malicious + suspicious ? 1 : 0;
}

VtReport vt_lookup(const std::wstring& sha256, const std::wstring& key, const Http& http) {
    auto [status, data] = vt_call(L"GET", L"/files/" + sha256, key, "", L"", http);
    if (status == 404) {
        VtReport r;
        r.sha256 = sha256;
        return r;
    }
    if (status != 200) {
        std::wstring message = data.get(L"error").get(L"message").str(L"unexpected answer");
        throw VtError(utf8(L"VirusTotal answered " + std::to_wstring(status) + L": " + message));
    }
    if (!data.get(L"data").is_object()) throw VtError("VirusTotal sent an answer that could not be read.");   // never reported as "0 engines flag it"
    return make_report(sha256, data.get(L"data").get(L"attributes"));
}

std::wstring upload_problem(const std::wstring& path) {
    static const std::set<std::wstring> scripts = {L".ps1", L".vbs", L".vbe", L".js", L".jse", L".bat", L".cmd", L".hta", L".wsf", L".jar", L".dll", L".sys",
                                                   L".scr", L".msi", L".lnk", L".py", L".com", L".exe", L".cpl", L".ocx"};
    Entry info;
    if (!stat_path(path, info)) return L"The file cannot be read.";
    if (info.size == 0) return L"The file is empty.";
    if (info.size > VT_MAX_UPLOAD) return L"The file is larger than 32 MB, the limit of a direct upload.";
    FileInspection inspection = inspect(path);
    if (!inspection.error.empty()) return L"The file cannot be read: " + inspection.error;
    const std::wstring& kind = inspection.kind;
    if (scripts.count(extension(path)) || kind == L"executable" || kind == L"script" || kind == L"shortcut" || kind == L"data" || kind == L"archive") return L"";
    return L"This looks like a " + inspection.true_type + L" (" + kind + L"). Only programs, scripts and archives are sent: documents, pictures and media can hold personal data.";
}

std::wstring upload_warning(const std::wstring& path) {
    return inspect(path).kind == L"archive" ? L"This is an archive: make sure it holds nothing private, VirusTotal will see everything inside." : L"";
}

std::wstring vt_upload(const std::wstring& path, const std::wstring& key, const Http& http) {
    std::wstring problem = upload_problem(path);
    if (!problem.empty()) throw VtError(utf8(problem));
    std::string content;
    if (!read_file(path, content, VT_MAX_UPLOAD)) throw VtError("The file cannot be read.");
    std::wstring boundary = random_hex(), name;
    for (wchar_t c : base_name(path)) name.push_back((c < 128 && (iswalnum(c) || c == L'.' || c == L'_' || c == L'-' || c == L' ')) ? c : L'_');
    if (name.empty()) name = L"file";
    std::string body = utf8(L"--" + boundary + L"\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + name +
                            L"\"\r\nContent-Type: application/octet-stream\r\n\r\n") +
                       content + utf8(L"\r\n--" + boundary + L"--\r\n");
    auto [status, data] = vt_call(L"POST", L"/files", key, body, L"multipart/form-data; boundary=" + boundary, http);
    std::wstring analysis = data.get(L"data").get(L"id").str();
    if (status != 200 || analysis.empty()) {
        throw VtError(utf8(L"VirusTotal did not accept the file (" + std::to_wstring(status) + L"): " + data.get(L"error").get(L"message").str()));
    }
    return analysis;
}

VtReport wait_for_analysis(const std::wstring& analysis_id, const std::wstring& sha256, const std::wstring& key, const Http& http, const Stop& stop,
                           const Sleeper& sleep, double waited, double step) {
    double elapsed = 0;
    for (;;) {
        auto [status, data] = vt_call(L"GET", L"/analyses/" + analysis_id, key, "", L"", http);
        const Json& attributes = data.get(L"data").get(L"attributes");
        std::wstring state = attributes.get(L"status").str();
        if (status == 200 && state == L"completed") {
            try {
                VtReport report = vt_lookup(sha256, key, http);   // richer than the analysis: names, label, type
                if (report.found) return report;
            } catch (const VtError&) {
            }
            return make_report(sha256, attributes);   // the file report is not ready yet: the analysis has the verdict
        }
        if (elapsed >= waited || stop()) {
            VtReport pending;
            pending.found = true;
            pending.sha256 = sha256;
            pending.status = state.empty() ? L"queued" : state;
            return pending;
        }
        sleep_checking(step, stop, sleep);
        elapsed += step;
    }
}

static std::wstring sha_or_empty(const std::wstring& path) { return sha256_file(path); }

std::vector<VtResult> check_files(const std::vector<std::wstring>& paths, const std::wstring& key, const Http& http, const Progress& progress, const Stop& stop,
                                  const Sleeper& sleep) {
    std::vector<VtResult> results;
    for (std::size_t i = 0; i < paths.size(); ++i) {
        if (stop()) break;
        if (i) sleep_checking(VT_REQUEST_GAP_SECONDS, stop, sleep);
        if (progress) progress(L"VirusTotal: looking up " + base_name(paths[i]) + L" (" + std::to_wstring(i + 1) + L"/" + std::to_wstring(paths.size()) + L")...");
        VtResult result;
        result.path = paths[i];
        bool stop_all = false;
        try {
            result.sha256 = sha_or_empty(paths[i]);
            if (result.sha256.empty()) throw VtError("The file cannot be read.");
            result.report = vt_lookup(result.sha256, key, http);
            result.has_report = true;
        } catch (const VtError& e) {
            result.error = wide(e.what());
            stop_all = result.error.find(L"refused the API key") != std::wstring::npos || result.error.find(L"quota") != std::wstring::npos;   // no point trying the others
        }
        results.push_back(std::move(result));
        if (stop_all) break;
    }
    return results;
}

VtResult submit_file(const std::wstring& path, const std::wstring& key, const Http& http, const Progress& progress, const Stop& stop, const Sleeper& sleep) {
    VtResult result;
    result.path = path;
    result.uploaded = true;
    try {
        result.sha256 = sha_or_empty(path);
        if (result.sha256.empty()) throw VtError("The file cannot be read.");
        if (progress) progress(L"VirusTotal: sending " + base_name(path) + L"...");
        std::wstring analysis = vt_upload(path, key, http);
        if (progress) progress(L"VirusTotal: analysis running, this takes a few minutes...");
        result.report = wait_for_analysis(analysis, result.sha256, key, http, stop, sleep);
        result.has_report = true;
    } catch (const VtError& e) {
        result.error = wide(e.what());
    }
    return result;
}

// endregion

// region Route

std::wstring public_address(const std::wstring& text) {
    IpAddress ip;
    return parse_ip(text, ip) && ip.is_global() ? ip.str() : L"";
}

std::vector<std::wstring> public_addresses(const std::vector<std::wstring>& addresses) {
    std::map<std::pair<int, unsigned __int128>, std::wstring> sorted;
    for (const auto& a : addresses) {
        IpAddress ip;
        if (parse_ip(a, ip) && ip.is_global()) sorted[{ip.version(), ip.value()}] = ip.str();
    }
    std::vector<std::wstring> out;
    for (const auto& kv : sorted) out.push_back(kv.second);
    return out;
}

std::wstring valid_host(const std::wstring& name_in) {
    static const std::wregex host_name(LR"(^(?=.{4,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$)");
    std::wstring name = name_in.substr(0, name_in.find(L" (+"));
    name = lower(trim(name));
    while (!name.empty() && name.back() == L'.') name.pop_back();
    if (!std::regex_match(name, host_name)) return L"";
    std::wstring tld = name.substr(name.find_last_of(L'.') + 1);
    bool numeric = !tld.empty();
    for (wchar_t c : tld) numeric &= c >= L'0' && c <= L'9';
    if (numeric) return L"";   // a name ends in letters: "192.168.1.1" is an address, not a site
    IpAddress ip;
    return parse_ip(name, ip) ? L"" : name;
}

std::vector<std::wstring> valid_hosts(const std::vector<std::wstring>& names) {
    std::set<std::wstring> found;
    for (const auto& n : names) {
        std::wstring v = valid_host(n);
        if (!v.empty()) found.insert(v);
    }
    return {found.begin(), found.end()};
}

std::wstring site_url(const std::wstring& host) {
    std::wstring h = valid_host(host);
    return h.empty() ? L"" : L"https://" + h + L"/";
}

std::wstring reputation_url(const std::wstring& target) {
    std::wstring address = public_address(target);
    if (!address.empty()) return std::wstring(VIRUSTOTAL_GUI) + L"ip-address/" + url_encode(address);
    std::wstring host = valid_host(target);
    return host.empty() ? L"" : std::wstring(VIRUSTOTAL_GUI) + L"domain/" + url_encode(host);
}

std::vector<std::wstring> build_trace_command(const std::wstring& address) {
    std::wstring target = public_address(address);
    if (target.empty()) throw std::invalid_argument("A route can only be traced to a public Internet address.");
    wchar_t cmd[64];
    (void)cmd;
    return {join(system32(), L"tracert.exe"), L"-d", L"-h", std::to_wstring(MAX_HOPS), L"-w", std::to_wstring(PROBE_TIMEOUT_MS), target};
}

std::wstring Hop::summary() const {
    if (address.empty()) return L"no answer";
    std::wstring out;
    for (std::size_t i = 0; i < times.size(); ++i) out += (i ? L"   " : L"") + times[i];
    return out;
}

bool parse_hop(const std::wstring& line, Hop& out) {
    static const std::wregex hop_line(LR"(^\s*(\d{1,3})\s+(.+?)\s*$)");
    static const std::wregex time_re(LR"((<?\s*\d+)\s*ms|\*)");
    std::wsmatch match;
    if (!std::regex_match(line, match, hop_line)) return false;
    std::wstring rest = match[2];
    std::vector<std::wstring> times;
    std::size_t end = 0;
    for (std::wsregex_iterator it(rest.begin(), rest.end(), time_re), stop; it != stop; ++it) {
        if ((*it)[0] == L"*") {
            times.push_back(L"*");
        } else {
            std::wstring t = (*it)[1];
            t.erase(std::remove_if(t.begin(), t.end(), [](wchar_t c) { return iswspace(c); }), t.end());
            times.push_back(t + L" ms");
        }
        end = (std::size_t)(it->position(0) + it->length(0));
    }
    if (times.empty()) return false;
    std::wstring address;
    std::wstring tail = rest.substr(end), token;
    std::vector<std::wstring> tokens;
    for (wchar_t c : tail + L" ") {
        if (iswspace(c)) {
            if (!token.empty()) tokens.push_back(token);
            token.clear();
        } else {
            token.push_back(c);
        }
    }
    for (const auto& t : tokens) {
        std::wstring cleaned = t;
        while (!cleaned.empty() && (cleaned.front() == L'[' || cleaned.front() == L'(' || cleaned.front() == L']' || cleaned.front() == L')')) cleaned.erase(0, 1);
        while (!cleaned.empty() && (cleaned.back() == L'[' || cleaned.back() == L'(' || cleaned.back() == L']' || cleaned.back() == L')')) cleaned.pop_back();
        IpAddress ip;
        if (parse_ip(cleaned, ip)) {
            address = ip.str();
            break;
        }
    }
    out.number = std::stoi(match[1]);
    out.times.assign(times.begin(), times.begin() + std::min<std::size_t>(3, times.size()));
    out.address = address;
    return true;
}

// endregion

// region What the Garbage page freed

std::wstring garbage_stats_path() { return join(data_dir(), L"garbage_stats.json"); }

std::vector<GarbageEntry> load_garbage_stats(const std::wstring& path) {
    std::vector<GarbageEntry> clean;
    Json data;
    if (!read_json(path.empty() ? garbage_stats_path() : path, data) || !data.is_array()) return clean;
    for (const Json& e : data.items()) {
        if (!e.is_object() || !e.get(L"t").is_number()) continue;
        clean.push_back({e.get(L"t").num(), std::max(0LL, e.get(L"bytes").integer()), std::max(0LL, e.get(L"files").integer()), std::max(0LL, e.get(L"registry").integer())});
    }
    return clean;
}

std::wstring record_garbage_stat(long long freed_bytes, long long files, long long registry, const std::wstring& path_in, double now) {
    if (freed_bytes <= 0 && files <= 0 && registry <= 0) return L"";   // nothing was freed: nothing is written
    std::wstring path = path_in.empty() ? garbage_stats_path() : path_in;
    auto entries = load_garbage_stats(path);
    entries.push_back({now < 0 ? now_seconds() : now, freed_bytes, files, registry});
    const std::size_t max_entries = 5000;
    if (entries.size() > max_entries) entries.erase(entries.begin(), entries.end() - (long)max_entries);
    Json list = Json::array();
    for (const auto& e : entries) {
        Json o = Json::object();
        o.set(L"t", Json::number(e.t));
        o.set(L"bytes", Json::number((double)e.bytes));
        o.set(L"files", Json::number((double)e.files));
        o.set(L"registry", Json::number((double)e.registry));
        list.push(o);
    }
    return atomic_json_write(path, list, false);
}

GarbageTotals garbage_totals(const std::vector<GarbageEntry>& entries) {
    GarbageTotals t;
    t.deletions = (long long)entries.size();
    for (const auto& e : entries) {
        t.bytes += e.bytes;
        t.files += e.files;
        t.registry += e.registry;
    }
    return t;
}

static std::wstring day_text(double seconds) {
    std::time_t t = (std::time_t)seconds;
    std::tm tm{};
    localtime_s(&tm, &t);
    wchar_t buf[16];
    wcsftime(buf, 16, L"%Y-%m-%d", &tm);
    return buf;
}

std::vector<std::pair<std::wstring, long long>> garbage_per_day(const std::vector<GarbageEntry>& entries, int days, double now_in) {
    double now = now_in < 0 ? now_seconds() : now_in;
    std::time_t t = (std::time_t)now;
    std::tm base{};
    localtime_s(&base, &t);
    base.tm_hour = 12;   // noon: a daylight-saving change never turns two days into one
    std::map<std::wstring, long long> buckets;
    for (int i = 0; i < days; ++i) {
        std::tm day = base;
        day.tm_mday -= i;
        day.tm_isdst = -1;
        buckets[day_text((double)std::mktime(&day))] = 0;
    }
    for (const auto& e : entries) {
        auto it = buckets.find(day_text(e.t));
        if (it != buckets.end()) it->second += e.bytes;
    }
    return {buckets.begin(), buckets.end()};
}

// endregion

}  // namespace dd
