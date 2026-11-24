// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Tests API keys, VirusTotal look-ups against a scripted server, route parsing, host checks and garbage statistics.

#include <cstdio>
#include <ctime>

#include <windows.h>

#include <ddcore/inspect.hpp>
#include <ddcore/json.hpp>
#include <ddcore/online.hpp>

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

static std::wstring work(const wchar_t* name) {
    std::wstring dir = join(exe_dir(), std::wstring(name) + L"_" + std::to_wstring(GetCurrentProcessId()));
    make_dirs(dir);
    return dir;
}

static const std::wstring KEY = L"0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef";

static void test_api_keys() {
    std::wstring dir = work(L"online_keys");
    std::wstring path = join(dir, L"api_keys.json");
    CHECK(get_api_key(L"virustotal", path).empty() && api_key_status(L"virustotal", path) == L"No key saved");
    CHECK(validate_api_key(L"virustotal", KEY).empty() && validate_api_key(L"virustotal", L"  " + KEY + L"\n").empty());
    CHECK(validate_api_key(L"virustotal", L"too short").find(L"64 letters and digits") != std::wstring::npos);
    CHECK(!validate_api_key(L"virustotal", KEY.substr(0, 63) + L"g").empty());   // not hexadecimal
    CHECK(!validate_api_key(L"nobody", KEY).empty());
    CHECK(set_api_key(L"virustotal", L"bad", path).find(L"64 letters") != std::wstring::npos && !is_file(path));   // nothing saved for a bad key
    CHECK(set_api_key(L"virustotal", KEY, path).empty());
    CHECK(get_api_key(L"virustotal", path) == KEY && api_key_status(L"virustotal", path) == L"Saved (ends with cdef)");
    std::string stored;
    read_file(path, stored);
    CHECK(stored.find("virustotal") != std::string::npos);
    CHECK(set_api_key(L"virustotal", L"", path).empty() && get_api_key(L"virustotal", path).empty());   // an empty key removes it
    write_file(path, "garbage");
    CHECK(get_api_key(L"virustotal", path).empty());
    write_file(path, "{\"keys\": [1,2]}");
    CHECK(get_api_key(L"virustotal", path).empty());
    CHECK(check_api_key(L"virustotal", L"  ").find(L"No key") == 0 && check_api_key(L"nobody", KEY).find(L"cannot be tested") != std::wstring::npos);
    delete_file(path);
    RemoveDirectoryW(dir.c_str());
}

// A scripted VirusTotal: answers by URL and records every request.
struct FakeServer {
    std::vector<HttpRequest> requests;
    std::map<std::wstring, std::pair<int, std::string>> answers;
    int analysis_polls_until_done = 0;
    Http http() {
        return [this](const HttpRequest& req) {
            requests.push_back(req);
            HttpResponse r;
            std::wstring path = req.url.substr(std::wstring(L"https://www.virustotal.com/api/v3").size());
            if (starts_with(path, L"/analyses/") && analysis_polls_until_done > 0) {
                --analysis_polls_until_done;
                r.ok = true;
                r.status = 200;
                r.body = "{\"data\":{\"attributes\":{\"status\":\"queued\"}}}";
                return r;
            }
            auto it = answers.find(path);
            if (it == answers.end()) {
                r.ok = false;
                r.error = L"no route";
                return r;
            }
            r.ok = true;
            r.status = it->second.first;
            r.body = it->second.second;
            return r;
        };
    }
};

static const char* FILE_REPORT =
    "{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":5,\"suspicious\":1,\"harmless\":10,\"undetected\":50},"
    "\"meaningful_name\":\"bad.exe\",\"names\":[\"bad.exe\",\"other.exe\",\"third.exe\"],\"type_description\":\"Win32 EXE\","
    "\"popular_threat_classification\":{\"suggested_threat_label\":\"trojan.generic\"}}}}";

static void test_virustotal_lookup() {
    FakeServer server;
    server.answers[L"/files/" + std::wstring(64, L'a')] = {200, FILE_REPORT};
    server.answers[L"/files/" + std::wstring(64, L'b')] = {404, "{}"};
    server.answers[L"/files/" + std::wstring(64, L'c')] = {401, "{}"};
    server.answers[L"/files/" + std::wstring(64, L'd')] = {429, "{}"};
    server.answers[L"/files/" + std::wstring(64, L'e')] = {503, ""};
    server.answers[L"/files/" + std::wstring(64, L'f')] = {400, "{\"error\":{\"message\":\"Bad hash\"}}"};
    server.answers[L"/files/" + std::wstring(64, L'g')] = {200, "not json"};
    Http http = server.http();

    VtReport r = vt_lookup(std::wstring(64, L'a'), KEY, http);
    CHECK(r.found && r.malicious == 5 && r.suspicious == 1 && r.harmless == 10 && r.undetected == 50 && r.total() == 66);
    CHECK((r.names == std::vector<std::wstring>{L"bad.exe", L"other.exe", L"third.exe"}));   // the meaningful name is not repeated
    CHECK(r.label == L"trojan.generic" && r.type == L"Win32 EXE" && r.severity() == 2);
    CHECK(r.verdict() == L"6/66 engines flag it (trojan.generic)" && r.link() == L"https://www.virustotal.com/gui/file/" + std::wstring(64, L'a'));
    CHECK(server.requests.back().headers[L"x-apikey"] == KEY && server.requests.back().method == L"GET" && server.requests.back().body.empty());
    CHECK(starts_with(server.requests.back().url, L"https://www.virustotal.com/"));   // the key only goes to VirusTotal, over HTTPS

    VtReport unknown = vt_lookup(std::wstring(64, L'b'), KEY, http);
    CHECK(!unknown.found && unknown.verdict() == L"Unknown to VirusTotal" && unknown.severity() == -1);
    auto message = [&](wchar_t c) {
        try {
            vt_lookup(std::wstring(64, c), KEY, http);
        } catch (const VtError& e) {
            return std::string(e.what());
        }
        return std::string("no error");
    };
    CHECK(message(L'c') == "VirusTotal refused the API key.");
    CHECK(message(L'd').find("quota reached") != std::string::npos);
    CHECK(message(L'e') == "VirusTotal is not available (error 503).");
    CHECK(message(L'f') == "VirusTotal answered 400: Bad hash");
    CHECK(message(L'g').find("could not be read") != std::string::npos);   // an answer that is not JSON is reported, not trusted
    CHECK(message(L'z').find("Cannot reach VirusTotal") != std::string::npos);

    VtReport few;
    few.found = true;
    few.malicious = 1;
    few.harmless = 70;
    CHECK(few.severity() == 1 && few.verdict() == L"1/71 engines flag it");   // no label: nothing in brackets
    VtReport clean;
    clean.found = true;
    clean.harmless = 70;
    CHECK(clean.severity() == 0 && clean.verdict() == L"0/70 engines flag it");
    VtReport busy;
    busy.found = true;
    busy.status = L"queued";
    CHECK(busy.severity() == -1 && busy.verdict() == L"Analysis in progress");
    VtReport suspicious_only;
    suspicious_only.found = true;
    suspicious_only.suspicious = 4;
    CHECK(suspicious_only.severity() == 1);   // three "malicious" are needed for the top level
}

static void test_virustotal_upload() {
    std::wstring dir = work(L"online_vt");
    std::wstring program = join(dir, L"tool.exe"), document = join(dir, L"photo.png"), empty = join(dir, L"empty.bin"), text = join(dir, L"weird n\xE9me\xA7.ps1");
    write_file(program, std::string("MZ") + std::string(100, 'x'));
    write_file(document, std::string("\x89PNG\r\n\x1a\n", 8) + std::string(100, 'x'));
    write_file(empty, "");
    write_file(text, "Write-Host hello");
    write_file(join(dir, L"pack.zip"), std::string("PK\x03\x04", 4) + std::string(100, 'x'));
    CHECK(upload_problem(program).empty() && upload_problem(text).empty());
    CHECK(upload_problem(document).find(L"documents, pictures and media") != std::wstring::npos);
    CHECK(upload_problem(empty) == L"The file is empty." && !upload_problem(join(dir, L"missing.exe")).empty());
    CHECK(upload_problem(join(dir, L"pack.zip")).empty() && upload_warning(join(dir, L"pack.zip")).find(L"archive") != std::wstring::npos && upload_warning(program).empty());
    // a document renamed to .exe is judged by its extension too (programs are what is allowed), a program renamed to .png by its content
    write_file(join(dir, L"disguised.png"), std::string("MZ") + std::string(100, 'x'));
    CHECK(upload_problem(join(dir, L"disguised.png")).empty());

    FakeServer server;
    server.answers[L"/files"] = {200, "{\"data\":{\"id\":\"analysis-123\"}}"};
    Http http = server.http();
    CHECK(vt_upload(program, KEY, http) == L"analysis-123");
    const HttpRequest& sent = server.requests.back();
    CHECK(sent.method == L"POST" && sent.headers.at(L"content-type").find(L"multipart/form-data; boundary=") == 0);
    CHECK(sent.body.find("filename=\"tool.exe\"") != std::string::npos && sent.body.find("MZ") != std::string::npos);
    std::wstring boundary = sent.headers.at(L"content-type").substr(30);
    CHECK(boundary.size() == 32 && sent.body.find("--" + utf8(boundary) + "--") != std::string::npos);
    vt_upload(text, KEY, http);
    CHECK(server.requests.back().body.find("filename=\"weird n_me_.ps1\"") != std::string::npos);   // unusual characters never reach the header

    bool refused = false;
    try {
        vt_upload(document, KEY, http);
    } catch (const VtError&) {
        refused = true;
    }
    CHECK(refused);   // checked again at upload time, whatever the caller did
    std::size_t before = server.requests.size();
    refused = false;
    try {
        vt_upload(empty, KEY, http);
    } catch (const VtError&) {
        refused = true;
    }
    CHECK(refused && server.requests.size() == before);   // nothing was sent

    server.answers[L"/files"] = {200, "{\"data\":{}}"};
    bool no_id = false;
    try {
        vt_upload(program, KEY, http);
    } catch (const VtError& e) {
        no_id = std::string(e.what()).find("did not accept") != std::string::npos;
    }
    CHECK(no_id);
    server.answers[L"/files"] = {413, "{\"error\":{\"message\":\"Too big\"}}"};
    bool too_big = false;
    try {
        vt_upload(program, KEY, http);
    } catch (const VtError& e) {
        too_big = std::string(e.what()).find("Too big") != std::string::npos;
    }
    CHECK(too_big);

    // waiting for the verdict: two polls "queued", then completed with the richer file report
    FakeServer waiter;
    std::wstring sha = std::wstring(64, L'a');
    waiter.answers[L"/analyses/analysis-123"] = {200, "{\"data\":{\"attributes\":{\"status\":\"completed\",\"stats\":{\"malicious\":2,\"undetected\":60}}}}"};
    waiter.answers[L"/files/" + sha] = {200, FILE_REPORT};
    waiter.analysis_polls_until_done = 2;
    std::vector<double> sleeps;
    Sleeper fake_sleep = [&](double seconds) { sleeps.push_back(seconds); };
    VtReport done = wait_for_analysis(L"analysis-123", sha, KEY, waiter.http(), never, fake_sleep);
    CHECK(done.status == L"completed" && done.malicious == 5 && done.names.size() == 3 && sleeps.size() == 2 && sleeps[0] == VT_REQUEST_GAP_SECONDS);
    // the file report is not ready yet (404): the analysis itself has the verdict
    FakeServer early;
    early.answers[L"/analyses/analysis-123"] = {200, "{\"data\":{\"attributes\":{\"status\":\"completed\",\"stats\":{\"malicious\":2,\"undetected\":60}}}}"};
    early.answers[L"/files/" + sha] = {404, "{}"};
    VtReport from_analysis = wait_for_analysis(L"analysis-123", sha, KEY, early.http(), never, fake_sleep);
    CHECK(from_analysis.found && from_analysis.malicious == 2 && from_analysis.undetected == 60);
    // never completes: give up after the time allowed, or when stopped
    FakeServer stuck;
    stuck.answers[L"/analyses/analysis-123"] = {200, "{\"data\":{\"attributes\":{\"status\":\"in-progress\"}}}"};
    sleeps.clear();
    VtReport gave_up = wait_for_analysis(L"analysis-123", sha, KEY, stuck.http(), never, fake_sleep, 60, 15);
    CHECK(gave_up.found && gave_up.status == L"in-progress" && sleeps.size() == 4 && gave_up.verdict() == L"Analysis in progress");
    sleeps.clear();
    VtReport stopped = wait_for_analysis(L"analysis-123", sha, KEY, stuck.http(), [] { return true; }, fake_sleep);
    CHECK(stopped.status == L"in-progress" && sleeps.empty());

    // the whole submit
    FakeServer full;
    full.answers[L"/files"] = {200, "{\"data\":{\"id\":\"analysis-123\"}}"};
    full.answers[L"/analyses/analysis-123"] = {200, "{\"data\":{\"attributes\":{\"status\":\"completed\",\"stats\":{\"malicious\":0,\"undetected\":70}}}}"};
    full.answers[L"/files/" + sha256_file(program)] = {200, FILE_REPORT};
    std::vector<std::wstring> messages;
    VtResult submitted = submit_file(program, KEY, full.http(), [&](const std::wstring& m) { messages.push_back(m); }, never, fake_sleep);
    CHECK(submitted.uploaded && submitted.error.empty() && submitted.has_report && submitted.report.malicious == 5 && submitted.sha256 == sha256_file(program));
    CHECK(messages.size() == 2 && messages[0].find(L"sending tool.exe") != std::wstring::npos);
    VtResult not_allowed = submit_file(document, KEY, full.http(), nullptr, never, fake_sleep);
    CHECK(!not_allowed.error.empty() && !not_allowed.has_report);
    VtResult missing = submit_file(join(dir, L"nope.exe"), KEY, full.http(), nullptr, never, fake_sleep);
    CHECK(!missing.error.empty());

    for (const wchar_t* n : {L"tool.exe", L"photo.png", L"empty.bin", L"pack.zip", L"disguised.png"}) delete_file(join(dir, n));
    delete_file(text);
    RemoveDirectoryW(dir.c_str());
}

static void test_virustotal_check_files() {
    std::wstring dir = work(L"online_check");
    std::wstring a = join(dir, L"a.exe"), b = join(dir, L"b.exe"), c = join(dir, L"c.exe");
    write_file(a, "MZ-a");
    write_file(b, "MZ-b");
    write_file(c, "MZ-c");
    FakeServer server;
    server.answers[L"/files/" + sha256_file(a)] = {200, FILE_REPORT};
    server.answers[L"/files/" + sha256_file(b)] = {404, "{}"};
    server.answers[L"/files/" + sha256_file(c)] = {200, FILE_REPORT};
    std::vector<double> sleeps;
    std::vector<std::wstring> messages;
    auto results = check_files({a, b, c}, KEY, server.http(), [&](const std::wstring& m) { messages.push_back(m); }, never, [&](double s) { sleeps.push_back(s); });
    CHECK(results.size() == 3 && results[0].has_report && results[0].report.found && results[1].has_report && !results[1].report.found && results[2].report.found);
    CHECK(sleeps.size() == 2 && sleeps[0] == VT_REQUEST_GAP_SECONDS);   // one request every 15 seconds, none before the first
    CHECK(messages.size() == 3 && messages[0].find(L"a.exe (1/3)") != std::wstring::npos);
    for (const auto& r : server.requests) CHECK(r.method == L"GET");   // looking up never uploads
    // a missing file is reported and the others go on
    auto with_missing = check_files({join(dir, L"gone.exe"), a}, KEY, server.http(), nullptr, never, [](double) {});
    CHECK(with_missing.size() == 2 && !with_missing[0].error.empty() && with_missing[1].has_report);
    // a refused key or a quota stops everything
    FakeServer refusing;
    refusing.answers[L"/files/" + sha256_file(a)] = {401, "{}"};
    auto stopped = check_files({a, b, c}, KEY, refusing.http(), nullptr, never, [](double) {});
    CHECK(stopped.size() == 1 && stopped[0].error.find(L"refused the API key") != std::wstring::npos && refusing.requests.size() == 1);
    FakeServer quota;
    quota.answers[L"/files/" + sha256_file(a)] = {429, "{}"};
    CHECK(check_files({a, b}, KEY, quota.http(), nullptr, never, [](double) {}).size() == 1);
    CHECK(check_files({a, b}, KEY, server.http(), nullptr, [] { return true; }, [](double) {}).empty());
    // the key is accepted or not
    FakeServer keycheck;
    keycheck.answers[L"/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"] = {200, FILE_REPORT};
    CHECK(check_api_key(L"virustotal", KEY, keycheck.http()).empty());
    FakeServer bad_key;
    bad_key.answers[L"/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"] = {401, "{}"};
    CHECK(check_api_key(L"virustotal", KEY, bad_key.http()) == L"VirusTotal refused the API key.");
    for (const auto& f : {a, b, c}) delete_file(f);
    RemoveDirectoryW(dir.c_str());
}

static void test_route() {
    CHECK(public_address(L"8.8.8.8") == L"8.8.8.8" && public_address(L" 1.1.1.1 ") == L"1.1.1.1");
    CHECK(public_address(L"192.168.1.1").empty() && public_address(L"10.0.0.1").empty() && public_address(L"127.0.0.1").empty() && public_address(L"100.64.0.1").empty());
    CHECK(public_address(L"example.com").empty() && public_address(L"").empty() && public_address(L"8.8.8.8; calc").empty());
    CHECK(public_address(L"2606:4700:4700::1111") == L"2606:4700:4700::1111" && public_address(L"fe80::1").empty());
    CHECK((public_addresses({L"2606:4700::1", L"8.8.4.4", L"192.168.0.1", L"1.1.1.1", L"8.8.4.4", L"junk"}) ==
           std::vector<std::wstring>{L"1.1.1.1", L"8.8.4.4", L"2606:4700::1"}));   // IPv4 first, then by value, no duplicates

    CHECK(valid_host(L"www.Example.com.") == L"www.example.com" && valid_host(L"one.one.one.one (+2 other names)") == L"one.one.one.one");
    CHECK(valid_host(L"192.168.1.1").empty() && valid_host(L"8.8.8.8").empty() && valid_host(L"1.2.3.4.5").empty());   // addresses are not sites
    CHECK(valid_host(L"localhost").empty() && valid_host(L"has space.com").empty() && valid_host(L"a/b.com").empty() && valid_host(L"-bad.com").empty());
    CHECK(valid_host(L"evil.com/path").empty() && valid_host(L"x.y").empty() == true);   // too short to be a host name
    CHECK(valid_host(L"a.bc").empty() == false && valid_host(L"").empty() && valid_host(L"under_score.com").empty());
    CHECK((valid_hosts({L"b.example.com", L"A.example.com", L"b.example.com (+1 other names)", L"192.168.0.1", L"junk"}) ==
           std::vector<std::wstring>{L"a.example.com", L"b.example.com"}));
    CHECK(site_url(L"Example.com") == L"https://example.com/" && site_url(L"192.168.1.1").empty() && site_url(L"javascript:alert(1)").empty());
    CHECK(reputation_url(L"8.8.8.8") == L"https://www.virustotal.com/gui/ip-address/8.8.8.8");
    CHECK(reputation_url(L"Example.com") == L"https://www.virustotal.com/gui/domain/example.com");
    CHECK(reputation_url(L"192.168.1.1").empty() && reputation_url(L"not a host").empty() && reputation_url(L"").empty());
    CHECK(reputation_url(L"2606:4700:4700::1111") == L"https://www.virustotal.com/gui/ip-address/2606%3A4700%3A4700%3A%3A1111");   // everything is percent-encoded

    auto cmd = build_trace_command(L"8.8.8.8");
    CHECK(cmd.size() == 7 && cmd[0] == join(system32(), L"tracert.exe") && cmd[1] == L"-d" && cmd[3] == L"30" && cmd[5] == L"1000" && cmd[6] == L"8.8.8.8");
    bool refused = false;
    try {
        build_trace_command(L"192.168.1.1");
    } catch (const std::invalid_argument&) {
        refused = true;
    }
    bool refused_name = false;
    try {
        build_trace_command(L"example.com");
    } catch (const std::invalid_argument&) {
        refused_name = true;
    }
    CHECK(refused && refused_name);   // only a public address ever reaches tracert, one argument, no shell

    Hop h;
    CHECK(parse_hop(L"  1    <1 ms    <1 ms    <1 ms  192.168.1.1", h) && h.number == 1 && h.address == L"192.168.1.1");
    CHECK((h.times == std::vector<std::wstring>{L"<1 ms", L"<1 ms", L"<1 ms"}) && h.summary() == L"<1 ms   <1 ms   <1 ms");
    CHECK(parse_hop(L"  2     *        *        *     Request timed out.", h) && h.number == 2 && h.address.empty() && h.summary() == L"no answer");
    CHECK((h.times == std::vector<std::wstring>{L"*", L"*", L"*"}));
    CHECK(parse_hop(L" 12    14 ms    13 ms    15 ms  one.one.one.one [1.1.1.1]", h) && h.number == 12 && h.address == L"1.1.1.1");
    CHECK(parse_hop(L"  4     *       12 ms     *     Délai d'attente de la demande dépassé.", h) && h.address.empty() && h.times[1] == L"12 ms");   // French Windows
    CHECK(parse_hop(L"  5    10 ms     9 ms     8 ms  2606:4700:4700::1111", h) && h.address == L"2606:4700:4700::1111");
    CHECK(parse_hop(L"  6    <1 ms     *       2 ms  10.0.0.1", h) && h.times.size() == 3 && h.times[1] == L"*");
    CHECK(parse_hop(L" 30    55 ms", h) && h.times.size() == 1 && h.address.empty());
    CHECK(!parse_hop(L"Tracing route to 8.8.8.8 over a maximum of 30 hops", h) && !parse_hop(L"Trace complete.", h) && !parse_hop(L"", h));
    CHECK(!parse_hop(L"over a maximum of 30 hops:", h) && !parse_hop(L"  1000 abc", h) && !parse_hop(L"Unable to resolve target system name nothing.invalid.", h));
}

static void test_garbage_stats() {
    std::wstring dir = work(L"online_stats");
    std::wstring path = join(dir, L"garbage_stats.json");
    CHECK(load_garbage_stats(path).empty() && garbage_totals({}).deletions == 0);
    CHECK(record_garbage_stat(0, 0, 0, path).empty() && !is_file(path));   // nothing freed: nothing written
    double now = 1795000000.0;
    CHECK(record_garbage_stat(1000, 3, 0, path, now - 86400).empty());
    CHECK(record_garbage_stat(500, 1, 2, path, now).empty());
    CHECK(record_garbage_stat(0, 0, 7, path, now).empty());   // registry entries alone count
    auto entries = load_garbage_stats(path);
    CHECK(entries.size() == 3 && entries[0].bytes == 1000);
    GarbageTotals t = garbage_totals(entries);
    CHECK(t.deletions == 3 && t.bytes == 1500 && t.files == 4 && t.registry == 9);
    auto days = garbage_per_day(entries, 3, now);
    CHECK(days.size() == 3 && days[0].first < days[1].first && days[1].first < days[2].first);
    CHECK(days[2].second == 500 && days[1].second == 1000 && days[0].second == 0);   // oldest first, zeros included
    CHECK(garbage_per_day(entries, 30, now).size() == 30);
    // damaged entries are dropped, negative numbers clamped
    write_file(path, "[{\"t\": 5, \"bytes\": -10, \"files\": 2}, {\"bytes\": 3}, \"x\", {\"t\": \"y\"}]");
    auto repaired = load_garbage_stats(path);
    CHECK(repaired.size() == 1 && repaired[0].bytes == 0 && repaired[0].files == 2);
    write_file(path, "not json");
    CHECK(load_garbage_stats(path).empty());
    // the file never grows without limit
    std::vector<GarbageEntry> many(5000, GarbageEntry{1, 1, 0, 0});
    Json list = Json::array();
    for (const auto& e : many) {
        Json o = Json::object();
        o.set(L"t", Json::number(e.t));
        o.set(L"bytes", Json::number((double)e.bytes));
        list.push(o);
    }
    write_file(path, utf8(list.dump()));
    record_garbage_stat(9, 0, 0, path, now);
    auto capped = load_garbage_stats(path);
    CHECK(capped.size() == 5000 && capped.back().bytes == 9);
    delete_file(path);
    RemoveDirectoryW(dir.c_str());
}

int run_online_tests() {
    test_api_keys();
    test_virustotal_lookup();
    test_virustotal_upload();
    test_virustotal_check_files();
    test_route();
    test_garbage_stats();
    std::printf("online: %d checks, %d failed\n", checks, failures);
    return failures;
}
