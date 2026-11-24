// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Tests IP classification against Python's ipaddress module, RDAP owner lookup, DNS names, GeoIP and traffic grouping.

#include <cmath>
#include <cstdio>
#include <cstdint>
#include <mutex>

#include <windows.h>

#include <ddcore/geoip.hpp>
#include <ddcore/ip.hpp>
#include <ddcore/ipinfo.hpp>
#include <ddcore/traffic.hpp>

#include "gz_blob.inc"

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

struct IpCase {
    const wchar_t* text;
    int valid, global;
    const wchar_t* normalized;
    const wchar_t* kind;
};

static const IpCase IP_CASES[] = {
#include "ip_cases.inc"
};

static void test_ip() {
    for (const IpCase& c : IP_CASES) {
        IpAddress ip;
        bool ok = parse_ip(c.text, ip);
        if (ok != (c.valid != 0)) std::fprintf(stderr, "  parse mismatch: %ls\n", c.text);
        CHECK(ok == (c.valid != 0));
        if (!ok) {
            CHECK(remote_kind(c.text).empty());
            continue;
        }
        if (ip.is_global() != (c.global != 0)) std::fprintf(stderr, "  global mismatch: %ls\n", c.text);
        CHECK(ip.is_global() == (c.global != 0));
        if (ip.str() != c.normalized) std::fprintf(stderr, "  text mismatch: %ls -> %ls (wanted %ls)\n", c.text, ip.str().c_str(), c.normalized);
        CHECK(ip.str() == c.normalized);
        if (remote_kind(c.text) != c.kind) std::fprintf(stderr, "  kind mismatch: %ls -> %ls (wanted %ls)\n", c.text, remote_kind(c.text).c_str(), c.kind);
        CHECK(remote_kind(c.text) == c.kind);
        CHECK(is_public(c.text) == (c.global != 0));
    }

    IpNetwork net;
    CHECK(parse_network(L"10.1.2.3/8", net) && net.base.str() == L"10.0.0.0" && net.prefix == 8);   // not strict: host bits are cleared
    CHECK(net.contains(IpAddress{false, {10, 200, 1, 1}}));
    IpAddress other;
    parse_ip(L"11.0.0.1", other);
    CHECK(!net.contains(other));
    parse_ip(L"::1", other);
    CHECK(!net.contains(other));   // another IP version never matches
    CHECK(!parse_network(L"10.0.0.0/33", net) && !parse_network(L"nope", net));
    CHECK(parse_network(L"2001:db8::/32", net) && net.contains(IpAddress::from_value(((unsigned __int128)0x20010db8 << 96) | 5, true)));
    CHECK(parse_network(L"0.0.0.0/0", net) && net.contains(other) == false && parse_ip(L"9.9.9.9", other) && net.contains(other));

    auto texts = [](const IpNetwork& n) { return n.base.str() + L"/" + std::to_wstring(n.prefix); };
    auto summary = [&](const wchar_t* a, const wchar_t* b) {
        IpAddress x, y;
        parse_ip(a, x);
        parse_ip(b, y);
        std::wstring out;
        for (const auto& n : summarize_range(x, y)) out += (out.empty() ? L"" : L" ") + texts(n);
        return out;
    };
    CHECK(summary(L"10.0.0.0", L"10.0.0.255") == L"10.0.0.0/24");
    CHECK(summary(L"1.2.3.4", L"1.2.3.9") == L"1.2.3.4/30 1.2.3.8/31");
    CHECK(summary(L"8.8.8.0", L"8.8.8.0") == L"8.8.8.0/32");
    CHECK(summary(L"2001:db8::", L"2001:db8::ffff") == L"2001:db8::/112");
    CHECK(summary(L"192.168.0.5", L"192.168.1.20") ==
          L"192.168.0.5/32 192.168.0.6/31 192.168.0.8/29 192.168.0.16/28 192.168.0.32/27 192.168.0.64/26 192.168.0.128/25 192.168.1.0/28 192.168.1.16/30 192.168.1.20/32");
}

static void test_dns_and_multicast() {
    int reads = 0;
    DnsNames dns([&] {
        ++reads;
        return parse_json(LR"J([{"Entry":"WWW.Example.com.","Data":"93.184.216.34"},{"Entry":"example.org","Data":"93.184.216.34"},
                                {"Entry":"www.example.com","Data":"93.184.216.34"},{"Entry":"","Data":"1.1.1.1"}])J").as_list();
    }, 3600);
    dns.refresh();
    dns.refresh();   // not asked again: the interval has not passed
    CHECK(reads == 1);
    auto names = dns.names(L"93.184.216.34");
    CHECK(names.size() == 2 && names[0] == L"www.example.com" && names[1] == L"example.org");
    CHECK(dns.names(L"1.1.1.1").empty() && dns.names(L"9.9.9.9").empty());
    dns.refresh(true);
    CHECK(reads == 2 && dns.names(L"93.184.216.34").size() == 2);   // names are kept, never doubled
    CHECK(multicast_names().at(L"224.0.0.251") == L"mDNS (local discovery)");
}

static const wchar_t* ARIN_ANSWER = LR"J({
  "name": "GOGL", "startAddress": "8.8.8.0", "endAddress": "8.8.8.255", "country": "United States",
  "entities": [
    {"roles": ["technical"], "vcardArray": ["vcard", [["fn", {}, "text", "Tech person"]]]},
    {"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"], ["kind", {}, "text", "org"],
      ["adr", {"label": "1600 Amphitheatre Parkway\nMountain View\nUS"}, "text", ["", "", "1600 Amphitheatre Parkway", "Mountain View", "CA", "94043", "US"]]]]}
  ]})J";

static void test_rdap() {
    Json answer = parse_json(ARIN_ANSWER);
    Owner o = parse_rdap(answer, L"rdap.arin.net");
    CHECK(o.organization == L"Google LLC" && o.country == L"US" && o.network == L"GOGL" && o.registry == L"rdap.arin.net");
    CHECK(o.range == L"8.8.8.0 - 8.8.8.255" && o.label() == L"Google LLC (US)");

    // no organisation entity: the remarks, then the address of an administrative contact
    Json remarks = parse_json(LR"J({"name":"NET-X","country":"FR","remarks":[{"description":["This is a certificate remark: CERTIFICATE"]},{"description":["Example ISP","customers"]}]})J");
    Owner r = parse_rdap(remarks);
    CHECK(r.organization == L"Example ISP customers" && r.country == L"FR" && r.label() == L"Example ISP customers (FR)");
    Json contact = parse_json(LR"J({"name":"NET-Y","entities":[{"roles":["administrative"],"vcardArray":["vcard",[["adr",{"label":"Acme Hosting\nStreet 1\nGermany"},"text",[]]]]}]})J");
    Owner c = parse_rdap(contact);
    CHECK(c.organization == L"Acme Hosting" && c.country == L"DE");   // the country name found in the label becomes an ISO code
    Json bare = parse_json(LR"J({"name":"ONLYNAME"})J");
    CHECK(parse_rdap(bare).label() == L"ONLYNAME" && parse_rdap(bare).country.empty());

    // which networks an answer may be cached for
    IpAddress ip;
    parse_ip(L"8.8.8.8", ip);
    auto nets = answer_networks(answer, ip);
    CHECK(nets.size() == 1 && nets[0].prefix == 24 && nets[0].base.str() == L"8.8.8.0");
    parse_ip(L"9.9.9.9", ip);
    auto outside = answer_networks(answer, ip);   // the range does not contain the queried address
    CHECK(outside.size() == 1 && outside[0].prefix == 32 && outside[0].base.str() == L"9.9.9.9");
    Json huge = parse_json(LR"J({"startAddress":"0.0.0.0","endAddress":"255.255.255.255"})J");
    parse_ip(L"8.8.4.4", ip);
    auto wide_range = answer_networks(huge, ip);   // an absurdly wide block is never cached as a whole
    CHECK(wide_range.size() == 1 && wide_range[0].prefix == 32);
    Json mixed = parse_json(LR"J({"startAddress":"::","endAddress":"ffff::"})J");
    CHECK(answer_networks(mixed, ip).size() == 1);
    CHECK(answer_networks(Json(), ip).size() == 1);
}

static void test_owner_lookup() {
    std::mutex lock;
    std::vector<std::wstring> asked;
    RdapFetch fetch = [&](const std::wstring& url, Json& data, std::wstring& final_url) {
        {
            std::lock_guard<std::mutex> g(lock);
            asked.push_back(url);
        }
        if (url == L"https://data.iana.org/rdap/ipv4.json") {
            data = parse_json(LR"J({"services":[[["8.0.0.0/8","9.0.0.0/8"],["http://insecure.example/","https://rdap.arin.net/registry/"]],[["8.8.8.0/24"],["https://rdap.special.example/"]]]})J");
            final_url = url;
            return true;
        }
        if (url == L"https://rdap.special.example/ip/8.8.8.8") {
            data = parse_json(ARIN_ANSWER);
            final_url = url;
            return true;
        }
        return false;   // everything else fails
    };
    OwnerLookup lookup(fetch, 1);
    CHECK(!lookup.lookup(L"192.168.1.1") && !lookup.lookup(L"abc") && !lookup.cached(L"abc"));   // private or not an address: never asked
    auto owner = lookup.resolve_now(L"8.8.8.8");
    CHECK(owner && owner->organization == L"Google LLC" && owner->registry == L"rdap.special.example");
    // the answer covers the whole /24: another address in it needs no request
    std::size_t before = asked.size();
    auto sibling = lookup.cached(L"8.8.8.200");
    CHECK(sibling && sibling->organization == L"Google LLC" && asked.size() == before);
    CHECK(!lookup.cached(L"8.8.9.1"));
    // a failed lookup is remembered and not retried at once
    auto failed = lookup.resolve_now(L"9.9.9.9");
    CHECK(!failed);
    std::size_t after_first = asked.size();
    CHECK(!lookup.lookup(L"9.9.9.9"));   // retry window not over: nothing is queued
    Sleep(150);
    CHECK(asked.size() == after_first);
    // the background path
    OwnerLookup background(fetch, 1);
    CHECK(!background.lookup(L"8.8.8.8"));
    for (int i = 0; i < 100 && !background.cached(L"8.8.8.8"); ++i) Sleep(20);
    auto found = background.lookup(L"8.8.8.8");
    CHECK(found && found->label() == L"Google LLC (US)");
    background.enabled = false;
    CHECK(!background.lookup(L"8.8.9.9"));   // disabled: nothing queued
    background.shutdown();
}

static void test_gzip() {
    std::string gz(reinterpret_cast<const char*>(GZ_BLOB), GZ_BLOB_SIZE), out;
    std::wstring error;
    CHECK(gunzip(gz, out, 1000000, error) && out.size() == GZ_PLAIN_SIZE && out.substr(0, 17) == "hello gzip world ");
    CHECK(!gunzip(gz, out, 100, error));   // larger than the limit
    CHECK(!gunzip("not gzip at all, not even close to it", out, 1000, error));
    std::string cut = gz.substr(0, gz.size() - 20);
    CHECK(!gunzip(cut, out, 1000000, error));
    CHECK(candidate_months(2026, 11) == (std::vector<std::wstring>{L"2026-11", L"2026-10"}));
    CHECK(candidate_months(2026, 1) == (std::vector<std::wstring>{L"2026-01", L"2025-12"}));
    CHECK(needs_update({}) && needs_update({{L"downloaded", L"nonsense"}}));
    CHECK(!needs_update({{L"downloaded", L"2026-11-15T08:00:00"}}, 1795000000.0 /* 2026-11-18 */));
    CHECK(needs_update({{L"downloaded", L"2026-09-01T08:00:00"}}, 1795000000.0));
}

// the build folder is <project>\cpp\build: the Python project keeps its database in <project>\geoip
static std::wstring project_root() { return dir_name(dir_name(exe_dir())); }
static std::wstring python_geoip_folder() { return join(project_root(), L"geoip"); }

static void test_world_and_geoip() {
    const World& w = world();
    CHECK(w.countries.size() == 198);
    std::size_t rings = 0;
    for (const auto& c : w.countries) for (const auto& ring : c.rings) rings += ring.size();   // points
    CHECK(rings == 10559);
    CHECK(country_code(L"France") == L"FR" && country_code(L"DEU") == L"DE" && country_code(L"fr") == L"FR");
    CHECK(country_code(L"FRA").empty());   // the bundled data has no ISO3 code for France (-99), like the Python version
    CHECK(country_code(L"United States of America") == L"US" && country_code(L"Viet Nam") == L"VN" && country_code(L"EU").empty());
    CHECK(country_code(L"").empty() && country_code(L"Atlantis").empty());
    const Country* fr = find_country(L"FR");
    CHECK(fr && fr->name == L"France" && !fr->rings.empty() && find_country(L"XX") == nullptr);
    CHECK(!home_country().empty());

    std::wstring folder = python_geoip_folder();
    if (!is_file(join(folder, DBIP_FILE_NAME))) {
        std::printf("  (no DB-IP database in %ls: lookups not exercised)\n", folder.c_str());
        return;
    }
    GeoIP geo(folder);
    CHECK(geo.available());
    auto check = [&](const wchar_t* addr, const wchar_t* country, const wchar_t* city, const wchar_t* region, double lat, double lon) {
        auto l = geo.locate(addr);
        bool ok = l && l->country == country && l->city == city && l->region == region && std::fabs(l->lat - lat) < 0.0001 && std::fabs(l->lon - lon) < 0.0001;
        if (!ok) std::fprintf(stderr, "  geoip mismatch for %ls\n", addr);
        CHECK(ok);
    };
    check(L"8.8.8.8", L"US", L"Mountain View", L"California", 37.422, -122.085);
    check(L"1.1.1.1", L"AU", L"Sydney", L"New South Wales", -33.8688, 151.209);
    check(L"142.250.74.46", L"US", L"Mountain View", L"California", 37.4225, -122.085);
    check(L"2001:4860:4860::8888", L"CA", L"Montreal", L"Quebec", 45.5019, -73.5674);
    check(L"91.121.0.1", L"FR", L"Roubaix", L"Hauts-de-France", 50.6924, 3.2011);
    check(L"200.200.200.200", L"BR", L"São José do Rio Preto", L"São Paulo", -21.2922, -50.3428);   // UTF-8 names
    CHECK(!geo.locate(L"192.168.1.1"));
    CHECK(!geo.locate(L"not an address"));
    auto l = geo.locate(L"8.8.8.8");
    CHECK(l && l->label() == L"Mountain View, US");
    CHECK(!geo.info().empty() && geo.info()[L"attribution"].find(L"DB-IP") != std::wstring::npos);

    // a suspended reader lets go of the file (so it can be replaced) and answers nothing; resuming brings it back
    geo.suspend();
    CHECK(!geo.locate(L"1.1.1.1") && !geo.available());
    std::wstring copy = temp_dir() + L"\\ddcore_geo_" + std::to_wstring(GetCurrentProcessId());
    make_dirs(copy);
    CHECK(CopyFileW(join(folder, DBIP_FILE_NAME).c_str(), join(copy, DBIP_FILE_NAME).c_str(), FALSE) != 0);
    geo.resume();
    CHECK(geo.locate(L"1.1.1.1").has_value());

    // damaged files never crash a lookup: cut copy and a copy with garbage in the data section
    {
        std::string bytes;
        read_file(join(folder, DBIP_FILE_NAME), bytes);
        std::wstring cut_folder = copy + L"\\cut";
        make_dirs(cut_folder);
        write_file(join(cut_folder, DBIP_FILE_NAME), bytes.substr(0, bytes.size() / 2));   // the metadata is gone
        GeoIP cut(cut_folder);
        CHECK(!cut.available() && !cut.locate(L"8.8.8.8"));
        std::string noise = bytes;
        for (std::size_t i = noise.size() / 2; i < noise.size() / 2 + 200000 && i < noise.size() - 200000; i += 7) noise[i] = (char)(noise[i] ^ 0x5A);
        std::wstring noise_folder = copy + L"\\noise";
        make_dirs(noise_folder);
        write_file(join(noise_folder, DBIP_FILE_NAME), noise);
        GeoIP noisy(noise_folder);
        for (const wchar_t* a : {L"8.8.8.8", L"1.1.1.1", L"91.121.0.1", L"200.200.200.200", L"185.199.108.153"}) noisy.locate(a);   // must simply return
        CHECK(true);
        cut.close();
        noisy.close();
        delete_file(join(cut_folder, DBIP_FILE_NAME));
        delete_file(join(noise_folder, DBIP_FILE_NAME));
        RemoveDirectoryW(cut_folder.c_str());
        RemoveDirectoryW(noise_folder.c_str());
    }
    delete_file(join(copy, DBIP_FILE_NAME));
    RemoveDirectoryW(copy.c_str());

    // the download refuses a location outside db-ip.com and anything that is not a city database; the old file stays
    std::wstring target_dir = temp_dir() + L"\\ddcore_dl_" + std::to_wstring(GetCurrentProcessId());
    make_dirs(target_dir);
    DbFetch wrong_host = [](const std::wstring&, const std::function<void(std::uint64_t, std::uint64_t)>&) {
        HttpResponse r;
        r.ok = true;
        r.status = 200;
        r.final_url = L"https://evil.example.net/file.gz";
        r.body = "x";
        return r;
    };
    bool threw = false;
    try {
        download_dbip(target_dir, nullptr, wrong_host);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw && !is_file(join(target_dir, DBIP_FILE_NAME)));
    DbFetch not_gzip = [](const std::wstring&, const std::function<void(std::uint64_t, std::uint64_t)>&) {
        HttpResponse r;
        r.ok = true;
        r.status = 200;
        r.final_url = L"https://download.db-ip.com/free/x.mmdb.gz";
        r.body = "plain text";
        return r;
    };
    threw = false;
    try {
        download_dbip(target_dir, nullptr, not_gzip);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw && !is_file(join(target_dir, DBIP_FILE_NAME)) && !is_file(join(target_dir, DBIP_FILE_NAME) + L".download"));
    RemoveDirectoryW(target_dir.c_str());
}

static ConnectionRow row(const wchar_t* direction, const wchar_t* addr, const wchar_t* country, const wchar_t* site, std::uint64_t rx, std::uint64_t tx) {
    ConnectionRow r;
    r.conn.protocol = L"TCP";
    r.conn.remote_addr = addr;
    r.direction = direction;
    r.remote_kind = L"Internet";
    r.country = country;
    r.site = site;
    r.received = rx;
    r.sent = tx;
    r.rate_in = (double)rx / 10;
    return r;
}

static void test_grouping() {
    TrafficSnapshot snap;
    AppTraffic browser;
    browser.process.pid = 100;
    browser.process.name = L"browser.exe";
    browser.process.description = L"Web Browser";
    browser.rows.push_back(row(L"Out", L"1.1.1.1", L"AU", L"one.one.one.one (+1 other names)", 100, 50));
    browser.rows.push_back(row(L"Out", L"1.0.0.1", L"AU", L"", 10, 5));
    browser.rows.push_back(row(L"In", L"8.8.8.8", L"US", L"dns.google", 1, 2));
    browser.rows.push_back(row(L"Listen", L"", L"", L"", 0, 0));
    ConnectionRow located = row(L"Out", L"8.8.4.4", L"", L"", 7, 7);   // no owner country, but a DB-IP location
    Location loc;
    loc.country = L"US";
    loc.city = L"Mountain View";
    loc.lat = 37.4;
    loc.lon = -122.1;
    located.location = loc;
    browser.rows.push_back(located);
    ConnectionRow unknown = row(L"Out", L"5.5.5.5", L"", L"", 0, 0);
    browser.rows.push_back(unknown);
    ConnectionRow lan = row(L"Out", L"192.168.1.9", L"", L"", 0, 0);
    lan.remote_kind = L"Local network";
    browser.rows.push_back(lan);
    snap.apps[100] = browser;
    AppTraffic idle;
    idle.process.pid = 0;
    idle.rows.push_back(row(L"Out", L"9.9.9.9", L"US", L"", 5, 5));
    snap.apps[0] = idle;   // the idle process is ignored

    int unlocated = 0;
    auto countries = by_country(snap, &unlocated);
    CHECK(countries.size() == 2 && unlocated == 1);
    CHECK(countries[L"AU"].outbound == 2 && countries[L"AU"].inbound == 0 && countries[L"AU"].received == 110 && countries[L"AU"].sent == 55);
    CHECK(countries[L"AU"].hosts.count(L"one.one.one.one") == 1 && countries[L"AU"].destinations.count(L"one.one.one.one") == 1);
    CHECK(countries[L"AU"].destinations.count(L"1.0.0.1") == 1);   // no site name: the address stands in
    CHECK(countries[L"US"].inbound == 1 && countries[L"US"].outbound == 1 && countries[L"US"].connections() == 2);
    CHECK(countries[L"US"].apps.count(L"Web Browser") == 1);

    auto places = by_place(snap);
    CHECK(places.size() == 3);   // AU (no database), US (no database), and the located city
    CHECK(places.count(L"country:AU") && !places[L"country:AU"].precise && !places[L"country:AU"].lat);
    CHECK(places.count(L"37.4,-122.1") && places[L"37.4,-122.1"].precise && places[L"37.4,-122.1"].label == L"Mountain View, US");
    CHECK(places[L"country:AU"].connections() == 2 && places[L"country:AU"].rate_in == 11);
}

static void test_real_traffic() {
    auto conns = list_connections();
    CHECK(!conns.empty());
    std::size_t listen = 0, established = 0;
    for (const auto& c : conns) {
        listen += c.state == L"Listen";
        established += c.state == L"Established";
        CHECK(c.local_port >= 0 && c.local_port <= 65535);
    }
    CHECK(listen > 0);
    auto names = process_names();
    CHECK(!names.empty() && names.count((int)GetCurrentProcessId()));
    CHECK(!process_path((int)GetCurrentProcessId()).empty());
    auto services = services_by_pid();
    CHECK(!services.empty());

    TrafficMonitor monitor(true, false, std::make_shared<DnsNames>([] { return std::vector<Json>{}; }), std::make_shared<OwnerLookup>([](const std::wstring&, Json&, std::wstring&) { return false; }, 1),
                           std::make_shared<GeoIP>(python_geoip_folder()));
    TrafficSnapshot first = monitor.sample();
    Sleep(1200);
    TrafficSnapshot second = monitor.sample();
    CHECK(!first.apps.empty() && !second.apps.empty());
    std::size_t rows = 0, internet = 0;
    for (const auto& [pid, app] : second.apps) {
        rows += app.rows.size();
        for (const auto& r : app.rows) internet += r.remote_kind == L"Internet" && (r.direction == L"In" || r.direction == L"Out");
    }
    int unlocated = 0;
    auto countries = by_country(second, &unlocated);
    std::printf("  machine: %zu connections (%zu established, %zu listening), %zu apps, %zu internet connections, %zu countries, %d unlocated, byte counters %s\n",
                conns.size(), established, listen, second.apps.size(), internet, countries.size(), unlocated, second.bytes_available ? "available" : "need administrator");
    monitor.close();
}

int run_traffic_tests() {
    set_world_data_file(join(project_root(), L"cpp\\data\\world_countries.json"));
    test_ip();
    test_dns_and_multicast();
    test_rdap();
    test_owner_lookup();
    test_gzip();
    test_world_and_geoip();
    test_grouping();
    test_real_traffic();
    std::printf("traffic/geoip: %d checks, %d failed\n", checks, failures);
    return failures;
}
