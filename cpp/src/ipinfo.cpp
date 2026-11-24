// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the lookup worker pool, the DNS name cache refresh and the owner tables for remote addresses.

#include <ddcore/ipinfo.hpp>

#include <algorithm>
#include <chrono>
#include <cstring>

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <ddcore/geoip.hpp>
#include <ddcore/net.hpp>
#include <ddcore/proc.hpp>

namespace dd {

namespace {

const wchar_t* BOOTSTRAP_V4 = L"https://data.iana.org/rdap/ipv4.json";
const wchar_t* BOOTSTRAP_V6 = L"https://data.iana.org/rdap/ipv6.json";
const std::size_t MAX_RESPONSE = 1024 * 1024;
const double RETRY_FAILED_AFTER = 600;

double monotonic_seconds() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

}  // namespace

// region WorkerPool

WorkerPool::WorkerPool(unsigned workers) {
    for (unsigned i = 0; i < std::max(1u, workers); ++i) {
        threads_.emplace_back([this] {
            for (;;) {
                std::function<void()> job;
                {
                    std::unique_lock<std::mutex> g(lock_);
                    wake_.wait(g, [this] { return stopping_ || !jobs_.empty(); });
                    if (stopping_) return;
                    job = std::move(jobs_.front());
                    jobs_.pop_front();
                }
                job();
            }
        });
    }
}

WorkerPool::~WorkerPool() { shutdown(); }

void WorkerPool::submit(std::function<void()> job) {
    {
        std::lock_guard<std::mutex> g(lock_);
        if (stopping_) return;
        jobs_.push_back(std::move(job));
    }
    wake_.notify_one();
}

void WorkerPool::shutdown() {
    {
        std::lock_guard<std::mutex> g(lock_);
        stopping_ = true;
        jobs_.clear();
    }
    wake_.notify_all();
    for (auto& t : threads_) {
        if (t.joinable()) t.join();
    }
    threads_.clear();
}

// endregion

bool is_public(const std::wstring& addr) {
    IpAddress ip;
    return parse_ip(addr, ip) && ip.is_global();
}

const std::map<std::wstring, std::wstring>& multicast_names() {
    static const std::map<std::wstring, std::wstring> m = {
        {L"224.0.0.251", L"mDNS (local discovery)"}, {L"ff02::fb", L"mDNS (local discovery)"},
        {L"239.255.255.250", L"SSDP / UPnP discovery"}, {L"ff02::c", L"SSDP / UPnP discovery"},
        {L"224.0.0.252", L"LLMNR (local name lookup)"}, {L"ff02::1:3", L"LLMNR (local name lookup)"},
        {L"255.255.255.255", L"Broadcast"}, {L"224.0.0.1", L"All hosts"}, {L"ff02::1", L"All hosts"}};
    return m;
}

// region DNS cache

DnsNames::DnsNames(Reader reader, double interval) : reader_(std::move(reader)), interval_(interval) {
    if (!reader_) {
        reader_ = [] {
            Json data = run_powershell_json(
                L"@(Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } "
                L"| ForEach-Object { [pscustomobject]@{ Entry = [string]$_.Entry; Data = [string]$_.Data } }) "
                L"| ConvertTo-Json -Compress",
                30000);
            return data.as_list();
        };
    }
}

void DnsNames::refresh(bool force) {
    double now = monotonic_seconds();
    {
        std::lock_guard<std::mutex> g(lock_);
        if (!force && now - last_ < interval_) return;
        last_ = now;
    }
    std::vector<Json> records = reader_();   // may take a while: the lock is not held
    std::lock_guard<std::mutex> g(lock_);
    for (const Json& rec : records) {
        std::wstring ip = lower(rec.get(L"Data").str()), name = lower(rec.get(L"Entry").str());
        while (!name.empty() && name.back() == L'.') name.pop_back();
        if (ip.empty() || name.empty()) continue;
        auto& list = names_[ip];
        if (std::find(list.begin(), list.end(), name) == list.end()) list.push_back(name);
    }
}

std::vector<std::wstring> DnsNames::names(const std::wstring& addr) const {
    std::lock_guard<std::mutex> g(lock_);
    auto it = names_.find(lower(addr.substr(0, addr.find(L'%'))));
    return it == names_.end() ? std::vector<std::wstring>{} : it->second;
}

// endregion

// region RDAP

std::wstring Owner::label() const {
    if (organization.empty()) return network;
    return country.empty() ? organization : organization + L" (" + country + L")";
}

namespace {

const std::vector<Json>& empty_items() {
    static const std::vector<Json> none;
    return none;
}

const Json& vcard_items(const Json& entity) {
    static const Json none;
    const Json& card = entity.get(L"vcardArray");
    return card.size() > 1 && card.at(1).is_array() ? card.at(1) : none;
}

std::wstring vcard_value(const Json& entity, const std::wstring& key) {
    for (const Json& item : vcard_items(entity).items()) {
        if (item.size() > 3 && item.at(0).str() == key && item.at(3).is_string()) return trim(item.at(3).str());
    }
    return L"";
}

std::wstring last_line(const std::wstring& text) {
    std::wstring t = trim(text);
    std::size_t nl = t.find_last_of(L'\n');
    return trim(nl == std::wstring::npos ? t : t.substr(nl + 1));
}

std::wstring first_line(const std::wstring& text) {
    std::wstring t = trim(text);
    std::size_t nl = t.find(L'\n');
    return trim(nl == std::wstring::npos ? t : t.substr(0, nl));
}

std::wstring vcard_country(const Json& entity) {
    for (const Json& item : vcard_items(entity).items()) {
        if (item.size() > 3 && item.at(0).str() == L"adr") {
            const Json& value = item.at(3);
            if (value.is_array() && value.size() > 6 && value.at(6).is_string() && !value.at(6).str().empty()) return trim(value.at(6).str());
            std::wstring label = item.at(1).is_object() ? item.at(1).get(L"label").str() : L"";
            if (!label.empty()) return last_line(label);
        }
    }
    return L"";
}

std::wstring address_first_line(const Json& entity) {
    for (const Json& item : vcard_items(entity).items()) {
        if (item.size() > 1 && item.at(0).str() == L"adr" && item.at(1).is_object() && !item.at(1).get(L"label").str().empty()) {
            return first_line(item.at(1).get(L"label").str());
        }
    }
    return L"";
}

void collect_entities(const Json& data, int depth, std::vector<Json>& out) {
    for (const Json& e : data.get(L"entities").as_list()) {
        out.push_back(e);
        if (depth < 2) collect_entities(e, depth + 1, out);
    }
}

bool has_role(const Json& entity, const std::wstring& role) {
    for (const Json& r : entity.get(L"roles").as_list()) {
        if (r.str() == role) return true;
    }
    return false;
}

}  // namespace

Owner parse_rdap(const Json& data, const std::wstring& registry) {
    Owner owner;
    owner.network = data.get(L"name").str();
    owner.registry = registry;
    if (!data.get(L"startAddress").str().empty()) owner.range = data.get(L"startAddress").str() + L" - " + data.get(L"endAddress").str();
    std::vector<Json> entities;
    collect_entities(data, 0, entities);
    std::vector<Json> registrants, orgs;
    for (const Json& e : entities) {
        if (has_role(e, L"registrant")) registrants.push_back(e);
    }
    for (const Json& e : registrants) {
        if (vcard_value(e, L"kind") == L"org") orgs.push_back(e);
    }
    if (!orgs.empty()) owner.organization = vcard_value(orgs[0], L"fn");
    if (owner.organization.empty()) {
        for (const Json& r : data.get(L"remarks").as_list()) {
            std::wstring text;
            for (const Json& d : r.get(L"description").as_list()) text += (text.empty() ? L"" : L" ") + d.str();
            text = trim(text);
            if (!text.empty() && text.size() <= 80 && text.find(L"CERTIFICATE") == std::wstring::npos) {
                owner.organization = text;
                break;
            }
        }
    }
    if (owner.organization.empty()) {
        for (const Json& e : entities) {
            if (has_role(e, L"administrative") || has_role(e, L"technical") || has_role(e, L"registrant")) {
                std::wstring line = address_first_line(e);
                if (!line.empty()) {
                    owner.organization = line;
                    break;
                }
            }
        }
    }
    std::wstring raw = data.get(L"country").str();
    if (raw.empty()) {
        std::vector<Json> all = orgs;
        all.insert(all.end(), registrants.begin(), registrants.end());
        all.insert(all.end(), entities.begin(), entities.end());
        for (const Json& e : all) {
            raw = vcard_country(e);
            if (!raw.empty()) break;
        }
    }
    std::wstring code;
    try {
        code = country_code(raw);
    } catch (const std::exception&) {
    }
    owner.country = !code.empty() ? code : (raw.size() == 2 ? raw : L"");   // always ISO 3166 alpha-2
    return owner;
}

std::vector<IpNetwork> answer_networks(const Json& data, const IpAddress& ip) {
    IpNetwork single;
    single.base = ip;
    single.prefix = ip.v6 ? 128 : 32;
    std::vector<IpNetwork> only_ip = {single};
    IpAddress start, end;
    if (!parse_ip(data.get(L"startAddress").str(), start) || !parse_ip(data.get(L"endAddress").str(), end)) return only_ip;
    if (start.v6 != ip.v6 || end.v6 != ip.v6 || !(start.value() <= ip.value() && ip.value() <= end.value())) return only_ip;
    std::vector<IpNetwork> networks = summarize_range(start, end);
    int min_prefix = ip.v6 ? 16 : 8;   // no registry allocates wider blocks to one organization
    if (networks.empty() || networks.size() > 64) return only_ip;
    for (const auto& n : networks) {
        if (n.prefix < min_prefix) return only_ip;
    }
    return networks;
}

bool fetch_rdap_json(const std::wstring& url, Json& data, std::wstring& final_url) {
    HttpRequest r;
    r.url = url;
    r.timeout_ms = 15000;
    r.max_bytes = MAX_RESPONSE;
    r.headers[L"Accept"] = L"application/rdap+json, application/json";
    r.headers[L"User-Agent"] = L"DDCleaner/3.0 (network monitor)";
    HttpResponse res = http_request(r);
    if (!res.ok || res.status != 200 || !starts_with(lower(res.final_url), L"https://")) return false;
    final_url = res.final_url;
    return try_parse_json(wide(res.body), data);
}

OwnerLookup::OwnerLookup(RdapFetch fetch, unsigned workers) : fetch_(fetch ? std::move(fetch) : RdapFetch(fetch_rdap_json)), pool_(workers) {}

OwnerLookup::~OwnerLookup() { shutdown(); }

void OwnerLookup::shutdown() { pool_.shutdown(); }

std::optional<Owner> OwnerLookup::cached(const std::wstring& addr) const {
    IpAddress ip;
    if (!parse_ip(addr, ip)) return std::nullopt;
    std::lock_guard<std::mutex> g(lock_);
    for (const auto& [net, owner] : networks_) {
        if (net.contains(ip)) return owner;
    }
    return std::nullopt;
}

std::optional<Owner> OwnerLookup::lookup(const std::wstring& addr) {
    if (!is_public(addr)) return std::nullopt;
    auto owner = cached(addr);
    if (owner || !enabled) return owner;
    {
        std::lock_guard<std::mutex> g(lock_);
        auto failed = failed_.find(addr);
        if (pending_.count(addr) || (failed != failed_.end() && monotonic_seconds() - failed->second < RETRY_FAILED_AFTER)) return std::nullopt;
        pending_.insert(addr);
    }
    pool_.submit([this, addr] { resolve(addr); });
    return std::nullopt;
}

std::optional<Owner> OwnerLookup::resolve_now(const std::wstring& addr) {
    if (!is_public(addr)) return std::nullopt;
    auto owner = cached(addr);
    if (!owner && enabled) {
        resolve(addr);
        owner = cached(addr);
    }
    return owner;
}

bool OwnerLookup::registry_url(const IpAddress& ip, std::wstring& base) {
    {
        std::lock_guard<std::mutex> g(lock_);
        if (bootstrap_.count(ip.version())) {
            for (const auto& [net, url] : bootstrap_[ip.version()]) {
                if (net.contains(ip)) {
                    base = url;
                    return true;
                }
            }
            return false;
        }
    }
    Json data;
    std::wstring final_url;
    if (!fetch_(ip.v6 ? BOOTSTRAP_V6 : BOOTSTRAP_V4, data, final_url)) throw std::runtime_error("bootstrap unavailable");
    std::vector<std::pair<IpNetwork, std::wstring>> entries;
    for (const Json& service : data.get(L"services").as_list()) {
        std::wstring chosen;
        for (const Json& u : service.at(1).as_list()) {
            if (starts_with(u.str(), L"https://")) {
                chosen = u.str();
                break;
            }
        }
        if (chosen.empty()) continue;
        for (const Json& p : service.at(0).as_list()) {
            IpNetwork n;
            if (parse_network(p.str(), n)) entries.emplace_back(n, chosen);
        }
    }
    std::stable_sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) { return a.first.prefix > b.first.prefix; });   // most specific first
    std::lock_guard<std::mutex> g(lock_);
    bootstrap_[ip.version()] = entries;
    for (const auto& [net, url] : entries) {
        if (net.contains(ip)) {
            base = url;
            return true;
        }
    }
    return false;
}

void OwnerLookup::resolve(const std::wstring& addr) {
    try {
        IpAddress ip;
        if (!parse_ip(addr, ip)) throw std::runtime_error("not an address");
        if (cached(addr)) {
            std::lock_guard<std::mutex> g(lock_);
            pending_.erase(addr);
            return;
        }
        std::wstring base;
        if (!registry_url(ip, base)) throw std::runtime_error("no registry for this address");
        while (!base.empty() && base.back() == L'/') base.pop_back();
        Json data;
        std::wstring final_url;
        if (!fetch_(base + L"/ip/" + ip.str(), data, final_url)) throw std::runtime_error("lookup failed");
        Owner owner = parse_rdap(data, url_host(final_url));
        auto networks = answer_networks(data, ip);
        std::lock_guard<std::mutex> g(lock_);
        for (const auto& n : networks) networks_.emplace_back(n, owner);
    } catch (const std::exception&) {
        std::lock_guard<std::mutex> g(lock_);
        failed_[addr] = monotonic_seconds();
    }
    std::lock_guard<std::mutex> g(lock_);
    pending_.erase(addr);
}

// endregion

// region Local network devices

std::map<std::wstring, std::wstring> arp_table() {
    std::map<std::wstring, std::wstring> out;
    ULONG size = 0;
    GetIpNetTable(nullptr, &size, FALSE);
    if (!size) return out;
    std::vector<unsigned char> buf(size + 1024);
    size = (ULONG)buf.size();
    if (GetIpNetTable(reinterpret_cast<PMIB_IPNETTABLE>(buf.data()), &size, FALSE) != NO_ERROR) return out;
    auto* table = reinterpret_cast<PMIB_IPNETTABLE>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_IPNETROW& r = table->table[i];
        if ((r.dwType != 3 && r.dwType != 4) || r.dwPhysAddrLen != 6) continue;   // dynamic / static entries
        wchar_t mac[32];
        swprintf(mac, 32, L"%02X-%02X-%02X-%02X-%02X-%02X", r.bPhysAddr[0], r.bPhysAddr[1], r.bPhysAddr[2], r.bPhysAddr[3], r.bPhysAddr[4], r.bPhysAddr[5]);
        std::wstring m = mac;
        if (m == L"FF-FF-FF-FF-FF-FF" || m == L"00-00-00-00-00-00" || starts_with(m, L"01-00-5E")) continue;
        IpAddress ip;
        std::memcpy(ip.bytes, &r.dwAddr, 4);
        out[ip.str()] = m;
    }
    return out;
}

std::set<std::wstring> default_gateways() {
    std::set<std::wstring> out;
    ULONG size = 0;
    GetIpForwardTable(nullptr, &size, FALSE);
    if (!size) return out;
    std::vector<unsigned char> buf(size + 4096);
    size = (ULONG)buf.size();
    if (GetIpForwardTable(reinterpret_cast<PMIB_IPFORWARDTABLE>(buf.data()), &size, FALSE) != NO_ERROR) return out;
    auto* table = reinterpret_cast<PMIB_IPFORWARDTABLE>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_IPFORWARDROW& r = table->table[i];
        if (r.dwForwardDest == 0 && r.dwForwardMask == 0 && r.dwForwardNextHop) {
            IpAddress ip;
            std::memcpy(ip.bytes, &r.dwForwardNextHop, 4);
            out.insert(ip.str());
        }
    }
    return out;
}

// endregion

}  // namespace dd
