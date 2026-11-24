// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements live traffic: TCP state names, port decoding and the byte counter that groups connections per application.

#include <ddcore/traffic.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tcpestats.h>
#include <tlhelp32.h>

#include <ddcore/inspect.hpp>

namespace dd {

namespace {

double monotonic_seconds() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

int port_of(DWORD dw) { return ntohs((u_short)(dw & 0xFFFF)); }

std::wstring v4_text(DWORD addr) {
    IpAddress ip;
    std::memcpy(ip.bytes, &addr, 4);
    return ip.str();
}

std::wstring v6_text(const UCHAR* raw) {
    IpAddress ip;
    ip.v6 = true;
    std::memcpy(ip.bytes, raw, 16);
    return ip.str();
}

const wchar_t* tcp_state(DWORD s) {
    static const wchar_t* names[] = {L"", L"Closed", L"Listen", L"SynSent", L"SynReceived", L"Established", L"FinWait1",
                                     L"FinWait2", L"CloseWait", L"Closing", L"LastAck", L"TimeWait", L"DeleteTcb"};
    return s >= 1 && s <= 12 ? names[s] : L"";
}

std::wstring state_text(DWORD s) { return s >= 1 && s <= 12 ? std::wstring(tcp_state(s)) : std::to_wstring(s); }

// The table can grow between the two calls: retry with a little room.
std::vector<unsigned char> table(const std::function<DWORD(void*, PDWORD)>& call) {
    DWORD size = 0;
    std::vector<unsigned char> buf;
    for (int attempt = 0; attempt < 5; ++attempt) {
        buf.assign(size ? size : 16, 0);
        DWORD err = call(buf.data(), &size);
        if (err == NO_ERROR) return buf;
        if (err != ERROR_INSUFFICIENT_BUFFER) return {};
        size += 4096;
    }
    return {};
}

}  // namespace

std::vector<Connection> list_connections() {
    std::vector<Connection> out;
    auto tcp4 = table([](void* p, PDWORD n) { return GetExtendedTcpTable(p, n, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0); });
    if (!tcp4.empty()) {
        auto* t = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(tcp4.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            const auto& r = t->table[i];
            out.push_back({L"TCP", AF_V4, v4_text(r.dwLocalAddr), port_of(r.dwLocalPort), v4_text(r.dwRemoteAddr), port_of(r.dwRemotePort),
                           state_text(r.dwState), (int)r.dwOwningPid});
        }
    }
    auto tcp6 = table([](void* p, PDWORD n) { return GetExtendedTcpTable(p, n, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0); });
    if (!tcp6.empty()) {
        auto* t = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(tcp6.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            const auto& r = t->table[i];
            out.push_back({L"TCP", AF_V6, v6_text(r.ucLocalAddr), port_of(r.dwLocalPort), v6_text(r.ucRemoteAddr), port_of(r.dwRemotePort),
                           state_text(r.dwState), (int)r.dwOwningPid});
        }
    }
    auto udp4 = table([](void* p, PDWORD n) { return GetExtendedUdpTable(p, n, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0); });
    if (!udp4.empty()) {
        auto* t = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(udp4.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            const auto& r = t->table[i];
            out.push_back({L"UDP", AF_V4, v4_text(r.dwLocalAddr), port_of(r.dwLocalPort), L"", 0, L"", (int)r.dwOwningPid});
        }
    }
    auto udp6 = table([](void* p, PDWORD n) { return GetExtendedUdpTable(p, n, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0); });
    if (!udp6.empty()) {
        auto* t = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(udp6.data());
        for (DWORD i = 0; i < t->dwNumEntries; ++i) {
            const auto& r = t->table[i];
            out.push_back({L"UDP", AF_V6, v6_text(r.ucLocalAddr), port_of(r.dwLocalPort), L"", 0, L"", (int)r.dwOwningPid});
        }
    }
    return out;
}

std::wstring direction(const Connection& conn, const std::set<std::pair<int, int>>& listening) {
    if (conn.protocol == L"UDP") return L"UDP";
    if (conn.state == L"Listen") return L"Listen";
    return listening.count({conn.pid, conn.local_port}) ? L"In" : L"Out";
}

std::wstring remote_kind(const std::wstring& addr) {
    if (addr.empty()) return L"";
    IpAddress ip;
    if (!parse_ip(addr, ip) || ip.is_unspecified()) return L"";
    if (ip.is_loopback()) return L"This PC";
    if (ip.is_private() || ip.is_link_local()) return L"Local network";
    if (ip.is_multicast()) return L"Multicast";
    return L"Internet";
}

// region Processes and services

std::wstring ProcessInfo::label() const {
    if (pid == 0) return L"System Idle (closed connections)";
    if (pid == 4) return L"System (Windows kernel)";
    std::wstring base = !description.empty() ? description : !name.empty() ? name : L"PID " + std::to_wstring(pid);
    if (services.empty()) return base;
    std::wstring list;
    for (std::size_t i = 0; i < services.size() && i < 3; ++i) list += (i ? L", " : L"") + services[i];
    return base + L" [" + list + (services.size() > 3 ? L"..." : L"") + L"]";
}

std::map<int, std::wstring> process_names() {
    std::map<int, std::wstring> names;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return names;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL ok = Process32FirstW(snap, &entry); ok; ok = Process32NextW(snap, &entry)) names[(int)entry.th32ProcessID] = entry.szExeFile;
    CloseHandle(snap);
    return names;
}

std::wstring process_path(int pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) return L"";
    wchar_t buf[1024];
    DWORD size = 1024;
    std::wstring path = QueryFullProcessImageNameW(h, 0, buf, &size) ? std::wstring(buf, size) : L"";
    CloseHandle(h);
    return path;
}

std::map<int, std::vector<std::wstring>> services_by_pid() {
    std::map<int, std::vector<std::wstring>> result;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return result;
    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, nullptr, 0, &needed, &count, &resume, nullptr);
    std::vector<unsigned char> buf(needed + 4096);
    resume = 0;
    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, buf.data(), (DWORD)buf.size(), &needed, &count, &resume, nullptr)) {
        auto* entries = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        for (DWORD i = 0; i < count; ++i) {
            int pid = (int)entries[i].ServiceStatusProcess.dwProcessId;
            if (pid) result[pid].push_back(entries[i].lpServiceName);
        }
    }
    CloseServiceHandle(scm);
    return result;
}

std::wstring ProcessResolver::description(const std::wstring& path) {
    if (path.empty()) return L"";
    auto it = descriptions_.find(path);
    if (it != descriptions_.end()) return it->second;
    PEInfo info = inspect_pe(path);
    auto d = info.strings.find(L"FileDescription");
    return descriptions_[path] = d == info.strings.end() ? L"" : d->second;
}

std::map<int, ProcessInfo> ProcessResolver::refresh(const std::set<int>& pids) {
    auto names = process_names();
    double now = monotonic_seconds();
    if (now - services_time_ > 30) {
        services_ = services_by_pid();
        services_time_ = now;
    }
    std::map<int, ProcessInfo> out;
    for (int pid : pids) {
        auto n = names.find(pid);
        std::wstring name = n == names.end() ? L"" : n->second;
        auto key = std::make_pair(pid, name);
        auto it = cache_.find(key);
        if (it == cache_.end()) {
            ProcessInfo info;
            info.pid = pid;
            info.name = name;
            info.path = pid > 4 ? process_path(pid) : L"";
            info.description = description(info.path);
            it = cache_.emplace(key, std::move(info)).first;
        }
        auto s = services_.find(pid);
        it->second.services = s == services_.end() ? std::vector<std::wstring>{} : s->second;
        out[pid] = it->second;
    }
    return out;
}

// endregion

// region Byte counters

std::optional<std::pair<std::uint64_t, std::uint64_t>> ByteCounter::read(const Connection& conn) {
    if (!available || conn.protocol != L"TCP" || conn.state != L"Established") return std::nullopt;
    bool v6 = conn.family == AF_V6;
    MIB_TCPROW row4{};
    MIB_TCP6ROW row6{};
    void* row;
    if (!v6) {
        IpAddress local, remote;
        if (!parse_ip(conn.local_addr, local) || !parse_ip(conn.remote_addr, remote)) return std::nullopt;
        row4.dwState = MIB_TCP_STATE_ESTAB;
        std::memcpy(&row4.dwLocalAddr, local.bytes, 4);
        std::memcpy(&row4.dwRemoteAddr, remote.bytes, 4);
        row4.dwLocalPort = htons((u_short)conn.local_port);
        row4.dwRemotePort = htons((u_short)conn.remote_port);
        row = &row4;
    } else {
        IpAddress local, remote;
        if (!parse_ip(conn.local_addr, local) || !parse_ip(conn.remote_addr, remote)) return std::nullopt;
        row6.State = MIB_TCP_STATE_ESTAB;
        std::memcpy(&row6.LocalAddr, local.bytes, 16);
        std::memcpy(&row6.RemoteAddr, remote.bytes, 16);
        row6.dwLocalPort = htons((u_short)conn.local_port);
        row6.dwRemotePort = htons((u_short)conn.remote_port);
        row = &row6;
    }
    if (!enabled_.count(conn.key())) {
        TCP_ESTATS_DATA_RW_v0 rw{};
        rw.EnableCollection = TRUE;
        ULONG err = v6 ? SetPerTcp6ConnectionEStats(static_cast<PMIB_TCP6ROW>(row), TcpConnectionEstatsData, reinterpret_cast<PUCHAR>(&rw), 0, sizeof(rw), 0)
                       : SetPerTcpConnectionEStats(static_cast<PMIB_TCPROW>(row), TcpConnectionEstatsData, reinterpret_cast<PUCHAR>(&rw), 0, sizeof(rw), 0);
        if (err == ERROR_ACCESS_DENIED) {
            available = false;
            return std::nullopt;
        }
        if (err) return std::nullopt;
        enabled_.insert(conn.key());
    }
    TCP_ESTATS_DATA_ROD_v0 rod{};
    ULONG err = v6 ? GetPerTcp6ConnectionEStats(static_cast<PMIB_TCP6ROW>(row), TcpConnectionEstatsData, nullptr, 0, 0, nullptr, 0, 0,
                                                reinterpret_cast<PUCHAR>(&rod), 0, sizeof(rod))
                   : GetPerTcpConnectionEStats(static_cast<PMIB_TCPROW>(row), TcpConnectionEstatsData, nullptr, 0, 0, nullptr, 0, 0,
                                               reinterpret_cast<PUCHAR>(&rod), 0, sizeof(rod));
    if (err) return std::nullopt;
    return std::make_pair((std::uint64_t)rod.DataBytesIn, (std::uint64_t)rod.DataBytesOut);
}

void ByteCounter::forget(const std::set<Connection::Key>& alive) {
    std::set<Connection::Key> kept;
    for (const auto& k : enabled_) {
        if (alive.count(k)) kept.insert(k);
    }
    enabled_ = std::move(kept);
}

// endregion

// region Reverse DNS

namespace {
struct WinsockInit {
    WinsockInit() {
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
    }
};
}  // namespace

HostResolver::HostResolver(unsigned workers) : pool_(workers) { static WinsockInit init; }

HostResolver::~HostResolver() { shutdown(); }

void HostResolver::shutdown() { pool_.shutdown(); }

std::wstring HostResolver::lookup(const std::wstring& addr) {
    std::wstring kind = remote_kind(addr);
    if (addr.empty() || kind.empty() || kind == L"This PC" || kind == L"Multicast") return L"";
    {
        std::lock_guard<std::mutex> g(lock_);
        auto it = names_.find(addr);
        if (it != names_.end()) return it->second;
        if (!pending_.insert(addr).second) return L"";
    }
    pool_.submit([this, addr] { resolve(addr); });
    return L"";
}

void HostResolver::resolve(const std::wstring& addr) {
    std::wstring name;
    IpAddress ip;
    if (parse_ip(addr, ip)) {
        char host[NI_MAXHOST] = {0};
        int rc;
        if (!ip.v6) {
            sockaddr_in sa{};
            sa.sin_family = AF_INET;
            std::memcpy(&sa.sin_addr, ip.bytes, 4);
            rc = getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), host, sizeof(host), nullptr, 0, NI_NAMEREQD);
        } else {
            sockaddr_in6 sa{};
            sa.sin6_family = AF_INET6;
            std::memcpy(&sa.sin6_addr, ip.bytes, 16);
            rc = getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), host, sizeof(host), nullptr, 0, NI_NAMEREQD);
        }
        if (rc == 0) name = wide(host);
    }
    std::lock_guard<std::mutex> g(lock_);
    names_[addr] = name;
    pending_.erase(addr);
}

// endregion

// region Sampling

std::wstring ConnectionRow::map_country() const { return location && !location->country.empty() ? location->country : country; }

int AppTraffic::count(const std::wstring& kind) const {
    int n = 0;
    for (const auto& r : rows) n += r.direction == kind;
    return n;
}

std::vector<std::wstring> AppTraffic::ports() const {
    std::set<std::pair<std::wstring, int>> unique;
    for (const auto& r : rows) {
        if (r.direction == L"Listen" || r.direction == L"UDP") unique.insert({r.conn.protocol, r.conn.local_port});
    }
    std::vector<std::wstring> out;
    for (const auto& [proto, port] : unique) out.push_back(proto + L" " + std::to_wstring(port));
    return out;
}

int AppTraffic::remote_hosts() const {
    std::set<std::wstring> hosts;
    for (const auto& r : rows) {
        if (r.direction == L"In" || r.direction == L"Out") hosts.insert(r.conn.remote_addr);
    }
    return (int)hosts.size();
}

TrafficMonitor::TrafficMonitor(bool resolve, bool lookup, std::shared_ptr<DnsNames> dns_in, std::shared_ptr<OwnerLookup> owners_in,
                               std::shared_ptr<GeoIP> locator)
    : geoip(locator ? locator : std::make_shared<GeoIP>()),
      dns(dns_in ? dns_in : std::make_shared<DnsNames>()),
      owners(owners_in ? owners_in : std::make_shared<OwnerLookup>()),
      resolve_hosts(resolve),
      lookup_owners(lookup) {}

TrafficMonitor::~TrafficMonitor() { close(); }

void TrafficMonitor::close() {
    hosts.shutdown();
    owners->shutdown();
    geoip->close();
}

void TrafficMonitor::refresh_lookups(double now) {
    try {
        dns->refresh();
    } catch (const std::exception&) {
    }
    if (now - local_time_ > 10) {
        local_time_ = now;
        arp_ = arp_table();
        gateways_ = default_gateways();
    }
    owners->enabled = lookup_owners;
}

void TrafficMonitor::describe(ConnectionRow& row) {
    std::wstring addr = row.conn.remote_addr.substr(0, row.conn.remote_addr.find(L'%'));
    const std::wstring& kind = row.remote_kind;
    if (kind == L"This PC") {
        row.site = L"this PC";
    } else if (kind == L"Multicast") {
        auto it = multicast_names().find(lower(addr));
        row.site = it == multicast_names().end() ? L"multicast group" : it->second;
    } else if (kind == L"Local network") {
        auto mac = arp_.find(addr);
        if (gateways_.count(addr)) row.site = L"Router / Internet box" + (row.host.empty() ? L"" : L" (" + row.host + L")");
        else row.site = row.host.empty() ? L"device on the local network" : row.host;
        row.owner = mac != arp_.end() ? L"Local device, MAC " + mac->second : L"Local device";
    } else if (kind == L"Internet") {
        auto names = dns->names(addr);
        if (!names.empty()) row.site = names[0] + (names.size() > 1 ? L" (+" + std::to_wstring(names.size() - 1) + L" other names)" : L"");
        else row.site = row.host;
        row.location = geoip->locate(addr);
        auto owner = owners->lookup(addr);
        if (owner) {
            row.owner = owner->label();
            row.country = owner->country;
            row.owner_detail = L"Network " + owner->network + L", " + owner->range + L", registry " + owner->registry;
        } else if (lookup_owners) {
            row.owner = L"looking up...";
        }
    }
}

TrafficSnapshot TrafficMonitor::sample() {
    double now = monotonic_seconds();
    std::vector<Connection> conns = list_connections();
    std::set<std::pair<int, int>> listening;
    std::set<int> pids;
    for (const auto& c : conns) {
        if (c.state == L"Listen") listening.insert({c.pid, c.local_port});
        pids.insert(c.pid);
    }
    auto procs = processes.refresh(pids);
    double elapsed = last_time_ > 0 ? now - last_time_ : 0.0;
    refresh_lookups(now);

    TrafficSnapshot snap;
    std::map<Connection::Key, std::pair<std::uint64_t, std::uint64_t>> current;
    for (const auto& c : conns) {
        ConnectionRow row;
        row.conn = c;
        row.direction = direction(c, listening);
        row.remote_kind = remote_kind(c.remote_addr);
        if (row.direction == L"In" || row.direction == L"Out") {
            if (resolve_hosts) row.host = hosts.lookup(c.remote_addr);
            describe(row);
        }
        auto counts = counter.read(c);
        if (counts) {
            row.received = counts->first;
            row.sent = counts->second;
            current[c.key()] = *counts;
            auto prev = last_.find(c.key());
            if (prev != last_.end() && elapsed > 0) {
                row.rate_in = (double)(counts->first >= prev->second.first ? counts->first - prev->second.first : 0) / elapsed;
                row.rate_out = (double)(counts->second >= prev->second.second ? counts->second - prev->second.second : 0) / elapsed;
            }
        }
        auto app = snap.apps.find(c.pid);
        if (app == snap.apps.end()) {
            AppTraffic fresh;
            auto p = procs.find(c.pid);
            if (p != procs.end()) fresh.process = p->second;
            else fresh.process.pid = c.pid;
            app = snap.apps.emplace(c.pid, std::move(fresh)).first;
        }
        app->second.rows.push_back(std::move(row));
    }

    // connections that disappeared keep counting in their application's totals
    for (const auto& [key, bytes] : last_) {
        if (current.count(key)) continue;
        int pid = std::get<5>(key);
        auto p = procs.find(pid);
        auto& closed = closed_[{pid, p == procs.end() ? L"" : p->second.name}];
        closed.first += bytes.first;
        closed.second += bytes.second;
    }
    std::set<Connection::Key> alive;
    for (const auto& kv : current) alive.insert(kv.first);
    counter.forget(alive);
    last_ = std::move(current);
    last_time_ = now;

    snap.time = now;
    snap.bytes_available = counter.available;
    for (auto& [pid, app] : snap.apps) {
        auto closed = closed_.find({pid, app.process.name});
        std::uint64_t rx = closed == closed_.end() ? 0 : closed->second.first, tx = closed == closed_.end() ? 0 : closed->second.second;
        for (const auto& r : app.rows) {
            rx += r.received.value_or(0);
            tx += r.sent.value_or(0);
            app.rate_in += r.rate_in;
            app.rate_out += r.rate_out;
        }
        app.received = rx;
        app.sent = tx;
        snap.total_rate_in += app.rate_in;
        snap.total_rate_out += app.rate_out;
    }
    return snap;
}

// endregion

// region Per country / per place

static std::wstring site_name(const ConnectionRow& r) {
    std::wstring site = r.site.substr(0, r.site.find(L" (+"));
    if (!site.empty()) return site;
    return !r.owner.empty() ? r.owner : r.conn.remote_addr;
}

std::map<std::wstring, CountryTraffic> by_country(const TrafficSnapshot& snap, int* unlocated_out) {
    std::map<std::wstring, CountryTraffic> countries;
    int unlocated = 0;
    for (const auto& [pid, app] : snap.apps) {
        if (pid == 0) continue;
        for (const auto& r : app.rows) {
            if ((r.direction != L"In" && r.direction != L"Out") || r.remote_kind != L"Internet") continue;
            std::wstring country = r.map_country();
            if (country.empty()) {
                ++unlocated;
                continue;
            }
            CountryTraffic& ct = countries.try_emplace(country, CountryTraffic{country}).first->second;
            if (r.direction == L"In") ++ct.inbound;
            else ++ct.outbound;
            ct.apps.insert(app.process.label());
            ct.destinations.insert(site_name(r));
            ct.received += r.received.value_or(0);
            ct.sent += r.sent.value_or(0);
            ct.rate_in += r.rate_in;
            ct.rate_out += r.rate_out;
            ct.addresses.insert(r.conn.remote_addr);
            if (!r.site.empty()) ct.hosts.insert(r.site.substr(0, r.site.find(L" (+")));
        }
    }
    if (unlocated_out) *unlocated_out = unlocated;
    return countries;
}

std::map<std::wstring, PlaceTraffic> by_place(const TrafficSnapshot& snap) {
    std::map<std::wstring, PlaceTraffic> places;
    for (const auto& [pid, app] : snap.apps) {
        if (pid == 0) continue;
        for (const auto& r : app.rows) {
            if ((r.direction != L"In" && r.direction != L"Out") || r.remote_kind != L"Internet" || r.map_country().empty()) continue;
            PlaceTraffic* place;
            if (r.location) {
                wchar_t key[64];
                swprintf(key, 64, L"%.1f,%.1f", std::round(r.location->lat * 10) / 10, std::round(r.location->lon * 10) / 10);
                auto it = places.find(key);
                if (it == places.end()) {
                    PlaceTraffic p;
                    p.key = key;
                    p.label = r.location->label().empty() ? r.location->country : r.location->label();
                    p.country = r.location->country;
                    p.lat = r.location->lat;
                    p.lon = r.location->lon;
                    p.precise = true;
                    it = places.emplace(key, std::move(p)).first;
                }
                place = &it->second;
            } else {
                std::wstring key = L"country:" + r.country;
                auto it = places.find(key);
                if (it == places.end()) {
                    PlaceTraffic p;
                    p.key = key;
                    p.label = r.country;
                    p.country = r.country;
                    it = places.emplace(key, std::move(p)).first;
                }
                place = &it->second;
            }
            if (r.direction == L"In") ++place->inbound;
            else ++place->outbound;
            place->apps.insert(app.process.label());
            place->destinations.insert(site_name(r));
            place->received += r.received.value_or(0);
            place->sent += r.sent.value_or(0);
            place->rate_in += r.rate_in;
            place->rate_out += r.rate_out;
            place->addresses.insert(r.conn.remote_addr);
            if (!r.site.empty()) place->hosts.insert(r.site.substr(0, r.site.find(L" (+")));
        }
    }
    return places;
}

// endregion

}  // namespace dd
