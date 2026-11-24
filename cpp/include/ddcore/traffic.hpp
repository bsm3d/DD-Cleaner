// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares live traffic per application: TCP and UDP connections with their owning process, direction and byte counts.

// Live traffic per process (read-only): TCP/UDP owners via iphlpapi; inbound when the local port is one the process listens on.
// Byte counts per TCP connection need administrator rights and count from when the connection is first seen (since monitored).
#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include <ddcore/geoip.hpp>
#include <ddcore/ipinfo.hpp>

namespace dd {

// region Connections
constexpr int AF_V4 = 2, AF_V6 = 23;

struct Connection {
    std::wstring protocol;   // TCP / UDP
    int family = AF_V4;
    std::wstring local_addr;
    int local_port = 0;
    std::wstring remote_addr;   // "" for UDP
    int remote_port = 0;
    std::wstring state;          // "" for UDP
    int pid = 0;
    using Key = std::tuple<std::wstring, std::wstring, int, std::wstring, int, int>;
    Key key() const { return {protocol, local_addr, local_port, remote_addr, remote_port, pid}; }
};

std::vector<Connection> list_connections();
// In / Out / Listen / UDP. A connection on a port its own process listens on was accepted: inbound.
std::wstring direction(const Connection& conn, const std::set<std::pair<int, int>>& listening);
// "This PC" | "Local network" | "Multicast" | "Internet" | "" (unspecified or not an address)
std::wstring remote_kind(const std::wstring& addr);
// endregion

// region Processes and services
struct ProcessInfo {
    int pid = 0;
    std::wstring name, path, description;
    std::vector<std::wstring> services;
    std::wstring label() const;
};

std::map<int, std::wstring> process_names();   // pid -> exe name for every process (Toolhelp snapshot, no rights needed)
std::wstring process_path(int pid);
std::map<int, std::vector<std::wstring>> services_by_pid();

class ProcessResolver {
public:
    // Caches path and description per (pid, exe name) so a reused PID is not mixed up.
    std::map<int, ProcessInfo> refresh(const std::set<int>& pids);

private:
    std::wstring description(const std::wstring& path);
    std::map<std::pair<int, std::wstring>, ProcessInfo> cache_;
    std::map<std::wstring, std::wstring> descriptions_;
    std::map<int, std::vector<std::wstring>> services_;
    double services_time_ = -1e9;
};
// endregion

// region Byte counters (TCP extended statistics)
class ByteCounter {
public:
    bool available = true;   // false once Windows refuses (not administrator)
    // (bytes received, bytes sent), nullopt when not available for this connection
    std::optional<std::pair<std::uint64_t, std::uint64_t>> read(const Connection& conn);
    void forget(const std::set<Connection::Key>& alive);

private:
    std::set<Connection::Key> enabled_;
};
// endregion

// region Reverse DNS
class HostResolver {
public:
    explicit HostResolver(unsigned workers = 4);
    ~HostResolver();
    std::wstring lookup(const std::wstring& addr);   // never blocks: "" until the name is known
    void shutdown();

private:
    void resolve(const std::wstring& addr);
    std::map<std::wstring, std::wstring> names_;
    std::set<std::wstring> pending_;
    std::mutex lock_;
    WorkerPool pool_;
};
// endregion

// region Sampling
struct ConnectionRow {
    Connection conn;
    std::wstring direction;
    std::wstring remote_kind;
    std::wstring host;
    std::optional<std::uint64_t> received, sent;
    double rate_in = 0, rate_out = 0;
    std::wstring site;           // what the connection goes to: site name asked in DNS, host name, device...
    std::wstring owner;          // who runs that address: organization (country), or local device and its MAC
    std::wstring owner_detail;   // network name, address block, registry
    std::wstring country;        // ISO code of the owner's registration country
    std::optional<Location> location;   // where the server actually is (DB-IP), when the database is present
    std::wstring map_country() const;
};

struct AppTraffic {
    ProcessInfo process;
    std::vector<ConnectionRow> rows;
    std::uint64_t received = 0, sent = 0;   // including connections closed since monitoring started
    double rate_in = 0, rate_out = 0;
    int count(const std::wstring& kind) const;
    std::vector<std::wstring> ports() const;   // local ports it listens on or binds (UDP)
    int remote_hosts() const;
};

struct TrafficSnapshot {
    std::map<int, AppTraffic> apps;
    double time = 0;
    bool bytes_available = false;
    double total_rate_in = 0, total_rate_out = 0;
};

class TrafficMonitor {
public:
    explicit TrafficMonitor(bool resolve_hosts = true, bool lookup_owners = true, std::shared_ptr<DnsNames> dns = nullptr,
                            std::shared_ptr<OwnerLookup> owners = nullptr, std::shared_ptr<GeoIP> locator = nullptr);
    ~TrafficMonitor();
    TrafficSnapshot sample();
    void describe(ConnectionRow& row);   // fill site (where it goes / comes from) and owner (who is behind the address)
    void close();

    ProcessResolver processes;
    std::shared_ptr<GeoIP> geoip;
    ByteCounter counter;
    HostResolver hosts;
    std::shared_ptr<DnsNames> dns;
    std::shared_ptr<OwnerLookup> owners;
    bool resolve_hosts, lookup_owners;

private:
    void refresh_lookups(double now);
    std::map<std::wstring, std::wstring> arp_;
    std::set<std::wstring> gateways_;
    double local_time_ = -1e9;
    std::map<Connection::Key, std::pair<std::uint64_t, std::uint64_t>> last_;
    double last_time_ = -1;
    std::map<std::pair<int, std::wstring>, std::pair<std::uint64_t, std::uint64_t>> closed_;   // (pid, exe) -> closed connections' totals
};
// endregion

// region Per country / per place (world map)
struct CountryTraffic {
    std::wstring code;
    int outbound = 0, inbound = 0;
    std::set<std::wstring> apps, destinations;
    std::uint64_t received = 0, sent = 0;
    double rate_in = 0, rate_out = 0;
    std::set<std::wstring> addresses, hosts;
    int connections() const { return outbound + inbound; }
};

// Internet connections grouped by the owner's country, and how many are not located (yet).
std::map<std::wstring, CountryTraffic> by_country(const TrafficSnapshot& snap, int* unlocated = nullptr);

// Connections ending at one place: a city (DB-IP) or, without the database, a country.
struct PlaceTraffic {
    std::wstring key, label, country;
    std::optional<double> lat, lon;   // none: use the country's label point
    bool precise = false;
    int outbound = 0, inbound = 0;
    std::set<std::wstring> apps, destinations;
    std::uint64_t received = 0, sent = 0;
    double rate_in = 0, rate_out = 0;   // now, bytes per second (administrator only)
    std::set<std::wstring> addresses, hosts;
    int connections() const { return outbound + inbound; }
};
std::map<std::wstring, PlaceTraffic> by_place(const TrafficSnapshot& snap);
// endregion

}  // namespace dd
