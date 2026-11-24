// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the owner lookup of remote addresses: DNS cache names, RDAP owners and the worker pool that runs the lookups.

// Qui est derrière une adresse distante : noms DNS du cache Windows (session), propriétaire RDAP (registre choisi par bootstrap IANA, mis en cache par bloc réseau).
// Adresse MAC via la table ARP, noms de groupes multicast connus.
// Les recherches tournent en arrière-plan ; les méthodes de recherche ne bloquent jamais.
#pragma once

#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <ddcore/common.hpp>
#include <ddcore/ip.hpp>
#include <ddcore/json.hpp>

namespace dd {

// A few threads running queued jobs; pending jobs are dropped on destruction.
class WorkerPool {
public:
    explicit WorkerPool(unsigned workers);
    ~WorkerPool();
    WorkerPool(const WorkerPool&) = delete;
    WorkerPool& operator=(const WorkerPool&) = delete;
    void submit(std::function<void()> job);
    void shutdown();

private:
    std::vector<std::thread> threads_;
    std::deque<std::function<void()>> jobs_;
    std::mutex lock_;
    std::condition_variable wake_;
    bool stopping_ = false;
};

bool is_public(const std::wstring& addr);
const std::map<std::wstring, std::wstring>& multicast_names();

// region DNS cache
class DnsNames {
public:
    using Reader = std::function<std::vector<Json>()>;
    explicit DnsNames(Reader reader = nullptr, double interval_seconds = 15.0);
    void refresh(bool force = false);
    std::vector<std::wstring> names(const std::wstring& addr) const;

private:
    mutable std::mutex lock_;
    std::map<std::wstring, std::vector<std::wstring>> names_;
    Reader reader_;
    double interval_;
    double last_ = -1e9;
};
// endregion

// region RDAP owner lookup
struct Owner {
    std::wstring organization, country;
    std::wstring network;    // network name in the registry (e.g. GOGL)
    std::wstring range;      // "start - end"
    std::wstring registry;
    std::wstring label() const;
};

Owner parse_rdap(const Json& data, const std::wstring& registry = L"");
// The networks an RDAP answer may be cached for. A range that does not contain the queried address, mixes IP versions or is
// absurdly wide would label unrelated addresses with this owner (cache poisoning): only the queried address is cached then.
std::vector<IpNetwork> answer_networks(const Json& data, const IpAddress& ip);

using RdapFetch = std::function<bool(const std::wstring& url, Json& data, std::wstring& final_url)>;
bool fetch_rdap_json(const std::wstring& url, Json& data, std::wstring& final_url);   // https only, 1 MB at most

class OwnerLookup {
public:
    explicit OwnerLookup(RdapFetch fetch = nullptr, unsigned workers = 2);
    ~OwnerLookup();
    bool enabled = true;
    std::optional<Owner> cached(const std::wstring& addr) const;
    std::optional<Owner> lookup(const std::wstring& addr);        // cached owner, or nullopt while the background lookup runs
    std::optional<Owner> resolve_now(const std::wstring& addr);   // blocking (worker threads)
    void shutdown();

private:
    void resolve(const std::wstring& addr);
    bool registry_url(const IpAddress& ip, std::wstring& base);

    RdapFetch fetch_;
    std::map<int, std::vector<std::pair<IpNetwork, std::wstring>>> bootstrap_;
    std::vector<std::pair<IpNetwork, Owner>> networks_;
    std::map<std::wstring, double> failed_;
    std::set<std::wstring> pending_;
    mutable std::mutex lock_;
    WorkerPool pool_;
};
// endregion

// region Local network devices
std::map<std::wstring, std::wstring> arp_table();   // IPv4 -> MAC of devices the PC talked to on the local network
std::set<std::wstring> default_gateways();           // IPv4 default gateways
// endregion

}  // namespace dd
