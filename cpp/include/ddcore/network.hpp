// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the network statistics: adapter counters, TCP and UDP totals, connection states and listening ports with exposure.

#pragma once

#include <map>
#include <set>
#include <string>
#include <vector>

#include <ddcore/firewall.hpp>
#include <ddcore/json.hpp>
#include <ddcore/sysinfo.hpp>

namespace dd {

struct NetItem {
    Status status = Status::Ok;
    std::wstring title;
    std::vector<std::wstring> details;
    std::wstring category = L"Network";
};

using Counters = std::map<std::wstring, std::map<std::wstring, std::uint64_t>>;   // "tcp" / "udp" -> counter -> value

Counters protocol_counters();   // summed over IPv4 and IPv6 (iphlpapi, since boot)
std::wstring human_bytes(double n);
std::vector<NetItem> evaluate_adapters(const std::vector<Json>& adapters);
std::vector<NetItem> evaluate_protocols(const Counters& counters, const std::vector<Json>& states);
std::vector<Listener> parse_listeners(const std::vector<Json>& data);
std::map<std::wstring, std::wstring> address_profiles(const std::vector<Json>& adapters, const std::vector<Json>& networks);
std::set<std::wstring> listener_profiles(const Listener& listener, const std::map<std::wstring, std::wstring>& addr_profiles,
                                         const std::set<std::wstring>& active);

struct ListenerRow {
    Listener listener;
    Exposure exposure;
};

struct NetworkReport {
    std::vector<NetItem> items;
    std::vector<ListenerRow> listeners;
    std::wstring error;
};

NetworkReport run_network_analysis(const FirewallReport* firewall = nullptr, const Progress& progress = nullptr);

}  // namespace dd
