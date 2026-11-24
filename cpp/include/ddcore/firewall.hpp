// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the Windows Firewall analysis: profiles, rule statistics, risky rules and the reachability of listening ports.

// Lecture seule, sauf l'interrupteur explicite du journal des paquets rejetés.
// Accessibilité des ports en écoute : quelle règle, s'il y en a une, laisse entrer le trafic.
#pragma once

#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <ddcore/common.hpp>
#include <ddcore/json.hpp>
#include <ddcore/sysinfo.hpp>

namespace dd {

// region Rules
struct FirewallRule {
    std::wstring id, name;
    std::wstring action;      // Allow / Block
    std::wstring direction;   // In / Out
    bool active = false;
    std::wstring protocol;    // "6", "17"... "" = any
    std::set<std::wstring> profiles;   // empty = all profiles
    std::vector<std::wstring> local_ports, remote_addresses, local_addresses;
    std::wstring app;         // expanded, lower-case path; "system" for the kernel; "" = none
    std::wstring service;     // "" = none
    std::wstring package;     // UWP app container rules
    bool edge = false;
    std::wstring source;      // Local | Group Policy
    bool interface_limited = false;

    bool local_scope_limited() const { return !local_addresses.empty() || interface_limited; }
    bool applies_to_profile(const std::wstring& profile) const { return profiles.empty() || profiles.count(profile) > 0; }
    bool any_remote() const;
    std::wstring scope() const;
    bool is_windows_component() const;
};

extern const wchar_t* PROFILE_NAMES[3];   // Domain, Private, Public

std::wstring resolve_indirect(const std::wstring& text);   // '@firewallapi.dll,-50327' -> localized name
using IndirectResolver = std::function<std::wstring(const std::wstring&)>;
// One registry rule: 'v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=80|App=...|Name=...|'. False when it is not a rule.
bool parse_rule(const std::wstring& rule_id, const std::wstring& value, FirewallRule& out, const std::wstring& source = L"Local",
                const IndirectResolver& resolve = resolve_indirect);
std::vector<FirewallRule> read_rules();
bool port_matches(const std::vector<std::wstring>& ports, int port);
// endregion

// region Profiles
struct ProfileState {
    std::wstring name;
    bool enabled = false;
    std::wstring inbound, outbound;
    bool log_blocked = false;
    std::wstring log_file;
};

void parse_profiles(const Json& data, std::map<std::wstring, ProfileState>& profiles, std::vector<Json>& networks);
std::set<std::wstring> active_profiles(const std::vector<Json>& networks);
Json collect_profiles();
std::pair<bool, std::wstring> set_dropped_packet_logging(bool enabled);   // the only change this module makes
// endregion

// region Listening ports
struct Listener {
    std::wstring protocol;   // TCP / UDP
    std::wstring address;
    int port = 0;
    int pid = 0;
    std::wstring process, path;
    std::vector<std::wstring> services;
    bool loopback() const { return starts_with(address, L"127.") || address == L"::1"; }
};

struct Exposure {
    std::wstring level;   // open / limited / blocked / local
    std::wstring text, rule;
};

Exposure evaluate_exposure(const Listener& listener, const std::vector<FirewallRule>& rules,
                           const std::map<std::wstring, ProfileState>& profiles, const std::set<std::wstring>& active);
// endregion

// region Findings
struct Finding {
    Status status = Status::Ok;
    std::wstring title;
    std::vector<std::wstring> details;
};

std::map<std::wstring, int> rule_statistics(const std::vector<FirewallRule>& rules);
bool is_protected_path(const std::wstring& path);   // Program Files, Windows: standard users cannot write there
std::vector<Finding> evaluate_firewall(const std::vector<FirewallRule>& rules, const std::map<std::wstring, ProfileState>& profiles,
                                       const std::set<std::wstring>& active,
                                       const std::function<bool(const std::wstring&)>& path_exists = [](const std::wstring& p) { return exists(p); });
// endregion

// region Blocked traffic log
using CounterMap = std::map<std::wstring, long long>;
std::vector<std::pair<std::wstring, long long>> most_common(const CounterMap& counter, std::size_t limit = (std::size_t)-1);

struct LogStats {
    std::vector<std::wstring> files;
    long long lines = 0;
    std::wstring first, last;
    std::map<std::pair<std::wstring, std::wstring>, long long> by_action;   // (action, direction)
    CounterMap inbound_sources, inbound_ports, outbound_targets, per_day, processes;
    std::map<std::wstring, std::wstring> source_owners;                      // remote IP -> owner, filled by the caller
    long long dropped() const;
};

void parse_log_lines(const std::vector<std::wstring>& lines, LogStats& stats);
bool read_log(const std::wstring& path, LogStats& stats);   // the log and its rotated '.old' copy; false when no log exists yet
std::wstring describe_port(const std::wstring& key);        // "TCP 445" -> "TCP 445 (SMB file sharing)"
// endregion

struct FirewallReport {
    std::map<std::wstring, ProfileState> profiles;
    std::vector<Json> networks;
    std::set<std::wstring> active;
    std::vector<FirewallRule> rules;
    std::map<std::wstring, int> stats;
    std::vector<Finding> findings;
    bool has_log = false;
    LogStats log;
    bool log_enabled = false;
    std::wstring log_path;
};

FirewallReport run_firewall_analysis(const Progress& progress = nullptr);

}  // namespace dd
