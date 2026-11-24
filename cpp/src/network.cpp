// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the network statistics: the owner lookup of connections through PowerShell and the counter formatting.

#include <ddcore/network.hpp>

#include <algorithm>
#include <cmath>
#include <cstdarg>
#include <tuple>

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <ddcore/proc.hpp>

namespace dd {

namespace {

std::wstring fmt(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    int n = _vscwprintf(format, copy);
    va_end(copy);
    std::wstring out;
    if (n > 0) {
        out.resize((std::size_t)n + 1);
        vswprintf(out.data(), out.size(), format, args);
        out.resize((std::size_t)n);
    }
    va_end(args);
    return out;
}

std::wstring join_list(const std::vector<Json>& items, const wchar_t* separator = L", ") {
    std::wstring out;
    for (std::size_t i = 0; i < items.size(); ++i) out += (i ? separator : L"") + items[i].str();
    return out;
}

const wchar_t* NETWORK_PS = LR"J(
$ip = @{}
foreach ($c in @(Get-NetIPConfiguration -ErrorAction SilentlyContinue)) { $ip[[int]$c.InterfaceIndex] = $c }
$stats = @{}
foreach ($s in @(Get-NetAdapterStatistics -ErrorAction SilentlyContinue)) { $stats[[string]$s.Name] = $s }
$adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
  $s = $stats[[string]$_.Name]; $c = $ip[[int]$_.ifIndex]
  [pscustomobject]@{ Name = $_.Name; Description = $_.InterfaceDescription; Status = [string]$_.Status;
    LinkSpeed = [string]$_.LinkSpeed; Mac = $_.MacAddress; Virtual = [bool]$_.Virtual;
    ReceivedBytes = [int64]$s.ReceivedBytes; SentBytes = [int64]$s.SentBytes;
    ReceivedPackets = [int64]($s.ReceivedUnicastPackets + $s.ReceivedMulticastPackets + $s.ReceivedBroadcastPackets);
    SentPackets = [int64]($s.SentUnicastPackets + $s.SentMulticastPackets + $s.SentBroadcastPackets);
    ReceivedErrors = [int64]$s.ReceivedPacketErrors; ReceivedDiscards = [int64]$s.ReceivedDiscardedPackets;
    SentErrors = [int64]$s.OutboundPacketErrors; SentDiscards = [int64]$s.OutboundDiscardedPackets;
    IPv4 = @($c.IPv4Address | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" });
    Gateway = @($c.IPv4DefaultGateway | ForEach-Object { [string]$_.NextHop });
    DNS = @($c.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses }) }
})
$procs = @{}
foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
  $path = ''; try { $path = [string]$p.Path } catch {}
  $procs[[int]$p.Id] = [pscustomobject]@{ Name = $p.ProcessName; Path = $path }
}
$svc = @{}
foreach ($s in @(Get-CimInstance Win32_Service -Filter "State='Running'" -ErrorAction SilentlyContinue)) {
  $k = [int]$s.ProcessId; if (-not $svc.ContainsKey($k)) { $svc[$k] = @() }; $svc[$k] += [string]$s.Name
}
function Owner([int]$procId) {
  $p = $procs[$procId]
  [pscustomobject]@{ Name = $(if ($p) { $p.Name } else { '' }); Path = $(if ($p) { $p.Path } else { '' });
    Services = $(if ($svc.ContainsKey($procId)) { @($svc[$procId]) } else { @() }) }
}
$listeners = @()
foreach ($t in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
  $listeners += [pscustomobject]@{ Protocol = 'TCP'; Address = [string]$t.LocalAddress; Port = [int]$t.LocalPort;
    Pid = [int]$t.OwningProcess; Owner = (Owner $t.OwningProcess) }
}
foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
  $listeners += [pscustomobject]@{ Protocol = 'UDP'; Address = [string]$u.LocalAddress; Port = [int]$u.LocalPort;
    Pid = [int]$u.OwningProcess; Owner = (Owner $u.OwningProcess) }
}
$states = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Group-Object { [string]$_.State } |
  ForEach-Object { [pscustomobject]@{ State = $_.Name; Count = $_.Count } })
[pscustomobject]@{ adapters = $adapters; listeners = $listeners; tcp_states = $states } |
  ConvertTo-Json -Depth 5 -Compress
)J";

}  // namespace

Counters protocol_counters() {
    Counters result;
    for (ULONG family : {(ULONG)AF_INET, (ULONG)AF_INET6}) {
        MIB_TCPSTATS t{};
        if (GetTcpStatisticsEx(&t, family) == NO_ERROR) {
            auto& tcp = result[L"tcp"];
            tcp[L"ActiveOpens"] += t.dwActiveOpens;
            tcp[L"PassiveOpens"] += t.dwPassiveOpens;
            tcp[L"AttemptFails"] += t.dwAttemptFails;
            tcp[L"EstabResets"] += t.dwEstabResets;
            tcp[L"CurrEstab"] += t.dwCurrEstab;
            tcp[L"InSegs"] += t.dwInSegs;
            tcp[L"OutSegs"] += t.dwOutSegs;
            tcp[L"RetransSegs"] += t.dwRetransSegs;
            tcp[L"InErrs"] += t.dwInErrs;
            tcp[L"OutRsts"] += t.dwOutRsts;
            tcp[L"NumConns"] += t.dwNumConns;
        }
        MIB_UDPSTATS u{};
        if (GetUdpStatisticsEx(&u, family) == NO_ERROR) {
            auto& udp = result[L"udp"];
            udp[L"InDatagrams"] += u.dwInDatagrams;
            udp[L"NoPorts"] += u.dwNoPorts;
            udp[L"InErrors"] += u.dwInErrors;
            udp[L"OutDatagrams"] += u.dwOutDatagrams;
            udp[L"NumAddrs"] += u.dwNumAddrs;
        }
    }
    return result;
}

std::wstring human_bytes(double n) {
    const wchar_t* units[] = {L"B", L"KB", L"MB", L"GB", L"TB"};
    for (int i = 0; i < 5; ++i) {
        if (std::fabs(n) < 1024 || i == 4) return i == 0 ? fmt(L"%d B", (int)n) : fmt(L"%.1f %ls", n, units[i]);
        n /= 1024;
    }
    return fmt(L"%.1f TB", n);
}

std::vector<NetItem> evaluate_adapters(const std::vector<Json>& adapters) {
    std::vector<NetItem> items;
    for (const Json& a : adapters) {
        if (a.get(L"Status").str() != L"Up") continue;
        long long packets = a.get(L"ReceivedPackets").integer() + a.get(L"SentPackets").integer();
        long long errors = a.get(L"ReceivedErrors").integer() + a.get(L"SentErrors").integer();
        long long discards = a.get(L"ReceivedDiscards").integer() + a.get(L"SentDiscards").integer();
        Status status = Status::Ok;
        std::vector<std::wstring> details = {a.get(L"Description").str(),
                                             L"Received " + human_bytes((double)a.get(L"ReceivedBytes").integer()) + L", sent " +
                                                 human_bytes((double)a.get(L"SentBytes").integer()) + L" since the adapter started"};
        auto ipv4 = a.get(L"IPv4").as_list(), gateway = a.get(L"Gateway").as_list(), dns = a.get(L"DNS").as_list();
        if (!ipv4.empty()) details.push_back(L"IPv4: " + join_list(ipv4));
        if (!gateway.empty()) details.push_back(L"Gateway: " + join_list(gateway));
        if (!dns.empty()) details.push_back(L"DNS servers: " + join_list(dns));
        if (packets) {
            double error_rate = 100.0 * errors / packets, discard_rate = 100.0 * discards / packets;
            if (errors) {
                details.push_back(fmt(L"Packet errors: %lld (%.3f %%)", errors, error_rate));
                if (error_rate >= 0.1) {
                    status = Status::Warning;
                    details.push_back(L"Errors usually mean a bad cable, port, or duplex/speed mismatch.");
                }
            }
            if (discards) {
                details.push_back(fmt(L"Discarded packets: %lld (%.3f %%)", discards, discard_rate));
                if (discard_rate >= 1) status = Status::Warning;
            }
        }
        if (!errors && !discards) details.push_back(L"No errors, no discarded packets");
        std::wstring speed = a.get(L"LinkSpeed").str();
        std::wstring title = a.get(L"Name").str() + L": " + (speed.empty() ? L"?" : speed);
        if ((starts_with(speed, L"10 Mbps") || starts_with(speed, L"100 Mbps")) && !a.get(L"Virtual").flag()) {
            details.push_back(L"Low link speed: if the adapter supports 1 Gbps, check the cable (Cat5e or better) and the switch/router port.");
            status = severity(status) >= severity(Status::Info) ? status : Status::Info;
        }
        items.push_back({status, title, details, L"Adapter"});
    }
    return items;
}

std::vector<NetItem> evaluate_protocols(const Counters& counters, const std::vector<Json>& states) {
    std::vector<NetItem> items;
    auto value = [&](const wchar_t* proto, const wchar_t* key) -> double {
        auto p = counters.find(proto);
        if (p == counters.end()) return 0;
        auto k = p->second.find(key);
        return k == p->second.end() ? 0 : (double)k->second;
    };
    double out_segs = value(L"tcp", L"OutSegs");
    if (out_segs) {
        double retrans = value(L"tcp", L"RetransSegs"), rate = 100 * retrans / out_segs;
        Status status = rate >= 5 ? Status::Critical : rate >= 2 ? Status::Warning : Status::Ok;
        std::vector<std::wstring> details = {fmt(L"%.0f of %.0f segments sent again since boot", retrans, out_segs),
                                             L"Above 2 % the connection loses packets: Wi-Fi interference, faulty cable, saturated link or ISP problem."};
        double opens = value(L"tcp", L"ActiveOpens");
        if (opens) {
            details.push_back(fmt(L"Outgoing connection attempts: %.0f, failed: %.0f (%.1f %%)", opens, value(L"tcp", L"AttemptFails"),
                                  100 * value(L"tcp", L"AttemptFails") / opens));
        }
        details.push_back(fmt(L"Connections reset: %.0f, received with errors: %.0f", value(L"tcp", L"EstabResets"), value(L"tcp", L"InErrs")));
        items.push_back({status, fmt(L"TCP retransmissions: %.2f %%", rate), details, L"TCP"});
    }
    double datagrams = value(L"udp", L"InDatagrams");
    if (datagrams) {
        double errs = value(L"udp", L"InErrors");
        items.push_back({errs && 100 * errs / datagrams >= 1 ? Status::Warning : Status::Ok,
                         fmt(L"UDP: %.0f datagrams received, %.0f with errors", datagrams, errs),
                         {fmt(L"Datagrams to closed ports: %.0f", value(L"udp", L"NoPorts"))}, L"UDP"});
    }
    if (!states.empty()) {
        std::vector<std::pair<std::wstring, long long>> counts;
        long long established = 0, listening = 0;
        for (const Json& s : states) {
            std::wstring name = s.get(L"State").str();
            long long n = s.get(L"Count").integer();
            counts.emplace_back(name, n);
            if (name == L"Established") established = n;
            if (name == L"Listen") listening = n;
        }
        std::stable_sort(counts.begin(), counts.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        std::vector<std::wstring> details;
        for (const auto& [k, v] : counts) details.push_back(k + L": " + std::to_wstring(v));
        items.push_back({Status::Info, fmt(L"TCP connections: %lld established, %lld listening", established, listening), details, L"TCP"});
    }
    return items;
}

std::vector<Listener> parse_listeners(const std::vector<Json>& data) {
    std::set<std::tuple<std::wstring, std::wstring, long long, long long>> seen;
    std::vector<Listener> out;
    for (const Json& d : data) {
        const Json& owner = d.get(L"Owner");
        auto key = std::make_tuple(d.get(L"Protocol").str(), d.get(L"Address").str(), d.get(L"Port").integer(), d.get(L"Pid").integer());
        if (!seen.insert(key).second) continue;
        std::wstring name = owner.get(L"Name").str();
        if (d.get(L"Pid").integer() == 4) name = L"System";
        Listener l;
        l.protocol = d.get(L"Protocol").str(L"?");
        if (l.protocol.empty()) l.protocol = L"?";
        l.address = d.get(L"Address").str();
        l.port = (int)d.get(L"Port").integer();
        l.pid = (int)d.get(L"Pid").integer();
        l.process = name;
        l.path = owner.get(L"Path").str();
        for (const Json& s : owner.get(L"Services").as_list()) {
            if (!s.str().empty()) l.services.push_back(s.str());
        }
        out.push_back(std::move(l));
    }
    std::stable_sort(out.begin(), out.end(), [](const Listener& a, const Listener& b) {
        if (a.loopback() != b.loopback()) return !a.loopback();
        if (a.protocol != b.protocol) return a.protocol < b.protocol;
        return a.port < b.port;
    });
    return out;
}

std::map<std::wstring, std::wstring> address_profiles(const std::vector<Json>& adapters, const std::vector<Json>& networks) {
    std::map<std::wstring, std::wstring> by_alias;
    for (const Json& n : networks) by_alias[n.get(L"Interface").str()] = *active_profiles({n}).begin();
    std::map<std::wstring, std::wstring> out;
    for (const Json& a : adapters) {
        auto it = by_alias.find(a.get(L"Name").str());
        if (it == by_alias.end()) continue;
        for (const Json& cidr : a.get(L"IPv4").as_list()) {
            std::wstring text = cidr.str();
            out[text.substr(0, text.find(L'/'))] = it->second;
        }
    }
    return out;
}

std::set<std::wstring> listener_profiles(const Listener& l, const std::map<std::wstring, std::wstring>& addr_profiles, const std::set<std::wstring>& active) {
    auto it = addr_profiles.find(l.address);
    if (it != addr_profiles.end()) return {it->second};   // a socket bound to one address is only reachable through that adapter's network
    return active;
}

NetworkReport run_network_analysis(const FirewallReport* fw, const Progress& progress) {
    NetworkReport report;
    if (progress) progress(L"Reading adapters and listening ports...");
    Json data = run_powershell_json(NETWORK_PS, 120000);
    if (!data.is_object()) {
        report.error = L"Network information could not be read (PowerShell failed).";
        return report;
    }
    auto adapters = data.get(L"adapters").as_list();
    report.items = evaluate_adapters(adapters);
    for (auto& i : evaluate_protocols(protocol_counters(), data.get(L"tcp_states").as_list())) report.items.push_back(std::move(i));

    FirewallReport own;
    if (!fw) {
        own = run_firewall_analysis();
        fw = &own;
    }
    auto addr_profiles = address_profiles(adapters, fw->networks);
    for (const Listener& l : parse_listeners(data.get(L"listeners").as_list())) {
        report.listeners.push_back({l, evaluate_exposure(l, fw->rules, fw->profiles, listener_profiles(l, addr_profiles, fw->active))});
    }
    std::vector<const ListenerRow*> open_rows;
    for (const auto& r : report.listeners) {
        if (r.exposure.level == L"open") open_rows.push_back(&r);
    }
    if (!open_rows.empty()) {
        CounterMap names;
        bool any_tcp = false;
        for (const auto* r : open_rows) {
            ++names[r->listener.process.empty() ? L"?" : r->listener.process];
            any_tcp |= r->listener.protocol == L"TCP";
        }
        std::vector<std::wstring> details;
        for (const auto& [n, c] : most_common(names)) details.push_back(n + L": " + std::to_wstring(c) + L" port(s)");
        details.push_back(L"Close what you do not use, or restrict the firewall rule (Private profile, local subnet).");
        report.items.push_back({any_tcp ? Status::Warning : Status::Info, fmt(L"%zu listening port(s) reachable from the network", open_rows.size()),
                                details, L"Ports"});
    } else {
        report.items.push_back({Status::Ok, L"No listening port is reachable from the network through the firewall", {}, L"Ports"});
    }
    return report;
}

}  // namespace dd
