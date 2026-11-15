"""
Network statistics (read-only): adapters (traffic, errors, discards, addresses, DNS), TCP/UDP counters
since boot, connection states, and listening ports with their process and firewall exposure.
"""

import ctypes
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from security_audit import _run_ps_json as run_ps_json
from ddcleaner import firewall
from ddcleaner.health import as_list
from ddcleaner.common import system_dll

OK, INFO, WARNING, CRITICAL = "ok", "info", "warning", "critical"

NETWORK_PS = r"""
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
"""


# region TCP / UDP counters (iphlpapi, since boot)

class MIB_TCPSTATS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulong) for n in (
        "RtoAlgorithm", "RtoMin", "RtoMax", "MaxConn", "ActiveOpens", "PassiveOpens", "AttemptFails",
        "EstabResets", "CurrEstab", "InSegs", "OutSegs", "RetransSegs", "InErrs", "OutRsts", "NumConns")]


class MIB_UDPSTATS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulong) for n in ("InDatagrams", "NoPorts", "InErrors", "OutDatagrams", "NumAddrs")]


AF_INET, AF_INET6 = 2, 23


def protocol_counters() -> Dict[str, Dict[str, int]]:
    """{'tcp': {...}, 'udp': {...}} summed over IPv4 and IPv6."""
    iphlp = system_dll("iphlpapi")
    tcp: Counter = Counter()
    udp: Counter = Counter()
    for family in (AF_INET, AF_INET6):
        t = MIB_TCPSTATS()
        if iphlp.GetTcpStatisticsEx(ctypes.byref(t), family) == 0:
            for name, _ in MIB_TCPSTATS._fields_[4:]:
                tcp[name] += getattr(t, name)
        u = MIB_UDPSTATS()
        if iphlp.GetUdpStatisticsEx(ctypes.byref(u), family) == 0:
            for name, _ in MIB_UDPSTATS._fields_:
                udp[name] += getattr(u, name)
    return {"tcp": dict(tcp), "udp": dict(udp)}

# endregion


@dataclass
class NetItem:
    status: str
    title: str
    details: List[str] = field(default_factory=list)
    category: str = "Network"


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


def evaluate_adapters(adapters: List[Dict]) -> List[NetItem]:
    items = []
    for a in adapters:
        if a.get("Status") != "Up":
            continue
        packets = (a.get("ReceivedPackets") or 0) + (a.get("SentPackets") or 0)
        errors = (a.get("ReceivedErrors") or 0) + (a.get("SentErrors") or 0)
        discards = (a.get("ReceivedDiscards") or 0) + (a.get("SentDiscards") or 0)
        status = OK
        details = [a.get("Description") or "",
                   f"Received {human_bytes(a.get('ReceivedBytes') or 0)}, sent {human_bytes(a.get('SentBytes') or 0)} "
                   f"since the adapter started"]
        if as_list(a.get("IPv4")):
            details.append("IPv4: " + ", ".join(as_list(a.get("IPv4"))))
        if as_list(a.get("Gateway")):
            details.append("Gateway: " + ", ".join(as_list(a.get("Gateway"))))
        if as_list(a.get("DNS")):
            details.append("DNS servers: " + ", ".join(as_list(a.get("DNS"))))
        if packets:
            error_rate = 100 * errors / packets
            discard_rate = 100 * discards / packets
            if errors:
                details.append(f"Packet errors: {errors} ({error_rate:.3f} %)")
                if error_rate >= 0.1:
                    status = WARNING
                    details.append("Errors usually mean a bad cable, port, or duplex/speed mismatch.")
            if discards:
                details.append(f"Discarded packets: {discards} ({discard_rate:.3f} %)")
                if discard_rate >= 1:
                    status = WARNING
        if not errors and not discards:
            details.append("No errors, no discarded packets")
        title = f"{a.get('Name')}: {a.get('LinkSpeed') or '?'}"
        if (a.get("LinkSpeed") or "").startswith(("10 Mbps", "100 Mbps")) and not a.get("Virtual"):
            details.append("Low link speed: if the adapter supports 1 Gbps, check the cable (Cat5e or better) "
                           "and the switch/router port.")
            status = max(status, INFO, key=["ok", "info", "warning", "critical"].index)
        items.append(NetItem(status, title, details, "Adapter"))
    return items


def evaluate_protocols(counters: Dict[str, Dict[str, int]], states: List[Dict]) -> List[NetItem]:
    items = []
    tcp = counters.get("tcp", {})
    out_segs = tcp.get("OutSegs") or 0
    if out_segs:
        rate = 100 * (tcp.get("RetransSegs") or 0) / out_segs
        status = CRITICAL if rate >= 5 else WARNING if rate >= 2 else OK
        details = [f"{tcp.get('RetransSegs', 0)} of {out_segs} segments sent again since boot",
                   "Above 2 % the connection loses packets: Wi-Fi interference, faulty cable, saturated link "
                   "or ISP problem."]
        opens = (tcp.get("ActiveOpens") or 0)
        if opens:
            details.append(f"Outgoing connection attempts: {opens}, failed: {tcp.get('AttemptFails', 0)} "
                           f"({100 * (tcp.get('AttemptFails') or 0) / opens:.1f} %)")
        details.append(f"Connections reset: {tcp.get('EstabResets', 0)}, received with errors: {tcp.get('InErrs', 0)}")
        items.append(NetItem(status, f"TCP retransmissions: {rate:.2f} %", details, "TCP"))
    udp = counters.get("udp", {})
    if udp.get("InDatagrams"):
        errs = udp.get("InErrors") or 0
        items.append(NetItem(WARNING if errs and 100 * errs / udp["InDatagrams"] >= 1 else OK,
                             f"UDP: {udp['InDatagrams']} datagrams received, {errs} with errors",
                             [f"Datagrams to closed ports: {udp.get('NoPorts', 0)}"], "UDP"))
    if states:
        counts = {s.get("State"): s.get("Count", 0) for s in states}
        items.append(NetItem(INFO, f"TCP connections: {counts.get('Established', 0)} established, "
                                   f"{counts.get('Listen', 0)} listening",
                             [f"{k}: {v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1])], "TCP"))
    return items


def parse_listeners(data: List[Dict]) -> List[firewall.Listener]:
    seen = set()
    out = []
    for d in data:
        owner = d.get("Owner") or {}
        key = (d.get("Protocol"), d.get("Address"), d.get("Port"), d.get("Pid"))
        if key in seen:
            continue
        seen.add(key)
        name = owner.get("Name") or ""
        if d.get("Pid") == 4:
            name = "System"
        out.append(firewall.Listener(protocol=d.get("Protocol") or "?", address=d.get("Address") or "",
                                     port=int(d.get("Port") or 0), pid=int(d.get("Pid") or 0), process=name,
                                     path=owner.get("Path") or "",
                                     services=[s for s in as_list(owner.get("Services")) if s]))
    return sorted(out, key=lambda l: (l.loopback, l.protocol, l.port))


def address_profiles(adapters: List[Dict], networks: List[Dict]) -> Dict[str, str]:
    """IPv4 address -> firewall profile of the network its adapter is connected to."""
    by_alias = {n.get("Interface"): firewall.active_profiles([n]).pop() for n in networks}
    out = {}
    for a in adapters:
        profile = by_alias.get(a.get("Name"))
        for cidr in as_list(a.get("IPv4")):
            if profile:
                out[str(cidr).split("/")[0]] = profile
    return out


def listener_profiles(listener: firewall.Listener, addr_profiles: Dict[str, str], active: set) -> set:
    """A socket bound to one address is only reachable through that adapter's network."""
    profile = addr_profiles.get(listener.address)
    return {profile} if profile else set(active)


@dataclass
class ListenerRow:
    listener: firewall.Listener
    exposure: firewall.Exposure


@dataclass
class NetworkReport:
    items: List[NetItem]
    listeners: List[ListenerRow]
    error: str = ""


def run_network_analysis(fw_report: Optional[firewall.FirewallReport] = None, progress=None) -> NetworkReport:
    if progress:
        progress("Reading adapters and listening ports...")
    rc, data = run_ps_json(NETWORK_PS, timeout=120)
    if not isinstance(data, dict):
        return NetworkReport([], [], "Network information could not be read (PowerShell failed).")
    items = evaluate_adapters(as_list(data.get("adapters")))
    try:
        counters = protocol_counters()
    except (AttributeError, OSError):
        counters = {}
    items += evaluate_protocols(counters, as_list(data.get("tcp_states")))

    fw_report = fw_report or firewall.run_firewall_analysis()
    addr_profiles = address_profiles(as_list(data.get("adapters")), fw_report.networks)
    rows = [ListenerRow(l, firewall.evaluate_exposure(l, fw_report.rules, fw_report.profiles,
                                                      listener_profiles(l, addr_profiles, fw_report.active)))
            for l in parse_listeners(as_list(data.get("listeners")))]
    open_rows = [r for r in rows if r.exposure.level == "open"]
    if open_rows:
        names = Counter(r.listener.process or "?" for r in open_rows)
        items.append(NetItem(WARNING if any(r.listener.protocol == "TCP" for r in open_rows) else INFO,
                             f"{len(open_rows)} listening port(s) reachable from the network",
                             [f"{n}: {c} port(s)" for n, c in names.most_common()]
                             + ["Close what you do not use, or restrict the firewall rule (Private profile, "
                                "local subnet)."], "Ports"))
    else:
        items.append(NetItem(OK, "No listening port is reachable from the network through the firewall",
                             category="Ports"))
    return NetworkReport(items, rows)
