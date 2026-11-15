"""
Windows Firewall analysis (read-only, except the explicit dropped-packet logging switch):
  - profiles (effective state) and active network categories;
  - rules read from the registry (local store + Group Policy): statistics and risky rules;
  - reachability of listening ports: which rule, if any, lets inbound traffic reach them;
  - statistics of blocked traffic from pfirewall.log (when dropped-packet logging is on).
"""

import ctypes
import os
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from security_audit import _run_ps as run_ps, _run_ps_json as run_ps_json
from ddcleaner.common import winreg, SYSTEM_ROOT
from ddcleaner.health import as_list

RULE_STORES = [
    (r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules", "Local"),
    (r"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules", "Group Policy"),
]
PROFILES = ("Domain", "Private", "Public")
PROTOCOLS = {"6": "TCP", "17": "UDP", "1": "ICMPv4", "58": "ICMPv6"}
DYNAMIC_RPC_START = 49152
MAX_LOG_BYTES = 32 * 1024 * 1024

OK, INFO, WARNING, CRITICAL = "ok", "info", "warning", "critical"


# region Rules

@dataclass
class FirewallRule:
    id: str
    name: str
    action: str                 # Allow / Block
    direction: str              # In / Out
    active: bool
    protocol: Optional[str]     # "6", "17"... None = any
    profiles: Set[str]          # empty = all profiles
    local_ports: List[str]
    remote_addresses: List[str]  # empty = any
    local_addresses: List[str]   # empty = any local address
    app: Optional[str]          # expanded, lower-case path; "system" for the kernel
    service: Optional[str]
    package: Optional[str]      # UWP app container rules
    edge: bool
    source: str
    interface_limited: bool = False

    @property
    def local_scope_limited(self) -> bool:
        return bool(self.local_addresses) or self.interface_limited

    def applies_to_profile(self, profile: str) -> bool:
        return not self.profiles or profile in self.profiles

    @property
    def any_remote(self) -> bool:
        return not self.remote_addresses or any(a.lower() in ("*", "any") for a in self.remote_addresses)

    @property
    def scope(self) -> str:
        return "any address" if self.any_remote else ", ".join(dict.fromkeys(self.remote_addresses))

    @property
    def is_windows_component(self) -> bool:
        if self.app in (None, "system"):
            return self.service is not None or self.app == "system" or self.name.startswith("@")
        return self.app.startswith(SYSTEM_ROOT.lower() + "\\")


_indirect_cache: Dict[str, str] = {}


def resolve_indirect(text: str) -> str:
    """'@firewallapi.dll,-50327' -> localized display name (falls back to the raw string)."""
    if not text.startswith("@"):
        return text
    if text in _indirect_cache:
        return _indirect_cache[text]
    result = text
    try:
        buf = ctypes.create_unicode_buffer(512)
        if ctypes.windll.shlwapi.SHLoadIndirectString(os.path.expandvars(text), buf, len(buf), None) == 0:
            result = buf.value or text
    except (AttributeError, OSError):
        pass
    _indirect_cache[text] = result
    return result


def parse_rule(rule_id: str, value: str, source: str = "Local", resolve: Callable[[str], str] = resolve_indirect
               ) -> Optional[FirewallRule]:
    """Parse one registry rule: 'v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=80|App=...|Name=...|'."""
    fields: Dict[str, List[str]] = {}
    for part in str(value).split("|")[1:]:
        key, sep, val = part.partition("=")
        if sep:
            fields.setdefault(key, []).append(val)
    if "Action" not in fields or "Dir" not in fields:
        return None

    def first(key: str) -> Optional[str]:
        return fields.get(key, [None])[0]

    def all_of(prefix: str) -> List[str]:
        return [v for k, vs in fields.items() if k == prefix or k.startswith(prefix + "2_") for v in vs]

    app = first("App")
    if app:
        app = "system" if app.lower() == "system" else os.path.normpath(os.path.expandvars(app)).lower()
    remote = [v for k, vs in fields.items() if k.startswith("RA") and k[2:3] in ("4", "6") for v in vs]
    local = [v for k, vs in fields.items() if k.startswith("LA") and k[2:3] in ("4", "6") for v in vs]
    return FirewallRule(
        id=rule_id, name=resolve(first("Name") or rule_id),
        action=first("Action"), direction=first("Dir"),
        active=(first("Active") or "").upper() == "TRUE",
        protocol=first("Protocol"),
        profiles={p for p in fields.get("Profile", []) if p in PROFILES},
        local_ports=all_of("LPort"),
        remote_addresses=remote,
        local_addresses=local,
        app=app, service=first("Svc"), package=first("AppPkgId") or first("PFN"),
        edge=(first("Edge") or "").upper() == "TRUE",
        source=source,
        # IF/IFType: specific interfaces; TTK*: trust tuple keywords (Wi-Fi Direct, proximity sharing...)
        interface_limited=any(k in ("IF", "IFType") or k.startswith("TTK") for k in fields),
    )


def read_rules() -> List[FirewallRule]:
    rules = []
    for path, source in RULE_STORES:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    rule = parse_rule(name, value, source)
                    if rule:
                        rules.append(rule)
        except OSError:
            continue
    return rules


def port_matches(ports: List[str], port: int) -> bool:
    if not ports:
        return True
    for p in ports:
        for item in p.split(","):
            item = item.strip()
            if item in ("*", "Any"):
                return True
            if item == "RPC-EPMap" and port == 135:
                return True
            if item == "RPC" and port >= DYNAMIC_RPC_START:
                return True
            lo, sep, hi = item.partition("-")
            try:
                if sep and int(lo) <= port <= int(hi):
                    return True
                if not sep and int(item) == port:
                    return True
            except ValueError:
                continue
    return False

# endregion


# region Profiles

PROFILES_PS = r"""
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{ Name = [string]$_.Name; Enabled = [string]$_.Enabled;
    DefaultInboundAction = [string]$_.DefaultInboundAction; DefaultOutboundAction = [string]$_.DefaultOutboundAction;
    LogBlocked = [string]$_.LogBlocked; LogAllowed = [string]$_.LogAllowed;
    LogFileName = [string]$_.LogFileName; LogMaxSizeKilobytes = [int]$_.LogMaxSizeKilobytes }
})
$networks = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ Interface = [string]$_.InterfaceAlias; Name = [string]$_.Name;
    Category = [string]$_.NetworkCategory; IPv4 = [string]$_.IPv4Connectivity }
})
[pscustomobject]@{ profiles = $profiles; networks = $networks } | ConvertTo-Json -Depth 4 -Compress
"""


@dataclass
class ProfileState:
    name: str
    enabled: bool
    inbound: str
    outbound: str
    log_blocked: bool
    log_file: str


def _bool(text) -> bool:
    return str(text).strip().lower() in ("true", "1")


def parse_profiles(data: Optional[Dict]) -> Tuple[Dict[str, ProfileState], List[Dict]]:
    profiles = {}
    for p in as_list((data or {}).get("profiles")):
        name = p.get("Name")
        if name not in PROFILES:
            continue
        inbound = p.get("DefaultInboundAction") or ""
        outbound = p.get("DefaultOutboundAction") or ""
        profiles[name] = ProfileState(
            name=name, enabled=_bool(p.get("Enabled")),
            inbound="Block" if inbound in ("", "NotConfigured") else inbound,   # Windows default
            outbound="Allow" if outbound in ("", "NotConfigured") else outbound,
            log_blocked=_bool(p.get("LogBlocked")),
            log_file=os.path.expandvars(p.get("LogFileName") or
                                        r"%systemroot%\system32\LogFiles\Firewall\pfirewall.log"))
    return profiles, as_list((data or {}).get("networks"))


def active_profiles(networks: List[Dict]) -> Set[str]:
    categories = {"Public": "Public", "Private": "Private", "DomainAuthenticated": "Domain"}
    active = {categories.get(n.get("Category"), "Public") for n in networks}
    return active or {"Public"}


def collect_profiles() -> Optional[Dict]:
    rc, data = run_ps_json(PROFILES_PS, timeout=60)
    return data if isinstance(data, dict) else None


def set_dropped_packet_logging(enabled: bool) -> Tuple[bool, str]:
    """The only change this module makes: turn logging of dropped packets on/off for all profiles."""
    value = "True" if enabled else "False"
    rc, out, err = run_ps(f"Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked {value} -ErrorAction Stop",
                          timeout=60)
    return rc == 0, (err or out).strip()

# endregion


# region Listening ports

@dataclass
class Listener:
    protocol: str       # TCP / UDP
    address: str
    port: int
    pid: int
    process: str = ""
    path: str = ""
    services: List[str] = field(default_factory=list)

    @property
    def loopback(self) -> bool:
        return self.address.startswith("127.") or self.address == "::1"


@dataclass
class Exposure:
    level: str      # open / limited / blocked / local
    text: str
    rule: str = ""


def _rule_matches_listener(rule: FirewallRule, listener: Listener) -> bool:
    if rule.package or rule.interface_limited:
        return False  # app container rules only apply to that UWP app; TTK/IF rules to special interfaces
    if rule.protocol and PROTOCOLS.get(rule.protocol) != listener.protocol:
        return False
    if rule.app:
        if rule.app == "system":
            if listener.pid != 4:
                return False
        elif listener.path:
            if os.path.normpath(listener.path).lower() != rule.app:
                return False
        elif os.path.basename(rule.app) != f"{listener.process}.exe".lower():
            return False  # path not readable: fall back to the executable name
    if rule.service and rule.service != "*":
        if rule.service.lower() not in (s.lower() for s in listener.services):
            return False
    elif rule.service == "*" and not listener.services:
        return False
    return port_matches(rule.local_ports, listener.port)


def evaluate_exposure(listener: Listener, rules: List[FirewallRule], profiles: Dict[str, ProfileState],
                      active: Iterable[str]) -> Exposure:
    """How reachable a listening port is from the network through the firewall (most open active profile)."""
    if listener.loopback:
        return Exposure("local", "Loopback only (this PC)")
    rank = {"open": 3, "limited": 2, "blocked": 1}
    best: Optional[Exposure] = None
    for profile in sorted(active):
        state = profiles.get(profile)
        if state is not None and not state.enabled:
            result = Exposure("open", f"Open: firewall is off ({profile})")
        else:
            inbound = [r for r in rules if r.active and r.direction == "In" and r.applies_to_profile(profile)
                       and _rule_matches_listener(r, listener)]
            blocks = [r for r in inbound if r.action == "Block"]
            allows = [r for r in inbound if r.action == "Allow"]
            if blocks:
                result = Exposure("blocked", f"Blocked by rule ({profile})", blocks[0].name)
            elif allows:
                wide = [r for r in allows if r.any_remote]
                chosen = (wide or allows)[0]
                if wide:
                    result = Exposure("open", f"Open to any address ({profile})", chosen.name)
                else:
                    result = Exposure("limited", f"Open to {chosen.scope} ({profile})", chosen.name)
            elif state is not None and state.inbound == "Allow":
                result = Exposure("open", f"Open: inbound allowed by default ({profile})")
            else:
                result = Exposure("blocked", f"Blocked by default ({profile})")
        if best is None or rank[result.level] > rank[best.level]:
            best = result
    return best or Exposure("blocked", "Blocked")

# endregion


# region Findings

@dataclass
class Finding:
    status: str
    title: str
    details: List[str] = field(default_factory=list)


def rule_statistics(rules: List[FirewallRule]) -> Dict[str, int]:
    active = [r for r in rules if r.active]
    return {
        "total": len(rules),
        "enabled": len(active),
        "inbound_allow": sum(1 for r in active if r.direction == "In" and r.action == "Allow"),
        "inbound_block": sum(1 for r in active if r.direction == "In" and r.action == "Block"),
        "outbound_block": sum(1 for r in active if r.direction == "Out" and r.action == "Block"),
        "group_policy": sum(1 for r in rules if r.source == "Group Policy"),
    }


def _rule_label(r: FirewallRule) -> str:
    what = r.app if r.app and r.app != "system" else (f"service {r.service}" if r.service else "any program")
    ports = ",".join(r.local_ports) if r.local_ports else "all ports"
    proto = PROTOCOLS.get(r.protocol or "", "any protocol" if not r.protocol else f"protocol {r.protocol}")
    profiles = "/".join(sorted(r.profiles)) if r.profiles else "all profiles"
    return f"{r.name}: {what}, {proto} {ports}, {profiles}, from {r.scope}"


def evaluate_firewall(rules: List[FirewallRule], profiles: Dict[str, ProfileState], active: Set[str],
                      path_exists: Callable[[str], bool] = os.path.exists) -> List[Finding]:
    findings: List[Finding] = []
    if not profiles:
        findings.append(Finding(WARNING, "Firewall profiles could not be read"))
    for name in PROFILES:
        p = profiles.get(name)
        if p is None:
            continue
        where = " (in use now)" if name in active else ""
        if not p.enabled:
            findings.append(Finding(CRITICAL, f"Firewall is OFF for the {name} profile{where}",
                                    ["Every listening port is reachable from that kind of network."]))
        elif p.inbound == "Allow":
            findings.append(Finding(CRITICAL, f"{name} profile allows inbound connections by default{where}",
                                    ["Only explicit block rules protect the PC. The Windows default is Block."]))
    if profiles and all(p.enabled and p.inbound != "Allow" for p in profiles.values()):
        findings.append(Finding(OK, "Firewall on for all profiles, inbound blocked by default"))

    inbound_allow = [r for r in rules if r.active and r.direction == "In" and r.action == "Allow" and not r.package]
    allow_all = [r for r in inbound_allow if not r.app and not r.service and not r.local_ports and r.any_remote
                 and not r.local_scope_limited]
    if allow_all:
        findings.append(Finding(CRITICAL, f"{len(allow_all)} rule(s) allow any inbound traffic",
                                ["No program, service or port restriction: the rule opens the PC completely."]
                                + [_rule_label(r) for r in allow_all]))

    public_open = [r for r in inbound_allow if r.applies_to_profile("Public") and r.any_remote
                   and not r.local_scope_limited and not r.is_windows_component and r not in allow_all]
    if public_open:
        findings.append(Finding(WARNING, f"{len(public_open)} program rule(s) accept connections on public networks",
                                ["Public profile = hotel, café, airport Wi-Fi. Restrict these rules to the Private "
                                 "profile unless the program must be reachable there."]
                                + [_rule_label(r) for r in public_open]))

    edge = [r for r in inbound_allow if r.edge and not r.is_windows_component]
    if edge:
        findings.append(Finding(INFO, f"{len(edge)} rule(s) allow edge traversal (reachable through NAT / Teredo)",
                                [_rule_label(r) for r in edge]))

    orphans = [r for r in rules if r.app and r.app != "system" and os.path.isabs(r.app)
               and os.path.splitdrive(r.app)[0] and path_exists(os.path.splitdrive(r.app)[0] + "\\")
               and not path_exists(r.app) and not r.app.startswith(SYSTEM_ROOT.lower() + "\\")]
    writable = [r for r in orphans if not is_protected_path(r.app)]
    protected = [r for r in orphans if is_protected_path(r.app)]
    if writable:
        allowing = [r for r in writable if r.action == "Allow" and r.active]
        findings.append(Finding(WARNING if allowing else INFO,
                                f"{len(writable)} rule(s) for missing programs in folders any user can write to",
                                ["A program copied later to that exact path inherits the rule (for example an "
                                 "inbound allow). Delete these rules in Windows Defender Firewall with Advanced "
                                 "Security (wf.msc)."]
                                + sorted({f"{r.name} ({r.action}{'' if r.active else ', disabled'}): {r.app}"
                                          for r in writable})))
    if protected:
        findings.append(Finding(INFO, f"{len(protected)} rule(s) for programs that were uninstalled",
                                ["Leftovers in Program Files: harmless, only administrators can recreate the "
                                 "file. Can be removed in wf.msc."]
                                + sorted({f"{r.name}: {r.app}" for r in protected})))
    return findings


def is_protected_path(path: str) -> bool:
    """Folders standard users cannot write to (Program Files, Windows)."""
    low = os.path.normpath(path).lower()
    roots = [os.environ.get(v, "") for v in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432")] + [SYSTEM_ROOT]
    return any(r and low.startswith(os.path.normpath(r).lower() + "\\") for r in roots)

# endregion


# region Blocked traffic log

@dataclass
class LogStats:
    files: List[str] = field(default_factory=list)
    lines: int = 0
    first: str = ""
    last: str = ""
    by_action: Counter = field(default_factory=Counter)        # (action, direction)
    inbound_sources: Counter = field(default_factory=Counter)  # remote IP of dropped inbound packets
    inbound_ports: Counter = field(default_factory=Counter)    # "TCP 445"
    outbound_targets: Counter = field(default_factory=Counter)  # "1.2.3.4 TCP 443" blocked outbound
    per_day: Counter = field(default_factory=Counter)
    processes: Counter = field(default_factory=Counter)        # PID of blocked packets (newer Windows logs it)
    source_owners: Dict[str, str] = field(default_factory=dict)  # remote IP -> owner, filled by the UI worker

    @property
    def dropped(self) -> int:
        return sum(n for (a, _), n in self.by_action.items() if a == "DROP")


def parse_log_lines(lines: Iterable[str], stats: Optional[LogStats] = None) -> LogStats:
    stats = stats or LogStats()
    fields = ["date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port", "size",
              "tcpflags", "tcpsyn", "tcpack", "tcpwin", "icmptype", "icmpcode", "info", "path"]
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith("#Fields:"):
                fields = line[8:].split()
            continue
        parts = line.split(" ")
        if len(parts) < 8:
            continue
        rec = dict(zip(fields, parts))
        stats.lines += 1
        stamp = f"{rec.get('date', '')} {rec.get('time', '')}"
        if not stats.first or stamp < stats.first:
            stats.first = stamp
        if stamp > stats.last:
            stats.last = stamp
        action = rec.get("action", "?")
        direction = rec.get("path", "?")
        stats.by_action[(action, direction)] += 1
        if action != "DROP":
            continue
        stats.per_day[rec.get("date", "?")] += 1
        if rec.get("pid", "-") not in ("-", "", "0"):
            stats.processes[rec["pid"]] += 1
        proto = rec.get("protocol", "?")
        if direction == "RECEIVE":
            stats.inbound_sources[rec.get("src-ip", "?")] += 1
            port = rec.get("dst-port", "-")
            stats.inbound_ports[f"{proto} {port}" if port != "-" else proto] += 1
        elif direction == "SEND":
            stats.outbound_targets[f"{rec.get('dst-ip', '?')} {proto} {rec.get('dst-port', '-')}"] += 1
    return stats


def read_log(path: str) -> Optional[LogStats]:
    """Statistics from the firewall log and its rotated '.old' copy; None when no log exists yet."""
    stats = LogStats()
    for p in (path + ".old", path):
        try:
            size = os.path.getsize(p)
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                if size > MAX_LOG_BYTES:
                    f.seek(size - MAX_LOG_BYTES)
                    f.readline()
                parse_log_lines(f, stats)
            stats.files.append(p)
        except OSError:
            continue
    return stats if stats.files else None


PORT_HINTS = {
    "TCP 445": "SMB file sharing", "TCP 139": "NetBIOS", "UDP 137": "NetBIOS name", "UDP 138": "NetBIOS datagram",
    "TCP 3389": "Remote Desktop", "TCP 22": "SSH", "TCP 23": "Telnet", "TCP 135": "RPC", "UDP 1900": "SSDP / UPnP",
    "UDP 5353": "mDNS", "UDP 5355": "LLMNR", "UDP 3702": "WS-Discovery", "UDP 67": "DHCP", "UDP 68": "DHCP",
    "TCP 80": "HTTP", "TCP 443": "HTTPS", "UDP 443": "QUIC", "UDP 123": "NTP", "UDP 161": "SNMP",
}


def describe_port(key: str) -> str:
    hint = PORT_HINTS.get(key)
    return f"{key} ({hint})" if hint else key

# endregion


@dataclass
class FirewallReport:
    profiles: Dict[str, ProfileState]
    networks: List[Dict]
    active: Set[str]
    rules: List[FirewallRule]
    stats: Dict[str, int]
    findings: List[Finding]
    log: Optional[LogStats]
    log_enabled: bool
    log_path: str


def run_firewall_analysis(progress=None) -> FirewallReport:
    if progress:
        progress("Reading firewall profiles and rules...")
    profiles, networks = parse_profiles(collect_profiles())
    active = active_profiles(networks)
    rules = read_rules()
    findings = evaluate_firewall(rules, profiles, active)
    log_enabled = any(p.log_blocked for p in profiles.values())
    log_path = next((p.log_file for p in profiles.values()),
                    os.path.join(SYSTEM_ROOT, "system32", "LogFiles", "Firewall", "pfirewall.log"))
    if progress:
        progress("Reading the firewall log...")
    return FirewallReport(profiles, networks, active, rules, rule_statistics(rules), findings,
                          read_log(log_path), log_enabled, log_path)
