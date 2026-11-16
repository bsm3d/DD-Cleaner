"""
Live network traffic per application (read-only):
  - TCP connections and UDP endpoints with their owning process (iphlpapi GetExtendedTcpTable/UdpTable);
  - direction: inbound when the local port is one the same process listens on, outbound otherwise;
  - process name, path, description and hosted services;
  - bytes received/sent per TCP connection (TCP extended statistics, administrator only): counting is
    switched on for each connection when it is first seen, so volumes are "since monitored";
  - reverse DNS names, resolved in the background.
"""

import ctypes
import ipaddress
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ddcleaner import geoip, ipinfo
from ddcleaner.pe_signature import version_info
from ddcleaner.common import system_dll

AF_INET, AF_INET6 = 2, 23
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1
ERROR_INSUFFICIENT_BUFFER = 122
TCP_STATES = {1: "Closed", 2: "Listen", 3: "SynSent", 4: "SynReceived", 5: "Established", 6: "FinWait1",
              7: "FinWait2", 8: "CloseWait", 9: "Closing", 10: "LastAck", 11: "TimeWait", 12: "DeleteTcb"}
ESTABLISHED = 5
TCP_ESTATS_DATA = 1


# region Win32 structures

class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwState", wintypes.DWORD), ("dwLocalAddr", wintypes.DWORD), ("dwLocalPort", wintypes.DWORD),
                ("dwRemoteAddr", wintypes.DWORD), ("dwRemotePort", wintypes.DWORD), ("dwOwningPid", wintypes.DWORD)]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("ucLocalAddr", ctypes.c_ubyte * 16), ("dwLocalScopeId", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD), ("ucRemoteAddr", ctypes.c_ubyte * 16),
                ("dwRemoteScopeId", wintypes.DWORD), ("dwRemotePort", wintypes.DWORD),
                ("dwState", wintypes.DWORD), ("dwOwningPid", wintypes.DWORD)]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwLocalAddr", wintypes.DWORD), ("dwLocalPort", wintypes.DWORD), ("dwOwningPid", wintypes.DWORD)]


class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("ucLocalAddr", ctypes.c_ubyte * 16), ("dwLocalScopeId", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD), ("dwOwningPid", wintypes.DWORD)]


class MIB_TCPROW(ctypes.Structure):
    _fields_ = [("dwState", wintypes.DWORD), ("dwLocalAddr", wintypes.DWORD), ("dwLocalPort", wintypes.DWORD),
                ("dwRemoteAddr", wintypes.DWORD), ("dwRemotePort", wintypes.DWORD)]


class MIB_TCP6ROW(ctypes.Structure):
    _fields_ = [("State", wintypes.DWORD), ("LocalAddr", ctypes.c_ubyte * 16), ("dwLocalScopeId", wintypes.DWORD),
                ("dwLocalPort", wintypes.DWORD), ("RemoteAddr", ctypes.c_ubyte * 16),
                ("dwRemoteScopeId", wintypes.DWORD), ("dwRemotePort", wintypes.DWORD)]


class TCP_ESTATS_DATA_RW_v0(ctypes.Structure):
    _fields_ = [("EnableCollection", ctypes.c_ubyte)]


class TCP_ESTATS_DATA_ROD_v0(ctypes.Structure):
    _fields_ = [("DataBytesOut", ctypes.c_uint64), ("DataSegsOut", ctypes.c_uint64),
                ("DataBytesIn", ctypes.c_uint64), ("DataSegsIn", ctypes.c_uint64),
                ("SegsOut", ctypes.c_uint64), ("SegsIn", ctypes.c_uint64),
                ("SoftErrors", ctypes.c_ulong), ("SoftErrorReason", ctypes.c_ulong),
                ("SndUna", ctypes.c_ulong), ("SndNxt", ctypes.c_ulong), ("SndMax", ctypes.c_ulong),
                ("ThruBytesAcked", ctypes.c_uint64), ("RcvNxt", ctypes.c_ulong),
                ("ThruBytesReceived", ctypes.c_uint64)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * 260)]


class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = [(n, wintypes.DWORD) for n in (
        "dwServiceType", "dwCurrentState", "dwControlsAccepted", "dwWin32ExitCode", "dwServiceSpecificExitCode",
        "dwCheckPoint", "dwWaitHint", "dwProcessId", "dwServiceFlags")]


class ENUM_SERVICE_STATUS_PROCESSW(ctypes.Structure):
    _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpDisplayName", wintypes.LPWSTR),
                ("ServiceStatusProcess", SERVICE_STATUS_PROCESS)]

_prototypes_set = False


def _set_prototypes():
    """64-bit handles and pointers must be declared, or ctypes truncates them to int."""
    global _prototypes_set
    if _prototypes_set:
        return
    k32, adv, iphlp = ctypes.windll.kernel32, ctypes.windll.advapi32, system_dll("iphlpapi")
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                               ctypes.POINTER(wintypes.DWORD)]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    adv.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    adv.OpenSCManagerW.restype = wintypes.HANDLE
    adv.EnumServicesStatusExW.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, wintypes.DWORD,
                                          ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                          ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                                          wintypes.LPCWSTR]
    adv.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    table_args = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL, wintypes.ULONG, ctypes.c_int,
                  wintypes.ULONG]
    iphlp.GetExtendedTcpTable.argtypes = table_args
    iphlp.GetExtendedUdpTable.argtypes = table_args
    for name in ("SetPerTcpConnectionEStats", "SetPerTcp6ConnectionEStats"):
        getattr(iphlp, name).argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                         wintypes.ULONG, wintypes.ULONG]
    for name in ("GetPerTcpConnectionEStats", "GetPerTcp6ConnectionEStats"):
        getattr(iphlp, name).argtypes = [ctypes.c_void_p, ctypes.c_int,
                                         ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG,
                                         ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG,
                                         ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG]
    _prototypes_set = True

# endregion


# region Connection tables

@dataclass(frozen=True)
class Connection:
    protocol: str           # TCP / UDP
    family: int             # AF_INET / AF_INET6
    local_addr: str
    local_port: int
    remote_addr: str        # "" for UDP
    remote_port: int
    state: str
    pid: int

    @property
    def key(self) -> Tuple:
        return (self.protocol, self.local_addr, self.local_port, self.remote_addr, self.remote_port, self.pid)


def _port(dw: int) -> int:
    return socket.ntohs(dw & 0xFFFF)


def _ipv4(dw: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", dw))


def _ipv6(raw) -> str:
    return socket.inet_ntop(socket.AF_INET6, bytes(raw))


def _table(func, family: int, table_class: int, row_type) -> list:
    size = wintypes.DWORD(0)
    buf = None
    for _ in range(5):
        buf = ctypes.create_string_buffer(size.value or 16)
        err = func(buf, ctypes.byref(size), False, family, table_class, 0)
        if err == 0:
            break
        if err != ERROR_INSUFFICIENT_BUFFER:
            return []
        size = wintypes.DWORD(size.value + 4096)  # the table can grow between the two calls
    else:
        return []
    count = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD))[0]
    offset = ctypes.sizeof(wintypes.DWORD)
    rows_type = row_type * count
    return list(rows_type.from_buffer_copy(buf.raw[offset:offset + ctypes.sizeof(rows_type)]))


def list_connections() -> List[Connection]:
    _set_prototypes()
    iphlp = system_dll("iphlpapi")
    out: List[Connection] = []
    for r in _table(iphlp.GetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_ALL, MIB_TCPROW_OWNER_PID):
        out.append(Connection("TCP", AF_INET, _ipv4(r.dwLocalAddr), _port(r.dwLocalPort), _ipv4(r.dwRemoteAddr),
                              _port(r.dwRemotePort), TCP_STATES.get(r.dwState, str(r.dwState)), r.dwOwningPid))
    for r in _table(iphlp.GetExtendedTcpTable, AF_INET6, TCP_TABLE_OWNER_PID_ALL, MIB_TCP6ROW_OWNER_PID):
        out.append(Connection("TCP", AF_INET6, _ipv6(r.ucLocalAddr), _port(r.dwLocalPort), _ipv6(r.ucRemoteAddr),
                              _port(r.dwRemotePort), TCP_STATES.get(r.dwState, str(r.dwState)), r.dwOwningPid))
    for r in _table(iphlp.GetExtendedUdpTable, AF_INET, UDP_TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID):
        out.append(Connection("UDP", AF_INET, _ipv4(r.dwLocalAddr), _port(r.dwLocalPort), "", 0, "", r.dwOwningPid))
    for r in _table(iphlp.GetExtendedUdpTable, AF_INET6, UDP_TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID):
        out.append(Connection("UDP", AF_INET6, _ipv6(r.ucLocalAddr), _port(r.dwLocalPort), "", 0, "", r.dwOwningPid))
    return out


def direction(conn: Connection, listening: Set[Tuple[int, int]]) -> str:
    """In / Out / Listen / UDP. A connection on a port its own process listens on was accepted: inbound."""
    if conn.protocol == "UDP":
        return "UDP"
    if conn.state == "Listen":
        return "Listen"
    return "In" if (conn.pid, conn.local_port) in listening else "Out"


def remote_kind(addr: str) -> str:
    if not addr:
        return ""
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return ""
    if ip.is_unspecified:
        return ""
    if ip.is_loopback:
        return "This PC"
    if ip.is_private or ip.is_link_local:
        return "Local network"
    if ip.is_multicast:
        return "Multicast"
    return "Internet"

# endregion


# region Processes and services

@dataclass
class ProcessInfo:
    pid: int
    name: str
    path: str = ""
    description: str = ""
    services: List[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.pid == 0:
            return "System Idle (closed connections)"
        if self.pid == 4:
            return "System (Windows kernel)"
        base = self.description or self.name or f"PID {self.pid}"
        if self.services:
            return f"{base} [{', '.join(self.services[:3])}{'...' if len(self.services) > 3 else ''}]"
        return base


def process_names() -> Dict[int, str]:
    """pid -> exe name for every process (Toolhelp snapshot, no rights needed)."""
    _set_prototypes()
    k32 = ctypes.windll.kernel32
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    names: Dict[int, str] = {}
    if not snap or snap == ctypes.c_void_p(-1).value:
        return names
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            names[entry.th32ProcessID] = entry.szExeFile
            ok = k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return names


def process_path(pid: int) -> str:
    _set_prototypes()
    k32 = ctypes.windll.kernel32
    handle = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(len(buf))
        if k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return buf.value
        return ""
    finally:
        k32.CloseHandle(handle)


def services_by_pid() -> Dict[int, List[str]]:
    _set_prototypes()
    adv = ctypes.windll.advapi32
    scm = adv.OpenSCManagerW(None, None, 0x0004)  # SC_MANAGER_ENUMERATE_SERVICE
    result: Dict[int, List[str]] = {}
    if not scm:
        return result
    try:
        needed, count, resume = wintypes.DWORD(0), wintypes.DWORD(0), wintypes.DWORD(0)
        adv.EnumServicesStatusExW(scm, 0, 0x30, 1, None, 0, ctypes.byref(needed), ctypes.byref(count),
                                  ctypes.byref(resume), None)
        buf = ctypes.create_string_buffer(needed.value + 4096)
        resume = wintypes.DWORD(0)
        if not adv.EnumServicesStatusExW(scm, 0, 0x30, 1, buf, len(buf), ctypes.byref(needed), ctypes.byref(count),
                                         ctypes.byref(resume), None):
            return result
        entries = ctypes.cast(buf, ctypes.POINTER(ENUM_SERVICE_STATUS_PROCESSW))
        for i in range(count.value):
            e = entries[i]
            pid = e.ServiceStatusProcess.dwProcessId
            if pid:
                result.setdefault(pid, []).append(e.lpServiceName)
    finally:
        adv.CloseServiceHandle(scm)
    return result


class ProcessResolver:
    """Caches path and description per (pid, exe name) so a reused PID is not mixed up."""

    def __init__(self):
        self._cache: Dict[Tuple[int, str], ProcessInfo] = {}
        self._descriptions: Dict[str, str] = {}
        self._services: Dict[int, List[str]] = {}
        self._services_time = 0.0

    def refresh(self, pids: Set[int]) -> Dict[int, ProcessInfo]:
        names = process_names()
        if time.monotonic() - self._services_time > 30:
            try:
                self._services = services_by_pid()
            except OSError:
                self._services = {}
            self._services_time = time.monotonic()
        out = {}
        for pid in pids:
            name = names.get(pid, "")
            info = self._cache.get((pid, name))
            if info is None:
                path = process_path(pid) if pid > 4 else ""
                info = ProcessInfo(pid, name, path, self._description(path))
                self._cache[(pid, name)] = info
            info.services = self._services.get(pid, [])
            out[pid] = info
        return out

    def _description(self, path: str) -> str:
        if not path:
            return ""
        if path not in self._descriptions:
            try:
                self._descriptions[path] = version_info(path)[1].get("FileDescription", "")
            except OSError:
                self._descriptions[path] = ""
        return self._descriptions[path]

# endregion


# region Byte counters (TCP extended statistics)

def _estats_row(conn: Connection):
    if conn.family == AF_INET:
        return MIB_TCPROW(ESTABLISHED, struct.unpack("<I", socket.inet_aton(conn.local_addr))[0],
                          socket.htons(conn.local_port), struct.unpack("<I", socket.inet_aton(conn.remote_addr))[0],
                          socket.htons(conn.remote_port))
    row = MIB_TCP6ROW()
    row.State = ESTABLISHED
    row.LocalAddr[:] = socket.inet_pton(socket.AF_INET6, conn.local_addr)
    row.RemoteAddr[:] = socket.inet_pton(socket.AF_INET6, conn.remote_addr)
    row.dwLocalPort, row.dwRemotePort = socket.htons(conn.local_port), socket.htons(conn.remote_port)
    return row


class ByteCounter:
    """Turns on data statistics for each established TCP connection and reads bytes in/out."""

    def __init__(self):
        self._enabled: Set[Tuple] = set()
        self.available = True  # False once Windows refuses (not administrator)

    def read(self, conn: Connection) -> Optional[Tuple[int, int]]:
        if not self.available or conn.protocol != "TCP" or conn.state != "Established":
            return None
        iphlp = system_dll("iphlpapi")
        v6 = conn.family == AF_INET6
        row = _estats_row(conn)
        if conn.key not in self._enabled:
            rw = TCP_ESTATS_DATA_RW_v0(1)
            setter = iphlp.SetPerTcp6ConnectionEStats if v6 else iphlp.SetPerTcpConnectionEStats
            err = setter(ctypes.byref(row), TCP_ESTATS_DATA, ctypes.byref(rw), 0, ctypes.sizeof(rw), 0)
            if err == 5:  # ERROR_ACCESS_DENIED
                self.available = False
                return None
            if err:
                return None
            self._enabled.add(conn.key)
        rod = TCP_ESTATS_DATA_ROD_v0()
        getter = iphlp.GetPerTcp6ConnectionEStats if v6 else iphlp.GetPerTcpConnectionEStats
        err = getter(ctypes.byref(row), TCP_ESTATS_DATA, None, 0, 0, None, 0, 0,
                     ctypes.byref(rod), 0, ctypes.sizeof(rod))
        if err:
            return None
        return rod.DataBytesIn, rod.DataBytesOut

    def forget(self, alive: Set[Tuple]):
        self._enabled &= alive

# endregion


# region Reverse DNS

class HostResolver:
    """Reverse DNS in the background; lookup() never blocks."""

    def __init__(self, workers: int = 4):
        self._names: Dict[str, str] = {}
        self._pending: Set[str] = set()
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="rdns")

    def lookup(self, addr: str) -> str:
        if not addr or remote_kind(addr) in ("", "This PC", "Multicast"):
            return ""
        if addr in self._names:
            return self._names[addr]
        if addr not in self._pending:
            self._pending.add(addr)
            self._pool.submit(self._resolve, addr)
        return ""

    def _resolve(self, addr: str):
        try:
            name = socket.gethostbyaddr(addr.split("%")[0])[0]
        except (OSError, UnicodeError):
            name = ""
        self._names[addr] = name
        self._pending.discard(addr)

    def shutdown(self):
        self._pool.shutdown(wait=False, cancel_futures=True)

# endregion


# region Sampling

@dataclass
class ConnectionRow:
    conn: Connection
    direction: str
    remote_kind: str
    host: str = ""
    received: Optional[int] = None
    sent: Optional[int] = None
    rate_in: float = 0.0
    rate_out: float = 0.0
    site: str = ""          # what the connection goes to: site name asked in DNS, host name, device...
    owner: str = ""         # who runs that address: organization (country), or local device and its MAC
    owner_detail: str = ""  # network name, address block, registry
    country: str = ""       # ISO code of the owner's registration country
    location: Optional[geoip.Location] = None  # where the server actually is (DB-IP), when the database is present

    @property
    def map_country(self) -> str:
        return self.location.country if self.location and self.location.country else self.country


@dataclass
class AppTraffic:
    process: ProcessInfo
    rows: List[ConnectionRow] = field(default_factory=list)
    received: int = 0       # including connections closed since monitoring started
    sent: int = 0
    rate_in: float = 0.0
    rate_out: float = 0.0

    def count(self, kind: str) -> int:
        return sum(1 for r in self.rows if r.direction == kind)

    @property
    def ports(self) -> List[str]:
        """Local ports it listens on or binds (UDP)."""
        return sorted({f"{r.conn.protocol} {r.conn.local_port}" for r in self.rows if r.direction in ("Listen", "UDP")},
                      key=lambda p: (p.split()[0], int(p.split()[1])))

    @property
    def remote_hosts(self) -> int:
        return len({r.conn.remote_addr for r in self.rows if r.direction in ("In", "Out")})


@dataclass
class TrafficSnapshot:
    apps: Dict[int, AppTraffic]
    time: float
    bytes_available: bool
    total_rate_in: float = 0.0
    total_rate_out: float = 0.0


class TrafficMonitor:
    """Keeps state between samples: enabled counters, previous bytes (rates) and closed-connection totals."""

    def __init__(self, resolve_hosts: bool = True, lookup_owners: bool = True, dns: Optional[ipinfo.DnsNames] = None,
                 owners: Optional[ipinfo.OwnerLookup] = None, locator: Optional[geoip.GeoIP] = None):
        self.processes = ProcessResolver()
        self.geoip = locator or geoip.GeoIP()
        self.counter = ByteCounter()
        self.hosts = HostResolver()
        self.dns = dns or ipinfo.DnsNames()
        self.owners = owners or ipinfo.OwnerLookup()
        self.resolve_hosts = resolve_hosts
        self.lookup_owners = lookup_owners
        self._arp: Dict[str, str] = {}
        self._gateways: Set[str] = set()
        self._local_time = -1e9
        self._last: Dict[Tuple, Tuple[int, int]] = {}
        self._last_time: Optional[float] = None
        self._closed: Dict[Tuple[int, str], List[int]] = {}  # (pid, exe) -> [received, sent] of closed connections

    def sample(self) -> TrafficSnapshot:
        now = time.monotonic()
        conns = list_connections()
        listening = {(c.pid, c.local_port) for c in conns if c.state == "Listen"}
        procs = self.processes.refresh({c.pid for c in conns})
        elapsed = (now - self._last_time) if self._last_time else 0.0

        self._refresh_lookups(now)

        apps: Dict[int, AppTraffic] = {}
        current: Dict[Tuple, Tuple[int, int]] = {}
        for c in conns:
            row = ConnectionRow(c, direction(c, listening), remote_kind(c.remote_addr))
            if row.direction in ("In", "Out"):
                if self.resolve_hosts:
                    row.host = self.hosts.lookup(c.remote_addr)
                self.describe(row)
            counts = self.counter.read(c)
            if counts is not None:
                row.received, row.sent = counts
                current[c.key] = counts
                prev = self._last.get(c.key)
                if prev and elapsed > 0:
                    row.rate_in = max(0, counts[0] - prev[0]) / elapsed
                    row.rate_out = max(0, counts[1] - prev[1]) / elapsed
            app = apps.setdefault(c.pid, AppTraffic(procs.get(c.pid) or ProcessInfo(c.pid, "")))
            app.rows.append(row)

        # connections that disappeared keep counting in their application's totals
        for key, (rx, tx) in self._last.items():
            if key not in current:
                pid = key[-1]
                closed = self._closed.setdefault((pid, (procs.get(pid) or ProcessInfo(pid, "")).name), [0, 0])
                closed[0] += rx
                closed[1] += tx
        self.counter.forget(set(current))
        self._last, self._last_time = current, now

        snap = TrafficSnapshot(apps, now, self.counter.available)
        for pid, app in apps.items():
            closed = self._closed.get((pid, app.process.name), [0, 0])
            app.received = closed[0] + sum(r.received or 0 for r in app.rows)
            app.sent = closed[1] + sum(r.sent or 0 for r in app.rows)
            app.rate_in = sum(r.rate_in for r in app.rows)
            app.rate_out = sum(r.rate_out for r in app.rows)
            snap.total_rate_in += app.rate_in
            snap.total_rate_out += app.rate_out
        return snap

    def _refresh_lookups(self, now: float):
        try:
            self.dns.refresh()
        except Exception:
            pass
        if now - self._local_time > 10:
            self._local_time = now
            try:
                self._arp = ipinfo.arp_table()
                self._gateways = ipinfo.default_gateways()
            except (OSError, AttributeError):
                pass
        self.owners.enabled = self.lookup_owners

    def describe(self, row: ConnectionRow):
        """Fill site (where it goes / comes from) and owner (who is behind the address)."""
        addr = row.conn.remote_addr.split("%")[0]
        kind = row.remote_kind
        if kind == "This PC":
            row.site = "this PC"
        elif kind == "Multicast":
            row.site = ipinfo.MULTICAST_NAMES.get(addr.lower(), "multicast group")
        elif kind == "Local network":
            mac = self._arp.get(addr, "")
            if addr in self._gateways:
                row.site = "Router / Internet box" + (f" ({row.host})" if row.host else "")
            else:
                row.site = row.host or "device on the local network"
            row.owner = f"Local device, MAC {mac}" if mac else "Local device"
        elif kind == "Internet":
            names = self.dns.names(addr)
            if names:
                row.site = names[0] + (f" (+{len(names) - 1} other names)" if len(names) > 1 else "")
            else:
                row.site = row.host
            row.location = self.geoip.locate(addr)
            owner = self.owners.lookup(addr)
            if owner is not None:
                row.owner = owner.label
                row.country = owner.country
                row.owner_detail = f"Network {owner.network}, {owner.range}, registry {owner.registry}"
            elif self.lookup_owners:
                row.owner = "looking up..."

    def close(self):
        self.hosts.shutdown()
        self.owners.shutdown()
        self.geoip.close()

# endregion


# region Per country (world map)

@dataclass
class CountryTraffic:
    code: str
    outbound: int = 0
    inbound: int = 0
    apps: Set[str] = field(default_factory=set)
    destinations: Set[str] = field(default_factory=set)
    received: int = 0
    sent: int = 0
    rate_in: float = 0.0
    rate_out: float = 0.0
    addresses: Set[str] = field(default_factory=set)   # remote addresses
    hosts: Set[str] = field(default_factory=set)       # site names the programs asked for

    @property
    def connections(self) -> int:
        return self.outbound + self.inbound


def by_country(snap: TrafficSnapshot) -> Tuple[Dict[str, CountryTraffic], int]:
    """Internet connections grouped by the owner's country, and how many are not located (yet)."""
    countries: Dict[str, CountryTraffic] = {}
    unlocated = 0
    for pid, app in snap.apps.items():
        if pid == 0:
            continue
        for r in app.rows:
            if r.direction not in ("In", "Out") or r.remote_kind != "Internet":
                continue
            if not r.map_country:
                unlocated += 1
                continue
            ct = countries.setdefault(r.map_country, CountryTraffic(r.map_country))
            if r.direction == "In":
                ct.inbound += 1
            else:
                ct.outbound += 1
            ct.apps.add(app.process.label)
            ct.destinations.add(r.site.split(" (+")[0] or r.owner or r.conn.remote_addr)
            ct.received += r.received or 0
            ct.sent += r.sent or 0
            ct.rate_in += r.rate_in
            ct.rate_out += r.rate_out
            ct.addresses.add(r.conn.remote_addr)
            if r.site:
                ct.hosts.add(r.site.split(" (+")[0])
    return countries, unlocated

@dataclass
class PlaceTraffic:
    """Connections ending at one place: a city (DB-IP) or, without the database, a country."""
    key: str
    label: str
    country: str
    lat: Optional[float]    # None: use the country's label point
    lon: Optional[float]
    precise: bool
    outbound: int = 0
    inbound: int = 0
    apps: Set[str] = field(default_factory=set)
    destinations: Set[str] = field(default_factory=set)
    received: int = 0
    sent: int = 0
    rate_in: float = 0.0          # now, bytes per second (administrator only)
    rate_out: float = 0.0
    addresses: Set[str] = field(default_factory=set)
    hosts: Set[str] = field(default_factory=set)

    @property
    def connections(self) -> int:
        return self.outbound + self.inbound


def by_place(snap: TrafficSnapshot) -> Dict[str, PlaceTraffic]:
    places: Dict[str, PlaceTraffic] = {}
    for pid, app in snap.apps.items():
        if pid == 0:
            continue
        for r in app.rows:
            if r.direction not in ("In", "Out") or r.remote_kind != "Internet" or not r.map_country:
                continue
            loc = r.location
            if loc is not None:
                key = f"{round(loc.lat, 1)},{round(loc.lon, 1)}"
                place = places.setdefault(key, PlaceTraffic(key, loc.label or loc.country, loc.country, loc.lat,
                                                            loc.lon, True))
            else:
                key = f"country:{r.country}"
                place = places.setdefault(key, PlaceTraffic(key, r.country, r.country, None, None, False))
            if r.direction == "In":
                place.inbound += 1
            else:
                place.outbound += 1
            place.apps.add(app.process.label)
            place.destinations.add(r.site.split(" (+")[0] or r.owner or r.conn.remote_addr)
            place.received += r.received or 0
            place.sent += r.sent or 0
            place.rate_in += r.rate_in
            place.rate_out += r.rate_out
            place.addresses.add(r.conn.remote_addr)
            if r.site:
                place.hosts.add(r.site.split(" (+")[0])
    return places

# endregion
