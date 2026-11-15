"""
Who is behind a remote address:
  - site names the PC asked for (Windows DNS client cache: name -> IP, remembered for the session);
  - owner of public addresses (RDAP, the successor of WHOIS), asked directly to the regional registry
    chosen with the IANA bootstrap files; one answer covers the whole network block, so it is cached;
  - hardware (MAC) address of devices on the local network (ARP table);
  - names of well-known multicast groups.
Lookups run in the background; the lookup methods never block.
"""

import ctypes
import ipaddress
import json
import socket
import struct
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set, Tuple

from security_audit import _run_ps_json as run_ps_json
from ddcleaner import geo
from ddcleaner.common import system_dll

BOOTSTRAP = {4: "https://data.iana.org/rdap/ipv4.json", 6: "https://data.iana.org/rdap/ipv6.json"}
MAX_RESPONSE = 1024 * 1024
RETRY_FAILED_AFTER = 600
USER_AGENT = "DDCleaner/3.0 (network monitor)"

MULTICAST_NAMES = {
    "224.0.0.251": "mDNS (local discovery)", "ff02::fb": "mDNS (local discovery)",
    "239.255.255.250": "SSDP / UPnP discovery", "ff02::c": "SSDP / UPnP discovery",
    "224.0.0.252": "LLMNR (local name lookup)", "ff02::1:3": "LLMNR (local name lookup)",
    "255.255.255.255": "Broadcast", "224.0.0.1": "All hosts", "ff02::1": "All hosts",
}


def is_public(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr.split("%")[0]).is_global
    except ValueError:
        return False


# region DNS cache

DNS_CACHE_PS = ("@(Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } "
                "| ForEach-Object { [pscustomobject]@{ Entry = [string]$_.Entry; Data = [string]$_.Data } }) "
                "| ConvertTo-Json -Compress")


class DnsNames:
    """IP -> site names the PC resolved. Entries leave the Windows cache quickly, so they are kept."""

    def __init__(self, reader: Callable[[], List[Dict]] = None, interval: float = 15.0):
        self._names: Dict[str, List[str]] = {}
        self._reader = reader or self._read_windows_cache
        self._interval = interval
        self._last = 0.0

    @staticmethod
    def _read_windows_cache() -> List[Dict]:
        rc, data = run_ps_json(DNS_CACHE_PS, timeout=30)
        if isinstance(data, dict):
            return [data]
        return data if isinstance(data, list) else []

    def refresh(self, force: bool = False):
        if not force and time.monotonic() - self._last < self._interval:
            return
        self._last = time.monotonic()
        for rec in self._reader():
            ip, name = str(rec.get("Data") or "").lower(), str(rec.get("Entry") or "").rstrip(".").lower()
            if not ip or not name:
                continue
            names = self._names.setdefault(ip, [])
            if name not in names:
                names.append(name)

    def names(self, addr: str) -> List[str]:
        return self._names.get(addr.split("%")[0].lower(), [])

# endregion


# region RDAP owner lookup

@dataclass
class Owner:
    organization: str = ""
    country: str = ""
    network: str = ""       # network name in the registry (e.g. GOGL)
    range: str = ""         # "start - end"
    registry: str = ""

    @property
    def label(self) -> str:
        if not self.organization:
            return self.network
        return f"{self.organization} ({self.country})" if self.country else self.organization


def _vcard(entity: Dict) -> List:
    card = entity.get("vcardArray") or []
    return card[1] if len(card) > 1 and isinstance(card[1], list) else []


def _vcard_value(entity: Dict, key: str) -> str:
    for item in _vcard(entity):
        if item and item[0] == key and len(item) > 3 and isinstance(item[3], str):
            return item[3].strip()
    return ""


def _vcard_country(entity: Dict) -> str:
    for item in _vcard(entity):
        if item and item[0] == "adr" and len(item) > 3:
            value = item[3]
            if isinstance(value, list) and len(value) > 6 and isinstance(value[6], str) and value[6]:
                return value[6].strip()
            label = item[1].get("label", "") if isinstance(item[1], dict) else ""
            if label:
                return label.strip().splitlines()[-1].strip()
    return ""


def _address_first_line(entity: Dict) -> str:
    for item in _vcard(entity):
        if item and item[0] == "adr" and isinstance(item[1], dict) and item[1].get("label"):
            return item[1]["label"].strip().splitlines()[0].strip()
    return ""


def _entities(data: Dict, depth: int = 0) -> List[Dict]:
    out = []
    for e in data.get("entities") or []:
        out.append(e)
        if depth < 2:
            out += _entities(e, depth + 1)
    return out


def parse_rdap(data: Dict, registry: str = "") -> Owner:
    """Organization and country from an RDAP IP network answer (ARIN, RIPE, APNIC, LACNIC, AFRINIC)."""
    owner = Owner(network=str(data.get("name") or ""), registry=registry)
    if data.get("startAddress"):
        owner.range = f"{data['startAddress']} - {data.get('endAddress', '')}"
    entities = _entities(data)
    registrants = [e for e in entities if "registrant" in (e.get("roles") or [])]
    orgs = [e for e in registrants if _vcard_value(e, "kind") == "org"]
    chosen = (orgs or [None])[0]
    if chosen is not None:
        owner.organization = _vcard_value(chosen, "fn")
    if not owner.organization:
        for r in data.get("remarks") or []:
            text = " ".join(r.get("description") or []).strip()
            if text and len(text) <= 80 and "CERTIFICATE" not in text:
                owner.organization = text
                break
    if not owner.organization:
        for e in entities:
            if set(e.get("roles") or []) & {"administrative", "technical", "registrant"}:
                line = _address_first_line(e)
                if line:
                    owner.organization = line
                    break
    raw = str(data.get("country") or "") or next(
        (c for c in (_vcard_country(e) for e in (orgs + registrants + entities)) if c), "")
    owner.country = geo.country_code(raw) or (raw if len(raw) == 2 else "")  # always ISO 3166 alpha-2
    return owner


def _fetch_json(url: str, opener=urllib.request.urlopen) -> Tuple[Dict, str]:
    parts = urllib.parse.urlparse(url)
    if parts.scheme != "https":
        raise ValueError(f"refusing non-HTTPS URL {url}")
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json",
                                               "User-Agent": USER_AGENT})
    with opener(req, timeout=15) as resp:
        final = resp.geturl()
        if urllib.parse.urlparse(final).scheme != "https":
            raise ValueError("redirected to a non-HTTPS URL")
        body = resp.read(MAX_RESPONSE + 1)
    if len(body) > MAX_RESPONSE:
        raise ValueError("answer too large")
    return json.loads(body.decode("utf-8", errors="replace")), final


MIN_PREFIX = {4: 8, 6: 16}  # no registry allocates wider blocks to one organization


def answer_networks(data: Dict, ip) -> List:
    """Networks an RDAP answer may be cached for. A range that does not contain the queried address, mixes
    IP versions or is absurdly wide (e.g. 0.0.0.0-255.255.255.255) would label unrelated addresses with
    this owner (cache poisoning): only the queried address is cached then."""
    single = [ipaddress.ip_network(f"{ip}/{32 if ip.version == 4 else 128}")]
    try:
        start = ipaddress.ip_address(data["startAddress"])
        end = ipaddress.ip_address(data["endAddress"])
    except (KeyError, ValueError, TypeError):
        return single
    if start.version != ip.version or end.version != ip.version or not start <= ip <= end:
        return single
    networks = list(ipaddress.summarize_address_range(start, end))
    if not networks or any(n.prefixlen < MIN_PREFIX[ip.version] for n in networks) or len(networks) > 64:
        return single
    return networks


class OwnerLookup:
    """Background RDAP lookups with a per-network cache."""

    def __init__(self, fetch: Callable[[str], Tuple[Dict, str]] = _fetch_json, workers: int = 2):
        self._fetch = fetch
        self._bootstrap: Dict[int, List[Tuple[object, str]]] = {}
        self._networks: List[Tuple[object, Owner]] = []   # (ip_network, owner)
        self._failed: Dict[str, float] = {}
        self._pending: Set[str] = set()
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="rdap")
        self.enabled = True

    def cached(self, addr: str) -> Optional[Owner]:
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            return None
        with self._lock:
            for net, owner in self._networks:
                if ip.version == net.version and ip in net:
                    return owner
        return None

    def lookup(self, addr: str) -> Optional[Owner]:
        """Cached owner, or None while the background lookup runs (or when disabled / not public)."""
        if not is_public(addr):
            return None
        owner = self.cached(addr)
        if owner is not None or not self.enabled:
            return owner
        with self._lock:
            if addr in self._pending or time.monotonic() - self._failed.get(addr, -1e9) < RETRY_FAILED_AFTER:
                return None
            self._pending.add(addr)
        self._pool.submit(self._resolve, addr)
        return None

    def resolve_now(self, addr: str) -> Optional[Owner]:
        """Blocking lookup (used from worker threads)."""
        if not is_public(addr):
            return None
        owner = self.cached(addr)
        if owner is None and self.enabled:
            self._resolve(addr)
            owner = self.cached(addr)
        return owner

    def _registry_url(self, ip) -> Optional[str]:
        if ip.version not in self._bootstrap:
            data, _ = self._fetch(BOOTSTRAP[ip.version])
            entries = []
            for prefixes, urls in data.get("services", []):
                base = next((u for u in urls if u.startswith("https://")), None)
                if base:
                    entries += [(ipaddress.ip_network(p, strict=False), base) for p in prefixes]
            entries.sort(key=lambda e: -e[0].prefixlen)  # most specific first
            self._bootstrap[ip.version] = entries
        for net, base in self._bootstrap[ip.version]:
            if ip in net:
                return base
        return None

    def _resolve(self, addr: str):
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
            if self.cached(addr) is not None:
                return
            base = self._registry_url(ip)
            if not base:
                raise ValueError("no registry for this address")
            data, final = self._fetch(base.rstrip("/") + "/ip/" + str(ip))
            owner = parse_rdap(data, urllib.parse.urlparse(final).hostname or "")
            networks = answer_networks(data, ip)
            with self._lock:
                self._networks += [(n, owner) for n in networks]
        except Exception:
            with self._lock:
                self._failed[addr] = time.monotonic()
        finally:
            with self._lock:
                self._pending.discard(addr)

    def shutdown(self):
        self._pool.shutdown(wait=False, cancel_futures=True)

# endregion


# region Local network devices

class MIB_IPNETROW(ctypes.Structure):
    _fields_ = [("dwIndex", wintypes.DWORD), ("dwPhysAddrLen", wintypes.DWORD), ("bPhysAddr", ctypes.c_ubyte * 8),
                ("dwAddr", wintypes.DWORD), ("dwType", wintypes.DWORD)]


def arp_table() -> Dict[str, str]:
    """IPv4 address -> MAC address of devices the PC talked to on the local network."""
    iphlp = system_dll("iphlpapi")
    iphlp.GetIpNetTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL]
    size = wintypes.ULONG(0)
    iphlp.GetIpNetTable(None, ctypes.byref(size), False)
    if not size.value:
        return {}
    buf = ctypes.create_string_buffer(size.value + 1024)
    size = wintypes.ULONG(len(buf))
    if iphlp.GetIpNetTable(buf, ctypes.byref(size), False) != 0:
        return {}
    count = struct.unpack_from("<I", buf.raw, 0)[0]
    rows = (MIB_IPNETROW * count).from_buffer_copy(buf.raw[4:4 + count * ctypes.sizeof(MIB_IPNETROW)])
    out = {}
    for r in rows:
        if r.dwType in (3, 4) and r.dwPhysAddrLen == 6:  # dynamic / static entries
            mac = "-".join(f"{b:02X}" for b in r.bPhysAddr[:6])
            if mac not in ("FF-FF-FF-FF-FF-FF", "00-00-00-00-00-00") and not mac.startswith("01-00-5E"):
                out[socket.inet_ntoa(struct.pack("<I", r.dwAddr))] = mac
    return out


class MIB_IPFORWARDROW(ctypes.Structure):
    _fields_ = [(n, wintypes.DWORD) for n in (
        "dwForwardDest", "dwForwardMask", "dwForwardPolicy", "dwForwardNextHop", "dwForwardIfIndex",
        "dwForwardType", "dwForwardProto", "dwForwardAge", "dwForwardNextHopAS", "dwForwardMetric1",
        "dwForwardMetric2", "dwForwardMetric3", "dwForwardMetric4", "dwForwardMetric5")]


def default_gateways() -> Set[str]:
    """IPv4 default gateways (usually the Internet box / router)."""
    iphlp = system_dll("iphlpapi")
    iphlp.GetIpForwardTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL]
    size = wintypes.ULONG(0)
    iphlp.GetIpForwardTable(None, ctypes.byref(size), False)
    if not size.value:
        return set()
    buf = ctypes.create_string_buffer(size.value + 4096)
    size = wintypes.ULONG(len(buf))
    if iphlp.GetIpForwardTable(buf, ctypes.byref(size), False) != 0:
        return set()
    count = struct.unpack_from("<I", buf.raw, 0)[0]
    rows = (MIB_IPFORWARDROW * count).from_buffer_copy(buf.raw[4:4 + count * ctypes.sizeof(MIB_IPFORWARDROW)])
    return {socket.inet_ntoa(struct.pack("<I", r.dwForwardNextHop)) for r in rows
            if r.dwForwardDest == 0 and r.dwForwardMask == 0 and r.dwForwardNextHop}

# endregion
