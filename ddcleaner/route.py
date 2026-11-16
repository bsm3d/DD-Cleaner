"""The route to a destination (Windows tracert) and the pages offered for a node of the world map. No Qt here.

Only a public IP address is ever given to tracert, as one argument of a program started without a shell. Host names
come from DNS and are checked before they become a link.
"""

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from ddcleaner.common import sys_exe

MAX_HOPS = 30
PROBE_TIMEOUT_MS = 1000
HOST_NAME = re.compile(r"^(?=.{4,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
VIRUSTOTAL = "https://www.virustotal.com/gui/"


# region Destinations

def public_address(text: str) -> str:
    """The normalized text of a public IP address, '' for anything else (a name, a private or local address)."""
    try:
        ip = ipaddress.ip_address((text or "").split("%")[0].strip())
    except ValueError:
        return ""
    return str(ip) if ip.is_global else ""


def public_addresses(addresses: Iterable[str]) -> List[str]:
    found = {public_address(a) for a in addresses}
    found.discard("")
    return sorted(found, key=lambda a: (ipaddress.ip_address(a).version, int(ipaddress.ip_address(a))))


def valid_host(name: str) -> str:
    """The lower-case host name, '' when it is not a plain Internet name (spaces, slashes, a bare word...)."""
    name = (name or "").split(" (+")[0].strip().rstrip(".").lower()
    if not HOST_NAME.match(name) or name.rsplit(".", 1)[-1].isdigit():
        return ""  # a name ends in letters: "192.168.1.1" is an address, not a site
    try:
        ipaddress.ip_address(name)
        return ""
    except ValueError:
        return name


def valid_hosts(names: Iterable[str]) -> List[str]:
    return sorted({valid_host(n) for n in names} - {""})


def site_url(host: str) -> str:
    host = valid_host(host)
    return f"https://{host}/" if host else ""


def reputation_url(target: str) -> str:
    """The VirusTotal page about an address or a host name: what security companies know about it. Opening it in the
    browser does not connect to the destination itself."""
    address = public_address(target)
    if address:
        return VIRUSTOTAL + "ip-address/" + urllib.parse.quote(address, safe="")
    host = valid_host(target)
    return VIRUSTOTAL + "domain/" + urllib.parse.quote(host, safe="") if host else ""

# endregion


# region tracert

def build_command(address: str) -> List[str]:
    """tracert, without name lookups (quicker, and no DNS request for every router), towards a public address."""
    target = public_address(address)
    if not target:
        raise ValueError("A route can only be traced to a public Internet address.")
    return [sys_exe("tracert.exe"), "-d", "-h", str(MAX_HOPS), "-w", str(PROBE_TIMEOUT_MS), target]


@dataclass
class Hop:
    number: int
    times: List[str] = field(default_factory=list)   # "12 ms", "<1 ms" or "*" for each probe
    address: str = ""                                # '' when the router did not answer

    @property
    def summary(self) -> str:
        return "   ".join(self.times) if self.address else "no answer"


HOP_LINE = re.compile(r"^\s*(\d{1,3})\s+(.+?)\s*$")
TIME = re.compile(r"(<?\s*\d+)\s*ms|\*")


def parse_hop(line: str) -> Optional[Hop]:
    """One line of tracert output, whatever the language of Windows: a hop number, up to three times or stars, then the
    address of the router. Header, footer and error lines are not hops (None)."""
    match = HOP_LINE.match(line or "")
    if not match:
        return None
    rest = match.group(2)
    times, end = [], 0
    for item in TIME.finditer(rest):
        times.append("*" if item.group(0) == "*" else item.group(1).replace(" ", "") + " ms")
        end = item.end()
    if not times:
        return None
    address = ""
    for token in rest[end:].split():
        try:
            address = str(ipaddress.ip_address(token.strip("[]()").split("%")[0]))
            break
        except ValueError:
            continue
    return Hop(int(match.group(1)), times[:3], address)

# endregion
