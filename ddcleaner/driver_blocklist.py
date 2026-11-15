"""
Microsoft vulnerable driver blocklist: download, policy parsing, driver inventory and matching.

The policy (DriverPolicy_Enforced.xml from https://aka.ms/VulnerableDriverBlockList) is evaluated the way
Windows code integrity does for kernel drivers (signing scenario 131):
  - Deny Hash rules: Authenticode SHA1/SHA256 of the file;
  - Deny FileName rules: OriginalFilename + file version range;
  - Denied signers: a certificate of the signing chain has the TBS hash, the leaf CN equals CertPublisher,
    the OPUS program name equals CertOemID, and, when the signer lists FileAttribRefs, the file matches one.
A match means Windows refuses to load that driver when the blocklist is enforced. Nothing here modifies the system.
"""

import io
import json
import logging
import os
import sys
import urllib.parse
import urllib.request
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

from ddcleaner.common import winreg, SYSTEM_ROOT, data_dir
from ddcleaner.pe_signature import PEInfo, inspect_file

BLOCKLIST_URL = "https://aka.ms/VulnerableDriverBlockList"
POLICY_MEMBER = "DriverPolicy_Enforced.xml"
KERNEL_SCENARIO = "131"
MAX_DOWNLOAD = 20 * 1024 * 1024
NS = {"s": "urn:schemas-microsoft-com:sipolicy"}

# FileAttrib / Deny attribute -> version resource string it is compared with
ATTRIBUTE_STRINGS = {
    "FileName": "OriginalFilename",
    "InternalName": "InternalName",
    "ProductName": "ProductName",
    "FileDescription": "FileDescription",
}
START_TYPES = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}


def get_blocklist_dir() -> str:
    return os.path.join(data_dir(), "driver_blocklist")


# region Policy

def parse_version(text: Optional[str]) -> Optional[Tuple[int, ...]]:
    if not text:
        return None
    try:
        parts = tuple(int(p) for p in text.split("."))
    except ValueError:
        return None
    return (parts + (0, 0, 0, 0))[:4]


@dataclass
class FileAttribute:
    """Name attribute + version range (Deny FileName rule or signer FileAttrib)."""
    attribute: str      # version resource string name, e.g. OriginalFilename
    value: str
    minimum: Optional[Tuple[int, ...]]
    maximum: Optional[Tuple[int, ...]]
    friendly: str = ""

    def matches(self, info: PEInfo) -> bool:
        found = info.strings.get(self.attribute)
        if not found or found.casefold() != self.value.casefold():
            return False
        if self.minimum is None and self.maximum is None:
            return True
        if info.version is None:
            return False
        # Deny-rule semantics (Microsoft App Control docs, "file rule levels"): both bounds -> inside the
        # range; MinimumFileVersion alone -> that version AND OLDER; MaximumFileVersion alone -> that
        # version and newer. Not the allow-rule meaning: reading Minimum as a lower bound would miss old
        # vulnerable builds and flag the fixed ones.
        if self.minimum is not None and self.maximum is not None:
            return self.minimum <= info.version <= self.maximum
        if self.minimum is not None:
            return info.version <= self.minimum
        return info.version >= self.maximum


@dataclass
class DeniedSigner:
    name: str
    tbs: set
    publisher: str = ""
    oem_id: str = ""
    file_attributes: List[FileAttribute] = field(default_factory=list)

    def matches(self, info: PEInfo) -> bool:
        for sig in info.signatures:
            if not any(c.tbs_hashes & self.tbs for c in sig.chain + sig.certificates):
                continue
            leaf = sig.leaf
            if self.publisher and (leaf is None or leaf.common_name != self.publisher):
                continue
            if self.oem_id and sig.opus_program.casefold() != self.oem_id.casefold():
                continue
            if self.file_attributes and not any(a.matches(info) for a in self.file_attributes):
                continue
            return True
        return False


@dataclass
class BlocklistPolicy:
    version: str
    hashes: Dict[str, str]              # authenticode hash (upper hex) -> rule friendly name
    file_rules: List[FileAttribute]
    signers: List[DeniedSigner]

    @property
    def rule_count(self) -> int:
        return len(self.hashes) + len(self.file_rules) + len(self.signers)

    def match(self, info: PEInfo) -> List[str]:
        """Human-readable reasons this file is on the blocklist (empty = not listed)."""
        reasons = []
        for algo, digest in info.hashes.items():
            name = self.hashes.get(digest)
            if name:
                reasons.append(f"Hash ({algo.upper()}): {name}")
                break
        for rule in self.file_rules:
            if rule.matches(info):
                reasons.append(f"File rule: {rule.friendly or rule.value}")
        for signer in self.signers:
            if signer.matches(info):
                reasons.append(f"Signer: {signer.name}")
        return reasons


def _file_attribute(el: ET.Element) -> Optional[FileAttribute]:
    for attr, string_name in ATTRIBUTE_STRINGS.items():
        value = el.get(attr)
        if value:
            return FileAttribute(string_name, value, parse_version(el.get("MinimumFileVersion")),
                                 parse_version(el.get("MaximumFileVersion")), el.get("FriendlyName", ""))
    return None


def parse_policy(xml_bytes: bytes) -> BlocklistPolicy:
    """Parse a WDAC SiPolicy XML; only rules of the kernel signing scenario (131) are kept."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as e:
        raise ValueError(f"invalid policy XML: {e}") from e
    if root.tag != "{%s}SiPolicy" % NS["s"]:
        raise ValueError("not a code integrity policy")

    scenario = next((s for s in root.findall(".//s:SigningScenario", NS) if s.get("Value") == KERNEL_SCENARIO), None)
    if scenario is None:
        raise ValueError("no kernel signing scenario in the policy")
    denied_rule_ids = {r.get("RuleID") for r in scenario.findall(".//s:FileRulesRef/s:FileRuleRef", NS)}
    denied_signer_ids = {s.get("SignerId") for s in scenario.findall(".//s:DeniedSigners/s:DeniedSigner", NS)}

    hashes: Dict[str, str] = {}
    file_rules: List[FileAttribute] = []
    attributes: Dict[str, FileAttribute] = {}
    for el in root.findall("s:FileRules/*", NS):
        tag = el.tag.split("}")[1]
        if tag == "FileAttrib":
            attr = _file_attribute(el)
            if attr:
                attributes[el.get("ID")] = attr
        elif tag == "Deny" and el.get("ID") in denied_rule_ids:
            if el.get("Hash"):
                hashes[el.get("Hash").upper()] = el.get("FriendlyName", "")
            else:
                attr = _file_attribute(el)
                if attr:
                    file_rules.append(attr)

    signers: List[DeniedSigner] = []
    for el in root.findall("s:Signers/s:Signer", NS):
        if el.get("ID") not in denied_signer_ids:
            continue
        tbs = {c.get("Value", "").upper() for c in el.findall("s:CertRoot", NS) if c.get("Value")}
        if not tbs:
            continue
        publisher = el.find("s:CertPublisher", NS)
        oem = el.find("s:CertOemID", NS)
        refs = [attributes[r.get("RuleID")] for r in el.findall("s:FileAttribRef", NS) if r.get("RuleID") in attributes]
        signers.append(DeniedSigner(
            name=el.get("Name", el.get("ID", "")), tbs=tbs,
            publisher=publisher.get("Value", "") if publisher is not None else "",
            oem_id=oem.get("Value", "") if oem is not None else "",
            file_attributes=refs,
        ))

    version_el = root.find("s:VersionEx", NS)
    policy = BlocklistPolicy(version_el.text.strip() if version_el is not None and version_el.text else "?",
                             hashes, file_rules, signers)
    if policy.rule_count == 0:
        raise ValueError("the policy contains no deny rule")
    return policy


def load_policy(folder: Optional[str] = None) -> Tuple[Optional[BlocklistPolicy], Dict]:
    """Cached policy and its metadata ({} when nothing was downloaded yet)."""
    folder = folder or get_blocklist_dir()
    path = os.path.join(folder, POLICY_MEMBER)
    if not os.path.isfile(path):
        return None, {}
    meta = {}
    try:
        with open(os.path.join(folder, "blocklist.json"), encoding="utf-8") as f:
            meta = json.load(f)
    except (OSError, ValueError):
        pass
    with open(path, "rb") as f:
        return parse_policy(f.read()), meta

# endregion


# region Download

def _is_microsoft_url(url: str) -> bool:
    parts = urllib.parse.urlparse(url)
    host = (parts.hostname or "").lower()
    return parts.scheme == "https" and (host == "microsoft.com" or host.endswith(".microsoft.com"))


def extract_policy(zip_bytes: bytes) -> bytes:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        member = next((i for i in z.infolist() if i.filename.replace("\\", "/").split("/")[-1] == POLICY_MEMBER), None)
        if member is None:
            raise ValueError(f"{POLICY_MEMBER} not found in the archive")
        if member.file_size > MAX_DOWNLOAD:
            raise ValueError("policy file too large")
        return z.read(member)


def download_blocklist(folder: Optional[str] = None, opener: Callable = urllib.request.urlopen) -> BlocklistPolicy:
    """Download the current Microsoft blocklist, validate it and store it (atomic replace)."""
    folder = folder or get_blocklist_dir()
    with opener(BLOCKLIST_URL, timeout=60) as resp:
        final_url = resp.geturl()
        if not _is_microsoft_url(final_url):
            raise ValueError(f"unexpected download location: {final_url}")
        data = resp.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError("download too large")
    xml_bytes = extract_policy(data)
    policy = parse_policy(xml_bytes)  # never store something we cannot use

    os.makedirs(folder, exist_ok=True)
    target = os.path.join(folder, POLICY_MEMBER)
    with open(target + ".tmp", "wb") as f:
        f.write(xml_bytes)
    os.replace(target + ".tmp", target)
    with open(os.path.join(folder, "blocklist.json"), "w", encoding="utf-8") as f:
        json.dump({"version": policy.version, "downloaded": datetime.now().isoformat(timespec="seconds"),
                   "source": final_url}, f, indent=2)
    logging.info(f"Driver blocklist {policy.version} downloaded from {final_url}")
    return policy

# endregion


# region Driver inventory

_device_map_cache: Optional[Dict[str, str]] = None


def device_map() -> Dict[str, str]:
    """'\\device\\harddiskvolume3' -> 'C:' (QueryDosDeviceW), to read kernel paths of loaded drivers."""
    global _device_map_cache
    if _device_map_cache is None:
        import ctypes
        import string
        out: Dict[str, str] = {}
        buf = ctypes.create_unicode_buffer(1024)
        for letter in string.ascii_uppercase:
            try:
                if ctypes.windll.kernel32.QueryDosDeviceW(f"{letter}:", buf, len(buf)):
                    out[buf.value.lower()] = f"{letter}:"
            except (AttributeError, OSError):
                break
        _device_map_cache = out
    return _device_map_cache


def normalize_driver_path(path: str) -> str:
    r"""Kernel/ImagePath forms (\SystemRoot\..., \??\C:\..., system32\..., \Device\HarddiskVolumeN\...)
    to a Win32 path; '' if unknown."""
    if not path:
        return ""
    p = os.path.expandvars(path.strip().strip('"'))
    low = p.lower()
    if low.startswith("\\systemroot\\"):
        p = os.path.join(SYSTEM_ROOT, p[12:])
    elif low.startswith("systemroot\\"):
        p = os.path.join(SYSTEM_ROOT, p[11:])
    elif low.startswith("\\??\\") or low.startswith("\\\\?\\"):
        p = p[4:]
    elif low.startswith("\\windows\\"):
        p = os.path.join(os.path.splitdrive(SYSTEM_ROOT)[0] + "\\", p[1:])
    elif low.startswith("system32\\") or low.startswith("syswow64\\"):
        p = os.path.join(SYSTEM_ROOT, p)
    elif low.startswith("\\device\\"):
        # drivers loaded from anywhere (a common "bring your own vulnerable driver" trick) show up like this
        drive = device_map().get("\\device\\" + low.split("\\")[2])
        if not drive:
            return ""
        p = drive + "\\" + p.split("\\", 3)[3] if p.count("\\") >= 3 else ""
    if not p or not os.path.isabs(p):
        return ""
    return os.path.normpath(p)


@dataclass
class DriverFile:
    path: str
    service: str = ""
    start: str = ""
    loaded: bool = False

    @property
    def state(self) -> str:
        if self.loaded:
            return "Loaded"
        if self.service:
            return f"Installed ({self.start})" if self.start else "Installed"
        return "File only"


def loaded_driver_paths() -> List[str]:
    """Kernel modules currently loaded (psapi)."""
    import ctypes
    from ctypes import wintypes
    psapi = ctypes.WinDLL("psapi")
    psapi.EnumDeviceDrivers.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    psapi.GetDeviceDriverFileNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    needed = wintypes.DWORD()
    count = 1024
    while True:
        bases = (ctypes.c_void_p * count)()
        if not psapi.EnumDeviceDrivers(bases, ctypes.sizeof(bases), ctypes.byref(needed)):
            return []
        if needed.value <= ctypes.sizeof(bases):
            break
        count = needed.value // ctypes.sizeof(ctypes.c_void_p) + 16
    paths = []
    buf = ctypes.create_unicode_buffer(1024)
    for base in bases[:needed.value // ctypes.sizeof(ctypes.c_void_p)]:
        if base and psapi.GetDeviceDriverFileNameW(base, buf, len(buf)):
            paths.append(buf.value)
    return paths


def driver_services() -> List[Tuple[str, str, int]]:
    """(service name, image path, start type) of kernel and file system driver services."""
    out = []
    root = r"SYSTEM\CurrentControlSet\Services"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root) as services:
        i = 0
        while True:
            try:
                name = winreg.EnumKey(services, i)
            except OSError:
                break
            i += 1
            try:
                with winreg.OpenKey(services, name) as key:
                    svc_type = winreg.QueryValueEx(key, "Type")[0]
                    if not isinstance(svc_type, int) or svc_type not in (1, 2):
                        continue
                    try:
                        image = winreg.QueryValueEx(key, "ImagePath")[0]
                    except OSError:
                        image = f"System32\\drivers\\{name}.sys"
                    try:
                        start = winreg.QueryValueEx(key, "Start")[0]
                    except OSError:
                        start = -1
                    out.append((name, str(image), start if isinstance(start, int) else -1))
            except OSError:
                continue
    return out


def collect_driver_files() -> List[DriverFile]:
    """Loaded kernel modules + registered driver services + System32\\drivers\\*.sys, one entry per file."""
    files: Dict[str, DriverFile] = {}

    def add(path: str) -> Optional[DriverFile]:
        p = normalize_driver_path(path)
        if not p or not os.path.isfile(p):
            return None
        return files.setdefault(p.lower(), DriverFile(path=p))

    try:
        for name, image, start in driver_services():
            entry = add(image)
            if entry and not entry.service:
                entry.service = name
                entry.start = START_TYPES.get(start, "")
    except OSError as e:
        logging.warning(f"Driver services not readable: {e}")
    try:
        for path in loaded_driver_paths():
            entry = add(path)
            if entry:
                entry.loaded = True
    except OSError as e:
        logging.warning(f"Loaded drivers not readable: {e}")
    drivers_dir = os.path.join(SYSTEM_ROOT, "System32", "drivers")
    try:
        for name in os.listdir(drivers_dir):
            if name.lower().endswith(".sys"):
                add(os.path.join(drivers_dir, name))
    except OSError as e:
        logging.warning(f"{drivers_dir} not readable: {e}")
    return sorted(files.values(), key=lambda d: d.path.lower())


@dataclass
class DriverCheck:
    driver: DriverFile
    info: PEInfo
    reasons: List[str]

    @property
    def flagged(self) -> bool:
        return bool(self.reasons)


def check_drivers(policy: BlocklistPolicy, drivers: List[DriverFile],
                  progress: Optional[Callable[[int, int, str], None]] = None,
                  stop: Optional[Callable[[], bool]] = None) -> List[DriverCheck]:
    results = []
    for n, drv in enumerate(drivers, 1):
        if stop and stop():
            break
        if progress:
            progress(n, len(drivers), drv.path)
        info = inspect_file(drv.path)
        results.append(DriverCheck(drv, info, policy.match(info) if not info.error else []))
    return results

# endregion


# region Windows protection state

@dataclass
class ProtectionState:
    blocklist_setting: Optional[int]    # VulnerableDriverBlocklistEnable, None = not set
    hvci_enabled: bool
    build: int

    @property
    def enforced(self) -> bool:
        """Best estimate of whether Windows currently enforces the blocklist."""
        if self.blocklist_setting == 0:
            return False
        if self.hvci_enabled:
            return True
        if self.blocklist_setting == 1:
            return True
        return self.build >= 22621  # on by default from Windows 11 22H2

    @property
    def summary(self) -> str:
        setting = {None: "not set (Windows default)", 0: "off", 1: "on"}.get(self.blocklist_setting,
                                                                           str(self.blocklist_setting))
        return (f"Windows blocklist setting: {setting}  |  Memory integrity (HVCI): "
                f"{'on' if self.hvci_enabled else 'off'}  |  Enforced: {'yes' if self.enforced else 'NO'}")


def _read_dword(path: str, value: str) -> Optional[int]:
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            data = winreg.QueryValueEx(key, value)[0]
            return data if isinstance(data, int) else None
    except OSError:
        return None


def protection_state() -> ProtectionState:
    return ProtectionState(
        blocklist_setting=_read_dword(r"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable"),
        hvci_enabled=_read_dword(r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios"
                                 r"\HypervisorEnforcedCodeIntegrity", "Enabled") == 1,
        build=getattr(sys.getwindowsversion(), "build", 0) if hasattr(sys, "getwindowsversion") else 0,
    )

# endregion
