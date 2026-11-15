"""Secrets Windows keeps for the user: saved Wi-Fi passwords and the Windows key stored in the firmware.

These are the user's own secrets on their own PC. They are only ever returned to the caller to be shown on screen:
this module writes nothing to disk, and nothing here is logged except how many items were read.
Wi-Fi passwords come from the Windows WLAN API (the same source as 'netsh wlan show profile key=clear',
without parsing translated text and without writing XML files).
"""

import ctypes
import logging
import re
import xml.etree.ElementTree as ET
from ctypes import wintypes
from dataclasses import dataclass
from typing import Callable, List, Optional

from ddcleaner.common import system_dll, winreg
from ddcleaner.system_info import run_powershell

WLAN_PROFILE_GET_PLAINTEXT_KEY = 4
NS = {"p": "http://www.microsoft.com/networking/WLAN/profile/v1"}
KEY_RE = re.compile(r"^[A-Z0-9]{5}(-[A-Z0-9]{5}){4}$")


@dataclass
class SecretRecord:
    """One secret shown on the passwords page. value is the secret ("" when there is none or it is not readable);
    note explains an empty value. Nothing here is ever logged; only counts are."""
    kind: str                 # "Wi-Fi", "Windows key", "License", "Windows credential", "Chrome", "Firefox"...
    name: str                 # SSID, software, credential target, site
    info: str = ""            # security / product / user name
    value: str = ""           # the secret itself
    readable: bool = True      # False: it exists but Windows / the browser would not give it to us
    note: str = ""            # why value is empty (open network, primary password set, binary...)


@dataclass
class WifiProfile:
    name: str
    authentication: str = ""
    encryption: str = ""
    password: str = ""        # "" = open network, enterprise login, or not readable
    readable: bool = True     # False: Windows would not give the key (not elevated)


def parse_profile_xml(xml_text: str) -> WifiProfile:
    """One WLAN profile XML -> WifiProfile. DTDs are refused: the text must be a plain profile."""
    if "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:
        raise ValueError("unexpected DTD in a WLAN profile")
    root = ET.fromstring(xml_text)

    def text(path: str) -> str:
        node = root.find(path, NS)
        return (node.text or "") if node is not None else ""

    profile = WifiProfile(
        name=text("p:name") or text("p:SSIDConfig/p:SSID/p:name"),
        authentication=text("p:MSM/p:security/p:authEncryption/p:authentication"),
        encryption=text("p:MSM/p:security/p:authEncryption/p:encryption"))
    shared = root.find("p:MSM/p:security/p:sharedKey", NS)
    if shared is not None:
        protected = (shared.findtext("p:protected", default="", namespaces=NS) or "").lower() == "true"
        profile.readable = not protected
        profile.password = "" if protected else (shared.findtext("p:keyMaterial", default="", namespaces=NS) or "")
    return profile


# region WLAN API

class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [("InterfaceGuid", GUID), ("Description", ctypes.c_wchar * 256), ("State", wintypes.DWORD)]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [("Count", wintypes.DWORD), ("Index", wintypes.DWORD), ("Items", WLAN_INTERFACE_INFO * 1)]


class WLAN_PROFILE_INFO(ctypes.Structure):
    _fields_ = [("Name", ctypes.c_wchar * 256), ("Flags", wintypes.DWORD)]


class WLAN_PROFILE_INFO_LIST(ctypes.Structure):
    _fields_ = [("Count", wintypes.DWORD), ("Index", wintypes.DWORD), ("Items", WLAN_PROFILE_INFO * 1)]


def _wlan_api():
    api = system_dll("wlanapi")
    api.WlanOpenHandle.argtypes = [wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
                                   ctypes.POINTER(wintypes.HANDLE)]
    api.WlanCloseHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    api.WlanFreeMemory.argtypes = [ctypes.c_void_p]
    api.WlanFreeMemory.restype = None
    api.WlanEnumInterfaces.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    api.WlanGetProfileList.argtypes = [wintypes.HANDLE, ctypes.POINTER(GUID), ctypes.c_void_p,
                                       ctypes.POINTER(ctypes.c_void_p)]
    api.WlanGetProfile.argtypes = [wintypes.HANDLE, ctypes.POINTER(GUID), wintypes.LPCWSTR, ctypes.c_void_p,
                                   ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD),
                                   ctypes.POINTER(wintypes.DWORD)]
    return api


def wifi_profiles() -> List[WifiProfile]:
    """Every saved Wi-Fi profile with its password (needs administrator rights to read the passwords).
    An empty list when the PC has no Wi-Fi adapter."""
    api = _wlan_api()
    handle, version = wintypes.HANDLE(), wintypes.DWORD()
    if api.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle)) != 0:
        return []  # WLAN service not running: no Wi-Fi on this PC
    profiles: List[WifiProfile] = []
    try:
        interfaces = ctypes.c_void_p()
        if api.WlanEnumInterfaces(handle, None, ctypes.byref(interfaces)) != 0:
            return []
        try:
            listing = ctypes.cast(interfaces, ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)).contents
            adapters = (WLAN_INTERFACE_INFO * listing.Count).from_address(
                ctypes.addressof(listing) + WLAN_INTERFACE_INFO_LIST.Items.offset)
            seen = set()
            for adapter in adapters:
                names = ctypes.c_void_p()
                if api.WlanGetProfileList(handle, ctypes.byref(adapter.InterfaceGuid), None, ctypes.byref(names)) != 0:
                    continue
                try:
                    plist = ctypes.cast(names, ctypes.POINTER(WLAN_PROFILE_INFO_LIST)).contents
                    items = (WLAN_PROFILE_INFO * plist.Count).from_address(
                        ctypes.addressof(plist) + WLAN_PROFILE_INFO_LIST.Items.offset)
                    profile_names = [i.Name for i in items]
                finally:
                    api.WlanFreeMemory(names)
                for name in profile_names:
                    if name in seen:
                        continue
                    seen.add(name)
                    xml_ptr, flags, access = ctypes.c_void_p(), wintypes.DWORD(WLAN_PROFILE_GET_PLAINTEXT_KEY), wintypes.DWORD()
                    if api.WlanGetProfile(handle, ctypes.byref(adapter.InterfaceGuid), name, None,
                                          ctypes.byref(xml_ptr), ctypes.byref(flags), ctypes.byref(access)) != 0:
                        profiles.append(WifiProfile(name, readable=False))
                        continue
                    try:
                        profile = parse_profile_xml(ctypes.wstring_at(xml_ptr))
                    except (ET.ParseError, ValueError):
                        profile = WifiProfile(name, readable=False)
                    finally:
                        api.WlanFreeMemory(xml_ptr)
                    profile.name = profile.name or name
                    profiles.append(profile)
        finally:
            api.WlanFreeMemory(interfaces)
    finally:
        api.WlanCloseHandle(handle, None)
    logging.info(f"Saved Wi-Fi profiles read: {len(profiles)}")  # count only, never the passwords
    return sorted(profiles, key=lambda p: p.name.lower())

# endregion


def windows_firmware_key(run: Callable = run_powershell) -> Optional[str]:
    """The Windows product key written in the PC's firmware (OEM machines), or None."""
    data = run("[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
               "ConvertTo-Json -InputObject ([string](Get-CimInstance SoftwareLicensingService).OA3xOriginalProductKey) -Compress")
    key = data.strip() if isinstance(data, str) else ""
    return key if KEY_RE.match(key) else None


# region Software license keys (registry)

# Known vendors whose products store a key in the registry (same roots as the audit script).
LICENSE_ROOTS = [
    ("Office", r"SOFTWARE\Microsoft\Office"),
    ("Office (32-bit)", r"SOFTWARE\WOW6432Node\Microsoft\Office"),
    ("Adobe", r"SOFTWARE\Adobe"),
    ("Adobe (32-bit)", r"SOFTWARE\WOW6432Node\Adobe"),
    ("Autodesk", r"SOFTWARE\Autodesk"),
    ("Autodesk (32-bit)", r"SOFTWARE\WOW6432Node\Autodesk"),
    ("VMware", r"SOFTWARE\VMware, Inc."),
]
LICENSE_VALUE_NAMES = {"productid", "serialnumber", "licensekey", "productkey", "pidkey", "serial", "regkey"}
LICENSE_MAX_DEPTH = 6
LICENSE_MAX_KEYS = 20000
_LICENSE_SHAPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+/=_-]{4,99}$")


def _looks_like_key(value) -> bool:
    return isinstance(value, str) and " " not in value.strip() and bool(_LICENSE_SHAPE.match(value.strip()))


def _walk_license(reg, hive, path: str, label: str, depth: int, counter: list) -> List[SecretRecord]:
    if depth > LICENSE_MAX_DEPTH or counter[0] > LICENSE_MAX_KEYS:
        return []
    counter[0] += 1
    try:
        key = reg.OpenKey(hive, path, 0, reg.KEY_READ | reg.KEY_WOW64_64KEY)
    except OSError:
        return []
    records, subs = [], []
    with key:
        index = 0
        while True:
            try:
                name, value, _vtype = reg.EnumValue(key, index)
            except OSError:
                break
            index += 1
            if name.lower() in LICENSE_VALUE_NAMES and _looks_like_key(value):
                product = path.split("\\")[-1] or label
                records.append(SecretRecord("License", label, product, value.strip()))
        index = 0
        while True:
            try:
                subs.append(reg.EnumKey(key, index))
            except OSError:
                break
            index += 1
    for sub in subs:
        records += _walk_license(reg, hive, f"{path}\\{sub}", label, depth + 1, counter)
    return records


def software_license_keys(reg=winreg) -> List[SecretRecord]:
    """Product keys and serials stored by Office, Adobe, Autodesk and VMware. Deduplicated by (vendor, key)."""
    seen, out = set(), []
    for label, root in LICENSE_ROOTS:
        counter = [0]  # one budget per vendor root: a large Office tree must not starve Adobe/Autodesk/VMware
        for record in _walk_license(reg, reg.HKEY_LOCAL_MACHINE, root, label, 0, counter):
            marker = (record.name, record.value)
            if marker not in seen:
                seen.add(marker)
                out.append(record)
    logging.info(f"Software license keys found: {len(out)}")  # count only, never the keys
    return out

# endregion


# region Windows Credential Manager

CRED_TYPE_GENERIC = 1
CRED_TYPE_DOMAIN_PASSWORD = 2


class _CREDENTIAL(ctypes.Structure):
    _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD), ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR), ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD), ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
                ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p), ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR)]


def _enumerate_credentials() -> List[dict]:
    """Every credential saved for the current user (Credential Manager). The blob is returned decrypted
    because this runs in the owner's own session."""
    advapi = system_dll("advapi32")
    advapi.CredEnumerateW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                      ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(_CREDENTIAL)))]
    advapi.CredEnumerateW.restype = wintypes.BOOL
    advapi.CredFree.argtypes = [ctypes.c_void_p]
    count = wintypes.DWORD()
    array = ctypes.POINTER(ctypes.POINTER(_CREDENTIAL))()
    if not advapi.CredEnumerateW(None, 0, ctypes.byref(count), ctypes.byref(array)):
        return []  # ERROR_NOT_FOUND when the vault is empty
    results = []
    try:
        for i in range(count.value):
            c = array[i].contents
            blob = ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize) if c.CredentialBlobSize else b""
            results.append({"target": c.TargetName or "", "user": c.UserName or "", "type": int(c.Type), "blob": blob})
    finally:
        advapi.CredFree(array)
    return results


def _looks_utf16(blob: bytes) -> bool:
    """A blob of UTF-16-LE text (the usual Credential Manager format) has a zero high byte in most code units;
    the same bytes read as UTF-16 when they are really UTF-8 would not."""
    if len(blob) < 2 or len(blob) % 2:
        return False
    highs = blob[1::2]
    return sum(1 for b in highs if b == 0) >= len(highs) * 0.6


def _decode_cred_blob(blob: bytes, cred_type: int):
    """(secret, readable, note). Domain passwords are never returned in clear; generic blobs are usually UTF-16,
    sometimes UTF-8, sometimes raw bytes."""
    if not blob:
        return "", True, "(no secret stored)"
    if cred_type == CRED_TYPE_DOMAIN_PASSWORD:
        return "", False, "domain password (not retrievable in clear)"
    if _looks_utf16(blob):
        try:
            text = blob.decode("utf-16-le").rstrip("\x00")
            if text and text.isprintable():
                return text, True, ""
        except UnicodeDecodeError:
            pass
    try:
        text = blob.decode("utf-8")
        if text and text.isprintable():
            return text, True, ""
    except UnicodeDecodeError:
        pass
    return "", False, "binary secret"


def credential_manager_entries(enumerate_fn: Callable = _enumerate_credentials) -> List[SecretRecord]:
    records = []
    for c in enumerate_fn():
        secret, readable, note = _decode_cred_blob(c["blob"], c["type"])
        records.append(SecretRecord("Windows credential", c["target"], c["user"], secret, readable, note))
    logging.info(f"Credential Manager entries read: {len(records)}")  # count only
    return records

# endregion


def collect_secrets(wifi: bool = True, windows_key: bool = True, licenses: bool = True,
                    credentials: bool = True, browsers: bool = True) -> List[SecretRecord]:
    """Gather every requested kind of secret into one list. A source that fails is logged and skipped, so one
    unreadable store never hides the others. Only counts are logged, never the secrets themselves."""
    records: List[SecretRecord] = []

    def safe(label, fn):
        try:
            return fn()
        except Exception as e:  # defensive: one broken source must not break the page
            logging.error(f"{label} unreadable: {e}")
            return []

    if wifi:
        for p in safe("Wi-Fi", wifi_profiles):
            note = "" if p.password else ("not readable" if not p.readable else "open or enterprise network")
            records.append(SecretRecord("Wi-Fi", p.name, " / ".join(x for x in (p.authentication, p.encryption) if x),
                                        p.password, p.readable, note))
    if windows_key:
        key = safe("Windows key", windows_firmware_key)
        if key:
            records.append(SecretRecord("Windows key", "Stored in the firmware", "OEM", key))
    if licenses:
        records += safe("License keys", software_license_keys)
    if credentials:
        records += safe("Credential Manager", credential_manager_entries)
    if browsers:
        from ddcleaner import browser_passwords  # lazy: avoids a circular import at module load
        records += safe("Browser passwords", browser_passwords.browser_logins)

    with_value = sum(1 for r in records if r.value)
    logging.info(f"Secrets collected: {len(records)} item(s), {with_value} with a readable secret")
    return records
