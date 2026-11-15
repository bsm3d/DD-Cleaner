"""Saved website passwords from the browsers installed for the current user.

Chromium family (Chrome, Edge, Brave, Vivaldi): the per-user AES key is in "Local State" (wrapped with DPAPI);
each password in the "Login Data" SQLite database is AES-256-GCM (format v10/v11) or, for older entries, a
DPAPI blob. Firefox: the logins are in logins.json, decrypted with the browser's own NSS library.

These are the user's own passwords on their own PC. This module only returns them to the caller to be shown
on screen; it writes nothing except a short-lived copy of the SQLite file (deleted right away, needed only
because the browser keeps the original locked), and it never logs a password, only counts. Reading them needs
the user to be signed in as themselves, which is the case when the program runs elevated under their account.
"""

import base64
import ctypes
import json
import logging
import os
import shutil
import sqlite3
import tempfile
from ctypes import wintypes
from typing import Callable, List, Optional
from pathlib import Path
from urllib.parse import urlsplit

from ddcleaner import folder_security, wincrypt
from ddcleaner.saved_keys import SecretRecord

LOCALAPPDATA = os.environ.get("LOCALAPPDATA", "")
APPDATA = os.environ.get("APPDATA", "")

# name -> path under %LOCALAPPDATA%
CHROMIUM_BROWSERS = [
    ("Chrome", r"Google\Chrome\User Data"),
    ("Edge", r"Microsoft\Edge\User Data"),
    ("Brave", r"BraveSoftware\Brave-Browser\User Data"),
    ("Vivaldi", r"Vivaldi\User Data"),
]
LOGIN_QUERY = "SELECT origin_url, username_value, password_value FROM logins"


def _host(url: str) -> str:
    try:
        return urlsplit(url).netloc or url or "(unknown site)"
    except ValueError:
        return url or "(unknown site)"


# region Chromium

def chromium_user_data_dirs(base: str = LOCALAPPDATA) -> List[tuple]:
    return [(name, os.path.join(base, rel)) for name, rel in CHROMIUM_BROWSERS
            if base and os.path.isdir(os.path.join(base, rel))]


def chromium_master_key(user_data_dir: str, unprotect: Callable = wincrypt.dpapi_unprotect) -> bytes:
    """The AES key shared by a browser's profiles, read from Local State and unwrapped with DPAPI."""
    with open(os.path.join(user_data_dir, "Local State"), encoding="utf-8") as f:
        encrypted = base64.b64decode(json.load(f)["os_crypt"]["encrypted_key"])
    if encrypted[:5] != b"DPAPI":
        raise ValueError("unexpected Local State key format")
    return unprotect(encrypted[5:])


class AppBoundValue(ValueError):
    """Chrome 127+ 'v20' values are wrapped with app-bound encryption (an extra key tied to the browser's own
    elevated service), not just the DPAPI master key: this program cannot decrypt them."""


def decrypt_chromium_value(blob: bytes, key: bytes, unprotect: Callable = wincrypt.dpapi_unprotect) -> str:
    """Decrypt one password_value. v10/v11 = AES-256-GCM with the master key; older = a DPAPI blob."""
    if not blob:
        return ""
    if blob[:3] == b"v20":
        raise AppBoundValue("app-bound encryption (Chrome 127+)")
    if blob[:3] in (b"v10", b"v11"):
        nonce, ciphertext, tag = blob[3:15], blob[15:-16], blob[-16:]
        return wincrypt.aes_gcm_decrypt(key, nonce, ciphertext, tag).decode("utf-8", "replace")
    return unprotect(blob).decode("utf-8", "replace")


def _profiles_with_logins(user_data_dir: str) -> List[str]:
    profiles = []
    for name in sorted(os.listdir(user_data_dir)):
        profile = os.path.join(user_data_dir, name)
        if os.path.isdir(profile) and os.path.isfile(os.path.join(profile, "Login Data")):
            profiles.append(profile)
    return profiles


def _read_login_rows(login_data_path: str) -> List[tuple]:
    """Copy the (locked) SQLite file, and any pending -wal/-journal beside it, to a temporary file read-only,
    then delete the copies."""
    handle, temp = tempfile.mkstemp(suffix=".db")
    os.close(handle)
    extra = []
    try:
        shutil.copy2(login_data_path, temp)
        for suffix in ("-wal", "-journal"):
            source = login_data_path + suffix
            if os.path.isfile(source):
                shutil.copy2(source, temp + suffix)
                extra.append(temp + suffix)
        # Path.as_uri() percent-encodes the path, so a temp folder containing # ? % or a space opens correctly
        connection = sqlite3.connect(Path(temp).as_uri() + "?mode=ro", uri=True)
        try:
            return connection.execute(LOGIN_QUERY).fetchall()
        finally:
            connection.close()
    finally:
        for path in [temp] + extra:
            try:
                os.remove(path)
            except OSError:
                pass


def chromium_logins(name: str, user_data_dir: str) -> List[SecretRecord]:
    try:
        key = chromium_master_key(user_data_dir)
    except (OSError, ValueError, KeyError, wincrypt.CryptoError) as e:
        logging.warning(f"{name}: encryption key not available: {e}")
        return [SecretRecord(name, "(all profiles)", "", "", readable=False, note="encryption key not readable")]
    records = []
    for profile in _profiles_with_logins(user_data_dir):
        label = os.path.basename(profile)
        try:
            rows = _read_login_rows(os.path.join(profile, "Login Data"))
        except (OSError, sqlite3.Error) as e:
            logging.warning(f"{name}/{label}: login database unreadable: {e}")
            continue
        for url, user, blob in rows:
            if not (user or blob):
                continue
            try:
                password, readable, note = decrypt_chromium_value(blob, key), True, ""
            except AppBoundValue:
                password, readable, note = "", False, "app-bound encryption (Chrome 127+), not readable"
            except (wincrypt.CryptoError, ValueError, OSError):
                password, readable, note = "", False, "could not decrypt"
            info = user or ""
            if label != "Default":
                info = f"{info}  ({label})".strip()
            records.append(SecretRecord(name, _host(url), info, password, readable, note))
    return records

# endregion


# region Firefox (NSS)

FIREFOX_PROFILES = r"Mozilla\Firefox\Profiles"
LOAD_WITH_ALTERED_SEARCH_PATH = 0x8
NSS_INIT_READONLY = 0x1  # nss.h: do not write to the profile (no upgrade, no lock files)


class _SECItem(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint), ("data", ctypes.c_void_p), ("len", ctypes.c_uint)]


def firefox_profiles(base: str = APPDATA) -> List[str]:
    root = os.path.join(base, FIREFOX_PROFILES)
    if not os.path.isdir(root):
        return []
    return [os.path.join(root, name) for name in sorted(os.listdir(root))
            if os.path.isfile(os.path.join(root, name, "logins.json"))
            and os.path.isfile(os.path.join(root, name, "key4.db"))]


def parse_firefox_logins(logins_json_text: str) -> List[tuple]:
    data = json.loads(logins_json_text)
    return [(entry.get("hostname", ""), entry.get("encryptedUsername", ""), entry.get("encryptedPassword", ""))
            for entry in data.get("logins", []) if isinstance(entry, dict)]


def _find_firefox_nss() -> Optional[str]:
    for variable in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
        root = os.environ.get(variable)
        if root and os.path.isfile(os.path.join(root, "Mozilla Firefox", "nss3.dll")):
            return os.path.join(root, "Mozilla Firefox")
    return None


def _undecrypted(profile: str, note: str) -> List[SecretRecord]:
    records = []
    path = os.path.join(profile, "logins.json")
    try:
        with open(path, encoding="utf-8") as f:
            logins = parse_firefox_logins(f.read())
    except (OSError, ValueError):
        return []
    for hostname, _user, _password in logins:
        records.append(SecretRecord("Firefox", _host(hostname) if hostname else os.path.basename(profile), "",
                                    "", readable=False, note=note))
    return records


class _Nss:
    """Firefox's NSS library, loaded from its own (administrator-protected) folder, used to decrypt one
    profile's logins. A primary password, or any native failure, leaves the passwords unreadable."""

    def __init__(self, nss_dir: str):
        self.nss_dir = nss_dir
        self.lib = None
        self._handle = None

    def __enter__(self):
        k32 = ctypes.windll.kernel32
        k32.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
        k32.LoadLibraryExW.restype = wintypes.HMODULE
        k32.FreeLibrary.argtypes = [wintypes.HMODULE]
        self._handle = k32.LoadLibraryExW(os.path.join(self.nss_dir, "nss3.dll"), None, LOAD_WITH_ALTERED_SEARCH_PATH)
        if not self._handle:
            raise OSError("nss3.dll could not be loaded")
        try:
            lib = ctypes.CDLL(os.path.join(self.nss_dir, "nss3.dll"), handle=self._handle)
            # restype MUST be set for every pointer-returning call: the ctypes default is c_int, which truncates
            # a 64-bit pointer and crashes the next call that uses it.
            # NSS_InitReadOnly is not exported by every NSS build; NSS_Initialize with NSS_INIT_READONLY is the
            # same read-only init through the general entry point, which is always present.
            lib.NSS_Initialize.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                           ctypes.c_uint32]
            lib.NSS_Initialize.restype = ctypes.c_int
            lib.NSS_Shutdown.restype = ctypes.c_int
            lib.PK11_GetInternalKeySlot.argtypes = []
            lib.PK11_GetInternalKeySlot.restype = ctypes.c_void_p
            lib.PK11_FreeSlot.argtypes = [ctypes.c_void_p]
            lib.PK11_Authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
            lib.PK11_Authenticate.restype = ctypes.c_int
            lib.PK11SDR_Decrypt.argtypes = [ctypes.POINTER(_SECItem), ctypes.POINTER(_SECItem), ctypes.c_void_p]
            lib.PK11SDR_Decrypt.restype = ctypes.c_int
            lib.SECITEM_ZfreeItem.argtypes = [ctypes.POINTER(_SECItem), ctypes.c_int]
        except (OSError, AttributeError):
            k32.FreeLibrary(self._handle)
            raise
        self.lib = lib
        return self

    def __exit__(self, *exc):
        if self.lib is not None:
            try:
                self.lib.NSS_Shutdown()
            except OSError:
                pass
        if self._handle:
            ctypes.windll.kernel32.FreeLibrary(self._handle)
        return False

    def profile_logins(self, profile: str) -> List[SecretRecord]:
        # read-only: Firefox may have the profile open at the same time
        try:
            configdir = ("sql:" + profile).encode("utf-8")
            if self.lib.NSS_Initialize(configdir, b"", b"", b"secmod.db", NSS_INIT_READONLY) != 0:
                return _undecrypted(profile, "NSS could not open the profile")
            try:
                slot = self.lib.PK11_GetInternalKeySlot()
                if slot:
                    authenticated = self.lib.PK11_Authenticate(slot, 1, None) == 0
                    self.lib.PK11_FreeSlot(slot)
                    if not authenticated:
                        return _undecrypted(profile, "protected by a primary password")
                try:
                    with open(os.path.join(profile, "logins.json"), encoding="utf-8") as f:
                        logins = parse_firefox_logins(f.read())
                except (OSError, ValueError):
                    return []
                records = []
                for hostname, enc_user, enc_password in logins:
                    user = self._decrypt(enc_user)
                    password = self._decrypt(enc_password)
                    readable = password is not None
                    records.append(SecretRecord("Firefox", _host(hostname) if hostname else os.path.basename(profile),
                                                user or "", password or "", readable,
                                                "" if readable else "could not decrypt"))
                return records
            finally:
                self.lib.NSS_Shutdown()  # close this profile before the next NSS_Init
        except OSError as e:  # any native failure: never let it take the whole page down
            logging.warning(f"Firefox profile {os.path.basename(profile)} not decrypted: {e}")
            return _undecrypted(profile, "could not decrypt (NSS)")

    def _decrypt(self, b64: str) -> Optional[str]:
        if not b64:
            return ""
        try:
            raw = base64.b64decode(b64)
        except (ValueError, TypeError):
            return None
        buffer = ctypes.create_string_buffer(raw, len(raw))
        item_in = _SECItem(0, ctypes.cast(buffer, ctypes.c_void_p), len(raw))
        item_out = _SECItem()
        if self.lib.PK11SDR_Decrypt(ctypes.byref(item_in), ctypes.byref(item_out), None) != 0:
            return None
        try:
            return ctypes.string_at(item_out.data, item_out.len).decode("utf-8", "replace")
        finally:
            if hasattr(self.lib, "SECITEM_ZfreeItem"):
                self.lib.SECITEM_ZfreeItem(ctypes.byref(item_out), False)


def firefox_logins() -> List[SecretRecord]:
    profiles = firefox_profiles()
    if not profiles:
        return []
    nss_dir = _find_firefox_nss()
    if not nss_dir:
        return [r for p in profiles for r in _undecrypted(p, "Firefox is not installed to decrypt the logins")]
    if folder_security.folder_risk(nss_dir):  # never load a DLL from a folder a standard user can write to
        logging.warning("Firefox folder is not protected; nss3.dll not loaded")
        return [r for p in profiles for r in _undecrypted(p, "Firefox folder not protected; not decrypted")]
    try:
        with _Nss(nss_dir) as nss:
            return [r for profile in profiles for r in nss.profile_logins(profile)]
    except OSError as e:
        logging.warning(f"Firefox NSS unavailable: {e}")
        return [r for p in profiles for r in _undecrypted(p, "NSS could not be loaded")]

# endregion


def browser_logins() -> List[SecretRecord]:
    """Saved passwords from every supported browser. Each browser is isolated: one failing does not stop
    the others. Never logs a password, only how many were read."""
    records: List[SecretRecord] = []
    for name, user_data_dir in chromium_user_data_dirs():
        try:
            records += chromium_logins(name, user_data_dir)
        except Exception as e:  # defensive: a single browser must not break the page
            logging.error(f"{name} passwords unreadable: {e}")
    try:
        records += firefox_logins()
    except Exception as e:
        logging.error(f"Firefox passwords unreadable: {e}")
    with_value = sum(1 for r in records if r.value)
    logging.info(f"Browser passwords read: {len(records)} login(s), {with_value} decrypted")  # counts only
    return records
