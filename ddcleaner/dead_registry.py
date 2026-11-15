"""Registry entries of programs that are gone: dead uninstall entries, App Paths, startup entries, cached traces,
plus a wildcard search of keys, value names and value data.

Searching is read-only. Deleting exports a .reg backup of every key it is about to change, only touches keys
under SOFTWARE, and refuses core Windows keys. Keys are read and written in the 64-bit view; what 32-bit
programs register sits under SOFTWARE\\WOW6432Node.
"""

import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set, Tuple

from ddcleaner import startup
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM_ROOT, SYSTEM32, data_dir, safe_environment, sys_exe, winreg
from ddcleaner.garbage import compile_patterns

SEARCH_LIMIT = 3000
MAX_DEPTH = 64

CAT_UNINSTALL = "Uninstall entry"
CAT_APP_PATH = "App Paths entry"
CAT_STARTUP = "Startup entry"
CAT_MUI = "Program name cache"
CAT_COMPAT = "Compatibility entry"
CAT_SHARED = "Shared DLL entry"
CAT_KEY, CAT_VALUE_NAME, CAT_VALUE_DATA = "Key name", "Value name", "Value data"

CURRENT = r"Microsoft\Windows\CurrentVersion"
UNINSTALL_PATHS = [("HKLM", rf"SOFTWARE\{CURRENT}\Uninstall"),
                   ("HKLM", rf"SOFTWARE\WOW6432Node\{CURRENT}\Uninstall"),
                   ("HKCU", rf"SOFTWARE\{CURRENT}\Uninstall")]
APP_PATHS = [("HKLM", rf"SOFTWARE\{CURRENT}\App Paths"),
             ("HKLM", rf"SOFTWARE\WOW6432Node\{CURRENT}\App Paths"),
             ("HKCU", rf"SOFTWARE\{CURRENT}\App Paths")]
MUI_CACHE = ("HKCU", r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache")
COMPAT_KEYS = [("HKCU", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"),
               ("HKCU", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted"),
               ("HKCU", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"),
               ("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers")]
SHARED_DLLS = [("HKLM", rf"SOFTWARE\{CURRENT}\SharedDLLs"), ("HKLM", rf"SOFTWARE\WOW6432Node\{CURRENT}\SharedDLLs")]
SEARCH_ROOTS = [("HKCU", "SOFTWARE"), ("HKLM", "SOFTWARE")]

# Whole keys that are never deleted, and trees that are never touched at all (compared in lower case, with the
# WOW6432Node level removed)
PROTECTED_KEYS = {
    "software", "software\\classes", "software\\classes\\clsid", "software\\classes\\interface",
    "software\\classes\\typelib", "software\\classes\\appid", "software\\clients", "software\\microsoft",
    "software\\microsoft\\windows", "software\\microsoft\\windows\\currentversion",
    "software\\microsoft\\windows\\currentversion\\run", "software\\microsoft\\windows\\currentversion\\runonce",
    "software\\microsoft\\windows\\currentversion\\uninstall", "software\\microsoft\\windows\\currentversion\\app paths",
    "software\\microsoft\\windows\\currentversion\\explorer", "software\\microsoft\\windows nt",
    "software\\microsoft\\windows nt\\currentversion", "software\\policies", "software\\registeredapplications",
}
BLOCKED_PREFIXES = (
    "software\\microsoft\\windows nt\\currentversion\\winlogon",
    "software\\microsoft\\windows nt\\currentversion\\svchost",
    "software\\microsoft\\windows nt\\currentversion\\profilelist",
    "software\\microsoft\\windows nt\\currentversion\\image file execution options",
    "software\\microsoft\\cryptography", "software\\microsoft\\windows\\currentversion\\policies",
    "software\\microsoft\\windows\\currentversion\\component based servicing",
    "software\\microsoft\\windows defender", "software\\microsoft\\security center", "software\\policies",
)


def hives(reg=winreg) -> Dict[str, object]:
    return {"HKLM": reg.HKEY_LOCAL_MACHINE, "HKCU": reg.HKEY_CURRENT_USER}


@dataclass
class RegEntry:
    hive: str                    # HKLM | HKCU
    key: str                     # key path below the hive
    value: Optional[str] = None  # value name, None when the entry is the key itself
    category: str = ""
    reason: str = ""
    data: str = ""               # the program name, or the value data, for display
    confidence: str = ""         # High | Medium for guesses (leftovers, history), '' when the entry is certain

    @property
    def location(self) -> str:
        return f"{self.hive}\\{self.key}"

    @property
    def kind(self) -> str:
        return "Key" if self.value is None else "Value"

    @property
    def display_name(self) -> str:
        return self.key.rsplit("\\", 1)[-1] if self.value is None else (self.value or "(default)")


@dataclass
class RegScan:
    entries: List[RegEntry]
    truncated: bool = False
    keys_seen: int = 0


# region Reading helpers

def _open(reg, hive: str, path: str, write: bool = False):
    access = reg.KEY_READ | reg.KEY_WOW64_64KEY | (reg.KEY_SET_VALUE if write else 0)
    return reg.OpenKey(hives(reg)[hive], path, 0, access)


def _subkeys(reg, key) -> List[str]:
    names, index = [], 0
    while True:
        try:
            names.append(reg.EnumKey(key, index))
        except OSError:
            return names
        index += 1


def _values(reg, key) -> List[Tuple[str, object, int]]:
    found, index = [], 0
    while True:
        try:
            found.append(tuple(reg.EnumValue(key, index)))
        except OSError:
            return found
        index += 1


def _open_or_none(reg, hive: str, path: str):
    try:
        return _open(reg, hive, path)
    except OSError:
        return None

# endregion


# region Is the file still there?

OK, MISSING, UNKNOWN = "ok", "missing", "unknown"
_PROGRAM_EXT = r"(?:exe|bat|cmd|com|msi|ico|dll|lnk|cpl|scr)"


def _judgeable(path: str) -> bool:
    """An absolute local path on a drive that is connected (an unplugged disk proves nothing)."""
    if not path or not os.path.isabs(path) or path.startswith("\\\\"):
        return False
    drive = os.path.splitdrive(path)[0]
    return bool(drive) and os.path.isdir(drive + "\\")


def check_target(command: str, is_folder: bool = False) -> Tuple[str, str]:
    """(path, state) for the program a command line runs. OK: it exists. MISSING: it is gone from a connected drive.
    UNKNOWN: relative, on a network or disconnected drive, or not understood. Files inside Windows are UNKNOWN
    (msiexec and friends say nothing about the program)."""
    command = os.path.expandvars((command or "").strip())
    if not command:
        return "", UNKNOWN
    if is_folder:
        candidate = command.strip('"')
    elif command.startswith('"'):
        end = command.find('"', 1)
        candidate = command[1:end] if end > 0 else command[1:]
    else:
        found = startup.command_path(command)
        if found:
            candidate = found
        else:
            match = re.match(rf"([A-Za-z]:\\.*?\.{_PROGRAM_EXT})(?=[\s,\"]|$)", command, re.I)
            candidate = match.group(1) if match else ""
    candidate = candidate.strip()
    if not candidate or not _judgeable(candidate):
        return candidate, UNKNOWN
    if os.path.normcase(candidate).startswith(os.path.normcase(SYSTEM_ROOT) + "\\"):
        return candidate, UNKNOWN
    exists = os.path.isdir(candidate) if is_folder else (os.path.exists(candidate) or bool(startup.command_path(candidate)))
    return candidate, OK if exists else MISSING

# endregion


# region Dead program entries

def dead_uninstall_entries(reg=winreg) -> List[RegEntry]:
    """Add/Remove Programs entries whose program, uninstaller and icon are all gone."""
    found = []
    for hive, base in UNINSTALL_PATHS:
        root = _open_or_none(reg, hive, base)
        if root is None:
            continue
        with root:
            names = _subkeys(reg, root)
        for sub in names:
            key = _open_or_none(reg, hive, f"{base}\\{sub}")
            if key is None:
                continue
            with key:
                values = {n: v for n, v, _t in _values(reg, key) if isinstance(v, str)}
            title = values.get("DisplayName", "").strip()
            if not title:
                continue
            checks = []
            if values.get("InstallLocation", "").strip():
                checks.append(check_target(values["InstallLocation"], is_folder=True))
            for name in ("UninstallString", "QuietUninstallString"):
                if values.get(name, "").strip():
                    checks.append(check_target(values[name]))
            judged = [c for c in checks if c[1] != UNKNOWN]
            # a missing icon alone proves nothing: it only counts next to a missing folder or uninstaller
            icon = re.sub(r",\s*-?\d+$", "", values.get("DisplayIcon", "").strip())
            icon_check = check_target(icon) if icon else ("", UNKNOWN)
            if judged and icon_check[1] != UNKNOWN:
                judged.append(icon_check)
            if judged and all(state == MISSING for _p, state in judged):
                found.append(RegEntry(hive, f"{base}\\{sub}", None, CAT_UNINSTALL,
                                      f"Program, uninstaller and icon are gone ({judged[0][0]})", title))
    return found


def dead_app_paths(reg=winreg) -> List[RegEntry]:
    found = []
    for hive, base in APP_PATHS:
        root = _open_or_none(reg, hive, base)
        if root is None:
            continue
        with root:
            names = _subkeys(reg, root)
        for sub in names:
            key = _open_or_none(reg, hive, f"{base}\\{sub}")
            if key is None:
                continue
            with key:
                default = next((v for n, v, _t in _values(reg, key) if n == "" and isinstance(v, str)), "")
            path, state = check_target(default)
            if state == MISSING:
                found.append(RegEntry(hive, f"{base}\\{sub}", None, CAT_APP_PATH, f"Program not found: {path}", sub))
    return found


def dead_startup_entries(reg=winreg) -> List[RegEntry]:
    found = []
    for hive, key_path, _scope, view32 in startup.RUN_KEYS:
        path = key_path.replace("SOFTWARE\\", "SOFTWARE\\WOW6432Node\\", 1) if view32 else key_path
        key = _open_or_none(reg, hive, path)
        if key is None:
            continue
        with key:
            values = _values(reg, key)
        for name, value, _t in values:
            if isinstance(value, str):
                target, state = check_target(value)
                if state == MISSING:
                    found.append(RegEntry(hive, path, name, CAT_STARTUP, f"Program not found: {target}", value))
    return found


def _dead_value_names(reg, hive: str, path: str, category: str, name_to_path: Callable[[str], str]) -> List[RegEntry]:
    key = _open_or_none(reg, hive, path)
    if key is None:
        return []
    with key:
        values = _values(reg, key)
    found = []
    for name, _value, _t in values:
        candidate = name_to_path(name)
        if candidate:
            target, state = check_target(f'"{candidate}"')
            if state == MISSING:
                found.append(RegEntry(hive, path, name, category, f"File not found: {target}", ""))
    return found


def _mui_path(name: str) -> str:
    match = re.match(r"^(.*?\.exe)\.(?:FriendlyAppName|ApplicationCompany)$", name, re.I)
    return match.group(1) if match else ""


def dead_cached_traces(reg=winreg) -> List[RegEntry]:
    """Names of programs kept by Windows after the program is gone: display-name cache, compatibility
    assistant, compatibility flags, shared DLL counters."""
    found = _dead_value_names(reg, *MUI_CACHE, CAT_MUI, _mui_path)
    for hive, path in COMPAT_KEYS:
        found += _dead_value_names(reg, hive, path, CAT_COMPAT, lambda n: n if re.match(r"^[A-Za-z]:\\", n) else "")
    for hive, path in SHARED_DLLS:
        found += _dead_value_names(reg, hive, path, CAT_SHARED, lambda n: n if re.match(r"^[A-Za-z]:\\", n) else "")
    return found


def scan_dead(reg=winreg, stop: Callable[[], bool] = lambda: False,
              progress: Optional[Callable[[str], None]] = None) -> RegScan:
    entries = []
    steps = [("Add/Remove Programs entries", dead_uninstall_entries), ("App Paths", dead_app_paths),
             ("startup entries", dead_startup_entries), ("cached program traces", dead_cached_traces)]
    for label, function in steps:
        if stop():
            break
        if progress:
            progress(f"Checking {label}...")
        entries += function(reg)
    entries.sort(key=lambda e: (e.category, e.location.lower(), (e.value or "").lower()))
    return RegScan(entries)


def installed_markers(reg=winreg) -> Set[str]:
    """Normalized names an installed program can be recognised by (title, publisher, folder, key name, App Paths).
    Used to tell which AppData / ProgramData folders still belong to something."""
    def norm(text: str) -> str:
        return re.sub(r"[^a-z0-9]", "", (text or "").lower())

    markers: Set[str] = set()

    def add(text: str, words: bool = False):
        if norm(text):
            markers.add(norm(text))
        if words:
            markers.update(norm(w) for w in re.split(r"[^A-Za-z0-9]+", text) if len(norm(w)) >= 4)

    for hive, base in UNINSTALL_PATHS:
        root = _open_or_none(reg, hive, base)
        if root is None:
            continue
        with root:
            names = _subkeys(reg, root)
        for sub in names:
            key = _open_or_none(reg, hive, f"{base}\\{sub}")
            if key is None:
                continue
            with key:
                values = {n: v for n, v, _t in _values(reg, key) if isinstance(v, str)}
            add(sub)
            add(values.get("DisplayName", ""), words=True)
            add(values.get("Publisher", ""), words=True)
            location = values.get("InstallLocation", "").strip().strip('"').rstrip("\\")
            if location:
                add(os.path.basename(location))
            for field_name in ("UninstallString", "DisplayIcon"):
                target, _state = check_target(re.sub(r",\s*-?\d+$", "", values.get(field_name, "")))
                if target:
                    add(os.path.basename(os.path.dirname(target)))
    for hive, base in APP_PATHS:
        root = _open_or_none(reg, hive, base)
        if root is not None:
            with root:
                for sub in _subkeys(reg, root):
                    add(os.path.splitext(sub)[0])
    markers.discard("")
    return {m for m in markers if len(m) >= 3}

# endregion


# region More presets: orphans, history, COM, leftovers of old programs

HISTORY_KEYS = [
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", "Run box history"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths", "Explorer address bar history"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", "Recent documents"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery", "Explorer search history"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU", "Open and Save dialog history"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU", "Last folders used by programs"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist", "Program launch counters"),
    (r"SOFTWARE\Microsoft\Internet Explorer\TypedURLs", "Typed web addresses"),
]
STARTUP_APPROVED = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
CLSID_ROOTS = [("HKLM", r"SOFTWARE\Classes\CLSID"), ("HKLM", r"SOFTWARE\WOW6432Node\Classes\CLSID"),
               ("HKCU", r"SOFTWARE\Classes\CLSID")]
VENDOR_ROOTS = [("HKCU", "SOFTWARE"), ("HKLM", "SOFTWARE"), ("HKLM", r"SOFTWARE\WOW6432Node")]
# vendor-level keys that belong to Windows or are shared plumbing, never reported as a program's leftovers
SKIP_VENDOR_KEYS = {"classes", "policies", "wow6432node", "clients", "registeredapplications", "odbc", "partner", "setup",
                    "appdatalow", "cryptography", "mozillaplugins", "dolby", "intel", "nvidia corporation", "realtek",
                    "amd", "asus", "khronos", "vulkankhr", "oem", "defaultuserenvironment"}
GUID_NAME = re.compile(r"^\{?[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\}?$", re.I)
OLD_VENDOR_DAYS = 180
SEARCH_COM_LIMIT = 2000
VENDOR_LIMIT = 500
CAT_HISTORY, CAT_APPROVED, CAT_COM, CAT_VENDOR = ("Usage history", "Orphan startup toggle", "COM registration",
                                                 "Leftover of an old program")
HIGH, MEDIUM = "High", "Medium"


def usage_history(reg=winreg) -> List[RegEntry]:
    """History lists Windows keeps and recreates by itself: useless to keep, harmless to delete."""
    found = []
    for path, label in HISTORY_KEYS:
        key = _open_or_none(reg, "HKCU", path)
        if key is None:
            continue
        with key:
            subkeys, values = len(_subkeys(reg, key)), len(_values(reg, key))
        if subkeys or values:
            found.append(RegEntry("HKCU", path, None, CAT_HISTORY, f"{label}: Windows recreates it when needed",
                                  f"{values} value(s), {subkeys} sub-key(s)", HIGH))
    return found


def orphan_startup_toggles(reg=winreg) -> List[RegEntry]:
    """Task Manager 'Startup' on/off switches whose startup entry no longer exists."""
    run_keys = {"Run": rf"SOFTWARE\{CURRENT}\Run", "Run32": rf"SOFTWARE\WOW6432Node\{CURRENT}\Run"}
    folders = {"HKLM": startup._known_folder(startup.CSIDL_COMMON_STARTUP), "HKCU": startup._known_folder(startup.CSIDL_STARTUP)}
    found = []
    for hive in ("HKCU", "HKLM"):
        for sub in ("Run", "Run32", "StartupFolder"):
            path = f"{STARTUP_APPROVED}\\{sub}"
            toggles = _open_or_none(reg, hive, path)
            if toggles is None:
                continue
            with toggles:
                names = [n for n, _v, _t in _values(reg, toggles)]
            if sub == "StartupFolder":
                existing = {n.lower() for n in os.listdir(folders[hive])} if folders[hive] and os.path.isdir(folders[hive]) else None
            else:
                run = _open_or_none(reg, hive, run_keys[sub])
                existing = set()
                if run is not None:
                    with run:
                        existing = {n.lower() for n, _v, _t in _values(reg, run)}
            if existing is None:
                continue
            for name in names:
                if name.lower() not in existing:
                    found.append(RegEntry(hive, path, name, CAT_APPROVED, "No startup entry of this name exists any more",
                                          "", HIGH))
    return found


def dead_com_registrations(reg=winreg, stop: Callable[[], bool] = lambda: False, limit: int = SEARCH_COM_LIMIT) -> List[RegEntry]:
    """COM classes whose program file is gone (the classic leftover of an uninstalled program)."""
    found = []
    for hive, base in CLSID_ROOTS:
        root = _open_or_none(reg, hive, base)
        if root is None:
            continue
        with root:
            guids = _subkeys(reg, root)
        for guid in guids:
            if stop() or len(found) >= limit:
                return found
            states = []
            for server in ("InprocServer32", "LocalServer32"):
                key = _open_or_none(reg, hive, f"{base}\\{guid}\\{server}")
                if key is None:
                    continue
                with key:
                    default = next((v for n, v, _t in _values(reg, key) if n == "" and isinstance(v, str)), "")
                states.append(check_target(default.strip()) if default.strip() else ("", UNKNOWN))
            if states and all(state == MISSING for _p, state in states):
                found.append(RegEntry(hive, f"{base}\\{guid}", None, CAT_COM, f"Registered file not found: {states[0][0]}",
                                      guid, MEDIUM))
    return found


def _paths_inside(reg, hive: str, path: str, depth: int = 0, budget: Optional[List[int]] = None) -> Tuple[int, int]:
    """(existing, missing) program paths found in the string values of a key and its sub-keys (shallow)."""
    budget = [300] if budget is None else budget
    key = _open_or_none(reg, hive, path)
    if key is None:
        return 0, 0
    with key:
        values = _values(reg, key)
        children = _subkeys(reg, key) if depth < 2 else []
    ok = missing = 0
    for _n, value, _t in values:
        if budget[0] <= 0:
            break
        if isinstance(value, str) and re.match(r'^"?[A-Za-z]:\\', value.strip()):
            budget[0] -= 1
            state = check_target(value, is_folder=value.strip().endswith("\\"))[1]
            ok += state == OK
            missing += state == MISSING
    for child in children:
        if budget[0] <= 0:
            break
        a, b = _paths_inside(reg, hive, f"{path}\\{child}", depth + 1, budget)
        ok, missing = ok + a, missing + b
    return ok, missing


def orphan_vendor_keys(reg=winreg, markers: Optional[Set[str]] = None, stop: Callable[[], bool] = lambda: False,
                       now: Optional[float] = None, limit: int = VENDOR_LIMIT) -> List[RegEntry]:
    """Vendor keys (HKCU\\SOFTWARE\\X, HKLM\\SOFTWARE\\X) that no installed program claims.

    High: files named inside are all gone. Medium: no file named, no program matches, untouched for 180 days.
    A key that names a file that still exists, or that matches an installed program, is never listed."""
    from ddcleaner import garbage
    markers = installed_markers(reg) if markers is None else markers
    now = time.time() if now is None else now
    found = []
    for hive, base in VENDOR_ROOTS:
        root = _open_or_none(reg, hive, base)
        if root is None:
            continue
        with root:
            names = _subkeys(reg, root)
        for name in names:
            low = name.lower()
            if stop() or len(found) >= limit:
                return found
            norm = re.sub(r"[^a-z0-9]", "", low)
            if (low in SKIP_VENDOR_KEYS or GUID_NAME.match(name) or norm.startswith(garbage.KEEP_PREFIXES)
                    or garbage.is_covered(name, markers)):
                continue
            path = f"{base}\\{name}"
            key = _open_or_none(reg, hive, path)
            if key is None:
                continue
            with key:
                last_write = reg.QueryInfoKey(key)[2]
            age_days = (now - (last_write / 1e7 - 11644473600)) / 86400
            ok, missing = _paths_inside(reg, hive, path)
            if ok:
                continue  # it names a file that is still there: in use
            if missing:
                found.append(RegEntry(hive, path, None, CAT_VENDOR,
                                      f"No installed program matches; the {missing} file(s) it names are gone", name, HIGH))
            elif age_days >= OLD_VENDOR_DAYS:
                found.append(RegEntry(hive, path, None, CAT_VENDOR,
                                      f"No installed program matches; untouched for {int(age_days)} days", name, MEDIUM))
    return found


@dataclass(frozen=True)
class RegPreset:
    id: str
    label: str
    description: str
    risk: str                       # Safe | Check | Review
    run: Callable


PRESETS: List[RegPreset] = [
    RegPreset("uninstall", "Dead uninstall entries", "Programs listed in Add/Remove Programs whose files, uninstaller and icon are gone.", "Safe", lambda reg, stop: dead_uninstall_entries(reg)),
    RegPreset("app_paths", "Dead App Paths", "Shortcuts to programs (Run box, Start) whose program is gone.", "Safe", lambda reg, stop: dead_app_paths(reg)),
    RegPreset("startup", "Dead startup entries", "Run keys that start a program which no longer exists.", "Safe", lambda reg, stop: dead_startup_entries(reg)),
    RegPreset("traces", "Cached traces of removed programs", "Program name cache, compatibility flags and shared-DLL counters of files that are gone.", "Safe", lambda reg, stop: dead_cached_traces(reg)),
    RegPreset("approved", "Orphan startup toggles", "On/off switches of Task Manager's Startup tab for entries that no longer exist.", "Safe", lambda reg, stop: orphan_startup_toggles(reg)),
    RegPreset("history", "Usage history lists", "Recent documents, Run box, Explorer address bar and searches, Open/Save dialogs, launch counters. Windows recreates them.", "Safe", lambda reg, stop: usage_history(reg)),
    RegPreset("com", "COM registrations with a missing file", "Classes registered by programs that were removed. Thousands can pile up; deleting a live one breaks that program, so check the file path.", "Check", lambda reg, stop: dead_com_registrations(reg, stop)),
    RegPreset("vendors", "Leftovers of old programs", "Vendor keys (HKCU/HKLM SOFTWARE) that no installed program claims. Portable tools you copied yourself look the same: read each line.", "Review", lambda reg, stop: orphan_vendor_keys(reg, None, stop)),
]
DEFAULT_PRESETS = [p.id for p in PRESETS if p.risk == "Safe"]


def scan_presets(ids: List[str], reg=winreg, stop: Callable[[], bool] = lambda: False,
                 progress: Optional[Callable[[str], None]] = None) -> "RegScan":
    entries: List[RegEntry] = []
    chosen = {i for i in ids}
    for preset in PRESETS:
        if preset.id not in chosen:
            continue
        if stop():
            break
        if progress:
            progress(f"Checking: {preset.label}...")
        entries += preset.run(reg, stop)
    entries.sort(key=lambda e: (e.category, e.location.lower(), (e.value or "").lower()))
    return RegScan(entries)

# endregion


# region Wildcard search

def search_registry(patterns: str, names: bool = True, value_names: bool = True, value_data: bool = True,
                    reg=winreg, stop: Callable[[], bool] = lambda: False,
                    progress: Optional[Callable[[str], None]] = None, limit: int = SEARCH_LIMIT) -> RegScan:
    """Keys, value names and string value data matching a word or wildcard, under HKCU\\SOFTWARE and
    HKLM\\SOFTWARE. A matching key is listed once, not its content."""
    match = compile_patterns(patterns)
    scan = RegScan([])
    stack = [(h, p, 0) for h, p in reversed(SEARCH_ROOTS)]
    while stack and not stop():
        hive, path, depth = stack.pop()
        key = _open_or_none(reg, hive, path)
        if key is None:
            continue
        scan.keys_seen += 1
        if progress and scan.keys_seen % 2000 == 0:
            progress(f"Searching the registry... {scan.keys_seen} keys looked at, {len(scan.entries)} found")
        with key:
            children = _subkeys(reg, key)
            values = _values(reg, key) if (value_names or value_data) else []
        for name, value, _t in values:
            shown = " ".join(value) if isinstance(value, list) else value if isinstance(value, str) else ""
            if value_names and match(name, f"{hive}\\{path}\\{name}"):
                scan.entries.append(RegEntry(hive, path, name, CAT_VALUE_NAME, "Value name matches", shown[:200]))
            elif value_data and shown and match(shown, shown):
                scan.entries.append(RegEntry(hive, path, name, CAT_VALUE_DATA, "Value data matches", shown[:200]))
        subfolders = []
        for child in children:
            child_path = f"{path}\\{child}"
            if names and match(child, f"{hive}\\{child_path}"):
                scan.entries.append(RegEntry(hive, child_path, None, CAT_KEY, "Key name matches"))
            elif depth < MAX_DEPTH:
                subfolders.append((hive, child_path, depth + 1))
        stack.extend(reversed(subfolders))
        if len(scan.entries) >= limit:
            scan.truncated = True
            scan.entries = scan.entries[:limit]
            break
    return scan

# endregion


# region Deleting

def _normal_key(path: str) -> str:
    return path.lower().replace("software\\wow6432node\\", "software\\", 1).rstrip("\\")


def protected_reason(entry: RegEntry) -> str:
    """Why this entry must not be deleted from here ('' when it is allowed)."""
    if entry.hive not in ("HKLM", "HKCU"):
        return "Unknown registry hive"
    key = _normal_key(entry.key)
    if key != "software" and not key.startswith("software\\"):
        return "Only keys under SOFTWARE can be deleted here"
    if any(key == p or key.startswith(p + "\\") for p in BLOCKED_PREFIXES):
        return "Security or system area"
    if entry.value is None and (key in PROTECTED_KEYS or key.count("\\") < 1 or key.endswith("\\wow6432node")):
        return "Core Windows key"
    return ""


def backup_dir() -> str:
    return os.path.join(data_dir(), "garbage_backups")


def export_key(hive: str, path: str, file: str) -> str:
    """Export a key to a .reg file with reg.exe. Returns '' or an error message."""
    try:
        completed = subprocess.run(
            [sys_exe("reg.exe"), "export", f"{hive}\\{path}", file, "/y", "/reg:64"], capture_output=True, text=True,
            errors="replace", timeout=120, cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)
    except (subprocess.SubprocessError, OSError) as e:
        return str(e)
    if completed.returncode != 0:
        return (completed.stderr or completed.stdout or "reg export failed").strip()[:200]
    return ""


def _delete_key_tree(reg, hive: str, path: str, depth: int = 0):
    if depth > MAX_DEPTH:
        raise OSError("Key tree too deep")
    with _open(reg, hive, path) as key:
        children = _subkeys(reg, key)
    for child in children:
        _delete_key_tree(reg, hive, f"{path}\\{child}", depth + 1)
    reg.DeleteKeyEx(hives(reg)[hive], path, reg.KEY_WOW64_64KEY, 0)


@dataclass
class RegDeleteResult:
    deleted: List[RegEntry] = field(default_factory=list)
    failed: List[Tuple[RegEntry, str]] = field(default_factory=list)
    backups: List[str] = field(default_factory=list)


def _safe_file_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text)[-60:]


def delete_entries(entries: List[RegEntry], folder: Optional[str] = None, reg=winreg,
                   export: Callable[[str, str, str], str] = export_key,
                   stop: Callable[[], bool] = lambda: False) -> RegDeleteResult:
    """Delete exactly these keys and values. Each key about to change is exported to a .reg file first (double-click
    it to put things back); an entry whose backup failed is left alone."""
    result = RegDeleteResult()
    folder = folder or backup_dir()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backed_up: Dict[Tuple[str, str], str] = {}  # (hive, key) -> '' or error
    for index, entry in enumerate(entries):
        if stop():
            result.failed.append((entry, "Stopped"))
            continue
        reason = protected_reason(entry)
        if reason:
            result.failed.append((entry, reason))
            continue
        probe = _open_or_none(reg, entry.hive, entry.key)
        if probe is None:
            result.deleted.append(entry)  # already gone
            continue
        with probe:
            pass
        slot = (entry.hive, entry.key.lower())
        if slot not in backed_up:
            try:
                os.makedirs(folder, exist_ok=True)
                file = os.path.join(folder, f"{stamp}_{len(backed_up) + 1:03d}_{entry.hive}_{_safe_file_name(entry.key)}.reg")
                backed_up[slot] = export(entry.hive, entry.key, file)
                if not backed_up[slot]:
                    result.backups.append(file)
            except OSError as e:
                backed_up[slot] = str(e)
        if backed_up[slot]:
            result.failed.append((entry, f"Backup failed, nothing deleted: {backed_up[slot]}"))
            continue
        try:
            if entry.value is None:
                _delete_key_tree(reg, entry.hive, entry.key)
            else:
                with _open(reg, entry.hive, entry.key, write=True) as key:
                    reg.DeleteValue(key, entry.value)
        except FileNotFoundError:
            pass  # removed meanwhile (an ancestor was deleted before)
        except PermissionError:
            result.failed.append((entry, "Access denied: run as administrator" if entry.hive == "HKLM"
                                  else "Access denied"))
            continue
        except OSError as e:
            result.failed.append((entry, str(e)))
            continue
        result.deleted.append(entry)
        logging.info(f"Registry cleanup: deleted {entry.location}" + (f" [{entry.value}]" if entry.value is not None else ""))
    return result

# endregion
