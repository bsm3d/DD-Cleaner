"""
Advanced security tweaks (services, Windows Script Host, script associations): catalogue, command
building, state snapshot and exact revert. No UI code here, so it can be tested without touching the system.

Revert trusts only the built-in catalogue: a snapshot JSON is data, and entries whose target (service,
registry value, extension) is not in the catalogue, or whose values are malformed, are ignored.
"""

import json
import logging
import os
import re
import shlex
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from ddcleaner.common import winreg, sys_exe
from ddcleaner.system_utils import SystemUtils

# (category, name, command, description, risk)
_SAFE = [
    ("Telemetry", "Disable DiagTrack", "sc config DiagTrack start= disabled",
     "Disable Connected User Experiences and Telemetry service", "Low"),
    ("Telemetry", "Disable dmwappushservice", "sc config dmwappushservice start= disabled",
     "Disable WAP Push Message Routing Service", "Low"),
    ("Files", "Unassociate .js", "assoc .js=", "Remove .js file association (block direct execution)", "Low"),
    ("Files", "Unassociate .vbs", "assoc .vbs=", "Remove .vbs file association (block direct execution)", "Low"),
    ("Files", "Unassociate .jse", "assoc .jse=", "Remove .jse file association (block direct execution)", "Low"),
    ("Files", "Unassociate .wsf", "assoc .wsf=", "Remove .wsf file association (block direct execution)", "Low"),
    ("Files", "Unassociate .vbe", "assoc .vbe=", "Remove .vbe file association (encoded VBScript)", "Low"),
    ("Files", "Unassociate .hta", "assoc .hta=", "Remove .hta file association (HTML applications run with full rights)", "Low"),
]
_MEDIUM = _SAFE + [
    ("Services", "Disable RemoteRegistry", "sc config RemoteRegistry start= disabled",
     "Disable remote registry access service", "Medium"),
    ("Services", "Disable RemoteAccess", "sc config RemoteAccess start= disabled",
     "Disable Routing and Remote Access service", "Medium"),
    ("Registry", "Disable WSH",
     'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings" /v Enabled /t REG_DWORD /d 0 /f',
     "Disable Windows Script Host (JScript/VBScript)", "Medium"),
    ("Registry", "WSH: ignore user settings",
     'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings" /v IgnoreUserSettings /t REG_DWORD /d 1 /f',
     "Without this, a program running as the user can turn WSH back on through HKCU", "Medium"),
    ("Registry", "WSH: log security failures",
     'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings" /v LogSecurityFailures /t REG_DWORD /d 1 /f',
     "Write an event when a blocked script tries to run", "Low"),
]
_AGGRESSIVE = _MEDIUM + [
    ("Services", "Disable Xbox services", "sc config XblAuthManager start= disabled",
     "Disable Xbox Live Auth Manager (gaming)", "High"),
    ("Services", "Disable Xbox GameSave", "sc config XblGameSave start= disabled",
     "Disable Xbox Live Game Save service", "High"),
    ("Privacy", "Disable Windows Feedback",
     'reg add "HKCU\\Software\\Microsoft\\Siuf\\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f',
     "Disable Windows Feedback notifications", "Medium"),
]
# "Custom" lists every tweak, unchecked
PRESETS: Dict[str, List[Tuple[str, str, str, str, str]]] = {
    "Safe (Recommended)": _SAFE,
    "Medium": _MEDIUM,
    "Aggressive": _AGGRESSIVE,
    "Custom": _AGGRESSIVE,
}

SERVICE_START_NAMES = {0: "boot", 1: "system", 2: "auto", 3: "demand", 4: "disabled"}

# Windows 10 defaults, used only when no snapshot exists
WIN10_DEFAULT_RESTORE = [
    ("Re-enable DiagTrack", "sc config DiagTrack start= auto"),
    ("Re-enable dmwappushservice", "sc config dmwappushservice start= demand"),
    ("Reset RemoteRegistry (Win10 default: disabled)", "sc config RemoteRegistry start= disabled"),
    ("Reset RemoteAccess (Win10 default: disabled)", "sc config RemoteAccess start= disabled"),
    ("Re-enable XblAuthManager", "sc config XblAuthManager start= demand"),
    ("Re-enable XblGameSave", "sc config XblGameSave start= demand"),
    ("Re-enable WSH", 'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings" /v Enabled /f'),
    ("Restore .js association", "assoc .js=JSFile"),
    ("Restore .vbs association", "assoc .vbs=VBSFile"),
    ("Restore .jse association", "assoc .jse=JSEFile"),
    ("Restore .wsf association", "assoc .wsf=WSFFile"),
    ("Restore .vbe association", "assoc .vbe=VBEFile"),
    ("Restore .hta association", "assoc .hta=htafile"),
    ("Re-enable WSH user settings",
     'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings" /v IgnoreUserSettings /f'),
    ("Remove WSH failure logging",
     'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings" /v LogSecurityFailures /f'),
]

_REG_TYPE_NAMES = {winreg.REG_SZ: "REG_SZ", winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
                   winreg.REG_DWORD: "REG_DWORD", winreg.REG_QWORD: "REG_QWORD"}
_PROGID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


EDITOR_PROGID = "txtfile"  # Notepad: always present, opens the file as text


def open_in_editor(cmd: str) -> str:
    """'assoc .js=' (remove the association) -> 'assoc .js=txtfile': a double click then shows the script in
    Notepad instead of asking which program to use. Any other command is returned unchanged."""
    parts = shlex.split(cmd)
    if len(parts) == 2 and parts[0].lower() == "assoc" and re.fullmatch(r"\.[A-Za-z0-9]{1,10}=", parts[1]):
        return f"assoc {parts[1]}{EDITOR_PROGID}"
    return cmd


def hardening_argv(cmd: str) -> List[str]:
    """Command string -> argv with absolute system binaries. Only sc / reg / assoc are allowed."""
    parts = shlex.split(cmd)
    if not parts:
        raise ValueError("Empty command")
    tool = parts[0].lower()
    if tool in ("sc", "sc.exe"):
        return [sys_exe("sc.exe")] + parts[1:]
    if tool in ("reg", "reg.exe"):
        return [sys_exe("reg.exe")] + parts[1:]
    if tool == "assoc":
        # assoc is a cmd.exe builtin, not an executable
        return [sys_exe("cmd.exe"), "/d", "/c", "assoc"] + parts[1:]
    raise ValueError(f"Command not allowed: {parts[0]}")


def parse_target(cmd: str) -> Dict[str, Any]:
    """What a catalogue command touches: {"kind": "service"|"reg"|"assoc", ...}."""
    parts = shlex.split(cmd)
    tool = parts[0].lower() if parts else ""
    if tool in ("sc", "sc.exe") and len(parts) >= 3 and parts[1].lower() == "config":
        return {"kind": "service", "service": parts[2]}
    if tool in ("reg", "reg.exe") and len(parts) >= 3:
        value = parts[parts.index("/v") + 1] if "/v" in parts else None
        return {"kind": "reg", "key": parts[2], "value": value}
    if tool == "assoc" and len(parts) >= 2:
        return {"kind": "assoc", "ext": parts[1].split("=")[0]}
    return {"kind": "unknown"}


def allowed_targets() -> Dict[str, Set]:
    """Every service / registry value / extension the catalogue can touch (the revert allow-list)."""
    allowed: Dict[str, Set] = {"service": set(), "reg": set(), "assoc": set()}
    commands = [c for _, _, c, _, _ in PRESETS["Custom"]] + [c for _, c in WIN10_DEFAULT_RESTORE]
    for cmd in commands:
        t = parse_target(cmd)
        if t["kind"] == "service":
            allowed["service"].add(t["service"].lower())
        elif t["kind"] == "reg":
            allowed["reg"].add((SystemUtils.normalize_registry_path(t["key"]).lower(), (t["value"] or "").lower()))
        elif t["kind"] == "assoc":
            allowed["assoc"].add(t["ext"].lower())
    return allowed


def read_reg_value(root_key: str, value: Optional[str]) -> Dict[str, Any]:
    """Snapshot one registry value (or its absence)."""
    hive_name, _, sub = SystemUtils.normalize_registry_path(root_key).partition('\\')
    hive = {"HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE, "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT, "HKEY_USERS": winreg.HKEY_USERS}.get(hive_name)
    if hive is None:
        return {"exists": False}
    try:
        with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ) as k:
            data, vtype = winreg.QueryValueEx(k, value or "")
            return {"exists": True, "type": vtype, "data": data}
    except OSError:
        return {"exists": False}


def snapshot_entries(tweaks: List[Tuple[str, str]], reader=read_reg_value) -> List[Dict[str, Any]]:
    """Current state of everything the tweaks will touch."""
    entries = []
    for name, cmd in tweaks:
        t = parse_target(cmd)
        entry: Dict[str, Any] = {"name": name, "command": cmd, **t}
        if t["kind"] == "service":
            base = f"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\{t['service']}"
            entry.update(start=reader(base, "Start"), delayed=reader(base, "DelayedAutostart"))
        elif t["kind"] == "reg":
            entry.update(state=reader(t["key"], t["value"]))
        elif t["kind"] == "assoc":
            entry.update(state=reader(f"HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\{t['ext']}", None))
        entries.append(entry)
    return entries


def snapshot_tweaks(tweaks: List[Tuple[str, str]], folder: str, reader=read_reg_value) -> Optional[str]:
    """Write the current state to <folder>/tweaks_backup_<timestamp>.json. None = failure (apply must abort)."""
    path = os.path.join(folder, f"tweaks_backup_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json")
    try:
        os.makedirs(folder, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"created": datetime.now().isoformat(), "entries": snapshot_entries(tweaks, reader)},
                      f, indent=2, default=str)
        return path
    except OSError as e:
        logging.error(f"Hardening snapshot failed: {e}")
        return None


def _quote(arg: str) -> str:
    return f'"{arg}"' if (not arg or any(c in arg for c in ' \t"')) else arg


def _append_exact(commands: List[Tuple[str, str]], label: str, argv: List[str]):
    """Commands are stored as strings and split again by hardening_argv(): refuse any value (quote,
    backslash before a quote, newline...) that would split into other arguments than the intended ones."""
    cmd = " ".join(_quote(a) for a in argv)
    if shlex.split(cmd) != argv or any(c in a for a in argv for c in "\r\n\0"):
        raise ValueError(f"unsafe characters in {label!r}")
    commands.append((label, cmd))


def revert_commands(entries: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
    """Commands that put back a recorded state. Untrusted or malformed entries are skipped (logged)."""
    allowed = allowed_targets()
    commands = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        kind = e.get("kind")
        try:
            if kind == "service":
                svc = str(e.get("service", ""))
                if svc.lower() not in allowed["service"]:
                    raise ValueError(f"service not in catalogue: {svc!r}")
                start = e.get("start") or {}
                if not start.get("exists"):
                    continue
                code = int(start["data"])
                if code not in SERVICE_START_NAMES:
                    raise ValueError(f"invalid start type {code}")
                name = SERVICE_START_NAMES[code]
                delayed = e.get("delayed") or {}
                if name == "auto" and delayed.get("exists") and int(delayed.get("data", 0)) == 1:
                    name = "delayed-auto"
                _append_exact(commands, f"Restore {svc} ({name})", ["sc", "config", svc, "start=", name])
            elif kind == "reg":
                key = str(e.get("key", ""))
                value = e.get("value")
                target = (SystemUtils.normalize_registry_path(key).lower(), (value or "").lower())
                if target not in allowed["reg"]:
                    raise ValueError(f"registry value not in catalogue: {key!r} {value!r}")
                key = SystemUtils.normalize_registry_path(key)  # the checked spelling, no trailing backslash
                v = ["/v", value] if value else ["/ve"]
                st = e.get("state") or {}
                label = f"{key} {value or '(default)'}"
                if not st.get("exists"):
                    _append_exact(commands, f"Remove {label}", ["reg", "delete", key] + v + ["/f"])
                    continue
                vtype = st.get("type")
                if vtype in (winreg.REG_DWORD, winreg.REG_QWORD):
                    data = str(int(st["data"]))
                elif vtype in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                    data = str(st["data"])
                    if '"' in data or "\n" in data:
                        raise ValueError("string data contains quotes/newlines")
                else:
                    raise ValueError(f"unsupported value type {vtype}")
                _append_exact(commands, f"Restore {label}",
                              ["reg", "add", key] + v + ["/t", _REG_TYPE_NAMES[vtype], "/d", data, "/f"])
            elif kind == "assoc":
                ext = str(e.get("ext", ""))
                if ext.lower() not in allowed["assoc"]:
                    raise ValueError(f"extension not in catalogue: {ext!r}")
                st = e.get("state") or {}
                progid = str(st.get("data") or "") if st.get("exists") else ""
                if progid and not _PROGID_RE.match(progid):
                    raise ValueError(f"invalid ProgID {progid!r}")
                _append_exact(commands, f"Restore {ext} association", ["assoc", f"{ext}={progid}"])
        except (ValueError, KeyError, TypeError) as err:
            logging.warning(f"Snapshot entry ignored ({err}): {e.get('name', '?')}")
    return commands


def revert_commands_from_snapshot(snapshot_file: str) -> List[Tuple[str, str]]:
    """Load a tweaks_backup_*.json and build its revert commands."""
    with open(snapshot_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    entries = data.get("entries", []) if isinstance(data, dict) else []
    return revert_commands(entries)
