"""Programs that start by themselves: Run / RunOnce keys, Startup folders, logon and boot scheduled tasks.

Read-only. For each entry the program file is located and checked (does it exist, who signed it, can a standard
user replace it). The point is to show what runs without being asked, and to let the user scan those files.
"""

import base64
import ctypes
import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from ddcleaner import file_inspect, folder_security, pe_signature
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM_ROOT, SYSTEM32, safe_environment, sys_exe, winreg

CSIDL_STARTUP = 0x07          # the current user's Startup folder
CSIDL_COMMON_STARTUP = 0x18   # Startup folder of all users
ALL_USERS, CURRENT_USER = "All users", "Current user"
PE_SUFFIXES = {".exe", ".dll", ".scr", ".com", ".sys"}

FLAG_MISSING = "File not found"
FLAG_WRITABLE = "Folder writable by standard users"
FLAG_UNSIGNED = "Not signed (or signed by catalog)"
FLAG_PACKED = "High entropy (possibly packed or encrypted)"

# (hive, key, scope, 32-bit view)
RUN_KEYS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", ALL_USERS, False),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", ALL_USERS, False),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", ALL_USERS, True),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", CURRENT_USER, False),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", CURRENT_USER, False),
]

TASKS_PS = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$t = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' -and
    @($_.Triggers | Where-Object { $_.CimClass.CimClassName -in 'MSFT_TaskLogonTrigger', 'MSFT_TaskBootTrigger' }).Count -gt 0
} | ForEach-Object {
    $a = @($_.Actions)[0]
    [pscustomobject]@{ Name = $_.TaskName; Path = $_.TaskPath; Exec = [string]$a.Execute; Args = [string]$a.Arguments;
                       User = [string]$_.Principal.UserId; Level = $_.Principal.RunLevel.ToString() }
}
ConvertTo-Json -InputObject @($t) -Compress
"""


@dataclass
class StartupEntry:
    name: str
    command: str
    location: str            # where it is registered, e.g. "HKLM\...\Run"
    kind: str                # Registry | Folder | Task
    scope: str               # All users | Current user | account of the task
    path: str = ""           # the program file, when it could be located
    exists: bool = False
    signer: str = ""
    true_type: str = ""      # the file's real type from its bytes, when it clashes with the extension
    dangerous_content: bool = False  # executable/script content hiding under a non-executable name
    flags: List[str] = field(default_factory=list)

    @property
    def severity(self) -> int:
        """0 = nothing to say, 1 = look at it, 2 = runs for everyone from a writable folder, or its content
        is an executable/script masquerading under another extension."""
        if FLAG_WRITABLE in self.flags or self.dangerous_content:
            return 2
        return 1 if self.flags else 0


# region Locating the program

PATHEXT = (".exe", ".com", ".bat", ".cmd")  # the extensions Windows itself tries for a name with none


def _with_pathext(exists: Callable[[str], bool], path: str) -> str:
    """path, or path+each of PATHEXT, whichever exists first ('' if none does). Windows runs 'rundll32 ...'
    and 'cmd /c ...' the same way: the .exe is implied, so a bare name must be tried both ways."""
    if exists(path):
        return path
    if os.path.splitext(path)[1]:  # an explicit (wrong) extension is not re-guessed
        return ""
    for ext in PATHEXT:
        if exists(path + ext):
            return path + ext
    return ""


def _bare_name_location(name: str) -> str:
    """A program without a folder is looked up in the Windows folders only (never in PATH or the current folder)."""
    for folder in (SYSTEM32, SYSTEM_ROOT):
        found = _with_pathext(os.path.isfile, os.path.join(folder, name))
        if found:
            return found
    return ""


def _is_file(candidate: str) -> str:
    """The existing file named by an absolute path ('' if none), trying PATHEXT if it has no extension.
    A relative path is never resolved: it would be looked up in the current folder."""
    if not os.path.isabs(candidate):
        return ""
    return _with_pathext(os.path.isfile, candidate)


def command_path(command: str) -> str:
    """The program file named by a command line ('' when it cannot be found). Quotes, %VARIABLES% and unquoted
    paths with spaces ('C:\\Program Files\\X\\x.exe /s') are handled."""
    command = os.path.expandvars((command or "").strip())
    if not command:
        return ""
    if command.startswith('"'):
        end = command.find('"', 1)
        candidate = command[1:end] if end > 0 else command[1:]
        found = _is_file(candidate)
        if found:
            return found
        return "" if os.path.dirname(candidate) else _bare_name_location(candidate)
    tokens = command.split(" ")
    for count in range(len(tokens), 0, -1):
        candidate = " ".join(tokens[:count])
        found = _is_file(candidate)
        if found:
            return found
    first = tokens[0]
    if not os.path.dirname(first):
        return _bare_name_location(first)
    return ""

# endregion


# region Collecting

def _known_folder(csidl: int) -> str:
    try:
        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.shell32.SHGetFolderPathW(None, csidl, None, 0, buf) == 0:
            return buf.value
    except (AttributeError, OSError):
        pass
    return ""


def read_run_keys(reg=winreg) -> List[StartupEntry]:
    entries = []
    hives = {"HKLM": reg.HKEY_LOCAL_MACHINE, "HKCU": reg.HKEY_CURRENT_USER}
    for hive, key, scope, view32 in RUN_KEYS:
        access = reg.KEY_READ | (reg.KEY_WOW64_32KEY if view32 else reg.KEY_WOW64_64KEY)
        try:
            handle = reg.OpenKey(hives[hive], key, 0, access)
        except OSError:
            continue
        with handle:
            index = 0
            while True:
                try:
                    name, value, _type = reg.EnumValue(handle, index)
                except OSError:
                    break
                index += 1
                if isinstance(value, str) and value.strip():
                    suffix = " (32-bit)" if view32 else ""
                    entries.append(StartupEntry(name or "(default)", value, f"{hive}\\{key}{suffix}", "Registry", scope))
    return entries


def read_startup_folders(folders: Optional[Dict[str, str]] = None) -> List[StartupEntry]:
    if folders is None:
        folders = {ALL_USERS: _known_folder(CSIDL_COMMON_STARTUP), CURRENT_USER: _known_folder(CSIDL_STARTUP)}
    entries = []
    for scope, folder in folders.items():
        if not folder or not os.path.isdir(folder):
            continue
        for name in sorted(os.listdir(folder)):
            full = os.path.join(folder, name)
            if name.lower() == "desktop.ini" or not os.path.isfile(full):
                continue
            entries.append(StartupEntry(name, full, folder, "Folder", scope, path=full))
    return entries


def _run_powershell(script: str, timeout: int = 60):
    completed = subprocess.run(
        [sys_exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
        cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    return json.loads(completed.stdout)


def read_logon_tasks(run: Callable = _run_powershell) -> List[StartupEntry]:
    try:
        data = run(TASKS_PS)
    except (subprocess.SubprocessError, ValueError, OSError) as e:
        logging.warning(f"Scheduled tasks not readable: {e}")
        return []
    if isinstance(data, dict):
        data = [data]
    entries = []
    for t in data or []:
        if not isinstance(t, dict) or not t.get("Exec"):
            continue
        command = f'"{t["Exec"]}" {t.get("Args", "")}'.strip() if " " in t["Exec"] and not t["Exec"].startswith('"') \
            else f'{t["Exec"]} {t.get("Args", "")}'.strip()
        who = str(t.get("User") or "")
        highest = " (highest privileges)" if str(t.get("Level")) == "Highest" else ""
        entries.append(StartupEntry(str(t.get("Name", "")), command, "Task Scheduler " + str(t.get("Path", "")), "Task",
                                    (who or "task") + highest))
    return entries


def resolve_shortcuts(entries: List[StartupEntry], run: Callable = _run_powershell) -> None:
    """The program behind each .lnk of a Startup folder (a shortcut is not what has to be scanned or signed)."""
    links = [e for e in entries if e.kind == "Folder" and e.path.lower().endswith(".lnk")]
    if not links:
        return
    payload = base64.b64encode(json.dumps([e.path for e in links]).encode("utf-8")).decode("ascii")
    script = ("[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
              f"$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{payload}')) | ConvertFrom-Json; "
              "$s = New-Object -ComObject WScript.Shell; "
              "$r = @($p | ForEach-Object { [pscustomobject]@{ Link = $_; Target = $s.CreateShortcut($_).TargetPath } }); "
              "ConvertTo-Json -InputObject $r -Compress")
    try:
        data = run(script)
    except (subprocess.SubprocessError, ValueError, OSError) as e:
        logging.warning(f"Shortcuts not resolved: {e}")
        return
    if isinstance(data, dict):
        data = [data]
    targets = {str(d.get("Link")): str(d.get("Target") or "") for d in data or [] if isinstance(d, dict)}
    for e in links:
        target = targets.get(e.path, "")
        if target:
            e.command = f'{e.command}  ->  {target}'
            e.path = target if os.path.isfile(target) else ""


def inspect_entry(entry: StartupEntry, signer_of: Callable = pe_signature.inspect_file,
                  writers_of: Callable = folder_security.unprivileged_writers,
                  inspect_of: Callable = file_inspect.inspect) -> None:
    """Fill path, exists, signer, real type and flags."""
    if entry.kind != "Folder" or not entry.path:
        entry.path = command_path(entry.command) if entry.kind != "Folder" else entry.path
    entry.exists = bool(entry.path) and os.path.isfile(entry.path)
    entry.flags = []
    if not entry.exists:
        entry.flags.append(FLAG_MISSING)
        return
    if os.path.splitext(entry.path)[1].lower() in PE_SUFFIXES:
        info = signer_of(entry.path)
        entry.signer = info.signer
        in_windows = os.path.normcase(entry.path).startswith(os.path.normcase(SYSTEM_ROOT) + os.sep)
        if not info.signer and not info.error and not in_windows:  # Windows files are signed by catalog
            entry.flags.append(FLAG_UNSIGNED)
    # real type from the bytes: an executable/script wearing a document name, or a packed executable
    inspection = inspect_of(entry.path)
    if inspection.mismatch:
        entry.flags.append(inspection.mismatch)
        entry.true_type = inspection.true_type
        entry.dangerous_content = inspection.dangerous
    if inspection.packed:
        entry.flags.append(FLAG_PACKED)
    # what runs for everybody (or with the highest privileges) must not be replaceable by a standard user
    if entry.scope == ALL_USERS or "highest" in entry.scope.lower():
        try:
            if writers_of(os.path.dirname(entry.path)):
                entry.flags.append(FLAG_WRITABLE)
        except OSError:
            pass


def collect_startup(stop: Callable[[], bool] = lambda: False, progress: Optional[Callable] = None) -> List[StartupEntry]:
    entries = read_run_keys() + read_startup_folders() + read_logon_tasks()
    resolve_shortcuts(entries)
    for index, entry in enumerate(entries, 1):
        if stop():
            break
        if progress:
            progress(index, len(entries), entry.name)
        inspect_entry(entry)
    logging.info(f"Startup programs: {len(entries)} entries, {sum(1 for e in entries if e.severity == 2)} replaceable "
                 "by a standard user")
    return entries

# endregion
