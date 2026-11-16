"""Removing a startup entry listed by startup.py: a Run / RunOnce value, a file of a Startup folder, or a logon / boot
scheduled task.

Every removal first saves what is needed to put the entry back, in startup_backups: the registry key as a .reg file
(double-click it), the scheduled task as an XML file (Task Scheduler > Import Task), and a Startup-folder file is
simply moved there (move it back). If the backup fails, nothing is removed. Only the places startup.py reads can be
touched: the known Run keys and the two Startup folders.
"""

import logging
import os
import shutil
from datetime import datetime
from types import SimpleNamespace
from typing import Callable, Dict, List, Optional, Tuple

from ddcleaner import dead_registry, hunt_cleanup, startup
from ddcleaner.common import data_dir, winreg
from ddcleaner.hunt_cleanup import RemoveResult
from ddcleaner.startup import StartupEntry

VIEW32 = " (32-bit)"
TASK_PREFIX = "Task Scheduler "
DEFAULT_VALUE = "(default)"
RUN_KEYS = {(hive, key.lower(), view32) for hive, key, _scope, view32 in startup.RUN_KEYS}


def backup_dir() -> str:
    return os.path.join(data_dir(), "startup_backups")


def target(entry: StartupEntry) -> Optional[Tuple]:
    """How to remove an entry: ('regvalue', hive, key, value name), ('file', path) or ('task', name, task path).
    None when the entry is not in one of the places this module may touch."""
    if entry.kind == "Registry":
        location = entry.location
        view32 = location.endswith(VIEW32)
        hive, _, key = (location[:-len(VIEW32)] if view32 else location).partition("\\")
        if (hive, key.lower(), view32) not in RUN_KEYS:
            return None
        if view32:  # the 32-bit view of HKLM\SOFTWARE is the WOW6432Node key
            key = "SOFTWARE\\WOW6432Node\\" + key[len("SOFTWARE\\"):]
        return "regvalue", hive, key, "" if entry.name == DEFAULT_VALUE else entry.name
    if entry.kind == "Folder" and entry.location and entry.name == os.path.basename(entry.name):
        return "file", os.path.join(entry.location, entry.name)
    if entry.kind == "Task" and entry.location.startswith(TASK_PREFIX) and entry.name:
        return "task", entry.name, entry.location[len(TASK_PREFIX):] or "\\"
    return None


def removable(entry: StartupEntry) -> bool:
    return target(entry) is not None


def needs_admin(entry: StartupEntry) -> bool:
    """A value under HKLM, a file of the all-users Startup folder and any scheduled task need administrator rights."""
    how = target(entry)
    if how is None:
        return False
    if how[0] == "regvalue":
        return how[1] == "HKLM"
    if how[0] == "file":
        return entry.scope == startup.ALL_USERS
    return True


def describe(entry: StartupEntry) -> str:
    """What removing this entry does, for the confirmation window."""
    how = target(entry)
    if how is None:
        return "Cannot be removed from here"
    if how[0] == "regvalue":
        return f"Delete the value {how[3] or DEFAULT_VALUE} in {how[1]}\\{how[2]} (the key is saved first)"
    if how[0] == "file":
        return f"Move {how[1]} to the backups folder"
    return f"Delete the scheduled task {how[2]}{how[1]} (saved as an XML file first)"


def remove_entries(entries: List[StartupEntry], folder: Optional[str] = None, reg=winreg,
                   run: Callable = hunt_cleanup._powershell, export: Callable = dead_registry.export_key,
                   startup_folders: Optional[Dict[str, str]] = None,
                   stop: Callable[[], bool] = lambda: False) -> RemoveResult:
    result = RemoveResult()
    folder = folder or backup_dir()
    if startup_folders is None:
        startup_folders = {startup.ALL_USERS: startup._known_folder(startup.CSIDL_COMMON_STARTUP),
                           startup.CURRENT_USER: startup._known_folder(startup.CSIDL_STARTUP)}
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for index, entry in enumerate(entries, 1):
        if stop():
            result.failed.append((entry, "Stopped"))
            continue
        how = target(entry)
        if how is None:
            result.failed.append((entry, "This entry cannot be removed from here"))
            continue
        prefix = os.path.join(folder, f"{stamp}_{index:02d}_")
        try:
            os.makedirs(folder, exist_ok=True)
            if how[0] == "regvalue":
                error = _remove_value(how, prefix + f"value_{hunt_cleanup._safe_name(entry.name)}.reg", reg, export, result)
            elif how[0] == "file":
                error = _remove_file(how[1], prefix + os.path.basename(how[1]), startup_folders, result)
            else:
                task = SimpleNamespace(removal=how)  # the shape hunt_cleanup expects
                error = hunt_cleanup._remove_task(task, prefix + f"task_{hunt_cleanup._safe_name(entry.name)}.xml",
                                                  run, result)
        except PermissionError:
            error = "Access denied: run as administrator"
        except OSError as e:
            error = str(e)
        if error:
            result.failed.append((entry, error))
        else:
            result.removed.append(entry)
            logging.info(f"Startup programs: removed {entry.name}: {describe(entry)}")
    return result


def _remove_value(how: Tuple, backup: str, reg, export: Callable, result: RemoveResult) -> str:
    _kind, hive, key, name = how
    handle = dead_registry._open_or_none(reg, hive, key)
    if handle is None:
        return ""  # the key is already gone
    with handle:
        try:
            reg.QueryValueEx(handle, name)
        except FileNotFoundError:
            return ""  # the value is already gone
    problem = export(hive, key, backup)
    if problem:
        return f"Backup failed, nothing removed: {problem}"
    result.backups.append(backup)
    with dead_registry._open(reg, hive, key, write=True) as handle:
        reg.DeleteValue(handle, name)
    return ""


def _remove_file(path: str, backup: str, startup_folders: Dict[str, str], result: RemoveResult) -> str:
    allowed = {os.path.normcase(os.path.normpath(f)) for f in startup_folders.values() if f}
    if os.path.normcase(os.path.normpath(os.path.dirname(path))) not in allowed:
        return "This file is not in a Startup folder: refused"
    if not os.path.lexists(path):
        return ""  # already gone
    if os.path.islink(path) or not os.path.isfile(path):
        return "Not a regular file: refused"
    shutil.move(path, backup)  # the backup and the removal at once: moving it back restores the entry
    result.backups.append(backup)
    return ""
