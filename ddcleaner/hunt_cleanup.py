"""Removing what the persistence hunt found: a scheduled task, a service, or a startup / debugger registry value.

Only three kinds of entry can be removed, only when the hunt said how (Finding.removal), and every removal first
saves what is needed to put it back: the task as an XML file (Task Scheduler > Import Task), the service key or the
value's key as a .reg file (double-click it, and restart for a service). If the backup fails, nothing is removed.
"""

import base64
import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional, Tuple

from ddcleaner import dead_registry, startup, threat_hunt
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM32, data_dir, safe_environment, sys_exe, winreg
from ddcleaner.threat_hunt import Finding

SERVICE_NAME = re.compile(r"[A-Za-z0-9_.@\- ]{1,256}")
ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE = 1060, 1072
# the only registry values it may delete: key (lower case, prefix) -> allowed value names (None = any)
ALLOWED_VALUES = [(threat_hunt.IFEO.lower() + "\\", {"debugger"}),
                  (threat_hunt.POLICIES_RUN.lower(), None)]

TASK_SCRIPT = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{payload}')) | ConvertFrom-Json
try {
    $xml = Export-ScheduledTask -TaskName $p.name -TaskPath $p.path -ErrorAction Stop
    [IO.File]::WriteAllText($p.file, $xml, [Text.Encoding]::Unicode)
    Unregister-ScheduledTask -TaskName $p.name -TaskPath $p.path -Confirm:$false -ErrorAction Stop
    ConvertTo-Json -Compress -InputObject @{ ok = $true; error = '' }
} catch {
    ConvertTo-Json -Compress -InputObject @{ ok = $false; error = [string]$_.Exception.Message }
}
"""


@dataclass
class RemoveResult:
    removed: List[Finding] = field(default_factory=list)
    failed: List[Tuple[Finding, str]] = field(default_factory=list)
    backups: List[str] = field(default_factory=list)
    reboot: bool = False             # a deleted service that was running disappears at the next restart


def backup_dir() -> str:
    return os.path.join(data_dir(), "hunt_backups")


def removable(finding: Finding) -> bool:
    return bool(finding.removal) and finding.removal[0] in ("task", "service", "regvalue")


def describe(finding: Finding) -> str:
    """What removing this finding does, for the confirmation window."""
    kind = finding.removal[0] if finding.removal else ""
    if kind == "task":
        return f"Delete the scheduled task {finding.removal[1]} (saved as an XML file first)"
    if kind == "service":
        return f"Delete the service {finding.removal[1]} (its registry key is saved first)"
    if kind == "regvalue":
        return f"Delete the value {finding.removal[3] or '(default)'} in {finding.removal[1]}\\{finding.removal[2]} (saved first)"
    return "Cannot be removed from here"


def _safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text)[:60] or "item"


def _value_allowed(key: str, value: str) -> bool:
    low = key.lower()
    for prefix, names in ALLOWED_VALUES:
        if low.startswith(prefix) or low == prefix.rstrip("\\"):
            return names is None or value.lower() in names
    return False


def _powershell(script: str, timeout: int = 60):
    return startup._run_powershell(script, timeout)


def _delete_service(name: str) -> int:
    done = subprocess.run([sys_exe("sc.exe"), "delete", name], capture_output=True, text=True, errors="replace",
                          timeout=60, cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)
    return done.returncode


def remove_findings(findings: List[Finding], folder: Optional[str] = None, reg=winreg,
                    run: Callable = _powershell, export: Callable = dead_registry.export_key,
                    delete_service: Callable[[str], int] = _delete_service,
                    stop: Callable[[], bool] = lambda: False) -> RemoveResult:
    result = RemoveResult()
    folder = folder or backup_dir()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for index, finding in enumerate(findings, 1):
        if stop():
            result.failed.append((finding, "Stopped"))
            continue
        if not removable(finding):
            result.failed.append((finding, "This entry cannot be removed from here"))
            continue
        try:
            os.makedirs(folder, exist_ok=True)
            kind = finding.removal[0]
            if kind == "task":
                error = _remove_task(finding, os.path.join(folder, f"{stamp}_{index:02d}_task_{_safe_name(finding.removal[1])}.xml"),
                                     run, result)
            elif kind == "service":
                error = _remove_service(finding, os.path.join(folder, f"{stamp}_{index:02d}_service_{_safe_name(finding.removal[1])}.reg"),
                                        export, delete_service, result)
            else:
                error = _remove_value(finding, os.path.join(folder, f"{stamp}_{index:02d}_value_{_safe_name(finding.removal[2].rsplit(chr(92), 1)[-1])}.reg"),
                                      reg, export, result)
        except OSError as e:
            error = str(e)
        if error:
            result.failed.append((finding, error))
        else:
            result.removed.append(finding)
            logging.info(f"Persistence hunt: removed {describe(finding)}")
    return result


def _remove_task(finding: Finding, backup: str, run: Callable, result: RemoveResult) -> str:
    _kind, name, path = finding.removal
    payload = base64.b64encode(json.dumps({"name": name, "path": path or "\\", "file": backup}).encode("utf-8")).decode("ascii")
    try:
        answer = run(TASK_SCRIPT.replace("{payload}", payload))
    except (subprocess.SubprocessError, ValueError, OSError) as e:
        return f"PowerShell failed: {e}"
    if not isinstance(answer, dict):
        return "The task could not be removed (administrator rights are needed)"
    if os.path.isfile(backup):
        result.backups.append(backup)
    if not answer.get("ok"):
        return str(answer.get("error") or "The task could not be removed").strip()
    if not os.path.isfile(backup):
        return "The task was removed but its backup file was not written"
    return ""


def _remove_service(finding: Finding, backup: str, export: Callable, delete_service: Callable, result: RemoveResult) -> str:
    name = finding.removal[1]
    if not SERVICE_NAME.fullmatch(name):
        return "Unusual service name: refused"
    if finding.path and threat_hunt.judge_in_windows(finding.path):
        return "A service of Windows itself is never removed from here"
    problem = export("HKLM", f"{threat_hunt.SERVICES_KEY}\\{name}", backup)
    if problem:
        return f"Backup failed, nothing removed: {problem}"
    result.backups.append(backup)
    code = delete_service(name)
    if code == ERROR_SERVICE_MARKED_FOR_DELETE:
        result.reboot = True
        return ""
    if code not in (0, ERROR_SERVICE_DOES_NOT_EXIST):
        return f"sc delete failed (code {code}): run as administrator"
    return ""


def _remove_value(finding: Finding, backup: str, reg, export: Callable, result: RemoveResult) -> str:
    _kind, hive, key, name = finding.removal
    if hive not in ("HKLM", "HKCU") or not _value_allowed(key, name):
        return "This registry value is not one that can be removed from here"
    try:
        handle = dead_registry._open_or_none(reg, hive, key)
        if handle is None:
            return ""  # already gone
        with handle:
            pass
        problem = export(hive, key, backup)
        if problem:
            return f"Backup failed, nothing removed: {problem}"
        result.backups.append(backup)
        with dead_registry._open(reg, hive, key, write=True) as handle:
            reg.DeleteValue(handle, name)
    except FileNotFoundError:
        return ""
    except PermissionError:
        return "Access denied: run as administrator"
    return ""
