"""Complete driver uninstall: a driver even when a connected device uses it, the entries of its devices that are not
connected, and what it leaves behind (its service and its .sys file).

Every step saves what it removes first (pnputil /export-driver for the package, a .reg and a copy of the file for a
leftover) and nothing happens when that copy fails. Core drivers are never touched. Leftover services and files are
only LISTED by uninstall_completely(); remove_leftovers() deletes them after the user confirmed a second time.
"""

import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set, Tuple

from ddcleaner import dead_registry
from ddcleaner.common import SYSTEM_ROOT, SYSTEM32, winreg
from ddcleaner.driver_cleanup import (CRITICAL_CLASSES, PUBLISHED, Candidate, Package, _pnputil, backup_dir)

SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
SERVICE_NAME = re.compile(r"[A-Za-z0-9_.@\-]{1,256}")
DRIVERS_FOLDER = os.path.join(SYSTEM32, "drivers")
SUCCESS_CODES = (0, 3010)          # 3010: done, a restart finishes the job
ADD_SERVICE = re.compile(r"^\s*AddService\s*=\s*\"?([A-Za-z0-9_.@\-]+)", re.I | re.M)


@dataclass
class Leftover:
    service: str             # HKLM\SYSTEM\CurrentControlSet\Services\<name>
    image: str               # its .sys file in System32\drivers
    file_exists: bool
    package: str             # the published name (oem12.inf) that declared the service


@dataclass
class UninstallResult:
    removed: List[Candidate] = field(default_factory=list)
    failed: List[Tuple[Candidate, str]] = field(default_factory=list)
    backups: List[str] = field(default_factory=list)
    leftovers: List[Leftover] = field(default_factory=list)
    ghosts_removed: int = 0
    reboot: bool = False


@dataclass
class LeftoverResult:
    removed: List[Leftover] = field(default_factory=list)
    failed: List[Tuple[Leftover, str]] = field(default_factory=list)
    backups: List[str] = field(default_factory=list)


# region Reading the INF files

def inf_path(published: str) -> str:
    """Windows keeps a copy of every installed package's INF as C:\\Windows\\INF\\oemNN.inf."""
    return os.path.join(SYSTEM_ROOT, "INF", published)


def read_inf(path: str) -> str:
    try:
        with open(path, "rb") as f:
            raw = f.read(2 * 1024 * 1024)
    except OSError:
        return ""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")


def inf_services(path: str) -> List[str]:
    """The services an INF installs (its AddService lines; what follows a ';' is a comment)."""
    text = "\n".join(line.split(";", 1)[0] for line in read_inf(path).splitlines())
    return list(dict.fromkeys(m.group(1) for m in ADD_SERVICE.finditer(text)))


def inbox_services(folder: str = os.path.join(SYSTEM_ROOT, "INF")) -> Set[str]:
    """Services named by the INFs of Windows itself: a service of the same name is never touched."""
    names: Set[str] = set()
    try:
        files = [os.path.join(folder, n) for n in os.listdir(folder) if n.lower().endswith(".inf") and not PUBLISHED.fullmatch(n)]
    except OSError:
        return names
    for path in files:
        names.update(s.lower() for s in inf_services(path))
    return names

# endregion


# region Leftovers

def resolve_driver_file(image: str) -> str:
    """The file a service's ImagePath names (\\SystemRoot\\..., system32\\drivers\\x.sys, \\??\\C:\\...)."""
    image = os.path.expandvars((image or "").strip().strip('"'))
    low = image.lower()
    if low.startswith("\\systemroot\\"):
        return os.path.join(SYSTEM_ROOT, image[len("\\SystemRoot\\"):])
    if low.startswith("\\??\\"):
        return image[4:]
    if os.path.isabs(image):
        return image
    return os.path.join(SYSTEM_ROOT, image) if image else ""


def _service_values(reg, name: str) -> Optional[Dict[str, object]]:
    key = dead_registry._open_or_none(reg, "HKLM", f"{SERVICES_KEY}\\{name}")
    if key is None:
        return None
    with key:
        return {n: v for n, v, _t in dead_registry._values(reg, key)}


def leftover_problem(name: str, values: Optional[Dict[str, object]]) -> str:
    """Why a service must not be offered ('' when it is a plain driver service whose file sits in System32\\drivers)."""
    if not SERVICE_NAME.fullmatch(name):
        return "Unusual service name"
    if values is None:
        return "No such service"
    if values.get("Type") not in (1, 2):
        return "Not a driver service"
    if values.get("Start") == 0:
        return "A boot-start driver: never touched"
    path = resolve_driver_file(str(values.get("ImagePath", "")))
    if not path or not os.path.normcase(path).startswith(os.path.normcase(DRIVERS_FOLDER) + os.sep):
        return "Its file is not in System32\\drivers"
    return ""


def find_leftovers(services: Dict[str, str], still_declared: Set[str], reg=winreg) -> List[Leftover]:
    """Driver services (name -> package) that survive the removal of their package and that nothing else declares."""
    found = []
    for name, package in services.items():
        if name.lower() in still_declared:
            continue
        values = _service_values(reg, name)
        if leftover_problem(name, values):
            continue
        path = resolve_driver_file(str(values.get("ImagePath", "")))
        found.append(Leftover(name, path, os.path.isfile(path), package))
    return found

# endregion


def uninstall_completely(candidates: List[Candidate], remaining: List[Package], folder: Optional[str] = None,
                         run: Callable = _pnputil, reg=winreg, inbox: Optional[Set[str]] = None,
                         stop: Callable[[], bool] = lambda: False) -> UninstallResult:
    """Remove packages even when a connected device uses them, then list what they leave behind.

    Per package: save a copy of its files (nothing happens without it), delete it with /uninstall /force when a device
    uses it (a plain delete otherwise, so Windows keeps its own safety), then remove the entries of the devices that
    are not connected. `remaining` is every package that stays installed (to know which services are still declared)."""
    result = UninstallResult()
    folder = folder or backup_dir()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    services: Dict[str, str] = {}
    for candidate in candidates:
        pkg = candidate.package
        if stop():
            result.failed.append((candidate, "Stopped"))
            continue
        if not PUBLISHED.fullmatch(pkg.published) or not candidate.removable or pkg.class_guid in CRITICAL_CLASSES:
            result.failed.append((candidate, "This package cannot be removed from here"))
            continue
        declared = inf_services(inf_path(pkg.published))
        target = os.path.join(folder, f"{stamp}_{pkg.published[:-4]}_{re.sub(r'[^A-Za-z0-9._-]', '_', pkg.original)}")
        try:
            os.makedirs(target, exist_ok=True)
            code, _out = run(["/export-driver", pkg.published, target])
            if code != 0 or not os.listdir(target):
                result.failed.append((candidate, "The backup of the driver files failed: nothing removed"))
                continue
            result.backups.append(target)
            args = ["/delete-driver", pkg.published] + (["/uninstall", "/force"] if candidate.in_use else [])
            code, out = run(args)
        except (OSError, subprocess.SubprocessError) as e:
            result.failed.append((candidate, str(e)))
            continue
        if code not in SUCCESS_CODES:
            result.failed.append((candidate, "Windows refused: the driver is in use" if "in use" in out.lower()
                                  else f"pnputil failed (code {code}): run as administrator"))
            continue
        result.reboot = result.reboot or code == 3010 or candidate.in_use
        result.removed.append(candidate)
        for instance_id in candidate.ghost_ids:
            try:
                if run(["/remove-device", instance_id])[0] in SUCCESS_CODES:
                    result.ghosts_removed += 1
            except (OSError, subprocess.SubprocessError):
                pass
        services.update({name: pkg.published for name in declared})
        logging.info(f"Driver uninstalled completely: {pkg.published} ({pkg.original}, {pkg.provider} {pkg.version})")
    gone = {c.package.published for c in result.removed}
    still_declared: Set[str] = set(inbox if inbox is not None else inbox_services())
    for other in remaining:
        if other.published not in gone:
            still_declared.update(s.lower() for s in inf_services(inf_path(other.published)))
    result.leftovers = find_leftovers(services, still_declared, reg)
    return result


def _delete_service_tree(reg, name: str):
    dead_registry._delete_key_tree(reg, "HKLM", f"{SERVICES_KEY}\\{name}")


def remove_leftovers(leftovers: List[Leftover], folder: Optional[str] = None, reg=winreg,
                     export: Callable = dead_registry.export_key, delete_tree: Optional[Callable] = None,
                     remove_file: Callable[[str], None] = os.remove,
                     stop: Callable[[], bool] = lambda: False) -> LeftoverResult:
    """Delete the service key and the .sys file of each leftover, after saving both. A file Windows still has loaded
    stays until the next restart."""
    result = LeftoverResult()
    folder = folder or backup_dir()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    delete_tree = delete_tree or (lambda name: _delete_service_tree(reg, name))
    for leftover in leftovers:
        if stop():
            result.failed.append((leftover, "Stopped"))
            continue
        values = _service_values(reg, leftover.service)
        problem = leftover_problem(leftover.service, values)
        if problem:
            result.failed.append((leftover, problem))
            continue
        path = resolve_driver_file(str(values.get("ImagePath", "")))
        target = os.path.join(folder, f"{stamp}_service_{re.sub(r'[^A-Za-z0-9._-]', '_', leftover.service)}")
        try:
            os.makedirs(target, exist_ok=True)
            problem = export("HKLM", f"{SERVICES_KEY}\\{leftover.service}", os.path.join(target, "service.reg"))
            if problem:
                result.failed.append((leftover, f"Backup failed, nothing removed: {problem}"))
                continue
            if os.path.isfile(path):
                shutil.copy2(path, target)
            result.backups.append(target)
            delete_tree(leftover.service)
        except PermissionError:
            result.failed.append((leftover, "Access denied: run as administrator"))
            continue
        except OSError as e:
            result.failed.append((leftover, str(e)))
            continue
        try:
            if os.path.isfile(path):
                remove_file(path)
        except OSError:
            result.failed.append((leftover, "The service entry is removed; the file is still loaded: delete it after a restart"))
            continue
        result.removed.append(leftover)
        logging.info(f"Driver leftover removed: service {leftover.service}")
    return result
