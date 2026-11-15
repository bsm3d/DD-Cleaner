"""Driver packages nothing uses any more (a webcam or NAS that is gone, old versions piled up in the driver store).

A third-party driver package (oemNN.inf) is only offered when no CONNECTED device uses it. Removing one first saves a
copy of its files (pnputil /export-driver, restore with pnputil /add-driver) and then asks Windows to delete it
WITHOUT /force, so Windows itself refuses a package that is still in use. Core classes (system, processor, storage
controllers...) are never offered.
"""

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set, Tuple

from ddcleaner import startup
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM_ROOT, SYSTEM32, data_dir, safe_environment, sys_exe

PUBLISHED = re.compile(r"oem\d+\.inf", re.I)
STORE = os.path.join(SYSTEM32, "DriverStore", "FileRepository")
# class GUIDs the PC cannot do without: never offered, even when no connected device seems to use them
CRITICAL_CLASSES = {
    "{4d36e97d-e325-11ce-bfc1-08002be10318}",   # System devices
    "{50127dc3-0f36-415e-a6cc-4cb3be910b65}",   # Processors
    "{4d36e96a-e325-11ce-bfc1-08002be10318}",   # Hard disk controllers
    "{4d36e97b-e325-11ce-bfc1-08002be10318}",   # SCSI and RAID controllers
    "{4d36e967-e325-11ce-bfc1-08002be10318}",   # Disk drives
    "{71a27cdd-812a-4273-a0b6-d3c24b0a2d36}",   # Volumes
    "{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}",   # Firmware
    "{d94ee5d8-d189-4994-83d2-f68d7d41b0e6}",   # Security devices
    "{4d36e966-e325-11ce-bfc1-08002be10318}",   # Computer
    "{72631e54-78a4-11d0-bcf7-00aa00b7b32a}",   # Batteries
    # these attach to another device's driver, so no device lists them as its own: they would look unused when they are not
    "{e2f84ce7-8efa-411c-aa69-97454ca4cb57}",   # Extensions
    "{62f9c741-b25a-46ce-b54c-9bccce08b6f2}",   # Software devices
    "{5c4c3332-344d-483c-8739-259e934c9cc8}",   # Software components
}
CAT_OLD, CAT_GONE, CAT_NONE = "Older version", "Device not connected", "No device"
CAT_USED, CAT_PROTECTED = "In use", "Protected"
RISK = {CAT_OLD: "Safe", CAT_GONE: "Check", CAT_NONE: "Check", CAT_USED: "Danger", CAT_PROTECTED: "Locked"}

BINDINGS_PS = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$present = @{}
Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | ForEach-Object { $present[([string]$_.InstanceId).ToUpper()] = $true }
$rows = Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.InfName -like 'oem*.inf' } | ForEach-Object {
    [pscustomobject]@{ Name = [string]$_.DeviceName; Inf = [string]$_.InfName; Id = [string]$_.DeviceID;
                       Class = [string]$_.DeviceClass; Present = [bool]$present[([string]$_.DeviceID).ToUpper()] }
}
ConvertTo-Json -InputObject @($rows) -Compress
"""


@dataclass
class Package:
    published: str           # oem12.inf
    original: str            # wdnetworkstorage.inf
    provider: str = ""
    class_name: str = ""
    class_guid: str = ""
    version: str = ""        # 1.2.3.4
    date: str = ""
    signer: str = ""

    @property
    def version_key(self) -> Tuple[int, ...]:
        return tuple(int(p) for p in re.findall(r"\d+", self.version))


@dataclass
class Binding:
    name: str
    inf: str
    present: bool
    device_class: str = ""
    instance_id: str = ""


@dataclass
class Candidate:
    package: Package
    category: str
    reason: str
    devices: List[str] = field(default_factory=list)       # the devices named in the reason (connected or not)
    ghost_ids: List[str] = field(default_factory=list)     # instance ids of the NOT connected devices that use it

    @property
    def risk(self) -> str:
        """Safe: a newer version is installed. Check: the hardware may still be yours (plug it in and it needs this driver).
        Danger: a connected device uses it right now. Locked: a core driver, never removed from here."""
        return RISK[self.category]

    @property
    def in_use(self) -> bool:
        return self.category == CAT_USED

    @property
    def removable(self) -> bool:
        return self.category != CAT_PROTECTED


@dataclass
class RemoveResult:
    removed: List[Candidate] = field(default_factory=list)
    failed: List[Tuple[Candidate, str]] = field(default_factory=list)
    backups: List[str] = field(default_factory=list)


def backup_dir() -> str:
    return os.path.join(data_dir(), "driver_backups")


# region Reading

def parse_enum_drivers(text: str) -> List[Package]:
    """Packages from `pnputil /enum-drivers`. The labels are translated by Windows, so the fields are read by position:
    published name, original name, provider, class name, class GUID, version and date, signer."""
    packages = []
    for block in re.split(r"\r?\n\s*\r?\n", text):
        values = [line.partition(":")[2].strip() for line in block.splitlines() if ":" in line]
        if len(values) < 6 or not PUBLISHED.fullmatch(values[0]):
            continue
        date, _, version = values[5].partition(" ")
        packages.append(Package(values[0].lower(), values[1], values[2], values[3], values[4].lower(), version.strip(),
                                date, values[6] if len(values) > 6 else ""))
    return packages


def _pnputil(args: List[str], timeout: int = 120) -> Tuple[int, str]:
    done = subprocess.run([sys_exe("pnputil.exe")] + args, capture_output=True, errors="replace", timeout=timeout,
                          cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)
    return done.returncode, done.stdout.decode("utf-8", errors="replace") if isinstance(done.stdout, bytes) else done.stdout


def list_packages(run: Callable = _pnputil) -> List[Package]:
    code, out = run(["/enum-drivers"])
    if code != 0:
        raise OSError("The driver store could not be listed")
    return parse_enum_drivers(out)


def read_bindings(run: Callable = startup._run_powershell) -> List[Binding]:
    data = run(BINDINGS_PS, 120)
    if isinstance(data, dict):
        data = [data]
    return [Binding(str(d.get("Name") or ""), str(d.get("Inf") or "").lower(), bool(d.get("Present")), str(d.get("Class") or ""),
                    str(d.get("Id") or ""))
            for d in data or [] if isinstance(d, dict)]

# endregion


def find_unused(packages: List[Package], bindings: List[Binding]) -> List[Candidate]:
    """Packages no connected device uses, with why each one is proposed."""
    if not any(b.present for b in bindings):
        raise OSError("The connected devices could not be read: nothing can be judged safely")
    in_use: Set[str] = {b.inf for b in bindings if b.present}
    candidates = []
    for pkg in packages:
        if pkg.published in in_use or pkg.class_guid in CRITICAL_CLASSES:
            continue
        candidates.append(_unused_candidate(pkg, packages, bindings))
    candidates.sort(key=lambda c: (c.package.class_name.lower(), c.package.original.lower(), c.package.version_key))
    return candidates


def _unused_candidate(pkg: Package, packages: List[Package], bindings: List[Binding]) -> Candidate:
    """Why a package that no connected device uses is proposed."""
    ghosts = [b for b in bindings if not b.present and b.inf == pkg.published]
    names = sorted({b.name for b in ghosts})
    ids = [b.instance_id for b in ghosts if b.instance_id]
    newer = [o for o in packages if o is not pkg and o.original.lower() == pkg.original.lower()
             and o.provider == pkg.provider and o.version_key > pkg.version_key]
    if newer:
        best = max(newer, key=lambda o: o.version_key)
        return Candidate(pkg, CAT_OLD, f"A newer version ({best.version}, {best.published}) is installed", names, ids)
    if names:
        return Candidate(pkg, CAT_GONE, "Only used by devices that are not connected: " + ", ".join(names[:3])
                         + ("..." if len(names) > 3 else ""), names, ids)
    return Candidate(pkg, CAT_NONE, "No device uses this package", [], [])


def list_all(packages: List[Package], bindings: List[Binding]) -> List[Candidate]:
    """Every third-party package with its situation: in use (a connected device needs it right now), unused, or a core
    driver that is listed but locked."""
    if not any(b.present for b in bindings):
        raise OSError("The connected devices could not be read: nothing can be judged safely")
    result = []
    for pkg in packages:
        present = sorted({b.name for b in bindings if b.present and b.inf == pkg.published})
        if pkg.class_guid in CRITICAL_CLASSES:
            result.append(Candidate(pkg, CAT_PROTECTED, "Core driver: never removed from here", present))
        elif present:
            ghosts = [b.instance_id for b in bindings if not b.present and b.inf == pkg.published and b.instance_id]
            result.append(Candidate(pkg, CAT_USED, "In use by: " + ", ".join(present[:3]) + ("..." if len(present) > 3 else ""),
                                    present, ghosts))
        else:
            result.append(_unused_candidate(pkg, packages, bindings))
    result.sort(key=lambda c: (c.package.class_name.lower(), c.package.original.lower(), c.package.version_key))
    return result


def scan_all(run_packages: Callable = _pnputil, run_bindings: Callable = startup._run_powershell) -> List[Candidate]:
    return list_all(list_packages(run_packages), read_bindings(run_bindings))


def scan(run_packages: Callable = _pnputil, run_bindings: Callable = startup._run_powershell) -> List[Candidate]:
    return find_unused(list_packages(run_packages), read_bindings(run_bindings))


def store_folder(original: str, store: str = STORE) -> str:
    """Where the files of a package sit in the driver store ('' when not found; newest folder if several)."""
    prefix = original.lower() + "_"
    try:
        folders = [os.path.join(store, n) for n in os.listdir(store) if n.lower().startswith(prefix)]
    except OSError:
        return ""
    return max(folders, key=os.path.getmtime) if folders else ""


def remove_packages(candidates: List[Candidate], folder: Optional[str] = None, run: Callable = _pnputil,
                    stop: Callable[[], bool] = lambda: False) -> RemoveResult:
    """Save then delete each package. A package Windows says is in use stays installed."""
    result = RemoveResult()
    folder = folder or backup_dir()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for candidate in candidates:
        pkg = candidate.package
        if stop():
            result.failed.append((candidate, "Stopped"))
            continue
        if not PUBLISHED.fullmatch(pkg.published) or pkg.class_guid in CRITICAL_CLASSES:
            result.failed.append((candidate, "This package cannot be removed from here"))
            continue
        target = os.path.join(folder, f"{stamp}_{pkg.published[:-4]}_{re.sub(r'[^A-Za-z0-9._-]', '_', pkg.original)}")
        try:
            os.makedirs(target, exist_ok=True)
            code, out = run(["/export-driver", pkg.published, target])
            if code != 0 or not os.listdir(target):
                result.failed.append((candidate, "The backup of the driver files failed: nothing removed"))
                continue
            result.backups.append(target)
            code, out = run(["/delete-driver", pkg.published])
        except (OSError, subprocess.SubprocessError) as e:
            result.failed.append((candidate, str(e)))
            continue
        if code in (0, 3010):
            result.removed.append(candidate)
            logging.info(f"Driver removed: {pkg.published} ({pkg.original}, {pkg.provider} {pkg.version})")
        else:
            why = "Windows refused: the driver is in use" if code in (1, 5, 259) or "in use" in out.lower() else \
                  f"pnputil failed (code {code}): run as administrator"
            result.failed.append((candidate, why))
    return result
