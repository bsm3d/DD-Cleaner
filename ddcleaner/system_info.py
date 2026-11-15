"""System inventory (installed programs, graphics cards, activation) and DPC/ISR load measurement. Read-only."""

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM32, SYSTEM_ROOT, safe_environment, sys_exe, winreg

GPU_CLASS_KEY = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
WINDOWS_APPLICATION_ID = "55c92734-d682-4d71-983e-d6ec3f16059f"
LICENSE_STATUS = {0: "Unlicensed", 1: "Licensed", 2: "Initial grace period", 3: "Additional grace period",
                  4: "Non-genuine grace period", 5: "Notification", 6: "Extended grace period"}


def run_powershell(script: str, timeout: int = 60):
    """Run a PowerShell script that prints JSON; None when it fails or prints nothing."""
    completed = subprocess.run(
        [sys_exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
        cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    return json.loads(completed.stdout)


# region Installed programs

@dataclass
class Program:
    name: str
    version: str
    publisher: str
    scope: str
    location: str = ""       # the folder of the program, when the entry says where it is


def _program_folder(install_location: str, *commands) -> str:
    """The install folder, or the folder of the program named by the icon / uninstaller (never a Windows folder)."""
    folder = (install_location or "").strip().strip('"').rstrip("\\")
    if folder and os.path.isabs(folder):
        return folder
    for command in commands:
        match = re.match(r'^\s*"?([A-Za-z]:\\[^"]*?\.(?:exe|ico|dll|msi))', str(command or ""), re.I)
        if match:
            parent = os.path.dirname(match.group(1))
            if not os.path.normcase(parent).startswith(os.path.normcase(SYSTEM_ROOT)):
                return parent
    return ""


def installed_programs(reg=winreg) -> List[Program]:
    """Programs listed in Add/Remove Programs (machine, 32-bit on 64-bit, current user). Updates and hidden
    system components are left out."""
    sources = [(reg.HKEY_LOCAL_MACHINE, reg.KEY_WOW64_64KEY, "All users"),
               (reg.HKEY_LOCAL_MACHINE, reg.KEY_WOW64_32KEY, "All users (32-bit)"),
               (reg.HKEY_CURRENT_USER, reg.KEY_WOW64_64KEY, "Current user")]
    found: Dict[tuple, Program] = {}

    def value(key, name):
        try:
            return reg.QueryValueEx(key, name)[0]
        except OSError:
            return None

    for hive, view, scope in sources:
        try:
            root = reg.OpenKey(hive, UNINSTALL_KEY, 0, reg.KEY_READ | view)
        except OSError:
            continue
        with root:
            index = 0
            while True:
                try:
                    sub = reg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                try:
                    key = reg.OpenKey(root, sub, 0, reg.KEY_READ | view)
                except OSError:
                    continue
                with key:
                    name = value(key, "DisplayName")
                    if not isinstance(name, str) or not name.strip():
                        continue
                    if value(key, "SystemComponent") == 1 or value(key, "ParentKeyName"):
                        continue
                    if name.startswith(("KB", "Update for", "Security Update")):
                        continue
                    version = str(value(key, "DisplayVersion") or "")
                    publisher = str(value(key, "Publisher") or "")
                    folder = _program_folder(value(key, "InstallLocation"), value(key, "DisplayIcon"), value(key, "UninstallString"))
                    found.setdefault((name.strip().lower(), version), Program(name.strip(), version, publisher, scope, folder))
    return sorted(found.values(), key=lambda p: p.name.lower())

# endregion


# region Graphics cards and activation

@dataclass
class Gpu:
    name: str
    driver_version: str
    driver_date: str
    vram_gb: float
    resolution: str


def gpu_memory_by_name(reg=winreg) -> Dict[str, int]:
    """Real video memory from the driver key. Win32_VideoController.AdapterRAM is a 32-bit number: 4 GB at most."""
    result: Dict[str, int] = {}
    try:
        root = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, GPU_CLASS_KEY, 0, reg.KEY_READ | reg.KEY_WOW64_64KEY)
    except OSError:
        return result
    with root:
        index = 0
        while True:
            try:
                sub = reg.EnumKey(root, index)
            except OSError:
                break
            index += 1
            try:
                with reg.OpenKey(root, sub, 0, reg.KEY_READ | reg.KEY_WOW64_64KEY) as key:
                    desc = reg.QueryValueEx(key, "DriverDesc")[0]
                    for name in ("HardwareInformation.qwMemorySize", "HardwareInformation.MemorySize"):
                        try:
                            size = reg.QueryValueEx(key, name)[0]
                        except OSError:
                            continue
                        if isinstance(size, int) and size > 0:
                            result[str(desc)] = max(result.get(str(desc), 0), size)
            except OSError:
                continue
    return result


GPU_PS = ("[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
          "$g = @(Get-CimInstance Win32_VideoController | ForEach-Object { [pscustomobject]@{ "
          "Name = $_.Name; Driver = $_.DriverVersion; "
          "Date = if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { '' }; "
          "Ram = [uint64]$_.AdapterRAM; W = $_.CurrentHorizontalResolution; H = $_.CurrentVerticalResolution; "
          "Hz = $_.CurrentRefreshRate } }); ConvertTo-Json -InputObject $g -Compress")


def graphics_cards(run: Callable = run_powershell, memory: Optional[Dict[str, int]] = None) -> List[Gpu]:
    data = run(GPU_PS)
    if isinstance(data, dict):
        data = [data]
    memory = gpu_memory_by_name() if memory is None else memory
    cards = []
    for g in data or []:
        if not isinstance(g, dict):
            continue
        name = str(g.get("Name") or "")
        vram = max(int(g.get("Ram") or 0), memory.get(name, 0))
        resolution = f"{g['W']}x{g['H']} @ {g.get('Hz')} Hz" if g.get("W") else ""
        cards.append(Gpu(name, str(g.get("Driver") or ""), str(g.get("Date") or ""), round(vram / 1024 ** 3, 1), resolution))
    return cards


ACTIVATION_PS = (
    "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
    f"$l = Get-CimInstance SoftwareLicensingProduct | Where-Object {{ $_.PartialProductKey -and $_.ApplicationID -eq '{WINDOWS_APPLICATION_ID}' }} "
    "| Select-Object -First 1; "
    "$o = Get-CimInstance Win32_OperatingSystem; "
    "[pscustomobject]@{ Edition = $o.Caption; Build = $o.BuildNumber; Status = if ($l) { [int]$l.LicenseStatus } else { -1 }; "
    "Channel = if ($l) { [string]$l.ProductKeyChannel } else { '' }; "
    "Partial = if ($l) { [string]$l.PartialProductKey } else { '' } } | ConvertTo-Json -Compress")


def windows_activation(run: Callable = run_powershell) -> Dict[str, str]:
    """Edition, build, activation state, license channel and the LAST FIVE characters of the key (never the key)."""
    data = run(ACTIVATION_PS)
    if not isinstance(data, dict):
        return {}
    status = int(data.get("Status", -1))
    return {"edition": str(data.get("Edition") or ""), "build": str(data.get("Build") or ""),
            "status": LICENSE_STATUS.get(status, "Unknown"), "licensed": str(status == 1),
            "channel": str(data.get("Channel") or ""), "partial_key": str(data.get("Partial") or "")}

# endregion


# region DPC / ISR load

@dataclass
class LoadResult:
    dpc: List[float]
    isr: List[float]

    @property
    def worst(self) -> float:
        return max(self.dpc + self.isr + [0.0])

    @property
    def verdict(self) -> str:
        """Rough reading for real-time audio and video work (percent of processor time, not microseconds)."""
        worst = self.worst
        if worst < 1.0:
            return "Low: nothing in the drivers is holding the processor."
        if worst < 3.0:
            return "Moderate: fine for most work, watch it if audio crackles."
        return "High: a driver is using a lot of processor time in interrupts; real-time audio may crackle. " \
               "Update the network, audio and graphics drivers, and test with a tool such as LatencyMon."


def load_script(samples: int) -> str:
    return ("$d = @(); $i = @(); "
            f"for ($n = 0; $n -lt {int(samples)}; $n++) {{ "
            "$p = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter \"Name='_Total'\"; "
            "$d += [double]$p.PercentDPCTime; $i += [double]$p.PercentInterruptTime; Start-Sleep -Seconds 1 }; "
            "[pscustomobject]@{ Dpc = $d; Isr = $i } | ConvertTo-Json -Compress")


def measure_dpc_isr(samples: int = 5, run: Callable = run_powershell) -> LoadResult:
    """DPC and interrupt time of the whole processor, one sample per second (locale independent: WMI, not
    the localized performance counter names)."""
    data = run(load_script(samples), timeout=samples + 60)
    if not isinstance(data, dict):
        raise RuntimeError("The processor counters could not be read.")

    def numbers(v):
        values = v if isinstance(v, list) else [v]
        return [float(x) for x in values if isinstance(x, (int, float))]
    result = LoadResult(numbers(data.get("Dpc")), numbers(data.get("Isr")))
    logging.info(f"DPC/ISR load: worst {result.worst:.2f}% over {len(result.dpc)} samples")
    return result

# endregion
