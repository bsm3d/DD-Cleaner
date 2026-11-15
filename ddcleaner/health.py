"""
System health report (read-only): disks, free space, stability index, crashes, hardware and storage
errors, application crashes, uptime and pending reboot.

Collectors query Windows (PowerShell/CIM, event logs, registry) and return plain data; evaluators turn
that data into HealthItems and never touch the system, so they can be tested with fake data.
"""

import ctypes
import os
import string
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from security_audit import _run_ps_json as run_ps_json
from ddcleaner.common import winreg, SYSTEM_ROOT

PERIOD_DAYS = 30

OK, INFO, WARNING, CRITICAL, UNKNOWN = "ok", "info", "warning", "critical", "unknown"
SEVERITY = {OK: 0, INFO: 1, UNKNOWN: 2, WARNING: 3, CRITICAL: 4}

BUGCHECK_NAMES = {
    0x0A: "IRQL_NOT_LESS_OR_EQUAL", 0x19: "BAD_POOL_HEADER", 0x1A: "MEMORY_MANAGEMENT",
    0x1E: "KMODE_EXCEPTION_NOT_HANDLED", 0x3B: "SYSTEM_SERVICE_EXCEPTION", 0x50: "PAGE_FAULT_IN_NONPAGED_AREA",
    0x7E: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", 0x7F: "UNEXPECTED_KERNEL_MODE_TRAP", 0x9F: "DRIVER_POWER_STATE_FAILURE",
    0xA0: "INTERNAL_POWER_ERROR", 0xC2: "BAD_POOL_CALLER", 0xD1: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
    0xEF: "CRITICAL_PROCESS_DIED", 0xF4: "CRITICAL_OBJECT_TERMINATION", 0x101: "CLOCK_WATCHDOG_TIMEOUT",
    0x116: "VIDEO_TDR_FAILURE", 0x117: "VIDEO_TDR_TIMEOUT_DETECTED", 0x119: "VIDEO_SCHEDULER_INTERNAL_ERROR",
    0x124: "WHEA_UNCORRECTABLE_ERROR", 0x133: "DPC_WATCHDOG_VIOLATION", 0x139: "KERNEL_SECURITY_CHECK_FAILURE",
    0x13A: "KERNEL_MODE_HEAP_CORRUPTION", 0x154: "UNEXPECTED_STORE_EXCEPTION", 0x1E0: "HYPERVISOR_ERROR",
    0xC000021A: "STATUS_SYSTEM_PROCESS_TERMINATED",
}


@dataclass
class HealthItem:
    category: str
    status: str
    title: str
    details: List[str] = field(default_factory=list)


def as_list(value: Any) -> List:
    """PowerShell JSON: null -> [], single object -> [object]."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_time(text: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(text)[:19])
    except ValueError:
        return None


def bugcheck_name(code: int) -> str:
    return BUGCHECK_NAMES.get(code, "")


WHEA_NOTIFICATION_TYPES = {
    "e8f56ffe-919c-4cc5-ba88-65abe14913bb": "Machine check (CPU)",
    "2dce8bb1-bdd7-450e-b9ad-9cf4ebd4f890": "Corrected machine check (CPU)",
    "4e292f96-d843-4a55-a8c2-d481f27ebeee": "Corrected platform error",
    "cf93c01f-1a16-4dfc-b8bc-9c4daf67c104": "PCI Express",
    "5bad89ff-b7e6-42c9-814a-cf2485d6e98a": "Non-maskable interrupt",
    "3d61a466-ab40-409a-a698-f362d464b38f": "Error from the previous boot",
    "0033f803-2e70-4e88-992c-6f26daf3db7a": "Device driver report",
}


def decode_whea_record(text: str) -> Dict[str, str]:
    """
    Decode the CPER record carried by WHEA-Logger events (a string of decimal byte values).
    Returns {'source', 'driver', 'device'} as far as they can be read; {} if it is not a CPER record.
    """
    import re
    import uuid
    try:
        raw = bytes(int(x) for x in str(text).split())
    except ValueError:
        return {}
    if len(raw) < 128 or raw[:4] != b"CPER":
        return {}
    out = {"source": WHEA_NOTIFICATION_TYPES.get(str(uuid.UUID(bytes_le=raw[80:96])), "Hardware")}
    pos = raw.find(b"STORPORT")
    if pos >= 0:
        section = raw[pos + 8:pos + 8 + 256]
        out["source"] = "Storage controller (storport)"
        wide = re.search(rb"(?:[\x21-\x7e]\x00){3,}", section)
        if wide:
            out["driver"] = wide.group().decode("utf-16-le")
            section = section[wide.end():]
        words = [w.decode("ascii").strip() for w in re.findall(rb"[\x20-\x7e]{3,}", section)]
        out["device"] = " ".join(w for w in words if w)[:80]
    return out


def parse_bugcheck(text: str) -> Optional[int]:
    """'0x0000009f (0x..., ...)' or '159' -> 0x9F."""
    token = str(text or "").strip().split(" ")[0].split("(")[0]
    try:
        return int(token, 16) if token.lower().startswith("0x") else int(token)
    except ValueError:
        return None


# region Collectors

DISKS_PS = r"""
$out = foreach ($d in Get-PhysicalDisk) {
  $rel = $null
  try {
    $c = $d | Get-StorageReliabilityCounter -ErrorAction Stop
    $rel = [pscustomobject]@{ Temperature = $c.Temperature; TemperatureMax = $c.TemperatureMax; Wear = $c.Wear;
      ReadErrorsUncorrected = $c.ReadErrorsUncorrected; WriteErrorsUncorrected = $c.WriteErrorsUncorrected;
      PowerOnHours = $c.PowerOnHours }
  } catch {}
  [pscustomobject]@{ DeviceId = [string]$d.DeviceId; Name = $d.FriendlyName; Media = [string]$d.MediaType;
    Bus = [string]$d.BusType; Serial = ([string]$d.SerialNumber).Trim(); Health = [string]$d.HealthStatus;
    Status = (@($d.OperationalStatus) | ForEach-Object { [string]$_ }) -join ', '; Size = [int64]$d.Size;
    Reliability = $rel }
}
$smart = $null
try {
  $smart = @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop |
    ForEach-Object { [pscustomobject]@{ Instance = $_.InstanceName; PredictFailure = [bool]$_.PredictFailure } })
} catch {}
[pscustomobject]@{ disks = @($out); smart = $smart } | ConvertTo-Json -Depth 5 -Compress
"""

EVENTS_PS = r"""
$since = (Get-Date).AddDays(-__DAYS__)
function Get-Ev([string]$log, [string[]]$providers, $ids, $levels, [int]$max, [bool]$withMessage) {
  $all = @()
  foreach ($p in $providers) {
    $f = @{ LogName = $log; ProviderName = $p; StartTime = $since }
    if ($ids) { $f.Id = $ids }
    if ($levels) { $f.Level = $levels }
    try {
      $all += @(Get-WinEvent -FilterHashtable $f -MaxEvents $max -ErrorAction Stop | ForEach-Object {
        $msg = ''
        if ($withMessage -and $_.Message) { $msg = ($_.Message -split "`r?`n")[0] }
        [pscustomobject]@{ Id = $_.Id; Provider = $_.ProviderName; Level = [int]$_.Level;
          Time = $_.TimeCreated.ToString('s');
          Props = @($_.Properties | Select-Object -First 8 | ForEach-Object { [string]$_.Value });
          Message = $msg }
      })
    } catch {}
  }
  return ,$all
}
$stability = $null
try {
  $m = @(Get-CimInstance Win32_ReliabilityStabilityMetrics -ErrorAction Stop |
    Where-Object { $_.TimeGenerated -ge $since } | Sort-Object TimeGenerated -Descending)
  if ($m.Count) {
    $stability = [pscustomobject]@{ Current = [double]$m[0].SystemStabilityIndex;
      Minimum = [double](($m | Measure-Object SystemStabilityIndex -Minimum).Minimum); Samples = $m.Count }
  }
} catch {}
[pscustomobject]@{
  bugchecks = Get-Ev 'System' @('Microsoft-Windows-WER-SystemErrorReporting') @(1001) $null 200 $false
  kernel_power = Get-Ev 'System' @('Microsoft-Windows-Kernel-Power') @(41) $null 200 $false
  whea = Get-Ev 'System' @('Microsoft-Windows-WHEA-Logger') $null $null 500 $true
  storage = Get-Ev 'System' @('disk', 'Ntfs', 'Microsoft-Windows-Ntfs', 'stornvme', 'storahci', 'volmgr') $null @(1, 2, 3) 500 $true
  app_crashes = Get-Ev 'Application' @('Application Error', 'Application Hang') @(1000, 1002) $null 3000 $false
  stability = $stability
} | ConvertTo-Json -Depth 5 -Compress
"""


def collect_disks() -> Optional[Dict]:
    rc, data = run_ps_json(DISKS_PS, timeout=120)
    return data if isinstance(data, dict) else None


def collect_events(days: int = PERIOD_DAYS) -> Optional[Dict]:
    rc, data = run_ps_json(EVENTS_PS.replace("__DAYS__", str(int(days))), timeout=180)
    return data if isinstance(data, dict) else None


def fixed_volumes() -> List[Dict]:
    """Fixed drives with size and free space."""
    import shutil
    volumes = []
    kernel32 = ctypes.windll.kernel32
    mask = kernel32.GetLogicalDrives()
    for i, letter in enumerate(string.ascii_uppercase):
        if not mask & (1 << i):
            continue
        root = f"{letter}:\\"
        if kernel32.GetDriveTypeW(root) != 3:  # DRIVE_FIXED
            continue
        try:
            usage = shutil.disk_usage(root)
        except OSError:
            continue
        volumes.append({"root": root, "total": usage.total, "free": usage.free,
                        "system": root.lower() == os.path.splitdrive(SYSTEM_ROOT)[0].lower() + "\\"})
    return volumes


def uptime() -> timedelta:
    kernel32 = ctypes.windll.kernel32
    kernel32.GetTickCount64.restype = ctypes.c_ulonglong
    return timedelta(milliseconds=kernel32.GetTickCount64())


def _key_exists(path: str) -> bool:
    try:
        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path).Close()
        return True
    except OSError:
        return False


def pending_reboot_reasons() -> List[str]:
    reasons = []
    if _key_exists(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"):
        reasons.append("Windows component servicing (updates or features) is waiting for a restart")
    if _key_exists(r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"):
        reasons.append("Windows Update is waiting for a restart")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager") as key:
            ops = winreg.QueryValueEx(key, "PendingFileRenameOperations")[0]
            if ops and any(ops):
                reasons.append("Files are waiting to be replaced at the next restart (installer or update)")
    except OSError:
        pass
    return reasons


def minidumps(days: int = PERIOD_DAYS) -> List[datetime]:
    folder = os.path.join(SYSTEM_ROOT, "Minidump")
    since = datetime.now() - timedelta(days=days)
    dates = []
    try:
        for name in os.listdir(folder):
            if name.lower().endswith(".dmp"):
                t = datetime.fromtimestamp(os.path.getmtime(os.path.join(folder, name)))
                if t >= since:
                    dates.append(t)
    except OSError:
        pass
    return sorted(dates, reverse=True)

# endregion


# region Evaluators

def evaluate_disks(data: Optional[Dict]) -> List[HealthItem]:
    if not data:
        return [HealthItem("Disks", UNKNOWN, "Disk health could not be read")]
    items = []
    for d in as_list(data.get("disks")):
        size_gb = (d.get("Size") or 0) / 1e9
        name = f"{d.get('Name') or 'Disk ' + str(d.get('DeviceId'))} ({d.get('Media') or '?'}, {d.get('Bus') or '?'}, {size_gb:.0f} GB)"
        health = d.get("Health") or "Unknown"
        status = OK if health == "Healthy" else CRITICAL if health == "Unhealthy" else WARNING
        details = [f"Windows health: {health}, status: {d.get('Status') or '?'}"]
        rel = d.get("Reliability")
        if rel:
            temp = rel.get("Temperature") or 0
            if temp:
                details.append(f"Temperature: {temp} °C (max seen {rel.get('TemperatureMax') or '?'} °C)")
                limit = 55 if d.get("Media") == "HDD" else 70
                if temp >= limit:
                    status = max(status, WARNING, key=SEVERITY.get)
                    details.append(f"Temperature is high (≥ {limit} °C): check cooling")
            wear = rel.get("Wear")
            if wear:
                details.append(f"Wear: {wear} % of rated endurance used")
                if wear >= 90:
                    status = CRITICAL
                elif wear >= 70:
                    status = max(status, WARNING, key=SEVERITY.get)
            errors = (rel.get("ReadErrorsUncorrected") or 0) + (rel.get("WriteErrorsUncorrected") or 0)
            if errors:
                status = max(status, WARNING, key=SEVERITY.get)
                details.append(f"Uncorrected read/write errors: {errors}")
            if rel.get("PowerOnHours"):
                details.append(f"Power-on time: {rel['PowerOnHours']} h")
        else:
            details.append("Temperature/wear counters: not available (administrator rights or driver support needed)")
        items.append(HealthItem("Disks", status, name, details))

    smart = data.get("smart")
    if smart is None:
        items.append(HealthItem("Disks", INFO, "SMART failure prediction not readable",
                                ["Needs administrator rights (or not supported by the disk driver)."]))
    else:
        failing = [s.get("Instance") for s in as_list(smart) if s.get("PredictFailure")]
        if failing:
            items.append(HealthItem("Disks", CRITICAL, f"SMART predicts a failure on {len(failing)} disk(s)",
                                    ["Back up your data now and replace the disk."] + [str(f) for f in failing]))
    if not items:
        items.append(HealthItem("Disks", UNKNOWN, "No disk reported"))
    return items


def evaluate_volumes(volumes: List[Dict]) -> List[HealthItem]:
    items = []
    for v in volumes:
        if not v.get("total"):
            continue
        pct = 100 * v["free"] / v["total"]
        free_gb = v["free"] / 1e9
        status = OK
        if pct < 5 or free_gb < 5:
            status = CRITICAL
        elif pct < 10 or free_gb < 15:
            status = WARNING
        label = f"{v['root']} {free_gb:.1f} GB free of {v['total'] / 1e9:.0f} GB ({pct:.0f} %)"
        details = ["System drive: updates need several GB free."] if v.get("system") and status != OK else []
        items.append(HealthItem("Free space", status, label, details))
    return items


def evaluate_stability(events: Optional[Dict]) -> HealthItem:
    stab = (events or {}).get("stability")
    if not stab:
        return HealthItem("Stability", UNKNOWN, "Reliability index not available",
                          ["Windows computes it hourly (service 'RacTask'); it may be disabled on this PC."])
    try:
        current, minimum = float(stab.get("Current")), float(stab.get("Minimum"))
    except (TypeError, ValueError):
        return HealthItem("Stability", UNKNOWN, "Reliability index not readable")
    status = OK if current >= 7 else WARNING if current >= 3 else CRITICAL
    return HealthItem("Stability", status, f"Windows reliability index: {current:.1f} / 10",
                      [f"Lowest in the last {PERIOD_DAYS} days: {minimum:.1f}",
                       "It drops with every crash, failed update and unexpected shutdown (see below). "
                       "Details: Control Panel > Security and Maintenance > View reliability history."])


def evaluate_crashes(events: Optional[Dict], dumps: List[datetime], disks: Optional[Dict] = None) -> List[HealthItem]:
    if events is None:
        return [HealthItem("Crashes", UNKNOWN, "Event logs could not be read")]
    items = []

    bugchecks = as_list(events.get("bugchecks"))
    power = as_list(events.get("kernel_power"))
    # Kernel-Power 41 with a bug check code duplicates a blue screen; with 0 it is a power loss or forced reset
    bsod_times = {e.get("Time") for e in bugchecks}
    blue_screens = []
    for e in bugchecks:
        code = parse_bugcheck((e.get("Props") or [""])[0])
        blue_screens.append((e.get("Time", ""), code))
    hard_resets = []
    for e in power:
        code = parse_bugcheck((e.get("Props") or ["0"])[0]) or 0
        if code:
            if not any(abs((parse_time(e.get("Time")) or datetime.min) - (parse_time(t) or datetime.max)).total_seconds()
                       < 600 for t in bsod_times):
                blue_screens.append((e.get("Time", ""), code))
        else:
            hard_resets.append(e.get("Time", ""))

    if blue_screens:
        status = CRITICAL if len(blue_screens) >= 3 else WARNING
        codes = Counter(c for _, c in blue_screens)
        details = [f"{f'0x{c:X}' if c is not None else '?'} {bugcheck_name(c) if c is not None else ''}: {n} time(s)"
                   for c, n in codes.most_common()]
        details += [str(t).replace("T", " ") for t in sorted((t for t, _ in blue_screens), key=str, reverse=True)[:10]]
        if dumps:
            details.append(f"{len(dumps)} crash dump(s) in {os.path.join(SYSTEM_ROOT, 'Minidump')}")
        items.append(HealthItem("Crashes", status, f"{len(blue_screens)} blue screen(s) in {PERIOD_DAYS} days", details))
    else:
        items.append(HealthItem("Crashes", OK, f"No blue screen in {PERIOD_DAYS} days"))

    if hard_resets:
        status = WARNING if len(hard_resets) >= 2 else INFO
        items.append(HealthItem("Crashes", status, f"{len(hard_resets)} unexpected shutdown(s) in {PERIOD_DAYS} days",
                                ["Power loss, reset button, forced power-off or a complete freeze (no blue screen). "
                                 "Frequent ones point to power supply, overheating or hardware issues."]
                                + [t.replace("T", " ") for t in sorted(hard_resets, reverse=True)[:10]]))

    # WHEA records raised by the storage stack (storport) name a disk: report them with storage
    whea_storage: Counter = Counter()
    whea_storage_times: Dict[tuple, List[str]] = {}
    whea_other = []
    for e in as_list(events.get("whea")):
        props = e.get("Props") or []
        record = decode_whea_record(props[1]) if len(props) > 1 else {}
        if record.get("driver") or "storport" in record.get("source", ""):
            key = (record.get("device") or "?", record.get("driver") or "?", e.get("Level") in (1, 2))
            whea_storage[key] += 1
            whea_storage_times.setdefault(key, []).append(e.get("Time", ""))
        else:
            whea_other.append((e, record))

    if whea_other:
        fatal = [e for e, _ in whea_other if e.get("Level") in (1, 2)]
        status = CRITICAL if fatal else WARNING
        by_kind = Counter((e.get("Id"), r.get("source", ""), e.get("Message") or "") for e, r in whea_other)
        items.append(HealthItem("Hardware", status,
                                f"{len(whea_other)} hardware error report(s) (WHEA) in {PERIOD_DAYS} days",
                                ["Reported by the CPU, memory or PCIe devices. Errors that repeat announce failing "
                                 "hardware, overclocking or unstable settings (voltages, memory profile)."]
                                + [f"Event {i} × {n}{f' ({s})' if s else ''}: {m}"
                                   for (i, s, m), n in by_kind.most_common(8)]
                                + [t.replace("T", " ") for t in sorted((e.get("Time", "") for e in fatal),
                                                                        reverse=True)[:10]]))
    else:
        items.append(HealthItem("Hardware", OK, f"No CPU / memory / PCIe error report (WHEA) in {PERIOD_DAYS} days"))

    storage_text = " ".join(e.get("Message") or "" for e in as_list(events.get("storage")))
    for (device, driver, fatal), n in whea_storage.most_common():
        same_model = [d for d in as_list((disks or {}).get("disks"))
                      if device != "?" and str(d.get("Name") or "").replace(" ", "").startswith(device.replace(" ", ""))]
        details = ["The disk stopped responding and was reset by its controller. Check the data and power cables, "
                   "then the disk itself (manufacturer tool). Back up its data.",
                   "Windows logs this as a 'fatal hardware error' (WHEA event 1) although the PC usually keeps running."]
        if len(same_model) > 1:
            details.append("Several disks have this model: " + ", ".join(
                f"Disk {d.get('DeviceId')} (serial {d.get('Serial') or '?'})" for d in same_model))
        details += disk_numbers_hint(storage_text, disks)
        details += [t.replace("T", " ") for t in whea_storage_times.get((device, driver, fatal), [])[:10]]
        items.append(HealthItem("Storage", CRITICAL if fatal else WARNING,
                                f"Disk {device}: {n} {'fatal ' if fatal else ''}device error(s) reported by {driver}",
                                details))

    storage = as_list(events.get("storage"))
    if storage:
        errors = [e for e in storage if e.get("Level") in (1, 2)]
        status = WARNING if errors else INFO
        by_src = Counter((e.get("Provider"), e.get("Id"), e.get("Message") or "") for e in storage)
        details = ["Bad blocks, I/O retries, disks disappearing or file system corruption. Run 'chkdsk' if NTFS "
                   "reports corruption."]
        details += [f"{p} {i} × {n}: {m}" for (p, i, m), n in by_src.most_common(8)]
        details += disk_numbers_hint(" ".join(m for _, _, m in by_src), disks)
        items.append(HealthItem("Storage", status, f"{len(storage)} disk / file system warning(s) in {PERIOD_DAYS} days",
                                details))
    else:
        items.append(HealthItem("Storage", OK, f"No disk or file system error in {PERIOD_DAYS} days"))
    return items


def disk_numbers_hint(text: str, disks: Optional[Dict]) -> List[str]:
    """'Disk 0' in event messages -> which physical disk that is (model and serial)."""
    import re
    by_id = {str(d.get("DeviceId")): d for d in as_list((disks or {}).get("disks"))}
    hints = []
    for number in sorted(set(re.findall(r"\b(?:Disk|Disque|Datenträger)\s+(\d+)\b", text, re.IGNORECASE))):
        d = by_id.get(number)
        if d:
            hints.append(f"'Disk {number}' in the events = {d.get('Name')} (serial {d.get('Serial') or '?'})")
    return hints


def evaluate_app_crashes(events: Optional[Dict]) -> Optional[HealthItem]:
    if events is None:
        return None
    crashes = as_list(events.get("app_crashes"))
    if not crashes:
        return HealthItem("Applications", OK, f"No application crash in {PERIOD_DAYS} days")
    counts = Counter()
    for e in crashes:
        app = (e.get("Props") or ["?"])[0] or "?"
        counts[(app, "hang" if e.get("Id") == 1002 else "crash")] += 1
    status = WARNING if counts.most_common(1)[0][1] >= 10 else INFO
    return HealthItem("Applications", status, f"{len(crashes)} application crash(es) / hang(s) in {PERIOD_DAYS} days",
                      [f"{app}: {n} {kind}(es)" if kind == "crash" else f"{app}: {n} hang(s)"
                       for (app, kind), n in counts.most_common(10)])


def evaluate_uptime(up: timedelta, reboot_reasons: List[str]) -> List[HealthItem]:
    items = []
    days = up.days
    text = f"Up for {days} day(s) {up.seconds // 3600} h"
    items.append(HealthItem("System", WARNING if days >= 30 else OK, text,
                            ["A restart every few weeks applies updates and frees leaked resources."] if days >= 30 else []))
    if reboot_reasons:
        items.append(HealthItem("System", WARNING, "A restart is pending", reboot_reasons))
    return items


def build_report(disks: Optional[Dict], events: Optional[Dict], volumes: List[Dict], up: timedelta,
                 reboot_reasons: List[str], dumps: List[datetime]) -> List[HealthItem]:
    items: List[HealthItem] = []
    items += evaluate_disks(disks)
    items += evaluate_volumes(volumes)
    items.append(evaluate_stability(events))
    items += evaluate_crashes(events, dumps, disks)
    app = evaluate_app_crashes(events)
    if app:
        items.append(app)
    items += evaluate_uptime(up, reboot_reasons)
    return items


def run_health_check(progress=None) -> List[HealthItem]:
    def step(text):
        if progress:
            progress(text)
    step("Reading disk health...")
    disks = collect_disks()
    step(f"Reading event logs ({PERIOD_DAYS} days)...")
    events = collect_events()
    step("Checking free space and pending restart...")
    return build_report(disks, events, fixed_volumes(), uptime(), pending_reboot_reasons(), minidumps())

# endregion
