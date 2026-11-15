"""Malware hunt, read-only: where malware keeps itself alive (services, scheduled tasks, hijacked Windows keys, WMI
subscriptions, hosts file, proxy, browser extensions) and what is running right now.

Nothing is changed. Every finding carries the program file when there is one, so the user can scan it with ClamAV.
A finding is a reason to look, not a verdict: severity 2 means "very unusual", 1 means "worth a look".
"""

import difflib
import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set

from ddcleaner import dead_registry, file_inspect, folder_security, pe_signature, startup, traffic
from ddcleaner.common import SYSTEM_ROOT, SYSTEM32, winreg

INFO, LOOK, SUSPICIOUS = 0, 1, 2
MAX_SIGNED_SIZE = 64 * 1024 * 1024  # bigger programs are not read for their signature (cost), only listed

SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
IFEO = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
WINDOWS_NT_WINDOWS = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
SESSION_MANAGER = r"SYSTEM\CurrentControlSet\Control\Session Manager"
INTERNET_SETTINGS = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
POLICIES_RUN = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
HOSTS_FILE = os.path.join(SYSTEM32, "drivers", "etc", "hosts")

ACCESSIBILITY_PROGRAMS = {"sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe",
                          "atbroker.exe"}
LOOPBACK = {"127.0.0.1", "0.0.0.0", "::1", "::"}
SECURITY_SITES = re.compile(r"(avast|avg\.|kaspersky|bitdefender|eset\.|norton|mcafee|malwarebytes|sophos|clamav|"
                            r"virustotal|defender|windowsupdate|update\.microsoft|symantec|trendmicro|f-secure)", re.I)
SENSITIVE_SITES = re.compile(r"(microsoft|windows|google|paypal|bank|login|accounts\.|apple|amazon|facebook|"
                             r"steam|github)", re.I)
# patterns of command lines used to download, decode or hide code
SUSPICIOUS_COMMANDS = [
    (r"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", "encoded PowerShell command", SUSPICIOUS),
    (r"frombase64string|invoke-expression|\biex\b|downloadstring|downloadfile|invoke-webrequest|\biwr\b|"
     r"net\.webclient", "PowerShell downloads or runs text as code", SUSPICIOUS),
    (r"(mshta|wscript|cscript|regsvr32|rundll32|bitsadmin|certutil)\b.*https?://", "script host or LOLBin fetching a URL", SUSPICIOUS),
    (r"certutil.*-urlcache|bitsadmin.*/transfer", "download through a Windows tool", SUSPICIOUS),
    (r"regsvr32.*scrobj\.dll|mshta\s+(vbscript|javascript)", "script run through a Windows tool", SUSPICIOUS),
    (r"-w(indowstyle)?\s+hidden|-nop\b.*-w\b|-noprofile.*hidden", "hidden window", LOOK),
]
# where a program that keeps itself alive has no business being
RISKY_FOLDERS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\", "\\downloads\\", "\\$recycle.bin\\")
KNOWN_SYSTEM_PROGRAMS = {
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", "services.exe", "winlogon.exe",
    "explorer.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "spoolsv.exe", "searchindexer.exe",
    "runtimebroker.exe", "sihost.exe", "fontdrvhost.exe", "ctfmon.exe", "audiodg.exe", "dwm.exe", "taskmgr.exe"}
NO_PATH_OK = {"system", "registry", "memcompression", "secure system", "smss.exe", "csrss.exe", "wininit.exe",
              "services.exe", "lsass.exe", "system idle process", "[system process]", "vmmem", "vmmemwsl"}


@dataclass
class Finding:
    category: str
    title: str
    detail: str = ""
    severity: int = INFO
    path: str = ""                     # program file to scan, when there is one
    location: str = ""                 # where it is registered
    flags: List[str] = field(default_factory=list)
    # how it can be removed (hunt_cleanup.py): ("task", name, task path), ("service", name) or
    # ("regvalue", hive, key, value name); None when this program does not offer to remove it
    removal: Optional[tuple] = None

    @property
    def dead(self) -> bool:
        """The program it starts no longer exists: removing it is the safest kind of cleanup."""
        return any(f in ("Program not found", "Automatic service whose program is missing") for f in self.flags)


@dataclass
class ProcessFinding:
    pid: int
    name: str
    path: str
    signer: str = ""
    connections: int = 0               # established connections to the Internet
    flags: List[str] = field(default_factory=list)
    severity: int = INFO


# region Shared checks

def risky_location(path: str) -> str:
    """The reason a program should not live here ('' when the place is ordinary)."""
    low = os.path.normcase(os.path.abspath(path)) if path else ""
    temp = os.path.normcase(os.path.abspath(tempfile.gettempdir())) + "\\"
    if low.startswith(temp) or any(marker in low + "\\" for marker in RISKY_FOLDERS):
        return "Runs from a temporary, download or public folder"
    return ""


def suspicious_command(command: str) -> List[tuple]:
    """(reason, severity) for each pattern a command line matches."""
    found = []
    for pattern, reason, severity in SUSPICIOUS_COMMANDS:
        if re.search(pattern, command or "", re.I):
            found.append((reason, severity))
    return found


def judge_in_windows(path: str) -> bool:
    return os.path.normcase(path).startswith(os.path.normcase(SYSTEM_ROOT) + os.sep)


def hijackable_prefixes(command: str) -> List[str]:
    """Files a standard user could plant to be started instead of an unquoted program path with spaces
    (Windows tries 'C:\\Program.exe' before 'C:\\Program Files\\x\\svc.exe')."""
    command = os.path.expandvars((command or "").strip())
    if not command or command.startswith('"'):
        return []
    match = re.match(r"([A-Za-z]:\\.*?\.(?:exe|bat|cmd|com))(?=\s|$)", command, re.I)
    if not match or " " not in match.group(1):
        return []
    full = match.group(1)
    planted = [full[:i] + ".exe" for i, c in enumerate(full) if c == " "]
    # a standard user cannot create files in a drive root by default, so only deeper folders count
    return [p for p in planted if os.path.dirname(os.path.dirname(p)) != os.path.dirname(p)]


class FileJudge:
    """Signature, packing and folder rights of program files, each file looked at once."""

    def __init__(self, signer_of: Callable = pe_signature.inspect_file, inspect_of: Callable = file_inspect.inspect,
                 writers_of: Callable = folder_security.unprivileged_writers):
        self._signer_of, self._inspect_of, self._writers_of = signer_of, inspect_of, writers_of
        self._signers: Dict[str, str] = {}
        self._packed: Dict[str, bool] = {}
        self._writable: Dict[str, bool] = {}

    @staticmethod
    def in_windows(path: str) -> bool:
        return judge_in_windows(path)

    def signer(self, path: str) -> str:
        """Signer name, '' when unsigned or unreadable (Windows files are signed by catalog: not judged)."""
        key = os.path.normcase(path)
        if key not in self._signers:
            try:
                too_big = os.path.getsize(path) > MAX_SIGNED_SIZE
            except OSError:
                too_big = True
            self._signers[key] = "" if too_big else self._signer_of(path, MAX_SIGNED_SIZE).signer
        return self._signers[key]

    def unsigned(self, path: str) -> bool:
        if self.in_windows(path) or os.path.splitext(path)[1].lower() not in startup.PE_SUFFIXES:
            return False
        try:
            if os.path.getsize(path) > MAX_SIGNED_SIZE:
                return False
        except OSError:
            return False
        return not self.signer(path)

    def packed(self, path: str) -> bool:
        key = os.path.normcase(path)
        if key not in self._packed:
            self._packed[key] = bool(self._inspect_of(path).packed)
        return self._packed[key]

    def writable_folder(self, path: str) -> bool:
        folder = os.path.dirname(path)
        key = os.path.normcase(folder)
        if key not in self._writable:
            try:
                self._writable[key] = bool(self._writers_of(folder))
            except OSError:
                self._writable[key] = False
        return self._writable[key]


def program_flags(path: str, judge: FileJudge, elevated: bool) -> tuple:
    """(flags, severity) for a program that runs by itself (service, task). elevated: it runs with high rights."""
    flags, severity = [], INFO
    reason = risky_location(path)
    if reason:
        flags.append(reason)
        severity = SUSPICIOUS
    if judge.unsigned(path):
        flags.append("Not signed")
        severity = max(severity, LOOK)
        if judge.packed(path):
            flags.append("High entropy (possibly packed)")
            severity = SUSPICIOUS
    if elevated and not judge.in_windows(path) and judge.writable_folder(path):
        flags.append("Its folder can be changed by standard users")
        severity = SUSPICIOUS
    return flags, severity

# endregion


# region Services

def read_services(reg=winreg) -> List[dict]:
    """Win32 services (own / shared process) with their program."""
    services = []
    root = dead_registry._open_or_none(reg, "HKLM", SERVICES_KEY)
    if root is None:
        return services
    with root:
        names = dead_registry._subkeys(reg, root)
    for name in names:
        key = dead_registry._open_or_none(reg, "HKLM", f"{SERVICES_KEY}\\{name}")
        if key is None:
            continue
        with key:
            values = {n: v for n, v, _t in dead_registry._values(reg, key)}
        kind, image = values.get("Type"), values.get("ImagePath")
        if not isinstance(kind, int) or not kind & 0x30 or not isinstance(image, str):
            continue
        dll = ""
        parameters = dead_registry._open_or_none(reg, "HKLM", f"{SERVICES_KEY}\\{name}\\Parameters")
        if parameters is not None:
            with parameters:
                dll = next((v for n, v, _t in dead_registry._values(reg, parameters) if n == "ServiceDll"
                            and isinstance(v, str)), "")
        services.append({"name": name, "display": str(values.get("DisplayName", "")), "image": image,
                         "start": values.get("Start"), "account": str(values.get("ObjectName", "")), "dll": dll})
    return services


def check_services(services: List[dict], judge: FileJudge, stop: Callable[[], bool] = lambda: False) -> List[Finding]:
    findings = []
    for svc in services:
        if stop():
            break
        if svc["start"] not in (0, 1, 2, 3):
            continue  # disabled
        image = os.path.expandvars(svc["image"]).strip()
        target = startup.command_path(image)
        if svc["dll"]:
            dll = os.path.expandvars(svc["dll"]).strip().strip('"')
            target = dll if os.path.isfile(dll) else target
        flags, severity = [], INFO
        if not target:
            if svc["start"] == 2 and dead_registry.check_target(image)[1] == dead_registry.MISSING:
                flags.append("Automatic service whose program is missing")
                severity = LOOK
        else:
            if judge.in_windows(target):
                continue  # catalog-signed Windows program
            flags, severity = program_flags(target, judge, elevated="system" in svc["account"].lower()
                                            or svc["account"] == "")
        if not (target and judge.in_windows(target)) and any(
                judge.writable_folder(p) for p in hijackable_prefixes(image)):
            flags.append("Unquoted path with spaces and a writable folder on the way (can be hijacked)")
            severity = max(severity, SUSPICIOUS)
        for reason, level in suspicious_command(image):
            flags.append(reason)
            severity = max(severity, level)
        if flags:
            findings.append(Finding("Service", svc["display"] or svc["name"], image, severity, target,
                                    f"HKLM\\{SERVICES_KEY}\\{svc['name']}", flags, ("service", svc["name"])))
    return findings

# endregion


# region Scheduled tasks and WMI

TASKS_PS = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$t = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
    $a = @($_.Actions)[0]
    [pscustomobject]@{ Name = $_.TaskName; Path = $_.TaskPath; Exec = [string]$a.Execute; Args = [string]$a.Arguments;
                       User = [string]$_.Principal.UserId; Level = $_.Principal.RunLevel.ToString() }
}
ConvertTo-Json -InputObject @($t) -Compress
"""

WMI_PS = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$c = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{ Kind = $_.CimClass.CimClassName; Name = [string]$_.Name; Cmd = [string]$_.CommandLineTemplate;
                       Exe = [string]$_.ExecutablePath; Script = [string]$_.ScriptText }
}
ConvertTo-Json -InputObject @($c) -Compress
"""


def _as_list(data) -> List[dict]:
    if isinstance(data, dict):
        data = [data]
    return [d for d in data or [] if isinstance(d, dict) and d]


def check_tasks(judge: FileJudge, run: Callable = startup._run_powershell,
                stop: Callable[[], bool] = lambda: False) -> List[Finding]:
    try:
        tasks = _as_list(run(TASKS_PS))
    except Exception as e:  # PowerShell missing, bad JSON, timeout: the other checks still run
        logging.warning(f"Scheduled tasks not readable: {e}")
        return []
    findings = []
    for t in tasks:
        if stop():
            break
        if not t.get("Exec"):
            continue
        exe = os.path.expandvars(str(t["Exec"])).strip().strip('"')
        command = f'"{exe}" {t.get("Args", "")}'.strip()
        target = exe if os.path.isfile(exe) else startup.command_path(command)
        elevated = str(t.get("Level")) == "Highest" or "system" in str(t.get("User", "")).lower()
        flags, severity = ([], INFO)
        if target and not judge.in_windows(target):
            flags, severity = program_flags(target, judge, elevated)
        elif not target and dead_registry.check_target(command)[1] == dead_registry.MISSING:
            flags, severity = ["Program not found"], LOOK
        for reason, level in suspicious_command(command):
            flags.append(reason)
            severity = max(severity, level)
        if flags:
            who = str(t.get("User") or "task") + (" (highest privileges)" if str(t.get("Level")) == "Highest" else "")
            findings.append(Finding("Scheduled task", str(t.get("Name", "")), command, severity, target or "",
                                    f"Task Scheduler {t.get('Path', '')} as {who}", flags,
                                    ("task", str(t.get("Name", "")), str(t.get("Path", "\\")))))
    return findings


def check_wmi(run: Callable = startup._run_powershell) -> List[Finding]:
    """Permanent WMI event subscriptions: a favourite hiding place, almost no honest program uses them."""
    try:
        consumers = _as_list(run(WMI_PS))
    except Exception as e:
        logging.warning(f"WMI subscriptions not readable: {e}")
        return []
    findings = []
    for c in consumers:
        kind, name = str(c.get("Kind", "")), str(c.get("Name", ""))
        if kind == "NTEventLogEventConsumer" or name == "SCM Event Log Consumer":
            continue  # installed by Windows
        action = c.get("Cmd") or c.get("Exe") or str(c.get("Script", ""))[:200]
        severity = SUSPICIOUS if kind in ("CommandLineEventConsumer", "ActiveScriptEventConsumer") else LOOK
        findings.append(Finding("WMI subscription", name or kind, str(action), severity, "",
                                f"root\\subscription ({kind})", ["Permanent WMI event consumer"]))
    return findings

# endregion


# region Hijacked Windows settings

def _values_of(reg, hive: str, path: str) -> Optional[Dict[str, object]]:
    key = dead_registry._open_or_none(reg, hive, path)
    if key is None:
        return None
    with key:
        return {n: v for n, v, _t in dead_registry._values(reg, key)}


def check_hijacks(reg=winreg) -> List[Finding]:
    findings: List[Finding] = []

    def add(title, detail, severity, location, *flags, path="", removal=None):
        findings.append(Finding("Windows setting", title, detail, severity, path, location, list(flags), removal))

    winlogon = _values_of(reg, "HKLM", WINLOGON) or {}
    shell = str(winlogon.get("Shell", "explorer.exe")).strip()
    if shell.lower() != "explorer.exe":
        add("Winlogon Shell", shell, SUSPICIOUS, f"HKLM\\{WINLOGON}", "Not the usual explorer.exe")
    userinit = str(winlogon.get("Userinit", "")).strip().rstrip(",").strip().lower()
    if userinit and userinit != os.path.join(SYSTEM32, "userinit.exe").lower():
        add("Winlogon Userinit", str(winlogon.get("Userinit")), SUSPICIOUS, f"HKLM\\{WINLOGON}",
            "Starts something besides userinit.exe")
    user_shell = (_values_of(reg, "HKCU", WINLOGON) or {}).get("Shell")
    if user_shell:
        add("Winlogon Shell (current user)", str(user_shell), SUSPICIOUS, f"HKCU\\{WINLOGON}",
            "A per-user shell replaces explorer.exe")

    ifeo = dead_registry._open_or_none(reg, "HKLM", IFEO)
    if ifeo is not None:
        with ifeo:
            programs = dead_registry._subkeys(reg, ifeo)
        for program in programs:
            debugger = (_values_of(reg, "HKLM", f"{IFEO}\\{program}") or {}).get("Debugger")
            if isinstance(debugger, str) and debugger.strip() and "vsjitdebugger" not in debugger.lower():
                target = startup.command_path(debugger)
                blocked = bool(target) and judge_in_windows(target) and program.lower() not in ACCESSIBILITY_PROGRAMS
                add(f"Debugger set for {program}", debugger, LOOK if blocked else SUSPICIOUS, f"HKLM\\{IFEO}\\{program}",
                    "The program is blocked from starting (a privacy tweak does this)" if blocked else
                    "Another program starts instead (accessibility tools are a classic target)",
                    removal=("regvalue", "HKLM", f"{IFEO}\\{program}", "Debugger"))

    windows = _values_of(reg, "HKLM", WINDOWS_NT_WINDOWS) or {}
    appinit = str(windows.get("AppInit_DLLs", "")).strip()
    if appinit:
        loaded = windows.get("LoadAppInit_DLLs") == 1
        add("AppInit_DLLs", appinit, SUSPICIOUS if loaded else LOOK, f"HKLM\\{WINDOWS_NT_WINDOWS}",
            "Loaded into every program" if loaded else "Set but not enabled")

    for name, value in (_values_of(reg, "HKLM", SESSION_MANAGER + "\\AppCertDlls") or {}).items():
        add("AppCertDlls", f"{name} = {value}", SUSPICIOUS, f"HKLM\\{SESSION_MANAGER}\\AppCertDlls",
            "A DLL is loaded into every process that starts programs")
    boot = (_values_of(reg, "HKLM", SESSION_MANAGER) or {}).get("BootExecute")
    boot_text = " ".join(boot) if isinstance(boot, list) else str(boot or "")
    if boot_text.strip() and boot_text.strip().lower() != "autocheck autochk *":
        add("BootExecute", boot_text, SUSPICIOUS, f"HKLM\\{SESSION_MANAGER}", "Runs before Windows starts")

    for hive in ("HKLM", "HKCU"):
        autorun = (_values_of(reg, hive, r"SOFTWARE\Microsoft\Command Processor") or {}).get("AutoRun")
        if isinstance(autorun, str) and autorun.strip():
            add("Command Prompt AutoRun", autorun, LOOK, f"{hive}\\SOFTWARE\\Microsoft\\Command Processor",
                "Runs every time a Command Prompt opens")
        for name, value in (_values_of(reg, hive, POLICIES_RUN) or {}).items():
            if isinstance(value, str) and value.strip():
                target = startup.command_path(value)
                add(f"Policy startup: {name}", value, LOOK, f"{hive}\\{POLICIES_RUN}",
                    "Starts at logon from a policy key", path=target, removal=("regvalue", hive, POLICIES_RUN, name))
    saver = (_values_of(reg, "HKCU", r"Control Panel\Desktop") or {}).get("SCRNSAVE.EXE")
    if isinstance(saver, str) and saver.strip() and not startup.command_path(saver).lower().startswith(SYSTEM_ROOT.lower()):
        add("Screen saver", saver, LOOK, "HKCU\\Control Panel\\Desktop", "A screen saver outside Windows is a program",
            path=startup.command_path(saver))

    command = (_values_of(reg, "HKLM", r"SOFTWARE\Classes\exefile\shell\open\command") or {}).get("")
    if isinstance(command, str) and command.strip() != '"%1" %*':
        add("How .exe files open", command, SUSPICIOUS, "HKLM\\SOFTWARE\\Classes\\exefile\\shell\\open\\command",
            "Every program is started through something else")
    return findings

# endregion


# region Hosts, proxy, browser extensions

def check_hosts(path: str = HOSTS_FILE) -> List[Finding]:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    findings = []
    for number, line in enumerate(lines, 1):
        parts = line.split("#", 1)[0].split()
        if len(parts) < 2:
            continue
        address, names = parts[0], parts[1:]
        for name in names:
            if address in LOOPBACK:
                if SECURITY_SITES.search(name):
                    findings.append(Finding("Hosts file", name, f"{address} {name}", SUSPICIOUS, "",
                                            f"{path}, line {number}", ["Blocks a security or update site"]))
            elif address.startswith("::"):
                continue
            else:
                severity = SUSPICIOUS if SENSITIVE_SITES.search(name) or SECURITY_SITES.search(name) else LOOK
                findings.append(Finding("Hosts file", name, f"{address} {name}", severity, "",
                                        f"{path}, line {number}", [f"Sends {name} to {address}"]))
    return findings


def check_proxy(reg=winreg) -> List[Finding]:
    values = _values_of(reg, "HKCU", INTERNET_SETTINGS) or {}
    findings = []
    if values.get("ProxyEnable") == 1 and str(values.get("ProxyServer", "")).strip():
        findings.append(Finding("Proxy", "Browser proxy is on", str(values["ProxyServer"]), LOOK, "",
                                f"HKCU\\{INTERNET_SETTINGS}", ["All web traffic goes through this server"]))
    if str(values.get("AutoConfigURL", "")).strip():
        findings.append(Finding("Proxy", "Proxy auto-configuration script", str(values["AutoConfigURL"]), LOOK, "",
                                f"HKCU\\{INTERNET_SETTINGS}", ["A script decides where web traffic goes"]))
    return findings


BROWSERS = {"Chrome": r"Google\Chrome\User Data", "Edge": r"Microsoft\Edge\User Data",
            "Brave": r"BraveSoftware\Brave-Browser\User Data"}
BROAD_HOSTS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
SENSITIVE_PERMISSIONS = {"cookies", "webRequest", "webRequestBlocking", "history", "nativeMessaging", "debugger",
                         "clipboardRead", "management", "proxy", "declarativeNetRequest"}


def _extension_name(folder: str, manifest: dict) -> str:
    name = str(manifest.get("name", ""))
    match = re.fullmatch(r"__MSG_(.+)__", name)
    if not match:
        return name
    default = str(manifest.get("default_locale", "en"))
    for locale in (default, "en", "en_US"):
        try:
            with open(os.path.join(folder, "_locales", locale, "messages.json"), encoding="utf-8-sig") as f:
                messages = {k.lower(): v for k, v in json.load(f).items()}
            return str(messages[match.group(1).lower()]["message"])
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return name


def check_extensions(local_app_data: Optional[str] = None) -> List[Finding]:
    """Chromium extensions with their reach. Only those that can read every site AND touch cookies, requests,
    history or the clipboard are marked; the others are listed for information."""
    base = local_app_data or startup._known_folder(0x1C) or ""  # CSIDL_LOCAL_APPDATA
    findings = []
    for browser, relative in BROWSERS.items():
        data = os.path.join(base, relative)
        if not os.path.isdir(data):
            continue
        for profile in sorted(os.listdir(data)):
            extensions = os.path.join(data, profile, "Extensions")
            if not os.path.isdir(extensions) or not (profile == "Default" or profile.startswith("Profile ")):
                continue
            for ext_id in sorted(os.listdir(extensions)):
                versions = sorted(os.listdir(os.path.join(extensions, ext_id)), reverse=True) \
                    if os.path.isdir(os.path.join(extensions, ext_id)) else []
                if not versions:
                    continue
                folder = os.path.join(extensions, ext_id, versions[0])
                try:
                    with open(os.path.join(folder, "manifest.json"), encoding="utf-8-sig") as f:
                        manifest = json.load(f)
                except (OSError, ValueError):
                    continue
                if not isinstance(manifest, dict):
                    continue
                permissions = {p for p in manifest.get("permissions", []) if isinstance(p, str)}
                hosts = permissions | {p for p in manifest.get("host_permissions", []) if isinstance(p, str)}
                for script in manifest.get("content_scripts", []) if isinstance(manifest.get("content_scripts"), list) else []:
                    if isinstance(script, dict):
                        hosts |= {m for m in script.get("matches", []) if isinstance(m, str)}
                broad = bool(hosts & BROAD_HOSTS)
                risky = sorted(permissions & SENSITIVE_PERMISSIONS)
                flags = []
                severity = INFO
                if broad and risky:
                    flags.append(f"Reads every site and can use: {', '.join(risky)}")
                    severity = LOOK
                findings.append(Finding("Browser extension", _extension_name(folder, manifest) or ext_id,
                                        f"{browser} ({profile}), version {manifest.get('version', '?')}, id {ext_id}",
                                        severity, "", folder, flags))
    return findings

# endregion


# region Collecting

def collect_persistence(reg=winreg, stop: Callable[[], bool] = lambda: False,
                        progress: Optional[Callable[[str], None]] = None, judge: Optional[FileJudge] = None,
                        run: Callable = startup._run_powershell, local_app_data: Optional[str] = None) -> List[Finding]:
    judge = judge or FileJudge()
    steps = [("services", lambda: check_services(read_services(reg), judge, stop)),
             ("scheduled tasks", lambda: check_tasks(judge, run, stop)),
             ("Windows settings", lambda: check_hijacks(reg)),
             ("WMI subscriptions", lambda: check_wmi(run)),
             ("hosts file", check_hosts), ("proxy", lambda: check_proxy(reg)),
             ("browser extensions", lambda: check_extensions(local_app_data))]
    findings: List[Finding] = []
    for label, step in steps:
        if stop():
            break
        if progress:
            progress(f"Checking {label}...")
        try:
            findings += step()
        except OSError as e:
            logging.warning(f"Malware hunt: {label} not checked: {e}")
    findings.sort(key=lambda f: (-f.severity, f.category, f.title.lower()))
    logging.info(f"Malware hunt: {len(findings)} findings, {sum(1 for f in findings if f.severity == SUSPICIOUS)} suspicious")
    return findings

# endregion


# region Running processes

def _lookalike(name: str) -> str:
    """The system program this name imitates ('' when it is not a near copy)."""
    low = name.lower()
    if low in KNOWN_SYSTEM_PROGRAMS or len(low) < 8:
        return ""
    for known in KNOWN_SYSTEM_PROGRAMS:
        if len(known) >= 8 and difflib.SequenceMatcher(None, low, known).ratio() >= 0.85:
            return known
    return ""


def expected_system_folders() -> Set[str]:
    return {os.path.normcase(SYSTEM32), os.path.normcase(os.path.join(SYSTEM_ROOT, "SysWOW64")),
            os.path.normcase(SYSTEM_ROOT)}


def judge_process(pid: int, name: str, path: str, internet: int, judge: FileJudge) -> ProcessFinding:
    finding = ProcessFinding(pid, name, path, connections=internet)
    flags = finding.flags
    severity = INFO
    low = name.lower()
    if not path:
        if low not in NO_PATH_OK and pid > 4:
            flags.append("Program path hidden (protected or access denied)")
        finding.severity = INFO
        return finding
    folder = os.path.normcase(os.path.dirname(path))
    if low in KNOWN_SYSTEM_PROGRAMS and folder not in expected_system_folders():
        flags.append("Named like a Windows program but not in the Windows folder")
        severity = SUSPICIOUS
    imitated = _lookalike(name)
    if imitated:
        flags.append(f"Name looks like {imitated}")
        severity = SUSPICIOUS
    if not os.path.isfile(path):
        flags.append("Program file no longer exists on disk")
        severity = SUSPICIOUS
    else:
        reason = risky_location(path)
        if reason:
            flags.append(reason)
            severity = SUSPICIOUS
        finding.signer = "" if judge.in_windows(path) else judge.signer(path)
        if judge.unsigned(path):
            flags.append("Not signed")
            severity = max(severity, LOOK)
            if judge.packed(path):
                flags.append("High entropy (possibly packed)")
                severity = max(severity, LOOK)
            if internet:
                flags.append(f"Unsigned and connected to the Internet ({internet})")
                severity = SUSPICIOUS
    finding.severity = severity
    return finding


def scan_processes(stop: Callable[[], bool] = lambda: False, progress: Optional[Callable[[str], None]] = None,
                   judge: Optional[FileJudge] = None, names: Optional[Callable] = None, path_of: Optional[Callable] = None,
                   connections: Optional[Callable] = None) -> List[ProcessFinding]:
    judge = judge or FileJudge()
    names = names or traffic.process_names
    path_of = path_of or traffic.process_path
    connections = connections or traffic.list_connections
    try:
        internet: Dict[int, int] = {}
        for c in connections():
            if c.protocol == "TCP" and c.state == "Established" and traffic.remote_kind(c.remote_addr) == "Internet":
                internet[c.pid] = internet.get(c.pid, 0) + 1
    except OSError:
        internet = {}
    findings = []
    processes = names()
    for index, (pid, name) in enumerate(sorted(processes.items()), 1):
        if stop():
            break
        if pid in (0, 4):
            continue
        if progress and index % 20 == 0:
            progress(f"Checking processes... {index}/{len(processes)}")
        findings.append(judge_process(pid, name, path_of(pid), internet.get(pid, 0), judge))
    findings.sort(key=lambda f: (-f.severity, f.name.lower(), f.pid))
    return findings


def program_paths(persistence: Iterable[Finding], processes: Iterable[ProcessFinding]) -> List[str]:
    """Distinct existing program files named by the findings (to hand to the antivirus)."""
    paths = {p.path for p in processes if p.path} | {f.path for f in persistence if f.path}
    return sorted({p for p in paths if os.path.isfile(p)}, key=str.lower)

# endregion
