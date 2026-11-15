"""
Security Audit Module for DD Cleaner
Provides comprehensive security assessment and hardening for Windows systems.

Security notes:
- All subprocesses use absolute paths (SystemRoot\\System32\\...)
  to prevent "binary planting" next to the portable executable.
- No localized text output is parsed: PowerShell returns JSON
  (ConvertTo-Json), service/registry states are read via winreg.
- Hardening writes a JSON snapshot (hardening_backup_<timestamp>.json)
  BEFORE any change, which allows an exact rollback.
"""

import base64
import ctypes
import glob
import json
import logging
import os
import platform
import re
import subprocess
import sys
import threading
import winreg
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from ddcleaner.common import data_dir, safe_environment


# ============================================================================
# SYSTEM PATHS & SUBPROCESS HELPERS
# ============================================================================

DEFAULT_TIMEOUT = 60
RESTORE_POINT_TIMEOUT = 300
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_LOCAL_SID_RE = re.compile(r"^S-1-5-21(-\d+)+$")


def _get_windows_dir() -> str:
    """Return the Windows directory from the API. %SystemRoot% is not trusted: the environment of an
    elevated process can come from the user's HKCU\\Environment."""
    try:
        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buf, 260):
            return buf.value
    except Exception:
        pass
    return r"C:\Windows"


def _get_system_dir() -> str:
    """Return the native System32 directory (Sysnative when running as 32-bit under WOW64)."""
    windir = _get_windows_dir()
    if platform.architecture()[0] == "32bit":
        sysnative = os.path.join(windir, "Sysnative")
        if os.path.isdir(sysnative):
            return sysnative
    return os.path.join(windir, "System32")


SYSTEM32 = _get_system_dir()
POWERSHELL_EXE = os.path.join(SYSTEM32, "WindowsPowerShell", "v1.0", "powershell.exe")
SC_EXE = os.path.join(SYSTEM32, "sc.exe")


def _decode(data: Optional[bytes]) -> str:
    """Decode subprocess output robustly (UTF-8, BOM stripped, invalid bytes replaced)."""
    if not data:
        return ""
    return data.decode("utf-8", errors="replace").lstrip("\ufeff")


def _run_exe(args: List[str], timeout: int = DEFAULT_TIMEOUT) -> Tuple[int, str, str]:
    """
    Run an executable (absolute path) without a window.

    Returns:
        Tuple of (return_code, stdout, stderr). return_code is -1 on timeout / launch error.
    """
    logger = logging.getLogger("SecurityAudit.subprocess")
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            shell=False,
            timeout=timeout,
            cwd=SYSTEM32,
            env=safe_environment(),  # no user PSModulePath: modules only from System32
            creationflags=CREATE_NO_WINDOW
        )
    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout ({timeout}s) running {os.path.basename(args[0])}")
        return -1, "", "timeout"
    except OSError as e:
        logger.error(f"Could not run {args[0]}: {e}")
        return -1, "", str(e)
    return result.returncode, _decode(result.stdout), _decode(result.stderr)


def _run_ps(script: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[int, str, str]:
    """Run a PowerShell script (passed via -EncodedCommand, UTF-8 output)."""
    prefix = (
        "$ProgressPreference='SilentlyContinue';"
        "try{[Console]::OutputEncoding=[System.Text.Encoding]::UTF8}catch{};"
    )
    encoded = base64.b64encode((prefix + script).encode("utf-16-le")).decode("ascii")
    return _run_exe(
        [POWERSHELL_EXE, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-EncodedCommand", encoded],
        timeout=timeout
    )


def _parse_json(text: str) -> Any:
    """Parse JSON from PowerShell stdout, tolerating leading noise."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    for opener in ("{", "["):
        idx = text.find(opener)
        if idx >= 0:
            try:
                return json.loads(text[idx:])
            except ValueError:
                continue
    return None


def _run_ps_json(script: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[int, Any]:
    """Run a PowerShell script whose stdout is JSON. Returns (return_code, parsed_or_None)."""
    rc, out, _err = _run_ps(script, timeout=timeout)
    return rc, _parse_json(out)


def _ps_quote(value: str) -> str:
    """Quote a string as a PowerShell single-quoted literal."""
    return "'" + str(value).replace("'", "''") + "'"


# ============================================================================
# REGISTRY HELPERS (64-bit view, locale independent)
# ============================================================================

_HIVES = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCU": winreg.HKEY_CURRENT_USER,
}


def _reg_read(hive: int, path: str, name: str) -> Tuple[bool, Any, int]:
    """Read a registry value. Returns (exists, value, type). Missing key/value -> (False, None, 0)."""
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            value, vtype = winreg.QueryValueEx(key, name)
            return True, value, vtype
    except FileNotFoundError:
        return False, None, 0


def _reg_write(hive: int, path: str, name: str, vtype: int, data: Any):
    """Write a registry value (creates the key if needed)."""
    with winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
        winreg.SetValueEx(key, name, 0, vtype, data)


def _reg_delete(hive: int, path: str, name: str):
    """Delete a registry value (no error if already absent)."""
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            winreg.DeleteValue(key, name)
    except FileNotFoundError:
        pass


def _encode_reg_state(exists: bool, value: Any, vtype: int) -> Dict:
    """Encode a registry value state for JSON."""
    if not exists:
        return {"exists": False}
    if isinstance(value, bytes):
        value = {"hex": value.hex()}
    return {"exists": True, "type": vtype, "data": value}


def _decode_reg_data(data: Any) -> Any:
    """Decode registry data stored by _encode_reg_state."""
    if isinstance(data, dict) and "hex" in data:
        return bytes.fromhex(data["hex"])
    return data


def _read_service_start(service_name: str) -> Tuple[Optional[int], Optional[int]]:
    """Read service start type from registry (2=auto, 3=manual, 4=disabled). (None, None) if absent."""
    path = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"
    exists, start, _ = _reg_read(winreg.HKEY_LOCAL_MACHINE, path, "Start")
    if not exists:
        return None, None
    d_exists, delayed, _ = _reg_read(winreg.HKEY_LOCAL_MACHINE, path, "DelayedAutostart")
    return int(start), (int(delayed) if d_exists else None)


def _is_remote_session() -> bool:
    """True if the current session is a Remote Desktop session."""
    if os.environ.get("SESSIONNAME", "").upper().startswith("RDP-"):
        return True
    try:
        SM_REMOTESESSION = 0x1000
        return bool(ctypes.windll.user32.GetSystemMetrics(SM_REMOTESESSION))
    except Exception:
        return False


def get_backup_dir() -> str:
    """Hardening backups: <protected data folder>\\hardening_backups. Revert trusts these files, so they must
    live where only administrators can write (see ddcleaner.common.data_dir)."""
    directory = os.path.join(data_dir(), "hardening_backups")
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError:
        pass  # _save_backup reports the failure and apply_profile aborts
    return directory


LSA_KEY = r"SYSTEM\CurrentControlSet\Control\Lsa"
WDIGEST_KEY = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
HVCI_KEY = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
NETBIOS_ROOT = r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
NETBIOS_DISABLED = 2  # NetbiosOptions: 0 = from DHCP, 1 = enabled, 2 = disabled
_NETBIOS_IFACE_RE = re.compile(r"^Tcpip_\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$")

# Points per domain: the original checks (25 / 30) plus the credential, SMBv1 and NetBIOS checks
SYSTEM_MAX_SCORE = 25 + 3 + 2 + 4
NETWORK_MAX_SCORE = 30 + 6 + 2


def _netbios_interfaces() -> Dict[str, Optional[int]]:
    """NetbiosOptions of every network interface (None = value absent = default = enabled)."""
    result: Dict[str, Optional[int]] = {}
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NETBIOS_ROOT, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    except FileNotFoundError:
        return result
    with root:
        index = 0
        while True:
            try:
                name = winreg.EnumKey(root, index)
            except OSError:
                break
            index += 1
            if not _NETBIOS_IFACE_RE.match(name):
                continue
            exists, value, _ = _reg_read(winreg.HKEY_LOCAL_MACHINE, f"{NETBIOS_ROOT}\\{name}", "NetbiosOptions")
            result[name] = int(value) if exists else None
    return result


_START_TYPE_PS = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}
_START_TYPE_SC = {0: "boot", 1: "system", 2: "auto", 3: "demand", 4: "disabled"}

HKCU_NOTE = (" (Setting read from the profile of the user who launched the app as administrator;"
             " if elevation used a different account, this profile may differ from the logged-on session.)")


# Former (French) enum values -> member name. Older hardening backups stored
# profile.value in French; RiskLevel("Critique") / HardeningProfile("Recommandé")
# etc. still resolve through Enum._missing_.
_LEGACY_ENUM_VALUES = {
    "Faible": "LOW", "Moyen": "MEDIUM", "Élevé": "HIGH", "Critique": "CRITICAL",
    "Système": "SYSTEM", "Comptes": "ACCOUNTS", "Réseau": "NETWORK", "Données": "DATA",
    "Basique": "BASIC", "Recommandé": "RECOMMENDED",
}


def _legacy_lookup(enum_cls, value):
    """Resolve a legacy French enum value (or a member name) to a member of enum_cls, else None."""
    if not isinstance(value, str):
        return None
    name = _LEGACY_ENUM_VALUES.get(value.strip(), value.strip().upper())
    return enum_cls.__members__.get(name)


class RiskLevel(Enum):
    """Risk level for security issues."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @classmethod
    def _missing_(cls, value):
        return _legacy_lookup(cls, value)


_RISK_RANK = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}


class SecurityDomain(Enum):
    """Security audit domains."""
    SYSTEM = "System"
    ACCOUNTS = "Accounts"
    NETWORK = "Network"
    DATA = "Data"

    @classmethod
    def _missing_(cls, value):
        return _legacy_lookup(cls, value)


class HardeningProfile(Enum):
    """Hardening profile levels."""
    BASIC = "Basic"
    RECOMMENDED = "Recommended"
    STRICT = "Strict"

    @classmethod
    def _missing_(cls, value):
        return _legacy_lookup(cls, value)


@dataclass
class SecurityIssue:
    """Represents a security issue found during audit."""
    id: str
    title: str
    description: str
    domain: SecurityDomain
    risk: RiskLevel
    current_state: str
    recommended_action: str
    score_impact: int  # Points lost (out of domain total)
    fix_command: Optional[str] = None
    revert_command: Optional[str] = None
    requires_reboot: bool = False
    learn_more_url: str = ""


@dataclass
class DomainScore:
    """Score for a security domain."""
    domain: SecurityDomain
    current_score: int
    max_score: int
    issues: List[SecurityIssue]

    @property
    def percentage(self) -> float:
        """Get percentage score."""
        return (self.current_score / self.max_score * 100) if self.max_score > 0 else 0.0

    @property
    def status(self) -> str:
        """Get status based on percentage."""
        pct = self.percentage
        if pct >= 85:
            return "🟢 Excellent"
        elif pct >= 70:
            return "🟡 Fair"
        elif pct >= 50:
            return "🟠 Medium"
        else:
            return "🔴 Critical"


class SecurityAuditor:
    """
    Main security audit engine.

    The audit is strictly read-only (winreg reads + PowerShell Get-* cmdlets).
    Results are built in new objects and published atomically at the end, so a GUI
    thread holding results from a previous audit never sees them mutated.
    """

    # Domain weights (must sum to 100)
    DOMAIN_WEIGHTS = {
        SecurityDomain.SYSTEM: 25,
        SecurityDomain.ACCOUNTS: 25,
        SecurityDomain.NETWORK: 30,
        SecurityDomain.DATA: 20,
    }

    def __init__(self):
        self.logger = logging.getLogger("SecurityAuditor")
        self.issues: List[SecurityIssue] = []
        self.domain_scores: Dict[SecurityDomain, DomainScore] = {}
        self._audit_lock = threading.Lock()
        self._work_issues: List[SecurityIssue] = []
        self._work_scores: Dict[SecurityDomain, DomainScore] = {}

    def run_full_audit(self) -> Tuple[int, Dict[SecurityDomain, DomainScore]]:
        """
        Run complete security audit.

        Returns:
            Tuple of (global_score, domain_scores_dict) - the dict is a copy.
        """
        with self._audit_lock:
            self.logger.info("=== Starting Security Audit ===")
            # Fresh objects for this run (never clear() shared ones)
            self._work_issues = []
            self._work_scores = {}

            # Run domain audits
            self._audit_system()
            self._audit_accounts()
            self._audit_network()
            self._audit_data()

            # Calculate scores
            global_score = self._calculate_global_score(self._work_scores)

            # Publish atomically (reference swap)
            self.issues = self._work_issues
            self.domain_scores = self._work_scores

            self.logger.info(f"Audit completed. Global score: {global_score}/100")
            return global_score, dict(self.domain_scores)

    def _calculate_global_score(self, scores: Optional[Dict[SecurityDomain, DomainScore]] = None) -> int:
        """Calculate global security score based on domain scores."""
        if scores is None:
            scores = self.domain_scores
        total_score = 0.0

        for domain, weight in self.DOMAIN_WEIGHTS.items():
            if domain in scores:
                domain_score = scores[domain]
                if domain_score.max_score > 0:
                    contribution = (domain_score.current_score / domain_score.max_score) * weight
                    total_score += contribution

        return int(round(total_score))

    def get_critical_issues(self, limit: int = 5) -> List[SecurityIssue]:
        """Get top critical issues sorted by risk and score impact (returns a new list)."""
        issues = list(self.issues)
        critical = [i for i in issues if i.risk in (RiskLevel.CRITICAL, RiskLevel.HIGH)]
        critical.sort(key=lambda x: (_RISK_RANK[x.risk], x.score_impact), reverse=True)
        return list(critical[:limit])

    def _record_domain(self, domain: SecurityDomain, max_score: int, issues: List[SecurityIssue]):
        """Store domain results in the working (unpublished) state."""
        current_score = max_score - sum(i.score_impact for i in issues)
        self._work_issues.extend(issues)
        self._work_scores[domain] = DomainScore(
            domain=domain,
            current_score=max(0, current_score),
            max_score=max_score,
            issues=list(issues)
        )

    # ============================================================================
    # SYSTEM AUDIT (25 points)
    # ============================================================================

    def _audit_system(self):
        """Audit system security (25% of total score)."""
        self.logger.info("Auditing system security...")
        issues = []

        # Windows Defender (5 points)
        defender_issue = self._check_defender()
        if defender_issue:
            issues.append(defender_issue)

        # Firewall (5 points)
        firewall_issue = self._check_firewall()
        if firewall_issue:
            issues.append(firewall_issue)

        # Windows Update (5 points)
        update_issue = self._check_windows_update()
        if update_issue:
            issues.append(update_issue)

        # UAC (3 points)
        uac_issue = self._check_uac()
        if uac_issue:
            issues.append(uac_issue)

        # Risky services (7 points)
        issues.extend(self._check_risky_services())

        # Credential and kernel protections (3 + 2 + 4 points)
        for check in (self._check_memory_integrity, self._check_lsass_protection, self._check_wdigest):
            issue = check()
            if issue:
                issues.append(issue)

        self._record_domain(SecurityDomain.SYSTEM, SYSTEM_MAX_SCORE, issues)

    def _check_defender(self) -> Optional[SecurityIssue]:
        """Check Windows Defender status (accepts another active antivirus registered in Security Center)."""
        script = r"""
$r = [ordered]@{ Rtp = $null; DefenderSc = $null; OtherAv = @() }
try { $r.Rtp = [bool](Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled } catch { }
try {
    $av = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
    $def = @($av | Where-Object { $_.pathToSignedProductExe -like 'windowsdefender://*' })
    if ($def.Count) { $r.DefenderSc = (([int]$def[0].productState -band 0x1000) -ne 0) }
    $r.OtherAv = @($av |
        Where-Object { ($_.pathToSignedProductExe -notlike 'windowsdefender://*') -and (([int]$_.productState -band 0x1000) -ne 0) } |
        ForEach-Object { [string]$_.displayName })
} catch { }
$r | ConvertTo-Json -Compress
"""
        try:
            _rc, data = _run_ps_json(script)
            if not isinstance(data, dict):
                self.logger.warning("Could not check Defender (no data)")
                return None
            rtp = data.get("Rtp")
            if rtp is None:
                # Defender PowerShell module unavailable: fall back to Security Center state
                rtp = data.get("DefenderSc")
            other_av = data.get("OtherAv") or []
            if isinstance(other_av, str):
                other_av = [other_av]
            if other_av:
                self.logger.info(f"Third-party antivirus active: {', '.join(other_av)}")
                return None
            if rtp is True:
                return None
            if rtp is None:
                return SecurityIssue(
                    id="defender_unknown",
                    title="Antivirus protection cannot be verified",
                    description="Could not check Windows Defender status and no other active antivirus was detected.",
                    domain=SecurityDomain.SYSTEM,
                    risk=RiskLevel.MEDIUM,
                    current_state="❔ Unknown",
                    recommended_action="Check antivirus protection manually (Windows Security)",
                    score_impact=2,
                    learn_more_url="https://docs.microsoft.com/windows/security/threat-protection/microsoft-defender-antivirus"
                )
            return SecurityIssue(
                id="defender_disabled",
                title="Windows Defender disabled",
                description="Windows Defender real-time protection is off; your system is vulnerable to malware.",
                domain=SecurityDomain.SYSTEM,
                risk=RiskLevel.CRITICAL,
                current_state="❌ Inactive",
                recommended_action="Enable Windows Defender immediately",
                score_impact=5,
                fix_command="Set-MpPreference -DisableRealtimeMonitoring $false",
                revert_command="Set-MpPreference -DisableRealtimeMonitoring $true",
                learn_more_url="https://docs.microsoft.com/windows/security/threat-protection/microsoft-defender-antivirus"
            )
        except Exception as e:
            self.logger.error(f"Error checking Defender: {e}")

        return None

    def _check_firewall(self) -> Optional[SecurityIssue]:
        """Check Windows Firewall status (effective policy, ActiveStore)."""
        script = r"""
$off = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
    Where-Object { $_.Enabled.ToString() -eq 'False' } | ForEach-Object { [string]$_.Name })
ConvertTo-Json -InputObject $off -Compress
"""
        try:
            rc, data = _run_ps_json(script)
            if rc != 0 or data is None:
                self.logger.warning("Could not check firewall")
                return None
            disabled = data if isinstance(data, list) else [data]
            disabled_count = len(disabled)
            if disabled_count > 0:
                return SecurityIssue(
                    id="firewall_disabled",
                    title=f"Firewall disabled ({disabled_count} profile(s))",
                    description=f"{disabled_count} firewall profile(s) disabled ({', '.join(map(str, disabled))}). The system is exposed to unauthorized network connections.",
                    domain=SecurityDomain.SYSTEM,
                    risk=RiskLevel.CRITICAL,
                    current_state=f"❌ {disabled_count} profile(s) inactive",
                    recommended_action="Enable the firewall on all profiles (Domain/Private/Public)",
                    score_impact=5,
                    fix_command="Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
                    learn_more_url="https://docs.microsoft.com/windows/security/threat-protection/windows-firewall"
                )
        except Exception as e:
            self.logger.error(f"Error checking firewall: {e}")

        return None

    def _get_last_update_date(self) -> Optional[datetime]:
        """Return last successful Windows Update installation date (UTC) or None if unknown."""
        script = r"""
$r = [ordered]@{ Date = $null }
try {
    $au = New-Object -ComObject Microsoft.Update.AutoUpdate
    $d = $au.Results.LastInstallationSuccessDate
    if ($d) { $r.Date = ([DateTime]$d).ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }
} catch { }
$r | ConvertTo-Json -Compress
"""
        try:
            _rc, data = _run_ps_json(script)
            if isinstance(data, dict) and data.get("Date"):
                parsed = datetime.strptime(data["Date"], "%Y-%m-%dT%H:%M:%S")
                if parsed.year >= 2000:
                    return parsed
        except Exception as e:
            self.logger.debug(f"Windows Update COM query failed: {e}")

        # Legacy fallback (removed on recent Windows 10 builds)
        try:
            exists, value, _ = _reg_read(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install",
                "LastSuccessTime"
            )
            if exists and value:
                return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
        except Exception as e:
            self.logger.debug(f"Windows Update registry fallback failed: {e}")
        return None

    def _check_windows_update(self) -> Optional[SecurityIssue]:
        """Check Windows Update status (unknown state is penalized, not ignored)."""
        try:
            last_update = self._get_last_update_date()
            if last_update is None:
                return SecurityIssue(
                    id="update_unknown",
                    title="Windows Update: status cannot be verified",
                    description="The date of the last successful update installation could not be determined.",
                    domain=SecurityDomain.SYSTEM,
                    risk=RiskLevel.MEDIUM,
                    current_state="❔ Unknown",
                    recommended_action="Check Windows Update manually",
                    score_impact=2,
                    learn_more_url="https://support.microsoft.com/windows-update"
                )

            days_ago = max(0, (datetime.now(timezone.utc).replace(tzinfo=None) - last_update).days)
            if days_ago > 30:
                return SecurityIssue(
                    id="update_outdated",
                    title=f"Windows updates out of date ({days_ago} days)",
                    description=f"Last update {days_ago} days ago. Known security vulnerabilities are not patched.",
                    domain=SecurityDomain.SYSTEM,
                    risk=RiskLevel.HIGH,
                    current_state=f"⚠️ Last update: {last_update.strftime('%Y-%m-%d')}",
                    recommended_action="Install available Windows updates",
                    score_impact=5,
                    learn_more_url="https://support.microsoft.com/windows-update"
                )
        except Exception as e:
            self.logger.debug(f"Could not check Windows Update: {e}")

        return None

    def _check_uac(self) -> Optional[SecurityIssue]:
        """
        Check UAC level.

        ConsentPromptBehaviorAdmin: 0=elevate without prompting, 1=credentials (secure desktop),
        2=consent (secure desktop), 3=credentials, 4=consent,
        5=consent for non-Windows binaries (Windows 10 default).
        """
        path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        hklm_path = "HKLM:\\" + path
        try:
            lua_exists, enable_lua, _ = _reg_read(winreg.HKEY_LOCAL_MACHINE, path, "EnableLUA")
            cpba_exists, level, _ = _reg_read(winreg.HKEY_LOCAL_MACHINE, path, "ConsentPromptBehaviorAdmin")
            posd_exists, secure_desktop, _ = _reg_read(winreg.HKEY_LOCAL_MACHINE, path, "PromptOnSecureDesktop")
            level = int(level) if cpba_exists else 5

            if lua_exists and int(enable_lua) == 0:
                return SecurityIssue(
                    id="uac_disabled",
                    title="UAC disabled",
                    description="User Account Control is disabled (EnableLUA=0): all programs run with administrator rights.",
                    domain=SecurityDomain.SYSTEM,
                    risk=RiskLevel.HIGH,
                    current_state="❌ Disabled",
                    recommended_action="Re-enable UAC (EnableLUA=1, reboot required)",
                    score_impact=3,
                    fix_command=f"Set-ItemProperty '{hklm_path}' -Name EnableLUA -Value 1",
                    revert_command=f"Set-ItemProperty '{hklm_path}' -Name EnableLUA -Value 0",
                    requires_reboot=True,
                    learn_more_url="https://docs.microsoft.com/windows/security/identity-protection/user-account-control"
                )

            if level == 0:
                return SecurityIssue(
                    id="uac_low",
                    title="UAC too permissive",
                    description="Current UAC level: 0 (elevate without prompting). Programs can elevate without user confirmation.",
                    domain=SecurityDomain.SYSTEM,
                    risk=RiskLevel.MEDIUM,
                    current_state="⚠️ Silent elevation (0)",
                    recommended_action="Restore the default level (5) or higher (2 = always notify)",
                    score_impact=3,
                    fix_command=f"Set-ItemProperty '{hklm_path}' -Name ConsentPromptBehaviorAdmin -Value 5",
                    revert_command=f"Set-ItemProperty '{hklm_path}' -Name ConsentPromptBehaviorAdmin -Value 0",
                    learn_more_url="https://docs.microsoft.com/windows/security/identity-protection/user-account-control"
                )

            if level in (3, 4, 5) and posd_exists and int(secure_desktop) == 0:
                return SecurityIssue(
                    id="uac_no_secure_desktop",
                    title="UAC prompt not on secure desktop",
                    description="The UAC prompt is not shown on the secure desktop (PromptOnSecureDesktop=0): a program can spoof or tamper with the prompt.",
                    domain=SecurityDomain.SYSTEM,
                    risk=RiskLevel.LOW,
                    current_state="⚠️ Secure desktop disabled",
                    recommended_action="Show the UAC prompt on the secure desktop",
                    score_impact=1,
                    fix_command=f"Set-ItemProperty '{hklm_path}' -Name PromptOnSecureDesktop -Value 1",
                    revert_command=f"Set-ItemProperty '{hklm_path}' -Name PromptOnSecureDesktop -Value 0",
                    learn_more_url="https://docs.microsoft.com/windows/security/identity-protection/user-account-control"
                )
        except Exception as e:
            self.logger.error(f"Error checking UAC: {e}")

        return None

    def _check_memory_integrity(self) -> Optional[SecurityIssue]:
        """Memory integrity (HVCI): is it running? Audit only, see the note in the issue text."""
        script = r"""
$r = [ordered]@{ Running = $null }
try {
    $d = Get-CimInstance -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
    $r.Running = (@($d.SecurityServicesRunning) -contains 2)
} catch { }
$r | ConvertTo-Json -Compress
"""
        try:
            _rc, data = _run_ps_json(script)
            running = data.get("Running") if isinstance(data, dict) else None
            if running is None:  # DeviceGuard WMI class missing: fall back to the configured value
                exists, value, _ = _reg_read(winreg.HKEY_LOCAL_MACHINE, HVCI_KEY, "Enabled")
                running = bool(exists and int(value) == 1)
            if running:
                return None
            return SecurityIssue(
                id="memory_integrity_off",
                title="Memory integrity (HVCI) is off",
                description=("Kernel code integrity is not enforced by the hypervisor, so a vulnerable or malicious "
                             "driver can run in the kernel. Windows checks driver compatibility when you turn it on "
                             "from Windows Security; setting the registry value by hand skips that check and can "
                             "stop devices (or boot) if a driver is incompatible, so it is not offered as an action."),
                domain=SecurityDomain.SYSTEM,
                risk=RiskLevel.MEDIUM,
                current_state="⚠️ Off",
                recommended_action="Windows Security > Device security > Core isolation > Memory integrity "
                                   "(the Driver Checker tab lists drivers on the Microsoft blocklist)",
                score_impact=3,
                requires_reboot=True,
                learn_more_url="https://learn.microsoft.com/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity"
            )
        except Exception as e:
            self.logger.debug(f"Could not check memory integrity: {e}")
        return None

    def _check_lsass_protection(self) -> Optional[SecurityIssue]:
        """LSA protection (LSASS as a protected process). Audit only: not cleanly undoable.

        RunAsPPL is the explicit registry switch; RunAsPPLBoot is a newer one Windows 11 can set on its own on
        a clean install, with neither value readable from this process as "the live state" (the running process's
        actual protection level isn't exposed by a plain registry read). Absent both, the state is uncertain
        rather than confidently off, so it is reported as such instead of a flat "disabled"."""
        try:
            exists, value, _ = _reg_read(winreg.HKEY_LOCAL_MACHINE, LSA_KEY, "RunAsPPL")
            if exists and int(value) in (1, 2):
                return None
            boot_exists, boot_value, _ = _reg_read(winreg.HKEY_LOCAL_MACHINE, LSA_KEY, "RunAsPPLBoot")
            if boot_exists and int(boot_value) in (1, 2):
                return None
            if exists and int(value) == 0:  # explicitly turned off: a confident finding
                return SecurityIssue(
                    id="lsass_unprotected",
                    title="LSA protection is off",
                    description=("LSASS holds logon credentials in memory and is not a protected process, so tools "
                                 "running as administrator can read it. It is not offered as an action: on UEFI PCs "
                                 "the setting is also stored in firmware, so removing the registry value does not "
                                 "undo it."),
                    domain=SecurityDomain.SYSTEM,
                    risk=RiskLevel.MEDIUM,
                    current_state="❌ Off",
                    recommended_action="Windows Security > Device security > Core isolation > Local Security Authority "
                                       "protection (or RunAsPPL=1, reboot). Check that your security software supports it first.",
                    score_impact=2,
                    requires_reboot=True,
                    learn_more_url="https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"
                )
            return SecurityIssue(  # neither value set: cannot tell a clean Windows 11 default from an older Windows
                id="lsass_unknown",
                title="LSA protection cannot be confirmed",
                description="Neither RunAsPPL nor RunAsPPLBoot is set. Recent Windows 11 installs can protect LSASS "
                            "without this registry value, so this may already be on; it cannot be confirmed from the "
                            "registry alone.",
                domain=SecurityDomain.SYSTEM,
                risk=RiskLevel.LOW,
                current_state="❔ Unknown",
                recommended_action="Check Windows Security > Device security > Core isolation > Local Security "
                                   "Authority protection",
                score_impact=1,
                learn_more_url="https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"
            )
        except Exception as e:
            self.logger.debug(f"Could not check LSA protection: {e}")
        return None

    def _check_wdigest(self) -> Optional[SecurityIssue]:
        """WDigest keeping clear-text passwords in memory. Windows 8.1+ default: off (value absent)."""
        try:
            exists, value, _ = _reg_read(winreg.HKEY_LOCAL_MACHINE, WDIGEST_KEY, "UseLogonCredential")
            if exists and int(value) == 1:
                return SecurityIssue(
                    id="wdigest_enabled",
                    title="WDigest stores clear-text passwords",
                    description="UseLogonCredential=1: your password is kept in clear text in memory and can be stolen by credential dumping tools.",
                    domain=SecurityDomain.SYSTEM,
                    risk=RiskLevel.CRITICAL,
                    current_state="❌ Enabled",
                    recommended_action="Set UseLogonCredential=0 (Recommended hardening profile)",
                    score_impact=4,
                    fix_command=f"Set-ItemProperty 'HKLM:\\{WDIGEST_KEY}' -Name UseLogonCredential -Value 0",
                    revert_command=f"Set-ItemProperty 'HKLM:\\{WDIGEST_KEY}' -Name UseLogonCredential -Value 1",
                    learn_more_url="https://learn.microsoft.com/security-updates/securityadvisories/2016/2871997"
                )
        except Exception as e:
            self.logger.debug(f"Could not check WDigest: {e}")
        return None

    def _check_risky_services(self) -> List[SecurityIssue]:
        """Check for risky Windows services (status via PowerShell JSON, start type via registry)."""
        issues = []
        risky_services = {
            "RemoteRegistry": ("Remote Registry", 2, RiskLevel.MEDIUM),
            "TermService": ("Remote Desktop", 2, RiskLevel.HIGH),
            "TlntSvr": ("Telnet", 2, RiskLevel.CRITICAL),
            "SNMP": ("SNMP", 1, RiskLevel.MEDIUM),
        }

        names = ",".join(_ps_quote(n) for n in risky_services)
        script = (
            "$out = @(); foreach ($n in @(" + names + ")) {"
            " $s = Get-Service -Name $n -ErrorAction SilentlyContinue;"
            " if ($s) { $out += [pscustomobject]@{ Name = [string]$s.Name; Status = $s.Status.ToString() } } };"
            " ConvertTo-Json -InputObject @($out) -Compress"
        )
        try:
            rc, data = _run_ps_json(script)
            if rc != 0 or data is None:
                self.logger.warning("Could not query risky services")
                return issues
            if isinstance(data, dict):
                data = [data]
            running = {str(s.get("Name", "")).lower() for s in data if s.get("Status") == "Running"}
        except Exception as e:
            self.logger.debug(f"Could not check services: {e}")
            return issues

        for service_name, (display_name, score, risk) in risky_services.items():
            if service_name.lower() not in running:
                continue
            try:
                start, _delayed = _read_service_start(service_name)
            except Exception:
                start = None
            revert_type = _START_TYPE_PS.get(start, "Manual")
            issues.append(SecurityIssue(
                id=f"service_{service_name.lower()}",
                title=f"Risky service running: {display_name}",
                description=f"The {display_name} service is running and could be exploited to access the system.",
                domain=SecurityDomain.SYSTEM,
                risk=risk,
                current_state="⚠️ Running",
                recommended_action=f"Disable the {display_name} service if not used",
                score_impact=score,
                fix_command=f"Stop-Service -Name {service_name} -Force; Set-Service -Name {service_name} -StartupType Disabled",
                revert_command=f"Set-Service -Name {service_name} -StartupType {revert_type}; Start-Service -Name {service_name}"
            ))

        return issues

    # ============================================================================
    # ACCOUNTS AUDIT (25 points)
    # ============================================================================

    def _audit_accounts(self):
        """Audit accounts and session security (25% of total score)."""
        self.logger.info("Auditing accounts security...")
        issues = []

        # Built-in admin (5 points) + Guest (3 points) - one PowerShell call
        builtin = self._get_builtin_accounts()

        admin_issue = self._check_builtin_admin(builtin)
        if admin_issue:
            issues.append(admin_issue)

        guest_issue = self._check_guest_account(builtin)
        if guest_issue:
            issues.append(guest_issue)

        # Autologon (8 points)
        autologon_issue = self._check_autologon()
        if autologon_issue:
            issues.append(autologon_issue)

        # Screen lock timeout (3 points)
        lock_issue = self._check_screen_lock()
        if lock_issue:
            issues.append(lock_issue)

        # Empty passwords (6 points)
        empty_pwd_issue = self._check_empty_passwords()
        if empty_pwd_issue:
            issues.append(empty_pwd_issue)

        self._record_domain(SecurityDomain.ACCOUNTS, 25, issues)

    def _get_builtin_accounts(self) -> Optional[Dict[str, Dict]]:
        """Find built-in Administrator (-500) and Guest (-501) by SID suffix (locale independent)."""
        script = r"""
$out = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-50[01]$' } |
    ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Sid = $_.SID.Value; Enabled = [bool]$_.Enabled } })
ConvertTo-Json -InputObject $out -Compress
"""
        try:
            rc, data = _run_ps_json(script)
            if rc != 0 or data is None:
                return None
            if isinstance(data, dict):
                data = [data]
            result = {}
            for acc in data:
                sid = str(acc.get("Sid", ""))
                if sid.endswith("-500"):
                    result["admin"] = acc
                elif sid.endswith("-501"):
                    result["guest"] = acc
            return result
        except Exception as e:
            self.logger.debug(f"Could not query built-in accounts: {e}")
            return None

    def _check_builtin_admin(self, builtin: Optional[Dict[str, Dict]] = None) -> Optional[SecurityIssue]:
        """Check if built-in Administrator account (SID -500) is enabled."""
        if builtin is None:
            builtin = self._get_builtin_accounts()
        admin = (builtin or {}).get("admin")
        if not admin or not admin.get("Enabled"):
            return None
        name = admin.get("Name", "Administrator")
        return SecurityIssue(
            id="admin_enabled",
            title="Built-in Administrator account enabled",
            description=f"The '{name}' account (SID -500) is a prime target for brute-force attacks. "
                        "Only disable it if another enabled administrator account exists.",
            domain=SecurityDomain.ACCOUNTS,
            risk=RiskLevel.MEDIUM,
            current_state="⚠️ Enabled",
            recommended_action="Disable the built-in Administrator account",
            score_impact=5,
            fix_command="Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Disable-LocalUser",
            revert_command="Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' } | Enable-LocalUser",
            learn_more_url="https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/accounts-administrator-account-status"
        )

    def _check_guest_account(self, builtin: Optional[Dict[str, Dict]] = None) -> Optional[SecurityIssue]:
        """Check if Guest account (SID -501) is enabled."""
        if builtin is None:
            builtin = self._get_builtin_accounts()
        guest = (builtin or {}).get("guest")
        if not guest or not guest.get("Enabled"):
            return None
        return SecurityIssue(
            id="guest_enabled",
            title="Guest account enabled",
            description="The Guest account allows unauthenticated access to the system.",
            domain=SecurityDomain.ACCOUNTS,
            risk=RiskLevel.MEDIUM,
            current_state="⚠️ Enabled",
            recommended_action="Disable the Guest account",
            score_impact=3,
            fix_command="Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser",
            revert_command="Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Enable-LocalUser"
        )

    def _check_autologon(self) -> Optional[SecurityIssue]:
        """Check for automatic logon."""
        try:
            exists, autologon, _ = _reg_read(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon"
            )
            if exists and str(autologon).strip() == "1":
                return SecurityIssue(
                    id="autologon_enabled",
                    title="Automatic logon enabled",
                    description="The password is stored in plain text in the registry and the session logs on automatically.",
                    domain=SecurityDomain.ACCOUNTS,
                    risk=RiskLevel.CRITICAL,
                    current_state="❌ Enabled",
                    recommended_action="Disable automatic logon immediately",
                    score_impact=8,
                    fix_command="Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 0",
                    revert_command="Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -Value 1",
                    learn_more_url="https://docs.microsoft.com/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon"
                )
        except Exception as e:
            self.logger.debug(f"Could not check autologon: {e}")

        return None

    def _check_screen_lock(self) -> Optional[SecurityIssue]:
        """Check screen lock timeout (HKCU of the elevated user)."""
        try:
            exists, timeout, _ = _reg_read(winreg.HKEY_CURRENT_USER, r"Control Panel\Desktop", "ScreenSaveTimeOut")
            if not exists:
                return None  # Not configured
            timeout_min = int(str(timeout).strip() or "0") // 60

            if timeout_min > 15 or timeout_min == 0:
                return SecurityIssue(
                    id="screen_lock_long",
                    title=f"Screen lock timeout too long ({timeout_min} min)",
                    description="A session left idle too long is vulnerable to unauthorized physical access." + HKCU_NOTE,
                    domain=SecurityDomain.ACCOUNTS,
                    risk=RiskLevel.LOW,
                    current_state=f"⚠️ {timeout_min} minutes",
                    recommended_action="Reduce the timeout to 10-15 minutes at most",
                    score_impact=3,
                    fix_command="Set-ItemProperty 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaveTimeOut -Value 600",
                    revert_command=f"Set-ItemProperty 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaveTimeOut -Value {_ps_quote(timeout)}"
                )
        except Exception as e:
            self.logger.debug(f"Could not check screen lock: {e}")

        return None

    def _check_empty_passwords(self) -> Optional[SecurityIssue]:
        """Check for accounts with empty passwords (limited detection). Windows default: LimitBlankPasswordUse=1."""
        try:
            exists, limit_blank, _ = _reg_read(
                winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse"
            )
            if exists and int(limit_blank) == 0:
                return SecurityIssue(
                    id="blank_passwords_allowed",
                    title="Blank passwords allowed",
                    description="System policy allows accounts without a password, making unauthorized access easier.",
                    domain=SecurityDomain.ACCOUNTS,
                    risk=RiskLevel.HIGH,
                    current_state="❌ Allowed",
                    recommended_action="Block blank passwords",
                    score_impact=6,
                    fix_command="Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LimitBlankPasswordUse -Value 1",
                    revert_command="Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LimitBlankPasswordUse -Value 0"
                )
        except Exception as e:
            self.logger.debug(f"Could not check blank password policy: {e}")

        return None

    # ============================================================================
    # NETWORK AUDIT (30 points)
    # ============================================================================

    def _audit_network(self):
        """Audit network security (30% of total score)."""
        self.logger.info("Auditing network security...")
        issues = []

        # RDP exposure (8 points)
        rdp_issue = self._check_rdp_exposure()
        if rdp_issue:
            issues.append(rdp_issue)

        # SMB exposure (7 points)
        smb_issue = self._check_smb_exposure()
        if smb_issue:
            issues.append(smb_issue)

        # Anonymous SAM access (7 points)
        sam_issue = self._check_anonymous_sam()
        if sam_issue:
            issues.append(sam_issue)

        # NTLMv2 enforcement (8 points)
        ntlm_issue = self._check_ntlmv2()
        if ntlm_issue:
            issues.append(ntlm_issue)

        # SMBv1 server (6 points), NetBIOS over TCP/IP (2 points)
        for check in (self._check_smb1, self._check_netbios):
            issue = check()
            if issue:
                issues.append(issue)

        self._record_domain(SecurityDomain.NETWORK, NETWORK_MAX_SCORE, issues)

    def _check_rdp_exposure(self) -> Optional[SecurityIssue]:
        """Check if RDP is exposed."""
        try:
            exists, deny_connections, _ = _reg_read(
                winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections"
            )
            if exists and int(deny_connections) == 0:
                return SecurityIssue(
                    id="rdp_exposed",
                    title="RDP exposed (port 3389)",
                    description="Remote Desktop is enabled and can be targeted by brute-force attacks.",
                    domain=SecurityDomain.NETWORK,
                    risk=RiskLevel.CRITICAL,
                    current_state="❌ Exposed",
                    recommended_action="Disable RDP if not used, or restrict access with the firewall",
                    score_impact=8,
                    fix_command="Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1",
                    revert_command="Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0",
                    learn_more_url="https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/remote-desktop-services"
                )
        except Exception as e:
            self.logger.debug(f"Could not check RDP: {e}")

        return None

    def _check_smb_exposure(self) -> Optional[SecurityIssue]:
        """Check SMB exposure and shares (administrative/special shares excluded)."""
        script = r"""
$n = @(Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special }).Count
ConvertTo-Json -InputObject ([int]$n) -Compress
"""
        try:
            rc, data = _run_ps_json(script)
            if rc == 0 and isinstance(data, int):
                share_count = data
                if share_count > 0:
                    return SecurityIssue(
                        id="smb_shares",
                        title=f"{share_count} active network share(s)",
                        description=f"{share_count} network share(s) exposed. Check their permissions and whether they are needed.",
                        domain=SecurityDomain.NETWORK,
                        risk=RiskLevel.MEDIUM,
                        current_state=f"⚠️ {share_count} share(s)",
                        recommended_action="Review network shares and remove unnecessary ones",
                        score_impact=7,
                        learn_more_url="https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-access"
                    )
        except Exception as e:
            self.logger.debug(f"Could not check SMB shares: {e}")

        return None

    def _check_anonymous_sam(self) -> Optional[SecurityIssue]:
        """Check anonymous SAM enumeration. Windows default: RestrictAnonymousSAM=1."""
        try:
            exists, restrict_anon_sam, _ = _reg_read(
                winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM"
            )
            if exists and int(restrict_anon_sam) == 0:
                return SecurityIssue(
                    id="sam_anonymous",
                    title="Anonymous SAM access allowed",
                    description="User accounts can be enumerated without authentication (network reconnaissance).",
                    domain=SecurityDomain.NETWORK,
                    risk=RiskLevel.CRITICAL,
                    current_state="❌ Open",
                    recommended_action="Block anonymous SAM access immediately",
                    score_impact=7,
                    fix_command="Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RestrictAnonymousSAM -Value 1",
                    revert_command="Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name RestrictAnonymousSAM -Value 0",
                    learn_more_url="https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts"
                )
        except Exception as e:
            self.logger.debug(f"Could not check SAM access: {e}")

        return None

    def _check_smb1(self) -> Optional[SecurityIssue]:
        """SMBv1 on the server side (this PC offering files over the obsolete protocol)."""
        try:
            rc, data = _run_ps_json(
                "ConvertTo-Json -InputObject ([bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol) -Compress")
            if rc == 0 and data is True:
                return SecurityIssue(
                    id="smb1_enabled",
                    title="SMBv1 server is enabled",
                    description="SMBv1 is the protocol exploited by WannaCry and EternalBlue. This PC still accepts it from the network.",
                    domain=SecurityDomain.NETWORK,
                    risk=RiskLevel.HIGH,
                    current_state="❌ Enabled",
                    recommended_action="Turn the SMBv1 server off (Recommended hardening profile). "
                                       "Connecting to an old NAS as a client is not affected.",
                    score_impact=6,
                    fix_command="Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                    revert_command="Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force",
                    learn_more_url="https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"
                )
        except Exception as e:
            self.logger.debug(f"Could not check SMBv1: {e}")
        return None

    def _check_netbios(self) -> Optional[SecurityIssue]:
        """NetBIOS over TCP/IP (TCP 139, UDP 137/138): name spoofing and discovery of this PC on the network."""
        try:
            interfaces = _netbios_interfaces()
            enabled = [name for name, opt in interfaces.items() if opt != NETBIOS_DISABLED]
            if enabled:
                return SecurityIssue(
                    id="netbios_enabled",
                    title=f"NetBIOS over TCP/IP enabled on {len(enabled)} interface(s)",
                    description="NetBIOS lets other machines discover this PC by name and enables name spoofing attacks. "
                                "Modern networks use DNS; only very old devices or workgroup browsing need it.",
                    domain=SecurityDomain.NETWORK,
                    risk=RiskLevel.LOW,
                    current_state=f"⚠️ {len(enabled)}/{len(interfaces)} interface(s)",
                    recommended_action="Disable NetBIOS over TCP/IP (Strict hardening profile; reconnect the network or reboot afterwards)",
                    score_impact=2,
                    requires_reboot=True,
                    learn_more_url="https://learn.microsoft.com/windows-server/networking/technologies/wins/wins-top"
                )
        except Exception as e:
            self.logger.debug(f"Could not check NetBIOS: {e}")
        return None

    def _check_ntlmv2(self) -> Optional[SecurityIssue]:
        """
        Check LAN Manager authentication level.

        Value absent = Windows 10 default = 3 (send NTLMv2 only), considered fine.
        Levels 0-2 send LM/NTLMv1 -> issue. Level 5 (refuse LM/NTLM) is only
        offered by the Strict profile (compatibility risk).
        """
        lsa = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
        try:
            exists, lm_level, _ = _reg_read(
                winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel"
            )
            if not exists:
                return None
            lm_level = int(lm_level)
            if lm_level < 3:
                return SecurityIssue(
                    id="ntlm_weak",
                    title=f"Weak authentication protocol (level {lm_level})",
                    description="NTLMv1 or LM is allowed. These protocols are vulnerable to relay and cracking attacks.",
                    domain=SecurityDomain.NETWORK,
                    risk=RiskLevel.HIGH,
                    current_state=f"⚠️ Level {lm_level}/5",
                    recommended_action="Send NTLMv2 only (level 3, Windows default) or higher (5 = Strict profile)",
                    score_impact=8,
                    fix_command=f"Set-ItemProperty '{lsa}' -Name LmCompatibilityLevel -Value 3",
                    revert_command=f"Set-ItemProperty '{lsa}' -Name LmCompatibilityLevel -Value {_ps_quote(lm_level)}",
                    learn_more_url="https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level"
                )
        except Exception as e:
            self.logger.debug(f"Could not check NTLM level: {e}")

        return None

    # ============================================================================
    # DATA AUDIT (20 points)
    # ============================================================================

    def _audit_data(self):
        """Audit data protection (20% of total score)."""
        self.logger.info("Auditing data security...")
        issues = []

        # BitLocker system (10 points). Not counted at all where it cannot exist (Windows Home, or no BitLocker
        # cmdlet): the maximum drops by those 10 points, so the domain is judged on what the PC can actually do.
        max_score = 20
        self._bitlocker_unavailable = False
        if self._bitlocker_edition_supported():
            bitlocker_issue = self._check_bitlocker()
            if bitlocker_issue:
                issues.append(bitlocker_issue)
        else:
            self._bitlocker_unavailable = True
        if self._bitlocker_unavailable:
            max_score -= 10
            self.logger.info("BitLocker is not available on this edition of Windows: not counted in the score")

        # Restore points (5 points)
        restore_issue = self._check_restore_points()
        if restore_issue:
            issues.append(restore_issue)

        # Windows Backup (5 points)
        backup_issue = self._check_windows_backup()
        if backup_issue:
            issues.append(backup_issue)

        self._record_domain(SecurityDomain.DATA, max_score, issues)

    @staticmethod
    def _bitlocker_edition_supported() -> bool:
        """False on Windows Home (EditionID 'Core...'): BitLocker drive encryption is Pro, Enterprise and Education
        only. An unreadable edition counts as supported, so the check itself decides."""
        try:
            exists, edition, _ = _reg_read(winreg.HKEY_LOCAL_MACHINE,
                                           r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "EditionID")
        except Exception:  # noqa: BLE001
            return True
        return not (exists and str(edition).lower().startswith("core"))

    def _check_bitlocker(self) -> Optional[SecurityIssue]:
        """Check BitLocker encryption status of the system drive."""
        script = r"""
$v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
[pscustomobject]@{ Status = $v.VolumeStatus.ToString(); Protection = $v.ProtectionStatus.ToString() } | ConvertTo-Json -Compress
"""
        drive = os.environ.get("SystemDrive", "C:")
        try:
            rc, data = _run_ps_json(script)
            if rc != 0 or not isinstance(data, dict):
                self.logger.debug("BitLocker status unavailable (edition without BitLocker or access denied)")
                self._bitlocker_unavailable = True  # the cmdlet is missing: nothing to enable, nothing to penalise
                return None
            status = str(data.get("Status", ""))
            protection = str(data.get("Protection", ""))
            if status != "FullyEncrypted":
                return SecurityIssue(
                    id="bitlocker_disabled",
                    title=f"BitLocker off on {drive}\\",
                    description="The system drive is not encrypted. If the device is stolen, all data is accessible.",
                    domain=SecurityDomain.DATA,
                    risk=RiskLevel.HIGH,
                    current_state="❌ Not encrypted",
                    recommended_action="Enable BitLocker on the system volume",
                    score_impact=10,
                    fix_command=f"Enable-BitLocker -MountPoint {drive} -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest",
                    requires_reboot=True,
                    learn_more_url="https://docs.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-overview"
                )
            if protection == "Off":
                return SecurityIssue(
                    id="bitlocker_suspended",
                    title=f"BitLocker protection suspended on {drive}\\",
                    description="The drive is encrypted but protection is suspended (key stored in clear on the disk).",
                    domain=SecurityDomain.DATA,
                    risk=RiskLevel.MEDIUM,
                    current_state="⚠️ Suspended",
                    recommended_action="Resume BitLocker protection",
                    score_impact=5,
                    fix_command=f"Resume-BitLocker -MountPoint {drive}",
                    learn_more_url="https://docs.microsoft.com/windows/security/information-protection/bitlocker/bitlocker-overview"
                )
        except Exception as e:
            self.logger.debug(f"Could not check BitLocker: {e}")

        return None

    def _check_restore_points(self) -> Optional[SecurityIssue]:
        """Check system restore points (last 7 days)."""
        script = r"""
$lim = (Get-Date).AddDays(-7)
$n = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue |
    Where-Object { $_.ConvertToDateTime($_.CreationTime) -gt $lim }).Count
ConvertTo-Json -InputObject ([int]$n) -Compress
"""
        try:
            rc, data = _run_ps_json(script)
            if rc == 0 and isinstance(data, int):
                if data == 0:
                    return SecurityIssue(
                        id="no_restore_point",
                        title="No recent restore point",
                        description="No restore point in the last 7 days (or System Protection is off). Configuration could be lost if something goes wrong.",
                        domain=SecurityDomain.DATA,
                        risk=RiskLevel.MEDIUM,
                        current_state="⚠️ None (< 7 days)",
                        recommended_action="Create a system restore point",
                        score_impact=5,
                        fix_command="Checkpoint-Computer -Description 'DD Cleaner Security Audit' -RestorePointType MODIFY_SETTINGS"
                    )
        except Exception as e:
            self.logger.debug(f"Could not check restore points: {e}")

        return None

    def _check_windows_backup(self) -> Optional[SecurityIssue]:
        """Check Windows Backup status (File History, HKCU of the elevated user)."""
        try:
            exists, enabled, _ = _reg_read(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\BackupRestore\FileHistory",
                "Enabled"
            )
            if not exists or int(enabled) != 1:
                return SecurityIssue(
                    id="backup_disabled",
                    title="File History disabled",
                    description="No automatic backup is configured. Data could be lost after a failure." + HKCU_NOTE,
                    domain=SecurityDomain.DATA,
                    risk=RiskLevel.LOW,
                    current_state="❌ Inactive",
                    recommended_action="Set up Windows File History",
                    score_impact=5,
                    learn_more_url="https://support.microsoft.com/windows-backup"
                )
        except Exception as e:
            self.logger.debug(f"Could not check Windows Backup: {e}")

        return None


# ============================================================================
# HARDENING ACTIONS
# ============================================================================

_LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"
_UAC = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

# Built-in action definitions. Revert always uses these definitions (never paths read back
# from the JSON backup) so a tampered backup cannot redirect writes elsewhere.
_ACTION_DEFS: Dict[str, Dict] = {
    "defender_enable": {"id": "defender_enable", "title": "Enable Defender", "kind": "defender"},
    "firewall_enable": {"id": "firewall_enable", "title": "Enable firewall", "kind": "firewall"},
    "guest_disable": {"id": "guest_disable", "title": "Disable Guest account", "kind": "account", "rid": 501},
    "autologon_disable": {
        "id": "autologon_disable", "title": "Disable automatic logon", "kind": "registry",
        "hive": "HKLM", "key": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "values": [{"name": "AutoAdminLogon", "type": winreg.REG_SZ, "data": "0"}],
    },
    "sam_restrict": {
        "id": "sam_restrict", "title": "Block anonymous SAM access", "kind": "registry", "hive": "HKLM", "key": _LSA,
        "values": [{"name": "RestrictAnonymousSAM", "type": winreg.REG_DWORD, "data": 1}],
    },
    "admin_disable": {"id": "admin_disable", "title": "Disable built-in Administrator", "kind": "account", "rid": 500},
    "rdp_disable": {
        "id": "rdp_disable", "title": "Disable RDP", "kind": "registry", "hive": "HKLM",
        "key": r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        "values": [{"name": "fDenyTSConnections", "type": winreg.REG_DWORD, "data": 1}],
    },
    "ntlmv2_enforce": {
        "id": "ntlmv2_enforce", "title": "Enforce NTLMv2 (refuse LM/NTLM)", "kind": "registry", "hive": "HKLM",
        "key": _LSA, "values": [{"name": "LmCompatibilityLevel", "type": winreg.REG_DWORD, "data": 5}],
    },
    "uac_max": {
        # 2 = Always notify, consent on the secure desktop
        "id": "uac_max", "title": "UAC maximum level", "kind": "registry", "hive": "HKLM", "key": _UAC,
        "values": [
            {"name": "ConsentPromptBehaviorAdmin", "type": winreg.REG_DWORD, "data": 2},
            {"name": "PromptOnSecureDesktop", "type": winreg.REG_DWORD, "data": 1},
        ],
    },
    "remote_registry_disable": {
        "id": "remote_registry_disable", "title": "Disable Remote Registry", "kind": "service",
        "service": "RemoteRegistry", "start": 4, "stop": True,
    },
    "wdigest_disable": {
        "id": "wdigest_disable", "title": "Stop WDigest keeping clear-text passwords", "kind": "registry",
        "hive": "HKLM", "key": WDIGEST_KEY,
        "values": [{"name": "UseLogonCredential", "type": winreg.REG_DWORD, "data": 0}],
    },
    # Server side only: connecting to an old NAS (client side) keeps working
    "smb1_disable": {"id": "smb1_disable", "title": "Turn the SMBv1 server off", "kind": "smb1"},
    "netbios_disable": {"id": "netbios_disable", "title": "Disable NetBIOS over TCP/IP", "kind": "netbios"},
}

_BASIC_IDS = ["defender_enable", "firewall_enable", "guest_disable", "autologon_disable"]
_RECOMMENDED_IDS = _BASIC_IDS + ["sam_restrict", "admin_disable", "wdigest_disable", "smb1_disable"]
# RDP disable, LmCompatibilityLevel=5 and NetBIOS off can lock users out / break legacy NAS and workgroup
# browsing: Strict only
_STRICT_IDS = _RECOMMENDED_IDS + ["rdp_disable", "ntlmv2_enforce", "uac_max", "remote_registry_disable",
                                  "netbios_disable"]


def profile_action_count(profile: "HardeningProfile") -> int:
    """Number of actions of a profile (the UI shows it instead of hard-coding it)."""
    return len({HardeningProfile.BASIC: _BASIC_IDS, HardeningProfile.RECOMMENDED: _RECOMMENDED_IDS}
               .get(profile, _STRICT_IDS))

_FIREWALL_PROFILES = {"Domain", "Private", "Public"}
_FIREWALL_VALUES = {"True", "False", "NotConfigured"}

_REVERTIBLE_STATUSES = ("applied", "failed")


class HardeningEngine:
    """
    Security hardening automation engine.

    Before any change a JSON snapshot of the current state is written to
    hardening_backup_<timestamp>.json (see get_backup_dir()). revert_last(),
    revert_backup(path) and revert_action(action_id) restore that exact state.
    """

    SYSTEM_RESTORE_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"

    def __init__(self):
        self.logger = logging.getLogger("HardeningEngine")
        self.applied_actions: List[Dict] = []
        self.last_backup_path: Optional[str] = None
        self.last_restore_point_ok: bool = False
        self.last_restore_point_message: str = ""
        self.last_skipped: List[str] = []
        self._lock = threading.RLock()

    # ------------------------------------------------------------------------
    # Restore point
    # ------------------------------------------------------------------------

    def create_restore_point(self, description: str = "DD Cleaner - Security hardening") -> bool:
        """
        Create a System Restore point (Checkpoint-Computer).

        Windows throttles restore point creation to one per 24h; the throttle is lifted
        temporarily (SystemRestorePointCreationFrequency=0) and the previous value / absence
        is restored afterwards. Result details in self.last_restore_point_message.

        Returns:
            True only if a new restore point was actually created.
        """
        with self._lock:
            self.last_restore_point_ok = False
            self.last_restore_point_message = ""
            safe_desc = re.sub(r"[^A-Za-z0-9 _.-]", "", description)[:200] or "DD Cleaner"

            # Temporarily lift the 24h throttle
            freq_before = None
            try:
                exists, value, vtype = _reg_read(winreg.HKEY_LOCAL_MACHINE, self.SYSTEM_RESTORE_KEY,
                                                 "SystemRestorePointCreationFrequency")
                freq_before = _encode_reg_state(exists, value, vtype)
                _reg_write(winreg.HKEY_LOCAL_MACHINE, self.SYSTEM_RESTORE_KEY,
                           "SystemRestorePointCreationFrequency", winreg.REG_DWORD, 0)
            except Exception as e:
                freq_before = None
                self.logger.warning(f"Could not lift restore point frequency limit: {e}")

            script = (
                "$r = [ordered]@{ Created = $false; Before = 0; After = 0; Warning = ''; Error = '' };"
                "try {"
                " $b = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object SequenceNumber);"
                " if ($b.Count) { $r.Before = [int]$b[-1].SequenceNumber };"
                " Checkpoint-Computer -Description " + _ps_quote(safe_desc) +
                " -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop -WarningAction SilentlyContinue -WarningVariable wv;"
                " $r.Warning = (@($wv) | ForEach-Object { $_.ToString() }) -join ' ';"
                " $a = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object SequenceNumber);"
                " if ($a.Count) { $r.After = [int]$a[-1].SequenceNumber };"
                " $r.Created = ($r.After -gt $r.Before)"
                "} catch { $r.Error = $_.Exception.Message };"
                "$r | ConvertTo-Json -Compress;"
                "if ($r.Created) { exit 0 } else { exit 1 }"
            )
            try:
                rc, data = _run_ps_json(script, timeout=RESTORE_POINT_TIMEOUT)
            finally:
                if freq_before is not None:
                    try:
                        self._restore_reg_value(winreg.HKEY_LOCAL_MACHINE, self.SYSTEM_RESTORE_KEY,
                                                "SystemRestorePointCreationFrequency", freq_before)
                    except Exception as e:
                        self.logger.error(f"Could not restore SystemRestorePointCreationFrequency: {e}")

            if rc == -1 and data is None:
                self.last_restore_point_message = "Timed out or PowerShell unavailable while creating the restore point."
            elif not isinstance(data, dict):
                self.last_restore_point_message = f"Unexpected response from Checkpoint-Computer (code {rc})."
            elif rc == 0 and data.get("Created"):
                self.last_restore_point_ok = True
                self.last_restore_point_message = "Restore point created."
            elif data.get("Error"):
                self.last_restore_point_message = (
                    "Restore point creation failed (System Protection disabled?): "
                    f"{data.get('Error')}"
                )
            elif data.get("Warning"):
                self.last_restore_point_message = (
                    "Windows did not create a restore point: limit of one per 24 h "
                    f"(a recent one already exists). Details: {data.get('Warning')}"
                )
            else:
                self.last_restore_point_message = "No new restore point detected after Checkpoint-Computer."

            log = self.logger.info if self.last_restore_point_ok else self.logger.warning
            log(f"Restore point: {self.last_restore_point_message}")
            return self.last_restore_point_ok

    # ------------------------------------------------------------------------
    # Apply
    # ------------------------------------------------------------------------

    def apply_profile(self, profile: HardeningProfile, custom_actions: Optional[List[str]] = None,
                      create_restore_point: bool = True,
                      require_restore_point: bool = False) -> Tuple[int, int, List[str]]:
        """
        Apply hardening profile.

        Args:
            profile: Hardening profile to apply
            custom_actions: Optional list of specific action IDs to apply
            create_restore_point: Try to create a System Restore point first (best-effort)
            require_restore_point: Abort if the restore point could not be created

        The JSON state snapshot is mandatory: if it cannot be written nothing is applied.
        Details: self.last_backup_path, self.last_restore_point_ok / _message, self.last_skipped.

        Returns:
            Tuple of (success_count, failure_count, error_messages)
        """
        with self._lock:
            self.logger.info(f"Applying hardening profile: {profile.value}")
            self.last_skipped = []
            self.last_backup_path = None

            actions = self._get_profile_actions(profile)
            if custom_actions:
                actions = [a for a in actions if a["id"] in custom_actions]

            success = 0
            failures = 0
            errors: List[str] = []

            if require_restore_point and not create_restore_point:
                msg = "Aborted: restore point not created. Restore point not requested."
                self.logger.error(msg)
                return 0, 1, [msg]

            # 1. Snapshot current state and write the JSON backup (mandatory, before touching anything,
            #    including the restore-point throttle value)
            entries = []
            for action in actions:
                entry = {"id": action["id"], "title": action["title"], "kind": action["kind"],
                         "before": None, "status": "pending", "message": ""}
                try:
                    entry["before"] = self._snapshot(action)
                except Exception as e:
                    entry["status"] = "snapshot_failed"
                    entry["message"] = str(e)
                    self.logger.error(f"Snapshot failed for {action['id']}: {e}")
                entries.append(entry)

            backup = {
                "version": 1,
                "created": datetime.now().isoformat(timespec="seconds"),
                "profile": profile.value,
                "restore_point": {"ok": False, "message": "pending"},
                "entries": entries,
            }
            backup_path = self._write_new_backup(backup)
            if not backup_path:
                msg = "Aborted: could not write the JSON backup to the protected backup folder (no changes applied)."
                self.logger.error(msg)
                return 0, max(1, len(actions)), errors + [msg]
            self.last_backup_path = backup_path

            # 2. Restore point (best-effort unless required)
            if create_restore_point:
                rp_ok = self.create_restore_point()
            else:
                rp_ok = False
                self.last_restore_point_ok = False
                self.last_restore_point_message = "Restore point not requested."
            backup["restore_point"] = {"ok": rp_ok, "message": self.last_restore_point_message}
            if not rp_ok:
                if require_restore_point:
                    msg = f"Aborted: restore point not created. {self.last_restore_point_message}"
                    self.logger.error(msg)
                    self._discard_backup(backup_path)
                    self.last_backup_path = None
                    return 0, 1, [msg]
                errors.append(f"Warning: {self.last_restore_point_message}")
            if not self._save_backup(backup_path, backup):
                msg = f"Aborted: the JSON backup {backup_path} can no longer be written (no changes applied)."
                self.logger.error(msg)
                return 0, max(1, len(actions)), errors + [msg]

            # 3. Apply
            for index, (action, entry) in enumerate(zip(actions, entries)):
                if entry["status"] == "snapshot_failed":
                    failures += 1
                    errors.append(f"Not applied (could not read initial state): {action['title']}")
                    continue

                skip_reason = self._precheck(action, entry["before"])
                if skip_reason:
                    entry["status"] = "skipped"
                    entry["message"] = skip_reason
                    self.last_skipped.append(f"{action['title']}: {skip_reason}")
                    errors.append(f"Skipped: {action['title']} - {skip_reason}")
                    self.logger.warning(f"Skipping {action['id']}: {skip_reason}")
                    self._save_backup(backup_path, backup)
                    continue

                # Mark as attempted before touching anything (crash-safe revert).
                # If that cannot be recorded, stop: a change without its marker could not be reverted.
                entry["status"] = "failed"
                if not self._save_backup(backup_path, backup):
                    entry["status"] = "pending"
                    remaining = len(actions) - index
                    failures += remaining
                    msg = (f"Aborted: backup {backup_path} became unwritable; "
                           f"{remaining} remaining action(s) not applied.")
                    errors.append(msg)
                    self.logger.error(msg)
                    break
                try:
                    if self._apply_action(action, entry["before"]):
                        success += 1
                        entry["status"] = "applied"
                        self.applied_actions.append({
                            "action": action,
                            "timestamp": datetime.now(),
                            "profile": profile.value,
                            "before": entry["before"],
                            "backup": backup_path,
                        })
                    else:
                        failures += 1
                        errors.append(f"Failed: {action['title']}")
                except Exception as e:
                    failures += 1
                    entry["message"] = str(e)
                    errors.append(f"Error applying {action['title']}: {e}")
                    self.logger.error(f"Error applying action {action['id']}: {e}")
                self._save_backup(backup_path, backup)

            self.logger.info(f"Profile applied: {success} success, {failures} failures, "
                             f"{len(self.last_skipped)} skipped. Backup: {backup_path}")
            return success, failures, errors

    def _precheck(self, action: Dict, before: Dict) -> Optional[str]:
        """Return a reason to skip the action, or None."""
        kind = action["kind"]
        if action["id"] == "rdp_disable" and _is_remote_session():
            return "Remote Desktop session in progress (disabling it would cut off access)"
        if kind == "account":
            if not before.get("sid"):
                return "account not found"
            if not before.get("enabled"):
                return "account already disabled"
            if action.get("rid") == 500:
                return self._builtin_admin_safety(before["sid"])
        if kind == "service" and not before.get("exists"):
            return "service not installed"
        if kind == "smb1" and before.get("enabled") is False:
            return "the SMBv1 server is already off"
        if kind == "netbios":
            interfaces = before.get("interfaces") or {}
            if not interfaces:
                return "no network interface found"
            if all((s or {}).get("exists") and (s or {}).get("data") == NETBIOS_DISABLED for s in interfaces.values()):
                return "NetBIOS is already disabled on every interface"
        return None

    def _builtin_admin_safety(self, admin_sid: str) -> Optional[str]:
        """Refuse to disable the built-in admin if it is the current user or the only enabled admin."""
        script = r"""
$r = [ordered]@{ CurrentSid = $null; Members = @(); EnabledLocal = @(); GroupOk = $false }
$r.CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$r.EnabledLocal = @(Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object { $_.SID.Value })
try {
    $r.Members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.SID.Value })
    $r.GroupOk = $true
} catch {
    try {
        $name = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $g = [ADSI]("WinNT://$env:COMPUTERNAME/$name,group")
        $r.Members = @($g.Invoke('Members') | ForEach-Object {
            $bytes = $_.GetType().InvokeMember('objectSid', 'GetProperty', $null, $_, $null)
            (New-Object Security.Principal.SecurityIdentifier($bytes, 0)).Value })
        $r.GroupOk = $true
    } catch { }
}
$r | ConvertTo-Json -Compress
"""
        rc, data = _run_ps_json(script)
        if rc != 0 or not isinstance(data, dict):
            return "safety check failed (administrator accounts)"
        if str(data.get("CurrentSid") or "") == admin_sid:
            return "it is the account currently in use"
        if not data.get("GroupOk"):
            return "could not list the Administrators group"
        members = data.get("Members") or []
        enabled = data.get("EnabledLocal") or []
        members = [members] if isinstance(members, str) else members
        enabled = set([enabled] if isinstance(enabled, str) else enabled)
        others = [m for m in members if m and m != admin_sid and m in enabled]
        if not others:
            return "it is the only enabled local administrator account"
        return None

    def _apply_action(self, action: Dict, before: Optional[Dict] = None) -> bool:
        """Apply a single hardening action."""
        kind = action.get("kind")
        try:
            if kind == "registry":
                hive = _HIVES[action["hive"]]
                for val in action["values"]:
                    _reg_write(hive, action["key"], val["name"], val["type"], val["data"])
                for val in action["values"]:
                    exists, current, _ = _reg_read(hive, action["key"], val["name"])
                    if not exists or current != val["data"]:
                        return False
                return True

            if kind == "service":
                name = action["service"]
                if not _SAFE_NAME_RE.match(name):
                    return False
                rc, _out, err = _run_exe([SC_EXE, "config", name, "start=", _START_TYPE_SC[action["start"]]])
                if rc != 0:
                    self.logger.error(f"sc config {name} failed ({rc}): {err.strip()}")
                    return False
                if action.get("stop"):
                    rc, _out, _err = _run_ps(f"Stop-Service -Name {_ps_quote(name)} -Force -ErrorAction Stop")
                    if rc != 0:
                        self.logger.warning(f"Service {name} disabled but could not be stopped")
                return True

            if kind == "account":
                sid = (before or {}).get("sid", "")
                if not _LOCAL_SID_RE.match(sid):
                    return False
                rc, _out, _err = _run_ps(f"Disable-LocalUser -SID {_ps_quote(sid)} -ErrorAction Stop")
                return rc == 0

            if kind == "defender":
                rc, data = _run_ps_json(
                    "Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop;"
                    "ConvertTo-Json -InputObject ([bool](Get-MpPreference).DisableRealtimeMonitoring) -Compress"
                )
                # Tamper Protection may silently ignore the change: verify
                return rc == 0 and data is False

            if kind == "firewall":
                rc, _out, _err = _run_ps(
                    "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop"
                )
                return rc == 0

            if kind == "smb1":
                rc, data = _run_ps_json(
                    "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false -ErrorAction Stop;"
                    "ConvertTo-Json -InputObject ([bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol) -Compress"
                )
                return rc == 0 and data is False  # verified, not assumed

            if kind == "netbios":
                names = list(((before or {}).get("interfaces") or {}))
                for name in names:
                    if _NETBIOS_IFACE_RE.match(name):
                        _reg_write(winreg.HKEY_LOCAL_MACHINE, f"{NETBIOS_ROOT}\\{name}", "NetbiosOptions",
                                   winreg.REG_DWORD, NETBIOS_DISABLED)
                return bool(names) and all(
                    _reg_read(winreg.HKEY_LOCAL_MACHINE, f"{NETBIOS_ROOT}\\{n}", "NetbiosOptions")[1] == NETBIOS_DISABLED
                    for n in names if _NETBIOS_IFACE_RE.match(n))

            self.logger.error(f"Unknown action kind for {action.get('id')}: {kind}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to apply action {action.get('id')}: {e}")
            return False

    # ------------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------------

    def _snapshot(self, action: Dict) -> Dict:
        """Capture current state for an action (raises on failure)."""
        kind = action["kind"]

        if kind == "registry":
            hive = _HIVES[action["hive"]]
            values = {}
            for val in action["values"]:
                exists, value, vtype = _reg_read(hive, action["key"], val["name"])
                values[val["name"]] = _encode_reg_state(exists, value, vtype)
            return {"values": values}

        if kind == "service":
            name = action["service"]
            start, delayed = _read_service_start(name)
            if start is None:
                return {"exists": False}
            running = None
            rc, data = _run_ps_json(
                f"$s = Get-Service -Name {_ps_quote(name)} -ErrorAction Stop;"
                "ConvertTo-Json -InputObject $s.Status.ToString() -Compress"
            )
            if rc == 0 and isinstance(data, str):
                running = (data == "Running")
            return {"exists": True, "start": start, "delayed": delayed, "running": running}

        if kind == "account":
            rid = int(action["rid"])
            rc, data = _run_ps_json(
                "$u = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-" + str(rid) + "$' } | Select-Object -First 1;"
                "if ($u) { [pscustomobject]@{ Sid = $u.SID.Value; Enabled = [bool]$u.Enabled } | ConvertTo-Json -Compress }"
                " else { 'null' }"
            )
            if rc != 0:
                raise RuntimeError("Get-LocalUser failed")
            if not isinstance(data, dict):
                return {"sid": None, "enabled": None}
            return {"sid": data.get("Sid"), "enabled": bool(data.get("Enabled"))}

        if kind == "defender":
            rc, data = _run_ps_json(
                "ConvertTo-Json -InputObject ([bool](Get-MpPreference -ErrorAction Stop).DisableRealtimeMonitoring) -Compress"
            )
            if rc != 0 or not isinstance(data, bool):
                raise RuntimeError("Get-MpPreference failed")
            return {"disable_realtime_monitoring": data}

        if kind == "firewall":
            rc, data = _run_ps_json(
                "$p = @(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop |"
                " ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Enabled = $_.Enabled.ToString() } });"
                "ConvertTo-Json -InputObject $p -Compress"
            )
            if rc != 0 or data is None:
                raise RuntimeError("Get-NetFirewallProfile failed")
            if isinstance(data, dict):
                data = [data]
            return {"profiles": [{"name": p.get("Name"), "enabled": p.get("Enabled")} for p in data]}

        if kind == "smb1":
            rc, data = _run_ps_json(
                "ConvertTo-Json -InputObject ([bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol) -Compress")
            if rc != 0 or not isinstance(data, bool):
                raise RuntimeError("Get-SmbServerConfiguration failed")
            return {"enabled": data}

        if kind == "netbios":
            interfaces = {}
            for name in _netbios_interfaces():
                exists, value, vtype = _reg_read(winreg.HKEY_LOCAL_MACHINE, f"{NETBIOS_ROOT}\\{name}", "NetbiosOptions")
                interfaces[name] = _encode_reg_state(exists, value, vtype)
            return {"interfaces": interfaces}

        raise ValueError(f"Unknown action kind: {kind}")

    # ------------------------------------------------------------------------
    # Revert
    # ------------------------------------------------------------------------

    def revert_action(self, action_id: str) -> bool:
        """Revert a previously applied action (from the latest backup containing it)."""
        with self._lock:
            path = self._find_backup_with(action_id)
            if not path:
                self.logger.error(f"No backup entry found to revert {action_id}")
                return False
            backup = self._load_backup(path)
            if backup is None:
                return False
            ok = False
            for entry in reversed(backup.get("entries", [])):
                if entry.get("id") == action_id and entry.get("status") in _REVERTIBLE_STATUSES:
                    ok = self._revert_entry(entry)
                    entry["status"] = "reverted" if ok else "revert_failed"
                    break
            self._save_backup(path, backup)
            return ok

    def revert_last(self) -> Tuple[int, int]:
        """
        Revert every action of the most recent hardening backup.

        Returns:
            Tuple of (reverted_count, failed_count)
        """
        with self._lock:
            path = self.last_backup_path if self.last_backup_path and os.path.isfile(self.last_backup_path) \
                else self._latest_backup()
            if not path:
                self.logger.error("No hardening backup found to revert")
                return 0, 0
            return self.revert_backup(path)

    def revert_backup(self, path: str) -> Tuple[int, int]:
        """Revert all attempted actions stored in a backup file. Returns (reverted_count, failed_count)."""
        with self._lock:
            backup = self._load_backup(path)
            if backup is None:
                return 0, 1
            ok_count = 0
            fail_count = 0
            for entry in reversed(backup.get("entries", [])):
                if entry.get("status") not in _REVERTIBLE_STATUSES:
                    continue
                if self._revert_entry(entry):
                    ok_count += 1
                    entry["status"] = "reverted"
                else:
                    fail_count += 1
                    entry["status"] = "revert_failed"
            backup["reverted"] = datetime.now().isoformat(timespec="seconds")
            self._save_backup(path, backup)
            self.logger.info(f"Revert of {path}: {ok_count} ok, {fail_count} failed")
            return ok_count, fail_count

    def _revert_entry(self, entry: Dict) -> bool:
        """Restore the state captured in a backup entry (definition taken from _ACTION_DEFS)."""
        action = _ACTION_DEFS.get(entry.get("id", ""))
        before = entry.get("before")
        if not action or not isinstance(before, dict):
            self.logger.error(f"Cannot revert unknown/invalid entry: {entry.get('id')}")
            return False
        kind = action["kind"]
        try:
            if kind == "registry":
                hive = _HIVES[action["hive"]]
                expected_types = {v["name"]: v["type"] for v in action["values"]}
                states = before.get("values") or {}
                restored = 0
                for name, vtype in expected_types.items():
                    if name in states:
                        self._restore_reg_value(hive, action["key"], name, states[name], vtype)
                        restored += 1
                return restored > 0  # nothing restored is not a successful undo

            if kind == "service":
                name = action["service"]
                start = before.get("start")
                if not before.get("exists") or start not in _START_TYPE_SC:
                    return False
                start_arg = "delayed-auto" if (start == 2 and before.get("delayed") == 1) else _START_TYPE_SC[start]
                rc, _out, err = _run_exe([SC_EXE, "config", name, "start=", start_arg])
                if rc != 0:
                    self.logger.error(f"sc config {name} failed ({rc}): {err.strip()}")
                    return False
                if before.get("running") is True:
                    rc, _out, _err = _run_ps(f"Start-Service -Name {_ps_quote(name)} -ErrorAction Stop")
                    if rc != 0:
                        self.logger.warning(f"Service {name} start type restored but it could not be started")
                return True

            if kind == "account":
                sid = str(before.get("sid") or "")
                if not _LOCAL_SID_RE.match(sid) or not sid.endswith(f"-{action['rid']}"):
                    return False
                verb = "Enable-LocalUser" if before.get("enabled") else "Disable-LocalUser"
                rc, _out, _err = _run_ps(f"{verb} -SID {_ps_quote(sid)} -ErrorAction Stop")
                return rc == 0

            if kind == "defender":
                value = before.get("disable_realtime_monitoring")
                if not isinstance(value, bool):
                    return False
                rc, _out, _err = _run_ps(
                    f"Set-MpPreference -DisableRealtimeMonitoring ${str(value).lower()} -ErrorAction Stop"
                )
                return rc == 0

            if kind == "firewall":
                commands = []
                for prof in before.get("profiles") or []:
                    name, enabled = prof.get("name"), prof.get("enabled")
                    if name in _FIREWALL_PROFILES and enabled in _FIREWALL_VALUES:
                        commands.append(f"Set-NetFirewallProfile -Profile {name} -Enabled {enabled} -ErrorAction Stop")
                if not commands:
                    return False
                rc, _out, _err = _run_ps(";".join(commands))
                return rc == 0

            if kind == "smb1":
                value = before.get("enabled")
                if not isinstance(value, bool):
                    return False
                rc, _out, _err = _run_ps(
                    f"Set-SmbServerConfiguration -EnableSMB1Protocol ${str(value).lower()} -Force -Confirm:$false -ErrorAction Stop")
                return rc == 0

            if kind == "netbios":
                restored = 0
                for name, state in (before.get("interfaces") or {}).items():
                    path = f"{NETBIOS_ROOT}\\{name}"
                    if not (isinstance(name, str) and _NETBIOS_IFACE_RE.match(name) and isinstance(state, dict)):
                        continue  # a backup cannot name another key
                    try:  # the adapter may have been removed since: never re-create its key
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0,
                                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
                            pass
                    except FileNotFoundError:
                        continue
                    self._restore_reg_value(winreg.HKEY_LOCAL_MACHINE, path, "NetbiosOptions", state, winreg.REG_DWORD)
                    restored += 1
                return restored > 0
        except Exception as e:
            self.logger.error(f"Failed to revert action {entry.get('id')}: {e}")
        return False

    def _restore_reg_value(self, hive: int, path: str, name: str, state: Dict, expected_type: Optional[int] = None):
        """Restore a registry value to a snapshot state (delete it if it was absent).
        The value keeps the type the catalogue writes: a backup cannot turn a DWORD into a string or a blob."""
        if not state.get("exists"):
            _reg_delete(hive, path, name)
            return
        vtype = int(state["type"])
        if expected_type is not None and vtype != expected_type:
            raise ValueError(f"{name}: type {vtype} in the backup, {expected_type} expected")
        data = _decode_reg_data(state.get("data"))
        if vtype == winreg.REG_DWORD:
            data = int(data)
            if not 0 <= data <= 0xFFFFFFFF:
                raise ValueError(f"{name}: DWORD out of range")
        elif vtype == winreg.REG_QWORD:
            data = int(data)
        elif vtype in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            data = str(data)
        else:
            raise ValueError(f"{name}: unsupported value type {vtype}")
        _reg_write(hive, path, name, vtype, data)

    # ------------------------------------------------------------------------
    # Backup files
    # ------------------------------------------------------------------------

    def _write_new_backup(self, backup: Dict) -> Optional[str]:
        """Create a new hardening_backup_<timestamp>.json file. Returns its path or None."""
        try:
            directory = get_backup_dir()
        except OSError as e:  # data folder unsafe or unavailable: no backup, so no change either
            self.logger.error(f"Backup folder unavailable: {e}")
            return None
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(directory, f"hardening_backup_{stamp}.json")
        suffix = 1
        while os.path.exists(path):
            path = os.path.join(directory, f"hardening_backup_{stamp}_{suffix}.json")
            suffix += 1
        if self._save_backup(path, backup):
            return path
        return None

    def _discard_backup(self, path: str) -> None:
        """Remove a backup written for a run that was aborted before any change."""
        try:
            os.remove(path)
        except OSError as e:
            self.logger.warning(f"Could not remove unused backup {path}: {e}")

    def _save_backup(self, path: str, backup: Dict) -> bool:
        """Atomically write a backup file."""
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(backup, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            return True
        except Exception as e:
            self.logger.error(f"Could not write hardening backup {path}: {e}")
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            return False

    def _load_backup(self, path: str) -> Optional[Dict]:
        """Load a backup file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
                raise ValueError("invalid format")
            return data
        except Exception as e:
            self.logger.error(f"Could not read hardening backup {path}: {e}")
            return None

    def list_backups(self) -> List[str]:
        """List hardening backup files, newest first."""
        pattern = os.path.join(get_backup_dir(), "hardening_backup_*.json")
        return sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)

    def _latest_backup(self) -> Optional[str]:
        """Most recent backup file, or None."""
        backups = self.list_backups()
        return backups[0] if backups else None

    def _find_backup_with(self, action_id: str) -> Optional[str]:
        """Most recent backup containing a revertible entry for action_id."""
        candidates = []
        if self.last_backup_path and os.path.isfile(self.last_backup_path):
            candidates.append(self.last_backup_path)
        candidates.extend(p for p in self.list_backups() if p not in candidates)
        for path in candidates:
            backup = self._load_backup(path)
            if backup and any(e.get("id") == action_id and e.get("status") in _REVERTIBLE_STATUSES
                              for e in backup["entries"]):
                return path
        return None

    def _get_profile_actions(self, profile: HardeningProfile) -> List[Dict]:
        """Get actions for a specific profile (copies of the built-in definitions)."""
        if profile == HardeningProfile.BASIC:
            ids = _BASIC_IDS
        elif profile == HardeningProfile.RECOMMENDED:
            ids = _RECOMMENDED_IDS
        else:
            ids = _STRICT_IDS
        return [dict(_ACTION_DEFS[i]) for i in ids]
