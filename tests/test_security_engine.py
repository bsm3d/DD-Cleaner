"""
Tests for security_audit.py (SecurityAuditor, HardeningEngine and helpers).

SAFETY: nothing in this file may touch the real system.
  - The autouse `guard` fixture replaces subprocess.run/Popen/..., os.system/startfile/popen,
    every winreg write function and the module's ctypes with blockers that RAISE and record
    the attempt; its teardown fails the test if any blocked call was attempted (even if the
    module swallowed the exception).
  - The `fake` fixture installs an in-memory Windows (registry + PowerShell/sc.exe responder)
    on top of the guard and redirects get_backup_dir() to tmp_path.
"""

import base64
import glob
import json
import os
import re
import subprocess
import sys
import types
import winreg

import pytest

import security_audit as sa
from security_audit import (
    HardeningEngine,
    HardeningProfile,
    RiskLevel,
    SecurityAuditor,
    SecurityDomain,
)

HKLM = winreg.HKEY_LOCAL_MACHINE
HKCU = winreg.HKEY_CURRENT_USER
REG_SZ = winreg.REG_SZ
REG_DWORD = winreg.REG_DWORD

ADMIN_SID = "S-1-5-21-1111-2222-3333-500"
GUEST_SID = "S-1-5-21-1111-2222-3333-501"
USER_SID = "S-1-5-21-1111-2222-3333-1001"
OTHER_ADMIN_SID = "S-1-5-21-1111-2222-3333-1002"

WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"
TS = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
UAC = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
RUN_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
RR_SVC = r"SYSTEM\CurrentControlSet\Services\RemoteRegistry"
SR_KEY = HardeningEngine.SYSTEM_RESTORE_KEY

ORIGINAL_GET_BACKUP_DIR = sa.get_backup_dir

BASIC = ["defender_enable", "firewall_enable", "guest_disable", "autologon_disable"]
RECOMMENDED = BASIC + ["sam_restrict", "admin_disable", "wdigest_disable", "smb1_disable"]
STRICT = RECOMMENDED + ["rdp_disable", "ntlmv2_enforce", "uac_max", "remote_registry_disable", "netbios_disable"]
WDIGEST = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
NETBT = r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
IFACE_A = "Tcpip_{11111111-2222-3333-4444-555555555555}"
IFACE_B = "Tcpip_{66666666-7777-8888-9999-000000000000}"


# ============================================================================
# SAFETY GUARD (autouse)
# ============================================================================

class SystemGuard:
    """Records and blocks any real system call."""

    def __init__(self):
        self.violations = []

    def blocker(self, name):
        def _blocked(*args, **kwargs):
            self.violations.append(name)
            raise RuntimeError(f"SAFETY GUARD: unexpected real system call {name}{args!r}")
        return _blocked


class _BlockedCtypes:
    """Stand-in for security_audit.ctypes: any attribute access is a violation."""

    def __init__(self, guard):
        object.__setattr__(self, "_guard", guard)

    def __getattr__(self, name):
        self._guard.violations.append(f"ctypes.{name}")
        raise RuntimeError(f"SAFETY GUARD: unexpected ctypes access ctypes.{name}")


_SUBPROCESS_FUNCS = ("run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput")
_OS_FUNCS = ("system", "startfile", "popen")
_WINREG_WRITES = ("SetValue", "SetValueEx", "CreateKey", "CreateKeyEx", "DeleteKey", "DeleteKeyEx",
                  "DeleteValue", "SaveKey", "LoadKey", "ConnectRegistry")


@pytest.fixture(autouse=True)
def guard(monkeypatch):
    g = SystemGuard()
    for name in _SUBPROCESS_FUNCS:
        if hasattr(subprocess, name):
            monkeypatch.setattr(subprocess, name, g.blocker(f"subprocess.{name}"))
    for name in _OS_FUNCS:
        if hasattr(os, name):
            monkeypatch.setattr(os, name, g.blocker(f"os.{name}"))
    for name in _WINREG_WRITES:
        if hasattr(winreg, name):
            monkeypatch.setattr(winreg, name, g.blocker(f"winreg.{name}"))
    monkeypatch.setattr(sa, "ctypes", _BlockedCtypes(g))
    yield g
    assert not g.violations, f"Real system call attempted: {g.violations}"


# ============================================================================
# FAKE WINDOWS
# ============================================================================

class FakeKey:
    def __init__(self, hive, path, access):
        self.hive, self.path, self.access = hive, path, access

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def Close(self):
        pass


class FakeSystem:
    """In-memory registry + PowerShell / sc.exe responder with full call recording."""

    def __init__(self, backup_dir):
        self.backup_dir = str(backup_dir)
        self.reg = {}            # (hive, path.lower(), name.lower()) -> (data, type)
        self.key_names = {}      # path.lower() -> path as written (the real registry keeps the case)
        self.reg_ops = []        # (op, hive, path, name, type, data, access)
        self.runs = []           # {"args", "kwargs", "script"}
        self.mutations = []      # {"kind", "detail", "backups"}
        self.unknown = []
        self.metrics_calls = []
        self.remote_metric = 0
        self.ps_overrides = []   # (needle, rc|"timeout", stdout)

        # hardening scenario
        self.defender_disabled = True
        self.defender_after_set = False
        self.firewall_profiles = [
            {"Name": "Domain", "Enabled": "True"},
            {"Name": "Private", "Enabled": "False"},
            {"Name": "Public", "Enabled": "NotConfigured"},
        ]
        self.accounts = {
            500: {"Name": "Administrateur", "Sid": ADMIN_SID, "Enabled": True},
            501: {"Name": "Invité", "Sid": GUEST_SID, "Enabled": True},
        }
        self.safety = None       # (rc, stdout) override
        self.restore_point = (0, {"Created": True, "Before": 1, "After": 2, "Warning": "", "Error": ""})
        self.freq_during_checkpoint = "not called"
        self.service_status = "Running"
        self.exe_rc = 0

        # audit scenario
        self.audit_defender = {"Rtp": False, "DefenderSc": None, "OtherAv": []}
        self.audit_firewall_off = ["Public"]
        self.audit_update = {"Date": None}
        self.audit_builtin = [
            {"Name": "Administrateur", "Sid": ADMIN_SID, "Enabled": True},
            {"Name": "Invité", "Sid": GUEST_SID, "Enabled": True},
        ]
        self.audit_services = []
        self.audit_smb = 0
        self.smb1_enabled = True
        self.audit_hvci = {"Running": False}
        self.audit_bitlocker = {"Status": "FullyEncrypted", "Protection": "On"}
        self.audit_restore_count = 3

        self.ctypes = types.SimpleNamespace(
            windll=types.SimpleNamespace(user32=types.SimpleNamespace(GetSystemMetrics=self._get_system_metrics))
        )

        self.reg_set(HKLM, WINLOGON, "AutoAdminLogon", "1", REG_SZ)
        self.reg_set(HKLM, LSA, "RestrictAnonymousSAM", 0, REG_DWORD)
        self.reg_set(HKLM, LSA, "LimitBlankPasswordUse", 0, REG_DWORD)
        self.reg_set(HKLM, TS, "fDenyTSConnections", 0, REG_DWORD)
        self.reg_set(HKLM, UAC, "EnableLUA", 1, REG_DWORD)
        self.reg_set(HKLM, UAC, "ConsentPromptBehaviorAdmin", 5, REG_DWORD)
        self.reg_set(HKLM, RR_SVC, "Start", 3, REG_DWORD)
        self.reg_set(HKLM, WDIGEST, "UseLogonCredential", 1, REG_DWORD)
        self.reg_set(HKLM, NETBT + "\\" + IFACE_A, "NetbiosOptions", 0, REG_DWORD)
        self.reg_set(HKLM, NETBT + "\\" + IFACE_B, "NetbiosOptions", 1, REG_DWORD)

    # ---- registry state -------------------------------------------------

    @staticmethod
    def _k(hive, path, name):
        return hive, path.lower(), name.lower()

    def reg_set(self, hive, path, name, data, vtype):
        self.key_names[path.lower()] = path
        self.reg[self._k(hive, path, name)] = (data, vtype)

    def reg_get(self, hive, path, name):
        return self.reg.get(self._k(hive, path, name))

    def writes(self, hardening_only=True):
        ops = [o for o in self.reg_ops if o[0] in ("write", "delete")]
        if hardening_only:
            ops = [o for o in ops if o[2].lower() != SR_KEY.lower()]
        return ops

    # ---- winreg API -----------------------------------------------------

    def OpenKey(self, key, sub_key, reserved=0, access=winreg.KEY_READ):
        low = sub_key.lower()
        if not any(h == key and (p == low or p.startswith(low + chr(92))) for (h, p, _n) in self.reg):
            raise FileNotFoundError(2, "key not found")  # a key exists when a value is stored in it or below it
        return FakeKey(key, sub_key, access)

    def EnumKey(self, key, index):
        """Direct sub keys of an opened key (derived from the stored values, original spelling kept)."""
        prefix = key.path.lower() + chr(92)
        subs = {}
        for (_h, path, _n) in self.reg:
            if path.startswith(prefix):
                original = self.key_names.get(path, path)
                subs.setdefault(path[len(prefix):].split(chr(92))[0], original[len(prefix):].split(chr(92))[0])
        ordered = sorted(subs.values(), key=str.lower)
        if index >= len(ordered):
            raise OSError(259, "no more data")
        return ordered[index]

    def CreateKeyEx(self, key, sub_key, reserved=0, access=winreg.KEY_WRITE):
        return FakeKey(key, sub_key, access)

    def QueryValueEx(self, key, name):
        val = self.reg_get(key.hive, key.path, name)
        if val is None:
            raise FileNotFoundError(2, "value not found")
        return val

    def SetValueEx(self, key, name, reserved, vtype, data):
        assert key.access & winreg.KEY_SET_VALUE, "write through a key opened without KEY_SET_VALUE"
        self.reg_ops.append(("write", key.hive, key.path, name, vtype, data, key.access))
        self._mutation("reg_write", (key.path, name))
        self.reg_set(key.hive, key.path, name, data, vtype)

    def DeleteValue(self, key, name):
        self.reg_ops.append(("delete", key.hive, key.path, name, None, None, key.access))
        self._mutation("reg_delete", (key.path, name))
        if self.reg.pop(self._k(key.hive, key.path, name), None) is None:
            raise FileNotFoundError(2, "value not found")

    # ---- ctypes ---------------------------------------------------------

    def _get_system_metrics(self, index):
        self.metrics_calls.append(index)
        return self.remote_metric if index == 0x1000 else 0

    # ---- mutation tracking ---------------------------------------------

    def _read_backups(self):
        result = {}
        for path in glob.glob(os.path.join(self.backup_dir, "hardening_backup_*.json")):
            with open(path, "r", encoding="utf-8") as f:
                result[os.path.normcase(path)] = json.load(f)
        return result

    def _mutation(self, kind, detail):
        self.mutations.append({"kind": kind, "detail": detail, "backups": self._read_backups()})

    def hardening_mutations(self):
        return [m for m in self.mutations if action_of(m) in sa._ACTION_DEFS]

    # ---- subprocess -----------------------------------------------------

    def run(self, args, **kwargs):
        args = list(args)
        exe = os.path.basename(args[0]).lower()
        script = None
        if exe == "powershell.exe":
            encoded = args[args.index("-EncodedCommand") + 1]
            script = base64.b64decode(encoded).decode("utf-16-le")
        self.runs.append({"args": args, "kwargs": kwargs, "script": script})
        if script is not None:
            rc, out = self._powershell(script)
        elif exe == "sc.exe":
            self._mutation("exe", " ".join(args[1:]))
            rc, out = self.exe_rc, ""
        else:
            self.unknown.append(args)
            rc, out = 1, ""
        if rc == "timeout":
            raise subprocess.TimeoutExpired(args[0], kwargs.get("timeout"))
        return types.SimpleNamespace(returncode=rc, stdout=out.encode("utf-8"), stderr=b"")

    def default_safety(self):
        return {"CurrentSid": USER_SID, "Members": [ADMIN_SID, OTHER_ADMIN_SID],
                "EnabledLocal": [ADMIN_SID, OTHER_ADMIN_SID, USER_SID], "GroupOk": True}

    def _powershell(self, script):
        for needle, rc, out in self.ps_overrides:
            if needle in script:
                return rc, out
        if "Checkpoint-Computer" in script:
            self._mutation("ps", "Checkpoint-Computer")
            self.freq_during_checkpoint = self.reg_get(HKLM, SR_KEY, "SystemRestorePointCreationFrequency")
            rc, data = self.restore_point
            return rc, ("" if data is None else json.dumps(data))
        if "GetCurrent()" in script:
            if self.safety is not None:
                return self.safety
            return 0, json.dumps(self.default_safety())
        if "Set-MpPreference" in script:
            self._mutation("ps", script)
            if "ConvertTo-Json" in script:
                return 0, json.dumps(self.defender_after_set)
            m = re.search(r"-DisableRealtimeMonitoring \$(true|false)", script)
            self.defender_disabled = (m.group(1) == "true")
            return 0, ""
        if "Get-MpComputerStatus" in script:
            return 0, json.dumps(self.audit_defender)
        if "Get-MpPreference" in script:
            return 0, json.dumps(self.defender_disabled)
        if "Set-NetFirewallProfile" in script:
            self._mutation("ps", script)
            return 0, ""
        if "PersistentStore" in script:
            return 0, json.dumps(self.firewall_profiles)
        if "ActiveStore" in script:
            return 0, json.dumps(self.audit_firewall_off)
        if "Microsoft.Update.AutoUpdate" in script:
            return 0, json.dumps(self.audit_update)
        if "-50[01]$" in script:
            return 0, json.dumps(self.audit_builtin)
        if "Disable-LocalUser" in script or "Enable-LocalUser" in script:
            self._mutation("ps", script)
            m = re.search(r"(Disable|Enable)-LocalUser -SID '([^']+)'", script)
            for acc in self.accounts.values():
                if m and acc["Sid"] == m.group(2):
                    acc["Enabled"] = (m.group(1) == "Enable")
            return 0, ""
        m = re.search(r"'-(\d+)\$'", script)
        if "Get-LocalUser" in script and m:
            acc = self.accounts.get(int(m.group(1)))
            if acc is None:
                return 0, "null"
            return 0, json.dumps({"Sid": acc["Sid"], "Enabled": acc["Enabled"]})
        if "Get-SmbShare" in script:
            return 0, json.dumps(self.audit_smb)
        if "Set-SmbServerConfiguration" in script:
            self._mutation("ps", script)
            self.smb1_enabled = "$true" in script.split("Set-SmbServerConfiguration")[1].split(";")[0]
            return 0, (json.dumps(self.smb1_enabled) if "ConvertTo-Json" in script else "")
        if "Get-SmbServerConfiguration" in script:
            return 0, json.dumps(self.smb1_enabled)
        if "Win32_DeviceGuard" in script:
            return 0, json.dumps(self.audit_hvci)
        if "Get-BitLockerVolume" in script:
            return 0, json.dumps(self.audit_bitlocker)
        if "Get-ComputerRestorePoint" in script:
            return 0, json.dumps(self.audit_restore_count)
        if "foreach ($n in" in script:
            return 0, json.dumps(self.audit_services)
        if "Stop-Service" in script or "Start-Service" in script:
            self._mutation("ps", script)
            return 0, ""
        if "Get-Service -Name 'RemoteRegistry'" in script:
            return 0, json.dumps(self.service_status)
        self.unknown.append(script)
        return 1, ""

    def ps_scripts(self):
        return [r["script"] for r in self.runs if r["script"] is not None]


def action_of(mutation):
    """Map a recorded mutation to the hardening action id that caused it."""
    kind, detail = mutation["kind"], mutation["detail"]
    if kind in ("reg_write", "reg_delete"):
        path, name = detail
        if path.lower().startswith(NETBT.lower()):
            return "netbios_disable"
        for aid, a in sa._ACTION_DEFS.items():
            if a["kind"] == "registry" and a["key"].lower() == path.lower() \
                    and name in {v["name"] for v in a["values"]}:
                return aid
        return None
    if kind == "exe":
        return "remote_registry_disable" if "RemoteRegistry" in detail else None
    if "Checkpoint-Computer" in detail:
        return "restore_point"
    if "Set-MpPreference" in detail:
        return "defender_enable"
    if "Set-NetFirewallProfile" in detail:
        return "firewall_enable"
    if "Set-SmbServerConfiguration" in detail:
        return "smb1_disable"
    if "LocalUser" in detail:
        if ADMIN_SID in detail:
            return "admin_disable"
        if GUEST_SID in detail:
            return "guest_disable"
        return None
    if "RemoteRegistry" in detail:
        return "remote_registry_disable"
    return None


@pytest.fixture
def fake(guard, monkeypatch, tmp_path):
    fs = FakeSystem(tmp_path / "backups")
    os.makedirs(fs.backup_dir)
    monkeypatch.setattr(subprocess, "run", fs.run)
    for name in ("OpenKey", "CreateKeyEx", "QueryValueEx", "SetValueEx", "DeleteValue", "EnumKey"):
        monkeypatch.setattr(winreg, name, getattr(fs, name))
    monkeypatch.setattr(sa, "ctypes", fs.ctypes)
    monkeypatch.setattr(sa, "get_backup_dir", lambda: fs.backup_dir)
    monkeypatch.setenv("SESSIONNAME", "Console")
    yield fs
    assert not fs.unknown, f"Unexpected commands reached the fake system: {fs.unknown}"


def backup_files(fs):
    return sorted(glob.glob(os.path.join(fs.backup_dir, "hardening_backup_*.json")))


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_backup(fs, name, entries, mtime=None, **extra):
    path = os.path.join(fs.backup_dir, name)
    data = {"version": 1, "created": "2026-01-01T00:00:00", "profile": "Strict", "entries": entries}
    data.update(extra)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    if mtime is not None:
        os.utime(path, (mtime, mtime))
    return path


# ============================================================================
# GUARD SELF-TEST
# ============================================================================

def test_guard_blocks_and_records_real_system_calls(guard, monkeypatch):
    """Proves the guard is active: real runners / winreg writes / ctypes raise and are recorded."""
    with pytest.raises(RuntimeError, match="SAFETY GUARD"):
        sa._run_exe([sa.SC_EXE, "query"])
    with pytest.raises(RuntimeError, match="SAFETY GUARD"):
        sa._run_ps("Get-Date")
    with pytest.raises(RuntimeError, match="SAFETY GUARD"):
        subprocess.Popen(["cmd.exe"])
    with pytest.raises(RuntimeError, match="SAFETY GUARD"):
        sa._reg_write(HKCU, r"Software\DDCleanerSelfTest", "x", REG_DWORD, 1)
    with pytest.raises(RuntimeError, match="SAFETY GUARD"):
        winreg.DeleteValue(HKCU, "x")
    monkeypatch.setenv("SESSIONNAME", "Console")
    assert sa._is_remote_session() is False  # ctypes blocked, exception swallowed by the module...
    assert guard.violations == [                # ...but still recorded, so the test would fail
        "subprocess.run", "subprocess.run", "subprocess.Popen",
        "winreg.CreateKeyEx", "winreg.DeleteValue", "ctypes.windll",
    ]
    guard.violations.clear()


# ============================================================================
# LOW-LEVEL HELPERS
# ============================================================================

def test_run_exe_passes_safe_arguments(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return types.SimpleNamespace(returncode=3, stdout=b"\xef\xbb\xbfhello \xff", stderr=b"err")

    monkeypatch.setattr(subprocess, "run", fake_run)
    rc, out, err = sa._run_exe([sa.SC_EXE, "query"], timeout=7)
    assert (rc, err) == (3, "err")
    assert out.startswith("hello ") and "\ufeff" not in out  # BOM stripped, bad byte replaced
    args, kwargs = calls[0]
    assert kwargs["timeout"] == 7
    assert kwargs["shell"] is False
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["capture_output"] is True
    assert kwargs["cwd"] == sa.SYSTEM32


@pytest.mark.parametrize("exc, expected_err", [
    (subprocess.TimeoutExpired("x", 5), "timeout"),
    (FileNotFoundError(2, "missing exe"), "missing exe"),
])
def test_run_exe_timeout_and_launch_errors(monkeypatch, exc, expected_err):
    def fake_run(args, **kwargs):
        raise exc
    monkeypatch.setattr(subprocess, "run", fake_run)
    rc, out, err = sa._run_exe([sa.SC_EXE, "query"])
    assert rc == -1 and out == ""
    assert expected_err in err


def test_run_ps_uses_encoded_command_and_absolute_powershell(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return types.SimpleNamespace(returncode=0, stdout=b'{"a": 1}', stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    rc, data = sa._run_ps_json("Write-Output 'héllo'", timeout=11)
    assert (rc, data) == (0, {"a": 1})
    args, kwargs = calls[0]
    assert args[0] == sa.POWERSHELL_EXE and os.path.isabs(args[0])
    for flag in ("-NoProfile", "-NonInteractive", "-EncodedCommand"):
        assert flag in args
    assert "-Command" not in args
    script = base64.b64decode(args[args.index("-EncodedCommand") + 1]).decode("utf-16-le")
    assert script.endswith("Write-Output 'héllo'")
    assert "OutputEncoding" in script
    assert kwargs["timeout"] == 11


@pytest.mark.parametrize("text, expected", [
    ('{"a": 1}', {"a": 1}),
    ("WARNING: noise\r\n[1, 2]", [1, 2]),
    ("junk {\"k\": true}", {"k": True}),
    ("", None),
    ("not json", None),
    (None, None),
])
def test_parse_json_tolerates_noise(text, expected):
    assert sa._parse_json(text) == expected


def test_ps_quote_escapes_single_quotes():
    assert sa._ps_quote("O'Brien") == "'O''Brien'"


def test_reg_state_encoding_roundtrip_through_json():
    state = json.loads(json.dumps(sa._encode_reg_state(True, b"\x00\xffA", winreg.REG_BINARY)))
    assert state == {"exists": True, "type": winreg.REG_BINARY, "data": {"hex": "00ff41"}}
    assert sa._decode_reg_data(state["data"]) == b"\x00\xffA"
    assert sa._encode_reg_state(False, None, 0) == {"exists": False}


def test_get_backup_dir_uses_the_protected_data_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(sa, "data_dir", lambda: str(tmp_path))
    result = sa.get_backup_dir()
    assert result == os.path.join(str(tmp_path), "hardening_backups")
    assert os.path.isabs(result) and os.path.isdir(result)


def test_get_backup_dir_does_not_raise_when_dir_cannot_be_created(monkeypatch, tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file")
    monkeypatch.setattr(sa, "data_dir", lambda: str(blocker))
    result = sa.get_backup_dir()
    assert result == os.path.join(str(blocker), "hardening_backups")
    assert not os.path.isdir(result)


# ============================================================================
# ENUMS
# ============================================================================

def test_enum_values_are_english():
    assert [r.value for r in RiskLevel] == ["Low", "Medium", "High", "Critical"]
    assert [d.value for d in SecurityDomain] == ["System", "Accounts", "Network", "Data"]
    assert [p.value for p in HardeningProfile] == ["Basic", "Recommended", "Strict"]


@pytest.mark.parametrize("cls, value, member", [
    (RiskLevel, "Faible", RiskLevel.LOW),
    (RiskLevel, "Moyen", RiskLevel.MEDIUM),
    (RiskLevel, "Élevé", RiskLevel.HIGH),
    (RiskLevel, "Critique", RiskLevel.CRITICAL),
    (SecurityDomain, "Système", SecurityDomain.SYSTEM),
    (SecurityDomain, "Comptes", SecurityDomain.ACCOUNTS),
    (SecurityDomain, "Réseau", SecurityDomain.NETWORK),
    (SecurityDomain, "Données", SecurityDomain.DATA),
    (HardeningProfile, "Basique", HardeningProfile.BASIC),
    (HardeningProfile, "Recommandé", HardeningProfile.RECOMMENDED),
    (HardeningProfile, "Strict", HardeningProfile.STRICT),
    (RiskLevel, "Critical", RiskLevel.CRITICAL),
])
def test_legacy_french_enum_values_resolve(cls, value, member):
    assert cls(value) is member


@pytest.mark.parametrize("cls, value", [
    (RiskLevel, "Extrême"),
    (RiskLevel, "Basique"),          # legacy value of another enum
    (SecurityDomain, "Critique"),
    (HardeningProfile, "Paranoid"),
    (HardeningProfile, 3),
    (HardeningProfile, None),
])
def test_unknown_enum_values_raise(cls, value):
    with pytest.raises(ValueError):
        cls(value)


# ============================================================================
# PROFILES
# ============================================================================

@pytest.mark.parametrize("profile, expected", [
    (HardeningProfile.BASIC, BASIC),
    (HardeningProfile.RECOMMENDED, RECOMMENDED),
    (HardeningProfile.STRICT, STRICT),
    (HardeningProfile("Recommandé"), RECOMMENDED),
])
def test_profile_contents(profile, expected):
    ids = [a["id"] for a in HardeningEngine()._get_profile_actions(profile)]
    assert ids == expected
    assert len(ids) == {"Basic": 4, "Recommended": 8, "Strict": 13}[profile.value]


@pytest.mark.parametrize("profile", [HardeningProfile.BASIC, HardeningProfile.RECOMMENDED])
def test_rdp_and_ntlm_level5_are_strict_only(profile):
    ids = {a["id"] for a in HardeningEngine()._get_profile_actions(profile)}
    assert "rdp_disable" not in ids and "ntlmv2_enforce" not in ids
    assert sa._ACTION_DEFS["ntlmv2_enforce"]["values"] == [
        {"name": "LmCompatibilityLevel", "type": REG_DWORD, "data": 5}]


def test_profile_actions_are_copies():
    actions = HardeningEngine()._get_profile_actions(HardeningProfile.STRICT)
    actions[0]["kind"] = "tampered"
    assert sa._ACTION_DEFS["defender_enable"]["kind"] == "defender"


def test_recommended_apply_never_touches_rdp_or_lm_level(fake):
    eng = HardeningEngine()
    s, f, _errs = eng.apply_profile(HardeningProfile.RECOMMENDED, create_restore_point=False)
    assert (s, f) == (8, 0)
    names = {o[3] for o in fake.writes()}
    assert names == {"AutoAdminLogon", "RestrictAnonymousSAM", "UseLogonCredential"}
    assert fake.smb1_enabled is False
    assert fake.reg_get(HKLM, NETBT + chr(92) + IFACE_A, "NetbiosOptions") == (0, REG_DWORD)  # NetBIOS: Strict only
    assert fake.reg_get(HKLM, TS, "fDenyTSConnections") == (0, REG_DWORD)
    assert fake.reg_get(HKLM, LSA, "LmCompatibilityLevel") is None


# ============================================================================
# APPLY: BACKUP FIRST, RESTORE POINT
# ============================================================================

def test_apply_writes_backup_before_any_change(fake):
    eng = HardeningEngine()
    s, f, errs = eng.apply_profile(HardeningProfile.STRICT, create_restore_point=False)
    assert (s, f) == (13, 0)
    assert errs == ["Warning: Restore point not requested."]

    muts = fake.hardening_mutations()
    assert {action_of(m) for m in muts} == set(STRICT)
    assert len(muts) == len(fake.mutations)  # nothing else was changed
    backup_key = os.path.normcase(eng.last_backup_path)
    for m in muts:
        # the backup file already existed with every "before" snapshot...
        assert list(m["backups"]) == [backup_key], m
        data = m["backups"][backup_key]
        assert [e["id"] for e in data["entries"]] == STRICT
        assert all(isinstance(e["before"], dict) for e in data["entries"])
        # ...and the entry being changed was already marked as attempted (crash-safe revert)
        entry = next(e for e in data["entries"] if e["id"] == action_of(m))
        assert entry["status"] == "failed"

    final = load(eng.last_backup_path)
    assert final["profile"] == "Strict"
    assert [e["status"] for e in final["entries"]] == ["applied"] * 13
    before = {e["id"]: e["before"] for e in final["entries"]}
    assert before["autologon_disable"] == {"values": {"AutoAdminLogon": {"exists": True, "type": REG_SZ, "data": "1"}}}
    assert before["uac_max"]["values"]["PromptOnSecureDesktop"] == {"exists": False}
    assert before["admin_disable"] == {"sid": ADMIN_SID, "enabled": True}
    assert before["remote_registry_disable"] == {"exists": True, "start": 3, "delayed": None, "running": True}
    assert len(eng.applied_actions) == 13


@pytest.mark.parametrize("how", ["missing_dir", "dir_is_blocked_by_file"])
def test_apply_aborts_without_changes_when_backup_cannot_be_written(fake, monkeypatch, tmp_path, how):
    if how == "missing_dir":
        monkeypatch.setattr(sa, "get_backup_dir", lambda: str(tmp_path / "does" / "not" / "exist"))
    else:
        # real get_backup_dir(): its base directory is a file, so makedirs fails
        monkeypatch.setattr(sa, "get_backup_dir", ORIGINAL_GET_BACKUP_DIR)
        blocker = tmp_path / "blocker"
        blocker.write_text("file")
        monkeypatch.setattr(sa, "data_dir", lambda: str(blocker))
    reg_before = dict(fake.reg)
    eng = HardeningEngine()
    s, f, errs = eng.apply_profile(HardeningProfile.STRICT, create_restore_point=False)
    assert s == 0 and f == 13
    assert errs[-1].startswith("Aborted") and "no changes applied" in errs[-1]
    assert fake.mutations == [] and fake.reg_ops == []
    assert all(not any(k in (s or "") for k in ("Set-", "Disable-", "Enable-", "Stop-", "Start-"))
               for s in fake.ps_scripts())
    assert not any(os.path.basename(r["args"][0]).lower() == "sc.exe" for r in fake.runs)
    assert fake.reg == reg_before
    assert eng.last_backup_path is None and eng.applied_actions == []


def test_apply_aborts_on_backup_failure_even_after_restore_point(fake, monkeypatch, tmp_path):
    monkeypatch.setattr(sa, "get_backup_dir", lambda: str(tmp_path / "missing"))
    eng = HardeningEngine()
    s, f, errs = eng.apply_profile(HardeningProfile.BASIC)
    assert (s, f) == (0, 4) and errs[-1].startswith("Aborted")
    assert fake.hardening_mutations() == []
    assert fake.writes() == []


def test_apply_with_default_args_touches_nothing_when_backup_unwritable(fake, monkeypatch, tmp_path):
    # Regression: the restore point (which writes SystemRestorePointCreationFrequency) used to run
    # before the backup check. The JSON backup is now written first.
    monkeypatch.setattr(sa, "get_backup_dir", lambda: str(tmp_path / "missing"))
    s, f, errs = HardeningEngine().apply_profile(HardeningProfile.BASIC)
    assert (s, f) == (0, 4) and errs[-1].startswith("Aborted")
    assert fake.reg_ops == [] and fake.mutations == []


def test_apply_stops_when_backup_becomes_unwritable_mid_run(fake, monkeypatch):
    eng = HardeningEngine()
    real_save = eng._save_backup
    calls = {"n": 0}

    def flaky_save(path, backup):
        calls["n"] += 1
        return real_save(path, backup) if calls["n"] <= 2 else False  # restore-point update + 1st marker OK

    monkeypatch.setattr(eng, "_save_backup", flaky_save)
    s, f, errs = eng.apply_profile(HardeningProfile.BASIC, create_restore_point=False)
    assert s <= 1 and s + f == 4
    assert any(e.startswith("Aborted: backup") for e in errs)
    # every change that happened was recorded as attempted in the backup first
    assert len(fake.hardening_mutations()) <= 1


def test_apply_default_signature_restore_point_failure_is_only_a_warning(fake):
    fake.restore_point = (1, {"Created": False, "Before": 4, "After": 4, "Warning": "",
                              "Error": "System Protection is disabled"})
    eng = HardeningEngine()
    result = eng.apply_profile(HardeningProfile.BASIC)
    assert isinstance(result, tuple) and len(result) == 3
    s, f, errs = result
    assert (s, f) == (4, 0)
    assert len(errs) == 1 and errs[0].startswith("Warning:")
    assert "System Protection is disabled" in errs[0]
    assert eng.last_restore_point_ok is False
    assert os.path.isfile(eng.last_backup_path)
    assert load(eng.last_backup_path)["restore_point"]["ok"] is False
    # 24 h throttle lifted during Checkpoint-Computer, then restored (it was absent -> deleted)
    assert fake.freq_during_checkpoint == (0, REG_DWORD)
    assert fake.reg_get(HKLM, SR_KEY, "SystemRestorePointCreationFrequency") is None
    # the JSON backup exists before anything is written, including the restore-point throttle value
    assert all(m["backups"] for m in fake.mutations)
    assert all(m["backups"] for m in fake.hardening_mutations())


def test_apply_restore_point_success_restores_previous_throttle(fake):
    fake.reg_set(HKLM, SR_KEY, "SystemRestorePointCreationFrequency", 1440, REG_DWORD)
    eng = HardeningEngine()
    s, f, errs = eng.apply_profile(HardeningProfile.BASIC)
    assert (s, f, errs) == (4, 0, [])
    assert eng.last_restore_point_ok is True
    assert fake.freq_during_checkpoint == (0, REG_DWORD)
    assert fake.reg_get(HKLM, SR_KEY, "SystemRestorePointCreationFrequency") == (1440, REG_DWORD)


@pytest.mark.parametrize("rp, expected_text", [
    ((1, {"Created": False, "Before": 4, "After": 4,
          "Warning": "A new restore point cannot be created within 1440 minutes", "Error": ""}), "24 h"),
    ((1, {"Created": False, "Before": 0, "After": 0, "Warning": "", "Error": "Access denied"}), "Access denied"),
    (("timeout", None), "Timed out"),
])
def test_require_restore_point_aborts(fake, rp, expected_text):
    if rp[0] == "timeout":
        fake.ps_overrides.append(("Checkpoint-Computer", "timeout", ""))
    else:
        fake.restore_point = rp
    eng = HardeningEngine()
    s, f, errs = eng.apply_profile(HardeningProfile.RECOMMENDED, require_restore_point=True)
    assert (s, f) == (0, 1)
    assert len(errs) == 1 and errs[0].startswith("Aborted") and expected_text in errs[0]
    assert backup_files(fake) == []
    assert fake.hardening_mutations() == [] and fake.writes() == []
    assert fake.reg_get(HKLM, SR_KEY, "SystemRestorePointCreationFrequency") is None


def test_require_restore_point_without_creating_one_aborts(fake):
    eng = HardeningEngine()
    s, f, errs = eng.apply_profile(HardeningProfile.BASIC, create_restore_point=False,
                                   require_restore_point=True)
    assert (s, f) == (0, 1) and errs[0].startswith("Aborted")
    assert fake.runs == [] and fake.reg_ops == []


def test_defender_tamper_protection_is_reported_as_failure(fake):
    fake.defender_after_set = True  # Set-MpPreference silently ignored
    eng = HardeningEngine()
    s, f, errs = eng.apply_profile(HardeningProfile.BASIC, create_restore_point=False)
    assert (s, f) == (3, 1)
    assert "Failed: Enable Defender" in errs


def test_snapshot_failure_skips_only_that_action(fake):
    fake.ps_overrides.append(("PersistentStore", 1, ""))
    eng = HardeningEngine()
    s, f, errs = eng.apply_profile(HardeningProfile.BASIC, create_restore_point=False)
    assert (s, f) == (3, 1)
    assert any("could not read initial state" in e and "firewall" in e for e in errs)
    assert not any("Set-NetFirewallProfile" in (sc or "") for sc in fake.ps_scripts())


# ============================================================================
# UAC MAX
# ============================================================================

def test_uac_max_sets_always_notify_2_not_5(fake):
    eng = HardeningEngine()
    s, f, _ = eng.apply_profile(HardeningProfile.STRICT, custom_actions=["uac_max"],
                                create_restore_point=False)
    assert (s, f) == (1, 0)
    assert fake.reg_get(HKLM, UAC, "ConsentPromptBehaviorAdmin") == (2, REG_DWORD)
    assert fake.reg_get(HKLM, UAC, "PromptOnSecureDesktop") == (1, REG_DWORD)
    writes = [(o[3], o[5]) for o in fake.writes()]
    assert writes == [("ConsentPromptBehaviorAdmin", 2), ("PromptOnSecureDesktop", 1)]
    # every hardening registry write goes to the 64-bit view
    assert all(o[6] & winreg.KEY_WOW64_64KEY for o in fake.reg_ops)


# ============================================================================
# RDP / REMOTE SESSION
# ============================================================================

@pytest.mark.parametrize("session, metric", [("RDP-Tcp#3", 0), ("rdp-tcp#0", 0), ("Console", 1)])
def test_rdp_disable_skipped_in_remote_session(fake, monkeypatch, session, metric):
    monkeypatch.setenv("SESSIONNAME", session)
    fake.remote_metric = metric
    eng = HardeningEngine()
    s, f, errs = eng.apply_profile(HardeningProfile.STRICT, create_restore_point=False)
    assert (s, f) == (12, 0)
    assert fake.reg_get(HKLM, TS, "fDenyTSConnections") == (0, REG_DWORD)
    assert not any(o[3] == "fDenyTSConnections" for o in fake.reg_ops)
    assert any(x.startswith("Disable RDP") and "Remote Desktop session" in x for x in eng.last_skipped)
    assert any(e.startswith("Skipped: Disable RDP") for e in errs)
    entry = next(e for e in load(eng.last_backup_path)["entries"] if e["id"] == "rdp_disable")
    assert entry["status"] == "skipped"
    if metric:
        assert 0x1000 in fake.metrics_calls


def test_rdp_disable_applied_in_console_session(fake):
    eng = HardeningEngine()
    s, f, _ = eng.apply_profile(HardeningProfile.STRICT, custom_actions=["rdp_disable"],
                                create_restore_point=False)
    assert (s, f) == (1, 0)
    assert fake.reg_get(HKLM, TS, "fDenyTSConnections") == (1, REG_DWORD)
    assert fake.metrics_calls == [0x1000]


def test_is_remote_session_detection(fake, monkeypatch):
    monkeypatch.setenv("SESSIONNAME", "Console")
    assert sa._is_remote_session() is False
    fake.remote_metric = 1
    assert sa._is_remote_session() is True
    fake.remote_metric = 0
    monkeypatch.setenv("SESSIONNAME", "RDP-Tcp#12")
    assert sa._is_remote_session() is True


# ============================================================================
# BUILT-IN ADMINISTRATOR SAFETY
# ============================================================================

def _safety(current=USER_SID, members=(ADMIN_SID, OTHER_ADMIN_SID),
            enabled=(ADMIN_SID, OTHER_ADMIN_SID, USER_SID), group_ok=True):
    return 0, json.dumps({"CurrentSid": current, "Members": members if isinstance(members, str) else list(members),
                          "EnabledLocal": enabled if isinstance(enabled, str) else list(enabled),
                          "GroupOk": group_ok})


@pytest.mark.parametrize("response, reason", [
    (_safety(current=ADMIN_SID), "currently in use"),
    (_safety(members=[ADMIN_SID, OTHER_ADMIN_SID], enabled=[ADMIN_SID, USER_SID]), "only enabled"),
    (_safety(members=ADMIN_SID, enabled=[ADMIN_SID, USER_SID]), "only enabled"),
    (_safety(members=[ADMIN_SID, "S-1-5-21-9-9-9-512"], enabled=[ADMIN_SID]), "only enabled"),
    (_safety(members=[], enabled=[]), "only enabled"),
    (_safety(group_ok=False), "could not list"),
    ((1, ""), "safety check failed"),
    ((0, "not json"), "safety check failed"),
    ((0, "[1, 2]"), "safety check failed"),
    (("timeout", ""), "safety check failed"),
])
def test_builtin_admin_safety_refuses(fake, response, reason):
    fake.safety = response
    result = HardeningEngine()._builtin_admin_safety(ADMIN_SID)
    assert result is not None and reason in result


@pytest.mark.parametrize("response", [
    _safety(),
    _safety(members=[ADMIN_SID, OTHER_ADMIN_SID], enabled=OTHER_ADMIN_SID),
])
def test_builtin_admin_safety_allows_when_another_enabled_admin_exists(fake, response):
    fake.safety = response
    assert HardeningEngine()._builtin_admin_safety(ADMIN_SID) is None


def _admin_disable_calls(fake):
    return [s for s in fake.ps_scripts() if "Disable-LocalUser" in s and ADMIN_SID in s]


@pytest.mark.parametrize("response", [
    _safety(current=ADMIN_SID),
    _safety(members=[ADMIN_SID], enabled=[ADMIN_SID, USER_SID]),
    (1, ""),
    ("timeout", ""),
    _safety(group_ok=False),
])
def test_apply_never_disables_builtin_admin_when_unsafe(fake, response):
    fake.safety = response
    eng = HardeningEngine()
    s, f, errs = eng.apply_profile(HardeningProfile.RECOMMENDED, create_restore_point=False)
    assert (s, f) == (7, 0)
    assert _admin_disable_calls(fake) == []
    assert fake.accounts[500]["Enabled"] is True
    assert any(x.startswith("Disable built-in Administrator") for x in eng.last_skipped)
    # the guest (Invité, -501) is still disabled by SID
    assert fake.accounts[501]["Enabled"] is False


def test_apply_disables_builtin_admin_by_sid_when_safe(fake):
    eng = HardeningEngine()
    s, f, _ = eng.apply_profile(HardeningProfile.RECOMMENDED, create_restore_point=False)
    assert (s, f) == (8, 0)
    assert _admin_disable_calls(fake) == [
        next(s for s in fake.ps_scripts() if "Disable-LocalUser" in s and ADMIN_SID in s)]
    assert fake.accounts[500]["Enabled"] is False and fake.accounts[501]["Enabled"] is False
    # accounts are located by SID suffix, never by (localized) name
    for script in fake.ps_scripts():
        for name in ("Administrator", "Administrateur", "Guest", "Invité"):
            assert f"'{name}'" not in script and f"-Name {name}" not in script
    assert all("-SID '" in s for s in fake.ps_scripts() if "Disable-LocalUser" in s)


def test_apply_skips_missing_or_already_disabled_accounts(fake):
    del fake.accounts[501]
    fake.accounts[500]["Enabled"] = False
    eng = HardeningEngine()
    s, f, _ = eng.apply_profile(HardeningProfile.RECOMMENDED, create_restore_point=False)
    assert (s, f) == (6, 0)
    skipped = " | ".join(eng.last_skipped)
    assert "account not found" in skipped and "already disabled" in skipped
    assert not any("GetCurrent()" in s for s in fake.ps_scripts())  # no safety query needed
    assert not any("Disable-LocalUser" in s for s in fake.ps_scripts())


# ============================================================================
# REVERT
# ============================================================================

def test_revert_backup_restores_exact_values_and_deletes_absent_ones(fake):
    initial_reg = dict(fake.reg)
    eng = HardeningEngine()
    s, f, _ = eng.apply_profile(HardeningProfile.STRICT, create_restore_point=False)
    assert (s, f) == (13, 0)
    assert fake.reg_get(HKLM, LSA, "LmCompatibilityLevel") == (5, REG_DWORD)
    path = eng.last_backup_path

    ops_before = len(fake.reg_ops)
    runs_before = len(fake.runs)
    fresh = HardeningEngine()
    assert fresh.revert_backup(path) == (13, 0)

    assert fake.reg == initial_reg  # exact values and types, absent values removed
    assert fake.reg_get(HKLM, WINLOGON, "AutoAdminLogon") == ("1", REG_SZ)
    deleted = {o[3] for o in fake.reg_ops[ops_before:] if o[0] == "delete"}
    assert deleted == {"LmCompatibilityLevel", "PromptOnSecureDesktop"}

    scripts = [r["script"] for r in fake.runs[runs_before:] if r["script"]]
    assert any(s.endswith(f"Enable-LocalUser -SID '{ADMIN_SID}' -ErrorAction Stop") for s in scripts)
    assert any(s.endswith(f"Enable-LocalUser -SID '{GUEST_SID}' -ErrorAction Stop") for s in scripts)
    assert any("Set-MpPreference -DisableRealtimeMonitoring $true" in s for s in scripts)
    assert any("Start-Service -Name 'RemoteRegistry'" in s for s in scripts)
    fw = next(s for s in scripts if "Set-NetFirewallProfile" in s)
    for prof, val in (("Domain", "True"), ("Private", "False"), ("Public", "NotConfigured")):
        assert f"-Profile {prof} -Enabled {val} " in fw
    sc_calls = [r["args"] for r in fake.runs[runs_before:] if r["script"] is None]
    assert sc_calls == [[sa.SC_EXE, "config", "RemoteRegistry", "start=", "demand"]]
    assert fake.accounts[500]["Enabled"] and fake.accounts[501]["Enabled"]
    assert fake.defender_disabled is True

    data = load(path)
    assert "reverted" in data
    assert [e["status"] for e in data["entries"]] == ["reverted"] * 13
    # a second revert has nothing left to do
    assert fresh.revert_backup(path) == (0, 0)


def test_revert_restores_delayed_auto_start(fake):
    fake.reg_set(HKLM, RR_SVC, "Start", 2, REG_DWORD)
    fake.reg_set(HKLM, RR_SVC, "DelayedAutostart", 1, REG_DWORD)
    fake.service_status = "Stopped"
    eng = HardeningEngine()
    eng.apply_profile(HardeningProfile.STRICT, custom_actions=["remote_registry_disable"],
                      create_restore_point=False)
    n = len(fake.runs)
    assert eng.revert_last() == (1, 0)
    new = fake.runs[n:]
    assert [r["args"][1:] for r in new] == [["config", "RemoteRegistry", "start=", "delayed-auto"]]


def test_revert_ignores_tampered_paths_and_values(fake):
    tampered = [
        {   # known id but the JSON points at the Run key and adds a foreign value
            "id": "autologon_disable", "kind": "registry", "hive": "HKCU", "key": RUN_KEY,
            "values": [{"name": "Evil", "type": REG_SZ, "data": "C:\\evil.exe"}],
            "status": "applied",
            "before": {"values": {
                "AutoAdminLogon": {"exists": True, "type": REG_SZ, "data": "1"},
                "Evil": {"exists": True, "type": REG_SZ, "data": "C:\\evil.exe"},
            }},
        },
        {   # unknown id with its own registry definition
            "id": "evil_run", "kind": "registry", "hive": "HKLM", "key": RUN_KEY,
            "values": [{"name": "Evil", "type": REG_SZ, "data": "C:\\evil.exe"}], "status": "applied",
            "before": {"values": {"Evil": {"exists": True, "type": REG_SZ, "data": "C:\\evil.exe"}}},
        },
        {   # admin revert pointed at another account's SID
            "id": "admin_disable", "status": "applied", "before": {"sid": USER_SID, "enabled": True},
        },
        {   # PowerShell injection through firewall profile fields
            "id": "firewall_enable", "status": "applied",
            "before": {"profiles": [{"name": "Public; Remove-Item C:\\x", "enabled": "True"},
                                    {"name": "Domain", "enabled": "False; calc.exe"}]},
        },
        {   # service redirected / start type injection
            "id": "remote_registry_disable", "service": "Evil", "status": "applied",
            "before": {"exists": True, "start": "auto & calc", "running": False},
        },
        {   # defender with non-bool
            "id": "defender_enable", "status": "applied",
            "before": {"disable_realtime_monitoring": "$true; calc"},
        },
    ]
    path = write_backup(fake, "hardening_backup_20260101_000000.json", tampered)
    ok, failed = HardeningEngine().revert_backup(path)
    assert (ok, failed) == (1, 5)
    writes = fake.writes()
    assert [(o[1], o[2], o[3]) for o in writes] == [(HKLM, WINLOGON, "AutoAdminLogon")]
    assert not any("\\run" in o[2].lower() for o in fake.reg_ops)
    assert not any(o[3] == "Evil" for o in fake.reg_ops)
    assert fake.runs == []  # no PowerShell / sc.exe at all


@pytest.mark.parametrize("content", [
    "",
    "not json {",
    "[]",
    '"string"',
    '{"version": 1}',
    '{"entries": "oops"}',
    '{"entries": {"id": "autologon_disable"}}',
])
def test_revert_rejects_malformed_backup_without_writes(fake, content):
    path = os.path.join(fake.backup_dir, "hardening_backup_bad.json")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    assert HardeningEngine().revert_backup(path) == (0, 1)
    assert fake.reg_ops == [] and fake.runs == []
    with open(path, "r", encoding="utf-8") as f:
        assert f.read() == content  # not rewritten


@pytest.mark.parametrize("entries", [
    [{"id": "something_else", "status": "applied", "before": {"values": {}}}],
    [{"id": "autologon_disable", "status": "applied", "before": "not a dict"}],
    [{"id": "autologon_disable", "status": "skipped", "before": {"values": {
        "AutoAdminLogon": {"exists": True, "type": REG_SZ, "data": "1"}}}}],
    [{"id": "autologon_disable", "before": {"values": {
        "AutoAdminLogon": {"exists": True, "type": REG_SZ, "data": "1"}}}}],
])
def test_revert_foreign_entries_cause_no_writes(fake, entries):
    path = write_backup(fake, "hardening_backup_foreign.json", entries, foreign=True)
    ok, _failed = HardeningEngine().revert_backup(path)
    assert ok == 0
    assert fake.reg_ops == [] and fake.runs == []


def test_revert_missing_file(fake):
    assert HardeningEngine().revert_backup(os.path.join(fake.backup_dir, "nope.json")) == (0, 1)
    assert fake.reg_ops == []


def _autologon_entry(data):
    return [{"id": "autologon_disable", "status": "applied",
             "before": {"values": {"AutoAdminLogon": {"exists": True, "type": REG_SZ, "data": data}}}}]


def test_list_backups_newest_first(fake):
    a = write_backup(fake, "hardening_backup_a.json", [], mtime=1_000_000)
    b = write_backup(fake, "hardening_backup_b.json", [], mtime=3_000_000)
    c = write_backup(fake, "hardening_backup_c.json", [], mtime=2_000_000)
    write_backup(fake, "other_file.json", [], mtime=4_000_000)
    assert HardeningEngine().list_backups() == [b, c, a]


def test_revert_last_uses_latest_backup(fake):
    older = write_backup(fake, "hardening_backup_20260101_000000.json", _autologon_entry("7"), mtime=1_000_000)
    newer = write_backup(fake, "hardening_backup_20260102_000000.json", _autologon_entry("1"), mtime=2_000_000)
    fake.reg_set(HKLM, WINLOGON, "AutoAdminLogon", "0", REG_SZ)
    assert HardeningEngine().revert_last() == (1, 0)
    assert fake.reg_get(HKLM, WINLOGON, "AutoAdminLogon") == ("1", REG_SZ)
    assert load(newer)["entries"][0]["status"] == "reverted"
    assert load(older)["entries"][0]["status"] == "applied"


def test_revert_last_without_backup(fake):
    assert HardeningEngine().revert_last() == (0, 0)
    assert fake.reg_ops == []


def test_revert_last_prefers_this_sessions_backup(fake):
    eng = HardeningEngine()
    eng.apply_profile(HardeningProfile.BASIC, custom_actions=["autologon_disable"], create_restore_point=False)
    write_backup(fake, "hardening_backup_29990101_000000.json", _autologon_entry("9"), mtime=4_000_000_000)
    assert eng.revert_last() == (1, 0)
    assert fake.reg_get(HKLM, WINLOGON, "AutoAdminLogon") == ("1", REG_SZ)


def test_revert_action_single(fake):
    eng = HardeningEngine()
    eng.apply_profile(HardeningProfile.RECOMMENDED, create_restore_point=False)
    assert fake.reg_get(HKLM, LSA, "RestrictAnonymousSAM") == (1, REG_DWORD)
    assert eng.revert_action("sam_restrict") is True
    assert fake.reg_get(HKLM, LSA, "RestrictAnonymousSAM") == (0, REG_DWORD)
    assert fake.reg_get(HKLM, WINLOGON, "AutoAdminLogon") == ("0", REG_SZ)  # others untouched
    assert eng.revert_action("sam_restrict") is False  # already reverted
    assert eng.revert_action("rdp_disable") is False   # never applied


# ============================================================================
# SECURITY AUDITOR (read-only, deterministic)
# ============================================================================

def _ids(scores):
    return {d: sorted(i.id for i in s.issues) for d, s in scores.items()}


def test_run_full_audit_is_deterministic_and_read_only(fake):
    auditor = SecurityAuditor()
    score, scores = auditor.run_full_audit()
    assert _ids(scores) == {
        SecurityDomain.SYSTEM: ["defender_disabled", "firewall_disabled", "lsass_unknown", "memory_integrity_off",
                                "update_unknown", "wdigest_enabled"],
        SecurityDomain.ACCOUNTS: ["admin_enabled", "autologon_enabled", "blank_passwords_allowed", "guest_enabled"],
        SecurityDomain.NETWORK: ["netbios_enabled", "rdp_exposed", "sam_anonymous", "smb1_enabled"],
        SecurityDomain.DATA: ["backup_disabled"],
    }
    assert {d: (s.current_score, s.max_score) for d, s in scores.items()} == {
        SecurityDomain.SYSTEM: (14, 34), SecurityDomain.ACCOUNTS: (3, 25),
        SecurityDomain.NETWORK: (15, 38), SecurityDomain.DATA: (15, 20),
    }
    assert score == 40
    admin = next(i for i in auditor.issues if i.id == "admin_enabled")
    assert "Administrateur" in admin.description
    assert fake.reg_ops == [] and fake.mutations == []


CURRENT_VERSION = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


@pytest.mark.parametrize("edition", ["Core", "CoreSingleLanguage", "CoreN", "CoreCountrySpecific"])
def test_bitlocker_is_not_counted_on_windows_home(fake, edition):
    """Windows Home has no BitLocker drive encryption: it must neither raise an alert nor cost points."""
    fake.reg_set(HKLM, CURRENT_VERSION, "EditionID", edition, REG_SZ)
    fake.audit_bitlocker = {"Status": "FullyDecrypted", "Protection": "Off"}     # what the Home cmdlet may report
    auditor = SecurityAuditor()
    _score, scores = auditor.run_full_audit()
    data = scores[SecurityDomain.DATA]
    assert "bitlocker_disabled" not in {i.id for i in auditor.issues}
    assert data.max_score == 10 and (data.current_score, data.max_score) == (5, 10)     # backup missing: -5


def test_a_home_pc_with_a_restore_point_and_backup_scores_full_marks_in_data(fake):
    fake.reg_set(HKLM, CURRENT_VERSION, "EditionID", "Core", REG_SZ)
    fake.reg_set(HKCU, r"Software\Microsoft\Windows\CurrentVersion\BackupRestore\FileHistory", "Enabled", 1, REG_DWORD)
    _score, scores = SecurityAuditor().run_full_audit()
    assert (scores[SecurityDomain.DATA].current_score, scores[SecurityDomain.DATA].max_score) == (10, 10)


@pytest.mark.parametrize("edition", ["Professional", "Enterprise", "Education", "ProfessionalWorkstation"])
def test_bitlocker_is_still_checked_on_editions_that_have_it(fake, edition):
    fake.reg_set(HKLM, CURRENT_VERSION, "EditionID", edition, REG_SZ)
    fake.audit_bitlocker = {"Status": "FullyDecrypted", "Protection": "Off"}
    auditor = SecurityAuditor()
    _score, scores = auditor.run_full_audit()
    assert "bitlocker_disabled" in {i.id for i in auditor.issues}
    assert (scores[SecurityDomain.DATA].current_score, scores[SecurityDomain.DATA].max_score) == (5, 20)


def test_bitlocker_is_not_counted_when_its_cmdlet_is_missing(fake):
    fake.ps_overrides.append(("Get-BitLockerVolume", 1, ""))
    auditor = SecurityAuditor()
    _score, scores = auditor.run_full_audit()
    assert "bitlocker_disabled" not in {i.id for i in auditor.issues} and scores[SecurityDomain.DATA].max_score == 10


def test_an_unreadable_edition_leaves_the_bitlocker_check_in_place(fake):
    fake.audit_bitlocker = {"Status": "FullyDecrypted", "Protection": "Off"}
    auditor = SecurityAuditor()
    auditor.run_full_audit()
    assert "bitlocker_disabled" in {i.id for i in auditor.issues}              # no EditionID in the fake registry


def test_builtin_accounts_found_by_sid_not_name(fake):
    fake.audit_builtin = [
        {"Name": "Administrator", "Sid": USER_SID, "Enabled": True},       # renamed normal user
        {"Name": "Administrateur", "Sid": ADMIN_SID, "Enabled": False},
        {"Name": "Invité", "Sid": GUEST_SID, "Enabled": True},
    ]
    auditor = SecurityAuditor()
    builtin = auditor._get_builtin_accounts()
    assert builtin["admin"]["Sid"] == ADMIN_SID and builtin["guest"]["Name"] == "Invité"
    assert auditor._check_builtin_admin(builtin) is None
    assert auditor._check_guest_account(builtin).id == "guest_enabled"


def test_audit_results_are_copies(fake):
    auditor = SecurityAuditor()
    _score, returned = auditor.run_full_audit()
    returned.clear()  # mutating the returned dict does not touch the auditor's state
    assert len(auditor.domain_scores) == 4

    _score, first = auditor.run_full_audit()
    first_issues = list(auditor.issues)
    first_ids = _ids(first)
    first_issue_list = auditor.issues
    first_critical = auditor.get_critical_issues()

    # system changes, second audit
    fake.reg_set(HKLM, WINLOGON, "AutoAdminLogon", "0", REG_SZ)
    fake.audit_firewall_off = []
    _score2, second = auditor.run_full_audit()

    assert "autologon_enabled" not in _ids(second)[SecurityDomain.ACCOUNTS]
    assert _ids(first) == first_ids  # previous result untouched
    assert "autologon_enabled" in [i.id for i in first_issue_list]
    assert "autologon_enabled" in [i.id for i in first_critical]
    assert second is not first and auditor.issues is not first_issue_list
    assert len(first_issues) == len(first_issue_list)


def test_get_critical_issues_sorted_new_list(fake):
    auditor = SecurityAuditor()
    auditor.run_full_audit()
    crit = auditor.get_critical_issues(limit=10)
    assert [i.id for i in crit] == [
        "autologon_enabled", "rdp_exposed", "sam_anonymous", "defender_disabled", "firewall_disabled",
        "wdigest_enabled", "blank_passwords_allowed", "smb1_enabled",
    ]
    ranks = [sa._RISK_RANK[i.risk] for i in crit]
    assert ranks == sorted(ranks, reverse=True)
    assert crit[-1].risk is RiskLevel.HIGH and crit[-1].score_impact <= crit[-2].score_impact  # HIGH: by impact
    assert crit is not auditor.issues
    n = len(auditor.issues)
    crit.clear()
    assert len(auditor.issues) == n
    top = auditor.get_critical_issues(limit=2)
    assert [i.id for i in top] == ["autologon_enabled", "rdp_exposed"]
    assert all(i.risk in (RiskLevel.CRITICAL, RiskLevel.HIGH) for i in auditor.get_critical_issues(99))


# ============================================================================
# SUBPROCESS HYGIENE
# ============================================================================

def test_every_subprocess_call_uses_absolute_systemroot_path_and_timeout(fake):
    eng = HardeningEngine()
    eng.apply_profile(HardeningProfile.STRICT)
    eng.revert_last()
    SecurityAuditor().run_full_audit()
    assert len(fake.runs) > 20

    windir = os.path.normcase(os.path.abspath(os.environ.get("SystemRoot", r"C:\Windows")))
    for call in fake.runs:
        exe = call["args"][0]
        assert os.path.isabs(exe), exe
        assert os.path.normcase(exe).startswith(windir + os.sep), exe
        assert os.path.basename(exe).lower() in ("powershell.exe", "sc.exe")
        timeout = call["kwargs"].get("timeout")
        assert isinstance(timeout, (int, float)) and 0 < timeout <= sa.RESTORE_POINT_TIMEOUT, call
        assert call["kwargs"].get("shell") is False
    checkpoint = [c for c in fake.runs if c["script"] and "Checkpoint-Computer" in c["script"]]
    assert checkpoint and all(c["kwargs"]["timeout"] == sa.RESTORE_POINT_TIMEOUT for c in checkpoint)


def test_module_source_has_single_subprocess_entry_point():
    with open(sa.__file__, "r", encoding="utf-8") as f:
        source = f.read()
    assert source.count("subprocess.run(") == 1
    for forbidden in ("subprocess.Popen", "subprocess.call(", "check_output", "os.system(",
                      "shell=True", "os.popen("):
        assert forbidden not in source


def test_revert_keeps_the_catalogue_value_type(fake):
    """Audit finding: a backup could restore a DWORD policy value as another type or an out-of-range number."""
    tampered = [
        {"id": "ntlmv2_enforce", "status": "applied",
         "before": {"values": {"LmCompatibilityLevel": {"exists": True, "type": REG_SZ, "data": "0"}}}},
        {"id": "ntlmv2_enforce", "status": "applied",
         "before": {"values": {"LmCompatibilityLevel": {"exists": True, "type": REG_DWORD, "data": 2 ** 40}}}},
        {"id": "ntlmv2_enforce", "status": "applied",
         "before": {"values": {"Other": {"exists": True, "type": REG_DWORD, "data": 1}}}},  # nothing restorable
    ]
    path = write_backup(fake, "hardening_backup_20260102_000000.json", tampered)
    ok, failed = HardeningEngine().revert_backup(path)
    assert ok == 0 and failed == 3
    assert fake.writes() == []
