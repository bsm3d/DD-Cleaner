"""
Elevation hardening: environment given to child processes, system paths from the API, protected data
folder, program folder permission check. Uses tmp_path only; nothing is created in ProgramData.
"""

import os
import subprocess
import sys

import pytest

from ddcleaner import common, folder_security
import security_audit as sa


def test_safe_environment_drops_user_controlled_variables():
    base = {"PSModulePath": r"C:\Users\x\Documents\WindowsPowerShell\Modules", "PATH": r"C:\Users\x\bin",
            "windir": r"C:\fake", "SystemRoot": r"C:\fake", "COR_PROFILER": "{evil}", "COMPLUS_Foo": "1",
            "PSExecutionPolicyPreference": "Bypass", "PYTHONPATH": r"C:\evil", "USERNAME": "bsm"}
    env = common.safe_environment(base)
    assert env["PSModulePath"] == os.path.join(common.SYSTEM32, "WindowsPowerShell", "v1.0", "Modules")
    assert env["SystemRoot"] == env["windir"] == common.SYSTEM_ROOT
    assert env["PATH"].split(";")[0] == common.SYSTEM32 and r"C:\Users" not in env["PATH"]
    assert not any(k in env for k in ("COR_PROFILER", "COMPLUS_Foo", "PSExecutionPolicyPreference", "PYTHONPATH"))
    assert env["USERNAME"] == "bsm"


def test_windows_folder_does_not_come_from_the_environment():
    out = subprocess.run([sys.executable, "-c", "from ddcleaner import common; import security_audit as s; "
                          "print(common.SYSTEM_ROOT); print(s.SYSTEM32)"],
                         capture_output=True, text=True, cwd=common.app_dir(),
                         env=dict(os.environ, SystemRoot=r"C:\fake", windir=r"C:\fake")).stdout.split()
    assert out[0].lower() != r"c:\fake" and os.path.isdir(out[0])
    assert out[1].lower().startswith(out[0].lower())


def test_powershell_ignores_a_module_planted_in_the_user_module_path(tmp_path, monkeypatch):
    """The attack found in the audit: a fake NetSecurity module first in PSModulePath."""
    mod = tmp_path / "NetSecurity"
    mod.mkdir()
    (mod / "NetSecurity.psm1").write_text('function Get-NetFirewallProfile { "HIJACKED" }\n'
                                          "Export-ModuleMember -Function Get-NetFirewallProfile\n")
    monkeypatch.setenv("PSModulePath", f"{tmp_path};{os.environ.get('PSModulePath', '')}")
    rc, out, err = sa._run_ps("(Get-Command Get-NetFirewallProfile).ModuleName")
    assert "HIJACKED" not in out and out.strip() == "NetSecurity"
    rc, out, err = sa._run_ps("(Get-Command Get-NetFirewallProfile).Module.ModuleBase")
    assert out.strip().lower().startswith(common.SYSTEM32.lower())


# region Data folder

@pytest.fixture
def frozen_programdata(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(common, "_common_app_data", lambda: str(tmp_path))
    monkeypatch.setattr(common, "_data_dir_cache", None)
    return tmp_path


def test_data_dir_refuses_a_folder_created_by_someone_else(frozen_programdata):
    (frozen_programdata / "DD Cleaner").mkdir()  # user-created: user owns it and can write
    with pytest.raises(common.UnsafeFolderError):
        common.data_dir()


def test_data_dir_refuses_a_junction(frozen_programdata, tmp_path_factory):
    target = tmp_path_factory.mktemp("elsewhere")
    link = frozen_programdata / "DD Cleaner"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=True)
    with pytest.raises(common.UnsafeFolderError, match="link"):
        common.data_dir()


def test_protected_folder_has_no_inherited_user_write(tmp_path, monkeypatch):
    user = folder_security.current_user_sid()
    # as a standard user the test cannot make Administrators the owner, so the SDDL keeps the default owner
    monkeypatch.setattr(common, "DATA_DIR_SDDL", f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x120089;;;{user})")
    path = str(tmp_path / "protected")
    common._create_protected_dir(path)
    writers = folder_security.unprivileged_writers(path)
    assert "Authenticated Users" not in writers and "Users" not in writers  # tmp_path would give both
    assert not any("owner" not in w and "your account" in w for w in writers)  # read-only for the user

# endregion


def test_program_folder_check_flags_user_writable_folders(tmp_path):
    assert folder_security.folder_risk(str(tmp_path))
    assert folder_security.unprivileged_writers(common.SYSTEM32) == []
