"""Shared low-level helpers: winreg import, Windows system paths, absolute system binaries,
environment given to child processes, protected data folder."""

import sys
import os
import ctypes
import subprocess
import types
from typing import Any, Dict, Optional


try:
    import winreg
except ImportError:
    def _winreg_missing(*args, **kwargs):
        raise ImportError("winreg module is not available on this platform")

    _winreg_stub: Any = types.ModuleType('winreg')
    _winreg_stub.HKEY_LOCAL_MACHINE = object()
    _winreg_stub.HKEY_CURRENT_USER = object()
    _winreg_stub.HKEY_CLASSES_ROOT = object()
    _winreg_stub.HKEY_USERS = object()
    _winreg_stub.OpenKey = _winreg_missing
    _winreg_stub.CreateKey = _winreg_missing
    _winreg_stub.QueryInfoKey = _winreg_missing
    _winreg_stub.EnumKey = _winreg_missing
    _winreg_stub.EnumValue = _winreg_missing
    _winreg_stub.QueryValueEx = _winreg_missing
    _winreg_stub.DeleteKey = _winreg_missing
    _winreg_stub.SetValueEx = _winreg_missing
    _winreg_stub.REG_SZ = 1
    winreg = _winreg_stub


def _windows_dir() -> str:
    """Windows folder from the API, never from %SystemRoot% / %windir%: the environment of an elevated
    process can come from the user's HKCU\\Environment (known UAC bypass: fake windir)."""
    try:
        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buf, 260):
            return buf.value
    except (AttributeError, OSError):
        pass
    return r"C:\Windows"


SYSTEM_ROOT = _windows_dir()
SYSTEM32 = os.path.join(SYSTEM_ROOT, "System32")
SUBPROCESS_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def sys_exe(name: str) -> str:
    """Absolute path of a Windows system binary (prevents binary planting next to the exe)."""
    if name.lower() == "powershell.exe":
        return os.path.join(SYSTEM32, "WindowsPowerShell", "v1.0", "powershell.exe")
    if name.lower() in ("explorer.exe", "regedit.exe"):
        return os.path.join(SYSTEM_ROOT, name)
    return os.path.join(SYSTEM32, name)


def app_dir() -> str:
    """Folder of the exe (frozen) or the project root (running from source)."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # ddcleaner/.. = project root


# ============================================================
# ENVIRONMENT OF CHILD PROCESSES
# ============================================================

# Variables a non-elevated user can set (HKCU\Environment) that change what an elevated child runs or loads
UNSAFE_VARIABLES = ("PSModulePath", "PSExecutionPolicyPreference", "PSModuleAutoloadingPreference",
                    "__PSLockdownPolicy", "COMPLUS_", "COR_", "DOTNET_", "PYTHON")


def safe_environment(base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Environment for elevated children (PowerShell, sc, reg, DISM...).

    PowerShell loads modules from the first folder of PSModulePath, and by default that is the user's
    Documents\\WindowsPowerShell\\Modules: any program running as the user could drop a fake NetSecurity or
    Defender module there and have it run as administrator by our PowerShell calls. Children only get the
    Windows module folder, system PATH and API-derived Windows paths."""
    env = {k: v for k, v in (base if base is not None else os.environ).items()
           if not k.upper().startswith(tuple(p.upper() for p in UNSAFE_VARIABLES))}
    env["SystemRoot"] = SYSTEM_ROOT
    env["windir"] = SYSTEM_ROOT
    env["ComSpec"] = os.path.join(SYSTEM32, "cmd.exe")
    env["PATH"] = ";".join([SYSTEM32, SYSTEM_ROOT, os.path.join(SYSTEM32, "Wbem"),
                            os.path.join(SYSTEM32, "WindowsPowerShell", "v1.0")])
    env["PSModulePath"] = os.path.join(SYSTEM32, "WindowsPowerShell", "v1.0", "Modules")
    return env


def harden_process_environment():
    """At startup: every child inherits the safe environment, whichever code starts it."""
    clean = safe_environment()
    for key in list(os.environ):
        if key not in clean:
            del os.environ[key]
    os.environ.update(clean)


# ============================================================
# PROTECTED DATA FOLDER
# ============================================================

class UnsafeFolderError(OSError):
    pass


# Protected DACL: SYSTEM and Administrators only, no inheritance from ProgramData (where Users may write)
DATA_DIR_SDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"


def _common_app_data() -> str:
    """C:\\ProgramData from the API (not from the environment)."""
    buf = ctypes.create_unicode_buffer(260)
    if ctypes.windll.shell32.SHGetFolderPathW(None, 0x23, None, 0, buf) != 0:  # CSIDL_COMMON_APPDATA
        raise OSError("ProgramData folder not found")
    return buf.value


def _is_reparse_point(path: str) -> bool:
    try:
        return bool(os.lstat(path).st_file_attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT
    except (OSError, AttributeError):
        return False


def _create_protected_dir(path: str):
    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", ctypes.c_ulong), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", ctypes.c_int)]

    adv, k32 = ctypes.windll.advapi32, ctypes.windll.kernel32
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    k32.CreateDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p]
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    sd = ctypes.c_void_p()
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(DATA_DIR_SDDL, 1, ctypes.byref(sd), None):
        raise ctypes.WinError()
    try:
        attrs = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), sd, 0)
        if not k32.CreateDirectoryW(path, ctypes.byref(attrs)):
            raise ctypes.WinError()
    finally:
        k32.LocalFree(sd)


_data_dir_cache: Optional[str] = None


def data_dir() -> str:
    """Where downloaded lists, backups and logs live.

    Frozen build (runs as administrator): C:\\ProgramData\\DD Cleaner, created with an administrators-only
    DACL and refused if someone else created it first or turned it into a junction. Running from source:
    the project folder (developer machine)."""
    global _data_dir_cache
    if not getattr(sys, "frozen", False):
        return app_dir()
    if _data_dir_cache:
        return _data_dir_cache
    from ddcleaner import folder_security
    path = os.path.join(_common_app_data(), "DD Cleaner")
    if not os.path.lexists(path):
        _create_protected_dir(path)
    if _is_reparse_point(path) or not os.path.isdir(path):
        raise UnsafeFolderError(f"{path} is a link or not a folder: delete it and restart the program.")
    writers = folder_security.unprivileged_writers(path)
    if writers:
        raise UnsafeFolderError(f"{path} can be modified by {', '.join(writers)}. It was not created by this "
                                "program: delete it and restart the program.")
    _data_dir_cache = path
    return path


# ============================================================
# SYSTEM DLLS
# ============================================================

_dll_cache: Dict[str, Any] = {}


def system_dll(name: str):
    """Load a Windows DLL from System32 by full path. Loading by bare name searches the program folder
    first for DLLs that are not KnownDLLs (iphlpapi, version...): a planted copy would run as administrator."""
    if name not in _dll_cache:
        _dll_cache[name] = ctypes.WinDLL(os.path.join(SYSTEM32, f"{name}.dll"))
    return _dll_cache[name]
