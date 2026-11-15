"""SystemUtils: platform/admin checks and registry path normalisation."""

import os
import platform
import ctypes


class SystemUtils:
    """System-related utility functions."""

    HIVE_ALIASES = {
        "HKLM": "HKEY_LOCAL_MACHINE", "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
        "HKCU": "HKEY_CURRENT_USER", "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
        "HKCR": "HKEY_CLASSES_ROOT", "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
        "HKU": "HKEY_USERS", "HKEY_USERS": "HKEY_USERS",
    }

    @staticmethod
    def is_windows() -> bool:
        return platform.system() == "Windows"

    @staticmethod
    def normalize_registry_path(path: str) -> str:
        """Expand hive aliases and strip redundant separators: 'hklm\\Software\\' -> 'HKEY_LOCAL_MACHINE\\Software'."""
        if not path or not isinstance(path, str):
            return ""
        p = path.strip().strip('\\')
        while '\\\\' in p:
            p = p.replace('\\\\', '\\')
        hive, _, rest = p.partition('\\')
        hive = SystemUtils.HIVE_ALIASES.get(hive.upper(), hive.upper())
        return f"{hive}\\{rest}" if rest else hive

    @staticmethod
    def check_admin_privileges() -> bool:
        if not SystemUtils.is_windows():
            ge = getattr(os, 'geteuid', None)
            if callable(ge):
                try:
                    return ge() == 0
                except Exception:
                    return False
            return False
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
