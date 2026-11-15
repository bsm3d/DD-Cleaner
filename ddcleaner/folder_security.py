"""
Is a folder writable by a process that is NOT elevated?

The program runs as administrator. If its own folder (exe, DLLs, downloaded databases, backups) can be
changed by a standard process of the same user, any malware running without elevation could plant a DLL
or tamper with the data and get its code run as administrator. This reads the folder's owner and DACL
(Win32 security API, no external tool) and reports who can write.
"""

import ctypes
import os
from ctypes import wintypes
from typing import List, Optional

SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x1
DACL_SECURITY_INFORMATION = 0x4
ACCESS_ALLOWED_ACE_TYPE = 0
INHERIT_ONLY_ACE = 0x08
TOKEN_QUERY = 0x0008
TOKEN_USER = 1

# Rights that let someone add or replace files in a folder, or take it over
WRITE_RIGHTS = (0x2 | 0x4 | 0x40 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000)
# FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE

UNPRIVILEGED_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-545": "Users",
    "S-1-5-4": "Interactive users",
    "S-1-5-32-546": "Guests",
}


class ACE_HEADER(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", wintypes.WORD)]


class ACCESS_ALLOWED_ACE(ctypes.Structure):
    _fields_ = [("Header", ACE_HEADER), ("Mask", wintypes.DWORD), ("SidStart", wintypes.DWORD)]


class ACL_SIZE_INFORMATION(ctypes.Structure):
    _fields_ = [("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD), ("AclBytesFree", wintypes.DWORD)]


def _api():
    adv, k32 = ctypes.windll.advapi32, ctypes.windll.kernel32
    adv.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
                                          ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                          ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                          ctypes.POINTER(ctypes.c_void_p)]
    adv.GetNamedSecurityInfoW.restype = wintypes.DWORD
    adv.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int]
    adv.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    return adv, k32


def _sid_string(adv, k32, psid) -> str:
    out = wintypes.LPWSTR()
    if not adv.ConvertSidToStringSidW(psid, ctypes.byref(out)):
        return ""
    try:
        return out.value
    finally:
        k32.LocalFree(out)


def current_user_sid() -> str:
    adv, k32 = _api()
    token = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        return ""
    try:
        size = wintypes.DWORD()
        adv.GetTokenInformation(token, TOKEN_USER, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token, TOKEN_USER, buf, size, ctypes.byref(size)):
            return ""
        psid = ctypes.c_void_p.from_buffer(buf).value  # TOKEN_USER starts with SID_AND_ATTRIBUTES.Sid
        return _sid_string(adv, k32, psid)
    finally:
        k32.CloseHandle(token)


def unprivileged_writers(path: str, user_sid: Optional[str] = None) -> List[str]:
    """Who, without administrator rights, can add or replace files in this folder ([] = protected)."""
    adv, k32 = _api()
    user_sid = user_sid if user_sid is not None else current_user_sid()
    risky = dict(UNPRIVILEGED_SIDS)
    if user_sid:
        risky[user_sid] = "your account (also when not elevated)"
    owner, dacl, sd = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    err = adv.GetNamedSecurityInfoW(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                                    ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(sd))
    if err != 0:
        raise OSError(err, f"cannot read the permissions of {path}")
    writers = []
    try:
        owner_sid = _sid_string(adv, k32, owner)
        if owner_sid in risky:
            writers.append(f"{risky[owner_sid]} (owner: can change the permissions)")
        if not dacl.value:
            return ["Everyone (the folder has no access control list)"]
        info = ACL_SIZE_INFORMATION()
        adv.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2)  # AclSizeInformation
        for i in range(info.AceCount):
            pace = ctypes.c_void_p()
            if not adv.GetAce(dacl, i, ctypes.byref(pace)):
                continue
            ace = ctypes.cast(pace, ctypes.POINTER(ACCESS_ALLOWED_ACE)).contents
            if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE or ace.Header.AceFlags & INHERIT_ONLY_ACE:
                continue
            if not ace.Mask & WRITE_RIGHTS:
                continue
            sid = _sid_string(adv, k32, pace.value + ACCESS_ALLOWED_ACE.SidStart.offset)
            if sid in risky and risky[sid] not in " ".join(writers):
                writers.append(risky[sid])
    finally:
        k32.LocalFree(sd)
    return writers


def folder_risk(folder: str) -> List[str]:
    """Human-readable problems for the program folder (empty when only administrators can change it)."""
    problems = []
    try:
        writers = unprivileged_writers(folder)
    except OSError as e:
        return [f"Permissions of {folder} could not be checked ({e})."]
    if writers:
        problems.append(f"{folder} can be modified without administrator rights by: {', '.join(writers)}.")
    return problems
