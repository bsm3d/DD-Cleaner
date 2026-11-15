"""Windows cryptographic primitives through ctypes: DPAPI unprotect and AES-256-GCM.

Used to read secrets the user's own Windows or browsers stored for them (Chromium login databases, saved
credentials). No external dependency: DPAPI (crypt32) and AES-GCM (CNG / bcrypt) come from the Windows
libraries, loaded from System32 by full path like everything else in this program.
"""

import ctypes
from ctypes import wintypes
from typing import Tuple

from ddcleaner.common import system_dll

STATUS_AUTH_TAG_MISMATCH = 0xC000A002


class CryptoError(Exception):
    pass


# region DPAPI (crypt32)

class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.c_void_p)]


def _blob(data: bytes) -> _DATA_BLOB:
    buffer = ctypes.create_string_buffer(data, len(data))  # keep a reference alive via the returned tuple
    return _DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.c_void_p)), buffer


def dpapi_unprotect(data: bytes, entropy: bytes = b"") -> bytes:
    """Decrypt a DPAPI blob for the current user (CryptUnprotectData). Raises CryptoError on failure."""
    crypt32 = system_dll("crypt32")
    crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.POINTER(_DATA_BLOB),
                                           ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DATA_BLOB)]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    in_blob, _k1 = _blob(data)
    out_blob = _DATA_BLOB()
    ent_blob = ent_keep = None
    if entropy:
        ent_blob, ent_keep = _blob(entropy)
    ok = crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, ctypes.byref(ent_blob) if ent_blob else None,
                                    None, None, 0, ctypes.byref(out_blob))
    if not ok:
        raise CryptoError("CryptUnprotectData failed (data not encrypted for this user).")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree.argtypes = [ctypes.c_void_p]  # 64-bit pointer, not a Python int
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)

# endregion


# region AES-256-GCM (CNG / bcrypt)

class _BCRYPT_AUTH_INFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.ULONG), ("dwInfoVersion", wintypes.ULONG),
                ("pbNonce", ctypes.c_void_p), ("cbNonce", wintypes.ULONG),
                ("pbAuthData", ctypes.c_void_p), ("cbAuthData", wintypes.ULONG),
                ("pbTag", ctypes.c_void_p), ("cbTag", wintypes.ULONG),
                ("pbMacContext", ctypes.c_void_p), ("cbMacContext", wintypes.ULONG),
                ("cbAAD", wintypes.ULONG), ("cbData", ctypes.c_ulonglong), ("dwFlags", wintypes.ULONG)]

BCRYPT_AUTH_MODE_INFO_VERSION = 1


def _check(status: int, name: str):
    if status != 0:
        if status & 0xFFFFFFFF == STATUS_AUTH_TAG_MISMATCH:
            raise CryptoError("AES-GCM authentication failed (wrong key or tampered data).")
        raise CryptoError(f"{name} failed: 0x{status & 0xFFFFFFFF:08X}")


def _buf(data: bytes):
    data = data or b"\x00"  # a zero-length ctypes array is not allowed
    return (ctypes.c_char * len(data)).from_buffer_copy(data)


class _GcmKey:
    """An open CNG AES-GCM key. Used as a context manager so the handles are always released."""

    def __init__(self, key: bytes):
        self.bcrypt = system_dll("bcrypt")
        self.h_alg = ctypes.c_void_p()
        self.h_key = ctypes.c_void_p()
        self._key = key

    def __enter__(self):
        b = self.bcrypt
        try:
            _check(b.BCryptOpenAlgorithmProvider(ctypes.byref(self.h_alg), "AES", None, 0),
                   "BCryptOpenAlgorithmProvider")
            mode = "ChainingModeGCM\x00".encode("utf-16-le")
            _check(b.BCryptSetProperty(self.h_alg, "ChainingMode", mode, len(mode), 0), "BCryptSetProperty")
            key_buf = _buf(self._key)
            _check(b.BCryptGenerateSymmetricKey(self.h_alg, ctypes.byref(self.h_key), None, 0, key_buf,
                                                len(self._key), 0), "BCryptGenerateSymmetricKey")
        except Exception:
            self.__exit__(None, None, None)  # __exit__ is not called when __enter__ raises: release the handles here
            raise
        return self

    def __exit__(self, *exc):
        if self.h_key:
            self.bcrypt.BCryptDestroyKey(self.h_key)
        if self.h_alg:
            self.bcrypt.BCryptCloseAlgorithmProvider(self.h_alg, 0)
        return False


def _auth_info(nonce_buf, tag_buf, aad_buf, aad_len):
    info = _BCRYPT_AUTH_INFO()
    info.cbSize = ctypes.sizeof(info)
    info.dwInfoVersion = BCRYPT_AUTH_MODE_INFO_VERSION
    info.pbNonce = ctypes.cast(nonce_buf, ctypes.c_void_p)
    info.cbNonce = ctypes.sizeof(nonce_buf)
    info.pbTag = ctypes.cast(tag_buf, ctypes.c_void_p)
    info.cbTag = ctypes.sizeof(tag_buf)
    if aad_len:
        info.pbAuthData = ctypes.cast(aad_buf, ctypes.c_void_p)
        info.cbAuthData = aad_len
    return info


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """Decrypt AES-GCM (256-bit key). Raises CryptoError if the tag does not match."""
    with _GcmKey(key) as gcm:
        nonce_buf, tag_buf, aad_buf = _buf(nonce), _buf(tag), _buf(aad)
        info = _auth_info(nonce_buf, tag_buf, aad_buf, len(aad))
        out = ctypes.create_string_buffer(len(ciphertext) or 1)
        written = wintypes.ULONG(0)
        ct_buf = _buf(ciphertext)
        _check(gcm.bcrypt.BCryptDecrypt(gcm.h_key, ct_buf, len(ciphertext), ctypes.byref(info),
                                        None, 0, out, len(ciphertext), ctypes.byref(written), 0), "BCryptDecrypt")
        return out.raw[:written.value]


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """Encrypt AES-GCM (256-bit key) -> (ciphertext, 16-byte tag). Here so round-trips can be tested."""
    with _GcmKey(key) as gcm:
        nonce_buf, tag_buf, aad_buf = _buf(nonce), ctypes.create_string_buffer(16), _buf(aad)
        info = _auth_info(nonce_buf, tag_buf, aad_buf, len(aad))
        out = ctypes.create_string_buffer(len(plaintext) or 1)
        written = wintypes.ULONG(0)
        pt_buf = _buf(plaintext)
        _check(gcm.bcrypt.BCryptEncrypt(gcm.h_key, pt_buf, len(plaintext), ctypes.byref(info),
                                        None, 0, out, len(plaintext), ctypes.byref(written), 0), "BCryptEncrypt")
        return out.raw[:written.value], tag_buf.raw[:16]

# endregion
