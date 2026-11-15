"""AES-256-GCM (CNG) and DPAPI wrappers. AES is checked against a published NIST/McGrew test vector and
by round-tripping; DPAPI is round-tripped against the real Windows API for the current user."""

import os

import pytest

from ddcleaner import wincrypt

u = bytes.fromhex


# McGrew & Viega GCM spec, Test Case 14 (256-bit key): everything zero but a non-empty block.
TC14_KEY = b"\x00" * 32
TC14_IV = b"\x00" * 12
TC14_PT = b"\x00" * 16
TC14_CT = u("cea7403d4d606b6e074ec5d3baf39d18")
TC14_TAG = u("d0d1c8a799996bf0265b98b5d48ab919")


def test_decrypt_matches_the_nist_test_vector():
    assert wincrypt.aes_gcm_decrypt(TC14_KEY, TC14_IV, TC14_CT, TC14_TAG) == TC14_PT


def test_encrypt_matches_the_nist_test_vector():
    ct, tag = wincrypt.aes_gcm_encrypt(TC14_KEY, TC14_IV, TC14_PT)
    assert ct == TC14_CT and tag == TC14_TAG


def test_round_trip_with_a_real_key_and_message():
    key, nonce = os.urandom(32), os.urandom(12)
    message = "mot de passe wifi éàü 🔐".encode("utf-8")
    ct, tag = wincrypt.aes_gcm_encrypt(key, nonce, message)
    assert ct != message
    assert wincrypt.aes_gcm_decrypt(key, nonce, ct, tag) == message


def test_a_tampered_tag_is_rejected():
    ct, tag = wincrypt.aes_gcm_encrypt(TC14_KEY, TC14_IV, b"secret payload!!")
    bad = bytearray(tag)
    bad[0] ^= 1
    with pytest.raises(wincrypt.CryptoError):
        wincrypt.aes_gcm_decrypt(TC14_KEY, TC14_IV, ct, bytes(bad))


def test_wrong_key_is_rejected():
    ct, tag = wincrypt.aes_gcm_encrypt(TC14_KEY, TC14_IV, b"another payload!")
    with pytest.raises(wincrypt.CryptoError):
        wincrypt.aes_gcm_decrypt(b"\x11" * 32, TC14_IV, ct, tag)


def test_dpapi_round_trip_for_the_current_user():
    secret = "firmware key ABCDE-12345".encode("utf-8")
    import ctypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("pb", ctypes.c_void_p)]

    buf = ctypes.create_string_buffer(secret, len(secret))
    out = BLOB()
    crypt32 = ctypes.WinDLL("crypt32")
    ok = crypt32.CryptProtectData(ctypes.byref(BLOB(len(secret), ctypes.cast(buf, ctypes.c_void_p))),
                                  None, None, None, None, 0, ctypes.byref(out))
    assert ok, "could not create a DPAPI blob to test against"
    blob = ctypes.string_at(out.pb, out.cb)
    ctypes.windll.kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    ctypes.windll.kernel32.LocalFree(out.pb)
    assert wincrypt.dpapi_unprotect(blob) == secret


def test_dpapi_rejects_garbage():
    with pytest.raises(wincrypt.CryptoError):
        wincrypt.dpapi_unprotect(b"not a real dpapi blob")


def test_gcm_key_open_failure_does_not_leak_the_algorithm_handle():
    """A key of an unsupported length makes BCryptGenerateSymmetricKey fail inside __enter__; __exit__ would
    normally not run in that case (Python only calls __exit__ after a successful __enter__), so _GcmKey must
    release what it opened itself before re-raising."""
    bad_key = b"\x01" * 5  # not 16, 24 or 32 bytes
    with pytest.raises(wincrypt.CryptoError):
        with wincrypt._GcmKey(bad_key):
            pass
    # if the algorithm handle had leaked, repeating this many times would exhaust a finite resource;
    # a few hundred clean failures is a cheap proxy for "nothing is leaking"
    for _ in range(300):
        with pytest.raises(wincrypt.CryptoError):
            with wincrypt._GcmKey(bad_key):
                pass


def test_gcm_key_handles_are_usable_after_a_failed_open():
    """The provider handle table is process-global: a leak from the bad-key case above would still show up
    here, as a failure to open a perfectly normal key right after."""
    bad_key = b"\x01" * 5
    try:
        with wincrypt._GcmKey(bad_key):
            pass
    except wincrypt.CryptoError:
        pass
    good_key = b"\x02" * 32
    with wincrypt._GcmKey(good_key) as gcm:
        assert gcm.h_key and gcm.h_alg
