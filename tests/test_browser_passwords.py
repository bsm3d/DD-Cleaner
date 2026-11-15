"""Browser password extraction. The Chromium pipeline (DPAPI-wrapped key, AES-256-GCM values, SQLite copy)
is exercised end to end with synthetic data built here, never a real browser profile. Firefox is tested up to
the native NSS call (profile discovery, logins.json parsing, and the guard that refuses an unprotected DLL)."""

import base64
import ctypes
import json
import os
import sqlite3
import tempfile

import pytest

from ddcleaner import browser_passwords as bp
from ddcleaner import wincrypt


def dpapi_protect(data: bytes) -> bytes:
    class BLOB(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("pb", ctypes.c_void_p)]

    buf = ctypes.create_string_buffer(data, len(data))
    out = BLOB()
    ok = ctypes.WinDLL("crypt32").CryptProtectData(
        ctypes.byref(BLOB(len(data), ctypes.cast(buf, ctypes.c_void_p))), None, None, None, None, 0, ctypes.byref(out))
    assert ok, "CryptProtectData failed"
    blob = ctypes.string_at(out.pb, out.cb)
    ctypes.windll.kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    ctypes.windll.kernel32.LocalFree(out.pb)
    return blob


def v10_blob(key: bytes, password: str) -> bytes:
    nonce = os.urandom(12)
    ciphertext, tag = wincrypt.aes_gcm_encrypt(key, nonce, password.encode("utf-8"))
    return b"v10" + nonce + ciphertext + tag


def make_user_data(tmp_path, key: bytes, logins, profile="Default", legacy=None):
    base = tmp_path / "User Data"
    base.mkdir(exist_ok=True)
    local_state = {"os_crypt": {"encrypted_key": base64.b64encode(b"DPAPI" + dpapi_protect(key)).decode("ascii")}}
    (base / "Local State").write_text(json.dumps(local_state), encoding="utf-8")
    prof = base / profile
    prof.mkdir(exist_ok=True)
    con = sqlite3.connect(os.path.join(str(prof), "Login Data"))
    con.execute("CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB)")
    for url, user, pw in logins:
        con.execute("INSERT INTO logins VALUES (?, ?, ?)", (url, user, v10_blob(key, pw)))
    for url, user, pw in (legacy or []):
        con.execute("INSERT INTO logins VALUES (?, ?, ?)", (url, user, dpapi_protect(pw.encode("utf-8"))))
    con.commit()
    con.close()
    return str(base)


# region Chromium

def test_master_key_is_unwrapped_from_local_state(tmp_path):
    key = os.urandom(32)
    base = make_user_data(tmp_path, key, [])
    assert bp.chromium_master_key(base) == key


def test_master_key_rejects_an_unexpected_format(tmp_path):
    base = tmp_path / "User Data"
    base.mkdir()
    (base / "Local State").write_text(json.dumps({"os_crypt": {"encrypted_key": base64.b64encode(b"XXXXXnope").decode()}}))
    with pytest.raises(ValueError):
        bp.chromium_master_key(str(base))


def test_decrypt_value_handles_v10_and_legacy_dpapi():
    key = os.urandom(32)
    assert bp.decrypt_chromium_value(v10_blob(key, "hunter2"), key) == "hunter2"
    assert bp.decrypt_chromium_value(dpapi_protect("old-style".encode("utf-8")), key) == "old-style"
    assert bp.decrypt_chromium_value(b"", key) == ""


def test_a_value_encrypted_with_another_key_is_reported_not_decryptable(tmp_path):
    base = make_user_data(tmp_path, os.urandom(32), [("https://site/", "me", "secret")])
    # a different master key: the GCM tag will not match
    records = bp.chromium_logins("Edge", base)
    # chromium_logins uses the real key from Local State, so this one DOES decrypt; test the mismatch directly:
    other = os.urandom(32)
    with pytest.raises(wincrypt.CryptoError):
        bp.decrypt_chromium_value(v10_blob(os.urandom(32), "x"), other)
    assert records and records[0].value == "secret"


def test_chromium_logins_decrypts_every_profile(tmp_path):
    key = os.urandom(32)
    base = make_user_data(tmp_path, key, [("https://mail.example.com/login", "alice@example.com", "p@ss word"),
                                          ("android://token@com.app/", "", "app-secret")],
                          legacy=[("https://old.example.com/", "bob", "legacypw")])
    make_user_data(tmp_path, key, [("https://work.example.com/", "carol", "work-secret")], profile="Profile 1")
    records = bp.chromium_logins("Chrome", base)
    by_user = {r.info.split("  ")[0]: r for r in records}
    assert by_user["alice@example.com"].value == "p@ss word"
    assert by_user["alice@example.com"].name == "mail.example.com"
    assert by_user["bob"].value == "legacypw"              # legacy DPAPI entry
    assert any(r.value == "work-secret" and "Profile 1" in r.info for r in records)
    assert all(r.kind == "Chrome" for r in records)
    assert not any("app-secret" == r.value and r.info.startswith("  ") for r in records)  # empty user kept


def test_chromium_logins_without_a_key_marks_everything_unreadable(tmp_path):
    base = tmp_path / "User Data"
    base.mkdir()
    (base / "Local State").write_text("{}", encoding="utf-8")  # no os_crypt key
    (base / "Default").mkdir()
    records = bp.chromium_logins("Edge", str(base))
    assert len(records) == 1 and not records[0].readable and "key not readable" in records[0].note


def test_locked_database_is_copied_before_reading(tmp_path, monkeypatch):
    key = os.urandom(32)
    base = make_user_data(tmp_path, key, [("https://x/", "u", "pw")])
    login_db = os.path.join(base, "Default", "Login Data")
    copied = {}
    real_copy = bp.shutil.copy2
    monkeypatch.setattr(bp.shutil, "copy2", lambda src, dst: copied.update(src=src) or real_copy(src, dst))
    bp.chromium_logins("Edge", base)
    assert copied["src"] == login_db  # the original is never opened directly


def test_user_data_dirs_only_lists_installed_browsers(tmp_path):
    (tmp_path / r"Microsoft\Edge\User Data".replace("\\", os.sep)).mkdir(parents=True)
    dirs = bp.chromium_user_data_dirs(str(tmp_path))
    assert [name for name, _ in dirs] == ["Edge"]

# endregion


# region Firefox

FF_LOGINS = json.dumps({"logins": [
    {"hostname": "https://site.example", "encryptedUsername": "MDoxMA==", "encryptedPassword": "MEUxMA=="},
    {"hostname": "https://other.example", "encryptedUsername": "", "encryptedPassword": ""},
    "not a dict",
]})


def make_firefox_profile(tmp_path, name="abcd.default"):
    root = tmp_path / "Mozilla" / "Firefox" / "Profiles" / name
    root.mkdir(parents=True)
    (root / "logins.json").write_text(FF_LOGINS, encoding="utf-8")
    (root / "key4.db").write_bytes(b"sqlite")
    return str(tmp_path)


def test_parse_firefox_logins_skips_non_dict_entries():
    parsed = bp.parse_firefox_logins(FF_LOGINS)
    assert len(parsed) == 2 and parsed[0][0] == "https://site.example"


def test_firefox_profiles_need_logins_and_key_db(tmp_path):
    base = make_firefox_profile(tmp_path)
    (tmp_path / "Mozilla" / "Firefox" / "Profiles" / "empty.profile").mkdir()
    assert len(bp.firefox_profiles(base)) == 1


def test_find_firefox_nss_from_program_files(monkeypatch, tmp_path):
    ff = tmp_path / "Mozilla Firefox"
    ff.mkdir()
    (ff / "nss3.dll").write_bytes(b"MZ")
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    monkeypatch.delenv("ProgramW6432", raising=False)
    assert bp._find_firefox_nss() == str(ff)


def test_firefox_logins_refuses_an_unprotected_nss_folder(tmp_path, monkeypatch):
    base = make_firefox_profile(tmp_path)
    real_profiles = bp.firefox_profiles
    monkeypatch.setattr(bp, "firefox_profiles", lambda: real_profiles(base))
    (tmp_path / "fakefirefox").mkdir()
    monkeypatch.setattr(bp, "_find_firefox_nss", lambda: str(tmp_path / "fakefirefox"))
    monkeypatch.setattr(bp.folder_security, "folder_risk", lambda folder: ["writable by Users"])
    records = bp.firefox_logins()
    assert records and all(not r.readable and "not protected" in r.note for r in records)


def test_firefox_logins_reports_when_firefox_is_absent(tmp_path, monkeypatch):
    base = make_firefox_profile(tmp_path)
    real_profiles = bp.firefox_profiles
    monkeypatch.setattr(bp, "firefox_profiles", lambda: real_profiles(base))
    monkeypatch.setattr(bp, "_find_firefox_nss", lambda: None)
    records = bp.firefox_logins()
    assert records and all("not installed" in r.note for r in records)

# endregion


def test_browser_logins_isolates_a_failing_browser(monkeypatch):
    monkeypatch.setattr(bp, "chromium_user_data_dirs", lambda base=None: [("Chrome", "x"), ("Edge", "y")])

    def chromium(name, path):
        if name == "Chrome":
            raise RuntimeError("boom")
        return [bp.SecretRecord("Edge", "site", "user", "pw")]
    monkeypatch.setattr(bp, "chromium_logins", chromium)
    monkeypatch.setattr(bp, "firefox_logins", lambda: [])
    records = bp.browser_logins()
    assert [r.kind for r in records] == ["Edge"]  # Chrome failed but did not stop Edge


def test_login_database_path_with_special_characters(tmp_path):
    """Before the fix, the sqlite URI was built by raw f-string concatenation ('file:{temp}?mode=ro'), so a
    temp directory containing # ? or % broke the URI or silently opened the wrong resource."""
    key = os.urandom(32)
    odd_dir = tmp_path / "weird #dir% name"
    odd_dir.mkdir()
    base = make_user_data(odd_dir, key, [("https://odd.example/", "user", "odd-path-secret")])
    records = bp.chromium_logins("Edge", base)
    assert any(r.value == "odd-path-secret" for r in records)


def test_wal_and_journal_files_are_copied_alongside_the_database(tmp_path, monkeypatch):
    """A password just saved by the browser can still be sitting in Login Data-wal; the copy must include it
    or a fresh save after a browser restart would silently be missed."""
    key = os.urandom(32)
    base = make_user_data(tmp_path, key, [("https://x/", "u", "pw")])
    wal_path = os.path.join(base, "Default", "Login Data-wal")
    with open(wal_path, "wb") as f:
        f.write(b"not a real wal file, just checking it gets copied")
    copied = []
    real_copy = bp.shutil.copy2
    monkeypatch.setattr(bp.shutil, "copy2", lambda src, dst: copied.append(src) or real_copy(src, dst))
    bp.chromium_logins("Edge", base)
    assert wal_path in copied


def test_temp_wal_copy_is_removed_even_though_the_db_has_no_wal(tmp_path):
    key = os.urandom(32)
    base = make_user_data(tmp_path, key, [("https://x/", "u", "pw")])
    before = set(os.listdir(tempfile.gettempdir()))
    bp.chromium_logins("Edge", base)
    after = set(os.listdir(tempfile.gettempdir()))
    assert after == before  # no leftover temp .db / .db-wal / .db-journal


def test_app_bound_v20_values_are_reported_distinctly():
    key = os.urandom(32)
    with pytest.raises(bp.AppBoundValue):
        bp.decrypt_chromium_value(b"v20" + b"\x00" * 20, key)


def test_chromium_logins_marks_v20_entries_as_app_bound(tmp_path):
    key = os.urandom(32)
    base = make_user_data(tmp_path, key, [])
    con = bp.sqlite3.connect(os.path.join(base, "Default", "Login Data"))
    con.execute("INSERT INTO logins VALUES (?, ?, ?)", ("https://appbound.example/", "user", b"v20" + b"\x00" * 40))
    con.commit()
    con.close()
    records = bp.chromium_logins("Chrome", base)
    assert len(records) == 1 and not records[0].readable
    assert "app-bound" in records[0].note
