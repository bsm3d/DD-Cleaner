"""Software license keys (registry walk), Windows Credential Manager decoding, and collect_secrets.
The registry is the in-memory FakeReg from test_system_pages; the credential vault is injected."""

from ddcleaner import saved_keys
from ddcleaner.saved_keys import SecretRecord

from test_system_pages import FakeReg  # noqa: F401

BS = chr(92)


# region License keys

def test_license_walk_finds_keys_and_skips_junk():
    # merge a few vendor roots into one HKLM/64 tree
    reg = FakeReg({("HKLM", "64"): {
        "SOFTWARE": {
            "Microsoft": {"Office": {"16.0": {"ProductID": "12345-ABCDE", "Noise": "x"},
                                     "Common": {"SerialNumber": "AA-BB-CC-DD"}}},
            "Adobe": {"Photoshop": {"LicenseKey": "PS-0001-0002"}},
            "Autodesk": {"Maya": {"ProductKey": "657M1", "Extra": "nope"}},
        }
    }})
    records = saved_keys.software_license_keys(reg)
    found = {(r.name, r.value) for r in records}
    assert ("Office", "12345-ABCDE") in found
    assert ("Office", "AA-BB-CC-DD") in found
    assert ("Adobe", "PS-0001-0002") in found
    assert ("Autodesk", "657M1") in found
    assert all(r.kind == "License" for r in records)


def test_license_shape_rejects_spaces_and_short_values():
    assert saved_keys._looks_like_key("ABCDE-12345-FGHIJ")
    assert not saved_keys._looks_like_key("with space inside")
    assert not saved_keys._looks_like_key("abc")             # too short
    assert not saved_keys._looks_like_key("")
    assert not saved_keys._looks_like_key(12345)             # not a string


def test_license_walk_is_bounded(monkeypatch):
    # a pathological deep tree must stop at LICENSE_MAX_DEPTH, not recurse forever
    deep = {}
    node = deep
    for i in range(50):
        node["Sub"] = {"SerialNumber": f"KEY{i:05d}"}
        node = node["Sub"]
    reg = FakeReg({("HKLM", "64"): {"SOFTWARE": {"Adobe": deep}}})
    records = saved_keys.software_license_keys(reg)
    assert 0 < len(records) <= saved_keys.LICENSE_MAX_DEPTH + 1

# endregion


# region Credential Manager

def cred(target, user, blob, ctype=saved_keys.CRED_TYPE_GENERIC):
    return {"target": target, "user": user, "type": ctype, "blob": blob}


def test_generic_credential_blob_is_decoded_as_text():
    entries = saved_keys.credential_manager_entries(lambda: [
        cred("git:https://github.com", "bsm", "ghp_secrettoken".encode("utf-16-le")),
        cred("MyApp", "user", "motdepasse".encode("utf-8")),
    ])
    assert entries[0].value == "ghp_secrettoken" and entries[0].name == "git:https://github.com"
    assert entries[1].value == "motdepasse"
    assert all(e.kind == "Windows credential" for e in entries)


def test_domain_password_is_never_returned_in_clear():
    secret, readable, note = saved_keys._decode_cred_blob(b"\x01\x02\x03", saved_keys.CRED_TYPE_DOMAIN_PASSWORD)
    assert secret == "" and not readable and "domain password" in note


def test_binary_and_empty_blobs():
    assert saved_keys._decode_cred_blob(b"", saved_keys.CRED_TYPE_GENERIC) == ("", True, "(no secret stored)")
    secret, readable, _ = saved_keys._decode_cred_blob(b"\x00\x01\x80\xff", saved_keys.CRED_TYPE_GENERIC)
    assert secret == "" and not readable

# endregion


# region collect_secrets

def test_collect_secrets_merges_sources_and_survives_a_failure(monkeypatch):
    monkeypatch.setattr(saved_keys, "wifi_profiles",
                        lambda: [saved_keys.WifiProfile("Home", "WPA2", "AES", "wifipw")])
    monkeypatch.setattr(saved_keys, "windows_firmware_key", lambda: "ABCDE-12345-FGHIJ-67890-KLMNO")

    def boom():
        raise RuntimeError("registry exploded")
    monkeypatch.setattr(saved_keys, "software_license_keys", boom)          # this source fails
    monkeypatch.setattr(saved_keys, "credential_manager_entries",
                        lambda: [SecretRecord("Windows credential", "app", "user", "cmpw")])
    import ddcleaner.browser_passwords as bp
    monkeypatch.setattr(bp, "browser_logins", lambda: [SecretRecord("Edge", "site", "u", "browserpw")])

    records = saved_keys.collect_secrets()
    kinds = [r.kind for r in records]
    assert kinds == ["Wi-Fi", "Windows key", "Windows credential", "Edge"]  # licenses failed, others kept
    assert {r.value for r in records} == {"wifipw", "ABCDE-12345-FGHIJ-67890-KLMNO", "cmpw", "browserpw"}


def test_collect_secrets_respects_the_flags(monkeypatch):
    monkeypatch.setattr(saved_keys, "wifi_profiles", lambda: [saved_keys.WifiProfile("Home", "WPA2", "AES", "x")])
    monkeypatch.setattr(saved_keys, "windows_firmware_key", lambda: None)
    monkeypatch.setattr(saved_keys, "software_license_keys", lambda: [SecretRecord("License", "Office", "16", "k")])
    records = saved_keys.collect_secrets(wifi=True, windows_key=False, licenses=False,
                                         credentials=False, browsers=False)
    assert [r.kind for r in records] == ["Wi-Fi"]

# endregion


def test_license_budget_is_per_vendor_root_not_shared(monkeypatch):
    """Before the fix, one shared counter meant a large tree under one vendor root (here: a wide Office
    installation) could exhaust the whole budget and silently hide every Adobe/Autodesk/VMware key."""
    monkeypatch.setattr(saved_keys, "LICENSE_MAX_KEYS", 50)  # small budget to make the scenario cheap to build
    wide_office = {}
    for i in range(200):  # far more than the budget, all under Office alone
        wide_office[f"App{i}"] = {"ProductID": f"OFFICE-{i:05d}-KEY"}
    reg = FakeReg({("HKLM", "64"): {
        "SOFTWARE": {
            "Microsoft": {"Office": wide_office},
            "Adobe": {"Photoshop": {"LicenseKey": "PS-0001-0002"}},
            "Autodesk": {"Maya": {"ProductKey": "657M1-EXTRA"}},
        }
    }})
    records = saved_keys.software_license_keys(reg)
    names = {r.name for r in records}
    assert "Adobe" in names and "Autodesk" in names  # not starved by the wide Office tree
    assert any(r.name == "Office" for r in records)  # Office itself still contributes up to its own budget
