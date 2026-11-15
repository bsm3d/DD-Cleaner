"""Preferences window and the API key store. The network is replaced by a fake; keys live in pytest's temporary
folder, never in the real data folder."""

import json
import os
import urllib.request

import pytest
from PySide6.QtWidgets import QDialog, QGroupBox, QLineEdit, QMenu, QMessageBox, QPushButton

from ddcleaner import api_keys

from test_ui_smoke import dialogs, window  # noqa: F401  (fixtures)

VT_KEY = "b" * 64
DEMO = api_keys.Provider("demo", "Demo", "A second service, only for tests.", "https://example.com/key", r"[a-z]{8}",
                         "8 lowercase letters")


class FakeHttp:
    def __init__(self, status=200, body=b"{}"):
        self.status, self.body, self.requests = status, body, []

    def __call__(self, request: urllib.request.Request):
        self.requests.append(request)
        return self.status, self.body


@pytest.fixture
def two_services(monkeypatch):
    """The store is meant to hold several services: add a fake one next to VirusTotal."""
    monkeypatch.setattr(api_keys, "PROVIDERS", [api_keys.VIRUSTOTAL, DEMO])


# region The store

def test_the_registry_lists_the_services():
    assert [p.id for p in api_keys.PROVIDERS] == ["virustotal"]
    assert api_keys.provider("virustotal").label == "VirusTotal"
    with pytest.raises(KeyError):
        api_keys.provider("nobody")
    for p in api_keys.PROVIDERS:
        assert p.get_it.startswith("https://") and p.purpose


def test_keys_round_trip_and_stay_apart(tmp_path, two_services):
    path = str(tmp_path / "sub" / "keys.json")
    assert api_keys.get("virustotal", path) == "" and api_keys.status("virustotal", path) == "No key saved"
    assert api_keys.set_key("virustotal", VT_KEY, path) == ""
    assert api_keys.set_key("demo", "  abcdefgh  ", path) == ""
    assert api_keys.get("virustotal", path) == VT_KEY and api_keys.get("demo", path) == "abcdefgh"
    assert api_keys.status("virustotal", path) == "Saved (ends with bbbb)"
    assert VT_KEY not in api_keys.status("virustotal", path)
    assert api_keys.set_key("virustotal", "", path) == "" and api_keys.get("virustotal", path) == ""
    assert api_keys.get("demo", path) == "abcdefgh"                          # the other key is untouched
    assert api_keys.set_key("demo", "", path) == "" and not api_keys.get("demo", path)


@pytest.mark.parametrize("key", ["short", "z" * 64, "b" * 63, "b" * 65, "b" * 63 + " "])
def test_a_key_with_the_wrong_shape_is_refused_and_nothing_is_written(tmp_path, key):
    path = str(tmp_path / "keys.json")
    if key.endswith(" "):
        key = key.strip()                                  # trailing spaces are trimmed first: 63 characters remain
    assert api_keys.set_key("virustotal", key, path)
    assert not os.path.exists(path)


def test_a_damaged_file_reads_as_empty_and_is_replaced_on_save(tmp_path, two_services):
    path = tmp_path / "keys.json"
    path.write_text("not json")
    assert api_keys.get("virustotal", str(path)) == ""
    assert api_keys.set_key("virustotal", VT_KEY, str(path)) == "" and api_keys.get("virustotal", str(path)) == VT_KEY
    path.write_text(json.dumps({"keys": {"virustotal": 5, "demo": "abcdefgh", 7: "x"}}))
    assert api_keys.get("virustotal", str(path)) == "" and api_keys.get("demo", str(path)) == "abcdefgh"
    path.write_text(json.dumps(["list"]))
    assert api_keys.get("demo", str(path)) == ""


def test_the_key_is_never_logged(tmp_path, caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    api_keys.set_key("virustotal", VT_KEY, str(tmp_path / "k.json"))
    api_keys.set_key("virustotal", "", str(tmp_path / "k.json"))
    assert VT_KEY not in caplog.text and "saved" in caplog.text


def test_an_unwritable_location_is_reported(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    assert api_keys.set_key("virustotal", VT_KEY, str(blocker / "keys.json"))

# endregion


# region Testing a key

def test_virustotal_key_test_uses_a_hash_lookup_of_an_empty_file():
    http = FakeHttp(404)                                     # unknown hash: the key itself was accepted
    assert api_keys.check_key("virustotal", VT_KEY, http) == ""
    assert http.requests[0].full_url.endswith(api_keys.EMPTY_FILE_SHA256)
    assert http.requests[0].get_header("X-apikey") == VT_KEY
    assert "refused" in api_keys.check_key("virustotal", VT_KEY, FakeHttp(401))
    assert "quota" in api_keys.check_key("virustotal", VT_KEY, FakeHttp(429))


def test_a_network_failure_is_a_message_not_a_crash():
    def down(request):
        raise OSError("Cannot reach the service: offline")
    assert "offline" in api_keys.check_key("virustotal", VT_KEY, down)
    assert api_keys.check_key("virustotal", "  ", FakeHttp()) == "No key to test."
    assert api_keys.check_key("unknown", "k", FakeHttp()) == "This service cannot be tested."

# endregion


# region The window

def open_prefs(window, monkeypatch, then):
    def inspect(dialog):
        then(dialog)
        return 0
    monkeypatch.setattr(QDialog, "exec", inspect)
    window._open_preferences()


def box(dialog, label):
    return next(b for b in dialog.findChildren(QGroupBox) if b.title() == label)


def button(group, text):
    return next(b for b in group.findChildren(QPushButton) if b.text() == text)


def test_preferences_is_in_the_file_menu(window):  # noqa: F811
    file_menu = next(m for m in window.findChildren(QMenu) if m.title() == "&File")
    texts = [a.text() for a in file_menu.actions()]
    assert "&Preferences..." in texts and texts.index("&Preferences...") < texts.index("E&xit")
    prefs = next(a for a in file_menu.actions() if a.text() == "&Preferences...")
    assert prefs.shortcut().toString() == "Ctrl+,"


def test_every_service_has_a_masked_field_and_a_status(window, monkeypatch, two_services):  # noqa: F811
    seen = {}

    def inspect(dialog):
        for label in ("VirusTotal", "Demo"):
            group = box(dialog, label)
            edit = group.findChild(QLineEdit)
            pid = label.lower() if label == "Demo" else "virustotal"
            seen[label] = (edit.echoMode(), [b.text() for b in group.findChildren(QPushButton)],
                           window.prefs_rows[pid]["status"].text())
        seen["groups"] = [b.title() for b in dialog.findChildren(QGroupBox)]
    open_prefs(window, monkeypatch, inspect)
    for label in ("VirusTotal", "Demo"):
        assert seen[label][0] == QLineEdit.EchoMode.Password and seen[label][1] == ["Save", "Remove", "Test"]
        assert seen[label][2] == "No key saved"
    assert seen["groups"][-1] == "Where things are kept" and "Mistral" not in seen["groups"]


def test_saving_a_key_hides_it_and_updates_the_status(window, monkeypatch):  # noqa: F811
    seen = {}

    def inspect(dialog):
        group = box(dialog, "VirusTotal")
        edit = group.findChild(QLineEdit)
        edit.setText(VT_KEY)
        button(group, "Save").click()
        seen["field"] = edit.text()
        seen["status"] = window.prefs_rows["virustotal"]["status"].text()
    open_prefs(window, monkeypatch, inspect)
    assert seen["field"] == "" and seen["status"] == "Saved (ends with bbbb)"
    assert api_keys.get("virustotal") == VT_KEY and VT_KEY not in seen["status"]


def test_a_bad_or_empty_key_is_explained(window, dialogs, monkeypatch):  # noqa: F811
    seen = {}

    def inspect(dialog):
        group = box(dialog, "VirusTotal")
        edit = group.findChild(QLineEdit)
        button(group, "Save").click()                          # nothing pasted
        seen["info"] = len(dialogs["info"])
        edit.setText("not a key")
        button(group, "Save").click()
        seen["status"] = window.prefs_rows["virustotal"]["status"].text()
        seen["field_kept"] = edit.text()
    open_prefs(window, monkeypatch, inspect)
    assert seen["info"] == 1 and "64 letters" in seen["status"] and seen["field_kept"] == "not a key"
    assert api_keys.get("virustotal") == ""


def test_removing_asks_first(window, dialogs, monkeypatch):  # noqa: F811
    api_keys.set_key("virustotal", VT_KEY)

    def inspect(dialog):
        dialogs["answer"] = QMessageBox.StandardButton.No
        button(box(dialog, "VirusTotal"), "Remove").click()
        assert api_keys.get("virustotal") == VT_KEY
        dialogs["answer"] = QMessageBox.StandardButton.Yes
        button(box(dialog, "VirusTotal"), "Remove").click()
    open_prefs(window, monkeypatch, inspect)
    assert api_keys.get("virustotal") == "" and len(dialogs["question"]) == 2


def test_the_test_button_reports_the_services_answer(window, dialogs, monkeypatch):  # noqa: F811
    calls = []

    def start(attr, function, on_done, button=None, status=""):
        calls.append(attr)
        try:
            on_done(function(), "")
        except Exception as e:  # noqa: BLE001
            on_done(None, str(e))
        return True
    monkeypatch.setattr(window, "_start_call", start)
    answers = iter(["", "VirusTotal refused the API key."])
    monkeypatch.setattr(api_keys, "check_key", lambda pid, key, http=None: next(answers))
    seen = []

    def inspect(dialog):
        group = box(dialog, "VirusTotal")
        button(group, "Test").click()                          # no key anywhere
        seen.append(("info", len(dialogs["info"])))
        group.findChild(QLineEdit).setText(VT_KEY)
        button(group, "Test").click()
        seen.append(window.prefs_rows["virustotal"]["status"].text())
        button(group, "Test").click()
        seen.append(window.prefs_rows["virustotal"]["status"].text())
    open_prefs(window, monkeypatch, inspect)
    assert seen[0] == ("info", 1) and calls == ["prefs_test_worker", "prefs_test_worker"]
    assert seen[1] == "The service accepted this key." and seen[2] == "Not accepted: VirusTotal refused the API key."


def test_testing_does_not_save_and_a_malformed_key_is_not_sent(window, dialogs, monkeypatch):  # noqa: F811
    sent = []
    monkeypatch.setattr(window, "_start_call", lambda *a, **k: sent.append(a) or True)

    def inspect(dialog):
        group = box(dialog, "VirusTotal")
        group.findChild(QLineEdit).setText("short")
        button(group, "Test").click()
        assert "64 letters" in window.prefs_rows["virustotal"]["status"].text()
    open_prefs(window, monkeypatch, inspect)
    assert sent == [] and api_keys.get("virustotal") == ""


def test_closing_refreshes_the_virustotal_status(window, monkeypatch):  # noqa: F811
    open_prefs(window, monkeypatch, lambda dialog: api_keys.set_key("virustotal", VT_KEY))
    assert "saved" in window.vt_key_status.text().lower() and "bbbb" in window.vt_key_status.text()
    assert window.prefs_rows == {}

# endregion
