"""
Removing startup entries: only the known Run keys, the Startup folders and scheduled tasks, always with a backup.
Registry writes stay under the self-test key, files in tmp_path, and no real task is touched.
"""

import base64
import json
import os
import re
import winreg

import pytest
from PySide6.QtWidgets import QMessageBox

from ddcleaner import startup, startup_cleanup as sc
from ddcleaner.hunt_cleanup import RemoveResult
from ddcleaner.startup import StartupEntry
from ddcleaner.ui import tab_cleanup

from test_ui_smoke import dialogs, window  # noqa: F401  (fixtures)

RUN = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"


def reg_entry(name="Updater", hive="HKCU", key=RUN, view32=False, scope=startup.CURRENT_USER):
    return StartupEntry(name, r'"C:\x\u.exe"', f"{hive}\\{key}" + (sc.VIEW32 if view32 else ""), "Registry", scope)


def task_entry(name="Nightly", path="\\Vendor\\"):
    return StartupEntry(name, "x.exe", sc.TASK_PREFIX + path, "Task", "SYSTEM (highest privileges)")


@pytest.fixture
def run_key(test_key, monkeypatch):
    """A stand-in Run key under the self-test key, accepted as a known Run key for the test."""
    key = test_key + r"\Run"
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as handle:
        winreg.SetValueEx(handle, "Updater", 0, winreg.REG_SZ, r'"C:\x\u.exe"')
        winreg.SetValueEx(handle, "Keep", 0, winreg.REG_SZ, "keep.exe")
    monkeypatch.setattr(sc, "RUN_KEYS", sc.RUN_KEYS | {("HKCU", key.lower(), False)})
    return key


def values(key):
    found, index = {}, 0
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
        while True:
            try:
                name, value, _ = winreg.EnumValue(handle, index)
            except OSError:
                return found
            found[name] = value
            index += 1


def fake_export(written):
    def export(hive, key, file):
        with open(file, "w", encoding="utf-8") as f:
            f.write(f"[{hive}\\{key}]")
        written.append(file)
        return ""
    return export


# region What can be removed, and how

def test_targets_name_the_exact_place():
    assert sc.target(reg_entry()) == ("regvalue", "HKCU", RUN, "Updater")
    assert sc.target(reg_entry("(default)")) == ("regvalue", "HKCU", RUN, "")
    wow = sc.target(reg_entry(hive="HKLM", view32=True, scope=startup.ALL_USERS))
    assert wow == ("regvalue", "HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Updater")
    folder = StartupEntry("tool.lnk", r"C:\S\tool.lnk  ->  C:\P\tool.exe", r"C:\S", "Folder", startup.CURRENT_USER,
                          path=r"C:\P\tool.exe")
    assert sc.target(folder) == ("file", r"C:\S\tool.lnk")           # the shortcut, never the program it points to
    assert sc.target(task_entry()) == ("task", "Nightly", "\\Vendor\\")


def test_other_places_are_refused():
    assert sc.target(reg_entry(key=r"SOFTWARE\Vendor\Settings")) is None
    assert sc.target(reg_entry(hive="HKCU", view32=True)) is None    # there is no 32-bit HKCU Run key in the list
    assert sc.target(StartupEntry("x", "x", "", "Folder", startup.CURRENT_USER)) is None
    assert sc.target(StartupEntry("..\\x", "x", r"C:\S", "Folder", startup.CURRENT_USER)) is None
    assert sc.target(StartupEntry("x", "x", "somewhere", "Task", "me")) is None
    assert not sc.removable(reg_entry(key=r"SOFTWARE\Vendor\Settings"))
    assert "Cannot be removed" in sc.describe(reg_entry(key=r"SOFTWARE\Vendor\Settings"))


def test_administrator_is_needed_for_what_is_shared():
    assert not sc.needs_admin(reg_entry())
    assert sc.needs_admin(reg_entry(hive="HKLM", scope=startup.ALL_USERS))
    assert sc.needs_admin(task_entry())
    mine = StartupEntry("a.lnk", "a", r"C:\S", "Folder", startup.CURRENT_USER)
    everyone = StartupEntry("a.lnk", "a", r"C:\S", "Folder", startup.ALL_USERS)
    assert not sc.needs_admin(mine) and sc.needs_admin(everyone)

# endregion


# region Removing

def test_a_run_value_is_saved_then_deleted_and_its_neighbours_stay(run_key, tmp_path):
    written = []
    entry = reg_entry(key=run_key)
    result = sc.remove_entries([entry], str(tmp_path / "b"), export=fake_export(written))
    assert result.removed == [entry] and not result.failed and result.backups == written and len(written) == 1
    assert values(run_key) == {"Keep": "keep.exe"}
    again = sc.remove_entries([entry], str(tmp_path / "b"), export=fake_export(written))
    assert again.removed == [entry] and len(written) == 1            # already gone: nothing to save, not an error


def test_nothing_is_removed_when_the_backup_fails(run_key, tmp_path):
    entry = reg_entry(key=run_key)
    result = sc.remove_entries([entry], str(tmp_path / "b"), export=lambda *a: "disk full")
    assert not result.removed and "Backup failed" in result.failed[0][1]
    assert "Updater" in values(run_key)


def test_a_startup_file_is_moved_to_the_backups(tmp_path):
    folder = tmp_path / "Startup"
    folder.mkdir()
    link = folder / "tool.lnk"
    link.write_bytes(b"shortcut")
    entry = StartupEntry("tool.lnk", str(link), str(folder), "Folder", startup.CURRENT_USER)
    result = sc.remove_entries([entry], str(tmp_path / "b"), startup_folders={startup.CURRENT_USER: str(folder)})
    assert result.removed == [entry] and not link.exists()
    assert open(result.backups[0], "rb").read() == b"shortcut"       # moving it back restores the entry


def test_a_file_outside_the_startup_folders_is_never_touched(tmp_path):
    elsewhere = tmp_path / "Documents"
    elsewhere.mkdir()
    victim = elsewhere / "report.docx"
    victim.write_text("important")
    entry = StartupEntry("report.docx", str(victim), str(elsewhere), "Folder", startup.CURRENT_USER)
    result = sc.remove_entries([entry], str(tmp_path / "b"),
                               startup_folders={startup.CURRENT_USER: str(tmp_path / "Startup")})
    assert victim.exists() and "not in a Startup folder" in result.failed[0][1]


def test_a_task_is_exported_then_unregistered(tmp_path):
    asked = []

    def run(script, timeout=60):
        payload = json.loads(base64.b64decode(re.search(r"FromBase64String\('([^']+)'\)", script).group(1)))
        asked.append(payload)
        with open(payload["file"], "w", encoding="utf-8") as f:
            f.write("<Task/>")
        return {"ok": True, "error": ""}
    entry = task_entry()
    result = sc.remove_entries([entry], str(tmp_path / "b"), run=run)
    assert result.removed == [entry] and asked[0]["name"] == "Nightly" and asked[0]["path"] == "\\Vendor\\"
    assert os.path.isfile(result.backups[0]) and result.backups[0].endswith(".xml")
    refused = sc.remove_entries([entry], str(tmp_path / "b"), run=lambda script, timeout=60: None)
    assert "administrator" in refused.failed[0][1]


def test_stop_and_unknown_entries_are_reported(tmp_path):
    result = sc.remove_entries([reg_entry(key=r"SOFTWARE\Vendor\Settings"), reg_entry()], str(tmp_path / "b"),
                               stop=lambda: False, export=lambda *a: "never called")
    assert "cannot be removed" in result.failed[0][1]
    stopped = sc.remove_entries([reg_entry()], str(tmp_path / "b"), stop=lambda: True)
    assert stopped.failed[0][1] == "Stopped" and not stopped.removed

# endregion


# region The Startup programs page

def rows(tree):
    return [tree.topLevelItem(i) for i in range(tree.topLevelItemCount())]


def test_removable_rows_have_a_checkbox_and_say_what_removal_does(window):  # noqa: F811
    odd = StartupEntry("Odd", "x", "somewhere else", "Registry", startup.CURRENT_USER)
    window._on_startup_scanned([reg_entry(), odd], "")
    by_name = {r.text(0): r for r in rows(window.startup_tree)}
    assert by_name["Updater"].checkState(0).name == "Unchecked" and "Delete the value Updater" in by_name["Updater"].toolTip(0)
    tab_cleanup.set_all_checked(window.startup_tree, True)
    assert [e.name for e in tab_cleanup.checked_payloads(window.startup_tree)] == ["Updater"]   # "Odd" has no checkbox


def test_removing_needs_a_tick_the_right_rights_and_a_yes(window, dialogs, monkeypatch):  # noqa: F811
    shared = reg_entry("Shared", hive="HKLM", scope=startup.ALL_USERS)
    window._on_startup_scanned([reg_entry(), shared], "")
    window.startup_tree.selectAll()
    window._remove_startup_entries()
    assert dialogs["info"] and not dialogs["question"]                  # selected is not ticked
    tab_cleanup.set_all_checked(window.startup_tree, True)
    monkeypatch.setattr("ddcleaner.ui.tab_system_info.SystemUtils.check_admin_privileges", staticmethod(lambda: False))
    before = len(dialogs["warning"])
    window._remove_startup_entries()
    assert len(dialogs["warning"]) == before + 1 and not dialogs["question"]
    monkeypatch.setattr("ddcleaner.ui.tab_system_info.SystemUtils.check_admin_privileges", staticmethod(lambda: True))
    called = []
    monkeypatch.setattr(window, "_start_call", lambda *a, **k: called.append(a) or True)
    dialogs["answer"] = QMessageBox.StandardButton.No
    window._remove_startup_entries()
    assert not called and "Remove 2 startup entries" in dialogs["question"][-1][0]
    dialogs["answer"] = QMessageBox.StandardButton.Yes
    window._remove_startup_entries()
    assert called and called[0][0] == "startup_remove_worker"


def test_removed_entries_leave_the_list_and_failures_are_shown(window, dialogs):  # noqa: F811
    good, bad = reg_entry("Good"), reg_entry("Bad")
    window._on_startup_scanned([good, bad], "")
    window._on_startup_removed(RemoveResult([good], [(bad, "Access denied: run as administrator")], ["a.reg"]), "")
    assert [r.text(0) for r in rows(window.startup_tree)] == ["Bad"] and window.startup_entries == [bad]
    assert "1 entry removed" in window.startup_summary.text()
    assert "Bad: Access denied" in dialogs["warning"][-1][0]
    window._on_startup_removed(None, "boom")
    assert len(dialogs["warning"]) >= 2

# endregion
