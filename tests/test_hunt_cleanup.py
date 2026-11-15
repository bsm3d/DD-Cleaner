"""Removing what the persistence hunt found. Tasks and services go through fakes (nothing real is touched); registry
values are removed for real, but only under pytest's HKCU test key. Backups go to pytest's temporary folder."""

import base64
import json
import os
import re
import types
import winreg

import pytest
from PySide6.QtWidgets import QMessageBox

from ddcleaner import hunt_cleanup as hc, threat_hunt as hunt
from ddcleaner.ui import tab_cleanup
from ddcleaner.threat_hunt import Finding

from test_ui_smoke import dialogs, window  # noqa: F401  (fixtures)


def task(name="Old Task", path="\\", **kw):
    return Finding("Scheduled task", name, "cmd", hunt.LOOK, "", "Task Scheduler", kw.pop("flags", []), ("task", name, path))


def service(name="OldSvc", path="", **kw):
    return Finding("Service", name, "image", hunt.LOOK, path, "HKLM", kw.pop("flags", []), ("service", name))


def fake_powershell(ok=True, error="", write_backup=True, seen=None):
    def run(script, timeout=60):
        payload = json.loads(base64.b64decode(re.search(r"FromBase64String\('([^']+)'\)", script).group(1)))
        if seen is not None:
            seen.append((script, payload))
        if write_backup:
            with open(payload["file"], "w") as f:
                f.write("<Task/>")
        return {"ok": ok, "error": error}
    return run


# region Describing and allowing

def test_what_can_be_removed():
    assert hc.removable(task()) and hc.removable(service()) and hc.removable(
        Finding("W", "t", removal=("regvalue", "HKLM", "k", "v")))
    assert not hc.removable(Finding("Hosts file", "x")) and not hc.removable(Finding("W", "t", removal=("other", "x")))
    assert "scheduled task Old Task" in hc.describe(task()) and "service OldSvc" in hc.describe(service())
    assert "(default)" in hc.describe(Finding("W", "t", removal=("regvalue", "HKCU", "k", "")))
    assert hc.describe(Finding("Hosts file", "x")) == "Cannot be removed from here"


def test_a_dead_finding_is_one_whose_program_is_gone():
    assert Finding("T", "x", flags=["Program not found"]).dead
    assert Finding("S", "x", flags=["Automatic service whose program is missing"]).dead
    assert not Finding("S", "x", flags=["Not signed"]).dead

# endregion


# region Tasks

def test_a_task_is_exported_then_unregistered(tmp_path):
    seen = []
    result = hc.remove_findings([task("Evil'Task\"; calc", "\\Acme\\")], str(tmp_path / "bk"), run=fake_powershell(seen=seen))
    assert len(result.removed) == 1 and not result.failed and len(result.backups) == 1
    script, payload = seen[0]
    assert payload["name"] == "Evil'Task\"; calc" and payload["path"] == "\\Acme\\"     # data travels encoded, not in the code
    assert "Evil" not in script and script.index("Export-ScheduledTask") < script.index("Unregister-ScheduledTask")
    assert payload["file"].startswith(str(tmp_path / "bk")) and payload["file"].endswith(".xml") and os.path.isfile(payload["file"])


def test_a_failed_task_removal_is_reported(tmp_path):
    failed = hc.remove_findings([task()], str(tmp_path), run=fake_powershell(ok=False, error="Access is denied", write_backup=False))
    assert failed.failed[0][1] == "Access is denied" and not failed.removed
    no_answer = hc.remove_findings([task()], str(tmp_path), run=lambda script, timeout=60: None)
    assert "administrator" in no_answer.failed[0][1]
    no_backup = hc.remove_findings([task()], str(tmp_path), run=fake_powershell(write_backup=False))
    assert "backup" in no_backup.failed[0][1]

    def boom(script, timeout=60):
        raise ValueError("bad json")
    assert "PowerShell failed" in hc.remove_findings([task()], str(tmp_path), run=boom).failed[0][1]

# endregion


# region Services

def test_a_service_is_backed_up_then_deleted(tmp_path):
    calls = []

    def export(hive, key, file):
        calls.append(("export", hive, key))
        open(file, "w").write("reg")
        return ""

    def delete(name):
        calls.append(("delete", name))
        return 0
    result = hc.remove_findings([service("Old Svc")], str(tmp_path), export=export, delete_service=delete)
    assert len(result.removed) == 1 and calls == [("export", "HKLM", hunt.SERVICES_KEY + "\\Old Svc"), ("delete", "Old Svc")]
    assert len(result.backups) == 1 and result.backups[0].endswith(".reg") and not result.reboot


@pytest.mark.parametrize("code, ok, reboot", [(0, True, False), (1072, True, True), (1060, True, False), (5, False, False)])
def test_service_delete_codes(tmp_path, code, ok, reboot):
    result = hc.remove_findings([service()], str(tmp_path), export=lambda *a: "", delete_service=lambda n: code)
    assert bool(result.removed) is ok and result.reboot is reboot
    if not ok:
        assert "administrator" in result.failed[0][1]


def test_nothing_is_deleted_when_the_service_backup_fails(tmp_path):
    result = hc.remove_findings([service()], str(tmp_path), export=lambda *a: "disk full",
                                delete_service=lambda n: pytest.fail("must not delete without a backup"))
    assert "Backup failed" in result.failed[0][1]


def test_windows_services_and_odd_names_are_refused(tmp_path):
    guard = dict(export=lambda *a: pytest.fail("no backup for a refused service"),
                 delete_service=lambda n: pytest.fail("refused"))
    windows = service("Spooler", path=os.path.join(hunt.SYSTEM32, "spoolsv.exe"))
    assert "Windows itself" in hc.remove_findings([windows], str(tmp_path), **guard).failed[0][1]
    for bad in ("..\\evil", "a/b", "x" * 300, "name;calc", ""):
        assert hc.remove_findings([service(bad)], str(tmp_path), **guard).failed

# endregion


# region Registry values (real HKCU test key)

@pytest.fixture
def run_key(test_key, monkeypatch):
    monkeypatch.setattr(hc, "ALLOWED_VALUES", [((test_key + "\\run").lower(), None),
                                               (hunt.IFEO.lower() + "\\", {"debugger"})])
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, test_key + "\\Run") as key:
        winreg.SetValueEx(key, "Dead", 0, winreg.REG_SZ, r"C:\gone.exe")
        winreg.SetValueEx(key, "Keep", 0, winreg.REG_SZ, "kept")
    return test_key + "\\Run"


def value_finding(key, name, hive="HKCU"):
    return Finding("Windows setting", "v", removal=("regvalue", hive, key, name))


def names(key):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as handle:
        return sorted(winreg.EnumValue(handle, i)[0] for i in range(winreg.QueryInfoKey(handle)[1]))


def test_a_registry_value_is_exported_then_deleted(run_key, tmp_path):
    result = hc.remove_findings([value_finding(run_key, "Dead")], str(tmp_path / "bk"))
    assert len(result.removed) == 1 and not result.failed and names(run_key) == ["Keep"]
    backup = result.backups[0]
    assert backup.endswith(".reg") and "gone.exe" in open(backup, "rb").read().decode("utf-16")


def test_a_failed_backup_leaves_the_value(run_key, tmp_path):
    result = hc.remove_findings([value_finding(run_key, "Dead")], str(tmp_path), export=lambda *a: "disk full")
    assert "Backup failed" in result.failed[0][1] and names(run_key) == ["Dead", "Keep"]


def test_only_known_startup_and_debugger_values_can_be_removed(run_key, tmp_path):
    guard = dict(export=lambda *a: pytest.fail("refused before any backup"))
    for finding in (value_finding(r"Software\Microsoft\Windows\CurrentVersion\Run", "Anything"),
                    value_finding(hunt.IFEO + "\\x.exe", "GlobalFlag", "HKLM"),
                    value_finding("Software\\Vendor", "x"), value_finding(run_key, "Dead", "HKU")):
        assert "not one that can be removed" in hc.remove_findings([finding], str(tmp_path), **guard).failed[0][1]
    assert names(run_key) == ["Dead", "Keep"]


def test_a_value_that_is_already_gone_counts_as_removed(test_key, run_key, tmp_path):
    result = hc.remove_findings([value_finding(test_key + "\\Run\\Sub", "x")], str(tmp_path))
    assert not result.failed or "not one" in result.failed[0][1]


def test_a_key_that_vanished_counts_as_removed(test_key, monkeypatch, tmp_path):
    monkeypatch.setattr(hc, "ALLOWED_VALUES", [((test_key + "\\nokey").lower(), None)])
    result = hc.remove_findings([value_finding(test_key + "\\NoKey", "x")], str(tmp_path),
                                export=lambda *a: pytest.fail("nothing to export"))
    assert len(result.removed) == 1


def test_stop_and_unremovable_entries(tmp_path):
    assert hc.remove_findings([task()], str(tmp_path), stop=lambda: True).failed[0][1] == "Stopped"
    other = hc.remove_findings([Finding("Hosts file", "x")], str(tmp_path))
    assert "cannot be removed" in other.failed[0][1]

# endregion


# region What the hunt offers

def test_hunt_findings_carry_their_removal():
    ps = os.path.join(hunt.SYSTEM32, "WindowsPowerShell", "v1.0", "powershell.exe")
    judge = types.SimpleNamespace(in_windows=hunt.judge_in_windows, unsigned=lambda p: False, packed=lambda p: False,
                                  writable_folder=lambda p: False, signer=lambda p: "")
    tasks = hunt.check_tasks(judge, lambda script: [
        {"Name": "Gone", "Path": "\\Acme\\", "Exec": r"C:\nowhere\gone.exe", "Args": "", "User": "me", "Level": "Limited"},
        {"Name": "Enc", "Path": "\\", "Exec": ps, "Args": "-enc " + "A" * 40, "User": "me", "Level": "Limited"}])
    by_name = {f.title: f for f in tasks}
    assert by_name["Gone"].removal == ("task", "Gone", "\\Acme\\") and by_name["Gone"].dead
    assert by_name["Enc"].removal == ("task", "Enc", "\\") and not by_name["Enc"].dead


def test_hijack_findings_offer_only_the_removable_ones():
    from test_hunt import tree, merge, CLEAN_HKLM, nested
    hklm = merge(CLEAN_HKLM, nested(hunt.IFEO, {"sethc.exe": {"Debugger": r"C:\Windows\System32\cmd.exe"}}),
                 nested(hunt.WINLOGON, {"Shell": "evil.exe"}))
    hkcu = nested(hunt.POLICIES_RUN, {"Updater": r"C:\nowhere\u.exe"})
    found = {f.title: f for f in hunt.check_hijacks(tree(hklm=hklm, hkcu=hkcu))}
    assert found["Debugger set for sethc.exe"].removal == ("regvalue", "HKLM", hunt.IFEO + "\\sethc.exe", "Debugger")
    assert found["Policy startup: Updater"].removal == ("regvalue", "HKCU", hunt.POLICIES_RUN, "Updater")
    assert found["Winlogon Shell"].removal is None                  # a core setting: never offered

# endregion


# region The Persistence page

def rows(tree_widget):
    return [tree_widget.topLevelItem(i) for i in range(tree_widget.topLevelItemCount())]


def ticked(tree_widget):
    return [f.title for f in tab_cleanup.checked_payloads(tree_widget)]


def test_dead_entries_are_proposed_ticked(window):  # noqa: F811
    dead = task("Dead task", flags=["Program not found"])
    other = service("Other", flags=["Not signed"])
    window._on_hunt_done([dead, other], "")
    assert ticked(window.hunt_tree) == ["Dead task"]
    assert "no longer exists" in window.hunt_summary.text() and "ticked" in window.hunt_summary.text()
    window.hunt_tree.topLevelItem(0).setSelected(True)                  # reading a row changes nothing
    window.hunt_flagged_cb.setChecked(False)                            # nor does showing every finding
    assert ticked(window.hunt_tree) == ["Dead task"]
    assert "scheduled task" in rows(window.hunt_tree)[0].toolTip(1) or "service" in rows(window.hunt_tree)[0].toolTip(1)


def test_removing_needs_a_selection_admin_rights_and_a_yes(window, dialogs, monkeypatch):  # noqa: F811
    window._on_hunt_done([Finding("Scheduled task", "Dead task", severity=hunt.LOOK, flags=["Program not found"],
                                  removal=("task", "Dead task", "\\"))], "")
    tab_cleanup.set_all_checked(window.hunt_tree, False)
    window.hunt_tree.selectAll()
    window._remove_hunt_findings()
    assert dialogs["info"] and not dialogs["question"]                      # selected is not ticked
    tab_cleanup.set_all_checked(window.hunt_tree, True)
    monkeypatch.setattr("ddcleaner.ui.tab_hunt.SystemUtils.check_admin_privileges", staticmethod(lambda: False))
    before = len(dialogs["warning"])
    window._remove_hunt_findings()
    assert len(dialogs["warning"]) == before + 1 and not dialogs["question"]
    monkeypatch.setattr("ddcleaner.ui.tab_hunt.SystemUtils.check_admin_privileges", staticmethod(lambda: True))
    called = []
    monkeypatch.setattr(window, "_start_call", lambda *a, **k: called.append(a) or True)
    dialogs["answer"] = QMessageBox.StandardButton.No
    window._remove_hunt_findings()
    assert dialogs["question"] and not called and "scheduled task Dead task" in dialogs["question"][-1][0]
    dialogs["answer"] = QMessageBox.StandardButton.Yes
    window._remove_hunt_findings()
    assert called and called[0][0] == "hunt_remove_worker"


def test_unremovable_selection_is_explained(window, dialogs, monkeypatch):  # noqa: F811
    window._on_hunt_done([Finding("Hosts file", "x.com", severity=hunt.SUSPICIOUS)], "")
    window.hunt_tree.selectAll()
    window._remove_hunt_findings()
    assert dialogs["info"] and not dialogs["question"]


def test_removed_entries_leave_the_list_and_failures_are_shown(window, dialogs):  # noqa: F811
    good = Finding("Scheduled task", "Good", severity=hunt.LOOK, removal=("task", "Good", "\\"))
    bad = Finding("Service", "Bad", severity=hunt.LOOK, removal=("service", "Bad"))
    window._on_hunt_done([good, bad], "")
    window._on_hunt_removed(hc.RemoveResult([good], [(bad, "sc delete failed (code 5): run as administrator")], ["b.xml"], True), "")
    assert [r.text(1) for r in rows(window.hunt_tree)] == ["Bad"]
    text = dialogs["warning"][-1][0]
    assert "Bad: sc delete failed" in text and "next restart" in text
    window._on_hunt_removed(None, "boom")
    assert len(dialogs["warning"]) >= 2

# endregion
