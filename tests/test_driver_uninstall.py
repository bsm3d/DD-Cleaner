"""Complete driver uninstall: the full listing, in-use drivers, ghost devices, leftover services and files, the page.
pnputil, the registry and the file system are faked or live in pytest's temporary folder: no real driver is touched."""

import os
import types

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMessageBox

from ddcleaner import driver_cleanup as dc, driver_uninstall as du

from test_locations_drivers import FakePnp, NET_GUID, SYSTEM_GUID, bind, cand, pkg
from test_system_pages import FakeReg, nested
from test_ui_smoke import dialogs, window  # noqa: F401  (fixtures)

BS = chr(92)
SERVICES = du.SERVICES_KEY


def used(published="oem1.inf", original="nic.inf", names=("Intel NIC",), ghosts=()):
    return dc.Candidate(pkg(published, original), dc.CAT_USED, "In use by: " + ", ".join(names), list(names), list(ghosts))


def write_inf(folder, published, services, encoding="utf-16"):
    body = "[Version]\nSignature=\"$Windows NT$\"\n" + "".join(
        f"[{s}.Install]\nAddService = {s}, 0x2, {s}_Service ; the driver\n" for s in services) + "; AddService = Commented, 0, x\n"
    path = os.path.join(folder, published)
    with open(path, "w", encoding=encoding) as f:
        f.write(body)
    return path


@pytest.fixture
def inf_folder(tmp_path, monkeypatch):
    folder = tmp_path / "INF"
    folder.mkdir()
    monkeypatch.setattr(du, "SYSTEM_ROOT", str(tmp_path))
    return folder


# region Listing everything

def test_every_package_is_listed_with_its_situation():
    packages = [pkg("oem1.inf", "used.inf"), pkg("oem2.inf", "gone.inf"), pkg("oem3.inf", "sys.inf", "AMD", "System", SYSTEM_GUID),
                pkg("oem4.inf", "free.inf")]
    bindings = [dc.Binding("Real NIC", "oem1.inf", True, "Net", "PCI\\A"), dc.Binding("Old NIC", "oem1.inf", False, "Net", "PCI\\OLD"),
                dc.Binding("Ghost cam", "oem2.inf", False, "Camera", "USB\\GHOST"), dc.Binding("GPIO", "oem3.inf", True, "System", "ACPI\\X")]
    by = {c.package.published: c for c in dc.list_all(packages, bindings)}
    assert by["oem1.inf"].category == dc.CAT_USED and by["oem1.inf"].risk == "Danger" and by["oem1.inf"].in_use
    assert by["oem1.inf"].devices == ["Real NIC"] and by["oem1.inf"].ghost_ids == ["PCI\\OLD"]
    assert by["oem2.inf"].category == dc.CAT_GONE and by["oem2.inf"].ghost_ids == ["USB\\GHOST"] and not by["oem2.inf"].in_use
    assert by["oem3.inf"].category == dc.CAT_PROTECTED and by["oem3.inf"].risk == "Locked" and not by["oem3.inf"].removable
    assert by["oem4.inf"].category == dc.CAT_NONE and by["oem4.inf"].removable
    with pytest.raises(OSError):
        dc.list_all(packages, [dc.Binding("x", "oem9.inf", False)])


def test_the_binding_reader_keeps_instance_ids_and_scan_all_wires_both_readers():
    rows = [{"Name": "NIC", "Inf": "OEM1.INF", "Id": "PCI\\VEN_1", "Class": "Net", "Present": True}]
    assert dc.read_bindings(lambda script, timeout=60: rows)[0].instance_id == "PCI\\VEN_1"
    out = dc.scan_all(lambda args: (0, "Published Name: oem1.inf\nOriginal Name: nic.inf\nProvider Name: Intel\nClass Name: Net\n"
                                       f"Class GUID: {NET_GUID}\nDriver Version: 01/01/2024 1.2.3.4\nSigner Name: MS\n"),
                      lambda script, timeout=60: rows)
    assert [(c.package.published, c.category) for c in out] == [("oem1.inf", dc.CAT_USED)]

# endregion


# region Reading INF files

@pytest.mark.parametrize("encoding", ["utf-16", "utf-8", "cp1252"])
def test_services_are_read_from_the_inf_whatever_its_encoding(inf_folder, encoding):
    path = write_inf(str(inf_folder), "oem7.inf", ["wdnas", "wdfilter"], encoding)
    assert du.inf_services(path) == ["wdnas", "wdfilter"]                    # the commented AddService is ignored


def test_unreadable_or_empty_infs_give_nothing(tmp_path):
    assert du.inf_services(str(tmp_path / "none.inf")) == [] and du.read_inf(str(tmp_path / "none.inf")) == ""
    (tmp_path / "empty.inf").write_bytes(b"")
    assert du.inf_services(str(tmp_path / "empty.inf")) == []


def test_inbox_services_come_from_the_windows_infs_only(inf_folder):
    write_inf(str(inf_folder), "usbhub3.inf", ["USBHUB3"])
    write_inf(str(inf_folder), "oem9.inf", ["vendorsvc"])
    assert du.inbox_services(str(inf_folder)) == {"usbhub3"} and du.inbox_services(str(inf_folder / "nope")) == set()

# endregion


# region Leftovers

def service_tree(tmp_path, **services):
    drivers = tmp_path / "System32" / "drivers"
    drivers.mkdir(parents=True, exist_ok=True)
    tree = {}
    for name, (kind, start, image) in services.items():
        tree[name] = {"Type": kind, "Start": start, "ImagePath": image}
        if image.lower().endswith(".sys") and "drivers" in image.lower():
            (drivers / os.path.basename(image)).write_bytes(b"MZ")
    return FakeReg({("HKLM", "64"): nested(SERVICES, tree)})


@pytest.fixture(autouse=True)
def fake_system(tmp_path, monkeypatch):
    monkeypatch.setattr(du, "SYSTEM_ROOT", str(tmp_path))
    monkeypatch.setattr(du, "DRIVERS_FOLDER", str(tmp_path / "System32" / "drivers"))


def test_leftover_rules(tmp_path):
    reg = service_tree(tmp_path,
                       gone=(1, 3, r"\SystemRoot\System32\drivers\gone.sys"),
                       boot=(1, 0, r"\SystemRoot\System32\drivers\boot.sys"),
                       app=(16, 2, r"C:\Program Files\App\svc.exe"),
                       elsewhere=(1, 3, r"C:\Vendor\drv\x.sys"),
                       shared=(1, 3, r"\SystemRoot\System32\drivers\shared.sys"),
                       fs=(2, 3, r"system32\drivers\fs.sys"))
    services = {n: "oem1.inf" for n in ("gone", "boot", "app", "elsewhere", "shared", "fs", "missing", "bad name;calc")}
    found = du.find_leftovers(services, {"shared"}, reg)
    assert sorted(l.service for l in found) == ["fs", "gone"]
    gone = next(l for l in found if l.service == "gone")
    assert gone.file_exists and gone.image.endswith("gone.sys") and gone.package == "oem1.inf"
    assert not any(l.service in ("boot", "app", "elsewhere", "shared") for l in found)


def test_why_a_service_is_refused():
    assert du.leftover_problem("x", None) == "No such service"
    assert "boot-start" in du.leftover_problem("x", {"Type": 1, "Start": 0, "ImagePath": "system32\\drivers\\a.sys"})
    assert "driver service" in du.leftover_problem("x", {"Type": 16, "Start": 2, "ImagePath": "x.exe"})
    assert "Unusual" in du.leftover_problem("..\\x", {"Type": 1})
    assert du.leftover_problem("x", {"Type": 1, "Start": 3, "ImagePath": "\\SystemRoot\\System32\\drivers\\a.sys"}) == ""


def test_image_paths_in_all_their_forms(tmp_path):
    root = str(tmp_path)
    assert du.resolve_driver_file("\\SystemRoot\\System32\\drivers\\a.sys") == os.path.join(root, "System32", "drivers", "a.sys")
    assert du.resolve_driver_file("system32\\drivers\\a.sys") == os.path.join(root, "system32\\drivers\\a.sys")
    assert du.resolve_driver_file("\\??\\C:\\x\\a.sys") == "C:\\x\\a.sys" and du.resolve_driver_file('"C:\\x\\a.sys"') == "C:\\x\\a.sys"
    assert du.resolve_driver_file("") == ""

# endregion


# region Uninstalling

def run_uninstall(candidates, tmp_path, run=None, remaining=(), reg=None, inbox=frozenset()):
    run = run or FakePnp()
    return du.uninstall_completely(candidates, list(remaining), str(tmp_path / "bk"), run, reg or FakeReg({}), set(inbox)), run


def test_an_unused_driver_is_deleted_plainly_but_an_in_use_one_is_forced(tmp_path):
    result, run = run_uninstall([cand("oem1.inf", "a.inf"), used("oem2.inf", "b.inf")], tmp_path)
    assert len(result.removed) == 2 and not result.failed and len(result.backups) == 2
    deletes = [c for c in run.calls if c[0] == "/delete-driver"]
    assert deletes == [["/delete-driver", "oem1.inf"], ["/delete-driver", "oem2.inf", "/uninstall", "/force"]]
    assert result.reboot                                                      # a driver that was in use


def test_every_package_is_saved_before_it_is_deleted(tmp_path):
    result, run = run_uninstall([used("oem2.inf", "b.inf")], tmp_path)
    assert [c[0] for c in run.calls[:2]] == ["/export-driver", "/delete-driver"]
    assert os.path.isfile(os.path.join(result.backups[0], "driver.inf"))


def test_nothing_is_deleted_without_its_copy(tmp_path):
    for run in (FakePnp(export=1), FakePnp(write=False)):
        result, run = run_uninstall([used()], tmp_path, run)
        assert "backup" in result.failed[0][1] and not result.removed and not any(c[0] == "/delete-driver" for c in run.calls)


def test_the_devices_that_are_not_connected_are_removed_too(tmp_path):
    result, run = run_uninstall([used("oem1.inf", ghosts=["PCI\\OLD1", "PCI\\OLD2"])], tmp_path)
    assert [c for c in run.calls if c[0] == "/remove-device"] == [["/remove-device", "PCI\\OLD1"], ["/remove-device", "PCI\\OLD2"]]
    assert result.ghosts_removed == 2


def test_a_failed_delete_leaves_the_package_and_removes_no_device(tmp_path):
    result, run = run_uninstall([used(ghosts=["PCI\\OLD"])], tmp_path, FakePnp(delete=87))
    assert "administrator" in result.failed[0][1] and not result.removed
    assert not any(c[0] == "/remove-device" for c in run.calls)


def test_core_drivers_and_odd_names_never_reach_pnputil(tmp_path):
    locked = dc.Candidate(pkg("oem5.inf", "sys.inf", "AMD", "System", SYSTEM_GUID), dc.CAT_PROTECTED, "core")
    forged = dc.Candidate(pkg("oem6.inf", "sys.inf", "AMD", "System", SYSTEM_GUID), dc.CAT_USED, "forged as in use")
    odd = used("..\\evil.inf")
    result, run = run_uninstall([locked, forged, odd], tmp_path)
    assert len(result.failed) == 3 and run.calls == []
    assert run_uninstall([used()], tmp_path)[0].failed == [] and du.uninstall_completely([used()], [], str(tmp_path), FakePnp(),
                                                                                    FakeReg({}), set(), stop=lambda: True).failed[0][1] == "Stopped"


def test_leftover_services_of_the_removed_driver_are_found_unless_something_else_declares_them(tmp_path, inf_folder):
    write_inf(str(inf_folder), "oem1.inf", ["nicsvc", "sharedsvc", "inboxsvc"])
    write_inf(str(inf_folder), "oem2.inf", ["sharedsvc"])
    reg = service_tree(tmp_path, nicsvc=(1, 3, r"\SystemRoot\System32\drivers\nic.sys"),
                       sharedsvc=(1, 3, r"\SystemRoot\System32\drivers\shared.sys"),
                       inboxsvc=(1, 3, r"\SystemRoot\System32\drivers\inbox.sys"))
    remaining = [pkg("oem1.inf", "nic.inf"), pkg("oem2.inf", "other.inf")]
    result, _ = run_uninstall([used("oem1.inf")], tmp_path, remaining=remaining, reg=reg, inbox={"inboxsvc"})
    assert [l.service for l in result.leftovers] == ["nicsvc"]                 # shared with oem2, inboxsvc belongs to Windows
    assert result.leftovers[0].package == "oem1.inf" and result.leftovers[0].file_exists


def test_no_leftover_is_reported_for_a_driver_that_failed_to_uninstall(tmp_path, inf_folder):
    write_inf(str(inf_folder), "oem1.inf", ["nicsvc"])
    reg = service_tree(tmp_path, nicsvc=(1, 3, r"\SystemRoot\System32\drivers\nic.sys"))
    assert run_uninstall([used("oem1.inf")], tmp_path, FakePnp(delete=5), reg=reg)[0].leftovers == []

# endregion


# region Removing the leftovers

def leftover(tmp_path, name="nicsvc", sys_name="nic.sys"):
    return du.Leftover(name, str(tmp_path / "System32" / "drivers" / sys_name), True, "oem1.inf")


def test_a_leftover_is_saved_then_its_key_and_file_are_deleted(tmp_path):
    reg = service_tree(tmp_path, nicsvc=(1, 3, r"\SystemRoot\System32\drivers\nic.sys"))
    deleted, exported = [], []

    def export(hive, key, file):
        exported.append((hive, key))
        open(file, "w").write("reg")
        return ""
    result = du.remove_leftovers([leftover(tmp_path)], str(tmp_path / "bk"), reg, export, deleted.append)
    assert len(result.removed) == 1 and not result.failed and deleted == ["nicsvc"]
    assert exported == [("HKLM", SERVICES + "\\nicsvc")] and not (tmp_path / "System32" / "drivers" / "nic.sys").exists()
    saved = result.backups[0]
    assert os.path.isfile(os.path.join(saved, "service.reg")) and os.path.isfile(os.path.join(saved, "nic.sys"))


def test_nothing_is_removed_when_the_leftover_backup_fails(tmp_path):
    reg = service_tree(tmp_path, nicsvc=(1, 3, r"\SystemRoot\System32\drivers\nic.sys"))
    result = du.remove_leftovers([leftover(tmp_path)], str(tmp_path / "bk"), reg, lambda *a: "disk full",
                                 lambda name: pytest.fail("no deletion without a backup"))
    assert "Backup failed" in result.failed[0][1] and (tmp_path / "System32" / "drivers" / "nic.sys").exists()


def test_a_leftover_that_became_unsafe_is_refused_again(tmp_path):
    reg = service_tree(tmp_path, nicsvc=(1, 0, r"\SystemRoot\System32\drivers\nic.sys"), app=(16, 2, "C:\\x\\a.exe"))
    guard = dict(export=lambda *a: pytest.fail("refused first"), delete_tree=lambda n: pytest.fail("refused first"))
    result = du.remove_leftovers([leftover(tmp_path), du.Leftover("app", "C:\\x\\a.exe", True, "oem1.inf"),
                                  du.Leftover("missing", "", False, "oem1.inf"), du.Leftover("..\\x", "", False, "oem1.inf")],
                                 str(tmp_path / "bk"), reg, **guard)
    assert len(result.failed) == 4 and not result.removed


def test_a_file_that_is_still_loaded_is_reported_after_the_key_is_gone(tmp_path):
    reg = service_tree(tmp_path, nicsvc=(1, 3, r"\SystemRoot\System32\drivers\nic.sys"))

    def locked(path):
        raise PermissionError("in use")
    deleted = []
    result = du.remove_leftovers([leftover(tmp_path)], str(tmp_path / "bk"), reg, lambda h, k, f: open(f, "w").close() or "",
                                 deleted.append, locked)
    assert deleted == ["nicsvc"] and "restart" in result.failed[0][1] and not result.removed


def test_access_denied_is_explained_and_stop_is_respected(tmp_path):
    reg = service_tree(tmp_path, nicsvc=(1, 3, r"\SystemRoot\System32\drivers\nic.sys"))

    def denied(name):
        raise PermissionError("denied")
    result = du.remove_leftovers([leftover(tmp_path)], str(tmp_path / "bk"), reg, lambda h, k, f: open(f, "w").close() or "", denied)
    assert "administrator" in result.failed[0][1] and (tmp_path / "System32" / "drivers" / "nic.sys").exists()
    assert du.remove_leftovers([leftover(tmp_path)], str(tmp_path), reg, stop=lambda: True).failed[0][1] == "Stopped"

# endregion


# region The page

def listed(window, candidates):
    window._on_all_drivers_scanned(candidates, "")
    return [window.uninstall_tree.topLevelItem(i) for i in range(window.uninstall_tree.topLevelItemCount())]


def sample():
    locked = dc.Candidate(pkg("oem3.inf", "sys.inf", "AMD", "System", SYSTEM_GUID), dc.CAT_PROTECTED, "Core driver")
    return [used("oem1.inf", "nic.inf"), cand("oem2.inf", "nas.inf"), locked]


def test_the_page_lists_everything_and_locks_the_core_drivers(window):  # noqa: F811
    rows = {r.text(0): r for r in listed(window, sample())}
    assert set(rows) == {"nic.inf", "nas.inf", "sys.inf"}
    assert rows["nic.inf"].text(5) == "Danger" and rows["nic.inf"].foreground(0).color().red() == 255
    assert rows["nas.inf"].text(5) == "Check" and not (rows["sys.inf"].flags() & Qt.ItemFlag.ItemIsUserCheckable)
    assert "1 in use, 1 locked, 1 unused" in window.uninstall_summary.text()
    window.uninstall_unused_cb.setChecked(True)
    assert [window.uninstall_tree.topLevelItem(i).text(0) for i in range(window.uninstall_tree.topLevelItemCount())] == ["nas.inf"]


def test_tick_the_unused_never_ticks_a_driver_in_use(window):  # noqa: F811
    listed(window, sample())
    window._tick_unused_drivers()
    from ddcleaner.ui.tab_cleanup import checked_payloads
    assert [c.package.published for c in checked_payloads(window.uninstall_tree)] == ["oem2.inf"]


def sync_calls(window, monkeypatch):
    calls = []
    monkeypatch.setattr(window, "_start_call", lambda attr, fn, done, button=None, status="": (calls.append((attr, fn, done)), True)[1])
    return calls


def tick_all(window):
    from ddcleaner.ui.tab_cleanup import set_all_checked
    set_all_checked(window.uninstall_tree, True)


def test_uninstalling_needs_a_tick_admin_rights_and_a_yes(window, dialogs, monkeypatch):  # noqa: F811
    listed(window, sample())
    window._uninstall_drivers_completely()
    assert dialogs["info"]
    tick_all(window)
    monkeypatch.setattr("ddcleaner.ui.tab_drivers.SystemUtils.check_admin_privileges", staticmethod(lambda: False))
    before = len(dialogs["warning"])
    window._uninstall_drivers_completely()
    assert len(dialogs["warning"]) == before + 1 and not dialogs["question"]
    monkeypatch.setattr("ddcleaner.ui.tab_drivers.SystemUtils.check_admin_privileges", staticmethod(lambda: True))
    calls = sync_calls(window, monkeypatch)
    dialogs["answer"] = QMessageBox.StandardButton.No
    window._uninstall_drivers_completely()
    assert dialogs["question"] and not calls
    text = dialogs["question"][-1][0]
    assert "IN USE" in text and "restore point" in text and "pnputil" not in text


def test_an_in_use_driver_gets_a_restore_point_first_and_an_unused_one_does_not(window, dialogs, monkeypatch):  # noqa: F811
    monkeypatch.setattr("ddcleaner.ui.tab_drivers.SystemUtils.check_admin_privileges", staticmethod(lambda: True))
    dialogs["answer"] = QMessageBox.StandardButton.Yes
    calls = sync_calls(window, monkeypatch)
    rows = listed(window, sample())
    rows[1].setCheckState(0, Qt.CheckState.Checked)                         # only the unused one (sorted by class/name)
    unused_row = next(r for r in rows if r.text(0) == "nas.inf")
    for r in rows:
        r.setCheckState(0, Qt.CheckState.Checked if r is unused_row else Qt.CheckState.Unchecked)
    window._uninstall_drivers_completely()
    assert [c[0] for c in calls] == ["driver_uninstall_worker"]
    calls.clear()
    next(r for r in rows if r.text(0) == "nic.inf").setCheckState(0, Qt.CheckState.Checked)
    window._uninstall_drivers_completely()
    assert [c[0] for c in calls] == ["driver_restore_worker"]


def test_without_a_restore_point_the_user_decides(window, dialogs, monkeypatch):  # noqa: F811
    chosen = [used()]
    started = []
    monkeypatch.setattr(window, "_run_driver_uninstall", lambda c: started.append(c))
    dialogs["answer"] = QMessageBox.StandardButton.No
    window._on_driver_restore_point(chosen, (False, "System Protection is off"), "")
    assert not started and "System Protection is off" in dialogs["question"][-1][0]
    dialogs["answer"] = QMessageBox.StandardButton.Yes
    window._on_driver_restore_point(chosen, (False, "x"), "")
    window._on_driver_restore_point(chosen, (True, "Restore point created."), "")
    window._on_driver_restore_point(chosen, None, "PowerShell failed")
    assert len(started) == 3


def test_the_uninstall_runs_with_the_other_packages_as_remaining(window, monkeypatch):  # noqa: F811
    listed(window, sample())
    calls = sync_calls(window, monkeypatch)
    seen = {}
    monkeypatch.setattr(du, "uninstall_completely", lambda chosen, remaining, folder, stop=None: seen.update(
        chosen=chosen, remaining=[p.published for p in remaining]) or du.UninstallResult())
    window._run_driver_uninstall([window.all_driver_candidates[0]])
    calls[0][1]()
    assert seen["remaining"] == ["oem1.inf", "oem2.inf", "oem3.inf"] and len(seen["chosen"]) == 1


def test_the_result_updates_the_list_and_offers_the_leftovers(window, dialogs, monkeypatch):  # noqa: F811
    candidates = sample()
    listed(window, candidates)
    left = du.Leftover("nicsvc", r"C:\Windows\System32\drivers\nic.sys", True, "oem1.inf")
    result = du.UninstallResult(removed=[candidates[0]], failed=[(candidates[1], "Windows refused: the driver is in use")],
                                leftovers=[left], ghosts_removed=2, reboot=True)
    calls = sync_calls(window, monkeypatch)
    dialogs["answer"] = QMessageBox.StandardButton.No
    window._on_drivers_uninstalled(result, "")
    assert [window.uninstall_tree.topLevelItem(i).text(0) for i in range(window.uninstall_tree.topLevelItemCount())] == ["nas.inf", "sys.inf"]
    info = dialogs["info"][-1][0]
    assert "nas.inf: Windows refused" in info and "2 entr" in info and "Restart" in info
    assert "service nicsvc" in dialogs["question"][-1][0] and not calls                  # declined: nothing runs
    dialogs["answer"] = QMessageBox.StandardButton.Yes
    window._on_drivers_uninstalled(du.UninstallResult(leftovers=[left]), "")
    assert [c[0] for c in calls] == ["driver_leftover_worker"]


def test_leftover_results_are_reported(window, dialogs):  # noqa: F811
    left = du.Leftover("nicsvc", "x", True, "oem1.inf")
    window._on_driver_leftovers_removed(du.LeftoverResult([left], [(left, "needs a restart")], []), "")
    assert "nicsvc: needs a restart" in dialogs["warning"][-1][0]
    window._on_driver_leftovers_removed(None, "boom")
    window._on_drivers_uninstalled(None, "boom")
    window._on_all_drivers_scanned(None, "unreadable")
    assert len(dialogs["warning"]) >= 4

# endregion
