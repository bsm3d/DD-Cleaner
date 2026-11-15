"""'Open location' everywhere, and the removal of unused driver packages. Explorer, Regedit and pnputil are replaced by
fakes; the driver store and the registry are never touched."""

import os
import types

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMessageBox, QTreeWidgetItem

from ddcleaner import driver_cleanup as dc, system_info
from ddcleaner.ui import locations
from ddcleaner.ui import tab_locations as tl
from ddcleaner.ui.locations import Place

from test_system_pages import FakeReg, nested, BS
from test_ui_smoke import dialogs, window  # noqa: F401  (fixtures)

SYSTEM_GUID = "{4d36e97d-e325-11ce-bfc1-08002be10318}"
NET_GUID = "{4d36e972-e325-11ce-bfc1-08002be10318}"
EXTENSION_GUID = "{e2f84ce7-8efa-411c-aa69-97454ca4cb57}"

ENGLISH = """Microsoft PnP Utility

Published Name:     oem14.inf
Original Name:      pnpxnas-mycloudgen2.inf
Provider Name:      Western Digital Corporation
Class Name:         Western Digital NAS
Class GUID:         {99999999-e325-11ce-bfc1-08002be10318}
Driver Version:     03/10/2019 3.1.1.2
Signer Name:        Microsoft Windows Hardware Compatibility Publisher

Published Name:     oem55.inf
Original Name:      amd3dvcache.inf
Provider Name:      Advanced Micro Devices, Inc.
Class Name:         System devices
Class GUID:         {4d36e97d-e325-11ce-bfc1-08002be10318}
Driver Version:     09/26/2025 1.0.0.12
Signer Name:        Microsoft Windows
"""
FRENCH = """Utilitaire PnP Microsoft

Nom publié :         oem3.inf
Nom d'origine :      hdwebcam.inf
Nom du fournisseur : Logitech
Nom de la classe :   Caméra
Identificateur de classe : {ca3e7ab9-b4c3-4ae6-8251-579ef933890f}
Version et date du pilote : 05/07/2021 13.1.0.7
Nom du signataire :  Microsoft Windows Hardware Compatibility Publisher
"""


def pkg(published, original, provider="Acme", cls="Net", guid=NET_GUID, version="1.0.0.0"):
    return dc.Package(published, original, provider, cls, guid, version, "01/01/2020")


def bind(name, inf, present, cls="X"):
    return dc.Binding(name, inf, present, cls)


# region Reading the driver store

def test_packages_are_read_by_position_so_the_language_does_not_matter():
    english = dc.parse_enum_drivers(ENGLISH)
    assert [(p.published, p.original, p.provider, p.version, p.date) for p in english] == [
        ("oem14.inf", "pnpxnas-mycloudgen2.inf", "Western Digital Corporation", "3.1.1.2", "03/10/2019"),
        ("oem55.inf", "amd3dvcache.inf", "Advanced Micro Devices, Inc.", "1.0.0.12", "09/26/2025")]
    assert english[0].class_name == "Western Digital NAS" and english[1].class_guid == SYSTEM_GUID
    french = dc.parse_enum_drivers(FRENCH)
    assert [(p.published, p.original, p.provider, p.version) for p in french] == [("oem3.inf", "hdwebcam.inf", "Logitech", "13.1.0.7")]
    assert dc.parse_enum_drivers("") == [] and dc.parse_enum_drivers("Published Name: c_system.inf\nOriginal Name: x\n") == []


def test_versions_compare_as_numbers():
    assert pkg("oem1.inf", "a.inf", version="10.0.0.1").version_key > pkg("oem2.inf", "a.inf", version="9.9.9.9").version_key
    assert pkg("oem1.inf", "a.inf", version="").version_key == ()


def test_listing_the_store_fails_cleanly():
    with pytest.raises(OSError):
        dc.list_packages(lambda args: (5, ""))
    assert len(dc.list_packages(lambda args: (0, ENGLISH))) == 2


def test_bindings_come_from_powershell_json():
    rows = [{"Name": "WD My Cloud", "Inf": "OEM1.INF", "Id": "SWD\\X", "Class": "NAS", "Present": False},
            {"Name": "Webcam", "Inf": "oem3.inf", "Id": "USB\\Y", "Class": "Camera", "Present": True}]
    got = dc.read_bindings(lambda script, timeout=60: rows)
    assert [(b.name, b.inf, b.present) for b in got] == [("WD My Cloud", "oem1.inf", False), ("Webcam", "oem3.inf", True)]
    assert dc.read_bindings(lambda s, t=60: rows[0])[0].name == "WD My Cloud" and dc.read_bindings(lambda s, t=60: None) == []

# endregion


# region Finding unused packages

def test_a_package_a_connected_device_uses_is_never_offered():
    packages = [pkg("oem1.inf", "used.inf"), pkg("oem2.inf", "free.inf")]
    found = dc.find_unused(packages, [bind("Cam", "oem1.inf", True), bind("Old", "oem9.inf", False)])
    assert [c.package.published for c in found] == ["oem2.inf"]


def test_the_three_kinds_of_unused_package():
    packages = [pkg("oem1.inf", "nas.inf", cls="NAS"), pkg("oem2.inf", "orphan.inf", cls="Printers"),
                pkg("oem3.inf", "net.inf", version="1.0.0.1"), pkg("oem4.inf", "net.inf", version="1.0.0.2"),
                pkg("oem5.inf", "keep.inf")]
    bindings = [bind("WD My Cloud", "oem1.inf", False), bind("Keep", "oem5.inf", True), bind("Net", "oem4.inf", True)]
    found = {c.package.published: c for c in dc.find_unused(packages, bindings)}
    assert set(found) == {"oem1.inf", "oem2.inf", "oem3.inf"}
    assert found["oem1.inf"].category == dc.CAT_GONE and "WD My Cloud" in found["oem1.inf"].reason and found["oem1.inf"].risk == "Check"
    assert found["oem2.inf"].category == dc.CAT_NONE and found["oem2.inf"].devices == []
    assert found["oem3.inf"].category == dc.CAT_OLD and "oem4.inf" in found["oem3.inf"].reason and found["oem3.inf"].risk == "Safe"


def test_core_classes_and_extensions_are_never_offered():
    packages = [pkg("oem1.inf", "sys.inf", "AMD", "System", SYSTEM_GUID), pkg("oem2.inf", "ext.inf", "Realtek", "Extensions", EXTENSION_GUID),
                pkg("oem3.inf", "ok.inf")]
    assert [c.package.published for c in dc.find_unused(packages, [bind("x", "oem99.inf", True)])] == ["oem3.inf"]


def test_unreadable_devices_mean_no_judgement_at_all():
    with pytest.raises(OSError, match="cannot be judged|nothing can be judged"):
        dc.find_unused([pkg("oem1.inf", "a.inf")], [])
    with pytest.raises(OSError):
        dc.find_unused([pkg("oem1.inf", "a.inf")], [bind("ghost", "oem1.inf", False)])        # nothing connected: suspicious


def test_scan_wires_the_two_readers_and_sorts_by_class():
    packages_out = ENGLISH.replace("oem55.inf", "oem56.inf")
    rows = [{"Name": "Keep", "Inf": "oem56.inf", "Present": True}]
    found = dc.scan(lambda args: (0, packages_out), lambda script, timeout=60: rows)
    assert [c.package.published for c in found] == ["oem14.inf"]


def test_the_store_folder_of_a_package(tmp_path):
    store = tmp_path / "FileRepository"
    for name in ("wd.inf_amd64_aaa", "wd.inf_amd64_bbb", "other.inf_amd64_ccc", "wdextra.inf_amd64_ddd"):
        (store / name).mkdir(parents=True)
    os.utime(store / "wd.inf_amd64_aaa", (1, 1))
    assert dc.store_folder("WD.inf", str(store)) == str(store / "wd.inf_amd64_bbb")        # newest, exact name
    assert dc.store_folder("missing.inf", str(store)) == "" and dc.store_folder("wd.inf", str(tmp_path / "none")) == ""

# endregion


# region Removing packages

class FakePnp:
    def __init__(self, export=0, delete=0, write=True):
        self.calls, self.export_code, self.delete_code, self.write = [], export, delete, write

    def __call__(self, args):
        self.calls.append(args)
        if args[0] == "/export-driver":
            if self.write and self.export_code == 0:
                open(os.path.join(args[2], "driver.inf"), "w").write("x")
            return self.export_code, ""
        return self.delete_code, "Failed: the driver is in use" if self.delete_code in (1, 5) else ""


def cand(published="oem14.inf", original="nas.inf", guid=NET_GUID, category=dc.CAT_GONE):
    return dc.Candidate(pkg(published, original, guid=guid), category, "why", ["WD My Cloud"])


def test_a_driver_is_saved_then_deleted_without_force(tmp_path):
    run = FakePnp()
    result = dc.remove_packages([cand()], str(tmp_path / "bk"), run)
    assert len(result.removed) == 1 and not result.failed and len(result.backups) == 1
    assert [c[0] for c in run.calls] == ["/export-driver", "/delete-driver"]
    assert run.calls[1] == ["/delete-driver", "oem14.inf"] and "/force" not in run.calls[1] and "/uninstall" not in run.calls[1]
    assert os.path.isfile(os.path.join(result.backups[0], "driver.inf")) and result.backups[0].startswith(str(tmp_path / "bk"))


def test_nothing_is_deleted_when_the_copy_fails(tmp_path):
    for run in (FakePnp(export=1), FakePnp(write=False)):
        result = dc.remove_packages([cand()], str(tmp_path / "bk"), run)
        assert "backup" in result.failed[0][1] and not result.removed and [c[0] for c in run.calls] == ["/export-driver"]


@pytest.mark.parametrize("code, word", [(1, "in use"), (5, "in use"), (87, "administrator")])
def test_a_driver_windows_refuses_stays_and_is_reported(tmp_path, code, word):
    result = dc.remove_packages([cand()], str(tmp_path), FakePnp(delete=code))
    assert word in result.failed[0][1] and not result.removed


def test_a_reboot_request_still_counts_as_removed(tmp_path):
    assert len(dc.remove_packages([cand()], str(tmp_path), FakePnp(delete=3010)).removed) == 1


def test_only_real_published_names_and_non_core_classes_reach_pnputil(tmp_path):
    run = FakePnp()
    bad = [cand("..\\evil.inf"), cand("c_system.inf"), cand("oem1.inf;calc"), cand("oem2.inf", guid=SYSTEM_GUID)]
    result = dc.remove_packages(bad, str(tmp_path), run)
    assert len(result.failed) == 4 and run.calls == []
    assert dc.remove_packages([cand()], str(tmp_path), FakePnp(), stop=lambda: True).failed[0][1] == "Stopped"


def test_a_failing_pnputil_is_an_error_not_a_crash(tmp_path):
    def boom(args):
        raise OSError("pnputil missing")
    assert "pnputil missing" in dc.remove_packages([cand()], str(tmp_path), boom).failed[0][1]

# endregion


# region Places

def test_registry_text_becomes_a_place():
    assert locations.parse_registry(r"HKLM\SOFTWARE\Vendor\App") == Place(hive="HKLM", key=r"SOFTWARE\Vendor\App")
    assert locations.parse_registry(r"HKEY_CURRENT_USER\Software\X") == Place(hive="HKCU", key=r"Software\X")
    assert locations.parse_registry(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (32-bit)").key == \
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    assert locations.parse_registry(r"HKCU\Software\X  [Value]").key == r"Software\X"
    assert locations.parse_registry(r"Task Scheduler \Acme") is None and locations.parse_registry("") is None
    assert locations.parse_registry(r"C:\Program Files") is None and locations.parse_registry(r"HKU\x") is None


def test_the_place_flags():
    assert Place().empty and not Place(path="C:\\x").empty and Place(hive="HKLM", key="k").has_key
    assert Place(hive="HKLM", key="SOFTWARE\\k").text == "HKLM\\SOFTWARE\\k" and Place(path="C:\\x").text == "C:\\x"


def test_explorer_selects_a_file_opens_a_folder_and_falls_back_to_the_nearest_folder(tmp_path):
    calls = []
    popen = lambda args, **kw: calls.append(args)
    f = tmp_path / "a" / "x.exe"
    f.parent.mkdir()
    f.write_bytes(b"MZ")
    assert locations.reveal(str(f), popen) == "" and calls[-1][1:] == ["/select,", str(f)]
    assert locations.reveal(str(f.parent), popen) == "" and calls[-1][1:] == [str(f.parent)]
    gone = locations.reveal(str(f.parent / "deep" / "gone.exe"), popen)
    assert "no longer exists" in gone and calls[-1][1:] == [str(f.parent)]
    assert locations.reveal("", popen) and locations.reveal('"' + str(f) + '"', popen) == ""
    assert locations.reveal("Z:\\nowhere\\x.exe", popen) == "This location no longer exists." or "no longer exists" in locations.reveal("Z:\\nowhere\\x.exe", popen)


def test_regedit_is_pointed_at_the_key_through_its_last_key_setting():
    written, launched = {}, []

    class Handle:
        def __enter__(self): return self
        def __exit__(self, *exc): return False

    reg = types.SimpleNamespace(HKEY_CURRENT_USER="HKCU", REG_SZ=1, CreateKey=lambda hive, path: (written.update(path=path), Handle())[1],
                                SetValueEx=lambda h, name, r, t, value: written.update(name=name, value=value))
    message = locations.open_in_regedit("HKLM", r"SOFTWARE\Vendor", lambda args, **kw: launched.append(args), reg)
    assert written == {"path": locations.REGEDIT_KEY, "name": "LastKey", "value": r"Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Vendor"}
    assert launched[0][0].lower().endswith("regedit.exe") and "Regedit opened" in message
    assert locations.open_in_regedit("HKU", "x", lambda *a, **k: None, reg) and locations.open_in_regedit("HKLM", "", lambda *a, **k: None, reg)

    def denied(hive, path):
        raise PermissionError("denied")
    assert "could not be opened" in locations.open_in_regedit("HKCU", "Software", lambda *a, **k: None,
                                                               types.SimpleNamespace(HKEY_CURRENT_USER=1, CreateKey=denied))


def test_the_menu_offers_what_the_place_allows():
    copied = []
    both = locations.actions_for(Place(path="C:\\x", hive="HKLM", key="k"), copied.append)
    assert [label for label, _ in both] == ["📂 Open location", "🧩 Open in Regedit", "📋 Copy path"]
    assert [label for label, _ in locations.actions_for(Place(hive="HKCU", key="Software\\X"), copied.append)] == \
        ["🧩 Open in Regedit", "📋 Copy path"]
    assert locations.actions_for(Place(), copied.append) == []
    both[2][1]()
    assert copied == ["C:\\x"]

# endregion


# region What each list points to

def holder(payload=None, text=("", "", "", "", "")):
    item = QTreeWidgetItem(list(text))
    if payload is not None:
        item.setData(0, Qt.ItemDataRole.UserRole, payload)
    return item


def test_each_list_resolves_its_rows(tmp_path):
    exe = tmp_path / "app.exe"
    exe.write_bytes(b"MZ")
    ns = types.SimpleNamespace
    assert tl.process_place(holder(ns(path=str(exe)))).path == str(exe)
    assert tl.garbage_place(holder(ns(path="C:\\g"))).path == "C:\\g"
    assert tl.program_place(holder(ns(location="C:\\Program Files\\X"))).path == "C:\\Program Files\\X"
    assert tl.quarantine_place(holder(ns(stored="C:\\q\\bad.exe"))).path == "C:\\q\\bad.exe"
    assert tl.registry_place(holder(ns(hive="HKCU", key="Software\\X"))) == Place(hive="HKCU", key="Software\\X")
    assert tl.text_place(0)(holder(None, ("C:\\threat.exe", "", "", "", ""))).path == "C:\\threat.exe"
    assert tl.process_place(holder(None)).empty and tl.registry_place(holder(None)).empty


def test_a_finding_prefers_its_file_then_its_registry_key_then_its_folder(tmp_path):
    ns = types.SimpleNamespace
    exe = tmp_path / "svc.exe"
    exe.write_bytes(b"MZ")
    assert tl.finding_place(holder(ns(path=str(exe), location="HKLM\\SYSTEM\\X"))).path == str(exe)
    assert tl.finding_place(holder(ns(path=str(tmp_path / "gone.exe"), location=r"HKLM\SYSTEM\CurrentControlSet\Services\Svc"))) == \
        Place(hive="HKLM", key=r"SYSTEM\CurrentControlSet\Services\Svc")
    assert tl.finding_place(holder(ns(path="", location=str(tmp_path)))).path == str(tmp_path)         # a browser extension
    assert tl.finding_place(holder(ns(path="", location="Task Scheduler \\Acme as me"))).empty


def test_a_startup_entry_points_to_its_program_or_its_run_key(tmp_path):
    ns = types.SimpleNamespace
    exe = tmp_path / "x.exe"
    exe.write_bytes(b"MZ")
    assert tl.startup_place(holder(ns(path=str(exe), kind="Registry", location="HKCU\\SOFTWARE\\Run"))).path == str(exe)
    gone = tl.startup_place(holder(ns(path="", kind="Registry", location=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (32-bit)")))
    assert gone.has_key and "WOW6432Node" in gone.key
    assert tl.startup_place(holder(ns(path="", kind="Task", location="Task Scheduler \\"))).empty


def test_a_driver_listed_by_its_inf_name_points_into_the_inf_folder():
    place = tl.inf_place(holder(None, ("", "", "", "", "oem12.inf")))
    assert place.path.lower().endswith(os.path.join("inf", "oem12.inf"))
    assert tl.inf_place(holder(None, ("", "", "", "", r"C:\x\y.inf"))).path == r"C:\x\y.inf" and tl.inf_place(holder(None)).empty


def test_an_unused_driver_points_to_its_folder_in_the_driver_store(monkeypatch, tmp_path):
    monkeypatch.setattr(dc, "store_folder", lambda original, store=None: str(tmp_path) if original == "nas.inf" else "")
    assert tl.unused_driver_place(holder(cand())).path == str(tmp_path)
    assert tl.unused_driver_place(holder(cand(original="other.inf"))).empty

# endregion


# region Installed programs know where they are

def test_installed_programs_carry_their_folder():
    key = system_info.UNINSTALL_KEY
    reg = FakeReg({("HKLM", "64"): nested(key, {
        "A": {"DisplayName": "Tool", "InstallLocation": "C:\\Program Files\\Tool\\"},
        "B": {"DisplayName": "FromIcon", "DisplayIcon": '"D:\\Apps\\Icon App\\app.exe",0'},
        "C": {"DisplayName": "FromUninstall", "UninstallString": '"E:\\Soft\\Z\\unins000.exe" /SILENT'},
        "D": {"DisplayName": "Msi", "UninstallString": "MsiExec.exe /X{GUID}", "DisplayIcon": "C:\\Windows\\Installer\\{G}\\i.exe"},
        "E": {"DisplayName": "Nothing"}})})
    folders = {p.name: p.location for p in system_info.installed_programs(reg)}
    assert folders == {"FromIcon": "D:\\Apps\\Icon App", "FromUninstall": "E:\\Soft\\Z", "Msi": "", "Nothing": "",
                       "Tool": "C:\\Program Files\\Tool"}
    assert system_info.Program("n", "1", "p", "All users").location == ""

# endregion


# region The window

def test_every_list_gets_a_location_menu(window):  # noqa: F811
    assert set(window.location_resolvers) == {"process_tree", "hunt_tree", "startup_tree", "program_tree", "garbage_tree",
                                              "registry_tree", "clam_threat_tree", "clam_quarantine_tree", "unused_tree", "uninstall_tree"}
    for name in window.location_resolvers:
        assert getattr(window, name).contextMenuPolicy() == Qt.ContextMenuPolicy.CustomContextMenu


def test_the_open_location_buttons_use_the_selected_row(window, dialogs, monkeypatch, tmp_path):  # noqa: F811
    window._open_selected_location("garbage_tree")
    assert dialogs["info"]
    opened = []
    monkeypatch.setattr(locations, "reveal", lambda path: opened.append(("path", path)) or "")
    monkeypatch.setattr(locations, "open_in_regedit", lambda hive, key: opened.append(("key", hive, key)) or "")
    from ddcleaner import garbage
    window._on_garbage_scanned(garbage.FileScan([garbage.GarbageItem(str(tmp_path / "x.tmp"), "File", 1)]), "")
    window.garbage_tree.topLevelItem(0).setSelected(True)
    window._open_selected_location("garbage_tree")
    from ddcleaner import dead_registry
    window._on_registry_scanned(dead_registry.RegScan([dead_registry.RegEntry("HKCU", "SOFTWARE\\Vendor", None, "Key", "r")]), "")
    window.registry_tree.topLevelItem(0).setSelected(True)
    window._open_selected_location("registry_tree", prefer_registry=True)
    assert opened == [("path", str(tmp_path / "x.tmp")), ("key", "HKCU", "SOFTWARE\\Vendor")]


def test_the_inventory_lists_the_program_folder(window):  # noqa: F811
    window.programs = [system_info.Program("7-Zip", "25", "Igor", "All users", "C:\\Program Files\\7-Zip")]
    window._filter_programs()
    item = window.program_tree.topLevelItem(0)
    assert item.toolTip(0) == "C:\\Program Files\\7-Zip"
    item.setSelected(True)
    assert window._selected_place("program_tree").path == "C:\\Program Files\\7-Zip"


def test_driver_pages_include_the_unused_drivers(window):  # noqa: F811
    pages = window.tab_widget.widget(0)
    assert [pages.tabText(i) for i in range(pages.count())] == ["Vulnerable drivers", "Driver age", "Unused drivers", "Uninstall drivers"]


def show_unused(window, candidates):
    window._on_unused_drivers_scanned(candidates, "")
    return [window.unused_tree.topLevelItem(i) for i in range(window.unused_tree.topLevelItemCount())]


def test_unused_drivers_are_listed_unticked_with_their_risk(window):  # noqa: F811
    rows = show_unused(window, [cand(), cand("oem3.inf", "old.inf", category=dc.CAT_OLD)])
    assert [r.text(5) for r in rows] == ["Check", "Safe"] and all(r.checkState(0) == Qt.CheckState.Unchecked for r in rows)
    assert "1 older version" in window.unused_summary.text() and "1 for hardware" in window.unused_summary.text()
    assert rows[1].foreground(0).color().green() > 100                  # the safe ones are green


def test_removing_drivers_needs_a_tick_admin_rights_and_a_yes(window, dialogs, monkeypatch):  # noqa: F811
    from ddcleaner.ui import tab_cleanup
    show_unused(window, [cand()])
    window._remove_unused_drivers()
    assert dialogs["info"] and not dialogs["question"]
    tab_cleanup.set_all_checked(window.unused_tree, True)
    monkeypatch.setattr("ddcleaner.ui.tab_drivers.SystemUtils.check_admin_privileges", staticmethod(lambda: False))
    before = len(dialogs["warning"])
    window._remove_unused_drivers()
    assert len(dialogs["warning"]) == before + 1 and not dialogs["question"]
    monkeypatch.setattr("ddcleaner.ui.tab_drivers.SystemUtils.check_admin_privileges", staticmethod(lambda: True))
    started = []
    monkeypatch.setattr(window, "_start_call", lambda *a, **k: started.append(a) or True)
    dialogs["answer"] = QMessageBox.StandardButton.No
    window._remove_unused_drivers()
    assert dialogs["question"] and not started and "pnputil /add-driver" in dialogs["question"][-1][0]
    dialogs["answer"] = QMessageBox.StandardButton.Yes
    window._remove_unused_drivers()
    assert started and started[0][0] == "driver_remove_worker"


def test_removed_drivers_leave_the_list_and_failures_are_shown(window, dialogs):  # noqa: F811
    good, bad = cand("oem1.inf", "good.inf"), cand("oem2.inf", "bad.inf")
    show_unused(window, [good, bad])
    window._on_unused_drivers_removed(dc.RemoveResult([good], [(bad, "Windows refused: the driver is in use")], ["b"]), "")
    assert window.unused_tree.topLevelItemCount() == 1 and window.unused_tree.topLevelItem(0).text(0) == "bad.inf"
    assert "bad.inf: Windows refused" in dialogs["warning"][-1][0] and "1 driver package(s) removed" in window.unused_summary.text()
    window._on_unused_drivers_removed(None, "boom")
    assert len(dialogs["warning"]) >= 2


def test_a_failed_comparison_is_explained(window, dialogs):  # noqa: F811
    window._on_unused_drivers_scanned(None, "devices unreadable")
    assert dialogs["warning"]

# endregion
