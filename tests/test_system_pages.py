"""Startup programs, inventory, DPC/ISR load and saved passwords: logic with fake registry / PowerShell, and the
pages of the System Health tab. Nothing real is read except the Windows folder layout."""

import ctypes
import logging
import os
import types

import pytest
from PySide6.QtWidgets import QMessageBox, QDialog, QTreeWidget
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest

from ddcleaner import startup, system_info, saved_keys
from ddcleaner.common import SYSTEM_ROOT, SYSTEM32
from ddcleaner.ui import tab_system_info

from test_ui_smoke import dialogs, window, close_event, FakeRunning  # noqa: F401  (fixtures)

BS = chr(92)


# region Fake registry (nested dicts)

class Node:
    def __init__(self, tree):
        self.tree = tree

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeReg:
    HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER = "HKLM", "HKCU"
    KEY_READ, KEY_WOW64_64KEY, KEY_WOW64_32KEY = 1, 2, 4

    def __init__(self, trees):
        self.trees = trees  # (hive, view) -> nested dict; leaves: values, dicts: keys

    def OpenKey(self, parent, path, reserved=0, access=0):
        if isinstance(parent, Node):
            tree, view = parent.tree, None
        else:
            view = "32" if access & self.KEY_WOW64_32KEY else "64"
            tree = self.trees.get((parent, view), {})
        for part in [p for p in path.split(BS) if p]:
            if not isinstance(tree, dict) or part not in tree or not isinstance(tree[part], dict):
                raise FileNotFoundError(2, "key not found")
            tree = tree[part]
        return Node(tree)

    def EnumKey(self, node, index):
        keys = [k for k, v in node.tree.items() if isinstance(v, dict)]
        if index >= len(keys):
            raise OSError(259, "no more")
        return keys[index]

    def EnumValue(self, node, index):
        values = [(k, v) for k, v in node.tree.items() if not isinstance(v, dict)]
        if index >= len(values):
            raise OSError(259, "no more")
        return values[index][0], values[index][1], 1

    def QueryValueEx(self, node, name):
        if name not in node.tree or isinstance(node.tree[name], dict):
            raise FileNotFoundError(2, "value not found")
        return node.tree[name], 1


def nested(path, content):
    tree = content
    for part in reversed(path.split(BS)):
        tree = {part: tree}
    return tree

# endregion


# region Startup programs

def test_command_path_handles_quotes_spaces_and_variables(tmp_path, monkeypatch):
    folder = tmp_path / "Program Files" / "App"
    folder.mkdir(parents=True)
    exe = folder / "app.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setenv("APPROOT", str(folder))
    assert startup.command_path(f'"{exe}" --minimized') == str(exe)
    assert startup.command_path(f"{exe} /s /q") == str(exe)                    # unquoted path with spaces
    assert startup.command_path("%APPROOT%" + BS + "app.exe -x") == str(exe)
    assert startup.command_path(f'"{folder}{BS}missing.exe"') == ""
    assert startup.command_path("") == ""


def test_command_path_looks_up_bare_names_in_windows_folders_only(tmp_path, monkeypatch):
    assert startup.command_path("cmd.exe /c echo") == os.path.join(SYSTEM32, "cmd.exe")
    (tmp_path / "planted.exe").write_bytes(b"MZ")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert startup.command_path("planted.exe") == ""  # neither the current folder nor PATH is searched


def test_command_path_resolves_bare_names_with_no_extension_via_pathext():
    # Windows runs "rundll32 shell32.dll,Foo" and "cmd /c echo" without an explicit .exe; before the fix these
    # were never resolved and wrongly came back as FLAG_MISSING
    assert startup.command_path("cmd /c echo hi") == os.path.join(SYSTEM32, "cmd.exe")
    assert startup.command_path("rundll32 shell32.dll,Foo") == os.path.join(SYSTEM32, "rundll32.exe")


def test_command_path_resolves_an_extensionless_quoted_full_path(tmp_path):
    exe = tmp_path / "tool.exe"
    exe.write_bytes(b"MZ")
    assert startup.command_path(f'"{tmp_path / "tool"}" -x') == str(exe)


def test_command_path_does_not_reguess_an_explicit_wrong_extension(tmp_path):
    # a real .exe named .ocx on purpose must not resolve to the unrelated real .exe beside it
    (tmp_path / "thing.exe").write_bytes(b"MZ")
    assert startup.command_path(f'"{tmp_path / "thing.ocx"}"') == ""


def test_command_path_prefers_the_name_as_written_over_a_pathext_guess(tmp_path):
    (tmp_path / "tool.bat").write_bytes(b"@echo off")
    (tmp_path / "tool.exe").write_bytes(b"MZ")
    assert startup.command_path(f'"{tmp_path / "tool.bat"}"') == str(tmp_path / "tool.bat")


def test_run_keys_are_read_for_both_views_and_scopes():
    run = BS.join(["SOFTWARE", "Microsoft", "Windows", "CurrentVersion", "Run"])
    reg = FakeReg({
        ("HKLM", "64"): nested(run, {"Tool": r"C:\a\tool.exe -x", "Empty": ""}),
        ("HKLM", "32"): nested(run, {"Old32": r"C:\a\old.exe"}),
        ("HKCU", "64"): nested(run, {"Mine": r"C:\u\mine.exe"}),
    })
    entries = startup.read_run_keys(reg)
    summary = {(e.name, e.scope, "(32-bit)" in e.location) for e in entries}
    assert summary == {("Tool", startup.ALL_USERS, False), ("Old32", startup.ALL_USERS, True),
                       ("Mine", startup.CURRENT_USER, False)}
    assert all(e.kind == "Registry" for e in entries)


def test_startup_folders_skip_desktop_ini(tmp_path):
    (tmp_path / "desktop.ini").write_text("x")
    (tmp_path / "x.lnk").write_bytes(b"L")
    entries = startup.read_startup_folders({startup.CURRENT_USER: str(tmp_path), startup.ALL_USERS: str(tmp_path / "nope")})
    assert [(e.name, e.kind, e.scope) for e in entries] == [("x.lnk", "Folder", startup.CURRENT_USER)]


def test_logon_tasks_from_powershell_json():
    one = {"Name": "Sync", "Path": BS + "Acme" + BS, "Exec": r"C:\Program Files\Acme\sync.exe", "Args": "/auto",
           "User": "SYSTEM", "Level": "Highest"}
    entries = startup.read_logon_tasks(lambda script: one)               # PowerShell prints a single object as a dict
    assert len(entries) == 1
    assert entries[0].command == r'"C:\Program Files\Acme\sync.exe" /auto'
    assert "highest" in entries[0].scope.lower() and entries[0].kind == "Task"
    assert startup.read_logon_tasks(lambda script: [{"Name": "NoAction", "Exec": ""}]) == []
    assert startup.read_logon_tasks(lambda script: None) == []

    def broken(script):
        raise ValueError("bad json")
    assert startup.read_logon_tasks(broken) == []


def test_shortcut_targets_replace_the_lnk(tmp_path):
    target = tmp_path / "real.exe"
    target.write_bytes(b"MZ")
    link = tmp_path / "real.lnk"
    link.write_bytes(b"L")
    entries = startup.read_startup_folders({startup.CURRENT_USER: str(tmp_path)})
    entries = [e for e in entries if e.name == "real.lnk"]
    startup.resolve_shortcuts(entries, lambda script: [{"Link": str(link), "Target": str(target)}])
    assert entries[0].path == str(target) and "real.exe" in entries[0].command


def stub_signer(signer="", error=""):
    return lambda path: types.SimpleNamespace(signer=signer, error=error)


def entry_for(path, scope, kind="Registry"):
    return startup.StartupEntry("x", f'"{path}"', "HKLM", kind, scope)


def test_inspect_flags_missing_unsigned_and_writable(tmp_path):
    exe = tmp_path / "prog.exe"
    exe.write_bytes(b"MZ")
    missing = entry_for(tmp_path / "gone.exe", startup.ALL_USERS)
    startup.inspect_entry(missing, stub_signer(), lambda folder: [])
    assert missing.flags == [startup.FLAG_MISSING] and missing.severity == 1

    risky = entry_for(exe, startup.ALL_USERS)
    startup.inspect_entry(risky, stub_signer(), lambda folder: ["Users"])
    assert risky.flags == [startup.FLAG_UNSIGNED, startup.FLAG_WRITABLE] and risky.severity == 2

    signed = entry_for(exe, startup.ALL_USERS)
    startup.inspect_entry(signed, stub_signer("Acme Corp"), lambda folder: [])
    assert signed.flags == [] and signed.signer == "Acme Corp" and signed.severity == 0


def test_user_scope_entries_do_not_ask_about_folder_rights(tmp_path):
    exe = tmp_path / "prog.exe"
    exe.write_bytes(b"MZ")
    mine = entry_for(exe, startup.CURRENT_USER)

    def forbidden(folder):
        raise AssertionError("folder rights are only relevant for everybody / highest privileges")
    startup.inspect_entry(mine, stub_signer("Me"), forbidden)
    assert mine.flags == []
    task = entry_for(exe, "SYSTEM (highest privileges)", kind="Task")
    startup.inspect_entry(task, stub_signer("Me"), lambda folder: ["Users"])
    assert startup.FLAG_WRITABLE in task.flags


def test_windows_files_are_not_flagged_as_unsigned():
    entry = entry_for(os.path.join(SYSTEM32, "cmd.exe"), startup.CURRENT_USER)
    startup.inspect_entry(entry, stub_signer(""), lambda folder: [], lambda path: _insp())
    assert entry.flags == []


def _insp(**kw):
    from ddcleaner.file_inspect import FileInspection
    return FileInspection(path=kw.get("path", "x"), **{k: v for k, v in kw.items() if k != "path"})


def test_startup_flags_an_executable_hiding_under_a_document_name(tmp_path):
    exe = tmp_path / "update.pdf"
    exe.write_bytes(b"MZ" + b"\x00" * 64)
    entry = startup.StartupEntry("Updater", f'"{exe}"', "HKCU", "Registry", startup.CURRENT_USER)
    startup.inspect_entry(entry, stub_signer("Acme"), lambda folder: [])  # real file_inspect
    assert entry.dangerous_content and entry.severity == 2
    assert any("not a .pdf" in f for f in entry.flags)


def test_startup_flags_a_packed_executable(tmp_path):
    exe = tmp_path / "tool.exe"
    exe.write_bytes(b"MZ" + b"\x00" * 62 + os.urandom(200000))
    entry = startup.StartupEntry("Tool", f'"{exe}"', "HKCU", "Registry", startup.CURRENT_USER)
    startup.inspect_entry(entry, stub_signer("Acme"), lambda folder: [])
    assert not entry.dangerous_content and entry.severity == 1
    assert any("packed" in f for f in entry.flags)

# endregion


# region Inventory and load

def test_installed_programs_skip_updates_and_system_components():
    key = system_info.UNINSTALL_KEY
    reg = FakeReg({
        ("HKLM", "64"): nested(key, {
            "A": {"DisplayName": "Tool", "DisplayVersion": "1.0", "Publisher": "Acme"},
            "B": {"DisplayName": "Hidden", "SystemComponent": 1},
            "C": {"DisplayName": "Child", "ParentKeyName": "OperatingSystem"},
            "D": {"DisplayName": "KB5000001"},
            "E": {"DisplayName": "Update for Something"},
            "F": {"DisplayVersion": "9"},
        }),
        ("HKLM", "32"): nested(key, {"A2": {"DisplayName": "Tool", "DisplayVersion": "1.0"},   # duplicate
                                     "G": {"DisplayName": "Old tool 32"}}),
        ("HKCU", "64"): nested(key, {"H": {"DisplayName": "Per-user app", "DisplayVersion": "2"}}),
    })
    programs = system_info.installed_programs(reg)
    assert [(p.name, p.scope) for p in programs] == [
        ("Old tool 32", "All users (32-bit)"), ("Per-user app", "Current user"), ("Tool", "All users")]


def test_video_memory_comes_from_the_driver_key_not_the_32_bit_field():
    four_gb = 4 * 1024 ** 3 - 1
    reg = FakeReg({("HKLM", "64"): nested(system_info.GPU_CLASS_KEY, {
        "0000": {"DriverDesc": "Big GPU", "HardwareInformation.qwMemorySize": 11 * 1024 ** 3},
        "0001": {"DriverDesc": "No memory info"},
        "Properties": {"x": 1},
    })})
    memory = system_info.gpu_memory_by_name(reg)
    assert memory == {"Big GPU": 11 * 1024 ** 3}
    cards = system_info.graphics_cards(
        lambda script: [{"Name": "Big GPU", "Driver": "1.2", "Date": "2025-01-01", "Ram": four_gb, "W": 1920, "H": 1200, "Hz": 60},
                        {"Name": "Basic", "Driver": "9", "Date": "", "Ram": 1024 ** 3, "W": None, "H": None, "Hz": None}],
        memory)
    assert [(c.name, c.vram_gb) for c in cards] == [("Big GPU", 11.0), ("Basic", 1.0)]
    assert cards[0].resolution == "1920x1200 @ 60 Hz" and cards[1].resolution == ""


def test_activation_exposes_only_the_end_of_the_key():
    data = {"Edition": "Windows 10 Home", "Build": "19045", "Status": 1, "Channel": "Retail", "Partial": "ABCDE"}
    result = system_info.windows_activation(lambda script: data)
    assert result["status"] == "Licensed" and result["partial_key"] == "ABCDE" and result["licensed"] == "True"
    assert system_info.windows_activation(lambda script: None) == {}
    assert "ProductKey" not in system_info.ACTIVATION_PS.replace("PartialProductKey", "").replace("ProductKeyChannel", "")


@pytest.mark.parametrize("dpc, isr, word", [([0.1, 0.4], [0.0], "Low"), ([1.5], [0.2], "Moderate"), ([0.2], [4.0], "High")])
def test_load_verdict(dpc, isr, word):
    assert system_info.LoadResult(dpc, isr).verdict.startswith(word)


def test_measure_accepts_one_sample_and_reports_failures():
    result = system_info.measure_dpc_isr(1, lambda script, timeout=0: {"Dpc": 0.5, "Isr": 0.25})  # single value, not a list
    assert result.dpc == [0.5] and result.isr == [0.25]
    with pytest.raises(RuntimeError):
        system_info.measure_dpc_isr(1, lambda script, timeout=0: None)


def test_load_script_uses_wmi_not_translated_counter_names():
    script = system_info.load_script(5)
    assert "Win32_PerfFormattedData_PerfOS_Processor" in script and "Get-Counter" not in script

# endregion


# region Saved passwords

WLAN_NS = "http://www.microsoft.com/networking/WLAN/profile/v1"


def profile_xml(name="Home", auth="WPA2PSK", enc="AES", key="s3cret pass", protected="false", extra=""):
    shared = (f"<sharedKey><keyType>passPhrase</keyType><protected>{protected}</protected>"
              f"<keyMaterial>{key}</keyMaterial></sharedKey>") if key is not None else ""
    return (f'<?xml version="1.0"?><WLANProfile xmlns="{WLAN_NS}"><name>{name}</name><MSM><security>'
            f"<authEncryption><authentication>{auth}</authentication><encryption>{enc}</encryption></authEncryption>"
            f"{shared}</security></MSM>{extra}</WLANProfile>")


def test_profile_with_a_readable_password():
    p = saved_keys.parse_profile_xml(profile_xml())
    assert (p.name, p.authentication, p.encryption, p.password, p.readable) == ("Home", "WPA2PSK", "AES", "s3cret pass", True)


def test_profile_whose_key_is_still_encrypted_is_not_readable():
    p = saved_keys.parse_profile_xml(profile_xml(protected="true", key="0100DEADBEEF"))
    assert p.password == "" and p.readable is False   # the ciphertext is never shown as if it were the password


def test_open_network_has_no_password():
    p = saved_keys.parse_profile_xml(profile_xml(auth="open", enc="none", key=None))
    assert p.password == "" and p.readable is True


def test_profiles_with_a_dtd_are_refused():
    evil = '<!DOCTYPE x [<!ENTITY a "aaaa">]>' + profile_xml(name="&a;")
    with pytest.raises(ValueError):
        saved_keys.parse_profile_xml(evil)


def test_wlan_structures_match_the_windows_layout():
    assert ctypes.sizeof(saved_keys.GUID) == 16
    assert ctypes.sizeof(saved_keys.WLAN_INTERFACE_INFO) == 16 + 512 + 4
    assert ctypes.sizeof(saved_keys.WLAN_PROFILE_INFO) == 512 + 4
    assert saved_keys.WLAN_INTERFACE_INFO_LIST.Items.offset == 8
    assert saved_keys.WLAN_PROFILE_INFO_LIST.Items.offset == 8


def test_firmware_key_must_look_like_a_product_key():
    good = "ABCDE-12345-FGHIJ-67890-KLMNO"
    assert saved_keys.windows_firmware_key(lambda script: good) == good
    assert saved_keys.windows_firmware_key(lambda script: "") is None
    assert saved_keys.windows_firmware_key(lambda script: "not a key") is None
    assert saved_keys.windows_firmware_key(lambda script: None) is None

# endregion


# region Pages

def test_health_tab_has_the_new_pages(window):  # noqa: F811
    health_tabs = window.tab_widget.widget(1)
    names = [health_tabs.tabText(i) for i in range(health_tabs.count())]
    assert names == ["Health report", "Repair tools", "Startup programs", "DPC / ISR load", "Inventory"]


def fake_entries(tmp_path):
    exe = tmp_path / "evil.exe"
    exe.write_bytes(b"MZ")
    risky = startup.StartupEntry("Updater", f'"{exe}"', "HKLM", "Registry", startup.ALL_USERS, path=str(exe),
                                 exists=True, flags=[startup.FLAG_WRITABLE])
    fine = startup.StartupEntry("Fine", "x", "HKCU", "Registry", startup.CURRENT_USER)
    return risky, fine, exe


def test_startup_results_are_colored_by_severity(window, tmp_path):  # noqa: F811
    risky, fine, _ = fake_entries(tmp_path)
    window._on_startup_scanned([risky, fine], "")
    assert "1 replaceable" in window.startup_summary.text()
    rows = {window.startup_tree.topLevelItem(i).text(0): window.startup_tree.topLevelItem(i)
            for i in range(window.startup_tree.topLevelItemCount())}
    assert rows["Updater"].foreground(0).color().red() == 255
    assert rows["Fine"].foreground(0).style() == Qt.BrushStyle.NoBrush


def test_startup_scan_with_clamav_sends_the_selected_files(window, tmp_path, monkeypatch):  # noqa: F811
    risky, fine, exe = fake_entries(tmp_path)
    window._on_startup_scanned([risky, fine], "")
    started = []
    monkeypatch.setattr(window, "_start_clam_scan", lambda paths: started.append(paths))
    window._scan_startup_with_clamav()                      # nothing selected: every program that has a file
    assert started == [[str(exe)]]
    assert window.tab_widget.currentWidget() is window.clam_tab_page
    assert window._clam_target_paths() == []                # the user's own "Items to scan" list is left alone


def test_startup_scan_with_clamav_needs_a_listing(window, dialogs):  # noqa: F811
    window._scan_startup_with_clamav()
    assert dialogs["info"]


def test_startup_scan_with_clamav_does_not_replace_targets_of_a_running_scan(window, dialogs, tmp_path):  # noqa: F811
    """Before the fix, the target list and the active tab were changed before checking for a running scan:
    clicking 'Scan with ClamAV' from Startup while a scan is in progress silently swapped out the user's
    in-progress target list."""
    risky, fine, exe = fake_entries(tmp_path)
    window._on_startup_scanned([risky, fine], "")
    window.clam_scan_worker = FakeRunning()
    window._set_clam_targets([r"C:\users_own_choice"])
    window._scan_startup_with_clamav()
    assert dialogs["info"]  # "already running", from _clam_busy()
    assert window._clam_target_paths() == [r"C:\users_own_choice"]  # untouched


def test_load_result_is_shown(window):  # noqa: F811
    window._on_load_measured(system_info.LoadResult([0.2, 3.5], [0.1]), "")
    text = window.load_result.text()
    assert "max 3.50 %" in text and "High" in text
    window._on_load_measured(None, "no counters")
    assert "no counters" in window.load_result.text()


def test_program_filter_matches_name_and_publisher(window):  # noqa: F811
    window.programs = [system_info.Program("7-Zip", "25", "Igor Pavlov", "All users"),
                       system_info.Program("Notepad++", "8", "Don Ho", "All users")]
    window.program_filter.setText("pavlov")
    assert window.program_tree.topLevelItemCount() == 1
    window.program_filter.setText("")
    assert window.program_tree.topLevelItemCount() == 2


def test_secrets_need_administrator_and_a_confirmation(window, dialogs, monkeypatch):  # noqa: F811
    monkeypatch.setattr(tab_system_info.SystemUtils, "check_admin_privileges", staticmethod(lambda: False))
    window._show_saved_secrets()
    assert dialogs["warning"] and not dialogs["question"]
    monkeypatch.setattr(tab_system_info.SystemUtils, "check_admin_privileges", staticmethod(lambda: True))
    dialogs["answer"] = QMessageBox.StandardButton.No
    window._show_saved_secrets()
    assert dialogs["question"] and getattr(window, "secrets_worker", None) is None


def test_secrets_are_hidden_until_shown_and_never_logged(window, monkeypatch, caplog):  # noqa: F811
    seen = {}

    def inspect(dialog):
        tree = dialog.findChild(QTreeWidget)
        seen["rows"] = [[tree.topLevelItem(i).text(c) for c in range(4)] for i in range(tree.topLevelItemCount())]
        buttons = {b.text(): b for b in dialog.findChildren(type(window.load_btn))}
        buttons["👁 Show"].click()
        seen["shown"] = [tree.topLevelItem(i).text(3) for i in range(tree.topLevelItemCount())]
        seen["tree"] = tree
        return 0

    monkeypatch.setattr(QDialog, "exec", inspect)
    caplog.set_level(logging.DEBUG)
    from ddcleaner.saved_keys import SecretRecord
    records = [SecretRecord("Wi-Fi", "Home", "WPA2PSK / AES", "hunter2 hunter2"),
               SecretRecord("Wi-Fi", "Cafe", "open", "", note="open or enterprise network"),
               SecretRecord("Edge", "mail.site", "me@site", "", readable=False, note="could not decrypt"),
               SecretRecord("Windows key", "Firmware", "OEM", "ABCDE-12345-FGHIJ-67890-KLMNO")]
    window._on_secrets_read(records, "")
    hidden = tab_system_info.HIDDEN
    assert [r[3] for r in seen["rows"]] == [hidden, "(open or enterprise network)", "(could not decrypt)", hidden]
    assert not any("hunter2" in c for r in seen["rows"] for c in r)
    assert seen["shown"][0] == "hunter2 hunter2" and seen["shown"][3] == "ABCDE-12345-FGHIJ-67890-KLMNO"
    assert seen["tree"].topLevelItemCount() == 0             # emptied when the window closes
    assert "hunter2" not in caplog.text and "ABCDE-12345" not in caplog.text


def test_copied_secret_is_cleared_from_the_clipboard(qapp, monkeypatch):
    from PySide6.QtWidgets import QApplication
    monkeypatch.setattr(tab_system_info, "CLIPBOARD_CLEAR_MS", 20)
    tab_system_info.SystemInfoTabMixin._copy_secret("topsecret")
    assert QApplication.clipboard().text() == "topsecret"
    QTest.qWait(150)
    assert QApplication.clipboard().text() == ""
    # something copied afterwards is left alone
    tab_system_info.SystemInfoTabMixin._copy_secret("old")
    QApplication.clipboard().setText("something else")
    QTest.qWait(150)
    assert QApplication.clipboard().text() == "something else"


def test_clipboard_does_not_offer_history_or_cloud_sync(qapp):
    """The clipboard formats Windows checks before adding an entry to clipboard history (Win+V) or syncing
    it to other devices; a copied password must opt out of both."""
    from PySide6.QtWidgets import QApplication
    tab_system_info.SystemInfoTabMixin._copy_secret("anothersecret")
    mime = QApplication.clipboard().mimeData()
    assert mime.hasFormat("ExcludeClipboardContentFromMonitorProcessing")
    assert bytes(mime.data("CanIncludeInClipboardHistory")) == b"\x00\x00\x00\x00"
    assert bytes(mime.data("CanUploadToCloudClipboard")) == b"\x00\x00\x00\x00"
    tab_system_info.SystemInfoTabMixin.clear_secret_clipboard()
    assert QApplication.clipboard().text() == ""


def test_clear_secret_clipboard_is_a_noop_without_a_pending_copy(qapp):
    """closeEvent calls this unconditionally; it must not touch a clipboard holding something unrelated."""
    from PySide6.QtWidgets import QApplication
    tab_system_info._copied_hash = None
    QApplication.clipboard().setText("whatever the user had copied")
    tab_system_info.SystemInfoTabMixin.clear_secret_clipboard()
    assert QApplication.clipboard().text() == "whatever the user had copied"


def test_close_event_clears_a_secret_left_on_the_clipboard(window, dialogs, qapp):  # noqa: F811
    """A copied password must not survive the application closing, even before the 30 s timer fires."""
    from PySide6.QtWidgets import QApplication
    tab_system_info.SystemInfoTabMixin._copy_secret("survives-until-close")
    assert QApplication.clipboard().text() == "survives-until-close"
    event = close_event()
    window.closeEvent(event)
    assert event.accepted
    assert QApplication.clipboard().text() == ""

# endregion
