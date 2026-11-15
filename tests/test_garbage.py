"""Garbage finder: file search and leftovers (tmp_path only), dead registry entries (fake registry), deletion with a
backup (real HKCU test key), and the Garbage tab. Recycle Bin and Explorer are replaced; nothing real is deleted."""

import os
import time

import pytest
from PySide6.QtWidgets import QMessageBox
from PySide6.QtCore import Qt

from ddcleaner import dead_registry, garbage
from ddcleaner.common import SYSTEM32
from ddcleaner.dead_registry import RegEntry
from ddcleaner.ui import tab_cleanup

from test_system_pages import FakeReg, nested, BS
from test_ui_smoke import dialogs, window  # noqa: F401  (fixtures)


def touch(path, data=b"x"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


# region Patterns

def test_a_word_means_contains_and_wildcards_work():
    match = garbage.compile_patterns("*.vscode")
    assert match(".vscode", "") and match("my.vscode", "") and not match("vscode", "")
    contains = garbage.compile_patterns("cache")
    assert contains("MyCache2", "") and not contains("cach", "")
    assert garbage.compile_patterns("a?c")("abc", "") and not garbage.compile_patterns("a?c")("abbc", "")


def test_quotes_mean_an_exact_name_and_semicolons_separate_terms():
    match = garbage.compile_patterns('"nul";*.tmp')
    assert match("nul", "") and match("NUL", "") and match("x.tmp", "")
    assert not match("annul", "") and not match("null", "")


def test_a_term_with_a_slash_is_matched_against_the_path():
    match = garbage.compile_patterns("*\\node_modules\\*")
    assert match("x", "C:\\proj\\node_modules\\x") and not match("x", "C:\\proj\\src\\x")


def test_an_empty_pattern_is_refused():
    with pytest.raises(ValueError):
        garbage.compile_patterns(" ; ")


def test_regex_characters_in_a_pattern_are_literal():
    match = garbage.compile_patterns("a+b(1)")
    assert match("xa+b(1)y", "") and not match("aab1", "")


@pytest.mark.parametrize("size, text", [(0, "0 B"), (1536, "1.5 KB"), (5 * 1024 ** 2, "5.0 MB"), (3 * 1024 ** 3, "3.0 GB")])
def test_human_size(size, text):
    assert garbage.human_size(size) == text

# endregion


# region Searching files

def test_search_lists_a_matching_folder_once_with_its_size(tmp_path):
    touch(tmp_path / "proj" / ".vscode" / "settings.json", b"12345")
    touch(tmp_path / "proj" / ".vscode" / "nested" / ".vscode" / "x.json", b"1")
    touch(tmp_path / "proj" / "code.py")
    scan = garbage.search_files("*.vscode", [str(tmp_path)])
    assert [(os.path.basename(i.path), i.kind, i.size) for i in scan.items] == [(".vscode", "Folder", 6)]


def test_search_finds_files_and_ignores_the_rest(tmp_path):
    touch(tmp_path / "a" / "x.tmp")
    touch(tmp_path / "b" / "y.TMP")
    touch(tmp_path / "b" / "keep.txt")
    scan = garbage.search_files("*.tmp", [str(tmp_path)])
    assert sorted(os.path.basename(i.path) for i in scan.items) == ["x.tmp", "y.TMP"]
    assert all(i.kind == "File" for i in scan.items)


def test_search_stops_on_request_and_at_the_limit(tmp_path):
    for n in range(5):
        touch(tmp_path / f"f{n}.tmp")
    assert garbage.search_files("*.tmp", [str(tmp_path)], stop=lambda: True).items == []
    limited = garbage.search_files("*.tmp", [str(tmp_path)], limit=3)
    assert limited.truncated and len(limited.items) == 3


def test_search_never_crosses_a_junction(tmp_path):
    import subprocess
    target = tmp_path / "target"
    touch(target / "inside.tmp")
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    link = scan_root / "link"
    done = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
    if done.returncode != 0:
        pytest.skip("cannot create a junction here")
    assert garbage.search_files("*.tmp", [str(scan_root)]).items == []


def test_a_file_named_like_a_device_is_found_and_deleted(tmp_path):
    path = garbage._long(str(tmp_path / "nul"))
    with open(path, "w") as f:
        f.write("junk")
    scan = garbage.search_files('"nul"', [str(tmp_path)])
    assert [os.path.basename(i.path) for i in scan.items] == ["nul"]
    result = garbage.delete_items(scan.items, recycle=lambda p: pytest.fail("devices cannot be recycled"))
    assert len(result.deleted) == 1 and not os.path.lexists(path)


def test_search_roots_drop_nested_folders(tmp_path):
    inner = tmp_path / "a" / "b"
    inner.mkdir(parents=True)
    assert garbage._outermost([str(inner), str(tmp_path / "a"), str(tmp_path)]) == [str(tmp_path)]
    assert garbage.search_roots(garbage.WHERE_CUSTOM, str(tmp_path)) == [str(tmp_path)]
    assert garbage.search_roots(garbage.WHERE_CUSTOM, str(tmp_path / "nope")) == []

# endregion


# region Leftovers

def make_old(path, days=400):
    stamp = time.time() - days * 86400
    os.utime(path, (stamp, stamp))


def test_leftovers_are_ranked_and_installed_programs_are_left_alone(tmp_path):
    roaming, pf = tmp_path / "Roaming", tmp_path / "ProgramFiles"
    touch(roaming / "Acme Tools" / "settings.ini")              # claimed by an installed program
    touch(roaming / "OldTool" / "data.db", b"12345")            # nothing claims it, old
    touch(roaming / "FreshTool" / "data.db")                    # nothing claims it, recent
    touch(roaming / "Microsoft" / "x")                          # Windows
    touch(pf / "Gone App" / "readme.txt")                       # no program file left
    touch(pf / "Live App" / "app.exe")                          # claimed and has its program
    touch(pf / "Portable Thing" / "thing.exe")                  # has a program but nothing claims it
    make_old(roaming / "OldTool")
    parents = [("AppData\\Roaming", str(roaming), False), ("Program Files", str(pf), True)]
    scan = garbage.find_leftovers({"acme", "acmetools", "liveapp"}, parents=parents)
    found = {os.path.basename(i.path): i.confidence for i in scan.items}
    assert found == {"Gone App": garbage.HIGH, "OldTool": garbage.MEDIUM, "FreshTool": garbage.LOW,
                     "Portable Thing": garbage.LOW}
    assert [i.confidence for i in scan.items] == sorted((i.confidence for i in scan.items),
                                                        key=lambda c: garbage.CONFIDENCE_ORDER[c])
    old = next(i for i in scan.items if i.path.endswith("OldTool"))
    assert old.size == 5 and "last changed" in old.reason


def test_a_marker_that_only_looks_similar_does_not_hide_a_leftover():
    assert garbage.is_covered("Acme Tools", {"acmetools"})
    assert garbage.is_covered("Microsoft Teams", {"microsoft"})   # a long marker inside the folder name
    assert garbage.is_covered("ab", set())                          # too short to judge
    assert not garbage.is_covered("Zeta Studio", {"acmetools", "liveapp"})


@pytest.mark.parametrize("min_days, expected", [(0, {"new.log", "week.log", "month.log"}),
                                                (1, {"week.log", "month.log"}),
                                                (7, {"week.log", "month.log"}),
                                                (30, {"month.log"})])
def test_the_age_filter_keeps_only_what_is_old_enough(tmp_path, min_days, expected):
    for name, days in (("new.log", 0.1), ("week.log", 8), ("month.log", 31)):
        make_old(touch(tmp_path / name), days)
    found = garbage.search_files("*.log", [str(tmp_path)], min_age_days=min_days)
    assert {os.path.basename(i.path) for i in found.items} == expected


def test_a_recent_matching_folder_is_skipped_whole_by_the_age_filter(tmp_path):
    touch(tmp_path / "Cache" / "a.bin")
    make_old(tmp_path / "Cache" / "a.bin", 100)           # old content, but the folder itself was touched just now
    assert garbage.search_files('"Cache"', [str(tmp_path)], min_age_days=7).items == []
    make_old(tmp_path / "Cache", 100)
    assert len(garbage.search_files('"Cache"', [str(tmp_path)], min_age_days=7).items) == 1


def test_the_age_filter_applies_to_leftovers_too(tmp_path):
    touch(tmp_path / "Roaming" / "FreshTool" / "x")
    touch(tmp_path / "Roaming" / "OldTool" / "x")
    make_old(tmp_path / "Roaming" / "OldTool", 40)
    parents = [("AppData\\Roaming", str(tmp_path / "Roaming"), False)]
    found = garbage.find_leftovers(set(), parents=parents, min_age_days=30)
    assert [os.path.basename(i.path) for i in found.items] == ["OldTool"]


def test_leftover_scan_can_be_stopped(tmp_path):
    touch(tmp_path / "Roaming" / "OldTool" / "x")
    parents = [("AppData\\Roaming", str(tmp_path / "Roaming"), False)]
    assert garbage.find_leftovers(set(), stop=lambda: True, parents=parents).items == []

# endregion


# region Deleting files

def item_for(path, kind="File", size=1):
    return garbage.GarbageItem(str(path), kind, size)


def test_delete_goes_to_the_recycle_bin_by_default(tmp_path):
    f = touch(tmp_path / "a.tmp")
    sent = []
    result = garbage.delete_items([item_for(f, size=7)], recycle=lambda p: sent.append(p) or "")
    assert sent == [str(f)] and len(result.deleted) == 1 and result.freed == 7


def test_permanent_delete_removes_files_and_folders(tmp_path):
    f = touch(tmp_path / "a.tmp")
    folder = touch(tmp_path / "cache" / "deep" / "x.bin").parent.parent
    read_only = touch(tmp_path / "ro.tmp")
    os.chmod(read_only, 0o444)
    result = garbage.delete_items([item_for(f), item_for(folder, "Folder"), item_for(read_only)], permanent=True,
                                  recycle=lambda p: pytest.fail("must not use the Recycle Bin"))
    assert len(result.deleted) == 3 and not result.failed
    assert not f.exists() and not folder.exists() and not read_only.exists()


def test_a_failed_recycle_is_reported_and_the_file_stays(tmp_path):
    f = touch(tmp_path / "a.tmp")
    result = garbage.delete_items([item_for(f)], recycle=lambda p: "locked")
    assert result.failed[0][1] == "locked" and f.exists() and not result.deleted


def test_a_missing_item_counts_as_deleted(tmp_path):
    result = garbage.delete_items([item_for(tmp_path / "gone.tmp")], permanent=True)
    assert len(result.deleted) == 1 and not result.failed


@pytest.mark.parametrize("path", ["C:\\", SYSTEM32, os.path.dirname(os.path.expanduser("~")), os.path.expanduser("~"),
                                  garbage.known_folder(garbage.CSIDL["documents"]), "relative\\path", ""])
def test_essential_folders_are_never_deleted(path):
    assert garbage.protected_reason(path)
    result = garbage.delete_items([item_for(path, "Folder")], permanent=True,
                                  recycle=lambda p: pytest.fail("a protected path must not reach the Recycle Bin"))
    assert result.failed and not result.deleted


def test_an_ordinary_folder_is_allowed(tmp_path):
    assert garbage.protected_reason(str(tmp_path / "anything")) == ""


def test_stop_leaves_the_remaining_items_alone(tmp_path):
    f = touch(tmp_path / "a.tmp")
    result = garbage.delete_items([item_for(f)], permanent=True, stop=lambda: True)
    assert f.exists() and result.failed[0][1] == "Stopped"

# endregion


# region Dead registry entries

UNINSTALL = dead_registry.UNINSTALL_PATHS[0][1]
UNINSTALL_32 = dead_registry.UNINSTALL_PATHS[1][1]


def hklm(tree):
    return FakeReg({("HKLM", "64"): tree})


def test_check_target_tells_missing_from_unknown(tmp_path):
    exe = touch(tmp_path / "app.exe")
    assert dead_registry.check_target(f'"{exe}" /s') == (str(exe), dead_registry.OK)
    assert dead_registry.check_target(f'"{tmp_path / "gone.exe"}"')[1] == dead_registry.MISSING
    assert dead_registry.check_target(f"{tmp_path / 'gone.exe'} /x")[1] == dead_registry.MISSING     # unquoted
    assert dead_registry.check_target("relative.exe")[1] == dead_registry.UNKNOWN
    assert dead_registry.check_target("")[1] == dead_registry.UNKNOWN
    assert dead_registry.check_target(os.path.join(SYSTEM32, "msiexec.exe") + " /X{ABC}")[1] == dead_registry.UNKNOWN
    assert dead_registry.check_target("msiexec /X{ABC}")[1] == dead_registry.UNKNOWN
    assert dead_registry.check_target("\\\\server\\share\\x.exe")[1] == dead_registry.UNKNOWN          # network
    assert dead_registry.check_target(str(tmp_path), is_folder=True)[1] == dead_registry.OK
    assert dead_registry.check_target(str(tmp_path / "gone"), is_folder=True)[1] == dead_registry.MISSING


def test_a_disconnected_drive_proves_nothing():
    free = next(c for c in "ZYXWVUTSRQP" if not os.path.isdir(f"{c}:\\"))
    assert dead_registry.check_target(f'"{free}:\\Apps\\x.exe"')[1] == dead_registry.UNKNOWN


def test_dead_uninstall_entries(tmp_path):
    alive = touch(tmp_path / "alive" / "unins.exe")
    reg = hklm(nested(UNINSTALL, {
        "Dead": {"DisplayName": "Dead App", "InstallLocation": str(tmp_path / "dead"),
                 "UninstallString": f'"{tmp_path / "dead" / "unins.exe"}" /S', "DisplayIcon": f"{tmp_path / 'dead' / 'a.exe'},0"},
        "Alive": {"DisplayName": "Alive App", "UninstallString": f'"{alive}"'},
        "HalfDead": {"DisplayName": "Half", "InstallLocation": str(tmp_path / "gone-folder"),
                     "UninstallString": f'"{alive}"'},                       # the uninstaller still exists
        "Msi": {"DisplayName": "Msi App", "UninstallString": "MsiExec.exe /X{GUID}"},   # nothing to judge
        "NoName": {"UninstallString": f'"{tmp_path / "x.exe"}"'},
    }))
    entries = dead_registry.dead_uninstall_entries(reg)
    assert [(e.key.rsplit(BS, 1)[-1], e.data, e.value, e.category) for e in entries] == [
        ("Dead", "Dead App", None, dead_registry.CAT_UNINSTALL)]


def test_a_missing_icon_alone_does_not_make_an_entry_dead(tmp_path):
    reg = hklm(nested(UNINSTALL, {"IconOnly": {"DisplayName": "Icon only", "DisplayIcon": f"{tmp_path / 'gone.ico'}"}}))
    assert dead_registry.dead_uninstall_entries(reg) == []


def test_windows_components_in_program_files_are_not_leftovers(tmp_path):
    touch(tmp_path / "PF" / "Microsoft.NET" / "RedistList.xml")
    touch(tmp_path / "PF" / "Microsoft Update Health Tools" / "x.txt")
    touch(tmp_path / "PF" / "Dead Tool" / "x.txt")
    scan = garbage.find_leftovers(set(), parents=[("Program Files", str(tmp_path / "PF"), True)])
    assert [os.path.basename(i.path) for i in scan.items] == ["Dead Tool"]


def test_the_recycle_bin_call_really_works(tmp_path):
    folder = touch(tmp_path / "probe" / "a.txt").parent
    f = touch(tmp_path / "probe.tmp")
    assert garbage.recycle_path(str(f)) == "" and not f.exists()
    assert garbage.recycle_path(str(folder)) == "" and not folder.exists()


def test_dead_uninstall_entries_cover_the_32_bit_branch(tmp_path):
    reg = hklm(nested(UNINSTALL_32, {"Old": {"DisplayName": "Old", "UninstallString": f'"{tmp_path / "gone.exe"}"'}}))
    entries = dead_registry.dead_uninstall_entries(reg)
    assert len(entries) == 1 and "WOW6432Node" in entries[0].key and entries[0].hive == "HKLM"


def test_dead_app_paths(tmp_path):
    exe = touch(tmp_path / "ok.exe")
    base = dead_registry.APP_PATHS[0][1]
    reg = hklm(nested(base, {"gone.exe": {"": str(tmp_path / "gone.exe")}, "ok.exe": {"": str(exe)}, "none.exe": {"Path": "x"}}))
    assert [e.display_name for e in dead_registry.dead_app_paths(reg)] == ["gone.exe"]


def test_dead_startup_values_are_value_entries(tmp_path):
    exe = touch(tmp_path / "ok.exe")
    run = dead_registry.startup.RUN_KEYS[0][1]
    reg = hklm(nested(run, {"Dead": f'"{tmp_path / "gone.exe"}" -min', "Fine": f'"{exe}"', "Cmd": "cmd.exe /c echo"}))
    entries = dead_registry.dead_startup_entries(reg)
    assert [(e.value, e.kind, e.category) for e in entries] == [("Dead", "Value", dead_registry.CAT_STARTUP)]


def test_cached_traces_only_report_missing_paths(tmp_path):
    exe = touch(tmp_path / "ok.exe")
    hive, mui = dead_registry.MUI_CACHE
    reg = FakeReg({("HKCU", "64"): nested(mui, {
        f"{tmp_path / 'gone.exe'}.FriendlyAppName": "Gone", f"{tmp_path / 'gone.exe'}.ApplicationCompany": "Co",
        f"{exe}.FriendlyAppName": "Alive", "LangID": "x", "@{pkg}": "y"})})
    names = [e.value for e in dead_registry.dead_cached_traces(reg)]
    assert len(names) == 2 and all("gone.exe" in n for n in names)


def test_scan_dead_collects_every_category_and_can_stop(tmp_path):
    reg = hklm(nested(UNINSTALL, {"Dead": {"DisplayName": "Dead", "UninstallString": f'"{tmp_path / "gone.exe"}"'}}))
    assert len(dead_registry.scan_dead(reg).entries) == 1
    assert dead_registry.scan_dead(reg, stop=lambda: True).entries == []


def test_installed_markers_cover_names_publishers_and_folders():
    reg = FakeReg({("HKLM", "64"): nested(UNINSTALL, {
        "Notepad++": {"DisplayName": "Notepad++ (64-bit x64)", "Publisher": "Notepad++ Team",
                      "InstallLocation": "C:\\Program Files\\Notepad++\\"},
        "x": {"DisplayName": "Visual Studio Code", "Publisher": "Microsoft Corporation"}})})
    markers = dead_registry.installed_markers(reg)
    assert {"notepad", "notepadteam", "visual", "studio", "code", "microsoft", "visualstudiocode"} <= markers
    assert garbage.is_covered("Code", markers) and garbage.is_covered("Notepad++", markers)

# endregion


# region Searching the registry

def test_registry_search_matches_keys_value_names_and_data():
    reg = FakeReg({("HKCU", "64"): nested("SOFTWARE", {
        "OldVendor": {"Setting": "1", "Sub": {"Deep": "2"}},
        "Other": {"Path": "C:\\Tools\\oldvendor\\app.exe", "OldVendorFlag": "1", "Plain": "no"}})})
    scan = dead_registry.search_registry("oldvendor", reg=reg)
    found = {(e.key.rsplit(BS, 1)[-1], e.value, e.category) for e in scan.entries}
    assert found == {("OldVendor", None, dead_registry.CAT_KEY), ("Other", "Path", dead_registry.CAT_VALUE_DATA),
                     ("Other", "OldVendorFlag", dead_registry.CAT_VALUE_NAME)}   # the matching key is not entered


def test_registry_search_respects_the_scope_flags_and_the_limit():
    reg = FakeReg({("HKCU", "64"): nested("SOFTWARE", {"Acme": {"Acme1": "a", "Acme2": "b"}})})
    only_keys = dead_registry.search_registry("acme", value_names=False, value_data=False, reg=reg)
    assert [e.category for e in only_keys.entries] == [dead_registry.CAT_KEY]
    only_values = dead_registry.search_registry("acme*", names=False, value_data=False, reg=reg)
    assert {e.value for e in only_values.entries} == {"Acme1", "Acme2"}
    limited = dead_registry.search_registry("acme", names=False, value_data=False, reg=reg, limit=1)
    assert limited.truncated and len(limited.entries) == 1
    assert dead_registry.search_registry("acme", reg=reg, stop=lambda: True).entries == []


@pytest.mark.parametrize("entry, protected", [
    (RegEntry("HKCU", "SOFTWARE\\Vendor\\App"), False),
    (RegEntry("HKLM", "SOFTWARE\\WOW6432Node\\Vendor"), False),
    (RegEntry("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\App"), False),
    (RegEntry("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Dead"), False),
    (RegEntry("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), True),        # the Run key itself
    (RegEntry("HKLM", "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"), True),
    (RegEntry("HKLM", "SOFTWARE\\Microsoft"), True),
    (RegEntry("HKCU", "SOFTWARE"), True),
    (RegEntry("HKCU", "SOFTWARE\\Classes\\CLSID"), True),
    (RegEntry("HKLM", "SYSTEM\\CurrentControlSet\\Services\\X"), True),
    (RegEntry("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Shell"), True),
    (RegEntry("HKLM", "SOFTWARE\\Policies\\Vendor"), True),
    (RegEntry("HKU", "SOFTWARE\\X"), True),
])
def test_protected_registry_entries(entry, protected):
    assert bool(dead_registry.protected_reason(entry)) is protected

# endregion


# region Deleting registry entries (real HKCU test key)

def build_vendor(winreg, base):
    for sub in ("Vendor\\App\\Deep", "Keep"):
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, f"{base}\\{sub}").Close()
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{base}\\Vendor\\App", 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "Path", 0, winreg.REG_SZ, "C:\\gone.exe")
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{base}\\Keep", 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "Dead", 0, winreg.REG_SZ, "C:\\gone.exe")
        winreg.SetValueEx(key, "Live", 0, winreg.REG_SZ, "kept")


def exists(winreg, path):
    try:
        winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY).Close()
        return True
    except FileNotFoundError:
        return False


def test_deleting_a_key_tree_and_a_value_exports_a_backup_first(test_key, tmp_path):
    import winreg
    build_vendor(winreg, test_key)
    entries = [RegEntry("HKCU", f"{test_key}\\Vendor"), RegEntry("HKCU", f"{test_key}\\Keep", "Dead")]
    result = dead_registry.delete_entries(entries, str(tmp_path / "backups"))
    assert len(result.deleted) == 2 and not result.failed and len(result.backups) == 2
    assert not exists(winreg, f"{test_key}\\Vendor") and exists(winreg, f"{test_key}\\Keep")
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{test_key}\\Keep") as key:
        assert winreg.QueryValueEx(key, "Live")[0] == "kept"
        with pytest.raises(FileNotFoundError):
            winreg.QueryValueEx(key, "Dead")
    backup = next(f for f in os.listdir(tmp_path / "backups") if "Vendor" in f)
    text = open(tmp_path / "backups" / backup, "rb").read().decode("utf-16")
    assert "gone.exe" in text and "Vendor" in text


def test_nothing_is_deleted_when_the_backup_fails(test_key, tmp_path):
    import winreg
    build_vendor(winreg, test_key)
    result = dead_registry.delete_entries([RegEntry("HKCU", f"{test_key}\\Vendor")], str(tmp_path),
                                          export=lambda hive, path, file: "disk full")
    assert exists(winreg, f"{test_key}\\Vendor") and not result.deleted
    assert "Backup failed" in result.failed[0][1]


def test_protected_and_vanished_entries(test_key, tmp_path):
    result = dead_registry.delete_entries(
        [RegEntry("HKLM", "SOFTWARE\\Microsoft"), RegEntry("HKCU", f"{test_key}\\NeverExisted")], str(tmp_path),
        export=lambda *a: pytest.fail("no backup for a protected or missing key"))
    assert [e.key for e in result.deleted] == [f"{test_key}\\NeverExisted"]
    assert result.failed[0][1] == "Core Windows key"


def test_an_ancestor_deleted_first_does_not_make_the_child_fail(test_key, tmp_path):
    import winreg
    build_vendor(winreg, test_key)
    entries = [RegEntry("HKCU", f"{test_key}\\Vendor"), RegEntry("HKCU", f"{test_key}\\Vendor\\App\\Deep")]
    result = dead_registry.delete_entries(entries, str(tmp_path))
    assert len(result.deleted) == 2 and not result.failed

# endregion


# region The Garbage tab

def rows(tree):
    return [tree.topLevelItem(i) for i in range(tree.topLevelItemCount())]


def test_garbage_tab_exists_with_both_pages(window):  # noqa: F811
    pages = window.tab_widget.widget(window.tab_widget.count() - 1)
    assert [pages.tabText(i) for i in range(pages.count())] == ["Files and folders", "Registry", "Overview"]


def test_scan_results_are_listed_unticked_and_sortable_by_size(window, tmp_path):  # noqa: F811
    small, big = touch(tmp_path / "a.tmp", b"1"), touch(tmp_path / "b.tmp", b"1" * 5000)
    scan = garbage.FileScan([garbage.GarbageItem(str(small), "File", 1, 0.0, "Matches the search"),
                             garbage.GarbageItem(str(big), "File", 5000, 0.0, "Matches the search")])
    window._on_garbage_scanned(scan, "")
    tree = window.garbage_tree
    assert tree.topLevelItemCount() == 2 and {r.text(2) for r in rows(tree)} == {"1 B", "4.9 KB"}
    assert all(r.checkState(0) == Qt.CheckState.Unchecked for r in rows(tree))
    tree.sortItems(2, Qt.SortOrder.DescendingOrder)
    assert [r.text(0) for r in rows(tree)] == ["b.tmp", "a.tmp"]       # 5000 B before 1 B, not "5.0 KB" vs "1 B" as text
    assert "2 item(s)" in window.garbage_summary.text()


def test_essential_folders_get_no_checkbox(window):  # noqa: F811
    scan = garbage.FileScan([garbage.GarbageItem(os.path.expanduser("~"), "Folder", 1)])
    window._on_garbage_scanned(scan, "")
    assert not (rows(window.garbage_tree)[0].flags() & Qt.ItemFlag.ItemIsUserCheckable)
    tab_cleanup.set_all_checked(window.garbage_tree, True)
    assert tab_cleanup.checked_payloads(window.garbage_tree) == []


def test_delete_needs_ticked_items_and_a_confirmation(window, dialogs, tmp_path):  # noqa: F811
    f = touch(tmp_path / "a.tmp")
    window._on_garbage_scanned(garbage.FileScan([garbage.GarbageItem(str(f), "File", 1)]), "")
    window._garbage_delete_files()
    assert dialogs["info"] and not dialogs["question"]
    tab_cleanup.set_all_checked(window.garbage_tree, True)
    dialogs["answer"] = QMessageBox.StandardButton.No
    window._garbage_delete_files()
    assert dialogs["question"] and f.exists() and getattr(window, "garbage_delete_worker", None) is None


def test_confirmed_delete_removes_the_row_and_reports_failures(window, dialogs, tmp_path, monkeypatch):  # noqa: F811
    good, bad = touch(tmp_path / "good.tmp"), touch(tmp_path / "bad.tmp")
    items = [garbage.GarbageItem(str(good), "File", 3), garbage.GarbageItem(str(bad), "File", 4)]
    window._on_garbage_scanned(garbage.FileScan(items), "")
    tab_cleanup.set_all_checked(window.garbage_tree, True)
    result = garbage.delete_items(items, recycle=lambda p: "locked" if "bad" in p else "")
    window._on_garbage_deleted(result, "")
    assert [r.text(0) for r in rows(window.garbage_tree)] == ["bad.tmp"]
    assert dialogs["warning"] and "1 deleted" in window.garbage_summary.text()


def test_registry_rows_show_protected_entries_without_checkbox(window):  # noqa: F811
    entries = [RegEntry("HKCU", "SOFTWARE\\Vendor", None, dead_registry.CAT_KEY, "Key name matches"),
               RegEntry("HKLM", "SOFTWARE\\Microsoft", None, dead_registry.CAT_KEY, "Key name matches")]
    window._on_registry_scanned(dead_registry.RegScan(entries), "")
    by_name = {r.text(0): r for r in rows(window.registry_tree)}
    assert by_name["Vendor"].flags() & Qt.ItemFlag.ItemIsUserCheckable
    assert not (by_name["Microsoft"].flags() & Qt.ItemFlag.ItemIsUserCheckable)
    assert "1 protected" in window.registry_summary.text()


def test_registry_delete_asks_for_admin_on_hklm(window, dialogs, monkeypatch):  # noqa: F811
    monkeypatch.setattr(tab_cleanup.SystemUtils, "check_admin_privileges", staticmethod(lambda: False))
    window._on_registry_scanned(dead_registry.RegScan([RegEntry("HKLM", "SOFTWARE\\Vendor")]), "")
    tab_cleanup.set_all_checked(window.registry_tree, True)
    window._registry_delete()
    assert dialogs["warning"] and not dialogs["question"]


def test_registry_delete_confirmation_then_cancel(window, dialogs, monkeypatch, tmp_path):  # noqa: F811
    monkeypatch.setattr(dead_registry, "backup_dir", lambda: str(tmp_path / "bk"))
    window._on_registry_scanned(dead_registry.RegScan([RegEntry("HKCU", "SOFTWARE\\Vendor")]), "")
    window._registry_delete()
    assert dialogs["info"]                                   # nothing ticked yet
    tab_cleanup.set_all_checked(window.registry_tree, True)
    dialogs["answer"] = QMessageBox.StandardButton.No
    window._registry_delete()
    assert dialogs["question"] and getattr(window, "garbage_delete_worker", None) is None


def test_empty_or_invalid_searches_do_not_start_a_worker(window, dialogs):  # noqa: F811
    window._garbage_search_files()
    window._registry_search()
    assert len(dialogs["info"]) == 2
    assert getattr(window, "garbage_file_worker", None) is None and getattr(window, "garbage_reg_worker", None) is None


def test_presets_fill_the_pattern_and_compile(window):  # noqa: F811
    for name, pattern in garbage.PRESETS.items():
        index = window.garbage_preset.findText(name)
        window._garbage_pick_preset(index)
        assert window.garbage_pattern.text() == pattern
        garbage.compile_patterns(pattern)
        assert window.garbage_preset.currentIndex() == 0


def test_stop_cancels_a_scan_and_the_buttons_come_back(window):  # noqa: F811
    window.garbage_search_btn.setEnabled(False)
    window.garbage_cancel.set()
    assert window._garbage_stopped()
    window._on_garbage_scanned(garbage.FileScan([], False, 3), "")
    assert window.garbage_search_btn.isEnabled() and "search stopped" in window.garbage_summary.text()

# endregion
