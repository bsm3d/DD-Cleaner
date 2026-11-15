"""Folders ending with ~ (Unity package folders) are never garbage, and the Scan all button."""

import os

import pytest

from ddcleaner import dead_registry as dr, garbage

from test_ui_smoke import dialogs, window  # noqa: F401  (fixtures)


def touch(path, data=b"x"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def unity_package(tmp_path):
    package = tmp_path / "Packages" / "com.acme.tool"
    for folder in ("Samples~", "Documentation~", "Editor Default Resources~"):
        touch(package / folder / "keep.txt")
    touch(package / "package.json")
    touch(package / "old.bak")
    touch(package / "notes.txt~")                               # an editor backup file: this one is fair game
    return package


# region Unity package folders

def test_a_folder_ending_with_a_tilde_is_never_listed_even_by_the_backup_preset(tmp_path):
    unity_package(tmp_path)
    found = garbage.search_files(garbage.PRESETS["Backups and old copies"], [str(tmp_path)])
    assert sorted(os.path.basename(i.path) for i in found.items) == ["notes.txt~", "old.bak"]
    assert all(i.kind == "File" for i in found.items)


@pytest.mark.parametrize("pattern", ["*~", '"Samples~"', "Samples*", "*", "Documentation~;Samples~"])
def test_no_pattern_can_list_such_a_folder(tmp_path, pattern):
    unity_package(tmp_path)
    found = garbage.search_files(pattern, [str(tmp_path)])
    assert not [i for i in found.items if i.kind == "Folder" and i.path.endswith("~")]


def test_the_search_still_looks_inside_those_folders(tmp_path):
    touch(tmp_path / "Samples~" / "deep" / "build.tmp")
    touch(tmp_path / "Samples~" / "__pycache__" / "x.pyc")
    found = garbage.search_files("*.tmp;" + garbage.PRESETS["Python caches"], [str(tmp_path)])
    assert sorted(os.path.basename(i.path) for i in found.items) == ["__pycache__", "build.tmp"]


def test_deleting_such_a_folder_is_refused_whatever_the_caller_asks(tmp_path):
    folder = unity_package(tmp_path) / "Samples~"
    assert "Unity" in garbage.protected_reason(str(folder))
    item = garbage.GarbageItem(str(folder), "Folder", 1)
    result = garbage.delete_items([item], permanent=True, recycle=lambda p: pytest.fail("must not reach the Recycle Bin"))
    assert result.failed and not result.deleted and (folder / "keep.txt").exists()
    # the files inside and ordinary backup files remain deletable
    assert garbage.protected_reason(str(folder / "keep.txt")) == ""
    assert garbage.protected_reason(str(folder.parent / "notes.txt~")) == ""


def test_a_file_named_with_a_tilde_is_not_confused_with_a_folder(tmp_path):
    f = touch(tmp_path / "doc.txt~")
    assert garbage.protected_reason(str(f)) == "" and not garbage.is_kept_folder("doc.txt~", False)
    assert garbage.is_kept_folder("Samples~", True) and not garbage.is_kept_folder("Samples", True)


def test_leftover_scan_ignores_them_too(tmp_path):
    touch(tmp_path / "Roaming" / "Samples~" / "x")
    touch(tmp_path / "Roaming" / "OldTool" / "x")
    scan = garbage.find_leftovers(set(), parents=[("AppData\\Roaming", str(tmp_path / "Roaming"), False)])
    assert [os.path.basename(i.path) for i in scan.items] == ["OldTool"]

# endregion


# region Scan all

def test_merged_scans_keep_the_confident_version_and_add_the_counters():
    a = garbage.FileScan([garbage.GarbageItem(r"C:\x\A", "Folder", 1), garbage.GarbageItem(r"C:\x\B", "File", 2)], False, 5)
    b = garbage.FileScan([garbage.GarbageItem(r"c:\x\a", "Folder", 1, 0.0, "leftover", garbage.HIGH),
                          garbage.GarbageItem(r"C:\x\C", "Folder", 3)], True, 7)
    merged = garbage.merge_scans(a, b)
    by_name = {os.path.basename(i.path).lower(): i for i in merged.items}
    assert set(by_name) == {"a", "b", "c"} and by_name["a"].confidence == garbage.HIGH
    assert merged.truncated and merged.folders_seen == 12


class Sync:
    """_start_call replacement: run the worker's function now, hand the result to the callback."""

    def __init__(self, window):
        self.calls = []
        window._start_call = self

    def __call__(self, attr, function, on_done, button=None, status=""):
        self.calls.append((attr, status))
        try:
            result, error = function(), ""
        except Exception as e:  # noqa: BLE001
            result, error = None, str(e)
        on_done(result, error)
        return True


def test_the_button_is_in_the_corner_of_the_garbage_tabs(window):  # noqa: F811
    assert window.scan_all_btn.text().endswith("Scan all") and window.garbage_tabs.cornerWidget() is not None
    assert window.scan_all_btn in window._scan_controls()


def test_scan_all_searches_every_preset_and_the_leftovers_then_every_registry_preset(window, tmp_path, monkeypatch):  # noqa: F811
    calls = Sync(window)
    asked = {}
    monkeypatch.setattr(garbage, "search_roots", lambda where, custom="": asked.update(where=where) or [str(tmp_path)])
    monkeypatch.setattr(garbage, "search_files", lambda patterns, roots, stop, progress, min_age_days=0: asked.update(patterns=patterns, roots=roots, age=min_age_days) or
                        garbage.FileScan([garbage.GarbageItem(str(tmp_path / "x.tmp"), "File", 2_000_000)], False, 4))
    monkeypatch.setattr(dr, "installed_markers", lambda *a, **k: {"acme"})
    monkeypatch.setattr(garbage, "find_leftovers", lambda markers, stop, progress, min_age_days=0: asked.update(markers=markers, leftover_age=min_age_days) or
                        garbage.FileScan([garbage.GarbageItem(str(tmp_path / "Old"), "Folder", 500_000, 0.0, "r", garbage.HIGH)], False, 2))
    monkeypatch.setattr(dr, "scan_presets", lambda ids, stop=None, progress=None: asked.update(ids=ids) or
                        dr.RegScan([dr.RegEntry("HKCU", "SOFTWARE\\a", None, dr.CAT_HISTORY, "r", "d", dr.HIGH)]))
    window._scan_all()
    assert [c[0] for c in calls.calls] == ["garbage_file_worker", "garbage_reg_worker"]
    assert asked["patterns"] == ";".join(garbage.PRESETS.values()) and asked["roots"] == [str(tmp_path)]
    assert asked["markers"] == {"acme"} and asked["ids"] == [p.id for p in dr.PRESETS]
    assert window.garbage_tree.topLevelItemCount() == 2 and window.registry_tree.topLevelItemCount() == 1
    assert len(window.garbage_found) == 2 and len(window.registry_found) == 1
    assert window.garbage_tabs.currentIndex() == window.garbage_tabs.count() - 1             # the Overview
    assert "Garbage found: 2.4 MB in 2 item(s)" in window.overview_summary.text()
    assert all(b.isEnabled() for b in window._scan_controls())
    assert "Scan all done" in window.status_label.text()


def test_scan_all_uses_the_place_chosen_on_the_files_page(window, tmp_path, monkeypatch):  # noqa: F811
    Sync(window)
    asked = {}
    monkeypatch.setattr(garbage, "search_roots", lambda where, custom="": asked.update(where=where, custom=custom) or [str(tmp_path)])
    monkeypatch.setattr(garbage, "search_files", lambda *a, **k: garbage.FileScan())
    monkeypatch.setattr(garbage, "find_leftovers", lambda *a, **k: garbage.FileScan())
    monkeypatch.setattr(dr, "installed_markers", lambda *a, **k: set())
    monkeypatch.setattr(dr, "scan_presets", lambda *a, **k: dr.RegScan([]))
    window.garbage_where.setCurrentIndex(1)
    window._scan_all()
    assert asked["where"] == garbage.WHERE_APPDATA


def test_the_age_choice_reaches_every_file_scan(window, tmp_path, monkeypatch):  # noqa: F811
    Sync(window)
    asked = {}
    monkeypatch.setattr(garbage, "search_roots", lambda where, custom="": [str(tmp_path)])
    monkeypatch.setattr(garbage, "search_files", lambda *a, min_age_days=0, **k: asked.update(search=min_age_days) or garbage.FileScan())
    monkeypatch.setattr(garbage, "find_leftovers", lambda *a, min_age_days=0, **k: asked.update(left=min_age_days) or garbage.FileScan())
    monkeypatch.setattr(dr, "installed_markers", lambda *a, **k: set())
    monkeypatch.setattr(dr, "scan_presets", lambda *a, **k: dr.RegScan([]))
    assert [window.garbage_age.itemData(i) for i in range(window.garbage_age.count())] == [0, 1, 7, 30]
    window.garbage_age.setCurrentIndex(2)                       # older than 7 days
    window.garbage_pattern.setText("*.log")
    window._garbage_search_files()
    window._garbage_find_leftovers()
    assert asked == {"search": 7, "left": 7}
    window.garbage_age.setCurrentIndex(3)
    window._scan_all()
    assert asked == {"search": 30, "left": 30}


def test_scan_all_needs_a_place_to_search(window, dialogs, monkeypatch):  # noqa: F811
    calls = Sync(window)
    monkeypatch.setattr(garbage, "search_roots", lambda where, custom="": [])
    window._scan_all()
    assert dialogs["info"] and not calls.calls


def test_a_stop_during_the_file_step_skips_the_registry(window, tmp_path, monkeypatch):  # noqa: F811
    calls = Sync(window)
    monkeypatch.setattr(garbage, "search_roots", lambda where, custom="": [str(tmp_path)])

    def stopping_search(patterns, roots, stop, progress, min_age_days=0):
        window.garbage_cancel.set()
        return garbage.FileScan()
    monkeypatch.setattr(garbage, "search_files", stopping_search)
    monkeypatch.setattr(garbage, "find_leftovers", lambda *a, **k: pytest.fail("stopped: no leftover scan"))
    monkeypatch.setattr(dr, "scan_presets", lambda *a, **k: pytest.fail("stopped: no registry scan"))
    window._scan_all()
    assert [c[0] for c in calls.calls] == ["garbage_file_worker"] and all(b.isEnabled() for b in window._scan_controls())


def test_an_error_in_the_file_step_is_shown_and_ends_the_chain(window, dialogs, tmp_path, monkeypatch):  # noqa: F811
    calls = Sync(window)
    monkeypatch.setattr(garbage, "search_roots", lambda where, custom="": [str(tmp_path)])

    def boom(*a, **k):
        raise OSError("disk unreadable")
    monkeypatch.setattr(garbage, "search_files", boom)
    monkeypatch.setattr(dr, "scan_presets", lambda *a, **k: pytest.fail("no registry scan after an error"))
    window._scan_all()
    assert dialogs["warning"] and [c[0] for c in calls.calls] == ["garbage_file_worker"]

# endregion
