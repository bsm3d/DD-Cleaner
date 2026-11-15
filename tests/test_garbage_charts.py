"""Registry presets, leftovers of old programs, sizes and statistics, the chart widgets and the Overview page.
Fake registries and temporary folders only; the one real-disk test just reads the drive sizes."""

import os
import time
from datetime import datetime

import pytest
from PySide6.QtGui import QColor

from ddcleaner import dead_registry as dr, garbage, garbage_stats as stats
from ddcleaner.dead_registry import RegEntry
from ddcleaner.ui import charts

from test_system_pages import FakeReg, nested, BS
from test_ui_smoke import dialogs, window  # noqa: F401  (fixtures)

NOW = 1_800_000_000.0


class AgedReg(FakeReg):
    """FakeReg that also knows how old a key is (QueryInfoKey), by the identity of its sub-tree."""

    def __init__(self, trees, ages=None):
        super().__init__(trees)
        self.ages = ages or {}

    def QueryInfoKey(self, node):
        days = self.ages.get(id(node.tree), 0)
        return 0, 0, int((NOW + 11644473600 - days * 86400) * 1e7)


def merge(*parts):
    out: dict = {}
    for part in parts:
        for k, v in part.items():
            out[k] = merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def exe(tmp_path, name="app.exe"):
    path = tmp_path / name
    path.write_bytes(b"MZ")
    return str(path)


# region Registry presets

def test_the_presets_are_listed_with_a_risk_and_the_safe_ones_are_the_default():
    assert [p.id for p in dr.PRESETS] == ["uninstall", "app_paths", "startup", "traces", "approved", "history", "com", "vendors"]
    assert {p.risk for p in dr.PRESETS} == {"Safe", "Check", "Review"}
    assert dr.DEFAULT_PRESETS == ["uninstall", "app_paths", "startup", "traces", "approved", "history"]
    assert all(p.description for p in dr.PRESETS)


def test_usage_history_lists_only_keys_that_hold_something():
    explorer = dr.HISTORY_KEYS[0][0].rsplit(BS, 1)[0]
    reg = FakeReg({("HKCU", "64"): merge(
        nested(explorer + r"\RunMRU", {"a": "cmd", "MRUList": "a"}),
        nested(explorer + r"\RecentDocs", {"Sub": {"x": 1}}),
        nested(explorer + r"\TypedPaths", {}))})                       # empty: nothing to clean
    found = dr.usage_history(reg)
    assert sorted(e.display_name for e in found) == ["RecentDocs", "RunMRU"]
    assert all(e.category == dr.CAT_HISTORY and e.hive == "HKCU" and e.confidence == dr.HIGH and e.value is None for e in found)
    assert "2 value(s)" in next(e for e in found if e.display_name == "RunMRU").data
    for entry in found:
        assert dr.protected_reason(entry) == ""                        # deletable from the tab


def test_orphan_startup_toggles(tmp_path):
    approved = dr.STARTUP_APPROVED + r"\Run"
    run = rf"SOFTWARE\{dr.CURRENT}\Run"
    reg = FakeReg({("HKCU", "64"): merge(nested(approved, {"Gone": b"\x02", "Live": b"\x02"}), nested(run, {"live": "x.exe"}))})
    found = dr.orphan_startup_toggles(reg)
    assert [(e.value, e.category, e.key) for e in found] == [("Gone", dr.CAT_APPROVED, approved)]
    assert dr.protected_reason(found[0]) == ""


def clsid(tmp_path):
    good, missing = exe(tmp_path, "good.exe"), str(tmp_path / "gone.exe")
    return nested(r"SOFTWARE\Classes\CLSID", {
        "{A}": {"InprocServer32": {"": missing}},
        "{B}": {"InprocServer32": {"": good}},
        "{C}": {"InprocServer32": {"": "ole32.dll"}},                          # bare name: not judged
        "{D}": {"LocalServer32": {"": f'"{missing}" /Automation'}},
        "{E}": {"InprocServer32": {"": good}, "LocalServer32": {"": missing}},  # one server is there: alive
        "{F}": {"LocalServer32": {"": f"{good} /Embedding"}},
        "{G}": {"ProgID": {"": "x"}}}), missing


def test_com_registrations_with_every_file_missing(tmp_path):
    tree, missing = clsid(tmp_path)
    found = dr.dead_com_registrations(FakeReg({("HKLM", "64"): tree}))
    assert sorted(e.data for e in found) == ["{A}", "{D}"]
    assert all(e.category == dr.CAT_COM and e.confidence == dr.MEDIUM and missing in e.reason for e in found)
    assert len(dr.dead_com_registrations(FakeReg({("HKLM", "64"): tree}), limit=1)) == 1
    assert dr.dead_com_registrations(FakeReg({("HKLM", "64"): tree}), stop=lambda: True) == []


def test_leftover_vendor_keys_of_programs_that_are_no_longer_installed(tmp_path):
    alive, gone = exe(tmp_path), str(tmp_path / "gone.exe")
    software = {"OldVendor": {"Path": gone, "Sub": {"File": gone}}, "QuietOld": {"Setting": 1}, "QuietNew": {"Setting": 1},
                "InUse": {"Path": alive, "Other": gone}, "Acme Tools": {"Path": gone}, "Microsoft": {"x": 1},
                "Classes": {}, "MixedAlive": {"Sub": {"Path": alive}, "Gone": gone}}
    ages = {id(software["QuietOld"]): 400, id(software["QuietNew"]): 5, id(software["OldVendor"]): 400}
    reg = AgedReg({("HKCU", "64"): nested("SOFTWARE", software)}, ages)
    found = {e.data: e for e in dr.orphan_vendor_keys(reg, {"acmetools"}, now=NOW)}
    assert set(found) == {"OldVendor", "QuietOld"}
    assert found["OldVendor"].confidence == dr.HIGH and "2 file(s)" in found["OldVendor"].reason
    assert found["QuietOld"].confidence == dr.MEDIUM and "400 days" in found["QuietOld"].reason
    assert found["OldVendor"].category == dr.CAT_VENDOR and dr.protected_reason(found["OldVendor"]) == ""
    assert len(dr.orphan_vendor_keys(reg, {"acmetools"}, now=NOW, limit=1)) == 1


def test_windows_keys_and_guid_keys_are_not_called_leftovers():
    software = {"OEM": {"x": 1}, "DefaultUserEnvironment": {"x": 1}, "c410b7d2-8fce-53b3-8332-e98b6e89a16a": {"x": 1},
                "{c410b7d2-8fce-53b3-8332-e98b6e89a16b}": {"x": 1}, "RealLeftover": {"x": 1}}
    reg = AgedReg({("HKLM", "64"): nested("SOFTWARE", software)}, {id(v): 900 for v in software.values()})
    assert [e.data for e in dr.orphan_vendor_keys(reg, set(), now=NOW)] == ["RealLeftover"]


def test_installed_programs_protect_their_vendor_keys_through_the_real_markers(tmp_path):
    uninstall = nested(dr.UNINSTALL_PATHS[0][1], {"x": {"DisplayName": "Notepad++ (64-bit)", "Publisher": "Don Ho"}})
    software = {"Notepad++": {"Setting": 1}, "Stranger": {"Setting": 1}}
    reg = AgedReg({("HKLM", "64"): merge(uninstall, nested("SOFTWARE", software)),
                   ("HKCU", "64"): {}}, {id(software["Stranger"]): 900, id(software["Notepad++"]): 900})
    names = [e.data for e in dr.orphan_vendor_keys(reg, now=NOW)]
    assert names == ["Stranger"]


def test_scan_presets_runs_only_the_chosen_ones_in_order_and_reports_progress(tmp_path):
    explorer = dr.HISTORY_KEYS[0][0].rsplit(BS, 1)[0]
    reg = FakeReg({("HKCU", "64"): nested(explorer + r"\RunMRU", {"a": "x"}),
                   ("HKLM", "64"): nested(dr.UNINSTALL_PATHS[0][1], {"Dead": {"DisplayName": "Dead", "UninstallString": f'"{tmp_path / "x.exe"}"'}})})
    messages = []
    scan = dr.scan_presets(["history", "uninstall"], reg, progress=messages.append)
    assert [e.category for e in scan.entries] == [dr.CAT_UNINSTALL, dr.CAT_HISTORY]      # sorted by category name
    assert messages == ["Checking: Dead uninstall entries...", "Checking: Usage history lists..."]
    assert dr.scan_presets([], reg).entries == [] and dr.scan_presets(["history"], reg, stop=lambda: True).entries == []
    assert dr.scan_presets(["nope"], reg).entries == []

# endregion


# region Sizes and categories

def item(path, size=100, confidence=""):
    return garbage.GarbageItem(path, "File", size, 0.0, "", confidence)


def test_items_are_grouped_like_the_presets_that_find_them():
    assert garbage.categorize(item(r"C:\a\x.tmp")) == "Temporary files"
    assert garbage.categorize(item(r"C:\a\__pycache__")) == "Python caches"
    assert garbage.categorize(item(r"C:\a\crash.dmp")) == "Crash dumps and error reports"
    assert garbage.categorize(item(r"C:\a\movie.mkv.part")) == "Incomplete downloads"
    assert garbage.categorize(item(r"C:\a\Folder", confidence="High")) == "Leftover folders (high confidence)"
    assert garbage.categorize(item(r"C:\a\report.docx")) == "Other matches"


def test_summary_by_category_and_by_drive():
    items = [item(r"C:\a\x.tmp", 10), item(r"C:\a\y.tmp", 30), item(r"d:\b\z.bak", 5), item(r"D:\c\q.docx", 1)]
    assert garbage.summarize(items) == [("Temporary files", 2, 40), ("Backups and old copies", 1, 5), ("Other matches", 1, 1)]
    assert garbage.size_by_drive(items) == {"C:": 40, "D:": 6}
    assert garbage.summarize([]) == [] and garbage.size_by_drive([]) == {}


def test_drive_usage_reads_real_drives_and_skips_missing_ones():
    usage = garbage.drive_usage()
    assert usage and all(u.total > 0 and u.used + u.free <= u.total + 1 for u in usage)
    assert garbage.drive_usage([r"Q:\nowhere"]) == []
    assert garbage.drive_usage([usage[0].root])[0].root == usage[0].root


def test_folder_usage_measures_each_folder_in_parallel(tmp_path):
    for name, size in (("big", 5000), ("small", 10), ("mid", 300)):
        (tmp_path / name / "sub").mkdir(parents=True)
        (tmp_path / name / "sub" / "f.bin").write_bytes(b"x" * size)
        (tmp_path / name / "g.bin").write_bytes(b"y" * 1)
    (tmp_path / "loose.txt").write_bytes(b"z" * 7)
    seen = []
    usage = garbage.folder_usage(str(tmp_path), progress=seen.append)
    assert [(os.path.basename(p), s) for p, s in usage.folders] == [("big", 5001), ("mid", 301), ("small", 11)]
    assert usage.loose_files == 7 and usage.total == 5001 + 301 + 11 + 7 and seen
    assert garbage.folder_usage(str(tmp_path / "missing")).folders == []


def test_folder_usage_does_not_cross_junctions_and_can_stop(tmp_path):
    import subprocess
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "f.bin").write_bytes(b"x" * 100)
    root = tmp_path / "root"
    root.mkdir()
    done = subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "link"), str(tmp_path / "real")], capture_output=True)
    if done.returncode != 0:
        pytest.skip("cannot create a junction here")
    assert garbage.folder_usage(str(root)).folders == []
    assert garbage.folder_usage(str(tmp_path), stop=lambda: True).truncated

# endregion


# region Statistics

def test_statistics_round_trip_and_totals(tmp_path):
    path = str(tmp_path / "s.json")
    assert stats.load(path) == []
    assert stats.record(0, 0, 0, path) == "" and not os.path.exists(path)           # nothing freed: nothing written
    stats.record(1000, 3, 0, path, now=NOW)
    stats.record(0, 0, 5, path, now=NOW + 60)
    stats.record(500, 1, 2, path, now=NOW + 86400)
    entries = stats.load(path)
    assert stats.totals(entries) == stats.Totals(3, 1500, 4, 7)


def test_statistics_per_day_include_the_empty_days_and_ignore_old_ones(tmp_path):
    path = str(tmp_path / "s.json")
    today = datetime.fromtimestamp(NOW)
    stats.record(100, 1, 0, path, now=NOW)
    stats.record(50, 1, 0, path, now=NOW - 86400)
    stats.record(999, 1, 0, path, now=NOW - 40 * 86400)
    days = stats.per_day(stats.load(path), 30, today)
    assert len(days) == 30 and days[-1][1] == 100 and days[-2][1] == 50 and sum(b for _d, b in days) == 150
    assert [d for d, _b in days] == sorted(d for d, _b in days)


def test_damaged_statistics_are_ignored_and_the_file_is_capped(tmp_path, monkeypatch):
    path = tmp_path / "s.json"
    path.write_text("not json")
    assert stats.load(str(path)) == []
    path.write_text('[{"t": 1, "bytes": 5}, {"x": 1}, "junk", {"t": "bad"}, {"t": 2, "bytes": -4}]')
    assert [e["bytes"] for e in stats.load(str(path))] == [5, 0]
    monkeypatch.setattr(stats, "MAX_ENTRIES", 3)
    for i in range(5):
        stats.record(i + 1, 1, 0, str(path), now=NOW + i)
    assert [e["bytes"] for e in stats.load(str(path))] == [3, 4, 5]


def test_an_unwritable_statistics_file_is_reported(tmp_path):
    blocker = tmp_path / "f"
    blocker.write_text("x")
    assert stats.record(1, 1, 0, str(blocker / "s.json"))

# endregion


# region Chart widgets

def painted_colors(widget, width=600):
    widget.resize(width, widget.sizeHint().height())
    image = widget.grab().toImage()
    return {image.pixelColor(x, y).rgb() for x in range(0, image.width(), 3) for y in range(0, image.height(), 3)}


def test_bar_chart_draws_its_bars_in_the_requested_colors(qapp):
    chart = charts.BarChart("Title", charts.ORANGE)
    chart.set_rows([charts.Bar("big", 100, "100 B"), charts.Bar("small", 10, "10 B"), charts.Bar("red", 50, "50 B", charts.RED)])
    assert chart.row_count() == 3 and chart.sizeHint().height() >= 28 + 3 * 26
    colors = painted_colors(chart)
    assert charts.ORANGE.rgb() in colors and charts.RED.rgb() in colors and charts.BLUE.rgb() not in colors


def test_charts_grow_with_their_rows_and_survive_empty_data(qapp):
    chart = charts.BarChart("Empty")
    base = chart.sizeHint().height()
    painted_colors(chart)                                              # empty: only the placeholder text
    chart.set_rows([charts.Bar(str(i), i, str(i)) for i in range(8)])
    assert chart.sizeHint().height() > base
    zero = charts.BarChart("Zeros")
    zero.set_rows([charts.Bar("none", 0, "0")])
    painted_colors(zero)


def test_stacked_bars_split_a_disk_into_segments_with_a_legend(qapp):
    chart = charts.StackedBarChart("Disks")
    chart.set_rows([charts.StackRow("C:", [charts.Segment(60, charts.BLUE), charts.Segment(5, charts.ORANGE),
                                           charts.Segment(35, charts.GREY)], "60 GB used"),
                    charts.StackRow("D:", [charts.Segment(0, charts.BLUE), charts.Segment(0, charts.GREY)], "empty")],
                   [("Used", charts.BLUE), ("Garbage", charts.ORANGE)])
    assert chart.row_count() == 3                                       # two disks and the legend
    colors = painted_colors(chart)
    assert {charts.BLUE.rgb(), charts.ORANGE.rgb(), charts.GREY.rgb()} <= colors


def test_column_chart_draws_columns_and_a_caption(qapp):
    chart = charts.ColumnChart("Freed", charts.GREEN)
    chart.set_values([(f"{d:02d}/10", 0 if d % 3 else d * 1000) for d in range(1, 31)], "42 MB in 30 days")
    assert charts.GREEN.rgb() in painted_colors(chart)
    quiet = charts.ColumnChart("None")
    quiet.set_values([("01/10", 0), ("02/10", 0)])
    painted_colors(quiet)                                               # all zero: placeholder, no crash

# endregion


# region The Overview page and the registry presets list

def test_the_overview_page_exists_and_reads_the_real_disks(window):  # noqa: F811
    window._refresh_overview()
    assert window.chart_disks.rows and window.chart_disks.rows[0].label.endswith(":")
    assert window.chart_categories.rows == [] and "Garbage found: 0 B in 0 item(s)" in window.overview_summary.text()
    assert window.usage_drive.count() == len(window.chart_disks.rows)


def test_found_garbage_is_charted_by_kind_and_on_its_drive(window):  # noqa: F811
    drive = window.chart_disks.rows[0].label
    items = [garbage.GarbageItem(f"{drive}\\a\\x.tmp", "File", 3_000_000), garbage.GarbageItem(f"{drive}\\a\\y.tmp", "File", 1_000_000),
             garbage.GarbageItem(f"{drive}\\a\\__pycache__", "Folder", 500_000)]
    window._on_garbage_scanned(garbage.FileScan(items), "")
    assert [(b.label, b.value) for b in window.chart_categories.rows] == [("Temporary files", 4_000_000), ("Python caches", 500_000)]
    assert "(2)" in window.chart_categories.rows[0].text
    assert [b.label for b in window.chart_biggest.rows] == ["x.tmp", "y.tmp", "__pycache__"]
    first = next(r for r in window.chart_disks.rows if r.label == drive)
    assert first.segments[1].value == 4_500_000 and "garbage 4.3 MB" in first.text
    assert "Garbage found: 4.3 MB in 3 item(s)" in window.overview_summary.text()


def test_low_confidence_leftovers_are_shown_but_not_counted_as_space_to_free(window):  # noqa: F811
    drive = window.chart_disks.rows[0].label
    items = [garbage.GarbageItem(f"{drive}\\a\\Old", "Folder", 2_000_000, 0.0, "", garbage.HIGH),
             garbage.GarbageItem(f"{drive}\\a\\npm", "Folder", 700_000_000, 0.0, "", garbage.LOW)]
    window._on_garbage_scanned(garbage.FileScan(items), "")
    labels = {b.label: b for b in window.chart_categories.rows}
    assert labels["Leftover folders (low confidence)"].color == charts.GREY and labels["Leftover folders (high confidence)"].color is None
    assert [b.label for b in window.chart_biggest.rows] == ["Old"]
    first = next(r for r in window.chart_disks.rows if r.label == drive)
    assert first.segments[1].value == 2_000_000
    text = window.overview_summary.text()
    assert "Garbage found: 1.9 MB in 1 item(s)" in text and "667.6 MB of low-confidence folders, not counted" in text
    assert garbage.is_likely(items[0]) and not garbage.is_likely(items[1]) and garbage.is_likely(garbage.GarbageItem("x", "File"))


def test_registry_entries_are_charted_by_kind(window):  # noqa: F811
    entries = [RegEntry("HKCU", "SOFTWARE\\a", None, dr.CAT_HISTORY), RegEntry("HKCU", "SOFTWARE\\b", None, dr.CAT_HISTORY),
               RegEntry("HKCU", "SOFTWARE\\c", None, dr.CAT_VENDOR)]
    window._on_registry_scanned(dr.RegScan(entries), "")
    assert [(b.label, b.value) for b in window.chart_registry.rows] == [(dr.CAT_HISTORY, 2), (dr.CAT_VENDOR, 1)]
    assert "Registry: 3 entries" in window.overview_summary.text()


def test_deleting_updates_the_charts_and_the_freed_total(window):  # noqa: F811
    drive = window.chart_disks.rows[0].label
    gone = garbage.GarbageItem(f"{drive}\\a\\x.tmp", "File", 2_000_000)
    kept = garbage.GarbageItem(f"{drive}\\a\\y.bak", "File", 1_000_000)
    window._on_garbage_scanned(garbage.FileScan([gone, kept]), "")
    window._on_garbage_deleted(garbage.DeleteResult([gone], [], 2_000_000), "")
    assert [b.label for b in window.chart_categories.rows] == ["Backups and old copies"]
    assert "Freed so far: 1.9 MB (1 item(s)" in window.overview_summary.text()
    assert window.chart_freed.values[-1][1] == 2_000_000 and "1.9 MB in 30 days" in window.chart_freed.caption
    entry = RegEntry("HKCU", "SOFTWARE\\a", None, dr.CAT_HISTORY)
    window._on_registry_scanned(dr.RegScan([entry]), "")
    window._on_registry_deleted(dr.RegDeleteResult([entry], [], []), "")
    assert window.chart_registry.rows == [] and "1 registry entry" in window.overview_summary.text()


def test_measuring_folders_fills_the_folder_chart(window, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setattr(window, "_start_call", lambda attr, fn, done, button=None, status="": (done(fn(), ""), True)[1])
    (tmp_path / "A").mkdir()
    (tmp_path / "A" / "f").write_bytes(b"x" * 2048)
    (tmp_path / "B").mkdir()
    (tmp_path / "B" / "f").write_bytes(b"x" * 100)
    window.usage_drive.clear()
    window.usage_drive.addItem(str(tmp_path))
    window._measure_folders()
    assert [(b.label, b.value) for b in window.chart_folders.rows] == [("A", 2048), ("B", 100)]
    assert str(tmp_path) in window.chart_folders.title


def test_the_registry_page_lists_the_presets_with_the_safe_ones_ticked(window):  # noqa: F811
    labels = [window.registry_presets.item(i).text() for i in range(window.registry_presets.count())]
    assert len(labels) == 8 and labels[0].endswith("[Safe]") and labels[-1].endswith("[Review]")
    assert window._checked_presets() == dr.DEFAULT_PRESETS
    assert "recreate" in window.registry_presets.item(5).toolTip().lower()


def test_scanning_presets_needs_one_and_passes_the_ticked_ones(window, dialogs, monkeypatch):  # noqa: F811
    from PySide6.QtCore import Qt
    asked = []
    monkeypatch.setattr(window, "_run_garbage_scan", lambda attr, fn, done, status: asked.append((attr, fn, status)))
    monkeypatch.setattr(dr, "scan_presets", lambda ids, **kw: asked.append(ids) or dr.RegScan([]))
    for i in range(window.registry_presets.count()):
        window.registry_presets.item(i).setCheckState(Qt.CheckState.Unchecked)
    window._registry_find_dead()
    assert dialogs["info"] and not asked
    window.registry_presets.item(6).setCheckState(Qt.CheckState.Checked)       # the COM preset
    window.registry_presets.item(7).setCheckState(Qt.CheckState.Checked)
    window._registry_find_dead()
    asked[0][1]()
    assert asked[1] == ["com", "vendors"]


def test_registry_rows_show_the_confidence_and_tint_the_guesses(window):  # noqa: F811
    entries = [RegEntry("HKCU", "SOFTWARE\\a", None, dr.CAT_VENDOR, "r", "a", dr.HIGH),
               RegEntry("HKCU", "SOFTWARE\\b", None, dr.CAT_VENDOR, "r", "b", dr.MEDIUM)]
    window._on_registry_scanned(dr.RegScan(entries), "")
    rows = {window.registry_tree.topLevelItem(i).text(0): window.registry_tree.topLevelItem(i)
            for i in range(window.registry_tree.topLevelItemCount())}
    assert rows["a"].text(4) == dr.HIGH and rows["b"].text(4) == dr.MEDIUM
    assert rows["b"].foreground(0).color().red() == 204 and rows["a"].foreground(0).style().name == "NoBrush"
    assert rows["a"].text(1) == "HKCU\\SOFTWARE\\a" and "HKCU\\SOFTWARE\\a" in rows["a"].toolTip(1)  # right after the name

# endregion
