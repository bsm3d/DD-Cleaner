"""
Ergonomics fixes of the interface: safe defaults of confirmations, no re-entrancy in the Garbage scans, lists that
sort, filter and tick the way they look, stop and shortcuts, remembered state, a window that fits small screens.
Nothing real is scanned or changed.
"""

from types import SimpleNamespace

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtCore import QEvent
from PySide6.QtWidgets import QDialog, QMessageBox, QPushButton, QRadioButton

from ddcleaner import dead_registry as dr
from ddcleaner.common import sys_exe
from ddcleaner.dead_registry import RegEntry
from ddcleaner.ui import main_window as mw_mod, tab_cleanup
from ddcleaner.ui.safe_text import count, listed
from ddcleaner.ui.tab_system_info import apply_tree_filter
from ddcleaner.workers import DISMWorker, SecurityAuditWorker

from test_ui_smoke import FakeRunning, dialogs, window  # noqa: F401  (fixtures)

DASH = chr(0x2014)


def rows(tree):
    return [tree.topLevelItem(i) for i in range(tree.topLevelItemCount())]


# region Confirmations and dialogs

def test_a_confirmation_defaults_to_no(window, monkeypatch):  # noqa: F811
    asked = []
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a: asked.append(a) or a[4]))
    assert window._confirm("Delete", "Delete 3 items?") is False        # the answer is the default button
    assert asked[0][4] == QMessageBox.StandardButton.No


def test_a_long_confirmation_carries_the_full_list(window, dialogs):  # noqa: F811
    lines = [f"C:\\junk\\{n}" for n in range(30)]
    assert window._full_list(lines[:3]) == ""                            # short: the box already shows everything
    assert window._full_list(lines).count("\n") == 29
    dialogs["answer"] = QMessageBox.StandardButton.Yes
    assert window._confirm("Delete", "Delete?", window._full_list(lines)) is True
    assert "Delete?" in dialogs["question"][-1][0]


def test_enter_in_a_dialog_presses_only_the_chosen_button(window):  # noqa: F811
    dialog = QDialog(window)
    first, close = QPushButton("Show", dialog), QPushButton("Close", dialog)
    window._set_dialog_default(dialog, close)
    assert close.isDefault() and not first.isDefault() and not first.autoDefault()
    window._set_dialog_default(dialog)
    assert not close.isDefault()


def test_profiles_are_real_radio_buttons_and_applying_needs_administrator(window, dialogs, monkeypatch):  # noqa: F811
    seen = {}

    def inspect(dialog):
        seen["radios"] = [(r.text(), r.isChecked()) for r in dialog.findChildren(QRadioButton)]
        dialog.findChildren(QRadioButton)[2].setChecked(True)
        seen["default"] = [b.text() for b in dialog.findChildren(QPushButton) if b.isDefault()]
        return 0
    monkeypatch.setattr(QDialog, "exec", inspect)
    window._show_hardening_profiles()
    assert len(seen["radios"]) == 3 and [checked for _text, checked in seen["radios"]] == [False, True, False]
    assert seen["default"] == ["✅ Apply profile..."] and window.selected_hardening_profile.value in seen["radios"][2][0]
    monkeypatch.setattr("ddcleaner.ui.tab_security.SystemUtils.check_admin_privileges", staticmethod(lambda: False))
    window._apply_hardening_profile(QDialog(window))
    assert dialogs["warning"] and not dialogs["question"]

# endregion


# region Garbage

def test_enter_during_a_scan_keeps_the_stop_request(window, dialogs):  # noqa: F811
    window.garbage_file_worker = FakeRunning()
    window._set_garbage_scanning(True)
    window._stop_garbage_scan()
    assert window.garbage_cancel.is_set() and window.garbage_stop_btns[0].text().endswith("Stopping...")
    window.garbage_pattern.setText("*.tmp")
    window._garbage_search_files()                                      # what Enter in the field does
    window.registry_pattern.setText("adobe*")
    window._registry_search()
    assert window.garbage_cancel.is_set()                               # the Stop already asked is not forgotten
    assert not window.garbage_search_btn.isEnabled() and not window.garbage_delete_btn.isEnabled()
    assert not dialogs["info"] and "already running" in window.status_label.text()
    assert isinstance(window.garbage_file_worker, FakeRunning)          # no second scan was started


def test_stop_buttons_are_only_live_during_a_scan(window):  # noqa: F811
    assert len(window.garbage_stop_btns) == 3 and not any(b.isEnabled() for b in window.garbage_stop_btns)
    window._stop_garbage_scan()
    assert not window.garbage_cancel.is_set()                           # nothing runs: nothing to stop
    window._set_garbage_scanning(True)
    assert all(b.isEnabled() for b in window.garbage_stop_btns)
    window._scan_finished()
    assert window.garbage_search_btn.isEnabled() and not window.garbage_stop_btns[0].isEnabled()


def test_registry_location_sits_next_to_the_name_with_a_real_width(window):  # noqa: F811
    tree = window.registry_tree
    assert [tree.headerItem().text(c) for c in range(2)] == ["Name", "Location"]
    assert tree.columnWidth(1) >= 300 and tree.columnCount() == len(tab_cleanup.REGISTRY_COLUMNS)


def test_rows_hidden_by_the_filter_are_never_ticked(window):  # noqa: F811
    entries = [RegEntry("HKCU", "SOFTWARE\\alpha", None, dr.CAT_VENDOR, "r", "alpha", dr.HIGH),
               RegEntry("HKCU", "SOFTWARE\\beta", None, dr.CAT_VENDOR, "r", "beta", dr.MEDIUM)]
    window._on_registry_scanned(dr.RegScan(entries), "")
    tree = window.registry_tree
    apply_tree_filter(tree, "ALPHA")
    assert [r.isHidden() for r in sorted(rows(tree), key=lambda r: r.text(0))] == [False, True]
    tab_cleanup.set_all_checked(tree, True)
    assert [e.display_name for e in tab_cleanup.checked_payloads(tree)] == ["alpha"]
    apply_tree_filter(tree, "")
    assert [e.display_name for e in tab_cleanup.checked_payloads(tree)] == ["alpha"]   # beta was never ticked
    tab_cleanup.set_all_checked(tree, True)
    tab_cleanup.tick_where(tree, lambda entry: entry.confidence != dr.MEDIUM)          # "Tick high confidence"
    assert [e.display_name for e in tab_cleanup.checked_payloads(tree)] == ["alpha"]


def test_space_ticks_every_selected_row(window):  # noqa: F811
    entries = [RegEntry("HKCU", f"SOFTWARE\\{n}", None, dr.CAT_VENDOR, "r", n, dr.HIGH) for n in "abc"]
    window._on_registry_scanned(dr.RegScan(entries), "")
    tree = window.registry_tree
    for row in rows(tree)[:2]:
        row.setSelected(True)
    space = QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Space, Qt.KeyboardModifier.NoModifier)
    tree.keyPressEvent(space)
    assert len(tab_cleanup.checked_payloads(tree)) == 2
    tree.keyPressEvent(space)
    assert tab_cleanup.checked_payloads(tree) == []

# endregion


# region Lists

def test_driver_age_sorts_as_a_number_oldest_first(window):  # noqa: F811
    drivers = [{"name": f"d{age}", "date_str": "2020-01-01", "version": "1", "provider": "p", "path": "oem1.inf",
                "age_days": age, "class": "Net"} for age in (999, 400, 30, 1825)]
    window._populate_drivers_tree(drivers)
    assert [r.text(5) for r in rows(window.drivers_tree)] == ["1825", "999", "400", "30"]
    window.all_drivers = drivers
    window.driver_age_combo.setCurrentIndex(3)                          # older than 3 years
    assert [r.text(5) for r in rows(window.drivers_tree)] == ["1825"]


def test_an_empty_blocklist_result_does_not_stay_filtered(window):  # noqa: F811
    window.vuln_only_flagged_cb.setChecked(True)
    window._on_vulnerable_drivers_checked([], "")
    assert not window.vuln_only_flagged_cb.isChecked()


def test_text_helpers():
    assert count(1, "entry", "entries") == "1 entry" and count(3, "entry", "entries") == "3 entries"
    assert count(2, "file") == "2 files"
    assert listed(["a", "b", "c"], 2) == "a\nb\n... and 1 more" and listed(["a"], 2) == "a"


def test_no_long_dash_and_no_french_in_the_interface_code():
    import pathlib
    root = pathlib.Path(mw_mod.__file__).resolve().parents[2]
    files = list((root / "ddcleaner").rglob("*.py")) + [root / "DD_Cleaner.py"]
    assert not [f.name for f in files if DASH in f.read_text(encoding="utf-8")]
    security = (root / "ddcleaner" / "ui" / "tab_security.py").read_text(encoding="utf-8")
    assert not [word for word in ("Risque", "Profils disponibles", "Erreurs:", "Sauvegardes") if word in security]

# endregion


# region Stop, progress and state

def test_the_progress_bar_stays_until_every_operation_ends(window):  # noqa: F811
    bar = window.progress_bar
    bar.setVisible(True)
    bar.setVisible(True)
    bar.setVisible(False)
    assert bar.active == 1 and not bar.isHidden()                       # one operation still runs
    bar.setVisible(False)
    bar.setVisible(False)                                               # an extra "done" never goes below zero
    assert bar.active == 0 and bar.isHidden()


def test_stop_reaches_the_running_scans_but_not_the_next_one(window):  # noqa: F811
    stopped = window._stopper("hunt_process_worker")
    window._stop_current()
    assert not stopped()                                                # nothing runs: Esc does nothing
    window.progress_bar.setVisible(True)
    window._stop_current()
    assert stopped() and window.status_label.text() == "Stopping..."
    assert not window._stopper("hunt_process_worker")()                 # a scan started afterwards is not born stopped
    window.progress_bar.setVisible(False)


def test_a_failed_audit_shows_no_score(window):  # noqa: F811
    worker = SecurityAuditWorker(SimpleNamespace(run_full_audit=lambda: 1 / 0))
    results = []
    worker.finished.connect(lambda score, domains: results.append((score, domains)))
    worker.run()
    assert results == [(0, {})] and "division" in worker.error
    window.security_audit_worker = worker
    window.progress_bar.setVisible(True)
    window._on_security_audit_complete(0, {})
    assert window.security_score_label.text() == "Score: -- / 100"
    assert "failed" in window.security_status_label.text() and "Critical" not in window.security_status_label.text()
    assert not window.security_apply_profile_btn.isEnabled() and not window.security_details_btn.isEnabled()
    assert window.security_audit_btn.isEnabled() and window.progress_bar.active == 0


def test_repair_output_is_streamed_and_a_stop_is_not_an_error(window, dialogs):  # noqa: F811
    worker = DISMWorker([sys_exe("cmd.exe"), "/c", "echo first& echo second"])
    chunks, done = [], []
    worker.output.connect(chunks.append)
    worker.finished.connect(lambda code, text: done.append((code, text)))
    worker.run()
    assert done[0][0] == 0 and "first" in "".join(chunks) and "second" in done[0][1] and "\r" not in done[0][1]

    window.dism_worker = SimpleNamespace(stopped=True, timed_out=False, isRunning=lambda: False)
    window.progress_bar.setVisible(True)
    window._set_repair_running(True)
    assert window.repair_stop_btn.isEnabled() and not window.sfc_scan_btn.isEnabled()
    window._on_dism_output("live line\n")
    before = len(dialogs["warning"])
    window._on_dism_finished(1, "live line\n")
    assert len(dialogs["warning"]) == before and "stopped" in window.status_label.text()
    assert window.sfc_scan_btn.isEnabled() and not window.repair_stop_btn.isEnabled()
    assert window.dism_output.toPlainText().count("live line") == 1    # not appended a second time at the end


def test_network_reset_needs_administrator(window, dialogs, monkeypatch):  # noqa: F811
    monkeypatch.setattr("ddcleaner.ui.tab_health.SystemUtils.check_admin_privileges", staticmethod(lambda: False))
    window._run_network_reset()
    assert dialogs["warning"] and not dialogs["question"] and "network_reset" not in window._bg_threads


def test_interface_state_is_remembered(window, qapp):  # noqa: F811
    window.clam_fast_cb.setChecked(True)
    window.clam_cache_days.setValue(21)
    window.tab_widget.setCurrentIndex(3)
    window.garbage_tree.setColumnWidth(0, 333)
    window.garbage_permanent_cb.setChecked(True)
    window._save_ui_state()
    again = mw_mod.MainWindow()
    try:
        assert again.clam_fast_cb.isChecked() and again.clam_cache_days.value() == 21
        assert again.tab_widget.currentIndex() == 3 and again.garbage_tree.columnWidth(0) == 333
        assert not again.clam_archives_cb.isEnabled()                   # Fast mode switches archives off: shown as such
        assert not again.garbage_permanent_cb.isChecked()               # a destructive option is never remembered
    finally:
        again._bg_threads.clear()
        again.close()
        again.deleteLater()


def test_the_window_fits_a_small_screen(window):  # noqa: F811
    """1366 x 768, or 1080p at 150 % (1280 x 720 logical): the long pages scroll instead of pushing the bottom
    of the window off screen."""
    assert window.minimumSizeHint().height() <= 700


def test_not_administrator_is_said_once_without_a_dialog(window, dialogs, monkeypatch):  # noqa: F811
    monkeypatch.setattr("ddcleaner.ui.main_window.SystemUtils.check_admin_privileges", staticmethod(lambda: False))
    before = len(dialogs["warning"])
    plain_user = mw_mod.MainWindow()
    try:
        assert len(dialogs["warning"]) == before and "not administrator" in plain_user.windowTitle()
        assert any("Restart as administrator" in b.text() for b in plain_user.findChildren(QPushButton))
    finally:
        plain_user._bg_threads.clear()
        plain_user.close()
        plain_user.deleteLater()

# endregion
