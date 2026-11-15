"""Garbage tab: find leftovers by word or wildcard (files and registry), find what uninstalled programs left
behind, list it, and delete what the user ticks. Searching changes nothing."""

import os
import subprocess
import threading
from datetime import datetime
from typing import List

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit, QComboBox, QCheckBox, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QMessageBox, QFileDialog, QListWidget, QListWidgetItem, QScrollArea
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from ddcleaner import dead_registry, garbage, garbage_stats
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM32, safe_environment, sys_exe
from ddcleaner.system_utils import SystemUtils
from ddcleaner.ui import charts
from ddcleaner.ui.safe_text import plain, count, listed
from ddcleaner.ui.tab_system_info import make_tree, primary, tree_filter, apply_tree_filter

SORT_ROLE = Qt.ItemDataRole.UserRole + 1
CONFIDENCE_COLORS = {garbage.HIGH: QColor(Qt.GlobalColor.red), garbage.MEDIUM: QColor(204, 112, 0)}
LISTED_IN_CONFIRMATION = 8
FILE_COLUMNS = ["Name", "Type", "Size", "Modified", "Confidence", "Reason", "Path"]
REGISTRY_COLUMNS = ["Name", "Location", "Type", "Category", "Confidence", "Reason", "Data"]
RISK_COLORS = {"Safe": QColor(34, 160, 90), "Check": QColor(204, 112, 0), "Review": QColor(220, 60, 60)}
MAX_BARS = 10
PATTERN_HELP = ("A word finds every name containing it. * and ? are wildcards (*.vscode, tmpclaude-*). "
                "Put a name in double quotes for an exact match (\"nul\"). Separate several with ;")


class SortableItem(QTreeWidgetItem):
    """Sorts on the number stored in SORT_ROLE when there is one (sizes, dates), otherwise on the text."""

    def __lt__(self, other):
        column = self.treeWidget().sortColumn()
        mine, theirs = self.data(column, SORT_ROLE), other.data(column, SORT_ROLE)
        if mine is not None and theirs is not None:
            return mine < theirs
        return self.text(column).lower() < other.text(column).lower()


def checkable(item: QTreeWidgetItem, checked: bool = False):
    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
    item.setCheckState(0, Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)


def not_checkable(item: QTreeWidgetItem):
    """No checkbox: Qt rows are checkable by default, so the flag has to be removed."""
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)


def tickable_rows(tree: QTreeWidget) -> list:
    """Rows that have a checkbox and are on screen (a row hidden by the filter is never ticked or acted on)."""
    rows = [tree.topLevelItem(i) for i in range(tree.topLevelItemCount())]
    return [item for item in rows if item.flags() & Qt.ItemFlag.ItemIsUserCheckable and not item.isHidden()]


def checked_payloads(tree: QTreeWidget) -> list:
    return [item.data(0, Qt.ItemDataRole.UserRole) for item in tickable_rows(tree)
            if item.checkState(0) == Qt.CheckState.Checked]


def set_all_checked(tree: QTreeWidget, checked: bool):
    tick_where(tree, lambda _payload: checked)


def tick_where(tree: QTreeWidget, wanted):
    """Tick the rows whose payload satisfies `wanted`, untick the others."""
    for item in tickable_rows(tree):
        ticked = wanted(item.data(0, Qt.ItemDataRole.UserRole))
        item.setCheckState(0, Qt.CheckState.Checked if ticked else Qt.CheckState.Unchecked)


def tick_buttons(tree: QTreeWidget) -> list:
    """'Tick all' and 'Untick all' for a list with checkboxes."""
    tick_all, untick_all = QPushButton("Tick all"), QPushButton("Untick all")
    tick_all.setToolTip("Tick every row shown (Space ticks the selected rows)")
    tick_all.clicked.connect(lambda: set_all_checked(tree, True))
    untick_all.clicked.connect(lambda: set_all_checked(tree, False))
    return [tick_all, untick_all]


def remove_rows(tree: QTreeWidget, gone: list):
    """Remove the rows whose payload is in `gone` (identity)."""
    ids = {id(p) for p in gone}
    for i in reversed(range(tree.topLevelItemCount())):
        if id(tree.topLevelItem(i).data(0, Qt.ItemDataRole.UserRole)) in ids:
            tree.takeTopLevelItem(i)


class CleanupTabMixin:
    """Garbage tab. Mixed into MainWindow."""

    def _create_cleanup_tab(self):
        self.garbage_cancel = threading.Event()  # set by the Stop button, checked by every scan
        self.garbage_custom_root = ""
        self.garbage_stop_btns: List[QPushButton] = []
        self._garbage_scanning = False
        self.garbage_found, self.registry_found = [], []   # what the last searches listed (the charts read them)
        self.folder_usage = None
        tabs = QTabWidget()
        tabs.addTab(self._create_garbage_files_page(), "Files and folders")
        tabs.addTab(self._create_garbage_registry_page(), "Registry")
        tabs.addTab(self._create_garbage_overview_page(), "Overview")
        self.garbage_tabs = tabs
        self.scan_all_btn = QPushButton("🔎 Scan all")
        self.scan_all_btn.setToolTip("Every file preset and the leftovers of uninstalled programs (in the place chosen on the "
                                     "Files page), then every registry preset. Nothing is changed: you tick what to delete.")
        self.scan_all_btn.clicked.connect(self._scan_all)
        stop_all = self._garbage_stop_button()
        corner = QWidget()
        corner_layout = QHBoxLayout(corner)
        corner_layout.setContentsMargins(0, 0, 0, 0)
        corner_layout.addWidget(self.scan_all_btn)
        corner_layout.addWidget(stop_all)
        tabs.setCornerWidget(corner, Qt.Corner.TopRightCorner)
        self.tab_widget.addTab(tabs, "🧹 Garbage")
        self._set_garbage_scanning(False)

    def _garbage_stop_button(self) -> QPushButton:
        button = QPushButton("⏹ Stop")
        button.clicked.connect(self._stop_garbage_scan)
        self.garbage_stop_btns.append(button)
        return button

    def _stop_garbage_scan(self):
        """Ask the running scan to stop (it finishes the folder or key it is reading)."""
        if not self._garbage_scanning:
            return
        self.garbage_cancel.set()
        for button in self.garbage_stop_btns:
            button.setEnabled(False)
            button.setText("⏹ Stopping...")

    def _garbage_running(self) -> bool:
        workers = (getattr(self, name, None) for name in ("garbage_file_worker", "garbage_reg_worker",
                                                          "garbage_delete_worker"))
        return any(w is not None and w.isRunning() for w in workers)

    def _set_garbage_scanning(self, scanning: bool):
        """Scan and delete buttons are off during a scan; the Stop buttons are on only then."""
        self._garbage_scanning = scanning
        for button in self._scan_controls() + [self.garbage_delete_btn, self.registry_delete_btn]:
            button.setEnabled(not scanning)
        for button in self.garbage_stop_btns:
            button.setEnabled(scanning)
            button.setText("⏹ Stop")

    def _garbage_stopped(self) -> bool:
        return self.stop_flag.is_set() or self.garbage_cancel.is_set()

    def _scan_controls(self) -> List[QPushButton]:
        return [self.garbage_search_btn, self.garbage_leftovers_btn, self.registry_search_btn, self.registry_dead_btn,
                self.scan_all_btn]

    def _scan_all(self):
        """Every file preset + the leftovers of removed programs, then every registry preset, one after the other."""
        roots = garbage.search_roots(self.garbage_where.currentData(), self.garbage_custom_root)
        if not roots:
            QMessageBox.information(self, "Info", "There is no folder to search: choose where on the Files page.")
            return
        patterns = ";".join(garbage.PRESETS.values())
        stopped = self._garbage_stopped
        age = self._min_age_days()

        def files():
            found = garbage.search_files(patterns, roots, stopped, self._update_status, min_age_days=age)
            if stopped():
                return found
            self._update_status("Looking for leftovers of uninstalled programs...")
            leftovers = garbage.find_leftovers(dead_registry.installed_markers(), stopped, self._update_status,
                                               min_age_days=age)
            return garbage.merge_scans(found, leftovers)
        self._run_garbage_scan("garbage_file_worker", files, self._on_scan_all_files, "Scan all: files and folders...")

    def _on_scan_all_files(self, scan, error):
        self._on_garbage_scanned(scan, error)          # fills the Files page, re-enables the buttons
        if error or self._garbage_stopped():
            return
        worker = getattr(self, "garbage_file_worker", None)
        if worker is not None:
            worker.wait(5000)  # its thread is ending: the registry scan must not be refused as "already running"
        ids = [p.id for p in dead_registry.PRESETS]
        stopped = self._garbage_stopped
        self._run_garbage_scan(
            "garbage_reg_worker", lambda: dead_registry.scan_presets(ids, stop=stopped, progress=self._update_status),
            self._on_scan_all_registry, "Scan all: registry...")

    def _on_scan_all_registry(self, scan, error):
        self._on_registry_scanned(scan, error)
        if error or self._garbage_stopped():
            return
        self.garbage_tabs.setCurrentIndex(self.garbage_tabs.count() - 1)      # the Overview shows the whole picture
        likely = sum(i.size for i in self.garbage_found if garbage.is_likely(i))
        self._update_status(f"Scan all done: {garbage.human_size(likely)} of garbage on disk, "
                            f"{count(len(self.registry_found), 'registry entry', 'registry entries')}.")

    def _run_garbage_scan(self, attr: str, function, on_done, status: str):
        if self._garbage_running():
            # Enter in a search field during a scan lands here: nothing may be reset, least of all a Stop already asked
            self._update_status("A Garbage scan or deletion is already running.")
            return
        self.garbage_cancel.clear()
        self._set_garbage_scanning(True)
        if not self._start_call(attr, function, on_done, None, status):
            self._set_garbage_scanning(False)

    def _scan_finished(self):
        self._set_garbage_scanning(False)

    def _open_in_explorer(self, args: List[str]):
        try:
            subprocess.Popen([sys_exe("explorer.exe")] + args, cwd=SYSTEM32, env=safe_environment(),
                             creationflags=SUBPROCESS_FLAGS)
        except OSError as e:
            QMessageBox.warning(self, "Error", plain(f"Could not open Explorer: {e}"))

    def _confirm_list(self, lines: List[str]) -> str:
        return listed(lines, LISTED_IN_CONFIRMATION)

    @staticmethod
    def _full_list(lines: List[str]) -> str:
        """The whole list for the "Show Details" part of a confirmation, when the box itself only shows the start."""
        return "\n".join(lines) if len(lines) > LISTED_IN_CONFIRMATION else ""

    # region Files and folders

    def _create_garbage_files_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        info = QLabel("Search by word or wildcard, or look for what uninstalled programs left behind. "
                      "Nothing is changed until you tick items and delete them.")
        info.setWordWrap(True)
        layout.addWidget(info)

        row = QHBoxLayout()
        self.garbage_pattern = QLineEdit()
        self.garbage_pattern.setPlaceholderText("Word or wildcard, e.g. *.vscode   tmpclaude-*   *.tmp;*.bak")
        self.garbage_pattern.setToolTip(PATTERN_HELP)
        self.garbage_pattern.returnPressed.connect(self._garbage_search_files)
        self.garbage_preset = QComboBox()
        self.garbage_preset.addItem("Presets...")
        self.garbage_preset.addItems(list(garbage.PRESETS))
        self.garbage_preset.activated.connect(self._garbage_pick_preset)
        self.garbage_where = QComboBox()
        for label, code in (("User profile", garbage.WHERE_PROFILE), ("AppData, ProgramData and Temp", garbage.WHERE_APPDATA),
                            ("All fixed drives", garbage.WHERE_DRIVES), ("Choose a folder...", garbage.WHERE_CUSTOM)):
            self.garbage_where.addItem(label, code)
        self.garbage_where.activated.connect(self._garbage_pick_where)
        row.addWidget(self.garbage_pattern, 1)
        row.addWidget(self.garbage_preset)
        row.addWidget(QLabel("in"))
        row.addWidget(self.garbage_where)
        layout.addLayout(row)

        row = QHBoxLayout()
        self.garbage_search_btn = primary(QPushButton("🔍 Search"))
        self.garbage_search_btn.clicked.connect(self._garbage_search_files)
        self.garbage_leftovers_btn = QPushButton("🧳 Leftovers of uninstalled programs")
        self.garbage_leftovers_btn.setToolTip("Folders in AppData, ProgramData and Program Files that no installed "
                                              "program claims")
        self.garbage_leftovers_btn.clicked.connect(self._garbage_find_leftovers)
        stop_btn = self._garbage_stop_button()
        self.garbage_age = QComboBox()
        for label, days in garbage.AGE_CHOICES:
            self.garbage_age.addItem(label, days)
        self.garbage_age.setToolTip("Only list files and folders last modified at least this long ago. Applies to the "
                                    "search, the leftovers and Scan all (the registry has no dates).")
        for button in (self.garbage_search_btn, self.garbage_leftovers_btn, stop_btn):
            row.addWidget(button)
        row.addStretch()
        row.addWidget(QLabel("Modified"))
        row.addWidget(self.garbage_age)
        layout.addLayout(row)

        self.garbage_tree = make_tree(FILE_COLUMNS, (260, 70, 90, 130, 90, 320, 420),
                                      "Search, look for leftovers or use Scan all to fill this list.")
        row = QHBoxLayout()
        self.garbage_summary = QLabel("Nothing searched yet.")
        self.garbage_summary.setWordWrap(True)
        row.addWidget(self.garbage_summary, 1)
        row.addWidget(tree_filter(self.garbage_tree))
        layout.addLayout(row)
        layout.addWidget(self.garbage_tree)

        row = QHBoxLayout()
        tick_likely = QPushButton("Tick likely")
        tick_likely.setToolTip("Tick the red and orange rows only: low-confidence folders stay unticked")
        tick_likely.clicked.connect(lambda: tick_where(self.garbage_tree, garbage.is_likely))
        open_btn = QPushButton("📂 Open location")
        open_btn.clicked.connect(self._garbage_open_location)
        export_btn = QPushButton("💾 Export")
        export_btn.setToolTip("Save the rows shown as a CSV file")
        export_btn.clicked.connect(lambda: self._export_tree(self.garbage_tree, "garbage_files.csv"))
        self.garbage_permanent_cb = QCheckBox("Delete permanently")
        self.garbage_permanent_cb.setToolTip("Skip the Recycle Bin: the ticked items cannot be recovered")
        self.garbage_delete_btn = QPushButton("🗑 Delete ticked items...")
        self.garbage_delete_btn.clicked.connect(self._garbage_delete_files)
        for widget in tick_buttons(self.garbage_tree) + [tick_likely, open_btn, export_btn]:
            row.addWidget(widget)
        row.addStretch()
        row.addWidget(self.garbage_permanent_cb)
        row.addWidget(self.garbage_delete_btn)
        layout.addLayout(row)

        note = QLabel("ℹ️ Red: very likely leftovers (Program Files folder with no program inside). Orange: no installed "
                      "program matches the name and nothing touched it for 90 days. Portable tools you copied yourself "
                      "look the same, so read the list before ticking. Deleted items go to the Recycle Bin unless "
                      "\"Delete permanently\" is ticked.")
        note.setWordWrap(True)
        note.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(note)
        return page

    def _garbage_pick_preset(self, index: int):
        name = self.garbage_preset.itemText(index)
        if name in garbage.PRESETS:
            self.garbage_pattern.setText(garbage.PRESETS[name])
        self.garbage_preset.setCurrentIndex(0)

    def _garbage_pick_where(self, index: int):
        if self.garbage_where.itemData(index) != garbage.WHERE_CUSTOM:
            return
        folder = QFileDialog.getExistingDirectory(self, "Folder to search", self.garbage_custom_root or "")
        if folder:
            self.garbage_custom_root = os.path.normpath(folder)
            self.garbage_where.setItemText(index, f"Folder: {self.garbage_custom_root}")
        elif not self.garbage_custom_root:
            self.garbage_where.setCurrentIndex(0)

    def _garbage_search_files(self):
        text = self.garbage_pattern.text().strip()
        try:
            garbage.compile_patterns(text)
        except ValueError as e:
            QMessageBox.information(self, "Info", plain(str(e)))
            return
        where = self.garbage_where.currentData()
        roots = garbage.search_roots(where, self.garbage_custom_root)
        if not roots:
            QMessageBox.information(self, "Info", "There is no folder to search here.")
            return
        stopped = self._garbage_stopped
        age = self._min_age_days()
        self._run_garbage_scan(
            "garbage_file_worker",
            lambda: garbage.search_files(text, roots, stopped, self._update_status, min_age_days=age),
            self._on_garbage_scanned, f"Searching {text}...")

    def _min_age_days(self) -> int:
        return self.garbage_age.currentData() or 0

    def _garbage_find_leftovers(self):
        stopped = self._garbage_stopped
        age = self._min_age_days()

        def collect():
            self._update_status("Reading the installed programs...")
            return garbage.find_leftovers(dead_registry.installed_markers(), stopped, self._update_status,
                                          min_age_days=age)
        self._run_garbage_scan("garbage_file_worker", collect, self._on_garbage_scanned,
                               "Looking for leftovers of uninstalled programs...")

    def _on_garbage_scanned(self, scan, error):
        self._scan_finished()
        if error:
            self._update_status("Search failed.")
            QMessageBox.warning(self, "Error", plain(f"The search failed: {error}"))
            return
        tree = self.garbage_tree
        tree.setSortingEnabled(False)
        tree.clear()
        for entry in scan.items:
            modified = datetime.fromtimestamp(entry.modified).strftime("%Y-%m-%d %H:%M") if entry.modified else ""
            item = SortableItem([os.path.basename(entry.path) or entry.path, entry.kind, garbage.human_size(entry.size),
                                 modified, entry.confidence, entry.reason, entry.path])
            item.setData(0, Qt.ItemDataRole.UserRole, entry)
            item.setData(2, SORT_ROLE, entry.size)
            item.setData(3, SORT_ROLE, entry.modified)
            item.setData(4, SORT_ROLE, garbage.CONFIDENCE_ORDER[entry.confidence])
            item.setToolTip(6, plain(entry.path))
            item.setToolTip(0, plain(entry.path))  # the Path column is often off screen
            color = CONFIDENCE_COLORS.get(entry.confidence)
            if garbage.protected_reason(entry.path):
                item.setToolTip(0, plain(f"{entry.path}\nProtected: this item cannot be deleted from here"))
                color = QColor(Qt.GlobalColor.gray)
                not_checkable(item)
            else:
                checkable(item)
            if color:
                for column in range(len(FILE_COLUMNS)):
                    item.setForeground(column, color)
            tree.addTopLevelItem(item)
        tree.setSortingEnabled(True)
        tree.sortItems(4, Qt.SortOrder.AscendingOrder)  # most likely leftovers first (search results all tie)
        apply_tree_filter(tree)
        total = sum(i.size for i in scan.items)
        more = f" (stopped at the first {garbage.SEARCH_LIMIT}: refine the search)" if scan.truncated else ""
        stopped = " (search stopped)" if self._garbage_stopped() else ""
        self.garbage_summary.setText(f"{len(scan.items)} item(s), {garbage.human_size(total)}{more}{stopped}. "
                                     f"{scan.folders_seen} folders looked at.")
        self.garbage_found = list(scan.items)
        self._refresh_overview()
        self._update_status("Search done.")

    def _garbage_open_location(self):
        items = self.garbage_tree.selectedItems()
        entry = items[0].data(0, Qt.ItemDataRole.UserRole) if items else None
        if entry is None or not os.path.lexists(entry.path):
            QMessageBox.information(self, "Info", "Select an item that still exists.")
            return
        self._open_in_explorer(["/select,", entry.path])

    def _garbage_delete_files(self):
        entries = checked_payloads(self.garbage_tree)
        if not entries:
            QMessageBox.information(self, "Info", "Tick the items to delete first.")
            return
        if self._garbage_running():
            QMessageBox.information(self, "Info", "Wait for the running scan or deletion to finish.")
            return
        permanent = self.garbage_permanent_cb.isChecked()
        how = ("PERMANENTLY. They cannot be recovered." if permanent else
               "They go to the Recycle Bin (an item too large for it is deleted for good).")
        paths = [e.path for e in entries]
        text = (f"Delete {count(len(entries), 'item')}, {garbage.human_size(sum(e.size for e in entries))}?\n{how}\n\n"
                + self._confirm_list(paths))
        if not self._confirm("Delete", text, self._full_list(paths)):
            return
        self._start_call("garbage_delete_worker", lambda: garbage.delete_items(entries, permanent, stop=self.stop_flag.is_set),
                         self._on_garbage_deleted, self.garbage_delete_btn, "Deleting...")

    def _on_garbage_deleted(self, result, error):
        if error:
            QMessageBox.warning(self, "Error", plain(f"The deletion failed: {error}"))
            return
        remove_rows(self.garbage_tree, result.deleted)
        gone = {id(i) for i in result.deleted}
        self.garbage_found = [i for i in self.garbage_found if id(i) not in gone]
        garbage_stats.record(result.freed, len(result.deleted))
        self._refresh_overview()
        self.garbage_summary.setText(f"{len(result.deleted)} deleted, {garbage.human_size(result.freed)} freed. "
                                     f"{count(self.garbage_tree.topLevelItemCount(), 'item')} left in the list.")
        self._update_status(f"{count(len(result.deleted), 'item')} deleted.")
        if result.failed:
            lines = [f"{item.path}: {why}" for item, why in result.failed]
            QMessageBox.warning(self, "Not everything was deleted",
                                plain(f"{count(len(result.failed), 'item')} could not be deleted:\n\n"
                                      + self._confirm_list(lines)))

    # endregion

    # region Registry

    def _create_garbage_registry_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        info = QLabel("Search the registry (HKCU\\SOFTWARE and HKLM\\SOFTWARE) by word or wildcard, or list entries of "
                      "programs that no longer exist. Every key is exported to a .reg backup before it is changed.")
        info.setWordWrap(True)
        layout.addWidget(info)

        row = QHBoxLayout()
        self.registry_pattern = QLineEdit()
        self.registry_pattern.setPlaceholderText("Word or wildcard, e.g. *oldvendor*   adobe*")
        self.registry_pattern.setToolTip(PATTERN_HELP)
        self.registry_pattern.returnPressed.connect(self._registry_search)
        self.registry_names_cb = QCheckBox("Key names")
        self.registry_values_cb = QCheckBox("Value names")
        self.registry_data_cb = QCheckBox("Value data")
        for box in (self.registry_names_cb, self.registry_values_cb, self.registry_data_cb):
            box.setChecked(True)
        row.addWidget(self.registry_pattern, 1)
        for box in (self.registry_names_cb, self.registry_values_cb, self.registry_data_cb):
            row.addWidget(box)
        layout.addLayout(row)

        row = QHBoxLayout()
        self.registry_search_btn = primary(QPushButton("🔍 Search"))
        self.registry_search_btn.clicked.connect(self._registry_search)
        self.registry_dead_btn = QPushButton("🧾 Scan the ticked presets")
        self.registry_dead_btn.setToolTip("Look for the kinds of entries ticked below: dead programs, history lists, "
                                          "leftovers of programs that are no longer installed...")
        self.registry_dead_btn.clicked.connect(self._registry_find_dead)
        stop_btn = self._garbage_stop_button()
        for button in (self.registry_search_btn, self.registry_dead_btn, stop_btn):
            row.addWidget(button)
        row.addStretch()
        layout.addLayout(row)

        self.registry_presets = QListWidget()
        self.registry_presets.setMaximumHeight(150)
        for preset in dead_registry.PRESETS:
            item = QListWidgetItem(f"{preset.label}   [{preset.risk}]")
            item.setData(Qt.ItemDataRole.UserRole, preset.id)
            item.setToolTip(plain(preset.description))
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if preset.id in dead_registry.DEFAULT_PRESETS else Qt.CheckState.Unchecked)
            item.setForeground(RISK_COLORS.get(preset.risk, QColor(Qt.GlobalColor.gray)))
            self.registry_presets.addItem(item)
        layout.addWidget(self.registry_presets)

        self.registry_tree = make_tree(REGISTRY_COLUMNS, (240, 420, 60, 150, 90, 280, 300),
                                       "Search or scan the ticked presets to fill this list.")
        row = QHBoxLayout()
        self.registry_summary = QLabel("Nothing searched yet.")
        self.registry_summary.setWordWrap(True)
        row.addWidget(self.registry_summary, 1)
        row.addWidget(tree_filter(self.registry_tree))
        layout.addLayout(row)
        layout.addWidget(self.registry_tree)

        row = QHBoxLayout()
        tick_sure = QPushButton("Tick high confidence")
        tick_sure.setToolTip("Tick every row except the orange ones (medium confidence)")
        tick_sure.clicked.connect(lambda: tick_where(self.registry_tree,
                                                     lambda entry: entry.confidence != dead_registry.MEDIUM))
        export_btn = QPushButton("💾 Export")
        export_btn.setToolTip("Save the rows shown as a CSV file")
        export_btn.clicked.connect(lambda: self._export_tree(self.registry_tree, "garbage_registry.csv"))
        backups_btn = QPushButton("📂 Backups")
        backups_btn.setToolTip("Folder of the .reg files saved before each deletion")
        backups_btn.clicked.connect(self._registry_open_backups)
        regedit_btn = QPushButton("🧩 Open in Regedit")
        regedit_btn.setToolTip("Open Regedit on the selected key (close Regedit first if it is already open)")
        regedit_btn.clicked.connect(lambda: self._open_selected_location("registry_tree", prefer_registry=True))
        self.registry_delete_btn = QPushButton("🗑 Delete ticked entries...")
        self.registry_delete_btn.clicked.connect(self._registry_delete)
        for widget in tick_buttons(self.registry_tree) + [tick_sure, regedit_btn, backups_btn, export_btn]:
            row.addWidget(widget)
        row.addStretch()
        row.addWidget(self.registry_delete_btn)
        layout.addLayout(row)

        note = QLabel("ℹ️ To undo, double-click the .reg file of the backups folder. Keys outside SOFTWARE and core "
                      "Windows keys cannot be deleted from here (no checkbox). Entries under HKLM need administrator "
                      "rights. A word search can match unrelated software: read each line before ticking.")
        note.setWordWrap(True)
        note.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(note)
        return page

    def _registry_search(self):
        text = self.registry_pattern.text().strip()
        try:
            garbage.compile_patterns(text)
        except ValueError as e:
            QMessageBox.information(self, "Info", plain(str(e)))
            return
        flags = (self.registry_names_cb.isChecked(), self.registry_values_cb.isChecked(), self.registry_data_cb.isChecked())
        if not any(flags):
            QMessageBox.information(self, "Info", "Tick at least one of: key names, value names, value data.")
            return
        stopped = self._garbage_stopped
        self._run_garbage_scan(
            "garbage_reg_worker",
            lambda: dead_registry.search_registry(text, *flags, stop=stopped, progress=self._update_status),
            self._on_registry_scanned, f"Searching the registry for {text}...")

    def _checked_presets(self) -> List[str]:
        return [self.registry_presets.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.registry_presets.count())
                if self.registry_presets.item(i).checkState() == Qt.CheckState.Checked]

    def _registry_find_dead(self):
        ids = self._checked_presets()
        if not ids:
            QMessageBox.information(self, "Info", "Tick at least one preset in the list.")
            return
        stopped = self._garbage_stopped
        self._run_garbage_scan(
            "garbage_reg_worker", lambda: dead_registry.scan_presets(ids, stop=stopped, progress=self._update_status),
            self._on_registry_scanned, "Looking for useless registry entries...")

    def _on_registry_scanned(self, scan, error):
        self._scan_finished()
        if error:
            self._update_status("Registry search failed.")
            QMessageBox.warning(self, "Error", plain(f"The registry search failed: {error}"))
            return
        tree = self.registry_tree
        tree.setSortingEnabled(False)
        tree.clear()
        locked = 0
        for entry in scan.entries:
            item = SortableItem([entry.display_name, entry.location, entry.kind, entry.category, entry.confidence,
                                 entry.reason, entry.data])
            item.setData(0, Qt.ItemDataRole.UserRole, entry)
            item.setToolTip(1, plain(entry.location + (f"\n[{entry.value or '(default)'}]" if entry.value is not None else "")))
            if entry.confidence == dead_registry.MEDIUM:
                for column in range(len(REGISTRY_COLUMNS)):
                    item.setForeground(column, QColor(204, 112, 0))
            why = dead_registry.protected_reason(entry)
            if why:
                locked += 1
                item.setToolTip(0, plain(f"Protected: {why}"))
                for column in range(len(REGISTRY_COLUMNS)):
                    item.setForeground(column, QColor(Qt.GlobalColor.gray))
                not_checkable(item)
            else:
                checkable(item)
            tree.addTopLevelItem(item)
        tree.setSortingEnabled(True)
        apply_tree_filter(tree)
        more = f" (stopped at the first {dead_registry.SEARCH_LIMIT}: refine the search)" if scan.truncated else ""
        stopped = " (search stopped)" if self._garbage_stopped() else ""
        protected = f", {locked} protected" if locked else ""
        self.registry_summary.setText(f"{count(len(scan.entries), 'entry', 'entries')}{protected}{more}{stopped}.")
        self.registry_found = list(scan.entries)
        self._refresh_overview()
        self._update_status("Registry search done.")

    def _registry_delete(self):
        entries = checked_payloads(self.registry_tree)
        if not entries:
            QMessageBox.information(self, "Info", "Tick the entries to delete first.")
            return
        if self._garbage_running():
            QMessageBox.information(self, "Info", "Wait for the running scan or deletion to finish.")
            return
        if any(e.hive == "HKLM" for e in entries) and not SystemUtils.check_admin_privileges():
            QMessageBox.warning(self, "Administrator Required",
                                "Entries under HKLM can only be deleted as administrator.\n"
                                "Restart the application as administrator, or untick them.")
            return
        keys = sum(1 for e in entries if e.value is None)
        lines = [f"{e.location}" + (f"  [{e.value or '(default)'}]" if e.value is not None else "") for e in entries]
        text = (f"Delete {count(keys, 'key')} and {count(len(entries) - keys, 'value')}?\n"
                f"A .reg backup of each key is saved first in:\n{dead_registry.backup_dir()}\n\n"
                + self._confirm_list(lines))
        if not self._confirm("Delete", text, self._full_list(lines)):
            return
        self._start_call("garbage_delete_worker",
                         lambda: dead_registry.delete_entries(entries, dead_registry.backup_dir(), stop=self.stop_flag.is_set),
                         self._on_registry_deleted, self.registry_delete_btn, "Deleting registry entries...")

    def _on_registry_deleted(self, result, error):
        if error:
            QMessageBox.warning(self, "Error", plain(f"The deletion failed: {error}"))
            return
        remove_rows(self.registry_tree, result.deleted)
        gone = {id(e) for e in result.deleted}
        self.registry_found = [e for e in self.registry_found if id(e) not in gone]
        garbage_stats.record(0, 0, len(result.deleted))
        self._refresh_overview()
        self.registry_summary.setText(f"{len(result.deleted)} deleted, {count(len(result.backups), 'backup file')}. "
                                      f"{count(self.registry_tree.topLevelItemCount(), 'entry', 'entries')} left in the list.")
        self._update_status(f"{count(len(result.deleted), 'registry entry', 'registry entries')} deleted.")
        if result.failed:
            lines = [f"{e.location}" + (f" [{e.value}]" if e.value else "") + f": {why}" for e, why in result.failed]
            QMessageBox.warning(self, "Not everything was deleted",
                                plain(f"{count(len(result.failed), 'entry', 'entries')} could not be deleted:\n\n"
                                      + self._confirm_list(lines)))

    def _registry_open_backups(self):
        folder = dead_registry.backup_dir()
        os.makedirs(folder, exist_ok=True)
        self._open_in_explorer([folder])

    # endregion

    # region Overview (charts)

    def _create_garbage_overview_page(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        row = QHBoxLayout()
        self.overview_summary = QLabel()
        self.overview_summary.setWordWrap(True)
        refresh = QPushButton("🔄 Refresh")
        refresh.setToolTip("Re-read the disks. The garbage shown comes from your last searches.")
        refresh.clicked.connect(self._refresh_overview)
        self.usage_drive = QComboBox()
        self.usage_btn = QPushButton("📊 Measure folders of")
        self.usage_btn.setToolTip("Size of every folder at the root of the drive (a few seconds to a few minutes)")
        self.usage_btn.clicked.connect(self._measure_folders)
        row.addWidget(self.overview_summary, 1)
        row.addWidget(self.usage_btn)
        row.addWidget(self.usage_drive)
        row.addWidget(refresh)
        outer.addLayout(row)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        layout = QVBoxLayout(body)
        self.chart_disks = charts.StackedBarChart("Disks: space used, garbage found, free space")
        self.chart_categories = charts.BarChart("Garbage found on disk, by kind", charts.ORANGE)
        self.chart_biggest = charts.BarChart("Biggest items found", charts.ORANGE)
        self.chart_registry = charts.BarChart("Registry entries found, by kind (entries)", charts.VIOLET)
        self.chart_freed = charts.ColumnChart("Space freed, last 30 days", charts.GREEN)
        self.chart_folders = charts.BarChart("Folders at the root of the drive measured", charts.BLUE)
        for chart in (self.chart_disks, self.chart_categories, self.chart_biggest, self.chart_registry, self.chart_freed,
                      self.chart_folders):
            layout.addWidget(chart)
        layout.addStretch()
        scroll.setWidget(body)
        outer.addWidget(scroll)
        note = QLabel("ℹ️ Charts show what the searches in the other two pages found, and what has been freed since you "
                      "started using them. The registry takes almost no disk space: its entries are counted, not weighed.")
        note.setWordWrap(True)
        note.setStyleSheet("color: gray; font-style: italic;")
        outer.addWidget(note)
        self._refresh_overview()
        return page

    def _refresh_overview(self):
        usage = garbage.drive_usage()
        likely = [i for i in self.garbage_found if garbage.is_likely(i)]
        per_drive = garbage.size_by_drive(likely)
        self.usage_drive.blockSignals(True)
        current = self.usage_drive.currentText()
        self.usage_drive.clear()
        self.usage_drive.addItems([u.root for u in usage])
        if current:
            self.usage_drive.setCurrentText(current)
        self.usage_drive.blockSignals(False)

        rows = []
        for u in usage:
            drive = u.root[:2].upper()
            junk = min(per_drive.get(drive, 0), max(u.used, 0))
            rows.append(charts.StackRow(
                drive, [charts.Segment(u.used - junk, charts.BLUE), charts.Segment(junk, charts.ORANGE),
                        charts.Segment(u.free, charts.GREY)],
                f"{garbage.human_size(u.used)} used / {garbage.human_size(u.total)}"
                + (f", garbage {garbage.human_size(junk)} ({junk * 100 / u.total:.2f} %)" if junk else "")))
        self.chart_disks.set_rows(rows, [("Used", charts.BLUE), ("Garbage found", charts.ORANGE), ("Free", charts.GREY)])

        kinds = garbage.summarize(self.garbage_found)
        self.chart_categories.set_rows([charts.Bar(k, size, f"{garbage.human_size(size)}  ({count})",
                                                   charts.GREY if "low confidence" in k else None) for k, count, size in kinds[:MAX_BARS]])
        biggest = sorted(likely, key=lambda i: -i.size)[:MAX_BARS]
        self.chart_biggest.set_rows([charts.Bar(os.path.basename(i.path) or i.path, i.size, garbage.human_size(i.size)) for i in biggest])

        counts = {}
        for entry in self.registry_found:
            counts[entry.category] = counts.get(entry.category, 0) + 1
        self.chart_registry.set_rows([charts.Bar(k, n, str(n)) for k, n in sorted(counts.items(), key=lambda r: -r[1])[:MAX_BARS]])

        entries = garbage_stats.load()
        total = garbage_stats.totals(entries)
        days = garbage_stats.per_day(entries)
        self.chart_freed.set_values([(d.strftime("%d/%m"), b) for d, b in days],
                                    f"{garbage.human_size(sum(b for _d, b in days))} in 30 days")
        self.chart_folders.set_rows([charts.Bar(os.path.basename(p) or p, s, garbage.human_size(s)) for p, s in
                                     (self.folder_usage.folders[:MAX_BARS] if self.folder_usage else [])])
        if self.folder_usage:
            self.chart_folders.title = (f"Folders of {self.folder_usage.root} ({garbage.human_size(self.folder_usage.total)} "
                                        "measured)")
        found = sum(i.size for i in likely)
        unsure = sum(i.size for i in self.garbage_found if not garbage.is_likely(i))
        self.overview_summary.setText(
            f"Garbage found: {garbage.human_size(found)} in {len(likely)} item(s)"
            + (f" (+ {garbage.human_size(unsure)} of low-confidence folders, not counted)" if unsure else "") + "   |   "
            f"Registry: {count(len(self.registry_found), 'entry', 'entries')}   |   "
            f"Freed so far: {garbage.human_size(total.bytes)} ({total.files} item(s), "
            f"{count(total.registry, 'registry entry', 'registry entries')}).")

    def _measure_folders(self):
        root = self.usage_drive.currentText()
        if not root:
            QMessageBox.information(self, "Info", "No drive to measure.")
            return
        stopped = self._stopper("garbage_usage_worker")  # its own stop: a running search keeps its Stop request
        self._start_call("garbage_usage_worker", lambda: garbage.folder_usage(root, stopped, self._update_status),
                         self._on_folders_measured, self.usage_btn, f"Measuring the folders of {root}...")

    def _on_folders_measured(self, usage, error):
        if error:
            QMessageBox.warning(self, "Error", plain(f"The measure failed: {error}"))
            return
        self.folder_usage = usage
        self._refresh_overview()
        self._update_status("Folders measured." if not usage.truncated else "Measure stopped.")

    # endregion
