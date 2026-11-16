"""System Health extra pages: startup programs (with removal of what the user ticks), DPC/ISR load, inventory and
saved passwords."""

import csv
import hashlib
import logging
import os
import subprocess

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTreeWidget, QTreeWidgetItem,
    QMessageBox, QFileDialog, QDialog, QLineEdit, QGroupBox, QHeaderView, QAbstractItemView
)
from PySide6.QtCore import Qt, QTimer, QMimeData, QByteArray
from PySide6.QtGui import QColor, QPainter

from ddcleaner import startup, startup_cleanup, system_info, saved_keys
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM32, safe_environment, sys_exe
from ddcleaner.system_utils import SystemUtils
from ddcleaner.workers import CallWorker
from ddcleaner.ui.safe_text import plain, csv_cell, count, listed

_copied_hash = None  # SHA-256 of the secret last copied, to clear it later without keeping the secret


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


HIDDEN = "•" * 8
CLIPBOARD_CLEAR_MS = 30_000
SEVERITY_COLORS = {2: QColor(Qt.GlobalColor.red), 1: QColor(204, 112, 0)}


class CheckTree(QTreeWidget):
    """A list that says so when it is empty, and where Space ticks or unticks every selected row."""

    empty_text = "Nothing to show yet."
    filter_text = ""

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Space:
            rows = [i for i in self.selectedItems() if i.flags() & Qt.ItemFlag.ItemIsUserCheckable
                    and i.data(0, Qt.ItemDataRole.CheckStateRole) is not None]
            if len(rows) > 1:
                ticked = all(i.checkState(0) == Qt.CheckState.Checked for i in rows)
                for item in rows:
                    item.setCheckState(0, Qt.CheckState.Unchecked if ticked else Qt.CheckState.Checked)
                return
        super().keyPressEvent(event)

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.topLevelItemCount() == 0 and self.empty_text:
            painter = QPainter(self.viewport())
            painter.setPen(QColor(Qt.GlobalColor.gray))
            painter.drawText(self.viewport().rect(), Qt.AlignmentFlag.AlignCenter, self.empty_text)


def primary(button: QPushButton) -> QPushButton:
    """Mark the button F5 presses on its page."""
    button.setProperty("primary", True)
    return button


def apply_tree_filter(tree: QTreeWidget, text=None):
    """Hide the rows that do not contain the filter text. A hidden row is never ticked, deleted or exported."""
    if text is not None:
        tree.filter_text = text.strip().lower()
    needle = getattr(tree, "filter_text", "")
    for i in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(i)
        item.setHidden(bool(needle) and not any(needle in item.text(c).lower() for c in range(tree.columnCount())))


def tree_filter(tree: QTreeWidget, placeholder: str = "Filter the list...") -> QLineEdit:
    edit = QLineEdit()
    edit.setPlaceholderText(placeholder)
    edit.setClearButtonEnabled(True)
    edit.setMaximumWidth(260)
    edit.setProperty("filter", True)  # Ctrl+F goes here
    edit.textChanged.connect(lambda text: apply_tree_filter(tree, text))
    return edit


def make_tree(headers, widths, empty: str = "") -> QTreeWidget:
    tree = CheckTree()
    if empty:
        tree.empty_text = empty
    tree.setHeaderLabels(headers)
    for column, width in enumerate(widths):
        tree.setColumnWidth(column, width)
    tree.setSortingEnabled(True)
    tree.sortByColumn(0, Qt.SortOrder.AscendingOrder)
    tree.setRootIsDecorated(False)
    tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
    return tree


class SystemInfoTabMixin:
    """Extra pages of the System Health tab. Mixed into MainWindow."""

    def _add_system_info_pages(self, tabs):
        tabs.addTab(self._create_startup_page(), "Startup programs")
        tabs.addTab(self._create_load_page(), "DPC / ISR load")
        tabs.addTab(self._create_inventory_page(), "Inventory")

    def _start_call(self, attr: str, function, on_done, button=None, status: str = "") -> bool:
        """Run function in a CallWorker stored as self.<attr>; refuse a second run."""
        running = getattr(self, attr, None)
        if running is not None and running.isRunning():
            QMessageBox.information(self, "Info", "This operation is already running.")
            return False
        if button is not None:
            button.setEnabled(False)
        self.progress_bar.setVisible(True)
        if status:
            self._update_status(status)

        def finished(result, error):
            self.progress_bar.setVisible(False)
            if button is not None:
                button.setEnabled(True)
            on_done(result, error)

        worker = CallWorker(function, attr)
        worker.done.connect(finished)
        setattr(self, attr, worker)
        worker.start()
        return True

    def _export_tree(self, tree: QTreeWidget, default_name: str):
        """Save the rows a list shows (hidden by a filter: left out) as CSV."""
        rows = [tree.topLevelItem(i) for i in range(tree.topLevelItemCount()) if not tree.topLevelItem(i).isHidden()]
        if not rows:
            QMessageBox.information(self, "Info", "There is nothing to export in this list yet.")
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Export to CSV", default_name, "CSV Files (*.csv)")
        if not filename:
            return
        columns = range(tree.columnCount())
        try:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([tree.headerItem().text(c) for c in columns])
                for item in rows:
                    writer.writerow([csv_cell(item.text(c)) for c in columns])
            self._update_status(f"Exported {count(len(rows), 'row')} to {filename}")
        except OSError as e:
            logging.error(f"Export failed: {e}")
            QMessageBox.critical(self, "Error", plain(f"Export failed: {e}"))

    # region Startup programs

    STARTUP_COLUMNS = ["Name", "Type", "For", "Signed by", "Notes", "Program / command"]

    def _create_startup_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        row = QHBoxLayout()
        self.startup_scan_btn = primary(QPushButton("🔄 List startup programs"))
        self.startup_scan_btn.setToolTip("Run / RunOnce keys, Startup folders and logon/boot scheduled tasks. "
                                         "Listing changes nothing.")
        self.startup_scan_btn.clicked.connect(self._scan_startup)
        self.startup_av_btn = QPushButton("🦠 Scan with ClamAV")
        self.startup_av_btn.setToolTip("Scan the selected programs (all of them when none is selected)")
        self.startup_av_btn.clicked.connect(self._scan_startup_with_clamav)
        open_btn = QPushButton("📂 Open location")
        open_btn.clicked.connect(self._open_startup_location)
        export_btn = QPushButton("💾 Export to CSV")
        export_btn.clicked.connect(self._export_startup)
        hunt_btn = QPushButton("🔎 Persistence hunt")
        hunt_btn.setToolTip("Go to Antivirus > Persistence: services, tasks and hijacked settings too, and entries "
                            "can be removed there")
        hunt_btn.clicked.connect(self._go_to_persistence)
        for button in (self.startup_scan_btn, self.startup_av_btn, open_btn, export_btn):
            row.addWidget(button)
        row.addStretch()
        row.addWidget(hunt_btn)
        layout.addLayout(row)
        self.startup_summary = QLabel("Not listed yet. Listing changes nothing.")
        self.startup_summary.setWordWrap(True)
        layout.addWidget(self.startup_summary)
        self.startup_tree = make_tree(self.STARTUP_COLUMNS, (190, 80, 150, 190, 230, 400),
                                      "List the startup programs to fill this list.")
        layout.addWidget(self.startup_tree)

        from ddcleaner.ui.tab_cleanup import tick_buttons  # here: tab_cleanup imports this module
        row = QHBoxLayout()
        backups_btn = QPushButton("📂 Backups")
        backups_btn.setToolTip("Folder where what was removed is saved (.reg for registry values, .xml for tasks, "
                               "and the files moved out of a Startup folder)")
        backups_btn.clicked.connect(self._open_startup_backups)
        self.startup_remove_btn = QPushButton("🗑 Remove ticked entries...")
        self.startup_remove_btn.setToolTip("Stop the ticked programs from starting with Windows. The program itself "
                                           "is not uninstalled, and each entry is saved first so it can be put back.")
        self.startup_remove_btn.clicked.connect(self._remove_startup_entries)
        for widget in tick_buttons(self.startup_tree) + [backups_btn]:
            row.addWidget(widget)
        row.addStretch()
        row.addWidget(self.startup_remove_btn)
        layout.addLayout(row)

        info = QLabel("ℹ️ Red: runs for everyone from a folder a standard user can write to, or the file's real "
                      "content is an executable/script hiding under another extension. Orange: missing, not signed, "
                      "or high entropy (possibly packed). Removing an entry only stops the automatic start: the "
                      "program stays installed. To switch one off without removing it: Task Manager > Startup.")
        info.setWordWrap(True)
        info.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(info)
        self.startup_entries = []
        return page

    def _go_to_persistence(self):
        self.tab_widget.setCurrentWidget(self.clam_tab_page)
        self.clam_pages.setCurrentWidget(self.persistence_page)

    def _scan_startup(self):
        stopped = self._stopper("startup_worker")
        self._start_call("startup_worker", lambda: startup.collect_startup(stopped),
                         self._on_startup_scanned, self.startup_scan_btn, "Listing startup programs...")

    def _on_startup_scanned(self, entries, error):
        from ddcleaner.ui.tab_cleanup import checkable, not_checkable  # here: tab_cleanup imports this module
        if error:
            self._update_status("Startup listing failed.")
            QMessageBox.warning(self, "Error", plain(f"The startup programs could not be listed: {error}"))
            return
        self.startup_entries = entries
        self.startup_tree.setSortingEnabled(False)
        self.startup_tree.clear()
        for entry in entries:
            item = QTreeWidgetItem([entry.name, entry.kind, entry.scope, entry.signer, "; ".join(entry.flags),
                                    entry.command])
            item.setData(0, Qt.ItemDataRole.UserRole, entry)
            item.setToolTip(5, plain(f"{entry.location}\n{entry.path or '(program not found)'}"))
            if startup_cleanup.removable(entry):
                checkable(item)
                item.setToolTip(0, plain(startup_cleanup.describe(entry)))
            else:
                not_checkable(item)
            if entry.severity:
                for column in range(len(self.STARTUP_COLUMNS)):
                    item.setForeground(column, SEVERITY_COLORS[entry.severity])
            self.startup_tree.addTopLevelItem(item)
        self.startup_tree.setSortingEnabled(True)
        replaceable = sum(1 for e in entries if e.severity == 2)
        flagged = sum(1 for e in entries if e.severity == 1)
        self.startup_summary.setText(f"{len(entries)} startup program(s): {replaceable} replaceable by a standard user, "
                                     f"{flagged} to look at.")
        self.startup_summary.setStyleSheet("color: red; font-weight: bold;" if replaceable else "")
        self._update_status("Startup programs listed.")

    def _remove_startup_entries(self):
        from ddcleaner.ui.tab_cleanup import checked_payloads
        chosen = [e for e in checked_payloads(self.startup_tree) if startup_cleanup.removable(e)]
        if not chosen:
            QMessageBox.information(self, "Info", "Tick the startup entries to remove first.")
            return
        if any(startup_cleanup.needs_admin(e) for e in chosen) and not SystemUtils.check_admin_privileges():
            QMessageBox.warning(self, "Administrator Required",
                                "Removing an entry that starts for all users, or a scheduled task, needs administrator "
                                "rights.\nRestart the application as administrator, or untick those entries.")
            return
        lines = [f"{e.name}: {startup_cleanup.describe(e)}" for e in chosen]
        text = (f"Remove {count(len(chosen), 'startup entry', 'startup entries')}?\n\n" + listed(lines)
                + "\n\nThe programs stay installed: they only stop starting by themselves. "
                  f"To undo, use the files saved in:\n{startup_cleanup.backup_dir()}")
        if not self._confirm("Remove startup entries", text, "\n".join(lines) if len(lines) > 10 else ""):
            return
        stopped = self.stop_flag.is_set  # a removal is not interrupted by Stop / Esc, only by closing the program
        self._start_call("startup_remove_worker",
                         lambda: startup_cleanup.remove_entries(chosen, startup_cleanup.backup_dir(), stop=stopped),
                         self._on_startup_removed, self.startup_remove_btn, "Removing the ticked startup entries...")

    def _on_startup_removed(self, result, error):
        from ddcleaner.ui.tab_cleanup import remove_rows
        if error:
            QMessageBox.warning(self, "Error", plain(f"The removal failed: {error}"))
            return
        remove_rows(self.startup_tree, result.removed)
        gone = {id(e) for e in result.removed}
        self.startup_entries = [e for e in self.startup_entries if id(e) not in gone]
        self.startup_summary.setText(f"{count(len(result.removed), 'entry', 'entries')} removed, "
                                     f"{count(len(result.backups), 'backup file')}. "
                                     f"{count(len(self.startup_entries), 'startup program')} left in the list.")
        self.startup_summary.setStyleSheet("")
        self._update_status(f"{count(len(result.removed), 'startup entry', 'startup entries')} removed.")
        if result.failed:
            QMessageBox.warning(self, "Not everything was removed", plain(
                f"{count(len(result.failed), 'entry', 'entries')} could not be removed:\n\n"
                + listed(f"{e.name}: {why}" for e, why in result.failed)))

    def _open_startup_backups(self):
        folder = startup_cleanup.backup_dir()
        os.makedirs(folder, exist_ok=True)
        subprocess.Popen([sys_exe("explorer.exe"), folder], cwd=SYSTEM32, env=safe_environment(),
                         creationflags=SUBPROCESS_FLAGS)

    def _selected_startup_entries(self) -> list:
        items = self.startup_tree.selectedItems()
        return [i.data(0, Qt.ItemDataRole.UserRole) for i in items]

    def _scan_startup_with_clamav(self):
        if self._clam_busy():  # check first: do not replace the user's targets while a scan is running
            return
        entries = self._selected_startup_entries() or self.startup_entries
        paths = sorted({e.path for e in entries if e.path and os.path.isfile(e.path)}, key=str.lower)
        if not paths:
            QMessageBox.information(self, "Info", "List the startup programs first: there is no program file to scan.")
            return
        self.tab_widget.setCurrentWidget(self.clam_tab_page)  # the user's own "Items to scan" list is left alone
        self.clam_pages.setCurrentIndex(0)
        self._start_clam_scan(paths)

    def _open_startup_location(self):
        entries = self._selected_startup_entries()
        if not entries or not entries[0].path or not os.path.isfile(entries[0].path):
            QMessageBox.information(self, "Info", "Select a program whose file exists.")
            return
        subprocess.Popen([sys_exe("explorer.exe"), "/select,", entries[0].path], cwd=SYSTEM32,
                         env=safe_environment(), creationflags=SUBPROCESS_FLAGS)

    def _export_startup(self):
        if not self.startup_entries:
            QMessageBox.information(self, "Info", "Nothing to export. List the startup programs first.")
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Export startup programs", "startup_programs.csv",
                                                  "CSV Files (*.csv)")
        if not filename:
            return
        try:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Name", "Type", "For", "Signed by", "Notes", "Command", "Program", "Registered in"])
                for e in self.startup_entries:
                    writer.writerow([csv_cell(v) for v in (e.name, e.kind, e.scope, e.signer, "; ".join(e.flags),
                                                           e.command, e.path, e.location)])
            self._update_status(f"Exported {count(len(self.startup_entries), 'startup program')} to {filename}")
        except OSError as e:
            logging.error(f"Startup export failed: {e}")
            QMessageBox.critical(self, "Error", plain(f"Export failed: {e}"))

    # endregion

    # region DPC / ISR load

    def _create_load_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        info = QLabel("Share of processor time spent in deferred procedure calls (DPC) and interrupts (ISR), the "
                      "usual cause of crackling in real-time audio. Five samples, one per second. Close heavy "
                      "programs for a clean reading, or run it while the problem happens. Nothing is changed.")
        info.setWordWrap(True)
        layout.addWidget(info)
        row = QHBoxLayout()
        self.load_btn = primary(QPushButton("⏱ Measure (5 s)"))
        self.load_btn.clicked.connect(self._measure_load)
        row.addWidget(self.load_btn)
        row.addStretch()
        layout.addLayout(row)
        self.load_result = QLabel("Not measured yet.")
        self.load_result.setWordWrap(True)
        self.load_result.setStyleSheet("font-size: 14px; padding: 8px;")
        layout.addWidget(self.load_result)
        layout.addStretch()
        return page

    def _measure_load(self):
        self.load_result.setText("Measuring...")
        self._start_call("load_worker", lambda: system_info.measure_dpc_isr(5), self._on_load_measured,
                         self.load_btn, "Measuring DPC / ISR load...")

    def _on_load_measured(self, result, error):
        if error:
            self.load_result.setText(plain(f"The measurement failed: {error}"))
            return
        average = lambda values: sum(values) / len(values) if values else 0.0  # noqa: E731
        self.load_result.setText(
            f"DPC: max {max(result.dpc, default=0):.2f} %, average {average(result.dpc):.2f} %\n"
            f"ISR: max {max(result.isr, default=0):.2f} %, average {average(result.isr):.2f} %\n\n{result.verdict}")
        self.load_result.setStyleSheet(
            "font-size: 14px; padding: 8px; color: " + ("red" if result.worst >= 3 else "#cc7000" if result.worst >= 1
                                                        else "darkgreen") + ";")
        self._update_status("DPC / ISR load measured.")

    # endregion

    # region Inventory

    def _create_inventory_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        row = QHBoxLayout()
        self.inventory_btn = primary(QPushButton("📋 Read inventory"))
        self.inventory_btn.clicked.connect(self._read_inventory)
        export_btn = QPushButton("💾 Export programs to CSV")
        export_btn.setToolTip("Every installed program, whatever the filter shows")
        export_btn.clicked.connect(self._export_programs)
        secrets_btn = QPushButton("🔑 Saved Wi-Fi passwords and Windows key...")
        secrets_btn.setToolTip("Shown on screen only, after a confirmation. Nothing is saved or logged.")
        secrets_btn.clicked.connect(self._show_saved_secrets)
        program_open = QPushButton("📂 Open location")
        program_open.setToolTip("Open the folder of the selected program")
        program_open.clicked.connect(lambda: self._open_selected_location("program_tree"))
        for button in (self.inventory_btn, export_btn, program_open):
            row.addWidget(button)
        row.addStretch()
        row.addWidget(secrets_btn)
        layout.addLayout(row)

        box = QGroupBox("This PC")
        box_layout = QVBoxLayout(box)
        self.inventory_system = QLabel("Not read yet.")
        self.inventory_system.setTextFormat(Qt.TextFormat.PlainText)
        self.inventory_system.setMinimumHeight(self.fontMetrics().lineSpacing() * 4)  # Windows line + up to 3 GPUs
        box_layout.addWidget(self.inventory_system)
        layout.addWidget(box)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Installed programs:"))
        self.program_filter = QLineEdit()
        self.program_filter.setPlaceholderText("Filter by name or publisher")
        self.program_filter.setClearButtonEnabled(True)
        self.program_filter.setProperty("filter", True)
        self.program_filter.textChanged.connect(self._filter_programs)
        filter_row.addWidget(self.program_filter)
        layout.addLayout(filter_row)
        self.program_tree = make_tree(["Name", "Version", "Publisher", "Installed for"], (360, 130, 280, 140),
                                      "Read the inventory to list the installed programs.")
        layout.addWidget(self.program_tree)
        self.programs = []
        return page

    def _read_inventory(self):
        def collect():
            return {"programs": system_info.installed_programs(), "gpus": system_info.graphics_cards(),
                    "activation": system_info.windows_activation()}
        self._start_call("inventory_worker", collect, self._on_inventory_read, self.inventory_btn, "Reading inventory...")

    def _on_inventory_read(self, data, error):
        if error:
            QMessageBox.warning(self, "Error", plain(f"The inventory could not be read: {error}"))
            return
        activation, gpus = data["activation"], data["gpus"]
        lines = []
        if activation:
            key_end = f", key ends with {activation['partial_key']}" if activation["partial_key"] else ""
            lines.append(f"{activation['edition']} (build {activation['build']}): {activation['status']}, "
                         f"{activation['channel'] or 'unknown channel'}{key_end}")
        for gpu in gpus:
            lines.append(f"GPU: {gpu.name}, {gpu.vram_gb} GB, driver {gpu.driver_version} ({gpu.driver_date})"
                         + (f", {gpu.resolution}" if gpu.resolution else ""))
        self.inventory_system.setText("\n".join(lines) or "Nothing could be read.")
        self.programs = data["programs"]
        self._filter_programs()
        self._update_status(f"Inventory read: {len(self.programs)} programs.")

    def _filter_programs(self):
        needle = self.program_filter.text().strip().lower()
        self.program_tree.setSortingEnabled(False)
        self.program_tree.clear()
        for p in self.programs:
            if needle and needle not in p.name.lower() and needle not in p.publisher.lower():
                continue
            item = QTreeWidgetItem([p.name, p.version, p.publisher, p.scope])
            item.setData(0, Qt.ItemDataRole.UserRole, p)
            if p.location:
                item.setToolTip(0, p.location)
            self.program_tree.addTopLevelItem(item)
        self.program_tree.setSortingEnabled(True)

    def _export_programs(self):
        if not self.programs:
            QMessageBox.information(self, "Info", "Nothing to export. Read the inventory first.")
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Export installed programs", "installed_programs.csv",
                                                  "CSV Files (*.csv)")
        if not filename:
            return
        try:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Name", "Version", "Publisher", "Installed for"])
                for p in self.programs:
                    writer.writerow([csv_cell(v) for v in (p.name, p.version, p.publisher, p.scope)])
            self._update_status(f"Exported all {count(len(self.programs), 'program')} to {filename}")
        except OSError as e:
            QMessageBox.critical(self, "Error", plain(f"Export failed: {e}"))

    # endregion

    # region Saved passwords

    def _show_saved_secrets(self):
        if not SystemUtils.check_admin_privileges():
            QMessageBox.warning(self, "Administrator Required",
                                "Windows only gives saved Wi-Fi passwords to an administrator.\n"
                                "Restart the application as administrator.")
            return
        if not self._confirm(
                "Show saved passwords (personal use only)",
                "⚠️ PERSONAL USE ONLY\n"
                "Use this only on your own PC, to recover your own passwords and keys. Reading the passwords of "
                "another person, or of a PC that is not yours, without their permission is forbidden and may be "
                "a crime.\n\n"
                "This reads the secrets saved on this PC and shows them on screen:\n"
                "  • Wi-Fi passwords and the firmware Windows key\n"
                "  • Windows Credential Manager (saved web, app and Remote Desktop logins)\n"
                "  • software license keys (Office, Adobe, Autodesk...)\n"
                "  • website passwords saved in Chrome, Edge, Brave and Firefox\n\n"
                "Nothing is written to a file or to the log, the clipboard is cleared 30 seconds after you copy a "
                "secret, and this window empties itself when closed. Make sure nobody can see your screen.\n\n"
                "I confirm these are my own passwords. Continue?"):
            return
        self._start_call("secrets_worker", saved_keys.collect_secrets, self._on_secrets_read, None,
                         "Reading saved passwords...")

    def _on_secrets_read(self, records, error):
        if error:
            QMessageBox.warning(self, "Error", plain(f"The saved passwords could not be read: {error}"))
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Saved passwords and keys")
        dialog.resize(900, 520)
        layout = QVBoxLayout(dialog)
        readable = sum(1 for r in records if r.value)
        layout.addWidget(QLabel(f"{len(records)} item(s), {readable} with a readable secret. Shown on screen only; "
                                "close this window when you are done."))
        tree = make_tree(["Type", "Name", "Detail", "Secret"], (150, 300, 220, 200))
        tree.setSortingEnabled(False)  # keep the source order (Wi-Fi, key, licenses, credentials, browsers)
        for record in records:
            if record.value:
                shown = HIDDEN
            elif record.note:
                shown = f"({record.note})"
            else:
                shown = "(none)"
            item = QTreeWidgetItem([record.kind, record.name, record.info, shown])  # tree items are plain text
            item.setData(3, Qt.ItemDataRole.UserRole, record.value)
            tree.addTopLevelItem(item)
        if not records:
            layout.addWidget(QLabel("No saved secret found on this PC."))
        layout.addWidget(tree)

        state = {"shown": False}

        def toggle():
            state["shown"] = not state["shown"]
            for i in range(tree.topLevelItemCount()):
                item = tree.topLevelItem(i)
                secret = item.data(3, Qt.ItemDataRole.UserRole)
                if secret:
                    item.setText(3, secret if state["shown"] else HIDDEN)
            show_btn.setText("🙈 Hide" if state["shown"] else "👁 Show")

        def copy():
            items = tree.selectedItems()
            secret = items[0].data(3, Qt.ItemDataRole.UserRole) if items else ""
            if not secret:
                QMessageBox.information(dialog, "Info", "Select a row that has a password.")
                return
            self._copy_secret(secret)

        row = QHBoxLayout()
        show_btn = QPushButton("👁 Show")
        show_btn.clicked.connect(toggle)
        copy_btn = QPushButton("📋 Copy selected (clears in 30 s)")
        copy_btn.clicked.connect(copy)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        row.addWidget(show_btn)
        row.addWidget(copy_btn)
        row.addStretch()
        row.addWidget(close_btn)
        layout.addLayout(row)
        self._set_dialog_default(dialog, close_btn)  # Enter must never be "Show"

        dialog.exec()
        tree.clear()  # drop the secrets from memory-backed widgets as soon as the window is closed
        dialog.deleteLater()

    @staticmethod
    def _copy_secret(secret: str):
        """Copy a secret without letting Windows keep it: the formats below keep it out of the clipboard history
        (Win+V), the cloud clipboard and clipboard monitors. Only a hash is remembered, never the secret."""
        global _copied_hash
        mime = QMimeData()
        mime.setText(secret)
        mime.setData("ExcludeClipboardContentFromMonitorProcessing", QByteArray(b"\x01"))
        mime.setData("CanIncludeInClipboardHistory", QByteArray(b"\x00\x00\x00\x00"))
        mime.setData("CanUploadToCloudClipboard", QByteArray(b"\x00\x00\x00\x00"))
        QApplication.clipboard().setMimeData(mime)
        _copied_hash = _digest(secret)
        QTimer.singleShot(CLIPBOARD_CLEAR_MS, SystemInfoTabMixin.clear_secret_clipboard)

    @staticmethod
    def clear_secret_clipboard():
        """Empty the clipboard if it still holds the secret we copied (also called when the window closes)."""
        global _copied_hash
        if _copied_hash is not None:
            clipboard = QApplication.clipboard()
            if _digest(clipboard.text()) == _copied_hash:
                clipboard.clear()
            _copied_hash = None

    # endregion
