"""Antivirus extra pages: running processes, persistence hunt (with removal of what the user ticks) and the automatic
protection (watched folders, scheduled quick scan, YARA rules). The scans themselves are ClamAV's (tab_antivirus.py)."""

import os
import subprocess
import time
from typing import List

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QCheckBox, QListWidget, QSpinBox, QGroupBox,
    QTreeWidgetItem, QMessageBox, QFileDialog
)
from PySide6.QtCore import Qt, QTimer, QStandardPaths
from PySide6.QtGui import QColor

from ddcleaner import clamav, hunt_cleanup, threat_hunt, watcher
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM32, safe_environment, sys_exe
from ddcleaner.system_utils import SystemUtils
from ddcleaner.ui.safe_text import plain, count, listed
from ddcleaner.ui.tab_cleanup import SortableItem, SORT_ROLE, checkable, not_checkable, checked_payloads, tick_buttons
from ddcleaner.ui.tab_antivirus import scrollable
from ddcleaner.ui.tab_system_info import make_tree, primary, tree_filter, apply_tree_filter
from ddcleaner.workers import CallWorker

SEVERITY_COLORS = {threat_hunt.SUSPICIOUS: QColor(Qt.GlobalColor.red), threat_hunt.LOOK: QColor(204, 112, 0)}
PROCESS_COLUMNS = ["Name", "PID", "Signed by", "Internet", "Notes", "Path"]
HUNT_COLUMNS = ["Type", "Name", "Notes", "Detail", "Where"]
PROTECTION_TICK_MS = 30_000
BATCH_SIZE = 200


def watch_step(folder_watcher) -> List[str]:
    """One background look at the watched folders: remember what is there the first time, report new files after."""
    if not getattr(folder_watcher, "primed", True):
        folder_watcher.prime()
        folder_watcher.primed = True
        return []
    return folder_watcher.poll()


class HuntTabMixin:
    """Extra pages of the Antivirus tab. Mixed into MainWindow."""

    def _add_hunt_pages(self, pages):
        self.hunt_processes, self.hunt_findings = [], []
        pages.addTab(self._create_process_page(), "Processes")
        pages.addTab(self._create_persistence_page(), "Persistence")
        pages.addTab(self._create_protection_page(), "Protection")
        self._start_protection()

    def _scan_program_files(self, paths: List[str]):
        if self._clam_busy():
            return
        paths = [p for p in paths if os.path.isfile(p)]
        if not paths:
            QMessageBox.information(self, "Info", "There is no program file to scan.")
            return
        self.tab_widget.setCurrentWidget(self.clam_tab_page)  # the user's own "Items to scan" list is left alone
        self.clam_pages.setCurrentIndex(0)
        self._start_clam_scan(paths)

    @staticmethod
    def _open_file_location(path: str):
        subprocess.Popen([sys_exe("explorer.exe"), "/select,", path], cwd=SYSTEM32, env=safe_environment(),
                         creationflags=SUBPROCESS_FLAGS)

    # region Processes

    def _create_process_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        row = QHBoxLayout()
        self.process_btn = primary(QPushButton("🔄 List running processes"))
        self.process_btn.setToolTip("Signature, folder, packing and Internet connections of every program running (read-only)")
        self.process_btn.clicked.connect(self._scan_processes)
        scan_btn = QPushButton("🦠 Scan with ClamAV")
        scan_btn.setToolTip("Scan the selected programs (every program with a flag when none is selected)")
        scan_btn.clicked.connect(self._scan_selected_processes)
        open_btn = QPushButton("📂 Open location")
        open_btn.clicked.connect(self._open_process_location)
        vt_btn = QPushButton("🛰 VirusTotal")
        vt_btn.setToolTip("Look the selected programs up on VirusTotal (only their hash is sent)")
        vt_btn.clicked.connect(lambda: self._virustotal_check([p.path for p in self._selected_processes()]))
        self.process_flagged_cb = QCheckBox("Only flagged")
        self.process_flagged_cb.setChecked(True)
        self.process_flagged_cb.toggled.connect(self._fill_processes)
        export_btn = QPushButton("💾 Export to CSV")
        export_btn.clicked.connect(lambda: self._export_tree(self.process_tree, "processes.csv"))
        self.process_tree = make_tree(PROCESS_COLUMNS, (190, 70, 190, 70, 380, 420),
                                      "List the running processes to fill this list.")
        for widget in (self.process_btn, scan_btn, vt_btn, open_btn, export_btn, self.process_flagged_cb):
            row.addWidget(widget)
        row.addStretch()
        row.addWidget(tree_filter(self.process_tree))
        layout.addLayout(row)
        self.process_summary = QLabel("Not listed yet. Nothing is changed by this page.")
        self.process_summary.setWordWrap(True)
        layout.addWidget(self.process_summary)
        layout.addWidget(self.process_tree)
        info = QLabel("ℹ️ Red: a Windows name outside the Windows folder, a program that runs from Temp or Downloads, a "
                      "file deleted from disk, or an unsigned program talking to the Internet. Orange: not signed. "
                      "A flag is a reason to look, not a verdict: scan the file to know.")
        info.setWordWrap(True)
        info.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(info)
        return page

    def _scan_processes(self):
        stopped = self._stopper("hunt_process_worker")
        self._start_call("hunt_process_worker", lambda: threat_hunt.scan_processes(stopped, self._update_status),
                         self._on_processes_scanned, self.process_btn, "Checking running processes...")

    def _on_processes_scanned(self, result, error):
        if error:
            QMessageBox.warning(self, "Error", plain(f"The processes could not be checked: {error}"))
            return
        self.hunt_processes = result
        self._fill_processes()
        self._update_status("Processes checked.")

    def _fill_processes(self):
        tree = self.process_tree
        only_flagged = self.process_flagged_cb.isChecked()
        tree.setSortingEnabled(False)
        tree.clear()
        shown = 0
        for p in self.hunt_processes:
            if only_flagged and not p.severity:
                continue
            shown += 1
            item = SortableItem([p.name, str(p.pid), p.signer, str(p.connections) if p.connections else "",
                                 "; ".join(p.flags), p.path])
            item.setData(0, Qt.ItemDataRole.UserRole, p)
            item.setData(1, SORT_ROLE, p.pid)
            item.setData(3, SORT_ROLE, p.connections)
            item.setToolTip(5, plain(p.path))
            if p.severity:
                for column in range(len(PROCESS_COLUMNS)):
                    item.setForeground(column, SEVERITY_COLORS[p.severity])
            tree.addTopLevelItem(item)
        tree.setSortingEnabled(True)
        apply_tree_filter(tree)
        red = sum(1 for p in self.hunt_processes if p.severity == threat_hunt.SUSPICIOUS)
        orange = sum(1 for p in self.hunt_processes if p.severity == threat_hunt.LOOK)
        self.process_summary.setText(f"{len(self.hunt_processes)} process(es): {red} suspicious, {orange} to look at"
                                     f" ({shown} shown).")
        self.process_summary.setStyleSheet("color: red; font-weight: bold;" if red else "")

    def _selected_processes(self) -> list:
        return [i.data(0, Qt.ItemDataRole.UserRole) for i in self.process_tree.selectedItems()]

    def _scan_selected_processes(self):
        chosen = self._selected_processes() or [p for p in self.hunt_processes if p.severity]
        if not self.hunt_processes:
            QMessageBox.information(self, "Info", "List the running processes first.")
            return
        self._scan_program_files(sorted({p.path for p in chosen if p.path}, key=str.lower))

    def _open_process_location(self):
        chosen = self._selected_processes()
        if not chosen or not chosen[0].path or not os.path.isfile(chosen[0].path):
            QMessageBox.information(self, "Info", "Select a program whose file exists.")
            return
        self._open_file_location(chosen[0].path)

    # endregion

    # region Persistence

    def _create_persistence_page(self) -> QWidget:
        page = QWidget()
        self.persistence_page = page
        layout = QVBoxLayout(page)
        row = QHBoxLayout()
        self.hunt_btn = primary(QPushButton("🔎 Hunt for persistence"))
        self.hunt_btn.setToolTip("Services, scheduled tasks, hijacked Windows settings, WMI subscriptions, hosts file, "
                                 "proxy and browser extensions. The hunt itself changes nothing.")
        self.hunt_btn.clicked.connect(self._hunt_persistence)
        scan_btn = QPushButton("🦠 Scan with ClamAV")
        scan_btn.setToolTip("Scan the selected programs, or every program named by the findings and the processes")
        scan_btn.clicked.connect(self._scan_hunt_programs)
        open_btn = QPushButton("📂 Open location")
        open_btn.clicked.connect(self._open_hunt_location)
        vt_btn = QPushButton("🛰 VirusTotal")
        vt_btn.setToolTip("Look the selected programs up on VirusTotal (only their hash is sent)")
        vt_btn.clicked.connect(lambda: self._virustotal_check([f.path for f in self._selected_findings()]))
        export_btn = QPushButton("💾 Export to CSV")
        export_btn.clicked.connect(lambda: self._export_tree(self.hunt_tree, "persistence.csv"))
        self.hunt_flagged_cb = QCheckBox("Only flagged")
        self.hunt_flagged_cb.setChecked(True)
        self.hunt_flagged_cb.toggled.connect(self._fill_hunt)
        self.hunt_tree = make_tree(HUNT_COLUMNS, (130, 220, 340, 380, 360), "Run the hunt to fill this list.")
        for widget in (self.hunt_btn, scan_btn, vt_btn, open_btn, export_btn, self.hunt_flagged_cb):
            row.addWidget(widget)
        row.addStretch()
        row.addWidget(tree_filter(self.hunt_tree))
        layout.addLayout(row)
        self.hunt_summary = QLabel("Not run yet. The hunt changes nothing.")
        self.hunt_summary.setWordWrap(True)
        layout.addWidget(self.hunt_summary)
        layout.addWidget(self.hunt_tree)

        row = QHBoxLayout()
        backups_btn = QPushButton("📂 Backups")
        backups_btn.setToolTip("Folder where what was removed is saved (.xml for tasks, .reg for the rest)")
        backups_btn.clicked.connect(self._open_hunt_backups)
        self.hunt_remove_btn = QPushButton("🗑 Remove ticked entries...")
        self.hunt_remove_btn.setToolTip("Delete the ticked scheduled tasks, services and startup values. Each one is "
                                        "saved first so it can be put back.")
        self.hunt_remove_btn.clicked.connect(self._remove_hunt_findings)
        for widget in tick_buttons(self.hunt_tree) + [backups_btn]:
            row.addWidget(widget)
        row.addStretch()
        row.addWidget(self.hunt_remove_btn)
        layout.addLayout(row)

        info = QLabel("ℹ️ These are the places malware uses to come back after a restart. Most findings are harmless "
                      "(a privacy tweak, an unsigned tool you installed): read the notes, then scan the program. "
                      "Only rows with a checkbox (scheduled tasks, services, startup values) can be removed here, and "
                      "only the ones you tick.")
        info.setWordWrap(True)
        info.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(info)
        return page

    def _hunt_persistence(self):
        stopped = self._stopper("hunt_persistence_worker")
        self._start_call("hunt_persistence_worker",
                         lambda: threat_hunt.collect_persistence(stop=stopped, progress=self._update_status),
                         self._on_hunt_done, self.hunt_btn, "Hunting for persistence...")

    def _on_hunt_done(self, result, error):
        if error:
            QMessageBox.warning(self, "Error", plain(f"The hunt failed: {error}"))
            return
        self.hunt_findings = result
        self._fill_hunt(preselect=True)
        self._update_status("Persistence hunt done.")

    def _fill_hunt(self, _checked=None, preselect: bool = False):
        """preselect (after a hunt): tick the entries whose program is gone. Otherwise the user's ticks are kept."""
        tree = self.hunt_tree
        only_flagged = self.hunt_flagged_cb.isChecked()
        ticked = {id(f) for f in checked_payloads(tree)}
        tree.setSortingEnabled(False)
        tree.clear()
        for f in self.hunt_findings:
            if only_flagged and not f.severity:
                continue
            item = SortableItem([f.category, f.title, "; ".join(f.flags), f.detail, f.location])
            item.setData(0, Qt.ItemDataRole.UserRole, f)
            item.setToolTip(3, plain(f.detail))
            item.setToolTip(4, plain(f.location))
            if f.severity:
                for column in range(len(HUNT_COLUMNS)):
                    item.setForeground(column, SEVERITY_COLORS[f.severity])
            if hunt_cleanup.removable(f):
                item.setToolTip(1, plain(hunt_cleanup.describe(f)))
                # proposed when what it starts is gone: removing it changes nothing
                checkable(item, id(f) in ticked or (preselect and f.dead))
            else:
                not_checkable(item)
            tree.addTopLevelItem(item)
        tree.setSortingEnabled(True)
        apply_tree_filter(tree)
        red = sum(1 for f in self.hunt_findings if f.severity == threat_hunt.SUSPICIOUS)
        orange = sum(1 for f in self.hunt_findings if f.severity == threat_hunt.LOOK)
        self.hunt_summary.setText(f"{red} suspicious, {orange} to look at, "
                                  f"{len(self.hunt_findings) - red - orange} for information.")
        dead = sum(1 for f in self.hunt_findings if f.dead and hunt_cleanup.removable(f))
        if dead:
            self.hunt_summary.setText(self.hunt_summary.text() + f" {count(dead, 'entry', 'entries')} "
                                      f"start{'s' if dead == 1 else ''} a program that no longer exists: ticked, "
                                      "ready to be removed.")
        self.hunt_summary.setStyleSheet("color: red; font-weight: bold;" if red else "")

    def _selected_findings(self) -> list:
        return [i.data(0, Qt.ItemDataRole.UserRole) for i in self.hunt_tree.selectedItems()]

    def _scan_hunt_programs(self):
        if not self.hunt_findings and not self.hunt_processes:
            QMessageBox.information(self, "Info", "Run the persistence hunt or list the processes first.")
            return
        chosen = self._selected_findings()
        paths = sorted({f.path for f in chosen if f.path}, key=str.lower) if chosen else \
            threat_hunt.program_paths(self.hunt_findings, self.hunt_processes)
        self._scan_program_files(paths)

    def _remove_hunt_findings(self):
        todo = [f for f in checked_payloads(self.hunt_tree) if hunt_cleanup.removable(f)]
        if not todo:
            QMessageBox.information(self, "Info", "Tick the entries to remove first. Only rows with a checkbox "
                                                  "(scheduled tasks, services and startup values) can be removed here.")
            return
        if not SystemUtils.check_admin_privileges():
            QMessageBox.warning(self, "Administrator Required",
                                "Removing a task, a service or a system registry value needs administrator rights.\n"
                                "Restart the application as administrator.")
            return
        lines = [f"{f.title}: {hunt_cleanup.describe(f)}" for f in todo]
        text = (f"Remove {count(len(todo), 'entry', 'entries')}?\n\n" + self._confirm_lines(lines)
                + "\n\nA finding is a reason to look, not a verdict: make sure you recognise what you remove. "
                  f"To undo, use the files saved in:\n{hunt_cleanup.backup_dir()}")
        if not self._confirm("Remove", text, "\n".join(lines) if len(lines) > 10 else ""):
            return
        stopped = self.stop_flag.is_set  # a removal is not interrupted by Stop / Esc, only by closing the program
        self._start_call("hunt_remove_worker",
                         lambda: hunt_cleanup.remove_findings(todo, hunt_cleanup.backup_dir(), stop=stopped),
                         self._on_hunt_removed, self.hunt_remove_btn, "Removing the ticked entries...")

    @staticmethod
    def _confirm_lines(lines: List[str], limit: int = 10) -> str:
        return listed(lines, limit)

    def _on_hunt_removed(self, result, error):
        if error:
            QMessageBox.warning(self, "Error", plain(f"The removal failed: {error}"))
            return
        gone = {id(f) for f in result.removed}
        self.hunt_findings = [f for f in self.hunt_findings if id(f) not in gone]
        self._fill_hunt()
        self._update_status(f"{count(len(result.removed), 'entry', 'entries')} removed.")
        notes = []
        if result.failed:
            notes.append(f"{len(result.failed)} could not be removed:\n" + self._confirm_lines(
                [f"{f.title}: {why}" for f, why in result.failed]))
        if result.reboot:
            notes.append("A running service disappears at the next restart.")
        if notes:
            QMessageBox.warning(self, "Removal", plain("\n\n".join(notes)))

    def _open_hunt_backups(self):
        folder = hunt_cleanup.backup_dir()
        os.makedirs(folder, exist_ok=True)
        subprocess.Popen([sys_exe("explorer.exe"), folder], cwd=SYSTEM32, env=safe_environment(),
                         creationflags=SUBPROCESS_FLAGS)

    def _open_hunt_location(self):
        chosen = self._selected_findings()
        if not chosen or not chosen[0].path or not os.path.isfile(chosen[0].path):
            QMessageBox.information(self, "Info", "Select a finding that has a program file.")
            return
        self._open_file_location(chosen[0].path)

    # endregion

    # region Protection

    def _create_protection_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        watch_box = QGroupBox("Scan new files automatically")
        watch_layout = QVBoxLayout(watch_box)
        self.watch_cb = QCheckBox("Watch these folders and scan each new file once it is complete")
        self.watch_cb.toggled.connect(self._protection_changed)
        watch_layout.addWidget(self.watch_cb)
        row = QHBoxLayout()
        self.watch_list = QListWidget()
        self.watch_list.setMaximumHeight(90)
        row.addWidget(self.watch_list)
        buttons = QVBoxLayout()
        add = QPushButton("Add folder...")
        add.clicked.connect(self._add_watch_folder)
        remove = QPushButton("Remove")
        remove.clicked.connect(self._remove_watch_folder)
        buttons.addWidget(add)
        buttons.addWidget(remove)
        row.addLayout(buttons)
        watch_layout.addLayout(row)
        self.watch_status = QLabel()
        watch_layout.addWidget(self.watch_status)
        layout.addWidget(watch_box)

        schedule_box = QGroupBox("Scheduled quick scan")
        schedule_layout = QHBoxLayout(schedule_box)
        schedule_layout.addWidget(QLabel("Quick scan (Downloads, Desktop, Temp) every"))
        self.schedule_spin = QSpinBox()
        self.schedule_spin.setRange(0, 24 * 30)
        self.schedule_spin.setKeyboardTracking(False)  # typing "12" saves once, not at "1" and again at "12"
        self.schedule_spin.valueChanged.connect(self._protection_changed)
        schedule_layout.addWidget(self.schedule_spin)
        schedule_layout.addWidget(QLabel("hour(s) while this program is open (0 = off)"))
        self.schedule_status = QLabel()
        schedule_layout.addWidget(self.schedule_status, 1)
        layout.addWidget(schedule_box)

        yara_box = QGroupBox("Custom YARA rules")
        yara_layout = QVBoxLayout(yara_box)
        row = QHBoxLayout()
        self.rule_list = QListWidget()
        self.rule_list.setMaximumHeight(90)
        row.addWidget(self.rule_list)
        buttons = QVBoxLayout()
        add_rule = QPushButton("Add rule file...")
        add_rule.clicked.connect(self._add_rule_file)
        self.add_rule_btn = add_rule
        remove_rule = QPushButton("Remove")
        remove_rule.clicked.connect(self._remove_rule_file)
        buttons.addWidget(add_rule)
        buttons.addWidget(remove_rule)
        row.addLayout(buttons)
        yara_layout.addLayout(row)
        yara_layout.addWidget(QLabel("ClamAV loads .yar / .yara files with its signatures, so every scan uses them. "
                                     "A file is checked by ClamAV before it is installed."))
        layout.addWidget(yara_box)

        layout.addWidget(self._create_virustotal_box())

        note = QLabel("ℹ️ The protection only works while this program is open: there is no background service. "
                      "Settings and rules are kept in the administrators-only data folder.")
        note.setWordWrap(True)
        note.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(note)
        layout.addStretch()
        return scrollable(page)

    def _start_protection(self):
        self.folder_watcher = None
        self.watch_poll_worker = None
        self.watch_queue: List[str] = []
        first_run = not os.path.isfile(watcher.settings_path())
        self.protection = watcher.load_settings()
        if first_run and not self.protection.folders:  # a list the user emptied stays empty
            self.protection.folders = [os.path.normpath(p) for p in (
                QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation),
                QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DesktopLocation)) if p]
        self._loading_protection = True
        self.watch_cb.setChecked(self.protection.watch_enabled)
        self.schedule_spin.setValue(self.protection.scan_hours)
        self.watch_list.clear()
        self.watch_list.addItems(self.protection.folders)
        self._loading_protection = False
        self._refresh_rules()
        self._rebuild_watcher()
        self.protection_timer = QTimer(self)
        self.protection_timer.timeout.connect(self._protection_timer_fired)
        self.protection_timer.start(PROTECTION_TICK_MS)

    def _rebuild_watcher(self):
        self.watch_queue = []
        if self.protection.watch_enabled and self.protection.folders:
            self.folder_watcher = watcher.FolderWatcher(self.protection.folders)
            self.folder_watcher.primed = False  # the first listing (up to 20 000 files) runs off the GUI thread
            self.watch_status.setText(f"Watching {count(len(self.protection.folders), 'folder')}. "
                                      "Files already there are not scanned.")
            self.watch_status.setStyleSheet("color: darkgreen;")
            self._poll_watch_folders()
        else:
            self.folder_watcher = None
            self.watch_status.setText("Off.")
            self.watch_status.setStyleSheet("color: gray;")
        self._refresh_schedule_status()

    def _refresh_schedule_status(self):
        hours = self.protection.scan_hours
        self.schedule_status.setText(f"Every {hours} h." if hours else "Off.")

    def _protection_changed(self, *_):
        if getattr(self, "_loading_protection", False):
            return
        watching = (self.protection.watch_enabled, list(self.protection.folders))
        self.protection.watch_enabled = self.watch_cb.isChecked()
        self.protection.scan_hours = self.schedule_spin.value()
        self.protection.folders = [self.watch_list.item(i).text() for i in range(self.watch_list.count())]
        error = watcher.save_settings(self.protection)
        if error:
            QMessageBox.warning(self, "Protection", plain(f"The settings could not be saved: {error}"))
        if (self.protection.watch_enabled, self.protection.folders) != watching:
            self._rebuild_watcher()  # a change of the schedule alone does not restart the watching
        else:
            self._refresh_schedule_status()

    def _add_watch_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Folder to watch")
        if folder:
            path = os.path.normpath(folder)
            if not self.watch_list.findItems(path, Qt.MatchFlag.MatchExactly):
                self.watch_list.addItem(path)
                self._protection_changed()

    def _remove_watch_folder(self):
        items = self.watch_list.selectedItems()
        if not items:
            QMessageBox.information(self, "Info", "Select a folder in the list first.")
            return
        for item in items:
            self.watch_list.takeItem(self.watch_list.row(item))
        self._protection_changed()

    def _protection_timer_fired(self):
        self._poll_watch_folders()
        self._protection_tick()

    def _poll_watch_folders(self):
        """Look at the watched folders in a background thread; new complete files reach _on_watch_polled."""
        target, running = self.folder_watcher, self.watch_poll_worker
        if target is None or (running is not None and running.isRunning()):
            return
        worker = CallWorker(lambda: watch_step(target), "Watched folders")
        worker.done.connect(lambda paths, error: self._on_watch_polled(target, paths, error))
        self.watch_poll_worker = worker
        worker.start()

    def _on_watch_polled(self, target, paths, error):
        if error or target is not self.folder_watcher:  # the settings changed while it was listing
            return
        self.watch_queue += [p for p in paths or [] if p not in self.watch_queue]

    def _protection_tick(self):
        """Every 30 s: scan the new complete files (or run the scheduled quick scan) when ClamAV is free."""
        if self._clam_running():
            return
        if self.watch_queue:
            batch, self.watch_queue = self.watch_queue[:BATCH_SIZE], self.watch_queue[BATCH_SIZE:]
            batch = [p for p in batch if os.path.exists(p)]
            if batch and self._start_clam_scan(batch, quiet=True, source="new files"):
                self._update_status(f"Protection: scanning {len(batch)} new file(s)...")
            elif batch:
                self.watch_status.setText("ClamAV is not ready: new files are not scanned.")
                self.watch_status.setStyleSheet("color: red;")
        elif watcher.scan_is_due(self.protection):
            if self._start_clam_scan(self._quick_scan_folders(), quiet=True, source="the scheduled quick scan"):
                self.protection.last_quick_scan = time.time()
                watcher.save_settings(self.protection)
                self.schedule_status.setText(f"Every {self.protection.scan_hours} h. Last run: now.")

    def _refresh_rules(self):
        self.rule_list.clear()
        self.rule_list.addItems(watcher.list_rule_files())

    def _add_rule_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "YARA rule file", "", "YARA rules (*.yar *.yara)")
        if not path:
            return
        self._refresh_clam_status()
        install = self.clam_install
        if install is None:  # no ClamAV to check the file with: only a copy, nothing slow
            self._on_rule_added(watcher.add_rule_file(path, install=None), "")
            return
        # clamscan loads the file to check it (up to 2 minutes): never on the GUI thread
        self._start_call("yara_rule_worker", lambda: watcher.add_rule_file(path, install=install),
                         self._on_rule_added, self.add_rule_btn, "Checking the rule file with ClamAV...")

    def _on_rule_added(self, problem, error):
        if problem or error:
            self._update_status("The rule file was not added.")
            QMessageBox.warning(self, "YARA rules", plain(problem or error))
            return
        self._update_status("Rule file added.")
        self._refresh_rules()
        self._refresh_clam_status()

    def _remove_rule_file(self):
        items = self.rule_list.selectedItems()
        if not items:
            QMessageBox.information(self, "Info", "Select a rule file first.")
            return
        error = watcher.remove_rule_file(items[0].text())
        if error:
            QMessageBox.warning(self, "YARA rules", plain(error))
        self._refresh_rules()
        self._refresh_clam_status()

    # endregion
