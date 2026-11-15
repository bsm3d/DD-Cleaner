"""Antivirus tab: scan files and folders with ClamAV, quarantine, signature updates."""

import logging
import os
import re
import subprocess
import time

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTreeWidgetItem, QMessageBox,
    QFileDialog, QGroupBox, QCheckBox, QListWidget, QAbstractItemView, QHeaderView, QTabWidget, QProgressBar,
    QPlainTextEdit, QSpinBox, QScrollArea, QFrame
)
from PySide6.QtCore import Qt, QStandardPaths, QTimer
from PySide6.QtGui import QColor

from ddcleaner import clamav
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM32, safe_environment, sys_exe
from ddcleaner import parallel_scan, scan_cache
from ddcleaner.workers import ClamProcessWorker, ClamScanPool
from ddcleaner.ui.safe_text import plain, count, listed
from ddcleaner.ui.tab_system_info import primary, CheckTree

DATABASE_MAX_AGE_DAYS = 3
LOG_MAX_LINES = 2000
STATE_DETECTED, STATE_QUARANTINED = "Detected", "Quarantined"


def scrollable(page: QWidget) -> QScrollArea:
    """A page that scrolls instead of forcing the window to be as tall as its content (small or scaled screens)."""
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setWidget(page)
    return scroll


class AntivirusTabMixin:
    """Antivirus tab (ClamAV). Mixed into MainWindow."""

    def _create_antivirus_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        status_box = QGroupBox("ClamAV")
        status_layout = QVBoxLayout(status_box)
        self.clam_install_label = QLabel()
        self.clam_install_label.setWordWrap(True)
        self.clam_db_label = QLabel()
        self.clam_db_label.setWordWrap(True)
        status_layout.addWidget(self.clam_install_label)
        status_layout.addWidget(self.clam_db_label)
        layout.addWidget(status_box)

        pages = QTabWidget()
        pages.addTab(self._create_clam_scan_page(), "Scan")
        pages.addTab(self._create_clam_quarantine_page(), "Quarantine")
        pages.addTab(self._create_clam_update_page(), "Signature update")
        self._add_hunt_pages(pages)  # running processes, persistence hunt, automatic protection (tab_hunt.py)
        layout.addWidget(pages)
        self.clam_pages = pages

        self.clam_tab_page = page
        self.tab_widget.addTab(page, "🦠 Antivirus")
        self.clam_scan_worker = None
        self.clam_update_worker = None
        self.clam_auto_scan = ""  # what the protection is scanning ('' for a scan started by a click)
        self.clam_scan_started = 0.0
        self.clam_threats, self.clam_counts, self.clam_last_file = {}, {"files": 0, "found": 0, "errors": 0}, ""
        self.clam_clock = QTimer(self)
        self.clam_clock.timeout.connect(self._tick_clam_scan)
        self._refresh_clam_status()
        self._refresh_clam_quarantine()

    # region Status

    def _refresh_clam_status(self):
        install, reason = clamav.find_install()
        self.clam_install = install
        if install is None:
            self.clam_install_label.setText(plain(reason))
            self.clam_install_label.setStyleSheet("color: red; font-weight: bold;")
        else:
            self.clam_install_label.setText(plain(f"Engine: {install.folder}"))
            self.clam_install_label.setStyleSheet("color: darkgreen;")
        info = clamav.read_database_info()
        if not info.ready:
            text, color = "Signature database: not downloaded yet (see \"Signature update\").", "color: red; font-weight: bold;"
        else:
            text = "Signature database: " + (f"{info.signatures:,} signatures".replace(",", " ") if info.signatures else "custom")
            color = "color: darkgreen;"
            if info.built:
                text += f", built {info.built:%Y-%m-%d}"
                if info.age_days is not None and info.age_days > DATABASE_MAX_AGE_DAYS:
                    text += f" ({info.age_days} days old, update recommended)"
                    color = "color: #b35900;"
        self.clam_db_label.setText(text)
        self.clam_db_label.setStyleSheet(color)

    def _clam_running(self) -> bool:
        return any(w is not None and w.isRunning() for w in (self.clam_scan_worker, self.clam_update_worker))

    def _clam_busy(self) -> bool:
        for worker in (self.clam_scan_worker, self.clam_update_worker):
            if worker is not None and worker.isRunning():
                QMessageBox.information(self, "Info", "A ClamAV operation is already running.")
                return True
        return False

    # endregion

    # region Scan page

    def _create_clam_scan_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        layout.addWidget(QLabel("Items to scan:"))
        target_row = QHBoxLayout()
        self.clam_targets = QListWidget()
        self.clam_targets.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.clam_targets.setMaximumHeight(90)
        target_row.addWidget(self.clam_targets)
        buttons = QVBoxLayout()
        for text, slot in (("Add file...", self._add_clam_file), ("Add folder...", self._add_clam_folder),
                           ("Remove", self._remove_clam_targets)):
            button = QPushButton(text)
            button.clicked.connect(slot)
            buttons.addWidget(button)
        target_row.addLayout(buttons)
        layout.addLayout(target_row)

        options = QHBoxLayout()
        self.clam_quarantine_cb = QCheckBox("Move threats to quarantine")
        self.clam_quarantine_cb.setChecked(True)
        self.clam_archives_cb = QCheckBox("Scan archives (zip, rar, 7z...)")
        self.clam_archives_cb.setChecked(True)
        options.addWidget(self.clam_quarantine_cb)
        options.addWidget(self.clam_archives_cb)
        options.addWidget(QLabel("Skip files larger than (MB):"))
        self.clam_maxsize_spin = QSpinBox()
        self.clam_maxsize_spin.setRange(*clamav.MAX_FILESIZE_MB)
        self.clam_maxsize_spin.setValue(100)
        options.addWidget(self.clam_maxsize_spin)
        options.addStretch()
        layout.addLayout(options)

        detection = QHBoxLayout()
        self.clam_pua_cb = QCheckBox("Detect unwanted apps (PUA)")
        self.clam_pua_cb.setToolTip("Also flag adware, bundleware and hacktools, not only malware.")
        self.clam_thorough_cb = QCheckBox("Thorough (flag encrypted archives, macros, broken files)")
        self.clam_thorough_cb.setToolTip("Catches more, but a password-protected archive or a macro document "
                                         "can then be flagged as a threat (and quarantined). More false positives.")
        self.clam_fast_cb = QCheckBox("Fast mode")
        self.clam_fast_cb.setToolTip("No archives, no heuristics, no phishing check: several times quicker, but "
                                     "catches less (a threat hidden in a zip or only spotted by heuristics is missed).")
        # Fast mode switches these two off in ClamAV: show it instead of leaving them ticked for nothing
        self.clam_fast_cb.toggled.connect(lambda fast: (self.clam_archives_cb.setEnabled(not fast),
                                                        self.clam_thorough_cb.setEnabled(not fast)))
        detection.addWidget(self.clam_fast_cb)
        detection.addWidget(self.clam_pua_cb)
        detection.addWidget(self.clam_thorough_cb)
        detection.addStretch()
        layout.addLayout(detection)

        speed = QHBoxLayout()
        self.clam_cache_cb = QCheckBox("Skip files unchanged since a clean scan in the last")
        self.clam_cache_cb.setChecked(True)
        self.clam_cache_cb.setToolTip("A file is skipped only if its size and date are the same and a scan with at least "
                                      "these options found it clean. New signatures reach it when this delay is over. "
                                      "Untick for a full re-check of everything.")
        self.clam_cache_days = QSpinBox()
        self.clam_cache_days.setRange(1, 60)
        self.clam_cache_days.setValue(7)
        self.clam_cache_days.setSuffix(" days")
        self.clam_threads_spin = QSpinBox()
        self.clam_threads_spin.setRange(0, parallel_scan.MAX_THREADS)
        self.clam_threads_spin.setSpecialValueText("Auto")
        self.clam_threads_spin.setToolTip("clamscan processes working in parallel. Each one keeps the signatures in "
                                          "memory (about 1 GB), so Auto stays within the free RAM.")
        clear_btn = QPushButton("Forget scan memory")
        clear_btn.clicked.connect(self._clear_scan_cache)
        for widget in (self.clam_cache_cb, self.clam_cache_days, QLabel("Parallel scans:"), self.clam_threads_spin, clear_btn):
            speed.addWidget(widget)
        speed.addStretch()
        layout.addLayout(speed)

        actions = QHBoxLayout()
        self.clam_scan_btn = primary(QPushButton("🔍 Scan these items"))
        self.clam_scan_btn.setToolTip("Scan every file and folder of the list above")
        self.clam_scan_btn.clicked.connect(lambda: self._start_clam_scan(self._clam_target_paths()))
        self.clam_quick_btn = QPushButton("⚡ Quick scan")
        self.clam_quick_btn.setToolTip("Downloads, Desktop and the temporary folder")
        self.clam_quick_btn.clicked.connect(self._clam_quick_scan)
        self.clam_full_btn = QPushButton("💽 Full scan")
        self.clam_full_btn.setToolTip("Every fixed disk. Can take hours.")
        self.clam_full_btn.clicked.connect(self._clam_full_scan)
        self.clam_stop_btn = QPushButton("⏹ Stop")
        self.clam_stop_btn.setEnabled(False)
        self.clam_stop_btn.clicked.connect(self._stop_clam_scan)
        for button in (self.clam_scan_btn, self.clam_quick_btn, self.clam_full_btn):
            actions.addWidget(button)
        actions.addStretch()
        actions.addWidget(self.clam_stop_btn)
        layout.addLayout(actions)

        self.clam_scan_summary = QLabel("Ready.")
        self.clam_scan_summary.setStyleSheet("font-weight: bold;")
        self.clam_scan_summary.setWordWrap(True)
        layout.addWidget(self.clam_scan_summary)
        self.clam_scan_progress = QProgressBar()
        self.clam_scan_progress.setVisible(False)
        layout.addWidget(self.clam_scan_progress)
        self.clam_scan_stats = QLabel()
        layout.addWidget(self.clam_scan_stats)
        self.clam_current_file = QLabel()
        self.clam_current_file.setStyleSheet("color: gray;")
        layout.addWidget(self.clam_current_file)

        self.clam_threat_tree = CheckTree()
        self.clam_threat_tree.empty_text = "Threats found by a scan are listed here."
        self.clam_threat_tree.setHeaderLabels(["File", "Threat", "State"])
        self.clam_threat_tree.setColumnWidth(0, 560)
        self.clam_threat_tree.setColumnWidth(1, 240)
        self.clam_threat_tree.setSortingEnabled(True)
        self.clam_threat_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.clam_threat_tree.setMinimumHeight(110)
        layout.addWidget(self.clam_threat_tree, 2)

        self.clam_scan_log = self._make_clam_log()
        self.clam_scan_log.setMinimumHeight(70)
        layout.addWidget(self.clam_scan_log, 1)
        info = QLabel("ℹ️ A scan never deletes anything. With quarantine on, infected files are moved to a folder only "
                      "administrators can open; you can restore or delete them from the Quarantine page.")
        info.setWordWrap(True)
        info.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(info)
        return scrollable(page)

    @staticmethod
    def _make_clam_log() -> QPlainTextEdit:
        log = QPlainTextEdit()
        log.setReadOnly(True)
        log.setMaximumBlockCount(LOG_MAX_LINES)
        log.setStyleSheet("font-family: 'Consolas', 'Courier New', monospace; font-size: 9pt;")
        return log

    def _add_clam_file(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Choose files to scan")
        for f in files:
            self._add_clam_target(f)

    def _add_clam_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Choose a folder to scan")
        if folder:
            self._add_clam_target(folder)

    def _add_clam_target(self, path: str):
        path = os.path.normpath(path)
        if not self.clam_targets.findItems(path, Qt.MatchFlag.MatchExactly):
            self.clam_targets.addItem(path)

    def _remove_clam_targets(self):
        for item in self.clam_targets.selectedItems():
            self.clam_targets.takeItem(self.clam_targets.row(item))

    def _clam_target_paths(self) -> list:
        return [self.clam_targets.item(i).text() for i in range(self.clam_targets.count())]

    def _set_clam_targets(self, paths: list):
        self.clam_targets.clear()
        for p in paths:
            self._add_clam_target(p)

    @staticmethod
    def _quick_scan_folders() -> list:
        folders = []
        for location in (QStandardPaths.StandardLocation.DownloadLocation,
                         QStandardPaths.StandardLocation.DesktopLocation,
                         QStandardPaths.StandardLocation.TempLocation):
            path = QStandardPaths.writableLocation(location)
            if path and os.path.isdir(path) and os.path.normpath(path) not in folders:
                folders.append(os.path.normpath(path))
        return folders

    def _clam_quick_scan(self):
        self._start_clam_scan(self._quick_scan_folders())  # the "Items to scan" list is the user's: left alone

    def _clam_full_scan(self):
        drives = clamav.fixed_drives()
        if not self._confirm("Full scan", f"Scan {', '.join(drives)}?\n\nThis can take several hours."):
            return
        self._start_clam_scan(drives)

    def _start_clam_scan(self, targets: list, quiet: bool = False, source: str = "") -> bool:
        """Start a scan. quiet (protection): no dialog, and nothing is started while another operation runs;
        source names what is scanned in the alert shown if a threat is found.
        Returns True when the scan started."""
        if quiet and self._clam_running():
            return False
        if not quiet and self._clam_busy():
            return False
        self._refresh_clam_status()

        def refuse(title: str, text: str, kind: str = "warning", page: int = -1) -> bool:
            if not quiet:
                getattr(QMessageBox, kind)(self, title, text)
                if page >= 0:
                    self.clam_pages.setCurrentIndex(page)
            return False

        if self.clam_install is None:
            return refuse("ClamAV", plain(self.clam_install_label.text()))
        if not clamav.read_database_info().ready:
            return refuse("ClamAV", "The signature database has not been downloaded yet.\n"
                                    "Use the \"Signature update\" page first.", page=2)
        targets = [t for t in targets if os.path.exists(t)]
        if not targets:
            return refuse("Info", "Add at least one existing file or folder to scan.", "information")
        if not all(os.path.isabs(t) for t in targets):
            return refuse("ClamAV", "The scan cannot start: every item to scan must be an absolute path.")
        try:
            os.makedirs(clamav.quarantine_dir(), exist_ok=True)
        except OSError as e:
            return refuse("ClamAV", plain(f"The scan cannot start: {e}"))
        options = parallel_scan.ScanOptions(
            quarantine=self.clam_quarantine_cb.isChecked(), archives=self.clam_archives_cb.isChecked(),
            pua=self.clam_pua_cb.isChecked(), thorough=self.clam_thorough_cb.isChecked(),
            fast=self.clam_fast_cb.isChecked(), max_filesize_mb=self.clam_maxsize_spin.value(),
            use_cache=self.clam_cache_cb.isChecked(), cache_days=self.clam_cache_days.value(),
            threads=self.clam_threads_spin.value())
        self.clam_auto_scan = source if quiet else ""

        if quiet:
            # the protection must not wipe the threats of a scan the user is still reading
            self.clam_scan_log.appendPlainText(f"--- Protection: scanning {source} ---")
        else:
            self.clam_threat_tree.clear()
            self.clam_scan_log.clear()
        self.clam_threats = {}      # path -> (threat, tree item), for this scan only
        self.clam_counts = {"files": 0, "found": 0, "errors": 0}
        self.clam_skipped, self.clam_processes = 0, 0
        self.clam_last_file = ""
        self.clam_scan_started = time.monotonic()
        self.clam_scan_summary.setText("Scan in progress...")
        self.clam_scan_summary.setStyleSheet("font-weight: bold;")
        self._set_clam_scan_running(True)
        self.progress_bar.setVisible(True)
        self.clam_scan_progress.setRange(0, 0)  # listing the files: no total yet
        self.clam_scan_progress.setVisible(True)
        self._update_status(f"ClamAV scan of {count(len(targets), 'item')}...")
        logging.info(f"ClamAV scan started: {', '.join(targets)}")
        self.clam_scan_worker = ClamScanPool(self.clam_install, targets, options)
        self.clam_scan_worker.lines.connect(self._on_clam_scan_lines)
        self.clam_scan_worker.done.connect(self._on_clam_scan_done)
        self.clam_scan_worker.progress.connect(self._on_clam_listing)
        self.clam_scan_worker.planned.connect(self._on_clam_planned)
        self.clam_scan_worker.start()
        self.clam_clock.start(500)
        return True

    def _on_clam_listing(self, text: str):
        self.clam_last_file = text

    def _on_clam_planned(self, to_scan: int, skipped: int, processes: int):
        self.clam_skipped, self.clam_processes = skipped, processes
        if to_scan:
            self.clam_scan_progress.setRange(0, to_scan)
        self.clam_scan_summary.setText(
            f"Scanning {to_scan} file(s)" + (f", {skipped} unchanged file(s) skipped" if skipped else "")
            + (f", {processes} in parallel" if processes > 1 else "") + "...")

    def _clear_scan_cache(self):
        if self._clam_running():
            QMessageBox.information(self, "Info", "Wait for the scan to finish.")
            return
        try:
            cache = scan_cache.ScanCache(os.path.join(clamav.clam_dir(), scan_cache.NAME))
            cache.clear()
            cache.close()
        except OSError as e:
            QMessageBox.warning(self, "ClamAV", plain(f"The scan memory could not be cleared: {e}"))
            return
        self._update_status("Scan memory cleared: the next scan checks every file.")

    def _set_clam_scan_running(self, running: bool):
        for button in (self.clam_scan_btn, self.clam_quick_btn, self.clam_full_btn):
            button.setEnabled(not running)
        self.clam_stop_btn.setEnabled(running)

    def _stop_clam_scan(self):
        if self.clam_scan_worker is not None and self.clam_scan_worker.isRunning():
            self.clam_scan_worker.stop()
            self.clam_stop_btn.setEnabled(False)

    def _tick_clam_scan(self):
        self.clam_scan_stats.setText(
            f"Files scanned: {self.clam_counts['files']}"
            + (f"    Unchanged, skipped: {getattr(self, 'clam_skipped', 0)}" if getattr(self, "clam_skipped", 0) else "")
            + f"    Threats: {self.clam_counts['found']}    "
            f"Time: {clamav.format_duration(time.monotonic() - self.clam_scan_started)}")
        self.clam_current_file.setText(plain(clamav.shorten(self.clam_last_file)))
        if self.clam_scan_progress.maximum():
            self.clam_scan_progress.setValue(min(self.clam_counts["files"], self.clam_scan_progress.maximum()))

    def _on_clam_scan_lines(self, lines: list):
        counts = self.clam_counts
        for line in lines:
            kind = clamav.parse_scan_line(line)
            if kind[0] in ("ok", "skip"):
                counts["files"] += 1
                self.clam_last_file = kind[1]
            elif kind[0] == "found":
                _, path, threat = kind
                counts["files"] += 1
                counts["found"] += 1
                self.clam_last_file = path
                item = QTreeWidgetItem([path, threat, STATE_DETECTED])
                item.setForeground(1, QColor(Qt.GlobalColor.red))
                self.clam_threat_tree.addTopLevelItem(item)
                self.clam_threats[path] = (threat, item)
                self.clam_scan_log.appendPlainText(f"THREAT  {path}  ({threat})")
                logging.warning(f"ClamAV threat: {path}: {threat}")
            elif kind[0] == "moved":
                _, path, stored = kind
                threat, item = self.clam_threats.get(path, ("?", None))
                if item is not None:
                    item.setText(2, STATE_QUARANTINED)
                try:
                    clamav.record_quarantine(path, stored, threat)
                except OSError as e:
                    logging.error(f"ClamAV: quarantine list not updated: {e}")
            elif kind[0] == "error":
                counts["errors"] += 1
                self.clam_scan_log.appendPlainText(kind[1])
            elif kind[0] == "other" and kind[1]:
                self.clam_scan_log.appendPlainText(kind[1])

    def _on_clam_scan_done(self, code: int):
        self.clam_clock.stop()
        worker = self.clam_scan_worker
        self._set_clam_scan_running(False)
        self.progress_bar.setVisible(False)
        self.clam_scan_progress.setVisible(False)
        self._tick_clam_scan()
        self.clam_current_file.clear()
        found, errors = self.clam_counts["found"], self.clam_counts["errors"]
        if worker is not None and worker.stopped:
            text, style = "Scan stopped.", "color: #b35900; font-weight: bold;"
        elif found:
            text, style = f"⚠️ {found} threat(s) detected.", "color: red; font-weight: bold;"
        elif code == 0:
            text, style = "✅ No threat detected.", "color: darkgreen; font-weight: bold;"
        else:
            text, style = f"The scan ended with an error (code {code}). See the log below.", "color: #b35900; font-weight: bold;"
        if not found and errors and code == 0:
            text += f" {errors} file(s) could not be read."
        skipped = getattr(self, "clam_skipped", 0)
        if skipped and not (worker is not None and worker.stopped):
            text += f" {skipped} unchanged file(s) were skipped (found clean by an earlier scan)."
        if self.clam_auto_scan:
            text = f"Protection ({self.clam_auto_scan}): {text}"
        self.clam_scan_summary.setText(text)
        self.clam_scan_summary.setStyleSheet(style)
        self._update_status(text.replace("⚠️ ", "").replace("✅ ", ""))
        logging.info(f"ClamAV scan finished: code {code}, {self.clam_counts['files']} files, {found} threats, {errors} errors")
        self._refresh_clam_quarantine()
        if found and self.clam_auto_scan:
            QMessageBox.warning(self, "Protection", plain(
                f"{count(found, 'threat')} found in {self.clam_auto_scan}:\n\n"
                + listed(f"{p}  ({t})" for p, (t, _item) in self.clam_threats.items())))
        self.clam_auto_scan = ""

    # endregion

    # region Quarantine page

    def _create_clam_quarantine_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        note = QLabel("Files isolated by ClamAV. They stay dangerous until you delete them.")
        note.setStyleSheet("color: gray;")
        layout.addWidget(note)
        self.clam_quarantine_tree = CheckTree()
        self.clam_quarantine_tree.empty_text = "No file in quarantine."
        self.clam_quarantine_tree.setHeaderLabels(["Original location", "Threat", "Date"])
        self.clam_quarantine_tree.setColumnWidth(0, 560)
        self.clam_quarantine_tree.setColumnWidth(1, 240)
        self.clam_quarantine_tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.clam_quarantine_tree.setSortingEnabled(True)
        layout.addWidget(self.clam_quarantine_tree)
        self.clam_quarantine_status = QLabel()
        self.clam_quarantine_status.setWordWrap(True)
        layout.addWidget(self.clam_quarantine_status)
        row = QHBoxLayout()
        restore = QPushButton("♻ Restore...")
        restore.clicked.connect(self._restore_clam_quarantine)
        delete = QPushButton("🗑 Delete permanently...")
        delete.clicked.connect(self._delete_clam_quarantine)
        folder = QPushButton("📂 Open folder")
        folder.clicked.connect(self._open_clam_quarantine_folder)
        vt = QPushButton("🛰 VirusTotal")
        vt.setToolTip("Look the selected files up on VirusTotal, and send one for analysis if it is unknown")
        vt.clicked.connect(lambda: self._virustotal_check([e.stored for e in self._quarantine_selection()]))
        refresh = QPushButton("🔄 Refresh")
        refresh.clicked.connect(self._refresh_clam_quarantine)
        for button in (restore, delete, vt, folder):
            row.addWidget(button)
        row.addStretch()
        row.addWidget(refresh)
        layout.addLayout(row)
        return page

    def _refresh_clam_quarantine(self):
        self.clam_quarantine_tree.clear()
        try:
            entries = clamav.list_quarantine()
        except OSError as e:
            logging.error(f"ClamAV quarantine unreadable: {e}")
            self.clam_quarantine_status.setText(plain(
                f"The quarantine could not be read: {e}. Its folder is reserved to administrators."))
            self.clam_quarantine_status.setStyleSheet("color: red;")
            return
        self.clam_quarantine_status.setText(f"{count(len(entries), 'file')} in quarantine." if entries
                                            else "The quarantine is empty.")
        self.clam_quarantine_status.setStyleSheet("color: gray;")
        for entry in entries:
            item = QTreeWidgetItem([entry.original, entry.threat, entry.date])
            item.setData(0, Qt.ItemDataRole.UserRole, entry)
            item.setToolTip(0, plain(f"Stored as: {entry.stored}"))
            self.clam_quarantine_tree.addTopLevelItem(item)

    def _quarantine_selection(self) -> list:
        """Selected quarantined files, without the 'select something' dialog."""
        return [i.data(0, Qt.ItemDataRole.UserRole) for i in self.clam_quarantine_tree.selectedItems()]

    def _selected_clam_entries(self) -> list:
        entries = [i.data(0, Qt.ItemDataRole.UserRole) for i in self.clam_quarantine_tree.selectedItems()]
        if not entries:
            QMessageBox.information(self, "Info", "Select one or more files in the list first.")
        return entries

    def _restore_clam_quarantine(self):
        entries = self._selected_clam_entries()
        if not entries:
            return
        if not self._confirm("Restore", f"Put {count(len(entries), 'file')} back at their original location?\n"
                                        "They probably contain a virus."):
            return
        self._quarantine_action(entries, clamav.restore_quarantined, "Restore", "restored")

    def _delete_clam_quarantine(self):
        entries = self._selected_clam_entries()
        if not entries:
            return
        if not self._confirm("Delete permanently",
                             f"Delete {count(len(entries), 'file')} for good? This cannot be undone."):
            return
        self._quarantine_action(entries, clamav.delete_quarantined, "Delete", "deleted")

    def _quarantine_action(self, entries: list, action, title: str, done: str):
        """Restore or delete each file, then one summary of what failed (never one box per file)."""
        failed = [f"{entry.original}: {error}" for entry, error in ((e, action(e)) for e in entries) if error]
        self._refresh_clam_quarantine()
        self._update_status(f"{count(len(entries) - len(failed), 'file')} {done}.")
        if failed:
            QMessageBox.warning(self, title, plain(f"{count(len(failed), 'file')} could not be {done}:\n\n"
                                                   + listed(failed)))

    def _open_clam_quarantine_folder(self):
        folder = clamav.quarantine_dir()
        os.makedirs(folder, exist_ok=True)
        subprocess.Popen([sys_exe("explorer.exe"), folder], cwd=SYSTEM32, env=safe_environment(),
                         creationflags=SUBPROCESS_FLAGS)

    # endregion

    # region Update page

    def _create_clam_update_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        hint = QLabel("Signatures are downloaded by freshclam from database.clamav.net. The first download is about "
                      "300 MB; later updates are small. Nothing else is sent.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color: gray;")
        layout.addWidget(hint)
        row = QHBoxLayout()
        self.clam_update_btn = primary(QPushButton("⬇ Update signatures..."))
        self.clam_update_btn.clicked.connect(self._start_clam_update)
        self.clam_update_stop_btn = QPushButton("⏹ Stop")
        self.clam_update_stop_btn.setToolTip("Stop the download. The signatures already installed are kept.")
        self.clam_update_stop_btn.setEnabled(False)
        self.clam_update_stop_btn.clicked.connect(self._stop_clam_update)
        self.clam_update_label = QLabel()
        row.addWidget(self.clam_update_btn)
        row.addWidget(self.clam_update_stop_btn)
        row.addWidget(self.clam_update_label, 1)
        layout.addLayout(row)
        self.clam_update_progress = QProgressBar()
        self.clam_update_progress.setRange(0, 100)
        layout.addWidget(self.clam_update_progress)
        self.clam_update_log = self._make_clam_log()
        layout.addWidget(self.clam_update_log)
        return page

    def _start_clam_update(self):
        if self._clam_busy():
            return
        self._refresh_clam_status()
        if self.clam_install is None:
            QMessageBox.warning(self, "ClamAV", plain(self.clam_install_label.text()))
            return
        first = not clamav.read_database_info().ready
        if not self._confirm(
                "Update signatures",
                ("Download the ClamAV signature database now (about 300 MB)?" if first
                 else "Check for new ClamAV signatures now?") + "\n\nfreshclam connects to database.clamav.net."):
            return
        try:
            conf = clamav.write_freshclam_conf()
        except OSError as e:
            QMessageBox.warning(self, "ClamAV", plain(f"The configuration could not be written: {e}"))
            return
        command = clamav.build_update_command(self.clam_install, conf, clamav.database_dir())
        self.clam_update_log.clear()
        self.clam_update_progress.setValue(0)
        self.clam_update_label.setText("Updating...")
        self.clam_update_btn.setEnabled(False)
        self.clam_update_stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self._update_status("Updating the ClamAV signatures...")
        logging.info("ClamAV signature update started")
        self.clam_update_worker = ClamProcessWorker(command)
        self.clam_update_worker.lines.connect(self._on_clam_update_lines)
        self.clam_update_worker.done.connect(self._on_clam_update_done)
        self.clam_update_worker.start()

    def _stop_clam_update(self):
        worker = self.clam_update_worker
        if worker is not None and worker.isRunning():
            worker.stop()
            self.clam_update_stop_btn.setEnabled(False)
            self.clam_update_label.setText("Stopping...")

    def _on_clam_update_lines(self, lines: list):
        for line in lines:
            match = re.search(r"(\d{1,3})%", line)
            if match:
                percent = min(int(match.group(1)), 100)
                self.clam_update_progress.setValue(percent)
                name = re.match(r"\s*(?:Downloading\s+)?(\S+)", line)
                self.clam_update_label.setText(plain(f"{name.group(1) if name else 'Downloading'} ({percent} %)"))
                if percent < 100:
                    continue  # progress ticks stay out of the log
            self.clam_update_log.appendPlainText(line)

    def _on_clam_update_done(self, code: int):
        self.progress_bar.setVisible(False)
        self.clam_update_btn.setEnabled(True)
        self.clam_update_stop_btn.setEnabled(False)
        worker = self.clam_update_worker
        if worker is not None and worker.stopped:
            text = "Update stopped."
        elif code == 0:
            self.clam_update_progress.setValue(100)
            text = "Signatures are up to date."
        else:
            text = f"The update failed (code {code}). See the log below."
        self.clam_update_label.setText(text)
        self._update_status(text)
        logging.info(f"ClamAV signature update finished: code {code}")
        self._refresh_clam_status()

    # endregion
