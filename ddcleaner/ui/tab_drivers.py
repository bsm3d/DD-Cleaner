"""Driver Checker tab: vulnerable drivers (Microsoft blocklist) and third-party driver age."""

import csv
import logging
import os
import subprocess
from datetime import datetime
from types import SimpleNamespace

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTreeWidgetItem,
    QMessageBox, QFileDialog, QComboBox, QMenu, QHeaderView, QTabWidget, QGroupBox, QCheckBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from ddcleaner import driver_blocklist, driver_cleanup, driver_uninstall
from ddcleaner.system_utils import SystemUtils
from ddcleaner.ui import locations
from ddcleaner.ui.tab_cleanup import (SortableItem, checkable, checked_payloads, not_checkable, remove_rows,
                                      set_all_checked, tick_buttons)
from ddcleaner.ui.tab_system_info import make_tree, primary, CheckTree
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM32, SYSTEM_ROOT, safe_environment, sys_exe
from ddcleaner.workers import DriverScanWorker, BlocklistDownloadWorker, VulnerableDriverScanWorker
from ddcleaner.ui.safe_text import plain, csv_cell, count, listed

BLOCKLIST_MAX_AGE_DAYS = 90
AGE_FILTERS = (("All drivers", 0), ("1 year", 365), ("2 years", 730), ("3 years", 1095), ("5 years", 1825))


class DriversTabMixin:
    """Driver Checker tab. Mixed into MainWindow."""

    def _create_drivers_tab(self):
        """Create driver checker tab (two pages)."""
        drivers_tabs = QTabWidget()
        drivers_tabs.addTab(self._create_vulnerable_drivers_page(), "Vulnerable drivers")
        drivers_tabs.addTab(self._create_driver_age_page(), "Driver age")
        drivers_tabs.addTab(self._create_unused_drivers_page(), "Unused drivers")
        drivers_tabs.addTab(self._create_uninstall_drivers_page(), "Uninstall drivers")
        self.drivers_tabs = drivers_tabs
        self.tab_widget.addTab(drivers_tabs, "🧩 Driver Checker")

    # region Vulnerable drivers

    VULN_COLUMNS = ["Driver", "Result", "State", "Service", "Version", "Signer", "Matched rule", "Path"]

    def _create_vulnerable_drivers_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        protection_box = QGroupBox("Windows protection")
        protection_layout = QVBoxLayout(protection_box)
        self.protection_label = QLabel()
        self.protection_label.setWordWrap(True)
        protection_layout.addWidget(self.protection_label)
        self.protection_hint = QLabel(
            "Windows does not block the drivers of the blocklist on this PC. To turn it on: Windows Security > "
            "Device security > Core isolation > Microsoft Vulnerable Driver Blocklist (or Memory integrity).")
        self.protection_hint.setWordWrap(True)
        self.protection_hint.setStyleSheet("color: #b35900;")
        protection_layout.addWidget(self.protection_hint)
        core_btn = QPushButton("🛡️ Open Core isolation settings")
        core_btn.clicked.connect(self._open_core_isolation)
        core_row = QHBoxLayout()
        core_row.addWidget(core_btn)
        core_row.addStretch()
        protection_layout.addLayout(core_row)
        layout.addWidget(protection_box)

        list_row = QHBoxLayout()
        self.blocklist_label = QLabel()
        list_row.addWidget(self.blocklist_label)
        list_row.addStretch()
        self.blocklist_download_btn = QPushButton("⬇ Download latest blocklist")
        self.blocklist_download_btn.setToolTip(f"Download the current list from Microsoft ({driver_blocklist.BLOCKLIST_URL})")
        self.blocklist_download_btn.clicked.connect(lambda: self._download_blocklist())
        self.vuln_scan_btn = primary(QPushButton("🔍 Check drivers"))
        self.vuln_scan_btn.setToolTip("Check loaded, installed and System32\\drivers files against the blocklist (read-only)")
        self.vuln_scan_btn.clicked.connect(self._scan_vulnerable_drivers)
        vuln_export_btn = QPushButton("💾 Export to CSV")
        vuln_export_btn.clicked.connect(self._export_vulnerable_drivers)
        list_row.addWidget(self.blocklist_download_btn)
        list_row.addWidget(self.vuln_scan_btn)
        list_row.addWidget(vuln_export_btn)
        layout.addLayout(list_row)

        self.vuln_only_flagged_cb = QCheckBox("Show only drivers on the blocklist")
        self.vuln_only_flagged_cb.toggled.connect(self._populate_vulnerable_tree)
        layout.addWidget(self.vuln_only_flagged_cb)

        self.vuln_tree = CheckTree()
        self.vuln_tree.empty_text = "Check the drivers to fill this list."
        self.vuln_tree.setHeaderLabels(self.VULN_COLUMNS)
        for col, width in enumerate((170, 110, 130, 110, 110, 200, 260)):
            self.vuln_tree.setColumnWidth(col, width)
        self.vuln_tree.setSortingEnabled(True)
        self.vuln_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.vuln_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.vuln_tree.customContextMenuRequested.connect(self._show_vuln_context_menu)
        layout.addWidget(self.vuln_tree)

        self.vuln_summary_label = QLabel("Not checked yet.")
        self.vuln_summary_label.setWordWrap(True)
        layout.addWidget(self.vuln_summary_label)

        info_label = QLabel("ℹ️ A listed driver can be abused to take control of the kernel (\"bring your own vulnerable "
                            "driver\"). Update or uninstall the software that installed it. This check changes nothing.")
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(info_label)

        self.vuln_results = []
        self.blocklist_policy = None
        self._refresh_protection_state()
        self._load_cached_blocklist()
        return page

    def _refresh_protection_state(self):
        try:
            state = driver_blocklist.protection_state()
        except Exception as e:
            logging.error(f"Protection state not readable: {e}")
            self.protection_label.setText("Windows protection state could not be read.")
            self.protection_hint.setVisible(False)
            return
        self.protection_label.setText(state.summary)
        self.protection_label.setStyleSheet("color: darkgreen;" if state.enforced else "color: red; font-weight: bold;")
        self.protection_hint.setVisible(not state.enforced)

    def _load_cached_blocklist(self):
        try:
            self.blocklist_policy, meta = driver_blocklist.load_policy()
        except Exception as e:
            logging.error(f"Cached blocklist unusable: {e}")
            self.blocklist_policy, meta = None, {}
        if self.blocklist_policy is None:
            self.blocklist_label.setText("Microsoft blocklist: not downloaded yet.")
            return
        text = f"Microsoft blocklist {self.blocklist_policy.version} ({self.blocklist_policy.rule_count} rules)"
        downloaded = meta.get("downloaded", "")
        try:
            age = (datetime.now() - datetime.fromisoformat(downloaded)).days
            text += f", downloaded {downloaded[:10]}"
            if age > BLOCKLIST_MAX_AGE_DAYS:
                text += f" ({age} days old, consider updating)"
        except ValueError:
            pass
        self.blocklist_label.setText(text)

    def _open_core_isolation(self):
        try:
            os.startfile("windowsdefender://coreisolation")
        except OSError as e:
            QMessageBox.warning(self, "Error", f"Could not open Windows Security: {e}")

    def _download_blocklist(self, then_scan: bool = False):
        worker = getattr(self, "blocklist_download_worker", None)
        if worker is not None and worker.isRunning():
            QMessageBox.information(self, "Info", "The blocklist is already being downloaded.")
            return
        self._update_status("Downloading the Microsoft vulnerable driver blocklist...")
        self.progress_bar.setVisible(True)
        self.blocklist_download_btn.setEnabled(False)
        self.blocklist_download_worker = BlocklistDownloadWorker()
        self.blocklist_download_worker.done.connect(lambda v, e: self._on_blocklist_downloaded(v, e, then_scan))
        self.blocklist_download_worker.start()

    def _on_blocklist_downloaded(self, version: str, error: str, then_scan: bool):
        self.progress_bar.setVisible(False)
        self.blocklist_download_btn.setEnabled(True)
        if error:
            self._update_status("Blocklist download failed.")
            QMessageBox.warning(self, "Download failed", plain(f"The blocklist could not be downloaded:\n{error}"))
            return
        self._load_cached_blocklist()
        self._update_status(f"Blocklist {version} downloaded.")
        if then_scan:
            self._scan_vulnerable_drivers()

    def _scan_vulnerable_drivers(self):
        worker = getattr(self, "vuln_scan_worker", None)
        if worker is not None and worker.isRunning():
            QMessageBox.information(self, "Info", "A driver check is already running.")
            return
        if self.blocklist_policy is None:
            if self._confirm("Blocklist needed",
                             "The Microsoft vulnerable driver blocklist has not been downloaded yet.\n\n"
                             "Download it now from Microsoft and check the drivers?"):
                self._download_blocklist(then_scan=True)
            return
        self._refresh_protection_state()
        self.vuln_tree.clear()
        self.vuln_results = []
        self.vuln_scan_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self._update_status("Checking drivers against the blocklist...")
        # the worker only asks "is_set()": Stop / Esc and closing the program both answer yes
        self.vuln_scan_worker = VulnerableDriverScanWorker(self.blocklist_policy,
                                                           SimpleNamespace(is_set=self._stopper("vuln_scan_worker")))
        self.vuln_scan_worker.progress.connect(
            lambda n, total, path: self._update_status(f"Checking driver {n}/{total}: {os.path.basename(path)}"))
        self.vuln_scan_worker.done.connect(self._on_vulnerable_drivers_checked)
        self.vuln_scan_worker.start()

    def _on_vulnerable_drivers_checked(self, results: list, error: str):
        self.progress_bar.setVisible(False)
        self.vuln_scan_btn.setEnabled(True)
        if error:
            self._update_status("Driver check failed.")
            QMessageBox.warning(self, "Error", plain(f"Driver check failed: {error}"))
            return
        self.vuln_results = results
        flagged = [r for r in results if r.flagged]
        unreadable = sum(1 for r in results if r.info.error)
        if flagged:
            loaded = sum(1 for r in flagged if r.driver.loaded)
            self.vuln_summary_label.setText(
                f"⚠️ {len(flagged)} driver(s) on the blocklist ({loaded} loaded right now) among {len(results)} checked.")
            self.vuln_summary_label.setStyleSheet("color: red; font-weight: bold;")
            self.vuln_only_flagged_cb.setChecked(True)  # toggled -> repopulates
        else:
            self.vuln_summary_label.setText(f"✅ No driver on the blocklist among {len(results)} checked."
                                            + (f" {unreadable} file(s) could not be read." if unreadable else ""))
            self.vuln_summary_label.setStyleSheet("color: darkgreen;")
            self.vuln_only_flagged_cb.setChecked(False)  # nothing flagged: an "only flagged" list would stay empty
        self._populate_vulnerable_tree()
        self._update_status(f"Driver check done: {len(flagged)} on the blocklist.")

    def _populate_vulnerable_tree(self):
        self.vuln_tree.setSortingEnabled(False)
        self.vuln_tree.clear()
        only_flagged = self.vuln_only_flagged_cb.isChecked()
        for r in self.vuln_results:
            if only_flagged and not r.flagged:
                continue
            if r.flagged:
                result, color = "● BLOCKLISTED", QColor(Qt.GlobalColor.red)
            elif r.info.error:
                result, color = "● Not readable", QColor(Qt.GlobalColor.gray)
            else:
                result, color = "● OK", QColor(Qt.GlobalColor.darkGreen)
            version = ".".join(str(v) for v in r.info.version) if r.info.version else ""
            signer = r.info.signer or ("" if r.info.error else "(catalog signed or unsigned)")
            item = QTreeWidgetItem([os.path.basename(r.driver.path), result, r.driver.state, r.driver.service,
                                    version, signer, "; ".join(r.reasons) or r.info.error, r.driver.path])
            item.setForeground(1, color)
            self.vuln_tree.addTopLevelItem(item)
        self.vuln_tree.setSortingEnabled(True)
        self.vuln_tree.sortItems(1, Qt.SortOrder.AscendingOrder)  # "● BLOCKLISTED" sorts first

    def _export_vulnerable_drivers(self):
        if not self.vuln_results:
            QMessageBox.information(self, "Info", "Nothing to export. Please check the drivers first.")
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Export driver check", "driver_blocklist_check.csv",
                                                  "CSV Files (*.csv)")
        if not filename:
            return
        try:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Driver", "Blocklisted", "State", "Service", "Version", "Signer",
                                 "Matched rules", "SHA256 (Authenticode)", "Path"])
                for r in self.vuln_results:
                    writer.writerow([csv_cell(v) for v in (
                        os.path.basename(r.driver.path), "yes" if r.flagged else "no", r.driver.state,
                        r.driver.service, ".".join(str(v) for v in r.info.version) if r.info.version else "",
                        r.info.signer, "; ".join(r.reasons) or r.info.error,
                        r.info.hashes.get("sha256", ""), r.driver.path)])
            logging.info(f"Exported driver check ({len(self.vuln_results)} drivers) to {filename}")
            self._update_status(f"Exported {count(len(self.vuln_results), 'driver')} to {filename}")
        except OSError as e:
            logging.error(f"Failed to export driver check: {e}")
            QMessageBox.critical(self, "Error", f"Export failed: {e}")

    def _show_vuln_context_menu(self, position):
        item = self.vuln_tree.itemAt(position)
        if not item:
            return
        menu = QMenu()
        open_folder = menu.addAction("📂 Open file location")
        copy_path = menu.addAction("📋 Copy path")
        copy_rule = menu.addAction("📋 Copy matched rule")
        action = menu.exec(self.vuln_tree.viewport().mapToGlobal(position))
        path = item.text(7)
        if action == open_folder and os.path.isfile(path):
            subprocess.Popen([sys_exe("explorer.exe"), "/select,", path], cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)
        elif action == copy_path:
            QApplication.clipboard().setText(path)
        elif action == copy_rule:
            QApplication.clipboard().setText(item.text(6))

    # endregion

    # region Driver age

    def _create_driver_age_page(self) -> QWidget:
        """Third-party (oem*.inf) drivers and their age."""
        drivers_widget = QWidget()
        layout = QVBoxLayout(drivers_widget)

        # Control buttons
        btn_layout = QHBoxLayout()
        scan_drivers_btn = primary(QPushButton("🔍 Scan drivers"))
        scan_drivers_btn.clicked.connect(self._scan_drivers)
        scan_drivers_btn.setToolTip("List the third-party drivers and their dates (read-only)")

        export_btn = QPushButton("💾 Export to CSV")
        export_btn.clicked.connect(self._export_drivers)
        export_btn.setToolTip("Every driver found, whatever the age filter shows")

        btn_layout.addWidget(scan_drivers_btn)
        btn_layout.addWidget(export_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Filter options
        filter_layout = QHBoxLayout()
        filter_label = QLabel("Show only drivers older than:")
        self.driver_age_combo = QComboBox()
        for label, days in AGE_FILTERS:
            self.driver_age_combo.addItem(label, days)
        self.driver_age_combo.currentIndexChanged.connect(self._filter_drivers)
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.driver_age_combo)
        filter_layout.addStretch()
        layout.addLayout(filter_layout)

        # Drivers tree
        self.drivers_tree = CheckTree()
        self.drivers_tree.empty_text = "Scan the drivers to fill this list."
        self.drivers_tree.setHeaderLabels(["Driver name", "Date", "Version", "Provider", "Path", "Age (days)", "Status"])
        self.drivers_tree.setColumnWidth(0, 200)
        self.drivers_tree.setColumnWidth(1, 100)
        self.drivers_tree.setColumnWidth(2, 100)
        self.drivers_tree.setColumnWidth(3, 150)
        self.drivers_tree.setSortingEnabled(True)
        self.drivers_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.drivers_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.drivers_tree.customContextMenuRequested.connect(self._show_driver_context_menu)
        layout.addWidget(self.drivers_tree)

        # Info label
        info_label = QLabel("ℹ️ Old drivers may have security vulnerabilities or compatibility issues. Orange: older "
                            "than 3 years. Red: older than 5 years.")
        info_label.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(info_label)

        # Store all drivers for filtering
        self.all_drivers = []
        return drivers_widget

    def _scan_drivers(self):
        """Scan third-party drivers in a worker thread and populate the tree."""
        worker = getattr(self, "driver_scan_worker", None)
        if worker is not None and worker.isRunning():
            QMessageBox.information(self, "Info", "A driver scan is already running.")
            return
        self.drivers_tree.clear()
        self.all_drivers = []
        self._update_status("Scanning drivers...")
        self.progress_bar.setVisible(True)
        self.driver_scan_worker = DriverScanWorker()
        self.driver_scan_worker.done.connect(self._on_drivers_scanned)
        self.driver_scan_worker.start()

    def _on_drivers_scanned(self, drivers: list, error: str):
        self.progress_bar.setVisible(False)
        self.all_drivers = drivers
        if error:
            logging.error(f"Driver scan failed: {error}")
            QMessageBox.warning(self, "Error", plain(f"Driver scan failed: {error}"))
        self._filter_drivers()
        self._update_status(f"Found {len(self.all_drivers)} drivers")

    def _populate_drivers_tree(self, drivers):
        """Populate the drivers tree with driver information."""
        self.drivers_tree.clear()

        for driver in drivers:
            item = QTreeWidgetItem()
            item.setText(0, driver['name'])
            item.setText(1, driver['date_str'])
            item.setText(2, driver['version'])
            item.setText(3, driver['provider'])
            item.setText(4, driver['path'])
            item.setData(5, Qt.ItemDataRole.DisplayRole, driver['age_days'])  # a number: sorted as one

            # Colour badge by age
            age = driver['age_days']
            dot = "● "

            if age > 1825:  # > 5 ans
                status_text = f"{dot}Critical"
                color = QColor(Qt.GlobalColor.red)
            elif age > 1095:  # > 3 ans
                status_text = f"{dot}Old"
                color = QColor(255, 165, 0)  # orange
            else:
                status_text = f"{dot}OK"
                color = QColor(Qt.GlobalColor.darkGreen)

            item.setText(6, status_text)
            item.setForeground(6, color)

            self.drivers_tree.addTopLevelItem(item)

        # Sort by age (oldest first)
        self.drivers_tree.sortItems(5, Qt.SortOrder.DescendingOrder)

    def _filter_drivers(self):
        """Filter drivers based on age selection."""
        threshold = self.driver_age_combo.currentData() or 0
        filtered = [d for d in self.all_drivers if d['age_days'] > threshold]
        self._populate_drivers_tree(filtered)
        self._update_status(f"Showing {count(len(filtered), 'driver')}")

    def _export_drivers(self):
        """Export driver list to CSV file."""
        if not self.all_drivers:
            QMessageBox.information(self, "Info", "No drivers to export. Please scan first.")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Drivers", "drivers.csv", "CSV Files (*.csv)"
        )

        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Driver Name', 'Date', 'Version', 'Provider', 'Path', 'Age (Days)', 'Class'])

                    for driver in self.all_drivers:
                        # device names and providers come from driver packages: never let them be formulas
                        writer.writerow([csv_cell(v) for v in (
                            driver['name'],
                            driver['date_str'],
                            driver['version'],
                            driver['provider'],
                            driver['path'],
                            driver['age_days'],
                            driver['class']
                        )])

                logging.info(f"Exported {len(self.all_drivers)} drivers to {filename}")
                self._update_status(f"Exported all {count(len(self.all_drivers), 'driver')} to {filename}")
            except Exception as e:
                logging.error(f"Failed to export drivers: {e}")
                QMessageBox.critical(self, "Error", f"Export failed: {str(e)}")

    def _show_driver_context_menu(self, position):
        """Show context menu for driver tree."""
        item = self.drivers_tree.itemAt(position)
        if not item:
            return

        menu = QMenu()
        name = item.text(4)
        inf = os.path.join(SYSTEM_ROOT, "INF", name) if name and os.path.basename(name) == name else name
        open_inf = menu.addAction("📂 Open location") if inf else None
        copy_name = menu.addAction("📋 Copy driver name")
        copy_path = menu.addAction("📋 Copy path")

        action = menu.exec(self.drivers_tree.viewport().mapToGlobal(position))

        if open_inf is not None and action == open_inf:
            self._update_status(locations.reveal(inf) or "Location opened.")
        elif action == copy_name:
            QApplication.clipboard().setText(item.text(0))
            self._update_status("Driver name copied to clipboard")
        elif action == copy_path:
            QApplication.clipboard().setText(item.text(4))
            self._update_status("Driver path copied to clipboard")

    # endregion

    # region Unused drivers

    UNUSED_COLUMNS = ["Driver", "Published", "Class", "Provider", "Version", "Risk", "Why"]

    def _create_unused_drivers_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        info = QLabel("Driver packages that no connected device uses: a webcam or NAS that is gone, hardware you "
                      "unplugged, old versions that piled up. A copy of each driver is saved before it is removed.")
        info.setWordWrap(True)
        layout.addWidget(info)
        row = QHBoxLayout()
        self.unused_scan_btn = primary(QPushButton("🔍 Find unused drivers"))
        self.unused_scan_btn.setToolTip("Compares the driver store with the devices connected now (read-only)")
        self.unused_scan_btn.clicked.connect(self._scan_unused_drivers)
        self.unused_tree = make_tree(self.UNUSED_COLUMNS, (220, 80, 170, 200, 110, 60, 420),
                                     "Find the unused drivers to fill this list.")
        open_btn = QPushButton("📂 Open location")
        open_btn.setToolTip("The folder of the driver in the Windows driver store")
        open_btn.clicked.connect(lambda: self._open_selected_location("unused_tree"))
        backups_btn = QPushButton("📂 Backups")
        backups_btn.setToolTip("Folder of the driver copies saved before each removal")
        backups_btn.clicked.connect(self._open_driver_backups)
        self.unused_remove_btn = QPushButton("🗑 Remove ticked drivers...")
        self.unused_remove_btn.clicked.connect(self._remove_unused_drivers)
        for widget in [self.unused_scan_btn] + tick_buttons(self.unused_tree) + [open_btn, backups_btn]:
            row.addWidget(widget)
        row.addStretch()
        row.addWidget(self.unused_remove_btn)
        layout.addLayout(row)
        self.unused_summary = QLabel("Not checked yet. Nothing is changed by the search.")
        self.unused_summary.setWordWrap(True)
        layout.addWidget(self.unused_summary)
        layout.addWidget(self.unused_tree)
        note = QLabel("ℹ️ Safe: a newer version of the same driver is installed. Check: the hardware may still be yours "
                      "(an audio interface, a phone, a printer): once unplugged its driver is not needed, but plugging it "
                      "in again will need it back, from the saved copy or the maker's installer. Windows refuses to "
                      "remove a driver that is in use. Core drivers are never listed.")
        note.setWordWrap(True)
        note.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(note)
        return page

    def _scan_unused_drivers(self):
        self._start_call("driver_unused_worker", driver_cleanup.scan, self._on_unused_drivers_scanned,
                         self.unused_scan_btn, "Comparing the driver store with the connected devices...")

    def _on_unused_drivers_scanned(self, candidates, error):
        if error:
            QMessageBox.warning(self, "Error", plain(f"The drivers could not be compared: {error}"))
            return
        tree = self.unused_tree
        tree.setSortingEnabled(False)
        tree.clear()
        for c in candidates:
            p = c.package
            item = SortableItem([p.original, p.published, p.class_name, p.provider, p.version, c.risk, c.reason])
            item.setData(0, Qt.ItemDataRole.UserRole, c)
            item.setToolTip(6, plain(c.reason))
            if c.risk == "Safe":
                for column in range(len(self.UNUSED_COLUMNS)):
                    item.setForeground(column, QColor(Qt.GlobalColor.darkGreen))
            checkable(item)
            tree.addTopLevelItem(item)
        tree.setSortingEnabled(True)
        safe = sum(1 for c in candidates if c.risk == "Safe")
        self.unused_summary.setText(f"{len(candidates)} unused driver package(s): {safe} older version(s), "
                                    f"{len(candidates) - safe} for hardware that is not connected.")
        self._update_status("Unused drivers listed.")

    def _remove_unused_drivers(self):
        chosen = checked_payloads(self.unused_tree)
        if not chosen:
            QMessageBox.information(self, "Info", "Tick the drivers to remove first.")
            return
        if not SystemUtils.check_admin_privileges():
            QMessageBox.warning(self, "Administrator Required",
                                "Removing a driver from the driver store needs administrator rights.\n"
                                "Restart the application as administrator.")
            return
        lines = [f"{c.package.original} ({c.package.provider} {c.package.version}): {c.reason}" for c in chosen]
        text = (f"Remove {count(len(chosen), 'driver package')} from Windows?\n\n" + listed(lines)
                + f"\n\nA copy of each is saved in:\n{driver_cleanup.backup_dir()}\n"
                  "To put one back: pnputil /add-driver <saved folder>\\*.inf /install")
        if not self._confirm("Remove drivers", text, "\n".join(lines) if len(lines) > 10 else ""):
            return
        stopped = self.stop_flag.is_set
        self._start_call("driver_remove_worker",
                         lambda: driver_cleanup.remove_packages(chosen, driver_cleanup.backup_dir(), stop=stopped),
                         self._on_unused_drivers_removed, self.unused_remove_btn, "Removing the drivers...")

    def _on_unused_drivers_removed(self, result, error):
        if error:
            QMessageBox.warning(self, "Error", plain(f"The removal failed: {error}"))
            return
        remove_rows(self.unused_tree, result.removed)
        self.unused_summary.setText(f"{len(result.removed)} driver package(s) removed, {len(result.backups)} saved copy(ies). "
                                    f"{self.unused_tree.topLevelItemCount()} left in the list.")
        self._update_status(f"{len(result.removed)} driver(s) removed.")
        if result.failed:
            lines = [f"{c.package.original}: {why}" for c, why in result.failed]
            QMessageBox.warning(self, "Not everything was removed",
                                plain(f"{count(len(result.failed), 'driver')} could not be removed:\n\n" + listed(lines)))

    def _open_driver_backups(self):
        folder = driver_cleanup.backup_dir()
        os.makedirs(folder, exist_ok=True)
        self._update_status(locations.reveal(folder) or "Backups folder opened.")

    # endregion

    # region Uninstall drivers (complete)

    UNINSTALL_COLUMNS = ["Driver", "Published", "Class", "Provider", "Version", "Risk", "Why"]
    STATUS_COLORS = {"Danger": QColor(Qt.GlobalColor.red), "Locked": QColor(Qt.GlobalColor.gray),
                     "Safe": QColor(Qt.GlobalColor.darkGreen)}

    def _create_uninstall_drivers_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        info = QLabel("Complete uninstall of a third-party driver, even one a connected device uses: a copy is saved, a "
                      "restore point is created, the driver is removed from the devices and from the driver store, and "
                      "the service and file it leaves behind are offered for removal.")
        info.setWordWrap(True)
        layout.addWidget(info)
        row = QHBoxLayout()
        self.uninstall_scan_btn = primary(QPushButton("🔍 List all drivers"))
        self.uninstall_scan_btn.setToolTip("Every third-party driver package and what uses it (read-only)")
        self.uninstall_scan_btn.clicked.connect(self._scan_all_drivers)
        self.uninstall_unused_cb = QCheckBox("Only unused")
        self.uninstall_unused_cb.toggled.connect(self._fill_uninstall_tree)
        select_unused = QPushButton("Tick the unused")
        select_unused.clicked.connect(self._tick_unused_drivers)
        select_none = QPushButton("Untick all")
        select_none.clicked.connect(lambda: set_all_checked(self.uninstall_tree, False))
        open_btn = QPushButton("📂 Open location")
        open_btn.clicked.connect(lambda: self._open_selected_location("uninstall_tree"))
        backups_btn = QPushButton("📂 Backups")
        backups_btn.setToolTip("Folder of the driver copies saved before each removal")
        backups_btn.clicked.connect(self._open_driver_backups)
        self.uninstall_btn = QPushButton("🗑 Uninstall completely...")
        self.uninstall_btn.clicked.connect(self._uninstall_drivers_completely)
        for widget in (self.uninstall_scan_btn, self.uninstall_unused_cb, select_unused, select_none, open_btn, backups_btn):
            row.addWidget(widget)
        row.addStretch()
        row.addWidget(self.uninstall_btn)
        layout.addLayout(row)
        self.uninstall_summary = QLabel("Not listed yet. Nothing is changed by the listing.")
        self.uninstall_summary.setWordWrap(True)
        layout.addWidget(self.uninstall_summary)
        self.uninstall_tree = make_tree(self.UNINSTALL_COLUMNS, (220, 80, 170, 200, 110, 70, 420),
                                        "List all drivers to fill this list.")
        layout.addWidget(self.uninstall_tree)
        note = QLabel("ℹ️ Danger: a connected device uses the driver now. Removing it makes the device fall back to a "
                      "generic Windows driver or stop working until a driver is installed again (a network or display "
                      "driver can cut your connection or screen resolution). Locked: core drivers, never removed here. "
                      "To undo: restore point, or pnputil /add-driver on the saved copy.")
        note.setWordWrap(True)
        note.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(note)
        self.all_driver_candidates = []
        return page

    def _scan_all_drivers(self):
        self._start_call("driver_all_worker", driver_cleanup.scan_all, self._on_all_drivers_scanned,
                         self.uninstall_scan_btn, "Listing the drivers and what uses them...")

    def _on_all_drivers_scanned(self, candidates, error):
        if error:
            QMessageBox.warning(self, "Error", plain(f"The drivers could not be listed: {error}"))
            return
        self.all_driver_candidates = list(candidates)
        self._fill_uninstall_tree()
        self._update_status("Drivers listed.")

    def _fill_uninstall_tree(self):
        tree = self.uninstall_tree
        only_unused = self.uninstall_unused_cb.isChecked()
        ticked = {id(c) for c in checked_payloads(tree)}  # "Only unused" must not lose what is already ticked
        tree.setSortingEnabled(False)
        tree.clear()
        for c in self.all_driver_candidates:
            if only_unused and (c.in_use or not c.removable):
                continue
            p = c.package
            item = SortableItem([p.original, p.published, p.class_name, p.provider, p.version, c.risk, c.reason])
            item.setData(0, Qt.ItemDataRole.UserRole, c)
            item.setToolTip(6, plain(c.reason))
            color = self.STATUS_COLORS.get(c.risk)
            if color:
                for column in range(len(self.UNINSTALL_COLUMNS)):
                    item.setForeground(column, color)
            if c.removable:
                checkable(item, id(c) in ticked)
            else:
                not_checkable(item)
            tree.addTopLevelItem(item)
        tree.setSortingEnabled(True)
        used = sum(1 for c in self.all_driver_candidates if c.in_use)
        locked = sum(1 for c in self.all_driver_candidates if not c.removable)
        self.uninstall_summary.setText(f"{len(self.all_driver_candidates)} third-party driver package(s): {used} in use, "
                                       f"{locked} locked, {len(self.all_driver_candidates) - used - locked} unused.")

    def _tick_unused_drivers(self):
        for i in range(self.uninstall_tree.topLevelItemCount()):
            item = self.uninstall_tree.topLevelItem(i)
            candidate = item.data(0, Qt.ItemDataRole.UserRole)
            if item.flags() & Qt.ItemFlag.ItemIsUserCheckable:
                item.setCheckState(0, Qt.CheckState.Checked if candidate.removable and not candidate.in_use
                                   else Qt.CheckState.Unchecked)

    def _uninstall_drivers_completely(self):
        chosen = checked_payloads(self.uninstall_tree)
        if not chosen:
            QMessageBox.information(self, "Info", "Tick the drivers to uninstall first.")
            return
        if not SystemUtils.check_admin_privileges():
            QMessageBox.warning(self, "Administrator Required",
                                "Uninstalling a driver needs administrator rights.\n"
                                "Restart the application as administrator.")
            return
        in_use = [c for c in chosen if c.in_use]
        lines = [f"{c.package.original} ({c.package.provider} {c.package.version}): {c.reason}" for c in chosen]
        text = f"Uninstall {count(len(chosen), 'driver package')} completely?\n\n" + listed(lines)
        if in_use:
            text += (f"\n\n{len(in_use)} of them are IN USE by connected devices. Those devices will fall back to a generic "
                     "driver or stop working until a driver is installed again. A restore point is created first, and a "
                     "restart is recommended afterwards.")
        text += (f"\n\nA copy of each driver is saved in:\n{driver_cleanup.backup_dir()}\n"
                 "The service and file a driver leaves behind are listed afterwards: you decide about those separately.")
        if not self._confirm("Uninstall drivers", text, "\n".join(lines) if len(lines) > 10 else ""):
            return
        if not in_use:
            self._run_driver_uninstall(chosen)
            return
        engine = self.hardening_engine

        def restore_point():
            ok = engine.create_restore_point("DD Cleaner - driver removal")
            return ok, engine.last_restore_point_message
        self._start_call("driver_restore_worker", restore_point,
                         lambda result, error: self._on_driver_restore_point(chosen, result, error),
                         self.uninstall_btn, "Creating a restore point...")

    def _on_driver_restore_point(self, chosen, result, error):
        ok, message = (False, error) if error or result is None else result
        if not ok:
            if not self._confirm("No restore point",
                                 f"A restore point could not be created:\n{message}\n\nUninstall the drivers anyway? "
                                 "(A copy of each driver is still saved.)"):
                self._update_status("Driver uninstall cancelled: no restore point.")
                return
        self._run_driver_uninstall(chosen)

    def _run_driver_uninstall(self, chosen):
        remaining = [c.package for c in self.all_driver_candidates]
        stopped = self.stop_flag.is_set
        self._start_call(
            "driver_uninstall_worker",
            lambda: driver_uninstall.uninstall_completely(chosen, remaining, driver_cleanup.backup_dir(), stop=stopped),
            self._on_drivers_uninstalled, self.uninstall_btn, "Uninstalling the drivers...")

    def _on_drivers_uninstalled(self, result, error):
        if error:
            QMessageBox.warning(self, "Error", plain(f"The uninstall failed: {error}"))
            return
        gone = {id(c) for c in result.removed}
        self.all_driver_candidates = [c for c in self.all_driver_candidates if id(c) not in gone]
        self._fill_uninstall_tree()
        self._update_status(f"{len(result.removed)} driver(s) uninstalled.")
        notes = []
        if result.failed:
            notes.append(f"{count(len(result.failed), 'driver')} could not be uninstalled:\n" + listed(
                f"{c.package.original}: {why}" for c, why in result.failed))
        if result.ghosts_removed:
            notes.append(f"{count(result.ghosts_removed, 'entry', 'entries')} of devices that are not connected "
                         f"{'was' if result.ghosts_removed == 1 else 'were'} removed too.")
        if result.reboot:
            notes.append("Restart the PC to finish: devices that used these drivers switch to another driver then.")
        if notes:
            QMessageBox.information(self, "Drivers uninstalled", plain("\n\n".join(notes)))
        if result.leftovers:
            self._offer_driver_leftovers(result.leftovers)

    def _offer_driver_leftovers(self, leftovers):
        lines = [f"service {l.service}" + (f"  +  {os.path.basename(l.image)}" if l.file_exists else "  (file already gone)")
                 for l in leftovers]
        if not self._confirm(
                "Leftovers",
                "The uninstalled drivers left these behind:\n\n" + listed(lines, 12)
                + f"\n\nRemove them too? Each service key and file is saved first in:\n{driver_cleanup.backup_dir()}\n"
                  "If Windows still has a file loaded, it is removed after a restart.",
                "\n".join(lines) if len(lines) > 12 else ""):
            return
        stopped = self.stop_flag.is_set
        self._start_call("driver_leftover_worker",
                         lambda: driver_uninstall.remove_leftovers(leftovers, driver_cleanup.backup_dir(), stop=stopped),
                         self._on_driver_leftovers_removed, self.uninstall_btn, "Removing the leftovers...")

    def _on_driver_leftovers_removed(self, result, error):
        if error:
            QMessageBox.warning(self, "Error", plain(f"The leftovers could not be removed: {error}"))
            return
        self._update_status(f"{len(result.removed)} leftover(s) removed.")
        if result.failed:
            QMessageBox.warning(self, "Leftovers", plain(f"{count(len(result.failed), 'leftover')} need attention:\n\n"
                                                         + listed(f"{l.service}: {why}" for l, why in result.failed)))

    # endregion
