"""System Health tab: health report (read-only) and repair tools (SFC, DISM, network reset)."""

import logging
import platform
import subprocess
from datetime import datetime
from typing import List, Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QGridLayout, QMessageBox, QTextEdit, QTabWidget,
    QTreeWidget, QTreeWidgetItem, QHeaderView, QFileDialog
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from ddcleaner import health
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM32, safe_environment, sys_exe
from ddcleaner.system_utils import SystemUtils
from ddcleaner.workers import DISMWorker, HealthCheckWorker
from ddcleaner.ui.safe_text import plain, csv_cell
from ddcleaner.ui.tab_system_info import primary

STATUS_STYLE = {
    health.OK: ("● OK", QColor(Qt.GlobalColor.darkGreen)),
    health.INFO: ("● Info", QColor(0, 102, 204)),
    health.UNKNOWN: ("● Unknown", QColor(Qt.GlobalColor.gray)),
    health.WARNING: ("● Warning", QColor(255, 140, 0)),
    health.CRITICAL: ("● Critical", QColor(Qt.GlobalColor.red)),
}


def fill_status_tree(tree: QTreeWidget, rows):
    """rows: (status, category, title, details). Worst first, details as child rows."""
    tree.clear()
    for status, category, title, details in sorted(rows, key=lambda r: -health.SEVERITY.get(r[0], 0)):
        text, color = STATUS_STYLE.get(status, STATUS_STYLE[health.UNKNOWN])
        item = QTreeWidgetItem([text, category, title])
        item.setForeground(0, color)
        for line in details:
            if line:
                child = QTreeWidgetItem(["", "", line])
                child.setToolTip(2, plain(line))
                item.addChild(child)
        tree.addTopLevelItem(item)
        # open problems automatically, unless the detail list is long (keeps the other findings visible)
        item.setExpanded(health.SEVERITY.get(status, 0) >= health.SEVERITY[health.WARNING] and len(details) <= 8)


def status_tree() -> QTreeWidget:
    tree = QTreeWidget()
    tree.setHeaderLabels(["Status", "Area", "Finding"])
    tree.setColumnWidth(0, 110)
    tree.setColumnWidth(1, 120)
    tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    tree.header().setStretchLastSection(True)
    tree.setWordWrap(True)
    return tree


def tree_as_text(tree: QTreeWidget) -> str:
    lines = []
    for i in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(i)
        lines.append(f"[{item.text(0).replace('● ', '')}] {item.text(1)}: {item.text(2)}")
        lines += [f"    {item.child(j).text(2)}" for j in range(item.childCount())]
    return "\n".join(lines)


class HealthTabMixin:
    """System Health tab. Mixed into MainWindow."""

    def _create_system_health_tab(self):
        health_tabs = QTabWidget()
        health_tabs.addTab(self._create_health_report_page(), "Health report")
        health_tabs.addTab(self._create_repair_tools_page(), "Repair tools")
        self._add_system_info_pages(health_tabs)  # startup programs, DPC / ISR load, inventory
        self.health_tabs = health_tabs
        self.tab_widget.addTab(health_tabs, "🩺 System Health")

    # region Health report

    def _create_health_report_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        row = QHBoxLayout()
        self.health_check_btn = primary(QPushButton("🩺 Run health check"))
        self.health_check_btn.setToolTip("Disks, free space, crashes, hardware errors, stability (read-only)")
        self.health_check_btn.clicked.connect(self._run_health_check)
        export_btn = QPushButton("💾 Save report")
        export_btn.clicked.connect(self._export_health_report)
        reliability_btn = QPushButton("📈 Reliability history")
        reliability_btn.setToolTip("Open the Windows Reliability Monitor")
        reliability_btn.clicked.connect(lambda: self._open_system_tool(["perfmon.exe", "/rel"]))
        row.addWidget(self.health_check_btn)
        row.addWidget(export_btn)
        row.addWidget(reliability_btn)
        row.addStretch()
        layout.addLayout(row)

        self.health_summary_label = QLabel(f"Checks the last {health.PERIOD_DAYS} days. Nothing is changed.")
        self.health_summary_label.setWordWrap(True)
        layout.addWidget(self.health_summary_label)
        self.health_tree = status_tree()
        layout.addWidget(self.health_tree)
        self.health_items: List[health.HealthItem] = []
        return page

    def _run_health_check(self):
        worker = getattr(self, "health_worker", None)
        if worker is not None and worker.isRunning():
            QMessageBox.information(self, "Info", "The health check is already running.")
            return
        self.health_check_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.health_worker = HealthCheckWorker()
        self.health_worker.progress.connect(self._update_status)
        self.health_worker.done.connect(self._on_health_checked)
        self.health_worker.start()

    def _on_health_checked(self, items: list, error: str):
        self.progress_bar.setVisible(False)
        self.health_check_btn.setEnabled(True)
        if error:
            self._update_status("Health check failed.")
            QMessageBox.warning(self, "Error", plain(f"Health check failed: {error}"))
            return
        self.health_items = items
        fill_status_tree(self.health_tree, [(i.status, i.category, i.title, i.details) for i in items])
        counts = {s: sum(1 for i in items if i.status == s) for s in (health.CRITICAL, health.WARNING)}
        admin = "" if SystemUtils.check_admin_privileges() else "  (not administrator: some disk counters are hidden)"
        self.health_summary_label.setText(
            f"{counts[health.CRITICAL]} critical, {counts[health.WARNING]} warning(s), "
            f"checked {datetime.now().strftime('%Y-%m-%d %H:%M')}{admin}")
        self.health_summary_label.setStyleSheet(
            "color: red; font-weight: bold;" if counts[health.CRITICAL] else
            "color: #cc7000; font-weight: bold;" if counts[health.WARNING] else "color: darkgreen;")
        logging.info(f"Health check: {counts[health.CRITICAL]} critical, {counts[health.WARNING]} warnings")
        self._update_status("Health check done.")

    def _export_health_report(self):
        if not self.health_items:
            QMessageBox.information(self, "Info", "Run the health check first.")
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save health report", f"health_report_{datetime.now().strftime('%Y%m%d')}.txt", "Text (*.txt)")
        if not filename:
            return
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"System health report - {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")
                f.write(tree_as_text(self.health_tree) + "\n")
            self._update_status(f"Report saved to {filename}")
        except OSError as e:
            QMessageBox.critical(self, "Error", f"Could not save the report: {e}")

    def _open_system_tool(self, command: List[str]):
        try:
            subprocess.Popen([sys_exe(command[0])] + command[1:], cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)
        except OSError as e:
            QMessageBox.warning(self, "Error", f"Could not start {command[0]}: {e}")

    # endregion

    # region Repair tools

    def _create_repair_tools_page(self) -> QWidget:
        """SFC, DISM and network reset."""
        health_widget = QWidget()
        layout = QVBoxLayout(health_widget)

        # Info label
        info_label = QLabel("System file and component store repair (administrator required). "
                            "Order when Windows misbehaves: SFC, then DISM RestoreHealth if SFC cannot repair, then SFC again.")
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(info_label)

        # Button grid for DISM/repair commands
        btn_layout = QGridLayout()

        self.sfc_verify_btn = QPushButton("🔍 SFC verify only")
        self.sfc_verify_btn.setToolTip("Check protected system files without repairing (sfc /verifyonly, ~10 min)")
        self.sfc_scan_btn = QPushButton("🛠️ SFC scan and repair...")
        self.sfc_scan_btn.setToolTip("Check and repair protected system files (sfc /scannow, ~10-20 min)")
        self.sfc_verify_btn.clicked.connect(self._run_sfc_verify)
        self.sfc_scan_btn.clicked.connect(self._run_sfc_scannow)

        self.dism_check_btn = QPushButton("🔍 DISM CheckHealth")
        self.dism_check_btn.setToolTip("Quick check for component store corruption (fast)")
        self.dism_scan_btn = QPushButton("🔎 DISM ScanHealth...")
        self.dism_scan_btn.setToolTip("Deep scan for corruption (slow, several minutes)")
        self.dism_restore_btn = QPushButton("🩺 DISM RestoreHealth...")
        self.dism_restore_btn.setToolTip("Attempt to repair component store corruption (very slow)")
        self.dism_cleanup_btn = QPushButton("🧹 Component store cleanup...")
        self.dism_cleanup_btn.setToolTip("Clean up WinSxS folder (reduces disk space)")
        self.net_reset_btn = QPushButton("🌐 Reset network stack...")
        self.net_reset_btn.setToolTip("Reset Winsock, TCP/IP stack, and flush DNS")

        self.dism_check_btn.clicked.connect(self._run_dism_checkhealth)
        self.dism_scan_btn.clicked.connect(self._run_dism_scanhealth)
        self.dism_restore_btn.clicked.connect(self._run_dism_restorehealth)
        self.dism_cleanup_btn.clicked.connect(self._run_dism_cleanup)
        self.net_reset_btn.clicked.connect(self._run_network_reset)

        btn_layout.addWidget(self.sfc_verify_btn, 0, 0)
        btn_layout.addWidget(self.sfc_scan_btn, 0, 1)
        btn_layout.addWidget(self.dism_check_btn, 1, 0)
        btn_layout.addWidget(self.dism_scan_btn, 1, 1)
        btn_layout.addWidget(self.dism_restore_btn, 2, 0)
        btn_layout.addWidget(self.dism_cleanup_btn, 2, 1)
        btn_layout.addWidget(self.net_reset_btn, 3, 0, 1, 2)
        self.repair_buttons = [self.sfc_verify_btn, self.sfc_scan_btn, self.dism_check_btn, self.dism_scan_btn,
                               self.dism_restore_btn, self.dism_cleanup_btn, self.net_reset_btn]

        layout.addLayout(btn_layout)

        # Output text area for DISM/repair logs
        output_row = QHBoxLayout()
        output_label = QLabel("Command output:")
        output_label.setStyleSheet("font-weight: bold;")
        output_row.addWidget(output_label)
        output_row.addStretch()
        self.repair_stop_btn = QPushButton("⏹ Stop...")
        self.repair_stop_btn.setToolTip("Stop the SFC or DISM run in progress")
        self.repair_stop_btn.setEnabled(False)
        self.repair_stop_btn.clicked.connect(self._stop_repair)
        output_row.addWidget(self.repair_stop_btn)
        layout.addLayout(output_row)

        self.dism_output = QTextEdit()
        self.dism_output.setReadOnly(True)
        self.dism_output.setPlaceholderText("SFC, DISM and repair output will appear here...")
        self.dism_output.setStyleSheet("font-family: 'Consolas', 'Courier New', monospace; font-size: 10pt;")
        layout.addWidget(self.dism_output)

        # Warning label
        warning_label = QLabel("⚠️ Repair operations can take a long time: the output above is shown as the tool "
                               "writes it. Some require administrator rights.")
        warning_label.setWordWrap(True)
        warning_label.setStyleSheet("color: #b35900; font-style: italic;")
        layout.addWidget(warning_label)
        return health_widget

    def _run_dism_command(self, args: List[str], description: str):
        """Run DISM /Online /Cleanup-Image with the given arguments."""
        self._run_repair_command([sys_exe("dism.exe"), "/Online", "/Cleanup-Image"] + args, description)

    def _run_sfc_verify(self):
        self._run_repair_command([sys_exe("sfc.exe"), "/verifyonly"], "SFC verify only", encoding="utf-16-le")

    def _run_sfc_scannow(self):
        if self._confirm(
                "SFC scan and repair",
                "SFC /scannow checks every protected system file and replaces damaged ones with the copy from the "
                "component store. It takes 10-20 minutes.\n\nContinue?"):
            self._run_repair_command([sys_exe("sfc.exe"), "/scannow"], "SFC scan and repair", encoding="utf-16-le")

    def _run_repair_command(self, cmd: List[str], description: str, encoding: Optional[str] = None):
        """Run one repair tool (SFC/DISM) in the worker, one at a time."""
        if platform.system() != "Windows":
            QMessageBox.warning(self, "Error", "Repair tools are only available on Windows.")
            return

        # Check if worker is already running
        if self.dism_worker and self.dism_worker.isRunning():
            QMessageBox.information(self, "Info", "A repair operation is already running.")
            return

        # Warn if not admin (but allow continuation)
        if not SystemUtils.check_admin_privileges():
            if not self._confirm("Administrator recommended",
                                 f"{description}\n\nRun without administrator rights? Some operations may fail."):
                return

        self.progress_bar.setVisible(True)
        self._update_status(description)
        self.dism_output.append(f"\n> {' '.join(cmd)}\n")
        self._set_repair_running(True)
        self._repair_streamed = False

        self.dism_worker = DISMWorker(cmd, encoding=encoding)
        self.dism_worker.progress.connect(self._update_status)
        self.dism_worker.output.connect(self._on_dism_output)
        self.dism_worker.finished.connect(self._on_dism_finished)
        self.dism_worker.start()

    def _set_repair_running(self, running: bool):
        """One repair at a time: its buttons are off while it runs, Stop is on only then."""
        for button in self.repair_buttons:
            button.setEnabled(not running)
        self.repair_stop_btn.setEnabled(running)

    def _stop_repair(self):
        worker = self.dism_worker
        if not (worker and worker.isRunning()):
            return
        if self._confirm("Stop the repair", "Stop the tool that is running?\n\nWhat it already repaired is kept, but "
                                            "the check has to be started again from the beginning."):
            worker.kill()
            self._update_status("Stopping the repair tool...")

    def _on_dism_output(self, text: str):
        """Output of the running tool, as it comes."""
        self._repair_streamed = True
        cursor = self.dism_output.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.insertText(text)
        self.dism_output.setTextCursor(cursor)
        self.dism_output.ensureCursorVisible()

    def _on_dism_finished(self, exit_code: int, output: str):
        """Handle DISM operation completion."""
        self.progress_bar.setVisible(False)
        self._set_repair_running(False)
        if not getattr(self, "_repair_streamed", False):
            self.dism_output.append(output)  # nothing was streamed (the tool could not start)
        if self.dism_worker is not None and self.dism_worker.stopped and not self.dism_worker.timed_out:
            self.dism_output.append("\nStopped.\n")
            self._update_status("Repair tool stopped.")
            return

        if exit_code == 0:
            self._update_status("Repair operation completed successfully.")
            QMessageBox.information(self, "Success", "Operation completed successfully.\n\nCheck the output for details.")
        else:
            self._update_status(f"Repair operation ended with exit code {exit_code}.")
            QMessageBox.warning(
                self,
                "Repair tool",
                f"The command ended with exit code {exit_code}.\n\nCheck the output for details "
                "(SFC also returns a non-zero code when it found problems)."
            )

    def _run_dism_checkhealth(self):
        """Run DISM CheckHealth (quick check)."""
        self._run_dism_command(["/CheckHealth"], "DISM CheckHealth (quick)")

    def _run_dism_scanhealth(self):
        """Run DISM ScanHealth (deep scan, may take several minutes)."""
        if self._confirm("DISM ScanHealth", "DISM ScanHealth will perform a deep scan for corruption.\n"
                                            "This may take several minutes.\n\nContinue?"):
            self._run_dism_command(["/ScanHealth"], "DISM ScanHealth (deep scan)")

    def _run_dism_restorehealth(self):
        """Run DISM RestoreHealth (repair, very slow)."""
        if self._confirm("DISM RestoreHealth", "DISM RestoreHealth will attempt to repair the component store.\n"
                                               "This may take a very long time (15-30 minutes or more).\n\nContinue?"):
            self._run_dism_command(["/RestoreHealth"], "DISM RestoreHealth (repair)")

    def _run_dism_cleanup(self):
        """Run DISM component store cleanup."""
        if self._confirm("Component store cleanup",
                         "This will run: DISM /Online /Cleanup-Image /StartComponentCleanup\n\n"
                         "This can reduce WinSxS folder size but might make some updates non-removable.\n\nContinue?"):
            self._run_dism_command(["/StartComponentCleanup"], "Component store cleanup")

    def _run_network_reset(self):
        """Reset network stack (Winsock, TCP/IP, DNS)."""
        if platform.system() != "Windows":
            QMessageBox.warning(self, "Error", "Network reset is only configured for Windows.")
            return

        if not SystemUtils.check_admin_privileges():
            QMessageBox.warning(self, "Administrator Required",
                                "Resetting the network stack needs administrator rights.\n"
                                "Restart the application as administrator.")
            return
        if not self._confirm("Network reset",
                             "This will reset:\n"
                             "• Winsock catalog (netsh winsock reset)\n"
                             "• TCP/IP stack (netsh int ip reset)\n"
                             "• DNS cache (ipconfig /flushdns)\n\n"
                             "You may lose current network connections and need to reboot.\n\nContinue?"):
            return

        # List of commands to run sequentially
        commands = [
            [sys_exe("netsh.exe"), "winsock", "reset"],
            [sys_exe("netsh.exe"), "int", "ip", "reset"],
            [sys_exe("ipconfig.exe"), "/flushdns"],
        ]

        self.dism_output.append("\n> Network reset sequence starting...\n")
        self.progress_bar.setVisible(True)

        def run_sequence():
            """Run network reset commands in sequence (worker thread: no direct widget access)."""
            full_output = []
            for cmd in commands:
                try:
                    self._update_status(f"Running: {' '.join(cmd)}")
                    completed = subprocess.run(cmd, capture_output=True, text=True, shell=False, cwd=SYSTEM32, env=safe_environment(),
                                               timeout=120, creationflags=SUBPROCESS_FLAGS)
                    out = (completed.stdout or "") + "\n" + (completed.stderr or "")
                    full_output.append(f"\n> {' '.join(cmd)}\n{out}\n")
                except Exception as e:
                    full_output.append(f"\nError running {' '.join(cmd)}: {e}\n")

            def finish():
                self.progress_bar.setVisible(False)
                self.net_reset_btn.setEnabled(True)
                self.dism_output.append("\n".join(full_output))
                self._update_status("Network reset sequence completed. A reboot may be required.")
                QMessageBox.information(
                    self,
                    "Network Reset Complete",
                    "Network reset sequence completed.\n\nA reboot is recommended for changes to take full effect."
                )
            self._ui(finish)

        self.net_reset_btn.setEnabled(False)
        if not self._start_bg_thread("network_reset", run_sequence):
            self.progress_bar.setVisible(False)
            self.net_reset_btn.setEnabled(True)

    # endregion
