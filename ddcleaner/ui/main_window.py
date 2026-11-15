"""Main window: layout, menus, logs, cross-thread plumbing, shutdown."""

import ctypes
import sys
import os
import subprocess
import threading
import logging
from datetime import datetime
from typing import List, Dict, Optional

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QPushButton, QLabel,
    QProgressBar, QMessageBox, QDialog, QTextEdit, QSizePolicy, QCheckBox, QComboBox, QSpinBox, QTreeWidget,
    QLineEdit
)
from PySide6.QtCore import Qt, QThread, Signal, QSettings
from PySide6.QtGui import QAction, QKeySequence, QShortcut

from security_audit import SecurityAuditor, HardeningEngine
from ddcleaner import folder_security
from ddcleaner.common import winreg, app_dir, data_dir, sys_exe, SYSTEM32, safe_environment, SUBPROCESS_FLAGS, UnsafeFolderError
from ddcleaner.system_utils import SystemUtils
from ddcleaner.ui.dialog_prefs import PreferencesMixin
from ddcleaner.ui.tab_antivirus import AntivirusTabMixin
from ddcleaner.ui.tab_cleanup import CleanupTabMixin
from ddcleaner.ui.tab_drivers import DriversTabMixin
from ddcleaner.ui.tab_hunt import HuntTabMixin
from ddcleaner.ui.tab_locations import LocationsMixin
from ddcleaner.ui.tab_virustotal import VirusTotalMixin
from ddcleaner.ui.tab_health import HealthTabMixin
from ddcleaner.ui.tab_network import NetworkTabMixin
from ddcleaner.ui.tab_system_info import SystemInfoTabMixin
from ddcleaner.ui.tab_security import SecurityTabMixin
from ddcleaner.ui.safe_text import plain


MAIN_WINDOW_SIZE = (1200, 800)
WORKER_ATTRS = ("driver_scan_worker", "vuln_scan_worker", "blocklist_download_worker", "dism_worker",
                "health_worker", "net_worker", "security_audit_worker", "hardening_apply_worker",
                "hardening_revert_worker", "clam_scan_worker", "clam_update_worker", "startup_worker", "load_worker",
                "inventory_worker", "secrets_worker", "geoip_worker", "garbage_file_worker", "garbage_reg_worker",
                "garbage_delete_worker", "hunt_process_worker", "hunt_persistence_worker",
                "vt_worker", "prefs_test_worker", "hunt_remove_worker", "garbage_usage_worker",
                "driver_unused_worker", "driver_remove_worker", "driver_all_worker", "driver_restore_worker",
                "driver_uninstall_worker", "driver_leftover_worker", "yara_rule_worker")


# What the "still running" question calls an operation (anything else: its internal name, made readable)
OPERATION_LABELS = {"dism_worker": "System repair (SFC / DISM)", "clam_scan_worker": "ClamAV scan",
                    "clam_update_worker": "Signature update", "vt_worker": "VirusTotal",
                    "net_worker": "Firewall and network analysis", "hardening": "Advanced tweaks",
                    "hardening_apply_worker": "Hardening profile", "hardening_revert_worker": "Undo of a hardening change",
                    "garbage_file_worker": "Garbage file scan", "garbage_reg_worker": "Garbage registry scan",
                    "garbage_delete_worker": "Garbage deletion", "network_reset": "Network reset"}
LOG_TAIL_BYTES = 512 * 1024
# Options remembered between two runs (checkboxes, lists, numbers). Never the ones that make an action destructive.
STATE_WIDGETS = ("clam_quarantine_cb", "clam_archives_cb", "clam_maxsize_spin", "clam_pua_cb", "clam_thorough_cb",
                 "clam_fast_cb", "clam_cache_cb", "clam_cache_days", "clam_threads_spin", "garbage_where",
                 "garbage_age", "registry_names_cb", "registry_values_cb", "registry_data_cb", "traffic_inbound_cb",
                 "traffic_ports_cb", "traffic_local_cb", "traffic_dns_cb", "traffic_owner_cb", "traffic_group_combo",
                 "net_hide_local_cb", "process_flagged_cb", "hunt_flagged_cb")


def operation_label(name: str) -> str:
    return OPERATION_LABELS.get(name) or name.replace("_worker", "").replace("_", " ").capitalize()


def ui_state_path() -> str:
    return os.path.join(data_dir(), "ui_state.ini")


class BusyBar(QProgressBar):
    """The shared progress bar: it stays on screen until every operation that showed it has hidden it."""

    def __init__(self):
        super().__init__()
        self.active = 0
        self.changed = None  # called with True while something runs

    def setVisible(self, visible: bool):
        self.active = self.active + 1 if visible else max(0, self.active - 1)
        super().setVisible(self.active > 0)
        if self.changed:
            self.changed(self.active > 0)


def logs_dir() -> str:
    return os.path.join(data_dir(), "logs")


def log_file_path() -> str:
    return os.path.join(logs_dir(), f"dd_cleaner_{datetime.now().strftime('%Y%m%d')}.log")


class MainWindow(
    DriversTabMixin,
    HealthTabMixin,
    SystemInfoTabMixin,
    NetworkTabMixin,
    SecurityTabMixin,
    AntivirusTabMixin,
    CleanupTabMixin,
    HuntTabMixin,
    VirusTotalMixin,
    PreferencesMixin,
    LocationsMixin,
    QMainWindow
):
    """Main application window. Each tab lives in its own mixin (ddcleaner/ui/tab_*.py)."""

    # Cross-thread plumbing: widgets must only be touched from the GUI thread
    status_sig = Signal(str)

    ui_call = Signal(object)

    def __init__(self):
        super().__init__()
        self.status_sig.connect(self._set_status_text, Qt.ConnectionType.QueuedConnection)
        self.ui_call.connect(self._run_ui_call, Qt.ConnectionType.QueuedConnection)
        self._bg_threads: Dict[str, threading.Thread] = {}
        self.stop_flag = threading.Event()  # set on shutdown; long background loops check it
        self._cancel_events: Dict[str, threading.Event] = {}  # one per running scan, set by Stop / Esc

        if not SystemUtils.is_windows() or not winreg:
            QMessageBox.critical(self, "Error", "This tool can only function on Windows.")
            sys.exit(1)

        self.is_admin = SystemUtils.check_admin_privileges()
        self.setWindowTitle("DD Cleaner 3.0" + ("" if self.is_admin else " (not administrator)"))
        self.resize(*MAIN_WINDOW_SIZE)

        self.dism_worker = None  # Worker for DISM/system repair commands

        # Security audit modules
        self.security_auditor = SecurityAuditor()
        self.hardening_engine = HardeningEngine()
        self.last_audit_score = 0
        self.last_audit_domains = {}

        self._check_program_folder()
        try:
            data_dir()
        except (UnsafeFolderError, OSError) as e:
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Critical)
            box.setWindowTitle("Unsafe data folder")
            box.setTextFormat(Qt.TextFormat.PlainText)
            box.setText(f"The program's data folder cannot be trusted:\n\n{e}")
            box.exec()
            sys.exit(1)

        self._setup_logging()
        self._setup_ui()
        self._setup_menu()
        self._setup_shortcuts()
        self._restore_ui_state()

    def _check_program_folder(self):
        """An elevated program must live in a folder only administrators can change (DLL planting, tampering)."""
        if not getattr(sys, "frozen", False):
            return  # running from source: the developer's folder
        problems = folder_security.folder_risk(app_dir())
        if not problems:
            return
        logging.warning("Program folder is not protected: " + " ".join(problems))
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Unsafe program folder")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText("This program runs as administrator, but its folder can be changed without administrator "
                    "rights:\n\n" + "\n".join(problems) + "\n\nAny program running under your account could "
                    "place a file there and have it run as administrator, or alter the downloaded lists. Move the "
                    "whole folder to C:\\Program Files\\DD Cleaner (only administrators can change it).")
        box.exec()

    def _setup_logging(self):
        os.makedirs(logs_dir(), exist_ok=True)
        log_file = log_file_path()

        # Check log file size and rotate if needed (limit: 10MB)
        self._rotate_log_if_needed(log_file)

        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def _rotate_log_if_needed(self, log_file: str, max_size_mb: int = 10):
        """Rotate log file if it exceeds size limit.

        Args:
            log_file: Path to log file
            max_size_mb: Maximum size in MB before rotation (default: 10MB)
        """
        try:
            if not os.path.exists(log_file):
                return

            # Check file size
            file_size_mb = os.path.getsize(log_file) / (1024 * 1024)

            if file_size_mb > max_size_mb:
                # Read all lines
                with open(log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()

                # Keep only last 50% of lines (sequential rewrite)
                keep_lines = len(lines) // 2
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.write(f"[LOG ROTATED - File exceeded {max_size_mb}MB, kept last {keep_lines} lines]\n")
                    f.writelines(lines[-keep_lines:])

                logging.info(f"Log file rotated: {log_file} exceeded {max_size_mb}MB, kept last {keep_lines} lines")
        except Exception as e:
            # Don't crash if rotation fails
            print(f"Warning: Log rotation failed: {e}")

    def _setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        self._create_drivers_tab()
        self._create_system_health_tab()
        self._create_network_tab()
        self._create_security_tab()  # Audit, profiles and advanced tweaks in one tab
        self._create_antivirus_tab()  # ClamAV scan, quarantine and signature update
        self._create_cleanup_tab()  # Garbage: wildcard search, leftovers of removed programs, dead registry entries

        # Status bar
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready.")
        # a long status text is cut, it never widens the window (the full text is in the tooltip)
        self.status_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.progress_bar = BusyBar()
        self.progress_bar.setMaximum(0)  # Indeterminate
        self.progress_bar.setMaximumWidth(260)
        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.setToolTip("Stop the running scans (Esc). A deletion or a repair finishes what it started.")
        self.stop_btn.clicked.connect(self._stop_current)
        self.stop_btn.setVisible(False)
        self.progress_bar.changed = self.stop_btn.setVisible
        self.progress_bar.setVisible(False)

        status_layout.addWidget(self.status_label, 1)
        status_layout.addWidget(self.progress_bar)
        status_layout.addWidget(self.stop_btn)
        if not self.is_admin:
            admin_btn = QPushButton("🛡 Restart as administrator")
            admin_btn.setToolTip("Not running as administrator: repairs, removals and some readings are unavailable. "
                                 "Windows asks for confirmation, then the program starts again.")
            admin_btn.clicked.connect(self._restart_as_admin)
            status_layout.addWidget(admin_btn)
        main_layout.addLayout(status_layout)
        self._attach_locations()  # right-click "Open location" on every list

    def _setup_menu(self):
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        prefs_action = QAction("&Preferences...", self)
        prefs_action.setShortcut("Ctrl+,")
        prefs_action.triggered.connect(self._open_preferences)
        file_menu.addAction(prefs_action)
        file_menu.addSeparator()

        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # View menu
        view_menu = menubar.addMenu("&View")

        show_logs_action = QAction("Show &Logs", self)
        show_logs_action.setShortcut("Ctrl+L")
        show_logs_action.triggered.connect(self._show_logs_window)
        view_menu.addAction(show_logs_action)

        # Help menu
        help_menu = menubar.addMenu("&Help")
        about_action = QAction("&About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _show_logs_window(self):
        """Today's log (its last part when it is long). Refresh reads it again."""
        log_dialog = QDialog(self)
        log_dialog.setWindowTitle("DD Cleaner - Logs")
        log_dialog.resize(900, 600)
        layout = QVBoxLayout(log_dialog)

        info_label = QLabel("Today's log: what the program did, warnings and errors. Press Refresh to read it again.")
        info_label.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(info_label)

        log_text = QTextEdit()
        log_text.setReadOnly(True)
        log_text.setStyleSheet("font-family: 'Consolas', 'Courier New', monospace; font-size: 9pt;")
        layout.addWidget(log_text)

        def load_logs():
            log_file = log_file_path()
            try:
                if not os.path.exists(log_file):
                    log_text.setPlainText("No log file found for today.")
                    return
                with open(log_file, "rb") as f:  # only the end: a 10 MB log must not freeze the window
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - LOG_TAIL_BYTES))
                    text = f.read().decode("utf-8", errors="replace")
                if size > LOG_TAIL_BYTES:
                    text = "[earlier lines are in the file]\n" + text.split("\n", 1)[-1]
                log_text.setPlainText(text)
                cursor = log_text.textCursor()
                cursor.movePosition(cursor.MoveOperation.End)
                log_text.setTextCursor(cursor)
            except OSError as e:
                log_text.setPlainText(f"Error reading log file: {e}")

        load_logs()

        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(load_logs)
        open_folder_btn = QPushButton("📂 Open logs folder")
        # absolute path + explorer: a relative "logs" could resolve to a planted logs.exe
        open_folder_btn.clicked.connect(lambda: subprocess.Popen(
            [sys_exe("explorer.exe"), logs_dir()], cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS))
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(log_dialog.close)
        btn_layout.addWidget(refresh_btn)
        btn_layout.addWidget(open_folder_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        self._set_dialog_default(log_dialog, close_btn)

        log_dialog.exec()
        log_dialog.deleteLater()  # free the dialog and its (possibly large) log text

    def _update_status(self, message: str):
        """Update status label from any thread (worker threads go through a queued signal)."""
        if QThread.currentThread() is not self.thread():
            self.status_sig.emit(message)
            return
        self._set_status_text(message)

    def _set_status_text(self, message: str):
        self.status_label.setText(message)
        self.status_label.setToolTip(plain(message))

    # region Shared dialogs, stop and shortcuts

    def _confirm(self, title: str, text: str, details: str = "") -> bool:
        """Yes / No question whose default is always No: a reflex Enter never deletes or changes anything.
        details: the full list, behind the box's "Show Details" button."""
        yes, no = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No
        if not details:
            return QMessageBox.question(self, title, plain(text), yes | no, no) == yes
        box = QMessageBox(QMessageBox.Icon.Question, title, plain(text), yes | no, self)
        box.setDefaultButton(no)
        box.setDetailedText(details)
        return box.exec() == yes

    @staticmethod
    def _set_dialog_default(dialog: QDialog, default: Optional[QPushButton] = None):
        """Qt makes the first button of a dialog the one Enter presses. Only `default` may be (none if None)."""
        for button in dialog.findChildren(QPushButton):
            button.setAutoDefault(False)
            button.setDefault(False)
        if default is not None:
            default.setDefault(True)

    def _stopper(self, name: str):
        """A 'should I stop?' function for one scan: true when the program closes or Stop / Esc is used."""
        event = threading.Event()
        self._cancel_events[name] = event
        return lambda: self.stop_flag.is_set() or event.is_set()

    def _stop_current(self):
        """Stop button of the status bar and Esc: ask every running scan to stop."""
        if not self.progress_bar.active:
            return
        for event in self._cancel_events.values():
            event.set()
        self._stop_garbage_scan()
        self._stop_clam_scan()
        self._update_status("Stopping...")

    def _setup_shortcuts(self):
        for keys, slot in (("F5", self._shortcut_run), ("Esc", self._stop_current), ("Ctrl+F", self._shortcut_filter)):
            QShortcut(QKeySequence(keys), self, slot)

    def _visible_marked(self, kind, mark: str) -> list:
        return [w for w in self.findChildren(kind) if w.property(mark) and w.isVisible() and w.isEnabled()]

    def _shortcut_run(self):
        """F5: the main scan or listing of the page on screen."""
        buttons = self._visible_marked(QPushButton, "primary")
        if buttons:
            buttons[0].click()

    def _shortcut_filter(self):
        """Ctrl+F: the filter of the list on screen."""
        fields = self._visible_marked(QLineEdit, "filter")
        if fields:
            fields[0].setFocus()
            fields[0].selectAll()

    def _restart_as_admin(self):
        if self._busy_operations():
            QMessageBox.information(self, "Info", "Wait for the running operation to finish first.")
            return
        if getattr(sys, "frozen", False):
            program, arguments = sys.executable, ""
        else:
            program, arguments = sys.executable, subprocess.list2cmdline([os.path.abspath(sys.argv[0])])
        try:
            started = ctypes.windll.shell32.ShellExecuteW(None, "runas", program, arguments, None, 1) > 32
        except (AttributeError, OSError):
            started = False
        if started:
            self.close()
        else:
            self._update_status("Not restarted: the Windows confirmation was refused.")

    # endregion

    # region Remembered interface state

    def _state_widgets(self) -> Dict[str, QWidget]:
        named = {name: getattr(self, name) for name in STATE_WIDGETS if hasattr(self, name)}
        named.update({name: w for name, w in vars(self).items() if isinstance(w, (QTabWidget, QTreeWidget))})
        return named

    def _save_ui_state(self):
        """Window size, pages on screen, column widths and scan options, for the next run."""
        try:
            settings = QSettings(ui_state_path(), QSettings.Format.IniFormat)
            settings.setValue("window/geometry", self.saveGeometry())
            settings.setValue("garbage/custom_root", self.garbage_custom_root)
            for name, widget in self._state_widgets().items():
                try:
                    if isinstance(widget, QTreeWidget):
                        settings.setValue(f"columns/{name}", widget.header().saveState())
                        settings.setValue(f"columns/{name}_count", widget.columnCount())
                    elif isinstance(widget, QTabWidget):
                        settings.setValue(f"pages/{name}", widget.currentIndex())
                    elif isinstance(widget, QCheckBox):
                        settings.setValue(f"options/{name}", widget.isChecked())
                    elif isinstance(widget, QComboBox):
                        settings.setValue(f"options/{name}", widget.currentIndex())
                    elif isinstance(widget, QSpinBox):
                        settings.setValue(f"options/{name}", widget.value())
                except RuntimeError:
                    continue  # a list of a dialog that is closed
            settings.sync()
        except (OSError, UnsafeFolderError) as e:
            logging.warning(f"Interface state not saved: {e}")

    def _restore_ui_state(self):
        try:
            path = ui_state_path()
            if not os.path.isfile(path):
                return
            settings = QSettings(path, QSettings.Format.IniFormat)
        except (OSError, UnsafeFolderError):
            return
        geometry = settings.value("window/geometry")
        if geometry:
            self.restoreGeometry(geometry)
        root = settings.value("garbage/custom_root", "", type=str)
        if root and os.path.isdir(root):
            self.garbage_custom_root = root
            self.garbage_where.setItemText(self.garbage_where.count() - 1, f"Folder: {root}")
        for name, widget in self._state_widgets().items():
            try:
                if isinstance(widget, QTreeWidget):
                    state = settings.value(f"columns/{name}")
                    if state and settings.value(f"columns/{name}_count", 0, type=int) == widget.columnCount():
                        widget.header().restoreState(state)
                    continue
                key = f"pages/{name}" if isinstance(widget, QTabWidget) else f"options/{name}"
                if not settings.contains(key):
                    continue
                if isinstance(widget, QCheckBox):
                    widget.setChecked(settings.value(key, type=bool))
                elif isinstance(widget, QSpinBox):
                    widget.setValue(settings.value(key, type=int))
                else:
                    index = settings.value(key, type=int)
                    if 0 <= index < widget.count():
                        widget.setCurrentIndex(index)
            except (RuntimeError, TypeError, ValueError):
                continue
        if self.garbage_where.currentIndex() == self.garbage_where.count() - 1 and not self.garbage_custom_root:
            self.garbage_where.setCurrentIndex(0)  # "Choose a folder..." without a folder: back to the default

    # endregion

    def _run_ui_call(self, fn):
        try:
            fn()
        except Exception as e:
            logging.error(f"UI update failed: {e}")

    def _ui(self, fn):
        """Run fn on the GUI thread (safe to call from any thread)."""
        self.ui_call.emit(fn)

    def _start_bg_thread(self, name: str, target) -> bool:
        """Start a tracked background thread; refuse if one with that name is still running."""
        running = self._bg_threads.get(name)
        if running and running.is_alive():
            QMessageBox.information(self, "Info", "This operation is already running.")
            return False
        t = threading.Thread(target=target, name=name, daemon=True)
        self._bg_threads[name] = t
        t.start()
        return True

    def _busy_operations(self) -> List[str]:
        busy = [n for n, t in self._bg_threads.items() if t.is_alive()]
        for attr in WORKER_ATTRS:
            w = getattr(self, attr, None)
            if w is not None and w.isRunning():
                busy.append(attr)
        return busy

    def _show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About DD Cleaner",
            "DD Cleaner 3.0\n\n"
            "Benoit (BSM) Saint-Moulin\n\n"
            "Driver scan, system health and security audit for Windows\n\n"
            "Features:\n"
            "• Vulnerable driver check (Microsoft blocklist)\n"
            "• Third-party driver age\n"
            "• System health report and repair (SFC, DISM)\n"
            "• Firewall and network analysis\n"
            "• Security audit and hardening\n"
            "• Antivirus scan and quarantine (ClamAV, installed separately)\n"
            "• Garbage finder: wildcard search, leftovers of removed programs, dead registry entries\n"
            "• Free and Open-Source"
        )

    def closeEvent(self, event):
        """Handle window close event - stop workers cleanly before quitting."""
        busy = self._busy_operations()
        if busy:
            names = sorted({operation_label(name) for name in busy})
            if not self._confirm("Operation in progress",
                                 "Still running:\n  " + "\n  ".join(names) + "\n\nStop and quit?"):
                event.ignore()
                return
            if not self._stop_all_workers():
                self.stop_flag.clear()  # closing is aborted: later scans must not see a stale stop request
                QMessageBox.warning(self, "Still running",
                                    "An operation did not stop in time. Please wait a moment and close again.")
                event.ignore()
                return
        self.clear_secret_clipboard()  # a copied password must not outlive the program
        # live traffic sampling is not an "operation": stop it silently
        self._stop_traffic()
        self.protection_timer.stop()
        for attr in ("traffic_worker", "watch_poll_worker"):  # short background reads, not "operations"
            worker = getattr(self, attr, None)
            if worker is not None and worker.isRunning():
                worker.wait(3000)
        self._save_ui_state()
        event.accept()

    def _stop_all_workers(self, timeout_ms: int = 15000) -> bool:
        """Signal every worker to stop and wait for it. False if something is still running."""
        self.stop_flag.set()
        if self.dism_worker and self.dism_worker.isRunning():
            self.dism_worker.kill()
        for attr in ("clam_scan_worker", "clam_update_worker"):
            w = getattr(self, attr, None)
            if w is not None and w.isRunning():
                w.stop()  # kills clamscan / freshclam

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            for attr in WORKER_ATTRS:
                w = getattr(self, attr, None)
                if w is not None and w.isRunning():
                    w.wait(timeout_ms)
            # Plain threads run short system commands (each with its own timeout)
            for t in self._bg_threads.values():
                if t.is_alive():
                    t.join(timeout_ms / 1000)
            # deliver the lines a stopped scan already queued (the quarantine list is written from them)
            QApplication.processEvents()
        finally:
            QApplication.restoreOverrideCursor()
        return not self._busy_operations()
