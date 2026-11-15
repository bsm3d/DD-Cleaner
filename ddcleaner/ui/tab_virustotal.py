"""VirusTotal from the Antivirus tab: look suspicious programs up by hash, and send one for analysis after an
explicit confirmation. The logic and the rules about what may be sent are in ddcleaner/virustotal.py."""

import os
from typing import List

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QGroupBox, QTreeWidgetItem, QMessageBox,
    QDialog
)
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QColor, QDesktopServices

from ddcleaner import api_keys, virustotal
from ddcleaner.ui import locations
from ddcleaner.ui.safe_text import plain
from ddcleaner.ui.tab_locations import vt_place
from ddcleaner.ui.tab_system_info import make_tree

MAX_LOOKUPS = 10
VERDICT_COLORS = {2: QColor(Qt.GlobalColor.red), 1: QColor(204, 112, 0), 0: QColor(Qt.GlobalColor.darkGreen)}
RESULT_COLUMNS = ["File", "VirusTotal says", "SHA-256"]


def describe(result: "virustotal.VtResult") -> str:
    if result.error:
        return result.error
    return result.report.verdict if result.report else ""


class VirusTotalMixin:
    """VirusTotal key box and results window. Mixed into MainWindow."""

    # region Key

    def _create_virustotal_box(self) -> QWidget:
        box = QGroupBox("VirusTotal")
        layout = QHBoxLayout(box)
        self.vt_key_status = QLabel()
        prefs = QPushButton("⚙ Preferences...")
        prefs.setToolTip("File > Preferences: save, test or remove the VirusTotal API key")
        prefs.clicked.connect(self._open_preferences)
        layout.addWidget(self.vt_key_status, 1)
        layout.addWidget(prefs)
        self._refresh_vt_key_status()
        return box

    def _refresh_vt_key_status(self):
        has_key = bool(virustotal.load_key())
        self.vt_key_status.setText("VirusTotal key: " + api_keys.status(api_keys.VIRUSTOTAL.id).lower()
                                   + ". Looking up sends only a file's hash; sending a file is always confirmed.")
        self.vt_key_status.setStyleSheet("color: darkgreen;" if has_key else "color: #b35900;")

    # endregion

    # region Look up

    def _virustotal_check(self, paths: List[str]):
        paths = sorted({p for p in paths if p and os.path.isfile(p)}, key=str.lower)
        if not paths:
            QMessageBox.information(self, "Info", "There is no program file to look up.")
            return
        key = virustotal.load_key()
        if not key:
            QMessageBox.information(self, "VirusTotal", "Save your VirusTotal API key first: the Preferences window opens.")
            self._open_preferences()
            return
        if len(paths) > MAX_LOOKUPS:
            QMessageBox.information(self, "Info", f"Only the first {MAX_LOOKUPS} files are looked up at once "
                                                  "(the free key allows 4 requests per minute).")
            paths = paths[:MAX_LOOKUPS]
        stopped = self._stopper("vt_worker")
        self._start_call("vt_worker", lambda: virustotal.check_files(paths, key, progress=self._update_status, stop=stopped),
                         self._on_vt_checked, None, "Looking up on VirusTotal...")

    def _on_vt_checked(self, results, error):
        if error:
            QMessageBox.warning(self, "VirusTotal", plain(f"The lookup failed: {error}"))
            return
        self._update_status("VirusTotal lookup done.")
        self._show_vt_results(results)

    def _show_vt_results(self, results: list):
        dialog = QDialog(self)
        dialog.setWindowTitle("VirusTotal")
        dialog.resize(1000, 380)
        layout = QVBoxLayout(dialog)
        tree = make_tree(RESULT_COLUMNS, (330, 330, 520))
        self.vt_tree = tree
        locations.attach(self, tree, vt_place)
        for result in results:
            item = QTreeWidgetItem(["", "", ""])
            item.setData(0, Qt.ItemDataRole.UserRole, result)
            tree.addTopLevelItem(item)
            self._refresh_vt_row(item)
        layout.addWidget(tree)
        self.vt_note = QLabel("Select an unknown file and use \"Send for analysis\" to have it analysed.")
        self.vt_note.setWordWrap(True)
        layout.addWidget(self.vt_note)
        row = QHBoxLayout()
        self.vt_send_btn = QPushButton("📤 Send selected file for analysis...")
        self.vt_send_btn.clicked.connect(self._send_vt_selected)
        open_btn = QPushButton("🌐 Open report")
        open_btn.clicked.connect(self._open_vt_report)
        close = QPushButton("Close")
        close.clicked.connect(dialog.close)
        row.addWidget(self.vt_send_btn)
        row.addWidget(open_btn)
        row.addStretch()
        row.addWidget(close)
        layout.addLayout(row)
        self._set_dialog_default(dialog, close)  # Enter must never be "Send for analysis"
        dialog.exec()
        dialog.deleteLater()

    def _refresh_vt_row(self, item: QTreeWidgetItem):
        result = item.data(0, Qt.ItemDataRole.UserRole)
        item.setText(0, os.path.basename(result.path))
        item.setToolTip(0, plain(result.path))
        item.setText(1, describe(result))
        item.setText(2, result.sha256)
        severity = result.report.severity if result.report and not result.error else -1
        for column in range(3):
            item.setForeground(column, VERDICT_COLORS.get(severity, QColor(Qt.GlobalColor.gray)))

    def _selected_vt_item(self):
        items = self.vt_tree.selectedItems()
        return items[0] if items else None

    def _open_vt_report(self):
        item = self._selected_vt_item()
        result = item.data(0, Qt.ItemDataRole.UserRole) if item else None
        if result is None or not result.report or not result.report.found:
            QMessageBox.information(self, "Info", "Select a file that VirusTotal knows.")
            return
        QDesktopServices.openUrl(QUrl(result.report.link))

    # endregion

    # region Send for analysis

    def _send_vt_selected(self):
        item = self._selected_vt_item()
        result = item.data(0, Qt.ItemDataRole.UserRole) if item else None
        if result is None:
            QMessageBox.information(self, "Info", "Select a file first.")
            return
        if result.report is not None and result.report.found:
            QMessageBox.information(self, "Info", "VirusTotal already knows this file: open its report instead.")
            return
        problem = virustotal.upload_problem(result.path)
        if problem:
            QMessageBox.warning(self, "VirusTotal", plain(problem))
            return
        key = virustotal.load_key()
        if not key:
            QMessageBox.warning(self, "VirusTotal", "No API key saved.")
            return
        size = os.path.getsize(result.path)
        warning = virustotal.upload_warning(result.path)
        text = (f"Send this file to VirusTotal?\n\n{result.path}\n{size:,} bytes\nSHA-256 {result.sha256}\n\n"
                "VirusTotal will share it with security companies and researchers. This cannot be undone."
                + (f"\n\n{warning}" if warning else ""))
        if not self._confirm("Send to VirusTotal", text):
            return
        stopped = self._stopper("vt_worker")
        self.vt_send_btn.setEnabled(False)
        started = self._start_call(
            "vt_worker", lambda: virustotal.submit_file(result.path, key, progress=self._update_status, stop=stopped),
            lambda sent, error: self._on_vt_sent(item, sent, error), None, "Sending to VirusTotal...")
        if not started:
            self.vt_send_btn.setEnabled(True)

    def _on_vt_sent(self, item: QTreeWidgetItem, sent, error):
        self.vt_send_btn.setEnabled(True)
        if error or sent is None:
            QMessageBox.warning(self, "VirusTotal", plain(f"The analysis failed: {error}"))
            return
        item.setData(0, Qt.ItemDataRole.UserRole, sent)
        self._refresh_vt_row(item)
        self.vt_note.setText(plain(describe(sent)))
        self._update_status("VirusTotal analysis: " + describe(sent))

    # endregion
