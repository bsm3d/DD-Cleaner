"""File > Preferences: the API keys of the online services. Keys are saved in the protected data folder (api_keys.py)."""

import subprocess

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit, QGroupBox, QMessageBox, QScrollArea, QWidget
)
from PySide6.QtCore import Qt

from ddcleaner import api_keys
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM32, data_dir, safe_environment, sys_exe
from ddcleaner.ui.safe_text import plain

OK_STYLE, BAD_STYLE, NEUTRAL_STYLE = "color: darkgreen;", "color: red;", "color: gray;"


class PreferencesMixin:
    """Preferences window. Mixed into MainWindow."""

    def _open_preferences(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Preferences")
        dialog.resize(700, 560)
        outer = QVBoxLayout(dialog)
        content = QWidget()
        layout = QVBoxLayout(content)
        intro = QLabel("API keys of the online services. A key is kept in the administrators-only data folder, is "
                       "never shown in full or written to the log, and is only sent to its own service.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.prefs_rows = {}
        for provider in api_keys.PROVIDERS:
            layout.addWidget(self._prefs_provider_box(provider))
        folder_box = QGroupBox("Where things are kept")
        folder_layout = QHBoxLayout(folder_box)
        path_label = QLabel(plain(data_dir()))
        path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        open_btn = QPushButton("📂 Open folder")
        open_btn.clicked.connect(self._open_data_folder)
        folder_layout.addWidget(path_label, 1)
        folder_layout.addWidget(open_btn)
        layout.addWidget(folder_box)
        layout.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(content)
        outer.addWidget(scroll)
        row = QHBoxLayout()
        row.addStretch()
        close = QPushButton("Close")
        close.clicked.connect(dialog.close)
        row.addWidget(close)
        outer.addLayout(row)
        self._set_dialog_default(dialog)  # Enter in a key field saves that key, it never presses another button
        dialog.exec()
        dialog.deleteLater()
        self.prefs_rows = {}
        if hasattr(self, "vt_key_status"):
            self._refresh_vt_key_status()

    def _prefs_provider_box(self, provider: "api_keys.Provider") -> QGroupBox:
        box = QGroupBox(provider.label)
        layout = QVBoxLayout(box)
        purpose = QLabel(provider.purpose)
        purpose.setWordWrap(True)
        layout.addWidget(purpose)
        link = QLabel(f'Create a key: <a href="{provider.get_it}">{provider.get_it}</a>')
        link.setOpenExternalLinks(True)
        layout.addWidget(link)
        row = QHBoxLayout()
        edit = QLineEdit()
        edit.setEchoMode(QLineEdit.EchoMode.Password)
        edit.setPlaceholderText(f"Paste the key here ({provider.format_hint})")
        save = QPushButton("Save")
        remove = QPushButton("Remove")
        test = QPushButton("Test")
        test.setToolTip("Ask the service whether it accepts this key (the key is sent to it)")
        for widget in (edit, save, remove, test):
            row.addWidget(widget, 1 if widget is edit else 0)
        layout.addLayout(row)
        status = QLabel()
        layout.addWidget(status)
        self.prefs_rows[provider.id] = {"edit": edit, "status": status, "test": test}
        save.clicked.connect(lambda: self._prefs_save(provider.id))
        edit.returnPressed.connect(lambda: self._prefs_save(provider.id))
        remove.clicked.connect(lambda: self._prefs_remove(provider.id))
        test.clicked.connect(lambda: self._prefs_test(provider.id))
        self._prefs_refresh(provider.id)
        return box

    def _prefs_refresh(self, provider_id: str, message: str = "", style: str = ""):
        row = self.prefs_rows[provider_id]
        saved = bool(api_keys.get(provider_id))
        row["status"].setText(message or api_keys.status(provider_id))
        row["status"].setStyleSheet(style or (OK_STYLE if saved else NEUTRAL_STYLE))

    def _prefs_save(self, provider_id: str):
        row = self.prefs_rows[provider_id]
        key = row["edit"].text().strip()
        if not key:
            QMessageBox.information(self, "Preferences", "Paste the key first. Use Remove to delete a saved key.")
            return
        error = api_keys.set_key(provider_id, key)
        if error:
            self._prefs_refresh(provider_id, error, BAD_STYLE)
            return
        row["edit"].clear()
        self._prefs_refresh(provider_id)

    def _prefs_remove(self, provider_id: str):
        if not api_keys.get(provider_id):
            self.prefs_rows[provider_id]["edit"].clear()
            return
        label = api_keys.provider(provider_id).label
        if not self._confirm("Remove", f"Remove the saved {label} key?"):
            return
        error = api_keys.set_key(provider_id, "")
        self.prefs_rows[provider_id]["edit"].clear()
        self._prefs_refresh(provider_id, error, BAD_STYLE if error else "")

    def _prefs_test(self, provider_id: str):
        row = self.prefs_rows[provider_id]
        key = row["edit"].text().strip() or api_keys.get(provider_id)
        if not key:
            QMessageBox.information(self, "Preferences", "There is no key to test: paste one or save it first.")
            return
        problem = api_keys.validate(provider_id, key)
        if problem:
            self._prefs_refresh(provider_id, problem, BAD_STYLE)
            return
        self._prefs_refresh(provider_id, "Testing...", NEUTRAL_STYLE)

        def done(result, error):
            if provider_id not in getattr(self, "prefs_rows", {}):
                return  # the window was closed meanwhile
            message = error or result
            if message:
                self._prefs_refresh(provider_id, f"Not accepted: {message}", BAD_STYLE)
            else:
                self._prefs_refresh(provider_id, "The service accepted this key.", OK_STYLE)
        started = self._start_call("prefs_test_worker", lambda: api_keys.check_key(provider_id, key), done,
                                   row["test"], "Testing the key...")
        if not started:
            self._prefs_refresh(provider_id)

    def _open_data_folder(self):
        try:
            subprocess.Popen([sys_exe("explorer.exe"), data_dir()], cwd=SYSTEM32, env=safe_environment(),
                             creationflags=SUBPROCESS_FLAGS)
        except OSError as e:
            QMessageBox.warning(self, "Preferences", plain(f"Could not open the folder: {e}"))
