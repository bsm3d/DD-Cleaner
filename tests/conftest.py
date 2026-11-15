"""
Shared test setup.

Safety rules for every test in this folder:
  - registry writes only under HKCU\\Software\\DDCleanerSelfTest (removed after each test);
  - file operations only inside pytest's tmp_path;
  - anything that would change the real system (services, restore points, hardening) is mocked.
"""

import os
import sys
import winreg

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

TEST_KEY = r"Software\DDCleanerSelfTest"


def _delete_tree(hive, path):
    """Recursive delete of a test key (tests only; the application never deletes recursively)."""
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
            children = []
            i = 0
            while True:
                try:
                    children.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
        for child in children:
            _delete_tree(hive, f"{path}\\{child}")
        winreg.DeleteKey(hive, path)
    except FileNotFoundError:
        pass


@pytest.fixture
def test_key():
    """Fresh HKCU\\Software\\DDCleanerSelfTest, removed afterwards."""
    _delete_tree(winreg.HKEY_CURRENT_USER, TEST_KEY)
    winreg.CreateKey(winreg.HKEY_CURRENT_USER, TEST_KEY).Close()
    yield TEST_KEY
    _delete_tree(winreg.HKEY_CURRENT_USER, TEST_KEY)


@pytest.fixture(autouse=True)
def ui_state_in_tmp(tmp_path, monkeypatch):
    """The remembered interface state (window size, options) of a test never reaches the project folder
    or the next test."""
    from ddcleaner.ui import main_window
    monkeypatch.setattr(main_window, "ui_state_path", lambda: str(tmp_path / "ui_state.ini"))


@pytest.fixture(scope="session")
def qapp():
    """One QApplication for UI tests (offscreen)."""
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app
