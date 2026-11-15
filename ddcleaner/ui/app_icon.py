"""The application icon (ddcleaner/data/dd_cleaner.png, drawn by tools/make_icon.py)."""

import os

from PySide6.QtGui import QIcon

APP_ID = "BSM.DDCleaner.3"
ICON_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "dd_cleaner.png")


def load_icon() -> QIcon:
    return QIcon(ICON_PATH)
