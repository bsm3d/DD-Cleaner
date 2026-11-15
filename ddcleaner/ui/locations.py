"""'Open location' for any entry: a file or folder in Explorer, a registry key in Regedit, or its path copied.

One place knows how, so every list of the program offers the same right-click menu.
"""

import os
import re
import subprocess
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import QApplication, QMenu, QTreeWidget, QTreeWidgetItem

from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM32, safe_environment, sys_exe, winreg

FULL_HIVES = {"HKLM": "HKEY_LOCAL_MACHINE", "HKCU": "HKEY_CURRENT_USER"}
LONG_HIVES = {"HKEY_LOCAL_MACHINE": "HKLM", "HKEY_CURRENT_USER": "HKCU", "HKLM": "HKLM", "HKCU": "HKCU"}
REGEDIT_KEY = r"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit"
REGISTRY_TEXT = re.compile(r"^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\(.+?)(\s+\(32-bit\))?(\s+\[.*\])?$")


@dataclass(frozen=True)
class Place:
    path: str = ""                       # a file or a folder
    hive: str = ""                       # HKLM | HKCU
    key: str = ""

    @property
    def has_path(self) -> bool:
        return bool(self.path)

    @property
    def has_key(self) -> bool:
        return bool(self.hive and self.key)

    @property
    def empty(self) -> bool:
        return not (self.has_path or self.has_key)

    @property
    def text(self) -> str:
        return self.path or (f"{self.hive}\\{self.key}" if self.has_key else "")


def parse_registry(text: str) -> Optional[Place]:
    """A Place from 'HKLM\\SOFTWARE\\...\\Run (32-bit)' style text (None when it is not a registry location)."""
    first = (text or "").strip().splitlines()[0] if (text or "").strip() else ""
    match = REGISTRY_TEXT.match(first)
    if not match:
        return None
    hive, key = LONG_HIVES[match.group(1)], match.group(2).rstrip("\\")
    if match.group(3) and key.upper().startswith("SOFTWARE\\") and "WOW6432NODE" not in key.upper():
        key = "SOFTWARE\\WOW6432Node\\" + key[len("SOFTWARE\\"):]
    return Place(hive=hive, key=key)


def nearest_existing_folder(path: str) -> str:
    path = os.path.normpath(path) if path else ""
    while path and not os.path.isdir(path):
        parent = os.path.dirname(path)
        if parent == path:
            return ""
        path = parent
    return path


def reveal(path: str, popen: Callable = subprocess.Popen) -> str:
    """Show a file (selected) or a folder in Explorer. A path that is gone opens its nearest existing folder.
    Returns '' or a note for the status bar."""
    path = (path or "").strip().strip('"')
    if not path:
        return "There is no location for this entry."
    explorer = [sys_exe("explorer.exe")]
    if os.path.isfile(path):
        popen(explorer + ["/select,", path], cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)
        return ""
    if os.path.isdir(path):
        popen(explorer + [path], cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)
        return ""
    parent = nearest_existing_folder(os.path.dirname(path))
    if parent:
        popen(explorer + [parent], cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)
        return f"{os.path.basename(path)} no longer exists: its folder was opened."
    return "This location no longer exists."


def open_in_regedit(hive: str, key: str, popen: Callable = subprocess.Popen, reg=winreg) -> str:
    """Open Regedit on a key (Regedit reads its last position from HKCU; a Regedit that is already open must be closed
    first, it ignores a second launch). Returns '' or a message."""
    if hive not in FULL_HIVES or not key:
        return "This is not a registry location."
    try:
        with reg.CreateKey(reg.HKEY_CURRENT_USER, REGEDIT_KEY) as handle:
            reg.SetValueEx(handle, "LastKey", 0, reg.REG_SZ, f"Computer\\{FULL_HIVES[hive]}\\{key}")
        popen([sys_exe("regedit.exe")], cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)
    except OSError as e:
        return f"Regedit could not be opened: {e}"
    return "Regedit opened. If it was already open, close it and try again."


def actions_for(place: Place, copy: Callable[[str], None]) -> List[Tuple[str, Callable[[], str]]]:
    """(label, action) for a place: each action returns '' or a status message."""
    actions: List[Tuple[str, Callable[[], str]]] = []
    if place.has_path:
        actions.append(("📂 Open location", lambda: reveal(place.path)))
    if place.has_key:
        actions.append(("🧩 Open in Regedit", lambda: open_in_regedit(place.hive, place.key)))
    if place.text:
        actions.append(("📋 Copy path", lambda: (copy(place.text), "Path copied to the clipboard.")[1]))
    return actions


def rows_text(items: List[QTreeWidgetItem]) -> str:
    """Rows as tab-separated text, one per line (pastes into a spreadsheet or a message)."""
    return "\n".join("\t".join(item.text(c) for c in range(item.columnCount())) for item in items)


def attach(window, tree: QTreeWidget, resolver: Callable[[QTreeWidgetItem], Place]):
    """On a list: right-click menu (Open location, Open in Regedit, Copy path, Copy row), Ctrl+C to copy the selected
    rows, and a double click to open the location, for whatever the resolver says the row is."""
    def copy_rows(items):
        if items:
            QApplication.clipboard().setText(rows_text(items))
            window._update_status(f"{len(items)} row(s) copied to the clipboard.")

    def show(position):
        item = tree.itemAt(position)
        if item is None:
            return
        place = resolver(item)
        menu = QMenu(tree)
        if place is not None and not place.empty:
            for label, action in actions_for(place, QApplication.clipboard().setText):
                menu.addAction(label).triggered.connect(
                    lambda _checked=False, a=action: window._update_status(a() or "Done."))
        selected = tree.selectedItems()
        rows = selected if item in selected else [item]
        menu.addAction("📋 Copy row" if len(rows) == 1 else f"📋 Copy {len(rows)} rows").triggered.connect(
            lambda _checked=False: copy_rows(rows))
        menu.exec(tree.viewport().mapToGlobal(position))

    def open_row(item, column):
        if column == 0 and item.data(0, Qt.ItemDataRole.CheckStateRole) is not None:
            return  # a double click on a checkbox ticks and unticks: it is not a request to open something
        place = resolver(item)
        if place is None or place.empty:
            return
        message = (reveal(place.path) if place.has_path else open_in_regedit(place.hive, place.key))
        window._update_status(message or "Location opened.")

    tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
    tree.customContextMenuRequested.connect(show)
    tree.itemDoubleClicked.connect(open_row)
    shortcut = QShortcut(QKeySequence(QKeySequence.StandardKey.Copy), tree)
    shortcut.setContext(Qt.ShortcutContext.WidgetShortcut)
    shortcut.activated.connect(lambda: copy_rows(tree.selectedItems()))
