"""Gives every list of the program an 'Open location' right-click menu, and one shared way to use it from a button."""

import os
from typing import Callable, Dict, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMessageBox, QTreeWidget, QTreeWidgetItem

from ddcleaner import driver_cleanup
from ddcleaner.common import SYSTEM_ROOT
from ddcleaner.ui import locations
from ddcleaner.ui.locations import Place

ROLE = Qt.ItemDataRole.UserRole


def _payload(item: QTreeWidgetItem):
    return item.data(0, ROLE)


def place_for_path(path: str) -> Place:
    return Place(path=path) if path else Place()


def place_for_text(text: str) -> Place:
    """A registry location when the text is one, else nothing."""
    return locations.parse_registry(text) or Place()


def process_place(item) -> Place:
    return place_for_path(getattr(_payload(item), "path", ""))


def finding_place(item) -> Place:
    finding = _payload(item)
    if finding is None:
        return Place()
    if getattr(finding, "path", "") and os.path.exists(finding.path):
        return Place(path=finding.path)
    registry = locations.parse_registry(getattr(finding, "location", ""))
    if registry:
        return registry
    where = getattr(finding, "location", "")
    if where and os.path.isabs(where) and os.path.exists(where):
        return Place(path=where)                       # a browser extension folder
    return place_for_path(getattr(finding, "path", ""))


def startup_place(item) -> Place:
    entry = _payload(item)
    if entry is None:
        return Place()
    if getattr(entry, "path", "") and os.path.exists(entry.path):
        return Place(path=entry.path)
    if getattr(entry, "kind", "") == "Registry":
        registry = locations.parse_registry(entry.location)
        if registry:
            return registry
    return place_for_path(getattr(entry, "path", ""))


def program_place(item) -> Place:
    return place_for_path(getattr(_payload(item), "location", ""))


def garbage_place(item) -> Place:
    return place_for_path(getattr(_payload(item), "path", ""))


def registry_place(item) -> Place:
    entry = _payload(item)
    return Place(hive=entry.hive, key=entry.key) if entry is not None else Place()


def text_place(column: int) -> Callable[[QTreeWidgetItem], Place]:
    return lambda item: place_for_path(item.text(column))


def quarantine_place(item) -> Place:
    return place_for_path(getattr(_payload(item), "stored", ""))


def unused_driver_place(item) -> Place:
    candidate = _payload(item)
    return place_for_path(driver_cleanup.store_folder(candidate.package.original)) if candidate is not None else Place()


def inf_place(item) -> Place:
    """A driver listed by its INF name (oem12.inf): the copy Windows keeps in C:\\Windows\\INF."""
    name = item.text(4)
    path = os.path.join(SYSTEM_ROOT, "INF", name) if name and os.path.basename(name) == name else name
    return place_for_path(path)


def vt_place(item) -> Place:
    return place_for_path(getattr(_payload(item), "path", ""))


class LocationsMixin:
    """Mixed into MainWindow. _attach_locations() runs once every tab exists."""

    def _location_targets(self) -> Dict[str, Callable]:
        return {"process_tree": process_place, "hunt_tree": finding_place, "startup_tree": startup_place,
                "program_tree": program_place, "garbage_tree": garbage_place, "registry_tree": registry_place,
                "clam_threat_tree": text_place(0), "clam_quarantine_tree": quarantine_place,
                "unused_tree": unused_driver_place, "uninstall_tree": unused_driver_place}

    def _attach_locations(self):
        self.location_resolvers: Dict[str, Callable] = {}
        for name, resolver in self._location_targets().items():
            tree: Optional[QTreeWidget] = getattr(self, name, None)
            if tree is not None:
                locations.attach(self, tree, resolver)
                self.location_resolvers[name] = resolver

    def _selected_place(self, tree_name: str) -> Place:
        tree = getattr(self, tree_name, None)
        items = tree.selectedItems() if tree is not None else []
        return self.location_resolvers[tree_name](items[0]) if items else Place()

    def _open_selected_location(self, tree_name: str, prefer_registry: bool = False):
        """Button behind every 'Open location' / 'Open in Regedit': acts on the first selected row."""
        place = self._selected_place(tree_name)
        if place.empty:
            QMessageBox.information(self, "Info", "Select an entry that has a location first.")
            return
        if place.has_key and (prefer_registry or not place.has_path):
            message = locations.open_in_regedit(place.hive, place.key)
        else:
            message = locations.reveal(place.path)
        self._update_status(message or "Location opened.")
