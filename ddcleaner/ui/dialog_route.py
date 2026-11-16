"""Route to a destination, shown hop by hop as tracert finds it, and drawn on the world map."""

import ipaddress
from typing import Callable, List, Optional, Tuple

from PySide6.QtWidgets import (
    QApplication, QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTreeWidget, QTreeWidgetItem, QHeaderView
)
from PySide6.QtCore import Qt

from ddcleaner import route
from ddcleaner.ui.safe_text import plain, count
from ddcleaner.workers import CommandWorker

Point = Tuple[int, float, float, str]   # hop number, latitude, longitude, text: what the map draws


def describe_hop_place(address: str, locate: Callable) -> Tuple[str, Optional[object]]:
    """('Local network' / a city / '', its Location) for the address of a router. Lookups are local (DB-IP file)."""
    if not address:
        return "", None
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "", None
    if not ip.is_global:
        return "Local network", None
    location = locate(address)
    return (location.label if location else ""), location


class RouteDialog(QDialog):
    """Not modal: the route also appears on the map behind it while it is being found."""

    def __init__(self, window, address: str, title: str, locate: Callable, on_route: Callable[[List[Point]], None]):
        super().__init__(window)
        self.window_ref, self.address, self.locate, self.on_route = window, address, locate, on_route
        self.setWindowTitle(plain(f"Route to {title}").replace("<p>", "").replace("</p>", "")[:120])
        self.resize(780, 440)
        self.hops: List[route.Hop] = []
        self.points: List[Point] = []
        self.buffer = ""
        self.worker: Optional[CommandWorker] = None
        layout = QVBoxLayout(self)
        self.status = QLabel("Starting the trace...")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Hop", "Address", "Times", "Where"])
        self.tree.setRootIsDecorated(False)
        for column, width in enumerate((50, 240, 220)):
            self.tree.setColumnWidth(column, width)
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        layout.addWidget(self.tree)
        info = QLabel("The trace sends a few small probe packets towards the address and lists the routers that answer. "
                      "The first hops are your own network. A hop with no answer is a router that does not reply: "
                      "usually harmless. Hops with a city are placed on the map from the local DB-IP file.")
        info.setWordWrap(True)
        info.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(info)
        row = QHBoxLayout()
        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.clicked.connect(self.stop)
        copy_btn = QPushButton("📋 Copy")
        copy_btn.clicked.connect(self.copy)
        clear_btn = QPushButton("Clear the route from the map")
        clear_btn.clicked.connect(lambda: self.on_route([]))
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        for widget in (self.stop_btn, copy_btn, clear_btn):
            row.addWidget(widget)
        row.addStretch()
        row.addWidget(close_btn)
        layout.addLayout(row)
        for button in self.findChildren(QPushButton):
            button.setAutoDefault(False)
        close_btn.setDefault(True)

    # region Running

    def start(self):
        try:
            command = route.build_command(self.address)
        except ValueError as e:
            self.status.setText(plain(str(e)))
            self.stop_btn.setEnabled(False)
            return
        self.worker = CommandWorker(command)
        self.worker.output.connect(self._on_text)
        self.worker.finished.connect(self._on_done)
        self.window_ref.route_worker = self.worker      # so closing the program stops it
        self.status.setText(f"Tracing the route to {self.address} (up to {route.MAX_HOPS} hops)...")
        self.worker.start()

    def stop(self):
        if self.worker is not None and self.worker.isRunning():
            self.worker.kill()
            self.stop_btn.setEnabled(False)

    def closeEvent(self, event):
        if self.worker is not None and self.worker.isRunning():
            self.worker.kill()
            self.worker.wait(3000)
        super().closeEvent(event)

    # endregion

    # region Output

    def _on_text(self, text: str):
        self.buffer += text
        *lines, self.buffer = self.buffer.split("\n")
        for line in lines:
            self._add_line(line)

    def _add_line(self, line: str):
        hop = route.parse_hop(line)
        if hop is None or (self.hops and hop.number <= self.hops[-1].number):
            return
        self.hops.append(hop)
        where, location = describe_hop_place(hop.address, self.locate)
        item = QTreeWidgetItem([str(hop.number), hop.address or "*", hop.summary, where])
        if not hop.address:
            for column in range(4):
                item.setForeground(column, Qt.GlobalColor.gray)
        self.tree.addTopLevelItem(item)
        self.tree.scrollToItem(item)
        if location is not None:
            self.points.append((hop.number, location.lat, location.lon, f"{hop.address}  {location.label}"))
            self.on_route(list(self.points))

    def _on_done(self, code: int, output: str):
        self._add_line(self.buffer)
        self.buffer = ""
        self.stop_btn.setEnabled(False)
        worker = self.worker
        shown = count(len(self.hops), "hop")
        if worker is not None and worker.stopped and not worker.timed_out:
            text = f"Stopped after {shown}."
        elif self.hops and self.hops[-1].address == self.address:
            text = f"Reached {self.address} in {shown}."
        elif self.hops:
            text = (f"The trace ended after {shown} without reaching {self.address}: many servers do not answer these "
                    "probes, which does not mean they are down.")
        else:
            text = plain(f"The trace could not run (exit code {code}). {output.strip()[:200]}")
        self.status.setText(text)

    def copy(self):
        lines = [f"{self.tree.topLevelItem(i).text(0):>3}  {self.tree.topLevelItem(i).text(1):<40} "
                 f"{self.tree.topLevelItem(i).text(2):<28} {self.tree.topLevelItem(i).text(3)}"
                 for i in range(self.tree.topLevelItemCount())]
        QApplication.clipboard().setText(f"Route to {self.address}\n" + "\n".join(lines))
        self.status.setText(self.status.text() + " Copied.")

    # endregion
