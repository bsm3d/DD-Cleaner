"""Firewall & Network tab: firewall profiles, rules and blocked traffic; adapters, TCP/UDP and listening ports."""

import logging
import os
import subprocess
from typing import Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QMessageBox, QTabWidget, QTreeWidget,
    QTreeWidgetItem, QHeaderView, QGroupBox, QCheckBox, QSplitter, QLineEdit, QApplication, QMenu, QComboBox
)
from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QColor, QCursor, QDesktopServices

from ddcleaner import firewall, geo, geoip, health, network, route, traffic
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM32, safe_environment, sys_exe
from ddcleaner.system_utils import SystemUtils
from ddcleaner.ui.tab_health import fill_status_tree, status_tree
from ddcleaner.ui.world_map import WorldMapWidget
from ddcleaner.ui.dialog_route import RouteDialog
from ddcleaner.ui.safe_text import plain
from ddcleaner.ui.tab_system_info import primary
from ddcleaner.workers import NetworkAnalysisWorker, TrafficSampleWorker, GeoIPDownloadWorker

EXPOSURE_COLORS = {
    "open": QColor(Qt.GlobalColor.red),
    "limited": QColor(255, 140, 0),
    "blocked": QColor(Qt.GlobalColor.darkGreen),
    "local": QColor(Qt.GlobalColor.gray),
}
TOP_N = 15
TRAFFIC_INTERVAL_MS = 2000
DIRECTION_COLORS = {"In": QColor(200, 90, 0), "Out": QColor(0, 102, 204), "Listen": QColor(Qt.GlobalColor.darkGray),
                    "UDP": QColor(Qt.GlobalColor.darkGray)}
SORT_ROLE = Qt.ItemDataRole.UserRole + 1
INBOUND_INTERNET = QColor(Qt.GlobalColor.red)


class SortableItem(QTreeWidgetItem):
    """Sorts numerically when a column has a SORT_ROLE value (bytes, rates, counts)."""

    def __lt__(self, other):
        tree = self.treeWidget()
        col = tree.sortColumn() if tree else 0
        a, b = self.data(col, SORT_ROLE), other.data(col, SORT_ROLE)
        if a is not None and b is not None:
            return a < b
        return self.text(col).lower() < other.text(col).lower()


def rate_text(rate: float) -> str:
    return f"{network.human_bytes(rate)}/s" if rate >= 1 else ""


def endpoint(addr: str, port: int) -> str:
    if not addr:
        return ""
    return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"


def plain_tree(headers, widths) -> QTreeWidget:
    tree = QTreeWidget()
    tree.setHeaderLabels(headers)
    for col, width in enumerate(widths):
        tree.setColumnWidth(col, width)
    tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    tree.setSortingEnabled(True)
    return tree


class NetworkTabMixin:
    """Firewall & Network tab. Mixed into MainWindow."""

    def _create_network_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        row = QHBoxLayout()
        self.net_analyze_btn = primary(QPushButton("🔍 Analyze firewall && network"))
        self.net_analyze_btn.setToolTip("Read firewall profiles, rules and log, adapters and listening ports (read-only)")
        self.net_analyze_btn.clicked.connect(self._run_network_analysis)
        wf_btn = QPushButton("🧱 Open Windows Firewall (advanced)")
        wf_btn.setToolTip("Windows Defender Firewall with Advanced Security (wf.msc): edit or delete rules")
        wf_btn.clicked.connect(self._open_wf_msc)
        row.addWidget(self.net_analyze_btn)
        row.addWidget(wf_btn)
        row.addStretch()
        layout.addLayout(row)
        self.net_summary_label = QLabel("Firewall and network not analyzed yet (the result fills the Firewall and "
                                        "Network pages). Nothing is changed by the analysis.")
        self.net_summary_label.setWordWrap(True)
        layout.addWidget(self.net_summary_label)

        tabs = QTabWidget()
        self.net_tabs = tabs
        tabs.addTab(self._create_traffic_page(), "Live traffic")
        tabs.addTab(self._create_map_page(), "World map")
        tabs.addTab(self._create_firewall_page(), "Firewall")
        tabs.addTab(self._create_network_page(), "Network")
        layout.addWidget(tabs)
        self.tab_widget.addTab(page, "🌐 Firewall && Network")
        self.fw_report: Optional[firewall.FirewallReport] = None
        self.net_report: Optional[network.NetworkReport] = None

    # region Live traffic

    TRAFFIC_COLUMNS = ["Application / destination", "Direction", "Protocol", "Local", "Remote", "Site / host",
                       "Owner (who)", "Location", "State", "Received", "Sent", "Download", "Upload"]
    GROUP_BY = ("Application", "Destination")

    def _create_traffic_page(self) -> QWidget:
        self.traffic_page = QWidget()
        layout = QVBoxLayout(self.traffic_page)
        row = QHBoxLayout()
        self.traffic_pause_btn = QPushButton("⏸ Pause")
        self.traffic_pause_btn.setCheckable(True)
        self.traffic_pause_btn.toggled.connect(
            lambda paused: self.traffic_pause_btn.setText("▶ Resume" if paused else "⏸ Pause"))
        row.addWidget(self.traffic_pause_btn)
        row.addWidget(QLabel("Group by:"))
        self.traffic_group_combo = QComboBox()
        self.traffic_group_combo.addItems(self.GROUP_BY)
        self.traffic_group_combo.setToolTip("Application: what each program does on the network.\n"
                                            "Destination: where the data goes / who connects to this PC.")
        self.traffic_group_combo.currentIndexChanged.connect(self._reset_traffic_tree)
        row.addWidget(self.traffic_group_combo)
        self.traffic_filter = QLineEdit()
        self.traffic_filter.setPlaceholderText("Filter: application, site, owner, port or address...")
        self.traffic_filter.setClearButtonEnabled(True)
        self.traffic_filter.setProperty("filter", True)  # Ctrl+F
        self.traffic_filter.textChanged.connect(lambda _: self._render_traffic())
        row.addWidget(self.traffic_filter, 1)
        layout.addLayout(row)

        options = QHBoxLayout()
        self.traffic_inbound_cb = QCheckBox("Only inbound (who connects to this PC)")
        self.traffic_ports_cb = QCheckBox("Listening ports && UDP")
        self.traffic_ports_cb.setChecked(True)
        self.traffic_ports_cb.setToolTip("Also show the ports each application listens on or binds (UDP)")
        self.traffic_local_cb = QCheckBox("Connections inside this PC")
        self.traffic_local_cb.setToolTip("Show connections between programs of this PC (127.0.0.1, ::1)")
        self.traffic_dns_cb = QCheckBox("Resolve host names")
        self.traffic_dns_cb.setChecked(True)
        self.traffic_dns_cb.setToolTip("Reverse DNS lookups of remote addresses (sent to your DNS server)")
        self.traffic_owner_cb = QCheckBox("Look up owners (RDAP)")
        # off until the user asks: it sends the public addresses this PC talks to to the Internet registries
        self.traffic_owner_cb.setToolTip(
            "Asks the regional Internet registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC) who owns each public address.\n"
            "Only public IP addresses are sent, once per network block. Your choice is remembered.")
        for cb in (self.traffic_inbound_cb, self.traffic_ports_cb, self.traffic_local_cb, self.traffic_dns_cb,
                   self.traffic_owner_cb):
            cb.toggled.connect(lambda _: self._render_traffic())
            options.addWidget(cb)
        options.addStretch()
        layout.addLayout(options)

        self.traffic_summary_label = QLabel("Starting...")
        self.traffic_summary_label.setWordWrap(True)
        layout.addWidget(self.traffic_summary_label)

        self.traffic_tree = QTreeWidget()
        self.traffic_tree.setHeaderLabels(self.TRAFFIC_COLUMNS)
        for col, width in enumerate((250, 90, 65, 170, 210, 230, 220, 190, 85, 80, 80, 80, 80)):
            self.traffic_tree.setColumnWidth(col, width)
        self.traffic_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.traffic_tree.setSortingEnabled(True)
        self.traffic_tree.sortItems(1, Qt.SortOrder.DescendingOrder)  # busiest first
        self.traffic_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.traffic_tree.customContextMenuRequested.connect(self._show_traffic_menu)
        layout.addWidget(self.traffic_tree)

        info = QLabel("Out = opened by this PC (where your data goes), In = opened by another computer (who comes in; "
                      "red when it comes from the Internet). Site = name the program asked for in DNS, owner = who "
                      "runs the address. Volumes need administrator rights and count from the moment a connection is "
                      "first seen. Read-only: nothing is blocked or changed.")
        info.setWordWrap(True)
        info.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(info)

        self.traffic_monitor: Optional[traffic.TrafficMonitor] = None
        self.traffic_snapshot: Optional[traffic.TrafficSnapshot] = None
        self._traffic_items = {}  # group key -> (group item, {row key: child item})
        self.traffic_timer = QTimer(self)
        self.traffic_timer.timeout.connect(self._traffic_tick)
        self.traffic_timer.start(TRAFFIC_INTERVAL_MS)
        return self.traffic_page

    def _traffic_tick(self):
        """Sample only while the page is on screen and not paused."""
        on_screen = self.traffic_page.isVisible() or self.map_page.isVisible()
        if self.traffic_pause_btn.isChecked() or not on_screen or self.stop_flag.is_set():
            return
        worker = getattr(self, "traffic_worker", None)
        if worker is not None and worker.isRunning():
            return
        if self.traffic_monitor is None:
            self.traffic_monitor = traffic.TrafficMonitor()
        self.traffic_monitor.resolve_hosts = self.traffic_dns_cb.isChecked()
        self.traffic_monitor.lookup_owners = self.traffic_owner_cb.isChecked()
        self.traffic_worker = TrafficSampleWorker(self.traffic_monitor)
        self.traffic_worker.done.connect(self._on_traffic_sample)
        self.traffic_worker.start()

    def _on_traffic_sample(self, snapshot, error: str):
        if error:
            self.traffic_summary_label.setText(f"Could not read the connection table: {error}")
            return
        self.traffic_snapshot = snapshot
        self._render_traffic()
        self._render_map()

    def _create_map_page(self) -> QWidget:
        self.map_page = QWidget()
        layout = QVBoxLayout(self.map_page)
        geo_row = QHBoxLayout()
        self.geoip_label = QLabel()
        self.geoip_label.setWordWrap(True)
        geo_row.addWidget(self.geoip_label, 1)
        self.geoip_btn = QPushButton("⬇ Download DB-IP City Lite (60 MB)")
        self.geoip_btn.setToolTip("Free database of server locations (city level), updated every month.\n"
                                  "Downloaded from db-ip.com, stored next to the program. " + geoip.ATTRIBUTION)
        self.geoip_btn.clicked.connect(self._download_geoip)
        geo_row.addWidget(self.geoip_btn)
        layout.addLayout(geo_row)
        self.map_summary_label = QLabel("Waiting for traffic...")
        self.map_summary_label.setWordWrap(True)
        layout.addWidget(self.map_summary_label)
        self.world_map = WorldMapWidget()
        self.world_map.country_clicked.connect(self._show_country_traffic)
        self.world_map.place_clicked.connect(self._show_place_traffic)
        self.world_map.place_activated.connect(self._map_lookup)
        self.world_map.place_trace.connect(self._map_trace)
        self.world_map.context_requested.connect(self._map_menu)
        layout.addWidget(self.world_map, 1)
        hint = QLabel("Hover a city, a country or a link for its traffic. Click: list its connections. Double-click a "
                      "city: look it up on VirusTotal (in your browser). Shift+click a city: trace the route to it. "
                      "Right-click: more. Wheel: zoom, drag: move, double-click elsewhere: whole world. Without DB-IP, "
                      "destinations are placed by the owner's country (needs \"Look up owners\" on the Live traffic "
                      "page).")
        hint.setWordWrap(True)
        hint.setStyleSheet("color: gray; font-style: italic;")
        layout.addWidget(hint)
        self.home_country = geo.home_country()
        self._refresh_geoip_label()
        return self.map_page

    def _refresh_geoip_label(self):
        info = geoip.GeoIP().info() if os.path.isfile(geoip.GeoIP().path) else {}
        if info:
            text = (f"Server locations: DB-IP City Lite {info.get('month', '?')} (city level). "
                    f"{geoip.ATTRIBUTION}.")
            if geoip.needs_update(info):
                text += " A newer monthly edition is available."
                self.geoip_btn.setText("⬇ Update DB-IP City Lite (60 MB)")
            else:
                self.geoip_btn.setText("⬇ Re-download DB-IP City Lite")
            self.geoip_label.setStyleSheet("")
        else:
            text = ("Server locations: registration country only (the owner's country, often not where the server "
                    "is). Download the free DB-IP City Lite database to place servers in their real city.")
            self.geoip_label.setStyleSheet("color: #b35900;")
        self.geoip_label.setText(text)

    def _download_geoip(self):
        worker = getattr(self, "geoip_worker", None)
        if worker is not None and worker.isRunning():
            return
        if not self._confirm(
                "DB-IP City Lite",
                "Download the DB-IP 'IP to City Lite' database (about 60 MB, about 130 MB once unpacked) from "
                "download.db-ip.com?\n\nIt is free (Creative Commons Attribution 4.0) and updated every month. "
                "Lookups then happen on this PC: no address is sent anywhere."):
            return
        self.geoip_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.geoip_worker = GeoIPDownloadWorker()
        self.geoip_worker.progress.connect(
            lambda n: self._update_status(f"Downloading DB-IP City Lite... {n // (1024 * 1024)} MB unpacked"))
        self.geoip_worker.done.connect(self._on_geoip_downloaded)
        self.geoip_worker.start()

    def _on_geoip_downloaded(self, info: dict, error: str):
        self.progress_bar.setVisible(False)
        self.geoip_btn.setEnabled(True)
        if error:
            self._update_status("DB-IP download failed.")
            QMessageBox.warning(self, "Download failed", plain(f"The database could not be downloaded:\n{error}"))
            return
        if self.traffic_monitor is not None:
            self.traffic_monitor.geoip.close()  # reopened on the next lookup
        self._refresh_geoip_label()
        self._update_status(f"DB-IP City Lite {info.get('month', '')} installed.")

    def _render_map(self):
        snap = self.traffic_snapshot
        if snap is None:
            return
        countries, unlocated = traffic.by_country(snap)
        self.world_map.set_data(countries, self.home_country, unlocated, traffic.by_place(snap))
        inbound = [d.code for d in countries.values() if d.inbound]
        destinations = sorted((d for d in countries.values() if d.outbound), key=lambda d: -d.outbound)
        text = (f"{sum(d.outbound for d in destinations)} outbound Internet connection(s) to "
                f"{len(destinations)} country(ies)" + (": " + ", ".join(f"{d.code} {d.outbound}" for d in destinations[:5])
                                                        if destinations else ""))
        if inbound:
            text += f"   |   inbound from: {', '.join(sorted(inbound))}"
        if unlocated:
            text += f"   |   {unlocated} not placed yet"
        if not self.traffic_owner_cb.isChecked() and not self.world_map.precise:
            text += " (owner lookups are off and DB-IP is not installed)"
        self.map_summary_label.setText(text)
        self.map_summary_label.setStyleSheet("color: red; font-weight: bold;" if inbound else "")

    # region Map actions: look up, route, menu

    def _map_choice(self, items: list) -> str:
        """The value of the item to use: the only one, or the one picked in a small menu at the cursor ('' = none)."""
        if not items:
            return ""
        if len(items) == 1:
            return items[0][1]
        menu = QMenu(self.world_map)
        actions = {menu.addAction(label): value for label, value in items}
        chosen = menu.exec(QCursor.pos())
        return actions.get(chosen, "")

    def _map_lookup(self, place):
        """Double-click on a node: what is known about the destination, on VirusTotal. The site itself is not
        contacted: it may be the very thing being checked."""
        items = ([(f"Look up {h} on VirusTotal", h) for h in route.valid_hosts(place.hosts)[:8]]
                 + [(f"Look up {a} on VirusTotal", a) for a in route.public_addresses(place.addresses)[:4]])
        target = self._map_choice(items)
        if not target:
            self._update_status("No site name or address to look up for this place yet.")
            return
        QDesktopServices.openUrl(QUrl(route.reputation_url(target)))
        self._update_status(f"VirusTotal page of {target} opened in the browser.")

    def _map_trace(self, place):
        """Shift+click on a node: the route to its address, hop by hop."""
        addresses = route.public_addresses(place.addresses)
        address = self._map_choice([(f"Trace the route to {a}", a) for a in addresses[:12]])
        if not address:
            self._update_status("No address to trace for this place yet.")
            return
        self._start_route(address, f"{place.label} ({address})")

    def _start_route(self, address: str, title: str):
        old = getattr(self, "_route_dialog", None)
        if old is not None:
            old.close()
        traffic_geoip = self.traffic_monitor.geoip if self.traffic_monitor is not None else geoip.GeoIP()
        dialog = RouteDialog(self, address, title, traffic_geoip.locate, self.world_map.set_route)
        self._route_dialog = dialog
        dialog.show()
        dialog.start()

    def _map_menu(self, place, position):
        menu = QMenu(self.world_map)
        if place is not None:
            where = place.label if place.precise else place.country
            menu.addAction(f"🔎 Show the connections to {where}").triggered.connect(
                lambda: self._show_place_traffic(place.label) if place.precise else self._show_country_traffic(place.country))
            menu.addAction("🛰 Look up on VirusTotal...").triggered.connect(lambda: self._map_lookup(place))
            menu.addAction("🧭 Trace the route...").triggered.connect(lambda: self._map_trace(place))
            hosts = route.valid_hosts(place.hosts)[:8]
            if hosts:
                sites = menu.addMenu("🌐 Open the site itself (connects to it)")
                for host in hosts:
                    sites.addAction(host).triggered.connect(
                        lambda _checked=False, h=host: QDesktopServices.openUrl(QUrl(route.site_url(h))))
            menu.addAction("📋 Copy the addresses").triggered.connect(
                lambda: QApplication.clipboard().setText("\n".join(sorted(place.addresses))))
            menu.addSeparator()
        if self.world_map.route:
            menu.addAction("Clear the route").triggered.connect(lambda: self.world_map.set_route([]))
        menu.addAction("Reset the view").triggered.connect(self.world_map.reset_view)
        menu.exec(position)

    # endregion

    def _show_country_traffic(self, code: str):
        """Map click: list that country's connections on the Live traffic page."""
        self.traffic_group_combo.setCurrentText("Destination")
        self.traffic_filter.setText(f"country:{code}")
        self.net_tabs.setCurrentWidget(self.traffic_page)

    def _show_place_traffic(self, label: str):
        self.traffic_group_combo.setCurrentText("Destination")
        self.traffic_filter.setText(f"place:{label}")
        self.net_tabs.setCurrentWidget(self.traffic_page)

    def _reset_traffic_tree(self):
        self.traffic_tree.clear()
        self._traffic_items = {}
        self.traffic_tree.headerItem().setText(0, f"{self.traffic_group_combo.currentText()} / connection")
        self._render_traffic()

    def _row_visible(self, app: traffic.AppTraffic, row: traffic.ConnectionRow, needle: str) -> bool:
        if self.traffic_inbound_cb.isChecked() and row.direction != "In":
            return False
        if row.direction in ("Listen", "UDP") and not self.traffic_ports_cb.isChecked():
            return False
        if row.remote_kind == "This PC" and not self.traffic_local_cb.isChecked():
            return False
        if row.direction in ("Listen", "UDP") and row.conn.local_addr in ("127.0.0.1", "::1") \
                and not self.traffic_local_cb.isChecked():
            return False
        if not needle:
            return True
        if needle.startswith("country:"):  # set by a click on the world map
            return row.direction in ("In", "Out") and row.map_country.lower() == needle[8:].strip()
        if needle.startswith("place:"):
            return row.location is not None and row.location.label.lower() == needle[6:].strip()
        c = row.conn
        haystack = " ".join([app.process.label, app.process.name, app.process.path, c.local_addr, str(c.local_port),
                             c.remote_addr, str(c.remote_port), row.host, row.site, row.owner, row.direction,
                             row.location.label if row.location else "",
                             c.protocol]).lower()
        return needle in haystack

    @staticmethod
    def _destination_key(row: traffic.ConnectionRow) -> str:
        """Where a connection goes: site name when known, else owner, else the address itself."""
        if row.site:
            return row.site.split(" (+")[0]
        if row.owner and row.owner != "looking up...":
            return row.owner
        return row.conn.remote_addr

    def _connection_values(self, first: str, r: traffic.ConnectionRow):
        c = r.conn
        is_link = r.direction in ("In", "Out")
        return [
            first, r.direction, c.protocol, endpoint(c.local_addr, c.local_port),
            endpoint(c.remote_addr, c.remote_port) if is_link else "",
            r.site if is_link else "", r.owner if is_link else "",
            r.location.label if is_link and r.location else "", c.state,
            network.human_bytes(r.received) if r.received is not None else "",
            network.human_bytes(r.sent) if r.sent is not None else "",
            rate_text(r.rate_in), rate_text(r.rate_out)]

    def _traffic_groups(self, snap: traffic.TrafficSnapshot, needle: str):
        """[(group key, group values, sort values, tooltip, inbound from Internet, [(row key, row, first col)])]."""
        by_destination = self.traffic_group_combo.currentText() == "Destination"
        groups = {}
        for pid, app in snap.apps.items():
            if pid == 0:
                continue  # closed connections (TIME_WAIT) owned by nobody
            label = f"{app.process.label}  (PID {pid})"
            for r in app.rows:
                if not self._row_visible(app, r, needle):
                    continue
                if by_destination:
                    if r.direction not in ("In", "Out"):
                        continue  # listening ports have no destination
                    key, first = self._destination_key(r), label
                else:
                    key, first = (pid, app.process.name), ""
                g = groups.setdefault(key, {"rows": [], "app": app, "pid": pid})
                g["rows"].append((r.conn.key, r, first))

        out = []
        for key, g in groups.items():
            rows = [r for _, r, _ in g["rows"]]
            n_in = sum(1 for r in rows if r.direction == "In")
            n_out = sum(1 for r in rows if r.direction == "Out")
            received = sum(r.received or 0 for r in rows)
            sent = sum(r.sent or 0 for r in rows)
            rate_in = sum(r.rate_in for r in rows)
            rate_out = sum(r.rate_out for r in rows)
            inbound_internet = any(r.direction == "In" and r.remote_kind == "Internet" for r in rows)
            addresses = sorted({r.conn.remote_addr for r in rows if r.direction in ("In", "Out")})
            if by_destination:
                first_row = rows[0]
                programs = sorted({lbl.split("  (PID")[0] for _, _, lbl in g["rows"]})
                values = [key, f"{n_in} in / {n_out} out", "", ", ".join(programs)[:80],
                          addresses[0] if len(addresses) == 1 else f"{len(addresses)} addresses",
                          first_row.site or first_row.host, first_row.owner,
                          ", ".join(sorted({r.location.label for r in rows if r.location}))[:80], "",
                          network.human_bytes(received) if snap.bytes_available else "",
                          network.human_bytes(sent) if snap.bytes_available else "",
                          rate_text(rate_in), rate_text(rate_out)]
                tooltip = "\n".join([key, first_row.owner_detail] + addresses[:20])
            else:
                app = g["app"]
                ports = sorted({f"{r.conn.protocol} {r.conn.local_port}" for r in rows if r.direction in ("Listen", "UDP")},
                               key=lambda p: (p[:3], int(p[4:])))
                sites = sorted({self._destination_key(r) for r in rows if r.direction in ("In", "Out")})
                received, sent = app.received, app.sent  # includes connections already closed
                values = [f"{app.process.label}  (PID {g['pid']})", f"{n_in} in / {n_out} out" if n_in or n_out else "",
                          "", ("Ports: " + ", ".join(ports[:6]) + (" ..." if len(ports) > 6 else "")) if ports else "",
                          f"{len(addresses)} address(es)" if addresses else "",
                          ", ".join(sites[:3]) + (f" +{len(sites) - 3}" if len(sites) > 3 else ""), "", "",
                          "", network.human_bytes(received) if snap.bytes_available else "",
                          network.human_bytes(sent) if snap.bytes_available else "",
                          rate_text(rate_in), rate_text(rate_out)]
                tooltip = (f"{app.process.name} (PID {g['pid']})\n{app.process.path}\n"
                           f"Services: {', '.join(app.process.services) or '-'}")
            sort = {1: (n_in + n_out) * 1000 + len(rows), 9: received, 10: sent, 11: rate_in, 12: rate_out}
            out.append((key, values, sort, tooltip, inbound_internet, g["rows"]))
        return out

    def _render_traffic(self):
        """Update the tree in place so expanded groups stay expanded between samples."""
        snap = self.traffic_snapshot
        if snap is None:
            return
        needle = self.traffic_filter.text().strip().lower()
        tree = self.traffic_tree
        tree.setSortingEnabled(False)
        groups = self._traffic_groups(snap, needle)
        seen = set()
        for key, values, sort, tooltip, inbound_internet, rows in groups:
            seen.add(key)
            if key in self._traffic_items:
                item, children = self._traffic_items[key]
            else:
                item, children = SortableItem(), {}
                tree.addTopLevelItem(item)
                self._traffic_items[key] = (item, children)
            self._set_row(item, values, sort)
            item.setToolTip(0, plain(tooltip))
            item.setForeground(0, INBOUND_INTERNET if inbound_internet else QColor(Qt.GlobalColor.black))

            seen_rows = set()
            for row_key, r, first in rows:
                seen_rows.add(row_key)
                child = children.get(row_key)
                if child is None:
                    child = SortableItem()
                    item.addChild(child)
                    children[row_key] = child
                self._set_row(child, self._connection_values(first, r),
                              {9: r.received or 0, 10: r.sent or 0, 11: r.rate_in, 12: r.rate_out})
                color = DIRECTION_COLORS.get(r.direction, QColor(Qt.GlobalColor.black))
                if r.direction == "In" and r.remote_kind == "Internet":
                    color = INBOUND_INTERNET
                child.setForeground(1, color)
                child.setForeground(4, color if r.direction == "In" else QColor(Qt.GlobalColor.black))
                child.setToolTip(6, plain(r.owner_detail) if r.owner_detail else "")
                child.setToolTip(5, plain(r.host) if r.host else "")
            for k in [k for k in children if k not in seen_rows]:
                item.removeChild(children.pop(k))
        for k in [k for k in self._traffic_items if k not in seen]:
            item, _ = self._traffic_items.pop(k)
            tree.takeTopLevelItem(tree.indexOfTopLevelItem(item))
        tree.setSortingEnabled(True)
        self._update_traffic_summary(snap)

    def _update_traffic_summary(self, snap: traffic.TrafficSnapshot):
        rows = [r for pid, app in snap.apps.items() if pid for r in app.rows if r.remote_kind != "This PC"]
        outbound = sum(1 for r in rows if r.direction == "Out")
        inbound_internet = sum(1 for r in rows if r.direction == "In" and r.remote_kind == "Internet")
        inbound_lan = sum(1 for r in rows if r.direction == "In" and r.remote_kind == "Local network")
        destinations = {self._destination_key(r) for r in rows if r.direction == "Out"}
        rates = (f"Download {network.human_bytes(snap.total_rate_in)}/s, upload {network.human_bytes(snap.total_rate_out)}/s"
                 if snap.bytes_available else "Byte counters need administrator rights")
        text = (f"{rates}   |   {outbound} outbound connection(s) to {len(destinations)} destination(s); "
                f"inbound: {inbound_internet} from the Internet, {inbound_lan} from the local network"
                + ("  (paused)" if self.traffic_pause_btn.isChecked() else ""))
        self.traffic_summary_label.setText(text)
        self.traffic_summary_label.setStyleSheet("color: red; font-weight: bold;" if inbound_internet else "")

    @staticmethod
    def _set_row(item: QTreeWidgetItem, values, sort=None):
        for col, value in enumerate(values):
            if item.text(col) != value:
                item.setText(col, value)
        for col, value in (sort or {}).items():
            item.setData(col, SORT_ROLE, value)

    def _show_traffic_menu(self, position):
        item = self.traffic_tree.itemAt(position)
        if not item:
            return
        menu = QMenu()
        copy_row = menu.addAction("📋 Copy row")
        copy_ip = menu.addAction("📋 Copy remote address")
        only_this = menu.addAction("🔎 Show only this")
        action = menu.exec(self.traffic_tree.viewport().mapToGlobal(position))
        if action == copy_row:
            QApplication.clipboard().setText("\t".join(item.text(c) for c in range(item.columnCount()) if item.text(c)))
        elif action == copy_ip:
            remote = item.text(4)
            QApplication.clipboard().setText(remote.rsplit(":", 1)[0].strip("[]") if remote.count(".") == 3 or
                                             remote.startswith("[") else remote)
        elif action == only_this:
            top = item.parent() or item
            self.traffic_filter.setText(top.text(0).split("  (PID")[0])

    def _stop_traffic(self):
        self.traffic_timer.stop()
        if self.traffic_monitor is not None:
            self.traffic_monitor.close()

    # endregion

    # region Pages

    def _create_firewall_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        splitter = QSplitter(Qt.Orientation.Vertical)

        top = QWidget()
        top_layout = QVBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        self.fw_profiles_tree = plain_tree(
            ["Profile", "In use", "Firewall", "Inbound default", "Outbound default", "Log dropped packets"],
            (110, 90, 90, 120, 130, 150))
        self.fw_profiles_tree.setMaximumHeight(110)
        top_layout.addWidget(self.fw_profiles_tree)
        self.fw_rules_label = QLabel()
        self.fw_rules_label.setWordWrap(True)
        top_layout.addWidget(self.fw_rules_label)
        self.fw_findings_tree = status_tree()
        top_layout.addWidget(self.fw_findings_tree)
        splitter.addWidget(top)

        log_box = QGroupBox("Blocked traffic (firewall log)")
        log_layout = QVBoxLayout(log_box)
        log_row = QHBoxLayout()
        self.fw_log_label = QLabel("Run the analysis to read the log.")
        self.fw_log_label.setWordWrap(True)
        log_row.addWidget(self.fw_log_label, 1)
        self.fw_log_toggle_btn = QPushButton("Enable dropped-packet logging")
        self.fw_log_toggle_btn.setEnabled(False)
        self.fw_log_toggle_btn.setToolTip("Run the analysis first: it reads whether logging is on.")
        self.fw_log_toggle_btn.clicked.connect(self._toggle_firewall_logging)
        log_row.addWidget(self.fw_log_toggle_btn)
        log_layout.addLayout(log_row)
        self.fw_log_tree = plain_tree(["Blocked", "Count"], (420, 90))
        log_layout.addWidget(self.fw_log_tree)
        splitter.addWidget(log_box)
        splitter.setSizes([520, 200])

        layout.addWidget(splitter)
        return page

    def _create_network_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.net_items_tree = status_tree()
        splitter.addWidget(self.net_items_tree)

        ports = QWidget()
        ports_layout = QVBoxLayout(ports)
        ports_layout.setContentsMargins(0, 0, 0, 0)
        ports_row = QHBoxLayout()
        ports_row.addWidget(QLabel("Listening ports and whether the firewall lets the network reach them:"))
        ports_row.addStretch()
        self.net_hide_local_cb = QCheckBox("Hide loopback-only and blocked ports")
        self.net_hide_local_cb.setChecked(True)
        self.net_hide_local_cb.toggled.connect(self._populate_listeners)
        ports_row.addWidget(self.net_hide_local_cb)
        ports_layout.addLayout(ports_row)
        self.net_listeners_tree = plain_tree(
            ["Protocol", "Address", "Port", "Process", "PID", "Services", "Reachable", "Firewall rule"],
            (70, 170, 60, 140, 60, 170, 230, 250))
        ports_layout.addWidget(self.net_listeners_tree)
        splitter.addWidget(ports)
        layout.addWidget(splitter)
        return page

    # endregion

    # region Analysis

    def _run_network_analysis(self):
        worker = getattr(self, "net_worker", None)
        if worker is not None and worker.isRunning():
            QMessageBox.information(self, "Info", "The analysis is already running.")
            return
        self.net_analyze_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        owners = None
        if self.traffic_owner_cb.isChecked():
            if self.traffic_monitor is None:
                self.traffic_monitor = traffic.TrafficMonitor()
            owners = self.traffic_monitor.owners  # shares the per-network cache with the live view
        self.net_worker = NetworkAnalysisWorker(owners)
        self.net_worker.progress.connect(self._update_status)
        self.net_worker.done.connect(self._on_network_analyzed)
        self.net_worker.start()

    def _on_network_analyzed(self, fw_report, net_report, error: str):
        self.progress_bar.setVisible(False)
        self.net_analyze_btn.setEnabled(True)
        if error:
            self._update_status("Analysis failed.")
            QMessageBox.warning(self, "Error", plain(f"Firewall/network analysis failed: {error}"))
            return
        self.fw_report, self.net_report = fw_report, net_report
        self._populate_firewall()
        self._populate_network()

        statuses = [f.status for f in fw_report.findings] + [i.status for i in net_report.items]
        critical = statuses.count(health.CRITICAL)
        warnings = statuses.count(health.WARNING)
        open_ports = sum(1 for r in net_report.listeners if r.exposure.level == "open")
        self.net_summary_label.setText(
            f"{critical} critical, {warnings} warning(s), {open_ports} listening port(s) reachable from the network"
            + (f". {net_report.error}" if net_report.error else ""))
        self.net_summary_label.setStyleSheet(
            "color: red; font-weight: bold;" if critical else
            "color: #cc7000; font-weight: bold;" if warnings else "color: darkgreen;")
        logging.info(f"Firewall/network analysis: {critical} critical, {warnings} warnings, {open_ports} open ports")
        self._update_status("Firewall and network analysis done.")
        if self.net_tabs.currentWidget() in (self.traffic_page, self.map_page):
            self.net_tabs.setCurrentIndex(2)  # the result is on the Firewall and Network pages, not on the live ones

    def _populate_firewall(self):
        r = self.fw_report
        self.fw_profiles_tree.clear()
        for name in firewall.PROFILES:
            p = r.profiles.get(name)
            if p is None:
                continue
            item = QTreeWidgetItem([name, "yes" if name in r.active else "", "On" if p.enabled else "OFF",
                                    p.inbound, p.outbound, "yes" if p.log_blocked else "no"])
            if not p.enabled or p.inbound == "Allow":
                for col in range(6):
                    item.setForeground(col, QColor(Qt.GlobalColor.red))
            self.fw_profiles_tree.addTopLevelItem(item)
        networks = ", ".join(f"{n.get('Interface')} = {n.get('Category')}" for n in r.networks)
        s = r.stats
        self.fw_rules_label.setText(
            f"Networks: {networks or 'none'}.   Rules: {s['total']} ({s['enabled']} enabled): "
            f"{s['inbound_allow']} inbound allow, {s['inbound_block']} inbound block, "
            f"{s['outbound_block']} outbound block" + (f", {s['group_policy']} from Group Policy" if s["group_policy"] else ""))
        fill_status_tree(self.fw_findings_tree, [(f.status, "Firewall", f.title, f.details) for f in r.findings])
        self._populate_firewall_log()

    def _populate_firewall_log(self):
        r = self.fw_report
        self.fw_log_tree.clear()
        self.fw_log_toggle_btn.setEnabled(True)
        self.fw_log_toggle_btn.setToolTip("Turns the Windows firewall log of blocked connections on or off "
                                          "(administrator rights, asked before anything changes)")
        self.fw_log_toggle_btn.setText("Disable dropped-packet logging" if r.log_enabled
                                       else "Enable dropped-packet logging")
        log = r.log
        if log is None or not log.lines:
            if r.log_enabled:
                self.fw_log_label.setText(f"Logging is on, but nothing has been written yet to {r.log_path}. "
                                          "Come back later (or run the analysis as administrator).")
            else:
                self.fw_log_label.setText("Windows does not log blocked connections (default). Turn logging on to "
                                          "see who tries to reach this PC and what is blocked. The log is limited "
                                          "to 4 MB and rotates by itself.")
            return
        state = "" if r.log_enabled else " Logging is now off: these are old entries."
        self.fw_log_label.setText(f"{log.dropped} dropped packets between {log.first} and {log.last} "
                                  f"({log.lines} log lines).{state}")

        def section(title, counter, describe=lambda k: k):
            if not counter:
                return
            parent = QTreeWidgetItem([title, str(sum(counter.values()))])
            for key, count in counter.most_common(TOP_N):
                parent.addChild(QTreeWidgetItem([describe(key), str(count)]))
            self.fw_log_tree.addTopLevelItem(parent)
            parent.setExpanded(True)

        if log.processes:
            try:
                names = traffic.process_names()
            except OSError:
                names = {}
            section("Blocked programs (by process ID)", log.processes,
                    lambda pid: f"{names.get(int(pid), 'process ended')} (PID {pid})")
        section("Inbound: most blocked ports", log.inbound_ports, firewall.describe_port)
        section("Inbound: most blocked sources (who tried to come in)", log.inbound_sources,
                lambda ip: f"{ip}: {log.source_owners[ip]}" if ip in log.source_owners else ip)
        section("Outbound: blocked destinations", log.outbound_targets)
        section("Per day", log.per_day)

    def _populate_network(self):
        r = self.net_report
        fill_status_tree(self.net_items_tree, [(i.status, i.category, i.title, i.details) for i in r.items])
        self._populate_listeners()

    def _populate_listeners(self):
        self.net_listeners_tree.setSortingEnabled(False)
        self.net_listeners_tree.clear()
        report = getattr(self, "net_report", None)
        if report is None:
            return
        hide = self.net_hide_local_cb.isChecked()
        for row in report.listeners:
            l, e = row.listener, row.exposure
            if hide and e.level in ("local", "blocked"):
                continue
            item = QTreeWidgetItem([l.protocol, l.address, "", l.process, "", ", ".join(l.services), e.text, e.rule])
            item.setData(2, Qt.ItemDataRole.DisplayRole, l.port)
            item.setData(4, Qt.ItemDataRole.DisplayRole, l.pid)
            item.setToolTip(3, plain(l.path or l.process))
            item.setForeground(6, EXPOSURE_COLORS.get(e.level, QColor(Qt.GlobalColor.black)))
            self.net_listeners_tree.addTopLevelItem(item)
        self.net_listeners_tree.setSortingEnabled(True)
        self.net_listeners_tree.sortItems(2, Qt.SortOrder.AscendingOrder)

    # endregion

    # region Actions

    def _open_wf_msc(self):
        try:
            # absolute .msc path: a relative "wf.msc" is looked up in the current folder first
            subprocess.Popen([sys_exe("mmc.exe"), sys_exe("wf.msc")], cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)
        except OSError as e:
            QMessageBox.warning(self, "Error", f"Could not open Windows Firewall: {e}")

    def _toggle_firewall_logging(self):
        if self.fw_report is None:
            return
        enable = not self.fw_report.log_enabled
        if not SystemUtils.check_admin_privileges():
            QMessageBox.warning(self, "Administrator required", "Changing firewall logging needs administrator rights.")
            return
        text = ("Turn on logging of dropped packets for the Domain, Private and Public profiles?\n\n"
                f"Windows then writes blocked connections to {self.fw_report.log_path} (4 MB max, rotated). "
                "Nothing else changes; you can turn it off here at any time."
                if enable else "Turn off logging of dropped packets for all profiles?")
        if not self._confirm("Firewall logging", text):
            return
        self.fw_log_toggle_btn.setEnabled(False)

        def work():
            ok, message = firewall.set_dropped_packet_logging(enable)
            logging.info(f"Firewall dropped-packet logging {'enabled' if enable else 'disabled'}: "
                         f"{'ok' if ok else message}")

            def finish():
                self.fw_log_toggle_btn.setEnabled(True)
                if not ok:
                    QMessageBox.warning(self, "Error", plain(f"The firewall setting could not be changed:\n{message}"))
                    return
                self._update_status(f"Dropped-packet logging {'enabled' if enable else 'disabled'}.")
                self._run_network_analysis()
            self._ui(finish)

        if not self._start_bg_thread("firewall_logging", work):
            self.fw_log_toggle_btn.setEnabled(True)

    # endregion
