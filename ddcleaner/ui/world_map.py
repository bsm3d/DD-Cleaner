"""World map of network destinations: countries, arcs from this PC, markers sized by connections."""

import html
import math
from typing import Dict, Iterator, List, Optional, Tuple

from PySide6.QtWidgets import QApplication, QWidget, QToolTip
from PySide6.QtCore import Qt, QPointF, QRectF, QTimer, Signal
from PySide6.QtGui import QPainter, QPainterPath, QPen, QColor, QTransform, QFont, QFontMetricsF

from ddcleaner import geo, geoip, network
from ddcleaner.traffic import CountryTraffic, PlaceTraffic

LAT_TOP, LAT_BOTTOM = 84.0, -58.0
OCEAN = QColor(223, 234, 245)
LAND = QColor(245, 245, 242)
BORDER = QColor(180, 180, 180)
OUT_COLOR = QColor(0, 102, 204)
IN_COLOR = QColor(220, 30, 30)
HOME_COLOR = QColor(20, 140, 60)
ROUTE_COLOR = QColor(224, 112, 0)
HINT = "Hover: details. Click: connections. Double-click a node: look it up. Shift+click: trace route. Right-click: more."
RoutePoint = Tuple[int, float, float, str]   # hop number, latitude, longitude, text


class WorldMapWidget(QWidget):
    """Equirectangular map.
    Hover a node, a link or a hop: details. Click: place_clicked / country_clicked (after the double-click delay).
    Double-click a node: place_activated. Shift+click a node: place_trace. Right-click: context_requested.
    Wheel: zoom, drag: pan, double-click elsewhere: reset the view."""

    country_clicked = Signal(str)
    place_clicked = Signal(str)       # city label
    place_activated = Signal(object)  # PlaceTraffic, double-click
    place_trace = Signal(object)      # PlaceTraffic, shift + click
    context_requested = Signal(object, object)  # PlaceTraffic or None, global position

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMouseTracking(True)
        self.setMinimumHeight(320)
        self.countries, _ = geo.world()
        self.paths: Dict[str, QPainterPath] = {}
        self._outlines = []
        for c in self.countries:
            path = QPainterPath()
            for ring in c.rings:
                path.moveTo(ring[0][0], -ring[0][1])
                for lon, lat in ring[1:]:
                    path.lineTo(lon, -lat)
                path.closeSubpath()
            self._outlines.append((c.code, path))
            if c.code:
                self.paths.setdefault(c.code, QPainterPath()).addPath(path)
        self.data: Dict[str, CountryTraffic] = {}
        self.places: Dict[str, PlaceTraffic] = {}
        self.route: List[RoutePoint] = []
        self.home = ""
        self.unlocated = 0
        self.zoom = 1.0
        self.center = QPointF(10.0, -(LAT_TOP + LAT_BOTTOM) / 2)  # lon, -lat at the widget center
        self._drag: Optional[QPointF] = None
        self._dragged = False
        self._hover: Optional[Tuple[str, object]] = None   # ("place", key) | ("arc", key) | ("hop", number)
        self._pending: Optional[QPointF] = None            # a click that waits to know whether it is a double-click
        self._click_timer = QTimer(self)
        self._click_timer.setSingleShot(True)
        self._click_timer.timeout.connect(self.flush_click)

    # region Data and projection

    def set_data(self, data: Dict[str, CountryTraffic], home: str, unlocated: int,
                 places: Optional[Dict[str, PlaceTraffic]] = None):
        self.data, self.home, self.unlocated = data, home, unlocated
        if places is None:  # one marker per country
            places = {f"country:{d.code}": PlaceTraffic(f"country:{d.code}", d.code, d.code, None, None, False,
                                                        d.outbound, d.inbound, d.apps, d.destinations, d.received,
                                                        d.sent, d.rate_in, d.rate_out, d.addresses, d.hosts)
                      for d in data.values()}
        self.places = places
        self.update()

    def set_route(self, points: List[RoutePoint]):
        """The hops of a traced route that could be placed, drawn as a dashed line from this PC. [] clears it."""
        self.route = list(points)
        self.update()

    def reset_view(self):
        self.zoom = 1.0
        self.center = QPointF(10.0, -(LAT_TOP + LAT_BOTTOM) / 2)
        self.update()

    def _place_point(self, place: PlaceTraffic) -> Optional[QPointF]:
        if place.lat is not None and place.lon is not None:
            return self._transform().map(QPointF(place.lon, -place.lat))
        return self._point(place.country)

    @property
    def precise(self) -> bool:
        return any(p.precise for p in self.places.values())

    def _transform(self) -> QTransform:
        base = min(self.width() / 360.0, self.height() / (LAT_TOP - LAT_BOTTOM))
        scale = base * self.zoom
        t = QTransform()
        t.translate(self.width() / 2, self.height() / 2)
        t.scale(scale, scale)
        t.translate(-self.center.x(), -self.center.y())
        return t

    def _point(self, code: str) -> Optional[QPointF]:
        c = geo.country(code)
        return self._transform().map(QPointF(c.lon, -c.lat)) if c else None

    @staticmethod
    def _radius(count: int) -> float:
        return 4 + 3.5 * math.log2(1 + count)

    @staticmethod
    def _arc_width(d: PlaceTraffic) -> float:
        return 1 + math.log2(1 + d.connections) * 0.8

    @staticmethod
    def _arc_path(a: QPointF, b: QPointF) -> QPainterPath:
        mid = (a + b) / 2
        dist = math.hypot(b.x() - a.x(), b.y() - a.y())
        path = QPainterPath(a)
        path.quadTo(QPointF(mid.x(), mid.y() - dist * 0.25), b)
        return path

    def _arcs(self) -> Iterator[Tuple[PlaceTraffic, QPointF, QPointF]]:
        """(place, this PC, place) for every link drawn, the busiest last (on top)."""
        home = self._point(self.home) if self.home else None
        if home is None:
            return
        for d in sorted(self.places.values(), key=lambda d: d.connections):
            target = self._place_point(d)
            if target is None or (not d.precise and d.country == self.home):
                continue
            yield d, home, target

    # endregion

    # region Painting

    def _label_font(self) -> QFont:
        font = QFont(self.font())
        font.setPointSizeF(8)
        font.setBold(True)
        return font

    def _label_layout(self) -> List[Tuple[PlaceTraffic, str, QRectF]]:
        """The names to draw: the busiest first, and none that would land on a name already drawn (a crowd of
        European cities stays readable; zoom in to see the others). The node under the cursor always has its name."""
        metrics = QFontMetricsF(self._label_font())
        order = sorted(self.places.values(), key=lambda d: (self._hover != ("place", d.key), -d.connections))
        placed, taken = [], []
        for d in order:
            at = self._place_point(d)
            if at is None:
                continue
            name = d.label.split(" (")[0].split(",")[0] if d.precise else d.country
            text = f"{name} {d.connections}"
            r = self._radius(d.connections)
            rect = QRectF(at.x() + r + 2, at.y() - 8, metrics.horizontalAdvance(text) + 6, 16)
            if self._hover != ("place", d.key) and any(rect.intersects(t) for t in taken):
                continue
            taken.append(rect)
            placed.append((d, text, rect))
        return placed

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), OCEAN)
        t = self._transform()

        p.save()
        p.setTransform(t)
        border = QPen(BORDER)
        border.setCosmetic(True)
        border.setWidthF(0.7)
        p.setPen(border)
        peak = max((d.connections for d in self.data.values()), default=1)
        for code, path in self._outlines:
            d = self.data.get(code)
            if d:
                strength = 0.25 + 0.75 * math.log(1 + d.connections) / math.log(1 + peak)
                fill = QColor(OUT_COLOR)
                fill.setAlphaF(0.12 + 0.38 * strength)
                p.setBrush(fill)
            elif code and code == self.home:
                fill = QColor(HOME_COLOR)
                fill.setAlphaF(0.15)
                p.setBrush(fill)
            else:
                p.setBrush(LAND)
            p.drawPath(path)
        p.restore()

        home = self._point(self.home) if self.home else None
        for d, a, b in self._arcs():
            self._draw_arc(p, a, b, d)
        # the big nodes first: a small one next to a big one stays visible on top of it
        for d in sorted(self.places.values(), key=lambda d: -d.connections):
            target = self._place_point(d)
            if target is not None:
                self._draw_marker(p, target, d)
        p.setFont(self._label_font())
        for d, text, rect in self._label_layout():
            p.setPen(QColor(30, 30, 30))
            p.drawText(rect, Qt.AlignmentFlag.AlignVCenter, text)
        self._draw_route(p, home)
        if home is not None:
            p.setPen(QPen(Qt.GlobalColor.white, 2))
            p.setBrush(HOME_COLOR)
            p.drawEllipse(home, 6, 6)
        self._draw_legend(p)
        p.end()

    def _draw_arc(self, p: QPainter, a: QPointF, b: QPointF, d: PlaceTraffic):
        hovered = self._hover == ("arc", d.key)
        color = QColor(IN_COLOR if d.inbound else OUT_COLOR)
        color.setAlphaF(0.95 if hovered else 0.55)
        width = self._arc_width(d) + (2 if hovered else 0)
        p.setPen(QPen(color, width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(self._arc_path(a, b))

    def _draw_marker(self, p: QPainter, at: QPointF, d: PlaceTraffic):
        r = self._radius(d.connections)
        color = QColor(IN_COLOR if d.inbound else OUT_COLOR)
        fill = QColor(color)
        fill.setAlphaF(0.75)
        if self._hover == ("place", d.key):
            p.setPen(QPen(QColor(30, 30, 30), 2))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(at, r + 3, r + 3)
        p.setPen(QPen(Qt.GlobalColor.white, 1.5))
        p.setBrush(fill)
        p.drawEllipse(at, r, r)

    def _route_dots(self) -> List[Tuple[int, QPointF, str]]:
        t = self._transform()
        return [(n, t.map(QPointF(lon, -lat)), text) for n, lat, lon, text in self.route]

    def _draw_route(self, p: QPainter, home: Optional[QPointF]):
        dots = self._route_dots()
        if not dots:
            return
        points = ([home] if home is not None else []) + [pt for _n, pt, _text in dots]
        p.setPen(QPen(ROUTE_COLOR, 2.2, Qt.PenStyle.DashLine, Qt.PenCapStyle.RoundCap))
        p.setBrush(Qt.BrushStyle.NoBrush)
        for a, b in zip(points, points[1:]):
            p.drawLine(a, b)
        font = QFont(self.font())
        font.setPointSizeF(7.5)
        font.setBold(True)
        p.setFont(font)
        for n, pt, _text in dots:
            hovered = self._hover == ("hop", n)
            p.setPen(QPen(Qt.GlobalColor.white, 1.5))
            p.setBrush(ROUTE_COLOR)
            radius = 7 if hovered else 5
            p.drawEllipse(pt, radius, radius)
            if self.zoom >= 2.5 or hovered:
                p.setPen(QColor(120, 60, 0))
                p.drawText(QRectF(pt.x() + radius + 1, pt.y() - 8, 24, 16), Qt.AlignmentFlag.AlignVCenter, str(n))

    def _draw_legend(self, p: QPainter):
        lines = [("● ", OUT_COLOR, "outbound: where data goes (size = connections)"),
                 ("● ", IN_COLOR, "a computer from this country connects to this PC"),
                 ("● ", HOME_COLOR, f"this PC ({self.home or 'region unknown'})")]
        if self.route:
            lines.append(("┅ ", ROUTE_COLOR, "route traced to a destination (numbers are the hops)"))
        if self.unlocated:
            lines.append(("", QColor(90, 90, 90), f"{self.unlocated} Internet connection(s) not located yet"))
        if self.precise:
            lines.append(("", QColor(90, 90, 90), f"Server locations: {geoip.ATTRIBUTION}"))
        else:
            lines.append(("", QColor(90, 90, 90), "Country where the network is registered (a CDN may serve you locally)"))
        lines.append(("", QColor(90, 90, 90), HINT))
        font = QFont(self.font())
        font.setPointSizeF(8.5)
        p.setFont(font)
        metrics = QFontMetricsF(font)
        h = 16
        width = min(self.width() - 16, max(metrics.horizontalAdvance(text) for _b, _c, text in lines) + 34)
        box = QRectF(8, self.height() - 10 - h * len(lines) - 8, width, h * len(lines) + 8)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(255, 255, 255, 215))
        p.drawRoundedRect(box, 4, 4)
        for i, (bullet, color, text) in enumerate(lines):
            y = box.top() + 4 + i * h
            p.setPen(color)
            p.drawText(QRectF(box.left() + 6, y, 14, h), Qt.AlignmentFlag.AlignVCenter, bullet)
            p.setPen(QColor(40, 40, 40))
            p.drawText(QRectF(box.left() + 20, y, box.width() - 24, h), Qt.AlignmentFlag.AlignVCenter, text)

    # endregion

    # region Hit tests and descriptions

    def place_at(self, pos: QPointF) -> Optional[PlaceTraffic]:
        best: Tuple[float, Optional[PlaceTraffic]] = (1e9, None)
        for d in self.places.values():
            at = self._place_point(d)
            if at is not None:
                dist = math.hypot(at.x() - pos.x(), at.y() - pos.y())
                if dist <= self._radius(d.connections) + 3 and dist < best[0]:
                    best = (dist, d)
        return best[1]

    def arc_at(self, pos: QPointF) -> Optional[PlaceTraffic]:
        """The link under the cursor (the nearest one when several are close)."""
        best: Tuple[float, Optional[PlaceTraffic]] = (1e9, None)
        for d, a, b in self._arcs():
            path = self._arc_path(a, b)
            limit = max(4.0, self._arc_width(d) / 2 + 3)
            for i in range(33):
                point = path.pointAtPercent(i / 32)
                dist = math.hypot(point.x() - pos.x(), point.y() - pos.y())
                if dist <= limit and dist < best[0]:
                    best = (dist, d)
        return best[1]

    def hop_at(self, pos: QPointF) -> Optional[RoutePoint]:
        for n, pt, _text in self._route_dots():
            if math.hypot(pt.x() - pos.x(), pt.y() - pos.y()) <= 7:
                return next(r for r in self.route if r[0] == n)
        return None

    def country_at(self, pos: QPointF) -> str:
        """Country under the cursor: markers first (small countries), then outlines."""
        place = self.place_at(pos)
        if place is not None:
            return place.country
        inverted, ok = self._transform().inverted()
        if ok:
            geo_pos = inverted.map(pos)
            for code, path in self.paths.items():
                if path.contains(geo_pos):
                    return code
        return ""

    def describe(self, code: str) -> str:
        c = geo.country(code)
        name = html.escape(c.name if c else code)
        d = self.data.get(code)
        if d is None:
            return f"{name}{' (this PC)' if code == self.home else ''}: no connection"
        parts = [f"<b>{name}</b>: {d.outbound} outbound, {d.inbound} inbound connection(s)"]
        parts += self._volume(d)
        parts += self._lists(d)
        return "<br>".join(parts)

    @staticmethod
    def _volume(d) -> list:
        """Bytes and current speed (they need administrator rights: nothing is said without them)."""
        parts = []
        if d.rate_in or d.rate_out:
            parts.append(f"Now: download {network.human_bytes(d.rate_in)}/s, upload {network.human_bytes(d.rate_out)}/s")
        if d.received or d.sent:
            parts.append(f"Received {network.human_bytes(d.received)}, sent {network.human_bytes(d.sent)}")
        return parts

    @staticmethod
    def _lists(d) -> list:
        # site names come from DNS / reverse DNS and owners from registries: escaped, never HTML
        dest = sorted(d.destinations)
        apps = sorted(a.split(" [")[0] for a in d.apps)
        addresses = sorted(d.addresses)
        lines = ["To: " + html.escape(", ".join(dest[:8])) + (f" +{len(dest) - 8}" if len(dest) > 8 else ""),
                 "Programs: " + html.escape(", ".join(apps[:8])) + (f" +{len(apps) - 8}" if len(apps) > 8 else "")]
        if addresses:
            lines.append("Addresses: " + html.escape(", ".join(addresses[:4]))
                         + (f" +{len(addresses) - 4}" if len(addresses) > 4 else ""))
        lines.append(f"<i>{html.escape(HINT)}</i>")
        return lines

    def describe_place(self, d: PlaceTraffic) -> str:
        if not d.precise:
            return self.describe(d.country)
        c = geo.country(d.country)
        parts = [f"<b>{html.escape(d.label)}</b>{', ' + html.escape(c.name) if c else ''}: "
                 f"{d.outbound} outbound, {d.inbound} inbound"]
        return "<br>".join(parts + self._volume(d) + self._lists(d))

    def describe_link(self, d: PlaceTraffic) -> str:
        """The traffic of the link between this PC and a node."""
        c = geo.country(d.country)
        name = d.label if d.precise else (c.name if c else d.country)
        parts = [f"<b>This PC → {html.escape(name)}</b>", f"{d.outbound} outbound, {d.inbound} inbound connection(s)"]
        if not (d.rate_in or d.rate_out or d.received or d.sent):
            parts.append("Volumes and speeds need administrator rights.")
        return "<br>".join(parts + self._volume(d) + self._lists(d))

    # endregion

    # region Interaction

    def _set_hover(self, hover: Optional[Tuple[str, object]]):
        if hover != self._hover:
            self._hover = hover
            self.setCursor(Qt.CursorShape.PointingHandCursor if hover else Qt.CursorShape.ArrowCursor)
            self.update()

    def mouseMoveEvent(self, event):
        pos = event.position()
        if self._drag is not None:
            delta = pos - self._drag
            if abs(delta.x()) + abs(delta.y()) > 2:
                self._dragged = True
                scale = self._transform().m11()
                self.center -= QPointF(delta.x() / scale, delta.y() / scale)
                self._drag = pos
                self.update()
            return
        place = self.place_at(pos)
        hop = None if place else self.hop_at(pos)
        arc = None if (place or hop) else self.arc_at(pos)
        self._set_hover(("place", place.key) if place else ("hop", hop[0]) if hop else
                        ("arc", arc.key) if arc else None)
        where = event.globalPosition().toPoint()
        if place is not None:
            QToolTip.showText(where, self.describe_place(place), self)
        elif hop is not None:
            QToolTip.showText(where, f"<b>Hop {hop[0]}</b>: {html.escape(hop[3])}", self)
        elif arc is not None:
            QToolTip.showText(where, self.describe_link(arc), self)
        else:
            code = self.country_at(pos)
            if code:
                QToolTip.showText(where, self.describe(code), self)
            else:
                QToolTip.hideText()

    def leaveEvent(self, event):
        self._set_hover(None)
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag, self._dragged = event.position(), False

    def mouseReleaseEvent(self, event):
        if event.button() != Qt.MouseButton.LeftButton or self._drag is None:
            return  # the release that ends a double-click has no press of its own
        dragged = self._dragged
        self._drag = None
        if dragged:
            return
        place = self.place_at(event.position())
        if place is not None and event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
            self._click_timer.stop()
            self._pending = None
            self.place_trace.emit(place)
            return
        # a click waits for the double-click delay: a double-click must not also list the connections of the node
        self._pending = event.position()
        self._click_timer.start(QApplication.doubleClickInterval())

    def flush_click(self):
        """Carry out the click that was waiting (its delay is over, or a test does not want to wait)."""
        self._click_timer.stop()
        pos, self._pending = self._pending, None
        if pos is None:
            return
        place = self.place_at(pos)
        if place is not None and place.precise:
            self.place_clicked.emit(place.label)
        else:
            code = self.country_at(pos)
            if code and code in self.data:
                self.country_clicked.emit(code)

    def mouseDoubleClickEvent(self, event):
        self._click_timer.stop()
        self._pending = None
        place = self.place_at(event.position())
        if place is not None:
            self.place_activated.emit(place)
        else:
            self.reset_view()

    def contextMenuEvent(self, event):
        pos = QPointF(event.pos())
        self.context_requested.emit(self.place_at(pos) or self.arc_at(pos), event.globalPos())

    def wheelEvent(self, event):
        steps = event.angleDelta().y() / 120
        if not steps:
            return
        old = self._transform()
        inverted, _ = old.inverted()
        anchor = inverted.map(event.position())  # keep the point under the cursor in place
        self.zoom = max(1.0, min(12.0, self.zoom * (1.25 ** steps)))
        new = self._transform()
        moved = new.map(anchor)
        scale = new.m11()
        self.center += QPointF((moved.x() - event.position().x()) / scale, (moved.y() - event.position().y()) / scale)
        self.update()

    # endregion
