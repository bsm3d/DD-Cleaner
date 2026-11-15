"""World map of network destinations: countries, arcs from this PC, markers sized by connections."""

import html
import math
from typing import Dict, Optional, Tuple

from PySide6.QtWidgets import QWidget, QToolTip
from PySide6.QtCore import Qt, QPointF, QRectF, Signal
from PySide6.QtGui import QPainter, QPainterPath, QPen, QColor, QBrush, QTransform, QFont

from ddcleaner import geo, geoip, network
from ddcleaner.traffic import CountryTraffic, PlaceTraffic

LAT_TOP, LAT_BOTTOM = 84.0, -58.0
OCEAN = QColor(223, 234, 245)
LAND = QColor(245, 245, 242)
BORDER = QColor(180, 180, 180)
OUT_COLOR = QColor(0, 102, 204)
IN_COLOR = QColor(220, 30, 30)
HOME_COLOR = QColor(20, 140, 60)


class WorldMapWidget(QWidget):
    """Equirectangular map. Wheel: zoom, drag: pan, double click: reset, click on a country: country_clicked."""

    country_clicked = Signal(str)
    place_clicked = Signal(str)  # city label

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
        self.home = ""
        self.unlocated = 0
        self.zoom = 1.0
        self.center = QPointF(10.0, -(LAT_TOP + LAT_BOTTOM) / 2)  # lon, -lat at the widget center
        self._drag: Optional[QPointF] = None
        self._dragged = False

    # region Data and projection

    def set_data(self, data: Dict[str, CountryTraffic], home: str, unlocated: int,
                 places: Optional[Dict[str, PlaceTraffic]] = None):
        self.data, self.home, self.unlocated = data, home, unlocated
        if places is None:  # one marker per country
            places = {f"country:{d.code}": PlaceTraffic(f"country:{d.code}", d.code, d.code, None, None, False,
                                                        d.outbound, d.inbound, d.apps, d.destinations, d.received,
                                                        d.sent) for d in data.values()}
        self.places = places
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

    # endregion

    # region Painting

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
        ordered = sorted(self.places.values(), key=lambda d: d.connections)
        if home is not None:
            for d in ordered:
                target = self._place_point(d)
                if target is None or (not d.precise and d.country == self.home):
                    continue
                self._draw_arc(p, home, target, d)
        for d in ordered:
            target = self._place_point(d)
            if target is not None:
                self._draw_marker(p, target, d)
        if home is not None:
            p.setPen(QPen(Qt.GlobalColor.white, 2))
            p.setBrush(HOME_COLOR)
            p.drawEllipse(home, 6, 6)
        self._draw_legend(p)
        p.end()

    def _draw_arc(self, p: QPainter, a: QPointF, b: QPointF, d: PlaceTraffic):
        mid = (a + b) / 2
        dist = math.hypot(b.x() - a.x(), b.y() - a.y())
        control = QPointF(mid.x(), mid.y() - dist * 0.25)
        path = QPainterPath(a)
        path.quadTo(control, b)
        color = QColor(IN_COLOR if d.inbound else OUT_COLOR)
        color.setAlphaF(0.55)
        p.setPen(QPen(color, 1 + math.log2(1 + d.connections) * 0.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(path)

    def _draw_marker(self, p: QPainter, at: QPointF, d: PlaceTraffic):
        r = self._radius(d.connections)
        color = QColor(IN_COLOR if d.inbound else OUT_COLOR)
        fill = QColor(color)
        fill.setAlphaF(0.75)
        p.setPen(QPen(Qt.GlobalColor.white, 1.5))
        p.setBrush(fill)
        p.drawEllipse(at, r, r)
        p.setPen(QColor(30, 30, 30))
        font = QFont(self.font())
        font.setPointSizeF(8)
        font.setBold(True)
        p.setFont(font)
        name = d.label.split(" (")[0].split(",")[0] if d.precise else d.country
        p.drawText(QRectF(at.x() + r + 2, at.y() - 8, 160, 16), Qt.AlignmentFlag.AlignVCenter,
                   f"{name} {d.connections}")

    def _draw_legend(self, p: QPainter):
        lines = [("● ", OUT_COLOR, "outbound: where data goes (size = connections)"),
                 ("● ", IN_COLOR, "a computer from this country connects to this PC"),
                 ("● ", HOME_COLOR, f"this PC ({self.home or 'region unknown'})")]
        if self.unlocated:
            lines.append(("", QColor(90, 90, 90), f"{self.unlocated} Internet connection(s) not located yet"))
        if self.precise:
            lines.append(("", QColor(90, 90, 90), f"Server locations: {geoip.ATTRIBUTION}"))
        else:
            lines.append(("", QColor(90, 90, 90), "Country where the network is registered (a CDN may serve you locally)"))
        font = QFont(self.font())
        font.setPointSizeF(8.5)
        p.setFont(font)
        h = 16
        box = QRectF(8, self.height() - 10 - h * len(lines) - 8, 470, h * len(lines) + 8)
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

    # region Interaction

    def place_at(self, pos: QPointF) -> Optional[PlaceTraffic]:
        best: Tuple[float, Optional[PlaceTraffic]] = (1e9, None)
        for d in self.places.values():
            at = self._place_point(d)
            if at is not None:
                dist = math.hypot(at.x() - pos.x(), at.y() - pos.y())
                if dist <= self._radius(d.connections) + 3 and dist < best[0]:
                    best = (dist, d)
        return best[1]

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
        if d.received or d.sent:
            parts.append(f"Received {network.human_bytes(d.received)}, sent {network.human_bytes(d.sent)}")
        parts += self._lists(d)
        return "<br>".join(parts)

    @staticmethod
    def _lists(d) -> list:
        # site names come from DNS / reverse DNS and owners from registries: escaped, never HTML
        dest = sorted(d.destinations)
        apps = sorted(a.split(" [")[0] for a in d.apps)
        return ["To: " + html.escape(", ".join(dest[:8])) + (f" +{len(dest) - 8}" if len(dest) > 8 else ""),
                "Programs: " + html.escape(", ".join(apps[:8])) + (f" +{len(apps) - 8}" if len(apps) > 8 else ""),
                "<i>Click to show these connections</i>"]

    def describe_place(self, d: PlaceTraffic) -> str:
        if not d.precise:
            return self.describe(d.country)
        c = geo.country(d.country)
        parts = [f"<b>{html.escape(d.label)}</b>{', ' + html.escape(c.name) if c else ''}: "
                 f"{d.outbound} outbound, {d.inbound} inbound"]
        if d.received or d.sent:
            parts.append(f"Received {network.human_bytes(d.received)}, sent {network.human_bytes(d.sent)}")
        return "<br>".join(parts + self._lists(d))

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
        code = self.country_at(pos)
        if place is not None:
            QToolTip.showText(event.globalPosition().toPoint(), self.describe_place(place), self)
        elif code:
            QToolTip.showText(event.globalPosition().toPoint(), self.describe(code), self)
        else:
            QToolTip.hideText()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag, self._dragged = event.position(), False

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            if not self._dragged:
                place = self.place_at(event.position())
                if place is not None and place.precise:
                    self.place_clicked.emit(place.label)
                else:
                    code = self.country_at(event.position())
                    if code and code in self.data:
                        self.country_clicked.emit(code)
            self._drag = None

    def mouseDoubleClickEvent(self, event):
        self.zoom = 1.0
        self.center = QPointF(10.0, -(LAT_TOP + LAT_BOTTOM) / 2)
        self.update()

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
