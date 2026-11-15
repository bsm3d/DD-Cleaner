"""Small chart widgets drawn with QPainter (no extra library): horizontal bars, stacked bars and columns.

They read their text color from the palette, so they stay readable in light and dark themes.
"""

from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from PySide6.QtCore import QRectF, QSize, Qt
from PySide6.QtGui import QColor, QFont, QFontMetrics, QPainter, QPalette
from PySide6.QtWidgets import QWidget

BLUE, ORANGE, GREEN = QColor(59, 130, 246), QColor(245, 158, 11), QColor(34, 160, 90)
RED, GREY, VIOLET = QColor(220, 60, 60), QColor(148, 163, 184), QColor(139, 92, 246)
ROW_HEIGHT, TITLE_HEIGHT, PAD = 26, 28, 8


@dataclass
class Bar:
    label: str
    value: float
    text: str = ""
    color: Optional[QColor] = None


@dataclass
class Segment:
    value: float
    color: QColor
    name: str = ""


@dataclass
class StackRow:
    label: str
    segments: List[Segment]
    text: str = ""


class _Chart(QWidget):
    EMPTY_TEXT = "Nothing to show yet"

    def __init__(self, title: str = "", parent=None):
        super().__init__(parent)
        self.title = title

    def _text_color(self) -> QColor:
        return self.palette().color(QPalette.ColorRole.WindowText)

    def _track_color(self) -> QColor:
        color = self.palette().color(QPalette.ColorRole.Mid)
        color.setAlpha(70)
        return color

    def _draw_title(self, painter: QPainter):
        if self.title:
            font = QFont(self.font())
            font.setBold(True)
            painter.setFont(font)
            painter.setPen(self._text_color())
            painter.drawText(QRectF(0, 0, self.width(), TITLE_HEIGHT), Qt.AlignmentFlag.AlignVCenter, self.title)
            painter.setFont(self.font())

    def _draw_empty(self, painter: QPainter):
        painter.setPen(self.palette().color(QPalette.ColorRole.PlaceholderText))
        painter.drawText(QRectF(0, TITLE_HEIGHT, self.width(), 40), Qt.AlignmentFlag.AlignCenter, self.EMPTY_TEXT)

    def row_count(self) -> int:
        raise NotImplementedError

    def sizeHint(self) -> QSize:
        return QSize(420, TITLE_HEIGHT + max(self.row_count(), 1) * ROW_HEIGHT + PAD)

    def minimumSizeHint(self) -> QSize:
        return QSize(240, self.sizeHint().height())


class BarChart(_Chart):
    """One horizontal bar per row, scaled to the biggest value. A row can carry its own color."""

    def __init__(self, title: str = "", color: QColor = BLUE, parent=None):
        super().__init__(title, parent)
        self.color, self.rows = color, []

    def set_rows(self, rows: Sequence[Bar]):
        self.rows = list(rows)
        self.updateGeometry()
        self.update()

    def row_count(self) -> int:
        return len(self.rows)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._draw_title(painter)
        if not self.rows:
            self._draw_empty(painter)
            return
        metrics = QFontMetrics(self.font())
        label_w = min(max(metrics.horizontalAdvance(r.label) for r in self.rows) + PAD, self.width() * 0.38)
        text_w = max(metrics.horizontalAdvance(r.text) for r in self.rows) + PAD
        bar_w = max(self.width() - label_w - text_w - PAD, 20)
        peak = max((r.value for r in self.rows), default=0) or 1
        for index, row in enumerate(self.rows):
            top = TITLE_HEIGHT + index * ROW_HEIGHT
            painter.setPen(self._text_color())
            painter.drawText(QRectF(0, top, label_w - PAD, ROW_HEIGHT), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                             metrics.elidedText(row.label, Qt.TextElideMode.ElideMiddle, int(label_w - PAD)))
            track = QRectF(label_w, top + 5, bar_w, ROW_HEIGHT - 10)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(self._track_color())
            painter.drawRoundedRect(track, 3, 3)
            painter.setBrush(row.color or self.color)
            fill = QRectF(track.left(), track.top(), max(track.width() * row.value / peak, 2 if row.value > 0 else 0), track.height())
            painter.drawRoundedRect(fill, 3, 3)
            painter.setPen(self._text_color())
            painter.drawText(QRectF(label_w + bar_w + PAD, top, text_w, ROW_HEIGHT), Qt.AlignmentFlag.AlignVCenter, row.text)


class StackedBarChart(_Chart):
    """Each row is one full-width bar cut into colored segments (a disk: used, garbage found, free)."""

    def __init__(self, title: str = "", parent=None):
        super().__init__(title, parent)
        self.rows, self.legend = [], []

    def set_rows(self, rows: Sequence[StackRow], legend: Sequence[Tuple[str, QColor]] = ()):
        self.rows, self.legend = list(rows), list(legend)
        self.updateGeometry()
        self.update()

    def row_count(self) -> int:
        return len(self.rows) + (1 if self.legend else 0)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._draw_title(painter)
        if not self.rows:
            self._draw_empty(painter)
            return
        metrics = QFontMetrics(self.font())
        label_w = max(metrics.horizontalAdvance(r.label) for r in self.rows) + PAD * 2
        text_w = max(metrics.horizontalAdvance(r.text) for r in self.rows) + PAD
        bar_w = max(self.width() - label_w - text_w - PAD, 20)
        for index, row in enumerate(self.rows):
            top = TITLE_HEIGHT + index * ROW_HEIGHT
            painter.setPen(self._text_color())
            painter.drawText(QRectF(0, top, label_w - PAD, ROW_HEIGHT), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, row.label)
            total = sum(s.value for s in row.segments) or 1
            left = label_w
            painter.setPen(Qt.PenStyle.NoPen)
            for segment in row.segments:
                width = bar_w * segment.value / total
                if segment.value > 0:
                    painter.setBrush(segment.color)
                    painter.drawRect(QRectF(left, top + 4, max(width, 2), ROW_HEIGHT - 8))
                left += width
            painter.setPen(self._text_color())
            painter.drawText(QRectF(label_w + bar_w + PAD, top, text_w, ROW_HEIGHT), Qt.AlignmentFlag.AlignVCenter, row.text)
        if self.legend:
            top = TITLE_HEIGHT + len(self.rows) * ROW_HEIGHT
            left = label_w
            for name, color in self.legend:
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(color)
                painter.drawRect(QRectF(left, top + 8, 10, 10))
                painter.setPen(self._text_color())
                width = metrics.horizontalAdvance(name)
                painter.drawText(QRectF(left + 14, top, width + PAD, ROW_HEIGHT), Qt.AlignmentFlag.AlignVCenter, name)
                left += 14 + width + PAD * 2


class ColumnChart(_Chart):
    """Vertical columns over time (bytes freed per day). Labels are thinned out to stay readable."""

    HEIGHT = 150

    def __init__(self, title: str = "", color: QColor = GREEN, parent=None):
        super().__init__(title, parent)
        self.color, self.values, self.caption = color, [], ""

    def set_values(self, values: Sequence[Tuple[str, float]], caption: str = ""):
        self.values, self.caption = list(values), caption
        self.update()

    def row_count(self) -> int:
        return (self.HEIGHT - PAD) // ROW_HEIGHT

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._draw_title(painter)
        if not self.values or not any(v for _l, v in self.values):
            self._draw_empty(painter)
            return
        metrics = QFontMetrics(self.font())
        area = QRectF(PAD, TITLE_HEIGHT + 4, self.width() - 2 * PAD, self.height() - TITLE_HEIGHT - 4 - metrics.height() - PAD)
        peak = max(v for _l, v in self.values) or 1
        slot = area.width() / len(self.values)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(self.color)
        for index, (_label, value) in enumerate(self.values):
            if value <= 0:
                continue
            height = max(area.height() * value / peak, 2)
            painter.drawRoundedRect(QRectF(area.left() + index * slot + slot * 0.15, area.bottom() - height, slot * 0.7, height), 2, 2)
        painter.setPen(self._text_color())
        step = max(1, int(metrics.horizontalAdvance("00-00") * 1.4 / max(slot, 1)) + 1)
        for index, (label, _value) in enumerate(self.values):
            if index % step == 0 or index == len(self.values) - 1:
                painter.drawText(QRectF(area.left() + index * slot - slot, area.bottom() + 2, slot * 3, metrics.height()),
                                 Qt.AlignmentFlag.AlignHCenter, label)
        if self.caption:
            painter.drawText(QRectF(0, 0, self.width() - PAD, TITLE_HEIGHT), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, self.caption)
