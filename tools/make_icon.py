"""Draws the DD Cleaner icon and writes ddcleaner/data/dd_cleaner.png (256 px) and dd_cleaner.ico (16 to 256 px).

Run it again after changing the drawing: python tools/make_icon.py
Only PySide6 is needed. Small sizes are BMP frames and the 256 px one is PNG, the layout every Windows version reads.
"""

import os
import struct
import sys

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QRectF, Qt
from PySide6.QtGui import (QBrush, QColor, QGuiApplication, QImage, QLinearGradient, QPainter, QPainterPath, QPen,
                           QPolygonF)

SIZES = (16, 24, 32, 48, 64, 128, 256)
CANVAS = 1024
RED = QColor(229, 50, 45)
DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ddcleaner", "data")


def shield_path() -> QPainterPath:
    path = QPainterPath(QPointF(512, 150))
    path.cubicTo(600, 215, 700, 240, 790, 240)
    path.lineTo(790, 520)
    path.cubicTo(790, 700, 660, 820, 512, 890)
    path.cubicTo(364, 820, 234, 700, 234, 520)
    path.lineTo(234, 240)
    path.cubicTo(324, 240, 424, 215, 512, 150)
    path.closeSubpath()
    return path


def sparkle(painter: QPainter, cx: float, cy: float, radius: float):
    """A four-point star: the 'clean' glint."""
    inner = radius * 0.22
    points = QPolygonF([QPointF(cx, cy - radius), QPointF(cx + inner, cy - inner), QPointF(cx + radius, cy),
                        QPointF(cx + inner, cy + inner), QPointF(cx, cy + radius), QPointF(cx - inner, cy + inner),
                        QPointF(cx - radius, cy), QPointF(cx - inner, cy - inner)])
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(255, 255, 255))
    painter.drawPolygon(points)


def draw() -> QImage:
    image = QImage(CANVAS, CANVAS, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    tile = QLinearGradient(0, 40, 0, 984)
    tile.setColorAt(0, QColor(38, 41, 49))
    tile.setColorAt(1, QColor(12, 13, 16))
    painter.setPen(QPen(QColor(255, 255, 255, 38), 8))
    painter.setBrush(QBrush(tile))
    painter.drawRoundedRect(QRectF(44, 44, 936, 936), 210, 210)

    shield = QLinearGradient(0, 150, 0, 890)
    shield.setColorAt(0, QColor(255, 255, 255))
    shield.setColorAt(1, QColor(208, 213, 221))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QBrush(shield))
    painter.drawPath(shield_path())

    check = QPainterPath(QPointF(366, 522))
    check.lineTo(480, 636)
    check.lineTo(672, 388)
    painter.setPen(QPen(RED, 92, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawPath(check)

    sparkle(painter, 858, 178, 92)
    sparkle(painter, 176, 812, 46)
    painter.end()
    return image


def png_bytes(image: QImage) -> bytes:
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    image.save(buffer, "PNG")
    return bytes(data)


def bmp_frame(image: QImage) -> bytes:
    """An ICO BMP frame: BITMAPINFOHEADER (height doubled), bottom-up BGRA pixels, then an empty AND mask."""
    size = image.width()
    image = image.convertToFormat(QImage.Format.Format_ARGB32)
    rows = []
    for y in range(size - 1, -1, -1):
        rows.append(bytes(image.constScanLine(y))[:size * 4])
    mask_row = ((size + 31) // 32) * 4
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, size * size * 4 + mask_row * size, 0, 0, 0, 0)
    return header + b"".join(rows) + bytes(mask_row * size)


def ico_bytes(frames) -> bytes:
    """frames: [(size, payload)]"""
    out = [struct.pack("<HHH", 0, 1, len(frames))]
    offset = 6 + 16 * len(frames)
    for size, payload in frames:
        out.append(struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(payload), offset))
        offset += len(payload)
    return b"".join(out) + b"".join(payload for _s, payload in frames)


def main():
    QGuiApplication.instance() or QGuiApplication(sys.argv)
    master = draw()
    frames = []
    for size in SIZES:
        scaled = master.scaled(size, size, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
        frames.append((size, png_bytes(scaled) if size == 256 else bmp_frame(scaled)))
        if size == 256:
            os.makedirs(DATA, exist_ok=True)
            with open(os.path.join(DATA, "dd_cleaner.png"), "wb") as f:
                f.write(png_bytes(scaled))
    with open(os.path.join(DATA, "dd_cleaner.ico"), "wb") as f:
        f.write(ico_bytes(frames))
    if "--preview" in sys.argv:  # a 512 px picture to look at: python tools/make_icon.py --preview folder
        folder = sys.argv[sys.argv.index("--preview") + 1]
        master.scaled(512, 512, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation).save(
            os.path.join(folder, "dd_cleaner_preview.png"))
    print("written to", DATA)


if __name__ == "__main__":
    main()
