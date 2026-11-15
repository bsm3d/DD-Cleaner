"""The application icon: the generated files, their use by the build scripts and by the window."""

import os
import struct
import sys

import pytest
from PySide6.QtGui import QColor, QImage

from ddcleaner.ui import app_icon

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import make_icon  # noqa: E402

ICO = os.path.join(ROOT, "ddcleaner", "data", "dd_cleaner.ico")
PNG = os.path.join(ROOT, "ddcleaner", "data", "dd_cleaner.png")


def read_ico(data: bytes):
    reserved, kind, count = struct.unpack_from("<HHH", data, 0)
    assert (reserved, kind) == (0, 1)
    frames = []
    for i in range(count):
        width, height, _colors, _res, planes, bits, length, offset = struct.unpack_from("<BBBBHHII", data, 6 + 16 * i)
        frames.append(((width or 256, height or 256), planes, bits, data[offset:offset + length]))
    return frames


def test_the_ico_holds_every_size_windows_asks_for():
    frames = read_ico(open(ICO, "rb").read())
    assert [f[0] for f in frames] == [(s, s) for s in (16, 24, 32, 48, 64, 128, 256)]
    assert all(planes == 1 and bits == 32 for _s, planes, bits, _d in frames)


def test_small_frames_are_bmp_and_the_big_one_is_png():
    for (width, _h), _p, _b, payload in read_ico(open(ICO, "rb").read()):
        if width == 256:
            assert payload[:8] == b"\x89PNG\r\n\x1a\n"
        else:
            size, w, h = struct.unpack_from("<Iii", payload, 0)
            assert (size, w, h) == (40, width, width * 2)                      # BMP header, height doubled
            assert len(payload) == 40 + width * width * 4 + ((width + 31) // 32 * 4) * width


def test_the_png_is_256_pixels_with_transparent_corners_and_the_brand_colors(qapp):
    image = QImage(PNG)
    assert (image.width(), image.height()) == (256, 256) and image.hasAlphaChannel()
    assert image.pixelColor(0, 0).alpha() == 0 and image.pixelColor(255, 255).alpha() == 0
    assert image.pixelColor(128, 128).alpha() == 255
    colors = {QColor(image.pixel(x, y)).name() for x in range(0, 256, 2) for y in range(0, 256, 2)}
    reds = [c for c in colors if int(c[1:3], 16) > 200 and int(c[3:5], 16) < 90 and int(c[5:7], 16) < 90]
    assert reds                                                               # the red check
    assert any(int(c[1:3], 16) > 235 and int(c[3:5], 16) > 235 for c in colors)  # the white shield


def test_the_drawing_is_reproducible_and_the_files_come_from_it(qapp):
    master = make_icon.draw()
    assert master.width() == 1024 and master.pixelColor(0, 0).alpha() == 0
    assert make_icon.png_bytes(master.scaled(256, 256)) [:4] == b"\x89PNG"
    packed = make_icon.ico_bytes([(16, b"x" * 10), (256, b"y" * 20)])
    assert read_ico(packed)[1][0] == (256, 256) and read_ico(packed)[0][3] == b"x" * 10


def test_the_window_icon_loads(qapp):
    assert os.path.isfile(app_icon.ICON_PATH) and not app_icon.load_icon().isNull()
    assert app_icon.APP_ID.startswith("BSM.")


def test_the_builds_use_the_icon():
    spec = open(os.path.join(ROOT, "DD_Cleaner.spec"), encoding="utf-8").read()
    installer = open(os.path.join(ROOT, "DD_Cleaner.iss"), encoding="utf-8").read()
    assert "icon=['ddcleaner/data/dd_cleaner.ico']" in spec and "ddcleaner/data/dd_cleaner.png" in spec
    assert "SetupIconFile=ddcleaner\\data\\dd_cleaner.ico" in installer
    assert os.path.isfile(ICO) and os.path.isfile(PNG)


def test_the_entry_point_sets_the_icon_and_the_taskbar_identity():
    source = open(os.path.join(ROOT, "DD_Cleaner.py"), encoding="utf-8").read()
    assert "app.setWindowIcon(load_icon())" in source and "SetCurrentProcessExplicitAppUserModelID(APP_ID)" in source


def test_every_main_window_shows_the_icon(window):  # noqa: F811
    window.setWindowIcon(app_icon.load_icon())
    assert not window.windowIcon().isNull()


from test_ui_smoke import dialogs, window  # noqa: E402,F401,F811  (fixtures)
