#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DD Cleaner - entry point.
Driver scan, system health and security audit for Windows.
Author : Benoit (BSM) Saint-Moulin
Version 3.0

The application lives in the ddcleaner package; this module starts it.
"""

import ctypes
import os
import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from ddcleaner.common import harden_process_environment
from ddcleaner.ui.app_icon import APP_ID, load_icon
from ddcleaner.ui.main_window import MainWindow


def main():
    # before anything starts a child process: no user-controlled PSModulePath, PATH, windir...
    harden_process_environment()
    # Portable build: keep config and logs next to the exe (UAC elevation resets cwd to System32)
    if getattr(sys, 'frozen', False):
        os.chdir(os.path.dirname(sys.executable))

    try:  # own identity for the taskbar: a run from source would otherwise group under python.exe
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    except (AttributeError, OSError):
        pass

    app = QApplication(sys.argv)
    app.setWindowIcon(load_icon())
    app.setStyle('Fusion')  # Modern style
    try:  # every colour of the interface is written for a light background: do not follow a dark Windows theme
        app.styleHints().setColorScheme(Qt.ColorScheme.Light)
    except AttributeError:
        pass  # Qt older than 6.8: Fusion does not follow the system scheme there

    # Set application-wide stylesheet for better look
    app.setStyleSheet("""
        QMainWindow {
            background-color: #f0f0f0;
        }
        QGroupBox {
            font-weight: bold;
            border: 2px solid #cccccc;
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px;
        }
        QPushButton {
            padding: 6px 12px;
            border: 1px solid #0078d4;
            border-radius: 3px;
            background-color: #0078d4;
            color: white;
            min-width: 80px;
        }
        QPushButton:hover {
            background-color: #106ebe;
        }
        QPushButton:pressed {
            background-color: #005a9e;
        }
        QPushButton:disabled {
            background-color: #cccccc;
            border-color: #999999;
            color: #666666;
        }
        QTreeWidget {
            border: 1px solid #cccccc;
            border-radius: 3px;
        }
        QTreeWidget::item:selected {
            background-color: #0078d4;
            color: white;
        }
        QTreeWidget::item:hover {
            background-color: #e5f3ff;
        }
        QScrollBar:vertical {
            background: #dcdcdc;
            width: 16px;
            margin: 0;
        }
        QScrollBar:horizontal {
            background: #dcdcdc;
            height: 16px;
            margin: 0;
        }
        QScrollBar::handle {
            background: #7a7a7a;
            border-radius: 4px;
            margin: 2px;
        }
        QScrollBar::handle:vertical {
            min-height: 30px;
        }
        QScrollBar::handle:horizontal {
            min-width: 30px;
        }
        QScrollBar::handle:hover {
            background: #5a5a5a;
        }
        QScrollBar::handle:pressed {
            background: #0078d4;
        }
        QScrollBar::add-line, QScrollBar::sub-line {
            width: 0;
            height: 0;
        }
        QScrollBar::add-page, QScrollBar::sub-page {
            background: none;
        }
        QProgressBar {
            border: 1px solid #cccccc;
            border-radius: 3px;
            text-align: center;
            height: 20px;
        }
        QProgressBar::chunk {
            background-color: #0078d4;
        }
    """)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
