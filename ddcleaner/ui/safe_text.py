"""Showing and exporting text that comes from outside the program (DNS, registries, drivers, event logs)."""

from PySide6.QtGui import Qt

CSV_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def plain(text) -> str:
    """For tooltips, labels and message boxes: Qt renders anything that looks like HTML as HTML, so a
    host name such as '<h1>Safe</h1>' would change what is displayed. This always shows the raw text."""
    return Qt.convertFromPlainText(str(text), Qt.WhiteSpaceMode.WhiteSpaceNormal)


def count(n: int, singular: str, plural: str = "") -> str:
    """'1 entry', '3 entries': the number with the right form of the word."""
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def listed(lines, limit: int = 10) -> str:
    """The first lines of a long list for a message box, then how many were left out."""
    lines = list(lines)
    return "\n".join(lines[:limit]) + (f"\n... and {len(lines) - limit} more" if len(lines) > limit else "")


def csv_cell(value):
    """Spreadsheets run cells starting with = + - @ as formulas (CSV injection): keep them as text."""
    if isinstance(value, str) and value.startswith(CSV_FORMULA_START):
        return "'" + value
    return value
