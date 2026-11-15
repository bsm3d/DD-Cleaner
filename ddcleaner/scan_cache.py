"""Memory of what ClamAV already found clean, so the next scan can skip files that did not change.

A file is skipped only when ALL of this holds: it was reported clean by a scan, its size and modification time (to the
nanosecond) are the same, that scan used at least the same options (archives, heuristics, PUA, thorough) as the one
being planned, and the result is recent (a few days). The trade-off is explicit and chosen by the user: a file that is
unchanged but that new signatures would now flag is only caught when its entry expires or when the cache is off.

The file lives in the protected ClamAV folder: a cache a standard program could edit could hide a file from the scan.
"""

import logging
import os
import sqlite3
import time
from typing import Iterable, Optional

NAME = "scan_cache.sqlite"
FLAG_ARCHIVES, FLAG_HEURISTICS, FLAG_PUA, FLAG_THOROUGH = 1, 2, 4, 8
BATCH = 2000

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    path TEXT PRIMARY KEY, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
    clean INTEGER NOT NULL DEFAULT 0, flags INTEGER NOT NULL DEFAULT 0, scanned REAL NOT NULL DEFAULT 0)
"""


def key_of(path: str) -> str:
    """The form a path is stored under (case-insensitive, normalized)."""
    return os.path.normcase(os.path.abspath(path))


class ScanCache:
    """SQLite file. Use one instance per thread."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        try:
            self.db = self._open()
        except sqlite3.DatabaseError:
            logging.warning("Scan cache unreadable: starting a new one")
            self._remove_files()
            self.db = self._open()

    def _open(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")
            db.execute(SCHEMA)
            db.execute("SELECT COUNT(*) FROM files").fetchone()
            db.commit()
        except sqlite3.DatabaseError:
            db.close()  # Windows cannot delete a file that is still open
            raise
        return db

    def _remove_files(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.path + suffix)
            except OSError:
                pass

    def close(self):
        try:
            self.db.commit()
            self.db.close()
        except sqlite3.Error:
            pass

    # region Reading

    def is_clean(self, key: str, size: int, mtime_ns: int, flags: int, max_age_days: float,
                 now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        row = self.db.execute("SELECT size, mtime_ns, clean, flags, scanned FROM files WHERE path = ?", (key,)).fetchone()
        if row is None:
            return False
        r_size, r_mtime, r_clean, r_flags, r_scanned = row
        return bool(r_clean and r_size == size and r_mtime == mtime_ns and r_flags & flags == flags
                    and now - r_scanned <= max_age_days * 86400)

    def count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM files WHERE clean = 1").fetchone()[0]

    # endregion

    # region Writing

    def mark_pending(self, rows: Iterable[tuple]):
        """(key, size, mtime_ns) of files about to be scanned. A pending entry is never skipped; it becomes clean
        only if the scan reports the file clean, and only for the size and time seen BEFORE the scan."""
        self.db.executemany("INSERT OR REPLACE INTO files (path, size, mtime_ns, clean, flags, scanned) "
                            "VALUES (?, ?, ?, 0, 0, 0)", rows)
        self.db.commit()

    def mark_clean(self, keys: Iterable[str], flags: int, now: Optional[float] = None):
        now = time.time() if now is None else now
        self.db.executemany("UPDATE files SET clean = 1, flags = ?, scanned = ? WHERE path = ? AND clean = 0",
                            ((flags, now, k) for k in keys))
        self.db.commit()

    def prune(self, older_than_days: float, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        cursor = self.db.execute("DELETE FROM files WHERE clean = 0 OR scanned < ?", (now - older_than_days * 86400,))
        self.db.commit()
        return cursor.rowcount

    def clear(self):
        self.db.execute("DELETE FROM files")
        self.db.commit()

    # endregion
