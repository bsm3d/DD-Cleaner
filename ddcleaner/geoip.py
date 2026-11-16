"""
Server locations from DB-IP "IP to City Lite" (CC BY 4.0, https://db-ip.com): a MaxMind DB (.mmdb) file,
downloaded on request (about 60 MB compressed) and read here with a small pure-Python reader
(no dependency; the file is memory-mapped, lookups are cached).

Attribution required by the license: "IP Geolocation by DB-IP".
"""

import gzip
import ipaddress
import json
import logging
import mmap
import os
import struct
import threading
import time
import urllib.parse
import urllib.request
import weakref
from dataclasses import dataclass
from datetime import date, datetime
from functools import lru_cache
from typing import Any, Callable, Dict, Optional, Tuple

from ddcleaner.common import data_dir

ATTRIBUTION = "IP Geolocation by DB-IP (db-ip.com, CC BY 4.0)"
DOWNLOAD_URL = "https://download.db-ip.com/free/dbip-city-lite-{month}.mmdb.gz"
FILE_NAME = "dbip-city-lite.mmdb"
MAX_SIZE = 600 * 1024 * 1024
METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"
UPDATE_AFTER_DAYS = 40
MAX_DEPTH = 32
MAX_DECODED_ITEMS = 100_000   # one DB-IP record is a few dozen items
REPLACE_TRIES, REPLACE_WAIT = 5, 0.5   # another program (an antivirus) may hold the new file for a moment
_locators = weakref.WeakSet()  # every GeoIP alive: they must let go of the file before an update replaces it


def get_geoip_dir() -> str:
    return os.path.join(data_dir(), "geoip")


class MMDBError(ValueError):
    pass


# region MaxMind DB reader

class MMDBReader:
    """Minimal reader for the MaxMind DB format (https://maxmind.github.io/MaxMind-DB/)."""

    def __init__(self, path: str):
        self._file = open(path, "rb")
        try:
            self._buf = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            self._file.close()
            raise MMDBError("empty database file")
        start = self._buf.rfind(METADATA_MARKER, max(0, len(self._buf) - 128 * 1024))
        if start < 0:
            self.close()
            raise MMDBError("not a MaxMind DB file")
        self._data_start = 0
        self._data_end = start  # the data section ends where the metadata marker starts
        meta_start = start + len(METADATA_MARKER)
        try:
            self.metadata, _ = self._decode(meta_start, base=meta_start, end=len(self._buf))
            self.node_count = int(self.metadata["node_count"])
            self.record_size = int(self.metadata["record_size"])
            self.ip_version = int(self.metadata["ip_version"])
        except (KeyError, TypeError, ValueError, IndexError, struct.error, RecursionError, MMDBError) as e:
            self.close()
            raise MMDBError(f"invalid metadata ({e})")
        if self.record_size not in (24, 28, 32) or self.ip_version not in (4, 6):
            self.close()
            raise MMDBError(f"unsupported record size {self.record_size} / IP version {self.ip_version}")
        self._node_bytes = self.record_size // 4
        self._tree_size = self._node_bytes * self.node_count
        self._data_start = self._tree_size + 16
        if self.node_count <= 0 or self._data_start > self._data_end:
            self.close()
            raise MMDBError("search tree larger than the file")
        self._ipv4_start = 0
        if self.ip_version == 6:
            node = 0
            for _ in range(96):
                if node >= self.node_count:
                    break
                node = self._read_node(node, 0)
            self._ipv4_start = node

    def close(self):
        try:
            self._buf.close()
        except (AttributeError, ValueError):
            pass
        self._file.close()

    def _read_node(self, node: int, bit: int) -> int:
        off = node * self._node_bytes
        b = self._buf[off:off + self._node_bytes]
        if self.record_size == 24:
            return int.from_bytes(b[3:6] if bit else b[0:3], "big")
        if self.record_size == 28:
            if bit:
                return ((b[3] & 0x0F) << 24) | int.from_bytes(b[4:7], "big")
            return ((b[3] & 0xF0) << 20) | int.from_bytes(b[0:3], "big")
        return int.from_bytes(b[4:8] if bit else b[0:4], "big")

    def lookup(self, addr: str) -> Optional[Dict[str, Any]]:
        ip = ipaddress.ip_address(addr.split("%")[0])
        if ip.version == 6 and self.ip_version == 4:
            return None
        packed = ip.packed
        bits = len(packed) * 8
        node = self._ipv4_start if ip.version == 4 and self.ip_version == 6 else 0
        for i in range(bits):
            if node >= self.node_count:
                break
            bit = (packed[i >> 3] >> (7 - (i & 7))) & 1
            node = self._read_node(node, bit)
        if node == self.node_count:
            return None  # no data for this address
        if node < self.node_count:
            raise MMDBError("invalid search tree")
        offset = node - self.node_count - 16
        value, _ = self._decode(self._data_start + offset, base=self._data_start, end=self._data_end)
        return value

    def _decode(self, pos: int, base: int, end: Optional[int] = None, depth: int = 0,
                budget: Optional[list] = None) -> Tuple[Any, int]:
        """Decode one value. The file may have been tampered with: every read is bounded, pointers may not
        point to pointers (spec) and nesting / total decoded items are capped (pointer fan-out, loops)."""
        end = self._data_end if end is None else end
        budget = budget if budget is not None else [MAX_DECODED_ITEMS]
        budget[0] -= 1
        if budget[0] < 0 or depth > MAX_DEPTH:
            raise MMDBError("data section too deep or too large")
        buf = self._buf

        def take(n: int) -> bytes:
            if n < 0 or pos + n > end:
                raise MMDBError("value past the end of its section")
            return buf[pos:pos + n]

        if not base <= pos < end:
            raise MMDBError("offset outside its section")
        ctrl = buf[pos]
        pos += 1
        kind = ctrl >> 5
        if kind == 1:  # pointer
            ss, vvv = (ctrl >> 3) & 3, ctrl & 7
            raw = take(ss + 1)
            if ss == 0:
                ptr = (vvv << 8) | raw[0]
            elif ss == 1:
                ptr = ((vvv << 16) | int.from_bytes(raw, "big")) + 2048
            elif ss == 2:
                ptr = ((vvv << 24) | int.from_bytes(raw, "big")) + 526336
            else:
                ptr = int.from_bytes(raw, "big")
            pos += ss + 1
            target = base + ptr
            if not base <= target < end or buf[target] >> 5 == 1:
                raise MMDBError("invalid pointer")
            value, _ = self._decode(target, base, end, depth + 1, budget)
            return value, pos
        if kind == 0:  # extended type
            kind = 7 + take(1)[0]
            pos += 1
        size = ctrl & 0x1F
        if size >= 29:
            extra = size - 28
            raw = take(extra)
            size = (29, 285, 65821)[extra - 1] + int.from_bytes(raw, "big")
            pos += extra

        if kind == 2:
            return take(size).decode("utf-8", errors="replace"), pos + size
        if kind == 3:
            return struct.unpack(">d", take(8))[0], pos + 8
        if kind == 4:
            return bytes(take(size)), pos + size
        if kind in (5, 6, 9, 10):
            if size > 16:
                raise MMDBError("integer too long")
            return int.from_bytes(take(size), "big"), pos + size
        if kind == 8:
            if size > 4:
                raise MMDBError("int32 too long")
            return int.from_bytes(take(size).rjust(4, b"\0"), "big", signed=True), pos + size
        if kind == 7:
            out = {}
            for _ in range(size):
                key, pos = self._decode(pos, base, end, depth + 1, budget)
                out[key], pos = self._decode(pos, base, end, depth + 1, budget)
            return out, pos
        if kind == 11:
            items = []
            for _ in range(size):
                item, pos = self._decode(pos, base, end, depth + 1, budget)
                items.append(item)
            return items, pos
        if kind == 14:
            return bool(size), pos
        if kind == 15:
            return struct.unpack(">f", take(4))[0], pos + 4
        if kind in (12, 13):
            return None, pos
        raise MMDBError(f"unknown data type {kind}")

# endregion


# region Locations

@dataclass(frozen=True)
class Location:
    country: str        # ISO code
    city: str
    region: str
    lat: float
    lon: float

    @property
    def label(self) -> str:
        return ", ".join(p for p in (self.city, self.country) if p)


def location_from_record(record: Optional[Dict]) -> Optional[Location]:
    if not isinstance(record, dict) or "location" not in record:
        return None
    loc = record.get("location") or {}
    try:
        lat, lon = float(loc["latitude"]), float(loc["longitude"])
    except (KeyError, TypeError, ValueError):
        return None
    names = lambda d: ((d or {}).get("names") or {}).get("en", "")  # noqa: E731
    subdivisions = record.get("subdivisions") or [{}]
    return Location((record.get("country") or {}).get("iso_code", ""), names(record.get("city")),
                    names(subdivisions[0]), lat, lon)


class GeoIP:
    """Opens the downloaded database lazily; locate() returns None when it is missing."""

    def __init__(self, folder: Optional[str] = None):
        self.folder = folder
        self._reader: Optional[MMDBReader] = None
        self._opened_mtime = None
        self._cache: Dict[str, Optional[Location]] = {}
        self._lock = threading.RLock()  # lookups run in the traffic thread, an update suspends from another one
        self._suspended = False
        _locators.add(self)

    @property
    def path(self) -> str:
        return os.path.join(self.folder or get_geoip_dir(), FILE_NAME)

    def _open(self) -> Optional[MMDBReader]:
        if self._suspended:
            return None
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return None
        if mtime != self._opened_mtime:  # first use, or the file was updated
            self.close()
            self._opened_mtime = mtime  # also on failure: a broken file is not retried on every lookup
            try:
                self._reader = MMDBReader(self.path)
            except Exception as e:  # a corrupted or crafted file must never stop the traffic view
                logging.error(f"GeoIP database unusable: {e}")
                self._reader = None
        return self._reader

    @property
    def available(self) -> bool:
        with self._lock:
            return self._open() is not None

    def locate(self, addr: str) -> Optional[Location]:
        with self._lock:
            if addr in self._cache:
                return self._cache[addr]
            reader = self._open()
            if reader is None:
                return None
            try:
                loc = location_from_record(reader.lookup(addr))
            except Exception:  # corrupted / crafted data section
                loc = None
            self._cache[addr] = loc
            return loc

    def info(self) -> Dict:
        try:
            with open(os.path.join(self.folder or get_geoip_dir(), "geoip.json"), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def close(self):
        with self._lock:
            if self._reader is not None:
                self._reader.close()
                self._reader = None
            self._cache.clear()

    def suspend(self):
        """Let go of the database file and stay away from it: Windows refuses to replace a file that is
        memory-mapped. Lookups answer None until resume()."""
        with self._lock:
            self._suspended = True
            self.close()

    def resume(self):
        with self._lock:
            self._suspended = False
            self._opened_mtime = None  # open the file again at the next lookup

# endregion


# region Download

def candidate_months(today: Optional[date] = None):
    """This month's file, then last month's (the new file appears on the 1st)."""
    today = today or date.today()
    prev = date(today.year - 1, 12, 1) if today.month == 1 else date(today.year, today.month - 1, 1)
    return [today.strftime("%Y-%m"), prev.strftime("%Y-%m")]


def download_dbip(folder: Optional[str] = None, progress: Optional[Callable[[int], None]] = None,
                  opener: Callable = urllib.request.urlopen, today: Optional[date] = None) -> Dict:
    """Download, decompress, validate and install the database (atomic replace). Returns its info."""
    folder = folder or get_geoip_dir()
    os.makedirs(folder, exist_ok=True)
    target = os.path.join(folder, FILE_NAME)
    tmp = target + ".download"
    last_error = None
    for month in candidate_months(today):
        url = DOWNLOAD_URL.format(month=month)
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "DDCleaner/3.0 (GeoIP update)"})
            with opener(request, timeout=60) as resp:
                final = resp.geturl()
                host = (urllib.parse.urlparse(final).hostname or "").lower()
                if urllib.parse.urlparse(final).scheme != "https" or not (host == "db-ip.com" or host.endswith(".db-ip.com")):
                    raise ValueError(f"unexpected download location: {final}")
                written = 0
                with gzip.GzipFile(fileobj=resp) as gz, open(tmp, "wb") as out:
                    while True:
                        chunk = gz.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > MAX_SIZE:
                            raise ValueError("database larger than expected")
                        out.write(chunk)
                        if progress:
                            progress(written)
            reader = MMDBReader(tmp)  # must be a valid city database before replacing the old one
            try:
                db_type = str(reader.metadata.get("database_type", ""))
                probe = location_from_record(reader.lookup("8.8.8.8"))
            finally:
                reader.close()
            if "city" not in db_type.lower() or probe is None:
                raise ValueError(f"unexpected database content ({db_type})")
            _install(tmp, target)
            info = {"month": month, "downloaded": datetime.now().isoformat(timespec="seconds"),
                    "source": final, "database_type": db_type, "attribution": ATTRIBUTION}
            with open(os.path.join(folder, "geoip.json"), "w", encoding="utf-8") as f:
                json.dump(info, f, indent=2)
            logging.info(f"DB-IP City Lite {month} installed ({written // (1024 * 1024)} MB)")
            return info
        except Exception as e:  # try the previous month, keep the old database
            last_error = e
            try:
                os.remove(tmp)
            except OSError:
                pass
    raise ValueError(f"DB-IP download failed: {last_error}")


def _install(tmp: str, target: str) -> None:
    """Put the new database in place of the old one. Every reader of this program lets go of the old file first
    (the live traffic view keeps it memory-mapped, and Windows then answers "Access is denied")."""
    wanted = os.path.normcase(os.path.abspath(target))
    readers = [g for g in list(_locators) if os.path.normcase(os.path.abspath(g.path)) == wanted]
    for reader in readers:
        reader.suspend()
    try:
        for attempt in range(REPLACE_TRIES):
            try:
                os.replace(tmp, target)
                return
            except PermissionError:
                if attempt == REPLACE_TRIES - 1:
                    raise
                time.sleep(REPLACE_WAIT)
    finally:
        for reader in readers:
            reader.resume()


def needs_update(info: Dict, today: Optional[date] = None) -> bool:
    try:
        downloaded = datetime.fromisoformat(info["downloaded"]).date()
    except (KeyError, ValueError):
        return True
    return ((today or date.today()) - downloaded).days > UPDATE_AFTER_DAYS

# endregion
