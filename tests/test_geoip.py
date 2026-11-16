"""
GeoIP: the pure-Python MaxMind DB reader (checked on a small database written by the test, including
pointers and every record size), location extraction, download validation, and the real DB-IP file when
it has been downloaded. No network access.
"""

import gzip
import io
import os
import struct
from datetime import date

import pytest

from ddcleaner import geoip


# region Tiny MMDB writer (test only)

def enc(value) -> bytes:
    def head(kind, size):
        ext = b""
        if kind > 7:
            ext, kind = bytes([kind - 7]), 0
        if size < 29:
            return bytes([(kind << 5) | size]) + ext
        if size < 285:
            return bytes([(kind << 5) | 29]) + ext + bytes([size - 29])
        return bytes([(kind << 5) | 30]) + ext + (size - 285).to_bytes(2, "big")

    if isinstance(value, bool):
        return head(14, int(value))
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return head(2, len(raw)) + raw
    if isinstance(value, float):
        return head(3, 8) + struct.pack(">d", value)
    if isinstance(value, int):
        raw = value.to_bytes(4, "big")
        return head(6, 4) + raw
    if isinstance(value, dict):
        return head(7, len(value)) + b"".join(enc(k) + enc(v) for k, v in value.items())
    if isinstance(value, list):
        return head(11, len(value)) + b"".join(enc(v) for v in value)
    if isinstance(value, Pointer):
        return bytes([(1 << 5) | (0 << 3) | ((value.offset >> 8) & 7), value.offset & 0xFF])
    raise TypeError(value)


class Pointer:
    def __init__(self, offset):
        self.offset = offset


def record_bytes(left: int, right: int, size: int) -> bytes:
    if size == 24:
        return left.to_bytes(3, "big") + right.to_bytes(3, "big")
    if size == 28:
        return (left & 0xFFFFFF).to_bytes(3, "big") + bytes([((left >> 24) << 4) | (right >> 24)]) + \
            (right & 0xFFFFFF).to_bytes(3, "big")
    return left.to_bytes(4, "big") + right.to_bytes(4, "big")


def build_mmdb(path, record_size=24, ip_version=4):
    """1.0.0.0/8 -> Brussels record (city name through a pointer); everything else: no data."""
    shared = enc("Brussels")                        # at data offset 0, reused through a pointer
    record = {"city": {"names": {"en": Pointer(0)}}, "country": {"iso_code": "BE"},
              "location": {"latitude": 50.85, "longitude": 4.35}, "subdivisions": [{"names": {"en": "Brussels"}}]}
    data = shared + enc(record)
    record_offset = len(shared)
    prefix = [0] * 96 + [0, 0, 0, 0, 0, 0, 0, 1] if ip_version == 6 else [0, 0, 0, 0, 0, 0, 0, 1]
    node_count = len(prefix)
    nodes = []
    for i, bit in enumerate(prefix):
        follow = i + 1 if i + 1 < node_count else node_count + 16 + record_offset
        other = node_count  # no data
        nodes.append(record_bytes(follow if bit == 0 else other, follow if bit == 1 else other, record_size))
    meta = {"node_count": node_count, "record_size": record_size, "ip_version": ip_version,
            "database_type": "Test-City-Lite", "binary_format_major_version": 2}
    with open(path, "wb") as f:
        f.write(b"".join(nodes) + bytes(16) + data + geoip.METADATA_MARKER + enc(meta))

# endregion


@pytest.mark.parametrize("record_size", [24, 28, 32])
@pytest.mark.parametrize("ip_version", [4, 6])
def test_reader_finds_record_and_follows_pointers(tmp_path, record_size, ip_version):
    path = tmp_path / "t.mmdb"
    build_mmdb(path, record_size, ip_version)
    reader = geoip.MMDBReader(str(path))
    try:
        assert reader.metadata["database_type"] == "Test-City-Lite"
        rec = reader.lookup("1.2.3.4")
        assert rec["city"]["names"]["en"] == "Brussels" and rec["location"]["latitude"] == 50.85
        assert reader.lookup("2.0.0.1") is None
        loc = geoip.location_from_record(rec)
        assert loc == geoip.Location("BE", "Brussels", "Brussels", 50.85, 4.35)
        assert loc.label == "Brussels, BE"
    finally:
        reader.close()


def test_not_a_database(tmp_path):
    bad = tmp_path / "bad.mmdb"
    bad.write_bytes(b"hello" * 100)
    with pytest.raises(geoip.MMDBError):
        geoip.MMDBReader(str(bad))
    assert geoip.GeoIP(str(tmp_path)).locate("8.8.8.8") is None  # no file: no location, no error


def test_geoip_caches_and_reopens_after_update(tmp_path):
    build_mmdb(tmp_path / geoip.FILE_NAME)
    g = geoip.GeoIP(str(tmp_path))
    try:
        assert g.available and g.locate("1.1.1.1").city == "Brussels"
        assert g.locate("9.9.9.9") is None
    finally:
        g.close()


# region Download

class FakeResponse(io.BytesIO):
    def __init__(self, url, body):
        super().__init__(body)
        self.url = url

    def geturl(self):
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def gz_of(path):
    return gzip.compress(open(path, "rb").read())


def test_download_installs_valid_city_database(tmp_path, monkeypatch):
    src = tmp_path / "src.mmdb"
    build_mmdb(src)
    body = gz_of(src)
    requested = []

    def opener(req, timeout):
        requested.append(req.full_url)
        if "2026-09" in req.full_url:
            raise OSError("not published yet")          # falls back to the previous month
        return FakeResponse("https://download.db-ip.com/free/x.mmdb.gz", body)

    # the fake database has no 8.8.8.8 record: validate with the address it knows
    monkeypatch.setattr(geoip, "location_from_record",
                        lambda rec: geoip.Location("BE", "Brussels", "", 50.85, 4.35) if rec else None)
    monkeypatch.setattr(geoip.MMDBReader, "lookup", lambda self, addr: {"location": {}})
    dest = tmp_path / "geo"
    info = geoip.download_dbip(str(dest), opener=opener, today=date(2026, 9, 1))
    assert info["month"] == "2026-08" and "DB-IP" in info["attribution"]
    assert requested[0].endswith("dbip-city-lite-2026-09.mmdb.gz")
    assert os.path.isfile(dest / geoip.FILE_NAME) and not os.path.exists(dest / (geoip.FILE_NAME + ".download"))


def test_an_update_replaces_a_database_that_is_in_use(tmp_path, monkeypatch):
    """The live traffic view keeps the database memory-mapped: Windows refuses to replace such a file
    ("Access is denied") unless the reader lets go of it first."""
    dest = tmp_path / "geo"
    dest.mkdir()
    build_mmdb(dest / geoip.FILE_NAME)
    in_use = geoip.GeoIP(str(dest))
    assert in_use.available and in_use._reader is not None           # the old file is mapped
    monkeypatch.setattr(geoip, "location_from_record",
                        lambda rec: geoip.Location("BE", "Brussels", "", 50.85, 4.35) if rec else None)
    monkeypatch.setattr(geoip.MMDBReader, "lookup", lambda self, addr: {"location": {}})
    body = gz_of(dest / geoip.FILE_NAME)
    old_reader = in_use._reader
    info = geoip.download_dbip(str(dest), today=date(2026, 9, 15),
                               opener=lambda req, timeout: FakeResponse("https://download.db-ip.com/free/x.mmdb.gz", body))
    assert info["month"] == "2026-09" and not os.path.exists(dest / (geoip.FILE_NAME + ".download"))
    assert in_use.locate("1.2.3.4").city == "Brussels" and in_use._reader is not old_reader   # reopened by itself
    in_use.close()


def test_a_suspended_reader_answers_nothing_and_caches_nothing(tmp_path):
    build_mmdb(tmp_path / geoip.FILE_NAME)
    g = geoip.GeoIP(str(tmp_path))
    g.suspend()
    assert g._reader is None and not g.available and g.locate("1.2.3.4") is None and g._cache == {}
    g.resume()
    assert g.available
    g.close()


def test_download_refuses_other_hosts_and_wrong_content(tmp_path):
    src = tmp_path / "src.mmdb"
    build_mmdb(src)
    body = gz_of(src)
    dest = tmp_path / "geo"
    with pytest.raises(ValueError):
        geoip.download_dbip(str(dest), opener=lambda req, timeout: FakeResponse("https://evil.example/x.gz", body))
    with pytest.raises(ValueError):  # a valid MMDB but not a city database with 8.8.8.8
        geoip.download_dbip(str(dest), opener=lambda req, timeout: FakeResponse(
            "https://download.db-ip.com/free/x.gz", body))
    assert not os.path.exists(dest / geoip.FILE_NAME)


def test_month_candidates_and_update_age():
    assert geoip.candidate_months(date(2026, 1, 3)) == ["2026-01", "2025-12"]
    assert geoip.needs_update({"downloaded": "2026-07-01T10:00:00"}, date(2026, 9, 1))
    assert not geoip.needs_update({"downloaded": "2026-08-25T10:00:00"}, date(2026, 9, 1))
    assert geoip.needs_update({})

# endregion


def test_real_database_when_downloaded():
    g = geoip.GeoIP()
    if not g.available:
        pytest.skip("DB-IP City Lite not downloaded")
    try:
        loc = g.locate("8.8.8.8")
        assert loc.country == "US" and -130 < loc.lon < -60
        assert g.locate("192.168.1.1") is None
        assert g.locate("2606:4700:4700::1111") is not None
    finally:
        g.close()
