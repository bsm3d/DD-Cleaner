"""
Regression tests for the security audit (2026-09-29): each test replays a finding with crafted input and
checks the hardened behaviour. Nothing touches the system.
"""

import ipaddress
import time

import pytest

from ddcleaner import geoip, health, ipinfo
from ddcleaner import pe_signature as ps
from tests.test_geoip import enc, record_bytes


# region Helpers

def tlv(tag, content):
    n = len(content)
    length = bytes([n]) if n < 0x80 else (lambda b: bytes([0x80 | len(b)]) + b)(n.to_bytes((n.bit_length() + 7) // 8, "big"))
    return bytes([tag]) + length + content


def oid(text):
    parts = [int(x) for x in text.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for v in parts[2:]:
        chunk = [v & 0x7F]
        v >>= 7
        while v:
            chunk.insert(0, 0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(chunk)
    return tlv(6, out)


def mmdb_with_data(path, data: bytes, record_offset: int = 0):
    """IPv4 tree where 1.0.0.0/8 points at data offset record_offset."""
    prefix = [0, 0, 0, 0, 0, 0, 0, 1]
    n = len(prefix)
    nodes = b""
    for i, bit in enumerate(prefix):
        follow = i + 1 if i + 1 < n else n + 16 + record_offset
        nodes += record_bytes(follow if bit == 0 else n, follow if bit == 1 else n, 24)
    meta = {"node_count": n, "record_size": 24, "ip_version": 4, "database_type": "Crafted"}
    path.write_bytes(nodes + bytes(16) + data + geoip.METADATA_MARKER + enc(meta))

# endregion


# region GeoIP (MMDB file next to the program could be tampered with)

def pointer_to(offset):
    return bytes([(1 << 5) | ((offset >> 8) & 7), offset & 0xFF])


@pytest.mark.parametrize("name,data", [
    ("pointer to itself", pointer_to(0)),
    ("pointer to a pointer", pointer_to(2) + pointer_to(0)),
    ("pointer past the end", pointer_to(2000)),
    ("string longer than the file", bytes([(2 << 5) | 30, 0xFF, 0xFF]) + b"abc"),
    ("truncated double", bytes([(3 << 5) | 8]) + b"\x00\x01"),
])
def test_crafted_geoip_records_are_rejected(tmp_path, name, data):
    mmdb_with_data(tmp_path / geoip.FILE_NAME, data)
    g = geoip.GeoIP(str(tmp_path))
    try:
        assert g.locate("1.2.3.4") is None  # no exception, no hang
    finally:
        g.close()


def test_pointer_fan_out_is_capped(tmp_path):
    # array of 1000 pointers to an array of 1000 pointers to a string: 1e6 decoded items -> refused
    leaf = enc("x" * 10)
    inner_off = len(leaf)
    inner = bytes([(0 << 5) | 30, 11 - 7]) + (1000 - 285).to_bytes(2, "big") + pointer_to(0) * 1000
    outer_off = inner_off + len(inner)
    outer = bytes([(0 << 5) | 30, 11 - 7]) + (1000 - 285).to_bytes(2, "big") + pointer_to(inner_off) * 1000
    path = tmp_path / geoip.FILE_NAME
    mmdb_with_data(path, leaf + inner + outer, record_offset=outer_off)
    reader = geoip.MMDBReader(str(path))
    try:
        started = time.time()
        with pytest.raises(geoip.MMDBError, match="too deep or too large"):
            reader.lookup("1.2.3.4")
        assert time.time() - started < 5
    finally:
        reader.close()


def test_corrupted_metadata_is_an_mmdb_error(tmp_path):
    path = tmp_path / "bad.mmdb"
    path.write_bytes(b"\x00" * 64 + geoip.METADATA_MARKER + pointer_to(0))  # metadata = pointer loop
    with pytest.raises(geoip.MMDBError):
        geoip.MMDBReader(str(path))
    path.write_bytes(geoip.METADATA_MARKER + enc({"node_count": 10 ** 9, "record_size": 24, "ip_version": 4}))
    with pytest.raises(geoip.MMDBError, match="larger than the file"):
        geoip.MMDBReader(str(path))

# endregion


# region RDAP cache poisoning

@pytest.mark.parametrize("answer,queried,expected", [
    ({"startAddress": "0.0.0.0", "endAddress": "255.255.255.255"}, "8.8.8.8", ["8.8.8.8/32"]),     # whole Internet
    ({"startAddress": "1.0.0.0", "endAddress": "1.0.0.255"}, "8.8.8.8", ["8.8.8.8/32"]),           # other block
    ({"startAddress": "2001:db8::", "endAddress": "2001:db8::ffff"}, "8.8.8.8", ["8.8.8.8/32"]),   # other family
    ({"startAddress": "garbage"}, "8.8.8.8", ["8.8.8.8/32"]),
    ({"startAddress": "8.8.8.0", "endAddress": "8.8.8.255"}, "8.8.8.8", ["8.8.8.0/24"]),           # legitimate
])
def test_rdap_answers_only_cover_the_queried_address(answer, queried, expected):
    nets = ipinfo.answer_networks(answer, ipaddress.ip_address(queried))
    assert [str(n) for n in nets] == expected

# endregion


# region Authenticode parsing (driver files)

def test_overlong_oid_is_refused_quickly():
    started = time.time()
    with pytest.raises(ps.PEFormatError):
        ps.der_oid(b"\x2a" + b"\xff" * 80000)
    assert time.time() - started < 0.1


def test_malformed_nested_signature_keeps_the_primary_signature():
    """Nested signatures sit in unauthenticated attributes: anyone can edit them without breaking the file's
    signature. A broken one used to erase the real signature and so skip every signer blocklist rule."""
    cert = tlv(0x30, tlv(0x30, tlv(2, b"\x00\x00\x07") + tlv(0x30, b"") + tlv(0x30, b"") + tlv(0x30, b"")
                         + tlv(0x30, b"\x00\x00\x07")))
    signer = tlv(2, b"\x01") + tlv(0x30, tlv(0x30, b"") + tlv(2, b"\x00\x00\x07")) + tlv(0x30, b"")
    bad_nested = tlv(0x30, oid(ps.OID_SIGNED_DATA) + tlv(0xA0, tlv(0x30, tlv(2, b"\x01") + tlv(0x31, b"")
                                                                      + tlv(0x30, b"") + tlv(0x31, tlv(0x30, tlv(2, b"\x01"))))))
    unauth = tlv(0xA1, tlv(0x30, oid(ps.OID_NESTED_SIGNATURE) + tlv(0x31, bad_nested)))

    def pkcs7(extra):
        sd = tlv(0x30, tlv(2, b"\x01") + tlv(0x31, b"") + tlv(0x30, b"") + tlv(0xA0, cert)
                 + tlv(0x31, tlv(0x30, signer + extra)))
        return tlv(0x30, oid(ps.OID_SIGNED_DATA) + tlv(0xA0, sd))

    assert len(ps.parse_pkcs7(pkcs7(b""))) == 1
    assert len(ps.parse_pkcs7(pkcs7(unauth))) == 1


def test_many_certificates_and_signers_stay_fast():
    cert = lambda i: tlv(0x30, tlv(0x30, tlv(2, i.to_bytes(3, "big")) + tlv(0x30, b"") + tlv(0x30, b"")  # noqa: E731
                                   + tlv(0x30, b"") + tlv(0x30, i.to_bytes(3, "big"))))
    signer = tlv(0x30, tlv(2, b"\x01") + tlv(0x30, tlv(0x30, b"\xff") + tlv(2, b"\x00")))
    sd = tlv(0x30, tlv(2, b"\x01") + tlv(0x31, b"") + tlv(0x30, oid("1.2.840.113549.1.7.1"))
             + tlv(0xA0, b"".join(cert(i) for i in range(4000))) + tlv(0x31, signer * 4000))
    started = time.time()
    ps.parse_pkcs7(tlv(0x30, oid(ps.OID_SIGNED_DATA) + tlv(0xA0, sd)))
    assert time.time() - started < 1

# endregion


# region Health report robustness

def test_odd_crash_events_do_not_break_the_report():
    events = {"bugchecks": [{"Id": 1001, "Time": "2026-09-20T10:00:00", "Props": ["garbage"]},
                            {"Id": 1001, "Time": "2026-09-20T10:00:00", "Props": ["0x9f"]}],
              "stability": {"Current": None, "Minimum": None}}
    items = health.evaluate_crashes(events, [])
    assert any("2 blue screen" in i.title for i in items)
    assert health.evaluate_stability(events).status == health.UNKNOWN

# endregion


# region Display and export of external text

def test_external_text_is_never_rendered_as_html(qapp):
    from PySide6.QtGui import QTextDocument
    from ddcleaner.ui.safe_text import plain
    evil = '<h1>SAFE - Microsoft verified</h1><img src="file:///C:/x.png">'
    doc = QTextDocument()
    doc.setHtml(plain(evil))
    assert doc.toPlainText() == evil  # shown literally


def test_world_map_tooltip_escapes_names(qapp):
    from ddcleaner.traffic import CountryTraffic
    from ddcleaner.ui.world_map import WorldMapWidget
    m = WorldMapWidget()
    m.data = {"US": CountryTraffic("US", outbound=1, destinations={"<h1>x</h1>"}, apps={"<b>app</b>"})}
    html = m.describe("US")
    assert "<h1>" not in html and "&lt;h1&gt;" in html and "&lt;b&gt;app" in html


@pytest.mark.parametrize("value,expected", [
    ("=HYPERLINK(\"http://x\")", "'=HYPERLINK(\"http://x\")"), ("+1+1", "'+1+1"), ("-2", "'-2"),
    ("@SUM(A1)", "'@SUM(A1)"), ("normal.sys", "normal.sys"), (42, 42),
])
def test_csv_cells_cannot_become_formulas(value, expected):
    from ddcleaner.ui.safe_text import csv_cell
    assert csv_cell(value) == expected

# endregion
