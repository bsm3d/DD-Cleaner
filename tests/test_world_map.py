"""
World map: bundled country data, country lookup, per-country aggregation of connections, map widget
hit-testing, tooltips and click-through to the Live traffic list.
"""

from PySide6.QtCore import QPointF

from ddcleaner import geo, ipinfo, traffic as t


def test_country_data_is_bundled_and_complete():
    countries, lookup = geo.world()
    codes = {c.code for c in countries}
    assert {"US", "FR", "BE", "DE", "CN", "BR", "AU", "SG", "HK", "NO"} <= codes  # FR/NO have -99 in the source
    france = geo.country("FR")
    assert france.rings and -5 < france.lon < 10 and 40 < france.lat < 52


def test_country_lookup_accepts_codes_names_and_registry_spellings():
    cases = {"fr": "FR", "France": "FR", "Canada": "CA", "United States": "US", "USA": "US",
             "Korea, Republic of": "KR", "Russian Federation": "RU", "Viet Nam": "VN", "UK": "GB",
             "EU": "", "": "", "Atlantis": ""}
    assert {k: geo.country_code(k) for k in cases} == cases


def test_rdap_countries_are_normalized():
    data = {"name": "X", "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [
        ["fn", {}, "text", "Beanfield Technologies Inc."], ["kind", {}, "text", "org"],
        ["adr", {"label": "Toronto\nON\nCanada"}, "text", ["", "", "", "", "", "", ""]]]]}]}
    assert ipinfo.parse_rdap(data).label == "Beanfield Technologies Inc. (CA)"


def test_home_country_is_an_iso_code():
    home = geo.home_country()
    assert home == "" or (len(home) == 2 and home.isupper())


def row(direction, country, site="", owner="", received=0, port=443):
    c = t.Connection("TCP", 2, "192.168.1.20", 50000 + port, "203.0.113.1", port, "Established", 10)
    return t.ConnectionRow(c, direction, "Internet", site=site, owner=owner, country=country, received=received)


def snapshot():
    app = t.AppTraffic(t.ProcessInfo(10, "claude.exe", description="Claude"), [
        row("Out", "US", site="api.anthropic.com (+1 other names)", received=1000, port=1),
        row("Out", "US", owner="Google LLC (US)", port=2),
        row("In", "NL", owner="Scanner BV (NL)", port=3),
        row("Out", "", port=4),                                     # owner not known yet
        t.ConnectionRow(t.Connection("TCP", 2, "a", 1, "192.168.1.1", 80, "Established", 10), "Out", "Local network"),
    ])
    return t.TrafficSnapshot({10: app, 0: t.AppTraffic(t.ProcessInfo(0, ""), [row("Out", "DE", port=5)])}, 0, True)


def test_by_country_aggregation():
    countries, unlocated = t.by_country(snapshot())
    assert set(countries) == {"US", "NL"} and unlocated == 1  # PID 0 and local network ignored
    us = countries["US"]
    assert (us.outbound, us.inbound, us.received) == (2, 0, 1000)
    assert us.destinations == {"api.anthropic.com", "Google LLC (US)"} and us.apps == {"Claude"}
    assert countries["NL"].inbound == 1


def located_snapshot():
    from ddcleaner.geoip import Location
    frankfurt = Location("DE", "Frankfurt am Main", "Hesse", 50.11, 8.68)
    r1 = row("Out", "US", owner="Google LLC (US)", port=1)
    r1.location = frankfurt                      # registered in the US, served from Frankfurt
    r2 = row("Out", "US", owner="Google LLC (US)", port=2)
    r2.location = frankfurt
    r3 = row("Out", "FR", owner="OVH SAS (FR)", port=3)  # no location: country marker
    app = t.AppTraffic(t.ProcessInfo(10, "srv.exe"), [r1, r2, r3])
    return t.TrafficSnapshot({10: app}, 0, True)


def test_real_location_wins_over_registration_country():
    countries, unlocated = t.by_country(located_snapshot())
    assert set(countries) == {"DE", "FR"} and countries["DE"].outbound == 2
    places = t.by_place(located_snapshot())
    city = places["50.1,8.7"]
    assert city.precise and city.label == "Frankfurt am Main, DE" and city.outbound == 2
    assert not places["country:FR"].precise


def test_map_places_hover_and_click(qapp):
    from ddcleaner.ui.world_map import WorldMapWidget
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    m = WorldMapWidget()
    m.resize(1000, 500)
    snap = located_snapshot()
    countries, unlocated = t.by_country(snap)
    m.set_data(countries, "BE", unlocated, t.by_place(snap))
    assert m.precise
    at = m._place_point(m.places["50.1,8.7"])
    assert m.place_at(at).label == "Frankfurt am Main, DE" and m.country_at(at) == "DE"
    assert "Frankfurt am Main, DE" in m.describe_place(m.place_at(at))
    clicked = []
    m.place_clicked.connect(clicked.append)
    m.grab()
    QTest.mouseClick(m, Qt.MouseButton.LeftButton, pos=at.toPoint())
    assert clicked == []                                 # a click waits for the double-click delay
    m.flush_click()
    assert clicked == ["Frankfurt am Main, DE"]


def test_map_widget_hit_test_tooltip_and_click(qapp):
    from ddcleaner.ui.world_map import WorldMapWidget
    m = WorldMapWidget()
    m.resize(1000, 500)
    countries, unlocated = t.by_country(snapshot())
    m.set_data(countries, "BE", unlocated)
    us = m._point("US")
    assert m.country_at(us) == "US"
    assert m.country_at(m._point("BR")) == "BR"          # outline hit without a marker
    assert m.country_at(QPointF(1, 1)) == ""             # ocean
    text = m.describe("US")
    assert "2 outbound" in text and "api.anthropic.com" in text and "Claude" in text
    assert "no connection" in m.describe("BE")
    clicked = []
    m.country_clicked.connect(clicked.append)
    m.grab()  # paints without error
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    QTest.mouseClick(m, Qt.MouseButton.LeftButton, pos=us.toPoint())
    m.flush_click()
    assert clicked == ["US"]


def test_map_click_filters_live_traffic(qapp, tmp_path, monkeypatch):
    from ddcleaner import driver_blocklist
    from ddcleaner.ui import main_window as mw_mod
    from PySide6.QtWidgets import QMessageBox
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(driver_blocklist, "get_blocklist_dir", lambda: str(tmp_path / "bl"))
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: None))
    w = mw_mod.MainWindow()
    try:
        w._on_traffic_sample(snapshot(), "")
        assert "to 1 country(ies): US 2" in w.map_summary_label.text() and "inbound from: NL" in w.map_summary_label.text()
        w._show_country_traffic("NL")
        assert w.traffic_group_combo.currentText() == "Destination" and w.traffic_filter.text() == "country:NL"
        assert w.net_tabs.currentWidget() is w.traffic_page
        assert w.traffic_tree.topLevelItemCount() == 1 and w.traffic_tree.topLevelItem(0).text(0) == "Scanner BV (NL)"
    finally:
        w._stop_traffic()
        w.close()
        w.deleteLater()
