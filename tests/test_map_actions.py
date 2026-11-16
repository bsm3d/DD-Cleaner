"""
World map actions: traffic of a link on hover, look-up on double-click, route trace on shift+click, right-click menu,
readable labels, and the route (tracert) parsing and dialog. No real route is traced and no browser is opened.
"""

import pytest
from PySide6.QtCore import QEvent, QPoint, QPointF, Qt
from PySide6.QtGui import QDesktopServices, QMouseEvent
from PySide6.QtTest import QTest

from ddcleaner import route, traffic as t
from ddcleaner.geoip import Location
from ddcleaner.ui import dialog_route
from ddcleaner.ui.world_map import WorldMapWidget

from test_ui_smoke import dialogs, window  # noqa: F401  (fixtures)


# region route.py

ENGLISH = """
Tracing route to dns.google [8.8.8.8]
over a maximum of 30 hops:

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     9 ms     8 ms    10 ms  81.240.0.1
  3     *        *        *     Request timed out.
  4    12 ms    11 ms    12 ms  dns.google [8.8.8.8]

Trace complete.
"""
FRENCH = """
Détermination de l'itinéraire vers 1.1.1.1 avec un maximum de 30 sauts :

  1     2 ms     1 ms     1 ms  192.168.1.1
  2     *        *        *     Délai d'attente de la demande dépassé.
  3    14 ms    14 ms    15 ms  1.1.1.1

Itinéraire déterminé.
"""


def test_tracert_lines_are_read_in_any_language():
    hops = [h for h in map(route.parse_hop, ENGLISH.splitlines()) if h]
    assert [h.number for h in hops] == [1, 2, 3, 4]
    assert hops[0].times == ["<1 ms", "<1 ms", "<1 ms"] and hops[0].address == "192.168.1.1"
    assert hops[2].address == "" and hops[2].summary == "no answer" and hops[2].times == ["*", "*", "*"]
    assert hops[3].address == "8.8.8.8" and hops[3].times[0] == "12 ms"          # the name in brackets is not the address
    french = [h for h in map(route.parse_hop, FRENCH.splitlines()) if h]
    assert [(h.number, h.address) for h in french] == [(1, "192.168.1.1"), (2, ""), (3, "1.1.1.1")]
    assert route.parse_hop("  7  192.168.1.1  reports: Destination host unreachable.") is None
    assert route.parse_hop("Trace complete.") is None and route.parse_hop("") is None
    v6 = route.parse_hop("  5    20 ms    21 ms    20 ms  2001:4860:4860::8888")
    assert v6.address == "2001:4860:4860::8888"


def test_only_public_addresses_are_traced_or_linked():
    assert route.public_address("8.8.8.8") == "8.8.8.8" and route.public_address("2001:4860:4860:0:0:0:0:8888")
    for bad in ("192.168.1.1", "10.0.0.5", "127.0.0.1", "169.254.1.1", "dns.google", "8.8.8.8; calc", "", None):
        assert route.public_address(bad) == ""
        with pytest.raises(ValueError):
            route.build_command(bad)
    command = route.build_command("8.8.8.8")
    assert command[0].lower().endswith("tracert.exe") and command[1:3] == ["-d", "-h"] and command[-1] == "8.8.8.8"
    assert route.public_addresses({"8.8.4.4", "8.8.8.8", "192.168.1.1", "2001:4860::1", "8.8.8.8%1"}) == \
        ["8.8.4.4", "8.8.8.8", "2001:4860::1"]


def test_host_names_are_checked_before_they_become_links():
    assert route.valid_host("API.Anthropic.com (+2 other names)") == "api.anthropic.com"
    for bad in ("", "localhost", "evil.com/../x", "a b.com", "x.com\r\nHost: y", "javascript:alert(1)", "8.8.8.8",
                "<script>.com", "-bad.com"):
        assert route.valid_host(bad) == ""
    assert route.valid_hosts(["b.example.com", "A.example.com", "a.example.com", "nope"]) == \
        ["a.example.com", "b.example.com"]
    assert route.site_url("Example.com") == "https://example.com/" and route.site_url("x y") == ""
    assert route.reputation_url("8.8.8.8") == "https://www.virustotal.com/gui/ip-address/8.8.8.8"
    assert route.reputation_url("dns.google") == "https://www.virustotal.com/gui/domain/dns.google"
    assert route.reputation_url("192.168.1.1") == "" and route.reputation_url("a b") == ""

# endregion


# region Data per place

def connection(port, addr, direction="Out", site="", rate=0.0, received=0):
    c = t.Connection("TCP", 2, "192.168.1.20", 50000 + port, addr, 443, "Established", 10)
    return t.ConnectionRow(c, direction, "Internet", site=site, owner="Owner (US)", country="US",
                           rate_in=rate, rate_out=rate / 2, received=received, sent=received // 2)


def sf_snapshot():
    sf = Location("US", "San Francisco", "California", 37.77, -122.42)
    rows = [connection(1, "8.8.8.8", site="dns.google (+1 other names)", rate=2048, received=4096),
            connection(2, "8.8.4.4", site="dns.google", rate=1024, received=2048)]
    for r in rows:
        r.location = sf
    return t.TrafficSnapshot({10: t.AppTraffic(t.ProcessInfo(10, "srv.exe"), rows)}, 0, True)


def test_a_place_knows_its_speed_addresses_and_sites():
    place = next(iter(t.by_place(sf_snapshot()).values()))
    assert place.rate_in == 3072 and place.rate_out == 1536 and place.received == 6144
    assert place.addresses == {"8.8.8.8", "8.8.4.4"} and place.hosts == {"dns.google"}
    country = t.by_country(sf_snapshot())[0]["US"]
    assert country.addresses == {"8.8.8.8", "8.8.4.4"} and country.hosts == {"dns.google"}

# endregion


# region The widget


@pytest.fixture
def world(qapp):
    m = WorldMapWidget()
    m.resize(1000, 500)
    snap = sf_snapshot()
    countries, unlocated = t.by_country(snap)
    m.set_data(countries, "BE", unlocated, t.by_place(snap))
    m.show()
    yield m
    m.close()


def place_of(m):
    return next(iter(m.places.values()))


def test_hovering_a_link_shows_its_traffic(world):
    place = place_of(world)
    a, b = next((a, b) for d, a, b in world._arcs())
    middle = world._arc_path(a, b).pointAtPercent(0.5)
    assert world.place_at(middle) is None and world.arc_at(middle).key == place.key
    assert world.arc_at(QPointF(middle.x(), middle.y() + 60)) is None
    text = world.describe_link(place)
    assert "This PC → San Francisco, US" in text and "download 3.0 KB/s, upload 1.5 KB/s" in text
    assert "Received 6.0 KB" in text and "8.8.4.4" in text and "Shift+click" in text
    QTest.mouseMove(world, middle.toPoint())
    assert world._hover == ("arc", place.key)
    QTest.mouseMove(world, QPoint(5, 5))
    assert world._hover is None
    world.grab()                                         # draws the highlighted link without error


def test_without_administrator_the_link_says_why_there_is_no_speed(world):
    place = place_of(world)
    place.rate_in = place.rate_out = place.received = place.sent = 0
    assert "need administrator rights" in world.describe_link(place)


def test_a_click_waits_so_that_a_double_click_does_not_also_list_connections(world):
    at = world._place_point(place_of(world)).toPoint()
    clicked, activated = [], []
    world.place_clicked.connect(clicked.append)
    world.place_activated.connect(activated.append)
    QTest.mouseClick(world, Qt.MouseButton.LeftButton, pos=at)
    QTest.mouseDClick(world, Qt.MouseButton.LeftButton, pos=at)
    world.flush_click()
    assert activated == [place_of(world)] and clicked == []     # the first click was cancelled by the double-click
    QTest.mouseClick(world, Qt.MouseButton.LeftButton, pos=at)
    world.flush_click()
    assert clicked == ["San Francisco, US"]


def test_double_click_elsewhere_resets_the_view(world):
    world.zoom = 4.0
    QTest.mouseDClick(world, Qt.MouseButton.LeftButton, pos=QPoint(5, 5))
    assert world.zoom == 1.0


def test_shift_click_traces_at_once_and_a_plain_click_does_not(world):
    at = world._place_point(place_of(world)).toPoint()
    traced, clicked = [], []
    world.place_trace.connect(traced.append)
    world.place_clicked.connect(clicked.append)
    QTest.mouseClick(world, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.ShiftModifier, pos=at)
    assert traced == [place_of(world)] and world._pending is None
    world.flush_click()
    assert clicked == []
    QTest.mouseClick(world, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.ShiftModifier, pos=QPoint(5, 5))
    assert len(traced) == 1                                     # shift + click on the sea traces nothing


def test_dragging_the_map_is_not_a_click(world):
    clicked = []
    world.place_clicked.connect(clicked.append)
    world.country_clicked.connect(clicked.append)
    QTest.mousePress(world, Qt.MouseButton.LeftButton, pos=QPoint(100, 100))
    QTest.mouseMove(world, QPoint(160, 140))
    QTest.mouseRelease(world, Qt.MouseButton.LeftButton, pos=QPoint(160, 140))
    world.flush_click()
    assert clicked == []


def test_right_click_asks_for_a_menu_on_a_node_and_on_the_map(world):
    asked = []
    world.context_requested.connect(lambda place, pos: asked.append(place))
    at = world._place_point(place_of(world)).toPoint()
    for pos in (at, QPoint(5, 5)):
        world.contextMenuEvent(type("E", (), {"pos": lambda s, p=pos: p, "globalPos": lambda s: QPoint(0, 0)})())
    assert asked == [place_of(world), None]


def test_crowded_labels_keep_the_busiest_and_the_hovered_one(world):
    crowded = {}
    for i in range(6):
        crowded[f"p{i}"] = t.PlaceTraffic(f"p{i}", f"City{i}", "DE", 50.0 + i * 0.01, 8.0, True, outbound=10 - i)
    crowded["far"] = t.PlaceTraffic("far", "Tokyo", "JP", 35.7, 139.7, True, outbound=1)
    world.set_data({}, "BE", 0, crowded)
    names = [d.label for d, _text, _rect in world._label_layout()]
    assert "City0" in names and "Tokyo" in names and len([n for n in names if n.startswith("City")]) < 6
    world._hover = ("place", "p5")                                # the one under the cursor is always named
    assert "City5" in [d.label for d, _text, _rect in world._label_layout()]
    world.grab()


def test_the_route_is_drawn_and_its_hops_have_a_tooltip(world):
    world.set_route([(2, 50.85, 4.35, "81.240.0.1  Brussels, BE"), (5, 51.5, -0.12, "5.5.5.5  London, GB")])
    assert world.hop_at(world._route_dots()[1][1]).__getitem__(0) == 5
    assert world.hop_at(QPointF(2, 2)) is None
    QTest.mouseMove(world, world._route_dots()[0][1].toPoint())
    assert world._hover == ("hop", 2)
    world.grab()
    world.set_route([])
    assert world.route == [] and world.hop_at(QPointF(2, 2)) is None

# endregion


# region Window actions


def test_double_click_opens_the_virustotal_page_not_the_site(window, monkeypatch):  # noqa: F811
    opened = []
    monkeypatch.setattr(QDesktopServices, "openUrl", staticmethod(lambda url: opened.append(url.toString())))
    place = place_of_snapshot()
    monkeypatch.setattr(window, "_map_choice", lambda items: items[0][1])
    window._map_lookup(place)
    assert opened == ["https://www.virustotal.com/gui/domain/dns.google"]
    seen = []
    monkeypatch.setattr(window, "_map_choice", lambda items: seen.append([i[0] for i in items]) or "")
    window._map_lookup(place)
    assert seen[0][0] == "Look up dns.google on VirusTotal" and "Look up 8.8.4.4 on VirusTotal" in seen[0]
    assert len(opened) == 1                                     # nothing chosen, nothing opened
    window._map_lookup(t.PlaceTraffic("x", "X", "US", None, None, False))
    assert "No site name or address" in window.status_label.text() and len(opened) == 1


def place_of_snapshot():
    return next(iter(t.by_place(sf_snapshot()).values()))


def test_shift_click_starts_a_trace_dialog_on_a_public_address(window, monkeypatch):  # noqa: F811
    started = []
    monkeypatch.setattr(dialog_route.RouteDialog, "start", lambda self: started.append(self.address))
    monkeypatch.setattr(window, "_map_choice", lambda items: items[-1][1] if items else "")
    window._map_trace(place_of_snapshot())
    assert started == ["8.8.8.8"] and window._route_dialog.isVisible()
    window._map_trace(place_of_snapshot())                       # a second trace replaces the first dialog
    assert len(started) == 2
    window._route_dialog.close()
    private = t.PlaceTraffic("p", "P", "US", None, None, False, addresses={"192.168.1.1", "not an address"})
    window._map_trace(private)
    assert len(started) == 2 and "No address to trace" in window.status_label.text()


def test_the_route_dialog_reads_the_output_as_it_comes(window):  # noqa: F811
    drawn = []
    here = {"8.8.8.8": Location("US", "Mountain View", "CA", 37.4, -122.1), "81.240.0.1": Location("BE", "Brussels", "", 50.85, 4.35)}
    dialog = dialog_route.RouteDialog(window, "8.8.8.8", "dns.google (8.8.8.8)", here.get, lambda pts: drawn.append(pts))
    for chunk in ("Tracing route\n\n  1    <1 ms    <1 ms    <1 ms  19", "2.168.1.1\n  2     9 ms     8 ms    10 ms  81.2",
                  "40.0.1\n  3     *        *        *     Request timed out.\n  4    12 ms    11 ms    12 ms  8.8.8.8"):
        dialog._on_text(chunk)                                   # a line may arrive in pieces
    assert [dialog.tree.topLevelItem(i).text(1) for i in range(dialog.tree.topLevelItemCount())] == \
        ["192.168.1.1", "81.240.0.1", "*", "8.8.8.8"][:3]        # the last line has no newline yet
    dialog._on_done(0, "")
    rows = [[dialog.tree.topLevelItem(i).text(c) for c in range(4)] for i in range(4)]
    assert rows[0][3] == "Local network" and rows[1][3] == "Brussels, BE" and rows[2][2] == "no answer"
    assert rows[3][1] == "8.8.8.8" and rows[3][3] == "Mountain View, US"
    assert "Reached 8.8.8.8 in 4 hops" in dialog.status.text()
    assert [p[0] for p in drawn[-1]] == [2, 4] and drawn[-1][0][3].startswith("81.240.0.1")   # only located hops
    dialog._on_text("  4    12 ms    12 ms    12 ms  8.8.8.8\n")                              # a repeated hop is ignored
    assert dialog.tree.topLevelItemCount() == 4
    dialog.close()


def test_the_dialog_reports_a_trace_that_ended_early_or_could_not_run(window):  # noqa: F811
    dialog = dialog_route.RouteDialog(window, "8.8.8.8", "x", lambda a: None, lambda pts: None)
    dialog._on_text("  1    1 ms    1 ms    1 ms  192.168.1.1\n")
    dialog._on_done(1, "")
    assert "without reaching 8.8.8.8" in dialog.status.text()
    broken = dialog_route.RouteDialog(window, "192.168.1.1", "x", lambda a: None, lambda pts: None)
    broken.start()                                               # a private address is refused, nothing runs
    assert "public Internet address" in broken.status.text() and not broken.stop_btn.isEnabled()
    dead = dialog_route.RouteDialog(window, "8.8.8.8", "x", lambda a: None, lambda pts: None)
    dead._on_done(-1, "Error: not found")
    assert "could not run" in dead.status.text()
    for d in (dialog, broken, dead):
        d.close()


def test_a_running_trace_is_an_operation_that_closing_stops(window, dialogs):  # noqa: F811
    from test_ui_smoke import FakeRunning, close_event
    window.route_worker = FakeRunning()
    assert "Route trace" in "".join(__import__("ddcleaner.ui.main_window", fromlist=["x"]).operation_label(n)
                                    for n in window._busy_operations())
    dialogs["answer"] = dialogs["answer"].__class__.Yes
    event = close_event()
    window.closeEvent(event)
    assert window.route_worker.waited is False or window.route_worker.running is False
    assert event.accepted

# endregion
