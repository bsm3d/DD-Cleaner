"""
Live traffic: direction and destination classification, per-application aggregation, rates and totals of
closed connections (fake connection tables and byte counters), plus read-only calls on this machine.
"""

import os

from ddcleaner import firewall
from ddcleaner import traffic as t


def conn(local_port, remote="203.0.113.9", remote_port=443, state="Established", pid=10, proto="TCP",
         local="192.168.1.20"):
    return t.Connection(proto, t.AF_INET, local, local_port, remote if proto == "TCP" else "",
                        remote_port if proto == "TCP" else 0, state if proto == "TCP" else "", pid)


# region Classification

def test_direction():
    listening = {(10, 8080)}
    assert t.direction(conn(8080, state="Listen", remote="0.0.0.0", remote_port=0), listening) == "Listen"
    assert t.direction(conn(8080), listening) == "In"          # accepted on a port the process listens on
    assert t.direction(conn(50000), listening) == "Out"
    assert t.direction(conn(8080, pid=11), listening) == "Out"  # another process: not its listening port
    assert t.direction(conn(5353, proto="UDP"), listening) == "UDP"


def test_remote_kind():
    assert t.remote_kind("8.8.8.8") == "Internet"
    assert t.remote_kind("192.168.1.1") == "Local network"
    assert t.remote_kind("fe80::1%11") == "Local network"
    assert t.remote_kind("127.0.0.1") == "This PC"
    assert t.remote_kind("::1") == "This PC"
    assert t.remote_kind("239.255.255.250") == "Multicast"
    assert t.remote_kind("0.0.0.0") == "" and t.remote_kind("") == ""


def test_process_labels():
    assert t.ProcessInfo(4, "System").label == "System (Windows kernel)"
    assert t.ProcessInfo(9, "chrome.exe", description="Google Chrome").label == "Google Chrome"
    assert t.ProcessInfo(9, "svchost.exe", services=["A", "B", "C", "D"]).label == "svchost.exe [A, B, C...]"

# endregion


# region Aggregation with fake data

class FakeProcesses:
    def refresh(self, pids):
        return {pid: t.ProcessInfo(pid, f"app{pid}.exe", rf"C:\Apps\app{pid}.exe") for pid in pids}


class FakeCounter:
    def __init__(self):
        self.available = True
        self.values = {}

    def read(self, c):
        return self.values.get(c.key) if c.state == "Established" else None

    def forget(self, alive):
        pass


class FakeDns:
    def __init__(self, names=None):
        self._names = names or {}

    def refresh(self, force=False):
        pass

    def names(self, addr):
        return self._names.get(addr, [])


class FakeOwners:
    def __init__(self, owners=None):
        self._owners = owners or {}
        self.enabled = True

    def lookup(self, addr):
        return self._owners.get(addr)

    def shutdown(self):
        pass


class FakeLocator:
    def locate(self, addr):
        from ddcleaner.geoip import Location
        return Location("US", "San Francisco", "California", 37.79, -122.4) if addr == "160.79.104.10" else None

    def close(self):
        pass


def make_monitor(monkeypatch, tables, dns=None, owners=None):
    """tables: list of connection lists returned by successive samples."""
    m = t.TrafficMonitor(resolve_hosts=False, lookup_owners=False, dns=dns or FakeDns(), owners=owners or FakeOwners(),
                         locator=FakeLocator())
    monkeypatch.setattr(t.ipinfo, "arp_table", lambda: {"192.168.1.30": "00-00-5E-00-53-01"})
    monkeypatch.setattr(t.ipinfo, "default_gateways", lambda: {"192.168.1.1"})
    m.processes = FakeProcesses()
    m.counter = FakeCounter()
    queue = list(tables)
    monkeypatch.setattr(t, "list_connections", lambda: queue.pop(0))
    clock = iter([100.0, 102.0, 104.0])
    monkeypatch.setattr(t.time, "monotonic", lambda: next(clock))
    return m


def test_monitor_groups_by_application_with_rates(monkeypatch):
    listen = conn(8080, state="Listen", remote="0.0.0.0", remote_port=0)
    inbound = conn(8080, remote="192.168.1.50", remote_port=51000)
    outbound = conn(50001, pid=20)
    m = make_monitor(monkeypatch, [[listen, inbound, outbound], [listen, inbound, outbound]])
    m.counter.values = {inbound.key: (1000, 500), outbound.key: (10_000, 2_000)}
    first = m.sample()
    assert first.apps[10].count("In") == 1 and first.apps[10].ports == ["TCP 8080"]
    assert first.apps[20].count("Out") == 1 and first.apps[20].remote_hosts == 1
    assert first.apps[10].rate_in == 0  # no previous sample yet

    m.counter.values = {inbound.key: (3000, 900), outbound.key: (30_000, 2_000)}
    second = m.sample()
    app = second.apps[10]
    assert (app.received, app.sent) == (3000, 900)
    assert (app.rate_in, app.rate_out) == (1000, 200)  # 2000 and 400 bytes over 2 seconds
    assert second.total_rate_in == 1000 + 10_000


def test_closed_connections_stay_in_totals(monkeypatch):
    a, b = conn(50001), conn(50002)
    m = make_monitor(monkeypatch, [[a, b], [a], [a]])
    m.counter.values = {a.key: (100, 10), b.key: (5000, 50)}
    m.sample()
    snap = m.sample()  # b closed: its bytes still count for the application
    assert (snap.apps[10].received, snap.apps[10].sent) == (5100, 60)
    snap = m.sample()
    assert snap.apps[10].received == 5100  # counted once, not again


def test_unavailable_counters_show_no_bytes(monkeypatch):
    m = make_monitor(monkeypatch, [[conn(50001)]])
    m.counter.available = False
    m.counter.values = {}
    snap = m.sample()
    assert not snap.bytes_available and snap.apps[10].rows[0].received is None

# endregion


def test_destinations_are_described(monkeypatch):
    from ddcleaner import ipinfo
    to_site = conn(50001, remote="160.79.104.10")
    unknown = conn(50002, remote="8.8.4.4")
    router = conn(50003, remote="192.168.1.1", remote_port=80)
    device = conn(8080, remote="192.168.1.30", remote_port=51000)
    listen = conn(8080, state="Listen", remote="0.0.0.0", remote_port=0)
    owners = FakeOwners({"160.79.104.10": ipinfo.Owner("Anthropic, PBC", "US", "AP-2440", "160.79.104.0 - x", "arin")})
    m = make_monitor(monkeypatch, [[to_site, unknown, router, device, listen]],
                     dns=FakeDns({"160.79.104.10": ["api.anthropic.com", "claude.ai"]}), owners=owners)
    m.lookup_owners = True
    rows = {r.conn.remote_addr: r for r in m.sample().apps[10].rows}
    site = rows["160.79.104.10"]
    assert site.site == "api.anthropic.com (+1 other names)" and site.owner == "Anthropic, PBC (US)"
    assert "AP-2440" in site.owner_detail
    assert site.location.city == "San Francisco" and site.map_country == "US"
    assert rows["8.8.4.4"].owner == "looking up..."
    assert rows["192.168.1.1"].site == "Router / Internet box"
    assert rows["192.168.1.30"].direction == "In"
    assert rows["192.168.1.30"].owner == "Local device, MAC 00-00-5E-00-53-01"


# region Firewall log with PIDs (newer Windows versions)

def test_log_pid_field():
    lines = ["#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack "
             "tcpwin icmptype icmpcode info path pid",
             "2026-09-28 10:00:00 DROP TCP 10.0.0.2 1.2.3.4 50000 443 0 - - - - - - - SEND 1234",
             "2026-09-28 10:00:01 DROP UDP 10.0.0.9 10.0.0.2 5353 5353 0 - - - - - - - RECEIVE -"]
    stats = firewall.parse_log_lines(lines)
    assert stats.processes == {"1234": 1}

# endregion


# region This machine (read-only)

def test_real_connection_table_and_processes():
    conns = t.list_connections()
    assert any(c.state == "Listen" for c in conns)
    assert all(0 <= c.local_port <= 65535 for c in conns)
    names = t.process_names()
    assert names.get(os.getpid(), "").lower().startswith("python")
    assert t.process_path(os.getpid()).lower().endswith(".exe")
    assert isinstance(t.services_by_pid(), dict)


def test_real_sample_runs():
    m = t.TrafficMonitor(resolve_hosts=False, lookup_owners=False)
    try:
        snap = m.sample()
        assert snap.apps
    finally:
        m.close()

# endregion
