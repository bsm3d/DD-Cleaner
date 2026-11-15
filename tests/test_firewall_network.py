"""
Firewall and network analysis: rule parsing, exposure of listening ports, findings, log statistics and
network evaluators. Pure logic with fake data; the last tests only read this machine's state.
The logging switch (the one write) is never called here.
"""

import os

import pytest

from ddcleaner import firewall as fw
from ddcleaner import network as net

SYSROOT = os.environ["SystemRoot"]
NO_RESOLVE = lambda s: s  # noqa: E731


def rule(value, rule_id="R", source="Local"):
    return fw.parse_rule(rule_id, value, source, resolve=NO_RESOLVE)


def profiles(inbound="Block", enabled=True):
    return {p: fw.ProfileState(p, enabled, inbound, "Allow", False, "x.log") for p in fw.PROFILES}


def listener(port=8080, proto="TCP", address="0.0.0.0", path=r"C:\Apps\srv.exe", process="srv", services=(), pid=100):
    return fw.Listener(proto, address, port, pid, process, path, list(services))


# region Rule parsing

def test_parse_rule_fields():
    r = rule(r"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=17|Profile=Private|Profile=Public|LPort=162|"
             r"RA4=LocalSubnet|RA6=LocalSubnet|App=%SystemRoot%\system32\snmptrap.exe|Svc=SNMPTRAP|Name=SNMP Trap|")
    assert (r.action, r.direction, r.active, r.protocol) == ("Allow", "In", True, "17")
    assert r.profiles == {"Private", "Public"} and r.local_ports == ["162"]
    assert r.app == os.path.join(SYSROOT, r"system32\snmptrap.exe").lower()
    assert r.service == "SNMPTRAP" and not r.any_remote and r.scope == "LocalSubnet"
    assert r.is_windows_component


def test_parse_rule_defaults_and_special_keys():
    r = rule(r"v2.10|Action=Allow|Active=TRUE|Dir=In|App=C:\Tools\a.exe|Name=a|Defer=User|")
    assert r.profiles == set() and r.applies_to_profile("Public") and r.any_remote
    assert r.protocol is None and r.local_ports == [] and not r.edge  # Defer=User is not edge traversal
    wfd = rule("v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=System|Name=WFD|TTK2_27=WFDKmDriver|")
    assert wfd.app == "system" and wfd.interface_limited
    assert rule("v2.30|Action=Allow|Active=TRUE|Dir=In|Edge=TRUE|Name=e|").edge
    assert rule("v2.30|Name=broken|") is None


@pytest.mark.parametrize("ports,port,expected", [
    ([], 1, True), (["80"], 80, True), (["80"], 81, False), (["1000-2000"], 1500, True),
    (["5000,6000"], 6000, True), (["RPC"], 49700, True), (["RPC"], 135, False), (["RPC-EPMap"], 135, True),
    (["IPHTTPSIn"], 443, False),
])
def test_port_matching(ports, port, expected):
    assert fw.port_matches(ports, port) is expected

# endregion


# region Exposure

def test_loopback_is_local():
    assert fw.evaluate_exposure(listener(address="127.0.0.1"), [], profiles(), {"Public"}).level == "local"


def test_default_block_and_program_rule():
    assert fw.evaluate_exposure(listener(), [], profiles(), {"Private"}).level == "blocked"
    allow = rule(r"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|App=C:\Apps\srv.exe|Name=Srv|")
    e = fw.evaluate_exposure(listener(), [allow], profiles(), {"Private"})
    assert (e.level, e.rule) == ("open", "Srv")
    assert fw.evaluate_exposure(listener(), [allow], profiles(), {"Public"}).level == "blocked"  # wrong profile
    assert fw.evaluate_exposure(listener(proto="UDP"), [allow], profiles(), {"Private"}).level == "blocked"


def test_block_rule_wins_and_scope_is_reported():
    allow = rule(r"v2.30|Action=Allow|Active=TRUE|Dir=In|LPort=8080|RA4=LocalSubnet|Name=Lan|")
    e = fw.evaluate_exposure(listener(), [allow], profiles(), {"Private"})
    assert e.level == "limited" and "LocalSubnet" in e.text
    block = rule(r"v2.30|Action=Block|Active=TRUE|Dir=In|LPort=8080|Name=No|")
    assert fw.evaluate_exposure(listener(), [allow, block], profiles(), {"Private"}).level == "blocked"
    disabled = rule(r"v2.30|Action=Allow|Active=FALSE|Dir=In|LPort=8080|Name=Off|")
    assert fw.evaluate_exposure(listener(), [disabled], profiles(), {"Private"}).level == "blocked"


def test_firewall_off_or_default_allow_opens_everything():
    assert "firewall is off" in fw.evaluate_exposure(listener(), [], profiles(enabled=False), {"Public"}).text
    assert fw.evaluate_exposure(listener(), [], profiles(inbound="Allow"), {"Public"}).level == "open"


def test_most_open_active_profile_is_reported():
    allow = rule(r"v2.30|Action=Allow|Active=TRUE|Dir=In|Profile=Private|LPort=8080|Name=P|")
    e = fw.evaluate_exposure(listener(), [allow], profiles(), {"Private", "Public"})
    assert e.level == "open" and "(Private)" in e.text


def test_service_and_system_rules():
    svc = rule(r"v2.30|Action=Allow|Active=TRUE|Dir=In|App=%SystemRoot%\system32\svchost.exe|Svc=SSDPSRV|LPort=1900|Name=S|")
    host = os.path.join(SYSROOT, r"System32\svchost.exe")
    assert fw.evaluate_exposure(listener(1900, "UDP", path=host, services=["SSDPSRV"]), [svc], profiles(),
                                {"Private"}).level == "open"
    assert fw.evaluate_exposure(listener(1900, "UDP", path=host, services=["Dnscache"]), [svc], profiles(),
                                {"Private"}).level == "blocked"
    # path unreadable (not administrator): the executable name still matches
    assert fw.evaluate_exposure(listener(1900, "UDP", path="", process="svchost", services=["SSDPSRV"]), [svc],
                                profiles(), {"Private"}).level == "open"
    kernel = rule("v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=System|LPort=445|Name=SMB|")
    assert fw.evaluate_exposure(listener(445, pid=4, path="", process="System"), [kernel], profiles(),
                                {"Private"}).level == "open"
    wfd = rule("v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=System|Name=WFD|TTK2_27=WFDKmDriver|")
    assert fw.evaluate_exposure(listener(445, pid=4, path="", process="System"), [wfd], profiles(),
                                {"Private"}).level == "blocked"


def test_listener_bound_to_one_adapter_uses_its_profile():
    adapters = [{"Name": "Ethernet", "IPv4": ["192.168.1.20/24"]}, {"Name": "Ethernet 3", "IPv4": "169.254.1.1/16"}]
    networks = [{"Interface": "Ethernet", "Category": "Private"}, {"Interface": "Ethernet 3", "Category": "Public"}]
    addr = net.address_profiles(adapters, networks)
    assert addr == {"192.168.1.20": "Private", "169.254.1.1": "Public"}
    assert net.listener_profiles(listener(address="169.254.1.1"), addr, {"Private", "Public"}) == {"Public"}
    assert net.listener_profiles(listener(address="0.0.0.0"), addr, {"Private", "Public"}) == {"Private", "Public"}

# endregion


# region Findings

def test_findings_profiles():
    bad = profiles()
    bad["Public"] = fw.ProfileState("Public", False, "Block", "Allow", False, "")
    bad["Private"] = fw.ProfileState("Private", True, "Allow", "Allow", False, "")
    titles = {f.title: f.status for f in fw.evaluate_firewall([], bad, {"Public"})}
    assert titles["Firewall is OFF for the Public profile (in use now)"] == fw.CRITICAL
    assert titles["Private profile allows inbound connections by default"] == fw.CRITICAL
    ok = fw.evaluate_firewall([], profiles(), {"Private"})
    assert [f.status for f in ok] == [fw.OK]


def test_findings_risky_rules():
    rules = [
        rule(r"v2.30|Action=Allow|Active=TRUE|Dir=In|Name=Everything|"),
        rule(r"v2.30|Action=Allow|Active=TRUE|Dir=In|App=C:\Apps\db.exe|Name=DB|Edge=TRUE|"),
        rule(r"v2.30|Action=Allow|Active=TRUE|Dir=In|App=C:\Apps\lan.exe|RA4=LocalSubnet|Name=Lan|"),
        rule(r"v2.30|Action=Allow|Active=TRUE|Dir=In|Profile=Private|App=C:\Apps\home.exe|Name=Home|"),
        rule(r"v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=53|LA4=172.20.0.1|Name=HNS DNS|"),
    ]
    findings = {f.title: f for f in fw.evaluate_firewall(rules, profiles(), {"Private"}, path_exists=lambda p: True)}
    assert findings["1 rule(s) allow any inbound traffic"].status == fw.CRITICAL
    public = findings["1 program rule(s) accept connections on public networks"]
    assert public.status == fw.WARNING and "DB" in public.details[1]
    assert "1 rule(s) allow edge traversal (reachable through NAT / Teredo)" in findings


def test_orphan_rules_split_by_folder_safety():
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    drive = os.path.splitdrive(program_files)[0] + "\\"
    rules = [
        rule(rf"v2.30|Action=Allow|Active=TRUE|Dir=In|App={drive}Temp\apache\httpd.exe|Name=Apache|"),
        rule(rf"v2.30|Action=Allow|Active=TRUE|Dir=In|App={program_files}\Old\old.exe|Profile=Private|Name=Old|"),
        rule(rf"v2.30|Action=Allow|Active=TRUE|Dir=In|App={SYSROOT}\ehome\ehshell.exe|Profile=Private|Name=MCE|"),
    ]
    exists = lambda p: p.lower() == drive.lower()  # noqa: E731  only the drive root exists
    findings = {f.title: f for f in fw.evaluate_firewall(rules, profiles(), {"Private"}, path_exists=exists)}
    writable = findings["1 rule(s) for missing programs in folders any user can write to"]
    assert writable.status == fw.WARNING and "Apache (Allow)" in writable.details[1]
    assert findings["1 rule(s) for programs that were uninstalled"].status == fw.INFO  # Windows' own ignored

# endregion


# region Log

LOG = """#Version: 1.5
#Software: Microsoft Windows Firewall
#Time Format: Local
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path

2026-09-27 10:00:01 DROP TCP 203.0.113.5 192.168.1.20 51000 445 52 S 1 0 64240 - - - RECEIVE
2026-09-27 10:00:02 DROP TCP 203.0.113.5 192.168.1.20 51001 3389 52 S 1 0 64240 - - - RECEIVE
2026-09-28 09:00:00 DROP UDP 192.168.1.40 192.168.1.20 5353 5353 80 - - - - - - - RECEIVE
2026-09-28 09:00:05 DROP TCP 192.168.1.20 198.51.100.7 50000 443 52 S 1 0 64240 - - - SEND
2026-09-28 09:00:06 ALLOW TCP 192.168.1.20 198.51.100.8 50001 443 0 - - - - - - - SEND
garbage
"""


def test_log_statistics():
    stats = fw.parse_log_lines(LOG.splitlines())
    assert stats.lines == 5 and stats.dropped == 4
    assert stats.first == "2026-09-27 10:00:01" and stats.last == "2026-09-28 09:00:06"
    assert stats.inbound_sources.most_common(1) == [("203.0.113.5", 2)]
    assert stats.inbound_ports["TCP 445"] == 1 and stats.outbound_targets["198.51.100.7 TCP 443"] == 1
    assert stats.per_day == {"2026-09-27": 2, "2026-09-28": 2}
    assert fw.describe_port("TCP 3389") == "TCP 3389 (Remote Desktop)"


def test_log_files_are_merged_and_missing_log_is_none(tmp_path):
    path = tmp_path / "pfirewall.log"
    assert fw.read_log(str(path)) is None
    (tmp_path / "pfirewall.log.old").write_text(LOG, encoding="utf-8")
    path.write_text(LOG, encoding="utf-8")
    stats = fw.read_log(str(path))
    assert stats.dropped == 8 and len(stats.files) == 2

# endregion


# region Network evaluators

def test_adapter_evaluation():
    items = net.evaluate_adapters([
        {"Name": "Ethernet", "Status": "Up", "LinkSpeed": "1 Gbps", "ReceivedPackets": 100000, "SentPackets": 100000,
         "ReceivedErrors": 0, "SentErrors": 0, "ReceivedDiscards": 0, "SentDiscards": 0, "IPv4": ["10.0.0.2/24"],
         "DNS": ["10.0.0.1"]},
        {"Name": "Bad", "Status": "Up", "LinkSpeed": "100 Mbps", "ReceivedPackets": 1000, "SentPackets": 0,
         "ReceivedErrors": 5, "SentErrors": 0, "ReceivedDiscards": 0, "SentDiscards": 0},
        {"Name": "Wi-Fi", "Status": "Disconnected"},
    ])
    assert [(i.title, i.status) for i in items] == [("Ethernet: 1 Gbps", net.OK), ("Bad: 100 Mbps", net.WARNING)]
    assert "DNS servers: 10.0.0.1" in items[0].details


def test_retransmission_thresholds():
    def rate(retrans):
        counters = {"tcp": {"OutSegs": 1000, "RetransSegs": retrans, "ActiveOpens": 10, "AttemptFails": 1}}
        return net.evaluate_protocols(counters, [])[0].status
    assert (rate(5), rate(30), rate(80)) == (net.OK, net.WARNING, net.CRITICAL)


def test_listener_parsing():
    rows = net.parse_listeners([
        {"Protocol": "TCP", "Address": "0.0.0.0", "Port": 445, "Pid": 4, "Owner": {"Name": "", "Services": [None]}},
        {"Protocol": "TCP", "Address": "0.0.0.0", "Port": 445, "Pid": 4, "Owner": {}},
        {"Protocol": "UDP", "Address": "127.0.0.1", "Port": 53, "Pid": 9, "Owner": {"Name": "dns", "Services": "Dnscache"}},
    ])
    assert len(rows) == 2 and rows[0].process == "System" and rows[0].services == []
    assert rows[1].loopback and rows[1].services == ["Dnscache"]

# endregion


# region This machine (read-only)

def test_real_rules_and_counters():
    rules = fw.read_rules()
    assert len(rules) > 20 and all(r.direction in ("In", "Out") for r in rules)
    counters = net.protocol_counters()
    assert counters["tcp"].get("OutSegs", 0) > 0

# endregion
