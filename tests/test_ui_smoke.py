"""
UI smoke tests (offscreen): the window builds, tabs exist, concurrency guards and shutdown behave.
Dialogs are replaced by recorders; no scan or system command is started.
"""

import os

import pytest
from PySide6.QtWidgets import QMessageBox, QFileDialog

from ddcleaner import api_keys, clamav, driver_blocklist, garbage_stats
from ddcleaner.pe_signature import PEInfo
from ddcleaner.ui import main_window as mw_mod
from PySide6.QtCore import QCoreApplication, QEvent, Qt
from PySide6.QtGui import QColor


class FakeRunning:
    """Stands in for a QThread that is still running."""
    def __init__(self, running=True):
        self.running = running
        self.waited = False

    def isRunning(self):
        return self.running

    def wait(self, *_):
        self.waited = True
        self.running = False
        return True

    def kill(self):
        self.running = False


@pytest.fixture
def dialogs(monkeypatch):
    """Record every message box; answer No to questions unless told otherwise."""
    calls = {"info": [], "warning": [], "critical": [], "question": [], "answer": QMessageBox.StandardButton.No}
    for kind in ("information", "warning", "critical"):
        key = "info" if kind == "information" else kind
        monkeypatch.setattr(QMessageBox, kind, staticmethod(lambda *a, _k=key, **kw: calls[_k].append(a[2:3])))

    def question(*a, **kw):
        calls["question"].append(a[2:3])
        return calls["answer"]
    monkeypatch.setattr(QMessageBox, "question", staticmethod(question))

    def exec_box(box):  # a confirmation that carries its full list behind "Show Details" is a real box
        calls["question"].append((box.text(),))
        return calls["answer"]
    monkeypatch.setattr(QMessageBox, "exec", exec_box)
    return calls


@pytest.fixture
def window(qapp, dialogs, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # logs of the test stay in tmp_path
    monkeypatch.setattr(driver_blocklist, "get_blocklist_dir", lambda: str(tmp_path / "driver_blocklist"))
    monkeypatch.setattr(clamav, "clam_dir", lambda: str(tmp_path / "clamav"))
    monkeypatch.setattr(api_keys, "store_path", lambda: str(tmp_path / "api_keys.json"))
    monkeypatch.setattr(garbage_stats, "stats_path", lambda: str(tmp_path / "garbage_stats.json"))
    w = mw_mod.MainWindow()
    yield w
    w._bg_threads.clear()
    w.close()
    w.deleteLater()
    # destroy it now: windows waiting for deletion pile up and then eat the time of a later test's qWait()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def close_event():
    return type("E", (), {"ignored": False, "accepted": False,
                          "ignore": lambda s: setattr(s, "ignored", True),
                          "accept": lambda s: setattr(s, "accepted", True)})()


def test_window_builds_with_expected_tabs(window):
    tabs = [window.tab_widget.tabText(i) for i in range(window.tab_widget.count())]
    assert tabs == ["🧩 Driver Checker", "🩺 System Health", "🌐 Firewall && Network", "🛡️ Security", "🦠 Antivirus",
                    "🧹 Garbage"]
    assert window.hardening_tree.topLevelItemCount() == 8  # "Safe (Recommended)" preset


def test_interface_is_english(window):
    french = ("Sécurité", "Annuler", "Appliquer", "Lancer", "Journal", "Aucun", "Détails", "Fermer")
    texts = [w.text() for w in window.findChildren(type(window.security_audit_btn))]
    assert not [t for t in texts if any(f in t for f in french)]


def test_driver_scan_refuses_second_run(window, dialogs):
    window.driver_scan_worker = FakeRunning()
    window._scan_drivers()
    assert isinstance(window.driver_scan_worker, FakeRunning)
    assert dialogs["info"]


def test_vulnerable_driver_check_needs_a_blocklist(window, dialogs):
    assert "not downloaded" in window.blocklist_label.text()
    dialogs["answer"] = QMessageBox.StandardButton.No
    window._scan_vulnerable_drivers()
    assert dialogs["question"]
    assert getattr(window, "vuln_scan_worker", None) is None
    assert getattr(window, "blocklist_download_worker", None) is None


def test_vulnerable_driver_results_show_listed_drivers_first(window):
    def check(name, reasons, loaded=False):
        info = PEInfo(path=name, hashes={"sha256": "A" * 64}, version=(1, 0, 0, 0))
        return driver_blocklist.DriverCheck(driver_blocklist.DriverFile(path=name, loaded=loaded), info, reasons)
    window._on_vulnerable_drivers_checked(
        [check(r"C:\d\a.sys", []), check(r"C:\d\z.sys", ["Hash (SHA256): z.sys"], loaded=True)], "")
    assert "1 driver(s) on the blocklist (1 loaded" in window.vuln_summary_label.text()
    assert window.vuln_only_flagged_cb.isChecked()
    assert window.vuln_tree.topLevelItemCount() == 1
    window.vuln_only_flagged_cb.setChecked(False)
    rows = [window.vuln_tree.topLevelItem(i) for i in range(window.vuln_tree.topLevelItemCount())]
    assert [r.text(0) for r in rows] == ["z.sys", "a.sys"]
    assert rows[0].text(1) == "● BLOCKLISTED" and rows[0].text(2) == "Loaded"


def test_close_asks_when_busy_and_can_be_cancelled(window, dialogs):
    window.dism_worker = FakeRunning()
    dialogs["answer"] = QMessageBox.StandardButton.No
    event = close_event()
    window.closeEvent(event)
    assert event.ignored and not event.accepted
    assert dialogs["question"]


def test_close_stops_workers_when_confirmed(window, dialogs):
    worker = FakeRunning()
    window.security_audit_worker = worker
    dialogs["answer"] = QMessageBox.StandardButton.Yes
    event = close_event()
    window.closeEvent(event)
    assert worker.waited and event.accepted
    assert window.stop_flag.is_set()


def test_undo_refuses_backups_outside_the_backup_folder(window, dialogs, tmp_path, monkeypatch):
    monkeypatch.setattr("ddcleaner.ui.tab_security.SystemUtils.check_admin_privileges", staticmethod(lambda: True))
    backups = tmp_path / "hardening_backups"
    backups.mkdir()
    (backups / "tweaks_backup_1.json").write_text('{"entries": []}', encoding="utf-8")
    outside = tmp_path / "tweaks_backup_evil.json"
    outside.write_text('{"entries": []}', encoding="utf-8")
    monkeypatch.setattr("ddcleaner.ui.tab_security.get_backup_dir", lambda: str(backups))
    monkeypatch.setattr(window, "_choose_backup", lambda backups: str(outside))
    started = []
    monkeypatch.setattr(window, "_run_hardening_commands", lambda *a, **k: started.append(a))
    window._revert_security_change()
    assert dialogs["warning"] and not started


def test_status_updates_from_worker_threads_are_queued(window, qapp):
    import threading
    t = threading.Thread(target=window._update_status, args=("from a worker",))
    t.start()
    t.join()
    qapp.processEvents()
    assert window.status_label.text() == "from a worker"


def test_no_tab_code_left_in_main_window():
    src = open(mw_mod.__file__, encoding="utf-8").read()
    assert len(src.splitlines()) < 700
    for tab in ("_create_drivers_tab", "_create_security_tab", "_create_system_health_tab"):
        assert f"def {tab}" not in src
    assert os.path.basename(mw_mod.__file__) == "main_window.py"


def test_health_report_shows_worst_first(window):
    from ddcleaner import health
    items = [health.HealthItem("Disks", health.OK, "Disk A"),
             health.HealthItem("Storage", health.CRITICAL, "Disk B failing", ["detail"])]
    window._on_health_checked(items, "")
    top = window.health_tree.topLevelItem(0)
    assert top.text(2) == "Disk B failing" and top.isExpanded() and top.child(0).text(2) == "detail"
    assert window.health_summary_label.text().startswith("1 critical, 0 warning(s)")


def fake_network_reports():
    from ddcleaner import firewall, network
    profiles = {p: firewall.ProfileState(p, True, "Block", "Allow", False, "x.log") for p in firewall.PROFILES}
    fw_report = firewall.FirewallReport(
        profiles, [{"Interface": "Ethernet", "Category": "Private"}], {"Private"}, [],
        firewall.rule_statistics([]), [firewall.Finding(firewall.WARNING, "1 program rule(s) accept ...")],
        None, False, "x.log")
    open_row = network.ListenerRow(firewall.Listener("TCP", "0.0.0.0", 3306, 50, "mysqld"),
                                   firewall.Exposure("open", "Open to any address (Private)", "MariaDB"))
    local_row = network.ListenerRow(firewall.Listener("TCP", "127.0.0.1", 5000, 51, "dev"),
                                    firewall.Exposure("local", "Loopback only (this PC)"))
    net_report = network.NetworkReport([network.NetItem(network.OK, "Ethernet: 1 Gbps", category="Adapter")],
                                       [open_row, local_row])
    return fw_report, net_report


def test_network_analysis_display(window):
    window._on_network_analyzed(*fake_network_reports(), "")
    assert "1 listening port(s) reachable" in window.net_summary_label.text()
    assert window.fw_profiles_tree.topLevelItemCount() == 3
    assert window.fw_findings_tree.topLevelItemCount() == 1
    assert window.net_listeners_tree.topLevelItemCount() == 1  # loopback hidden by default
    window.net_hide_local_cb.setChecked(False)
    assert window.net_listeners_tree.topLevelItemCount() == 2
    assert "does not log blocked connections" in window.fw_log_label.text()
    assert window.fw_log_toggle_btn.text() == "Enable dropped-packet logging"


def test_firewall_logging_switch_needs_confirmation(window, dialogs, monkeypatch):
    from ddcleaner import firewall
    window._on_network_analyzed(*fake_network_reports(), "")
    monkeypatch.setattr("ddcleaner.ui.tab_network.SystemUtils.check_admin_privileges", staticmethod(lambda: True))
    called = []
    monkeypatch.setattr(firewall, "set_dropped_packet_logging", lambda enabled: called.append(enabled) or (True, ""))
    dialogs["answer"] = QMessageBox.StandardButton.No
    window._toggle_firewall_logging()
    assert dialogs["question"] and not called and "firewall_logging" not in window._bg_threads


def test_live_traffic_tree_updates_in_place(window):
    from ddcleaner import traffic
    listen = traffic.Connection("TCP", 2, "0.0.0.0", 8080, "0.0.0.0", 0, "Listen", 10)
    out = traffic.Connection("TCP", 2, "192.168.1.20", 50001, "8.8.8.8", 443, "Established", 10)
    local = traffic.Connection("TCP", 2, "127.0.0.1", 50002, "127.0.0.1", 9000, "Established", 10)
    inbound = traffic.Connection("TCP", 2, "192.168.1.20", 8080, "198.51.100.3", 40000, "Established", 10)

    def snapshot(rate):
        app = traffic.AppTraffic(traffic.ProcessInfo(10, "srv.exe", r"C:\Apps\srv.exe", "My Server"),
                                 [traffic.ConnectionRow(listen, "Listen", ""),
                                  traffic.ConnectionRow(out, "Out", "Internet", "dns.google", 100, 50, rate, 0,
                                                        site="dns.google", owner="Google LLC (US)"),
                                  traffic.ConnectionRow(inbound, "In", "Internet", site="scanner.example",
                                                        owner="Evil Hosting (XX)"),
                                  traffic.ConnectionRow(local, "Out", "This PC")],
                                 received=100, sent=50, rate_in=rate)
        return traffic.TrafficSnapshot({10: app}, 0.0, True, rate, 0)

    window._on_traffic_sample(snapshot(2048), "")
    tree = window.traffic_tree
    assert tree.topLevelItemCount() == 1
    top = tree.topLevelItem(0)
    assert top.text(0) == "My Server  (PID 10)" and top.text(1) == "1 in / 1 out"
    assert top.childCount() == 3  # the connection inside this PC is hidden by default
    top.setExpanded(True)
    window._on_traffic_sample(snapshot(4096), "")
    assert tree.topLevelItem(0) is top and top.isExpanded()  # updated in place
    assert top.text(11) == "4.0 KB/s"
    summary = window.traffic_summary_label.text()
    assert "Download 4.0 KB/s" in summary and "inbound: 1 from the Internet" in summary
    window.traffic_filter.setText("dns.google")
    assert top.childCount() == 1
    window.traffic_filter.setText("")
    window.traffic_inbound_cb.setChecked(True)
    assert top.childCount() == 1 and top.child(0).text(5) == "scanner.example"
    window.traffic_inbound_cb.setChecked(False)

    window.traffic_group_combo.setCurrentText("Destination")
    groups = {tree.topLevelItem(i).text(0): tree.topLevelItem(i) for i in range(tree.topLevelItemCount())}
    assert set(groups) == {"dns.google", "scanner.example"}  # listening port has no destination
    assert groups["dns.google"].text(6) == "Google LLC (US)" and groups["dns.google"].text(4) == "8.8.8.8"
    assert groups["scanner.example"].child(0).text(0) == "My Server  (PID 10)"
    assert groups["scanner.example"].foreground(0).color() == QColor(Qt.GlobalColor.red)
    window.traffic_filter.setText("nothing-matches")
    assert tree.topLevelItemCount() == 0


def test_blocked_sources_show_their_owner(window):
    from ddcleaner import firewall
    fw_report, net_report = fake_network_reports()
    log = firewall.parse_log_lines([
        "2026-09-28 10:00:00 DROP TCP 203.0.113.5 192.168.1.20 51000 445 52 S 1 0 64240 - - - RECEIVE"])
    log.files = ["x.log"]
    log.source_owners["203.0.113.5"] = "Some Hosting Ltd (NL)"
    fw_report.log, fw_report.log_enabled = log, True
    window._on_network_analyzed(fw_report, net_report, "")
    sections = {window.fw_log_tree.topLevelItem(i).text(0): window.fw_log_tree.topLevelItem(i)
                for i in range(window.fw_log_tree.topLevelItemCount())}
    sources = sections["Inbound: most blocked sources (who tried to come in)"]
    assert sources.child(0).text(0) == "203.0.113.5: Some Hosting Ltd (NL)"
    assert window.fw_log_toggle_btn.text() == "Disable dropped-packet logging"
