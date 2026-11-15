"""VirusTotal: hash lookup, upload rules, quota handling and the window. The network is replaced by a fake: nothing is
ever sent, and the API key is stored in pytest's temporary folder."""

import hashlib
import json
import os
import urllib.request

import pytest
from PySide6.QtWidgets import QDialog, QMessageBox, QPushButton, QTreeWidget

from ddcleaner import api_keys, virustotal as vt

from test_ui_smoke import dialogs, window  # noqa: F401  (fixtures)

KEY = "a" * 64
SHA = hashlib.sha256(b"MZ" + b"\x00" * 64).hexdigest()


class FakeHttp:
    """Answers requests from a queue of (status, body) and keeps every request it received."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.requests = []

    def __call__(self, request: urllib.request.Request):
        self.requests.append(request)
        status, body = self.answers.pop(0) if self.answers else (200, {})
        return status, json.dumps(body).encode("utf-8")


def file_answer(malicious=0, suspicious=0, harmless=60, undetected=10, **extra):
    attrs = {"last_analysis_stats": {"malicious": malicious, "suspicious": suspicious, "harmless": harmless,
                                     "undetected": undetected}, "meaningful_name": "evil.exe",
             "names": ["evil.exe", "e.exe"], "type_description": "Win32 EXE", **extra}
    return 200, {"data": {"attributes": attrs}}


def make_file(tmp_path, name="sample.exe", data=b"MZ" + b"\x00" * 64):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


# region Lookup

def test_lookup_reads_the_verdict_and_sends_only_the_hash():
    http = FakeHttp(file_answer(malicious=5, suspicious=1, popular_threat_classification={"suggested_threat_label": "trojan.agent"}))
    report = vt.lookup(SHA, KEY, http)
    assert report.found and report.total == 76 and report.verdict == "6/76 engines flag it (trojan.agent)"
    assert report.severity == 2 and report.names == ["evil.exe", "e.exe"] and report.link == vt.GUI + SHA
    request = http.requests[0]
    assert request.full_url == f"{vt.API}/files/{SHA}" and request.get_method() == "GET" and request.data is None
    assert request.get_header("X-apikey") == KEY


def test_severity_levels():
    assert vt.lookup(SHA, KEY, FakeHttp(file_answer())).severity == 0
    assert vt.lookup(SHA, KEY, FakeHttp(file_answer(malicious=1))).severity == 1
    assert vt.lookup(SHA, KEY, FakeHttp(file_answer(malicious=2, suspicious=3))).severity == 1
    assert vt.lookup(SHA, KEY, FakeHttp(file_answer(malicious=3))).severity == 2
    assert vt.lookup(SHA, KEY, FakeHttp((404, {}))).severity == -1


def test_unknown_hash_and_errors():
    unknown = vt.lookup(SHA, KEY, FakeHttp((404, {"error": {"code": "NotFoundError"}})))
    assert not unknown.found and unknown.verdict == "Unknown to VirusTotal"
    with pytest.raises(vt.VtError, match="refused the API key"):
        vt.lookup(SHA, KEY, FakeHttp((401, {})))
    with pytest.raises(vt.VtError, match="quota"):
        vt.lookup(SHA, KEY, FakeHttp((429, {})))
    with pytest.raises(vt.VtError, match="not available"):
        vt.lookup(SHA, KEY, FakeHttp((503, {})))
    with pytest.raises(vt.VtError, match="400"):
        vt.lookup(SHA, KEY, FakeHttp((400, {"error": {"message": "bad request"}})))


def test_a_garbled_answer_is_not_a_crash():
    class Garbage:
        def __call__(self, request):
            return 200, b"<html>captive portal</html>"
    assert not vt.lookup(SHA, KEY, Garbage()).malicious


def test_check_files_waits_between_requests_and_reports_each_file(tmp_path):
    a, b = make_file(tmp_path, "a.exe"), make_file(tmp_path, "b.exe", b"MZ other")
    http = FakeHttp(file_answer(malicious=4), (404, {}))
    sleeps, seen = [], []
    results = vt.check_files([a, b], KEY, http, seen.append, sleep=sleeps.append)
    assert [r.report.found for r in results] == [True, False] and sleeps == [vt.REQUEST_GAP_SECONDS]
    assert results[0].sha256 == hashlib.sha256(open(a, "rb").read()).hexdigest() and len(seen) == 2


def test_check_files_survives_an_unreadable_file_but_stops_on_a_bad_key(tmp_path):
    good = make_file(tmp_path)
    results = vt.check_files([str(tmp_path / "gone.exe"), good], KEY, FakeHttp(file_answer()), sleep=lambda s: None)
    assert results[0].error and results[1].report.found
    http = FakeHttp((401, {}))
    stopped = vt.check_files([good, make_file(tmp_path, "b.exe", b"MZ2")], KEY, http, sleep=lambda s: None)
    assert len(stopped) == 1 and "refused" in stopped[0].error and len(http.requests) == 1
    assert vt.check_files([good], KEY, FakeHttp(), stop=lambda: True) == []

# endregion


# region What may be sent

def test_programs_scripts_and_archives_may_be_sent_documents_may_not(tmp_path):
    assert vt.upload_problem(make_file(tmp_path, "tool.exe")) == ""
    assert vt.upload_problem(make_file(tmp_path, "run.ps1", b"Write-Host hi")) == ""
    assert vt.upload_problem(make_file(tmp_path, "loader.dat", b"MZ" + b"\x00" * 64)) == ""      # an exe in disguise
    assert vt.upload_problem(make_file(tmp_path, "pack.zip", b"PK\x03\x04" + b"\x00" * 40)) == ""
    assert "documents" in vt.upload_problem(make_file(tmp_path, "report.pdf", b"%PDF-1.7 secret"))
    assert vt.upload_problem(make_file(tmp_path, "photo.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 40))
    assert vt.upload_problem(make_file(tmp_path, "notes.txt", b"my passwords are here"))
    assert vt.upload_problem(make_file(tmp_path, "empty.exe", b"")) == "The file is empty."
    assert vt.upload_problem(str(tmp_path / "nope.exe"))


def test_big_files_are_refused(tmp_path, monkeypatch):
    path = make_file(tmp_path)
    monkeypatch.setattr(vt, "MAX_UPLOAD", 10)
    assert "larger than" in vt.upload_problem(path)


def test_archives_come_with_a_warning(tmp_path):
    assert vt.upload_warning(make_file(tmp_path, "pack.zip", b"PK\x03\x04" + b"\x00" * 40))
    assert vt.upload_warning(make_file(tmp_path)) == ""


def test_upload_builds_a_multipart_request_with_a_safe_file_name(tmp_path):
    path = make_file(tmp_path, "évil‮exe.exe", b"MZ-payload")
    http = FakeHttp((200, {"data": {"id": "analysis-1"}}))
    assert vt.upload(path, KEY, http) == "analysis-1"
    request = http.requests[0]
    body = request.data.decode("latin-1")
    assert request.full_url == vt.API + "/files" and request.get_method() == "POST"
    assert request.get_header("Content-type").startswith("multipart/form-data; boundary=")
    assert "MZ-payload" in body and 'filename="' in body
    assert all(ord(c) < 128 for c in body.split('filename="')[1].split('"')[0])


def test_a_refused_file_never_reaches_the_network(tmp_path):
    http = FakeHttp()
    with pytest.raises(vt.VtError):
        vt.upload(make_file(tmp_path, "secret.pdf", b"%PDF-1.7"), KEY, http)
    assert http.requests == []


def test_rejected_upload_is_reported(tmp_path):
    with pytest.raises(vt.VtError, match="did not accept"):
        vt.upload(make_file(tmp_path), KEY, FakeHttp((400, {"error": {"message": "file too big"}})))


def test_waiting_for_the_analysis():
    queued = (200, {"data": {"attributes": {"status": "queued"}}})
    done = (200, {"data": {"attributes": {"status": "completed", "stats": {"malicious": 2, "harmless": 70}}}})
    sleeps = []
    http = FakeHttp(queued, queued, done, file_answer(malicious=2))
    report = vt.wait_for_analysis("id", SHA, KEY, http, sleep=sleeps.append)
    assert report.status == "completed" and report.malicious == 2 and sleeps == [15, 15]
    # the file report is not ready yet: the analysis numbers are used
    http = FakeHttp(done, (404, {}))
    assert vt.wait_for_analysis("id", SHA, KEY, http, sleep=lambda s: None).malicious == 2


def test_waiting_gives_up_after_the_limit_and_when_stopped():
    queued = (200, {"data": {"attributes": {"status": "queued"}}})
    report = vt.wait_for_analysis("id", SHA, KEY, FakeHttp(*[queued] * 50), sleep=lambda s: None, waited=30, step=15)
    assert report.found and report.status == "queued" and report.verdict == "Analysis in progress"
    assert vt.wait_for_analysis("id", SHA, KEY, FakeHttp(queued), stop=lambda: True).status == "queued"


def test_submit_file_end_to_end(tmp_path):
    path = make_file(tmp_path)
    http = FakeHttp((200, {"data": {"id": "a1"}}), (200, {"data": {"attributes": {"status": "completed"}}}),
                    file_answer(malicious=9))
    messages = []
    result = vt.submit_file(path, KEY, http, messages.append, sleep=lambda s: None)
    assert result.uploaded and not result.error and result.report.severity == 2 and len(messages) == 2
    failed = vt.submit_file(make_file(tmp_path, "d.docx", b"PK\x03\x04docx"), KEY, FakeHttp(), sleep=lambda s: None)
    assert failed.error and failed.report is None

# endregion


# region The window

def test_the_protection_page_points_to_the_preferences(window):  # noqa: F811
    assert "no key" in window.vt_key_status.text().lower()
    api_keys.set_key("virustotal", KEY)
    window._refresh_vt_key_status()
    assert "saved (ends with aaaa)" in window.vt_key_status.text().lower() and vt.load_key() == KEY


def capture_calls(window, monkeypatch):
    """Run what the window would hand to a worker thread right away."""
    calls = []

    def start(attr, function, on_done, button=None, status=""):
        calls.append((attr, status))
        try:
            result, error = function(), ""
        except Exception as e:  # noqa: BLE001
            result, error = None, str(e)
        on_done(result, error)
        return True
    monkeypatch.setattr(window, "_start_call", start)
    return calls


def test_lookup_needs_files_and_a_key(window, dialogs, tmp_path, monkeypatch):  # noqa: F811
    opened = []
    monkeypatch.setattr(window, "_open_preferences", lambda: opened.append(True))
    window._virustotal_check([])
    assert dialogs["info"] and not opened
    window._virustotal_check([make_file(tmp_path)])
    assert opened == [True]


def test_lookup_shows_the_verdicts(window, dialogs, tmp_path, monkeypatch):  # noqa: F811
    api_keys.set_key("virustotal", KEY)
    calls = capture_calls(window, monkeypatch)
    sample = make_file(tmp_path)
    monkeypatch.setattr(vt, "check_files", lambda paths, key, **kw: [
        vt.VtResult(paths[0], SHA, vt.lookup(SHA, key, FakeHttp(file_answer(malicious=7))))])
    seen = {}

    def inspect(dialog):
        tree = dialog.findChild(QTreeWidget)
        seen["rows"] = [[tree.topLevelItem(i).text(c) for c in range(3)] for i in range(tree.topLevelItemCount())]
        seen["red"] = tree.topLevelItem(0).foreground(1).color().red()
        return 0
    monkeypatch.setattr(QDialog, "exec", inspect)
    window._virustotal_check([sample])
    assert calls[0][0] == "vt_worker"
    assert seen["rows"] == [["sample.exe", "7/77 engines flag it", SHA]] and seen["red"] == 255


def show_results(window, monkeypatch, results, then):
    def inspect(dialog):
        tree = dialog.findChild(QTreeWidget)
        tree.setCurrentItem(tree.topLevelItem(0))
        tree.topLevelItem(0).setSelected(True)
        then(dialog, tree)
        return 0
    monkeypatch.setattr(QDialog, "exec", inspect)
    window._show_vt_results(results)


def test_sending_needs_a_confirmation_and_never_happens_on_no(window, dialogs, tmp_path, monkeypatch):  # noqa: F811
    api_keys.set_key("virustotal", KEY)
    calls = capture_calls(window, monkeypatch)
    sent = []
    monkeypatch.setattr(vt, "submit_file", lambda path, key, **kw: sent.append(path) or vt.VtResult(
        path, SHA, vt.VtReport(True, SHA, malicious=12, harmless=50), uploaded=True))
    path = make_file(tmp_path)
    unknown = vt.VtResult(path, SHA, vt.VtReport(False, SHA))

    def click_no(dialog, tree):
        dialogs["answer"] = QMessageBox.StandardButton.No
        window._send_vt_selected()
        assert dialogs["question"] and not sent and not calls
        assert "cannot be undone" in dialogs["question"][-1][0]
    show_results(window, monkeypatch, [unknown], click_no)

    def click_yes(dialog, tree):
        dialogs["answer"] = QMessageBox.StandardButton.Yes
        window._send_vt_selected()
        assert sent == [path] and calls[-1][0] == "vt_worker"
        assert tree.topLevelItem(0).text(1) == "12/62 engines flag it"
        assert window.vt_send_btn.isEnabled()
    show_results(window, monkeypatch, [unknown], click_yes)


def test_known_files_and_forbidden_files_are_not_sent(window, dialogs, tmp_path, monkeypatch):  # noqa: F811
    api_keys.set_key("virustotal", KEY)
    calls = capture_calls(window, monkeypatch)
    known = vt.VtResult(make_file(tmp_path), SHA, vt.VtReport(True, SHA, harmless=60))

    def click(dialog, tree):
        window._send_vt_selected()
    show_results(window, monkeypatch, [known], click)
    assert dialogs["info"] and not dialogs["question"] and not calls

    document = vt.VtResult(make_file(tmp_path, "cv.pdf", b"%PDF-1.7 private"), SHA, vt.VtReport(False, SHA))
    before = len(dialogs["warning"])
    show_results(window, monkeypatch, [document], click)
    assert len(dialogs["warning"]) == before + 1 and not dialogs["question"] and not calls


def test_the_report_opens_only_for_known_files(window, dialogs, tmp_path, monkeypatch):  # noqa: F811
    from PySide6.QtGui import QDesktopServices
    opened = []
    monkeypatch.setattr(QDesktopServices, "openUrl", staticmethod(lambda url: opened.append(url.toString()) or True))
    unknown = vt.VtResult(make_file(tmp_path), SHA, vt.VtReport(False, SHA))
    show_results(window, monkeypatch, [unknown], lambda d, t: window._open_vt_report())
    assert not opened and dialogs["info"]
    known = vt.VtResult(make_file(tmp_path), SHA, vt.VtReport(True, SHA))
    show_results(window, monkeypatch, [known], lambda d, t: window._open_vt_report())
    assert opened == [vt.GUI + SHA]


def test_a_failed_lookup_is_shown_not_raised(window, dialogs, monkeypatch):  # noqa: F811
    window._on_vt_checked(None, "boom")
    assert dialogs["warning"]


def test_buttons_exist_on_the_processes_persistence_and_quarantine_pages(window):  # noqa: F811
    texts = [b.text() for b in window.clam_tab_page.findChildren(QPushButton)]
    assert texts.count("🛰 VirusTotal") == 3

# endregion
