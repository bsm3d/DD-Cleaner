"""ClamAV integration: command building, output parsing, signature database, quarantine, tab behaviour.
File operations stay in tmp_path; the one real clamscan run uses a harmless test signature."""

import hashlib
import os
import subprocess

import pytest
from PySide6.QtWidgets import QMessageBox

from ddcleaner import clamav
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM32, safe_environment

from test_ui_smoke import FakeRunning, dialogs, window  # noqa: F401  (fixtures)

FAKE_INSTALL = clamav.Install(r"C:\Program Files\ClamAV", r"C:\Program Files\ClamAV\clamscan.exe",
                              r"C:\Program Files\ClamAV\freshclam.exe")


# region Output parsing

def test_parse_scan_line_kinds():
    assert clamav.parse_scan_line(r"C:\a b\x.exe: Win.Test.EICAR_HDB-1 FOUND") == \
        ("found", r"C:\a b\x.exe", "Win.Test.EICAR_HDB-1")
    assert clamav.parse_scan_line(r"C:\a\x.exe: moved to 'C:\q\x.exe'") == ("moved", r"C:\a\x.exe", r"C:\q\x.exe")
    assert clamav.parse_scan_line(r"C:\a\ok.txt: OK") == ("ok", r"C:\a\ok.txt")
    assert clamav.parse_scan_line(r"C:\a\e.txt: Empty file") == ("skip", r"C:\a\e.txt")
    assert clamav.parse_scan_line(r"C:\a\locked.sys: Access denied. ERROR")[0] == "error"
    assert clamav.parse_scan_line("Scanned files: 12") == ("summary", "files", "12")
    assert clamav.parse_scan_line("----------- SCAN SUMMARY -----------") == ("other", "")
    assert clamav.parse_scan_line("LibClamAV Warning: something")[0] == "other"


def test_a_file_named_like_a_status_is_still_a_threat():
    # the threat name is whatever follows the LAST ': ', so ': ' inside a path cannot hide a detection
    assert clamav.parse_scan_line(r"C:\x: OK\evil: Trojan.Gen FOUND") == ("found", r"C:\x: OK\evil", "Trojan.Gen")

# endregion


# region Commands

def test_scan_command_excludes_our_own_folder_and_moves_to_quarantine(tmp_path):
    cmd = clamav.build_scan_command(FAKE_INSTALL, [r"C:\Users"], database=str(tmp_path / "db"),
                                    clam_folder=str(tmp_path / "clamav"))
    assert cmd[0] == FAKE_INSTALL.clamscan and cmd[-1] == r"C:\Users"
    assert f"--database={tmp_path / 'db'}" in cmd
    assert any(a.startswith("--exclude-dir=") for a in cmd)
    assert f"--move={tmp_path / 'clamav' / 'quarantine'}" in cmd
    assert not any(a.startswith("--remove") for a in cmd)  # never deletes on its own


def test_scan_command_options(tmp_path):
    cmd = clamav.build_scan_command(FAKE_INSTALL, [r"C:\x"], quarantine=False, archives=False, max_filesize_mb=999999,
                                    database=str(tmp_path), clam_folder=str(tmp_path))
    assert "--scan-archive=no" in cmd
    assert not any(a.startswith("--move") for a in cmd)
    assert "--max-filesize=4000M" in cmd  # clamped


def test_scan_command_refuses_relative_targets_and_empty_list(tmp_path):
    with pytest.raises(ValueError):
        clamav.build_scan_command(FAKE_INSTALL, ["--remove"], database=str(tmp_path), clam_folder=str(tmp_path))
    with pytest.raises(ValueError):
        clamav.build_scan_command(FAKE_INSTALL, [], database=str(tmp_path), clam_folder=str(tmp_path))


def test_update_command_and_conf(tmp_path):
    conf = clamav.write_freshclam_conf(str(tmp_path / "freshclam.conf"), str(tmp_path / "db"), str(tmp_path / "f.log"))
    text = open(conf, encoding="utf-8").read()
    assert f"DatabaseDirectory {tmp_path / 'db'}" in text and "database.clamav.net" in text
    assert os.path.isdir(tmp_path / "db")
    cmd = clamav.build_update_command(FAKE_INSTALL, conf, str(tmp_path / "db"))
    assert cmd[0] == FAKE_INSTALL.freshclam and f"--config-file={conf}" in cmd

# endregion


# region Signature database

def test_database_info_reads_cvd_headers(tmp_path):
    # ClamAV-VDB:build time:version:signatures:functionality level:...
    header = b"ClamAV-VDB:11 Oct 2026 08-00 +0000:27800:%d:90:md5:sig:builder:1700000000"
    (tmp_path / "daily.cvd").write_bytes((header % 8000).ljust(512, b" ") + b"data")
    (tmp_path / "main.cvd").write_bytes((header % 100).ljust(512, b" "))
    info = clamav.read_database_info(str(tmp_path))
    assert info.ready and info.signatures == 8100
    assert (info.built.year, info.built.month, info.built.day) == (2026, 10, 11)


def test_database_info_missing_or_empty(tmp_path):
    assert not clamav.read_database_info(str(tmp_path / "nope")).ready
    assert not clamav.read_database_info(str(tmp_path)).ready
    (tmp_path / "notes.txt").write_text("x")
    assert not clamav.read_database_info(str(tmp_path)).ready
    (tmp_path / "custom.hdb").write_text("x")
    assert clamav.read_database_info(str(tmp_path)).ready

# endregion


# region Quarantine

def make_quarantined(tmp_path, content=b"payload"):
    folder = tmp_path / "q"
    folder.mkdir(parents=True, exist_ok=True)
    stored = folder / "evil.exe"
    stored.write_bytes(content)
    original = tmp_path / "home" / "evil.exe"
    clamav.record_quarantine(str(original), str(stored), "Win.Test", str(folder))
    return str(folder), str(original), str(stored)


def test_quarantine_list_restore_and_delete(tmp_path):
    folder, original, stored = make_quarantined(tmp_path)
    entry, = clamav.list_quarantine(folder)
    assert (entry.original, entry.threat) == (original, "Win.Test")
    assert clamav.restore_quarantined(entry, folder) == ""
    assert os.path.isfile(original) and not os.path.exists(stored)
    assert clamav.list_quarantine(folder) == []

    folder, original, stored = make_quarantined(tmp_path / "again")
    entry, = clamav.list_quarantine(folder)
    assert clamav.delete_quarantined(entry, folder) == ""
    assert not os.path.exists(stored) and clamav.list_quarantine(folder) == []


def test_restore_never_overwrites(tmp_path):
    folder, original, stored = make_quarantined(tmp_path)
    os.makedirs(os.path.dirname(original))
    with open(original, "wb") as f:
        f.write(b"user data")
    entry, = clamav.list_quarantine(folder)
    assert "already exists" in clamav.restore_quarantined(entry, folder)
    assert open(original, "rb").read() == b"user data" and os.path.isfile(stored)


def test_files_without_manifest_entry_are_listed_but_not_restorable(tmp_path):
    folder = tmp_path / "q"
    folder.mkdir()
    (folder / "orphan.bin").write_bytes(b"x")
    entry, = clamav.list_quarantine(str(folder))
    assert entry.original == clamav.UNKNOWN_ORIGIN
    assert "unknown" in clamav.restore_quarantined(entry, str(folder))


def test_manifest_cannot_point_outside_the_quarantine(tmp_path):
    folder, _, _ = make_quarantined(tmp_path)
    victim = tmp_path / "important.txt"
    victim.write_text("keep me")
    clamav.record_quarantine(str(tmp_path / "x"), str(victim), "Fake", folder)
    assert all(e.stored != str(victim) for e in clamav.list_quarantine(folder))
    outside = clamav.QuarantineEntry(str(tmp_path / "x"), str(victim), "Fake", "")
    assert clamav.delete_quarantined(outside, folder) and victim.exists()
    assert clamav.restore_quarantined(outside, folder) and victim.exists()

# endregion


# region Install

def test_find_install_refuses_an_unprotected_folder(tmp_path, monkeypatch):
    base = tmp_path / "pf"
    (base / "ClamAV").mkdir(parents=True)
    for name in ("clamscan.exe", "freshclam.exe"):
        (base / "ClamAV" / name).write_bytes(b"")
    monkeypatch.setattr(clamav, "_known_folder", lambda csidl: str(base))
    monkeypatch.setattr(clamav.folder_security, "folder_risk", lambda f: [f"{f} can be modified by Users."])
    install, reason = clamav.find_install()
    assert install is None and "not protected" in reason
    monkeypatch.setattr(clamav.folder_security, "folder_risk", lambda f: [])
    install, reason = clamav.find_install()
    assert install and install.clamscan.endswith("clamscan.exe") and reason == ""


def test_find_install_reports_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(clamav, "_known_folder", lambda csidl: str(tmp_path))
    install, reason = clamav.find_install()
    assert install is None and "not installed" in reason

# endregion


# region Real clamscan (skipped when ClamAV is not installed)

@pytest.fixture
def real_install():
    install, reason = clamav.find_install()
    if install is None:
        pytest.skip(reason)
    return install


def run(cmd):
    return subprocess.run(cmd, capture_output=True, cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)


def test_real_scan_detects_a_test_signature_and_quarantines_it(real_install, tmp_path):
    clam = tmp_path / "Clam Folder"          # a space in the path: the --exclude-dir regex must cope
    db = clam / "database"
    db.mkdir(parents=True)
    sample = tmp_path / "scan me" / "sample.txt"
    sample.parent.mkdir()
    payload = b"DD-CLEANER-HARMLESS-TEST-STRING"
    sample.write_bytes(payload)
    (tmp_path / "scan me" / "clean.txt").write_bytes(b"hello")
    (db / "test.hdb").write_text(f"{hashlib.md5(payload).hexdigest()}:{len(payload)}:Test.Harmless.DD\n")

    cmd = clamav.build_scan_command(real_install, [str(sample.parent)], database=str(db), clam_folder=str(clam))
    os.makedirs(clam / "quarantine")
    result = run(cmd)
    lines = result.stdout.decode("utf-8", errors="replace").splitlines()
    kinds = [clamav.parse_scan_line(line) for line in lines]
    found = [k for k in kinds if k[0] == "found"]
    moved = [k for k in kinds if k[0] == "moved"]
    assert result.returncode == 1, lines
    assert found and found[0][2].startswith("Test.Harmless.DD")
    assert moved and not sample.exists()
    assert (tmp_path / "scan me" / "clean.txt").exists()

    clamav.record_quarantine(moved[0][1], moved[0][2], found[0][2], str(clam / "quarantine"))
    entry, = clamav.list_quarantine(str(clam / "quarantine"))
    assert clamav.restore_quarantined(entry, str(clam / "quarantine")) == ""
    assert sample.read_bytes() == payload

    # the scan must skip our own folder: pointing it at the parent finds nothing in database/ or quarantine/
    (clam / "quarantine" / "known_bad.txt").write_bytes(payload)
    again = run(clamav.build_scan_command(real_install, [str(clam)], database=str(db), clam_folder=str(clam)))
    assert again.returncode == 0, again.stdout.decode(errors="replace")

# endregion


# region Tab

def test_scan_lines_fill_the_threat_list(window, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setattr(clamav, "quarantine_dir", lambda: str(tmp_path / "q"))
    window.clam_counts = {"files": 0, "found": 0, "errors": 0}
    window.clam_threats = {}
    stored = tmp_path / "q" / "bad.exe"
    stored.parent.mkdir()
    stored.write_bytes(b"x")
    window._on_clam_scan_lines([
        r"C:\ok.txt: OK",
        r"C:\<h1>bad</h1>.exe: Win.Test FOUND",
        r"C:\<h1>bad</h1>.exe: moved to '" + str(stored) + "'",
        r"C:\locked.sys: Access denied. ERROR",
    ])
    assert window.clam_counts == {"files": 2, "found": 1, "errors": 1}
    row = window.clam_threat_tree.topLevelItem(0)
    assert (row.text(0), row.text(1), row.text(2)) == (r"C:\<h1>bad</h1>.exe", "Win.Test", "Quarantined")
    assert [e.threat for e in clamav.list_quarantine()] == ["Win.Test"]


def test_scan_needs_the_signature_database(window, dialogs, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setattr(clamav, "find_install", lambda: (FAKE_INSTALL, ""))
    monkeypatch.setattr(clamav, "read_database_info", lambda folder=None: clamav.DatabaseInfo())
    window._start_clam_scan([str(tmp_path)])
    assert dialogs["warning"] and window.clam_scan_worker is None
    assert window.clam_pages.currentIndex() == 2  # sent to the update page


def test_scan_without_clamav_installed_explains_why(window, dialogs, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setattr(clamav, "find_install", lambda: (None, "ClamAV is not installed in C:\\Program Files\\ClamAV."))
    window._start_clam_scan([str(tmp_path)])
    assert dialogs["warning"] and window.clam_scan_worker is None


def test_antivirus_operations_refuse_to_overlap(window, dialogs):  # noqa: F811
    window.clam_update_worker = FakeRunning()
    window._start_clam_scan([r"C:\Windows"])
    window._start_clam_update()
    assert len(dialogs["info"]) == 2 and not dialogs["question"]


def test_update_asks_before_downloading(window, dialogs, monkeypatch):  # noqa: F811
    monkeypatch.setattr(clamav, "find_install", lambda: (FAKE_INSTALL, ""))
    dialogs["answer"] = QMessageBox.StandardButton.No
    window._start_clam_update()
    assert dialogs["question"] and window.clam_update_worker is None


def test_closing_stops_a_running_scan(window, dialogs):  # noqa: F811
    class Scan(FakeRunning):
        stopped = False

        def stop(self):
            self.stopped = True
            self.running = False

    scan = Scan()
    window.clam_scan_worker = scan
    dialogs["answer"] = QMessageBox.StandardButton.Yes
    event = type("E", (), {"accept": lambda s: None, "ignore": lambda s: None})()
    window.closeEvent(event)
    assert scan.stopped

# endregion


# region Manifest robustness (atomic write, corrupted manifest)

def test_manifest_write_is_atomic(tmp_path, monkeypatch):
    """record_quarantine must never leave a half-written manifest.json on disk: a reader that ran mid-write
    would otherwise see truncated JSON."""
    folder, _, _ = make_quarantined(tmp_path)
    real_replace = os.replace
    calls = []

    def spying_replace(src, dst):
        calls.append((src, dst))
        assert os.path.isfile(src) and src.endswith(".tmp")
        real_replace(src, dst)
    monkeypatch.setattr(clamav.os, "replace", spying_replace)
    (tmp_path / "q" / "x2.exe").write_bytes(b"evil2")
    clamav.record_quarantine(str(tmp_path / "x2"), str(tmp_path / "q" / "x2.exe"), "Another.Threat", folder)
    assert calls  # os.replace was actually used, not a direct write
    assert not os.path.isfile(os.path.join(folder, clamav.MANIFEST_NAME + ".tmp"))  # no leftover temp file
    assert len(clamav.list_quarantine(folder)) == 2


def test_a_corrupted_manifest_is_preserved_instead_of_silently_overwritten(tmp_path):
    """Before the fix, record_quarantine() on a manifest.json that failed to parse would call _read_manifest
    (which returns [] for bad JSON) and write that [] straight back, destroying every entry. The corrupted
    file must survive, renamed, so nothing is silently lost."""
    folder, original, stored = make_quarantined(tmp_path)
    manifest_path = os.path.join(folder, clamav.MANIFEST_NAME)
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write("{not valid json")  # simulate a crash mid-write
    (tmp_path / "q" / "second.exe").write_bytes(b"evil2")
    clamav.record_quarantine(str(tmp_path / "home" / "second.exe"), str(tmp_path / "q" / "second.exe"),
                             "Second.Threat", folder)
    assert os.path.isfile(manifest_path + ".corrupt")
    with open(manifest_path + ".corrupt", encoding="utf-8") as f:
        assert f.read() == "{not valid json"
    # the new entry was still recorded despite the old file being unreadable
    entries = clamav.list_quarantine(folder)
    assert any(e.threat == "Second.Threat" for e in entries)


def test_an_empty_manifest_file_is_not_treated_as_corrupted(tmp_path):
    """A genuinely empty list (every quarantined file restored/deleted) must not be mistaken for corruption."""
    folder, original, stored = make_quarantined(tmp_path)
    entry, = clamav.list_quarantine(folder)
    clamav.delete_quarantined(entry, folder)
    assert clamav.list_quarantine(folder) == []
    manifest_path = os.path.join(folder, clamav.MANIFEST_NAME)
    assert os.path.isfile(manifest_path)
    (tmp_path / "q" / "x3.exe").write_bytes(b"evil3")
    clamav.record_quarantine(str(tmp_path / "home" / "x3.exe"), str(tmp_path / "q" / "x3.exe"), "X3", folder)
    assert not os.path.isfile(manifest_path + ".corrupt")
    assert len(clamav.list_quarantine(folder)) == 1

# endregion
