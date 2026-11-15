"""Scan cache, scan planning, parallel clamscan processes and the new options of the Scan page. The real clamscan
runs only against a tiny test signature database in pytest's temporary folder."""

import hashlib
import os
import sqlite3
import subprocess
import time

import pytest

from ddcleaner import clamav, parallel_scan as ps, scan_cache as sc
from ddcleaner.workers import ClamScanPool

from test_clamav import FAKE_INSTALL
from test_ui_smoke import FakeRunning, dialogs, window  # noqa: F401  (fixtures)

PAYLOAD = b"DD-CLEANER-HARMLESS-TEST-STRING"
real_install = clamav.find_install()[0]
needs_clamav = pytest.mark.skipif(real_install is None, reason="ClamAV is not installed")


@pytest.fixture(autouse=True)
def plenty_of_memory(monkeypatch):
    """Other programs may be using the RAM while the tests run: the planner must see plenty, so the number of
    processes it plans does not depend on the machine's mood (thread_count itself is tested with explicit values)."""
    monkeypatch.setattr(ps, "free_memory", lambda: 64 * 1024 ** 3)


def make_files(folder, count, prefix="f", size=10):
    folder.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (folder / f"{prefix}{i:05d}.txt").write_bytes(bytes([65 + i % 20]) * size)


# region The cache

def test_a_file_is_skipped_only_when_clean_unchanged_recent_and_checked_as_much(tmp_path):
    cache = sc.ScanCache(str(tmp_path / "c.sqlite"))
    key, now = sc.key_of(r"C:\Data\A.txt"), 1_000_000.0
    flags = sc.FLAG_ARCHIVES | sc.FLAG_HEURISTICS
    assert not cache.is_clean(key, 10, 5, flags, 7, now)                      # unknown
    cache.mark_pending([(key, 10, 5)])
    assert not cache.is_clean(key, 10, 5, flags, 7, now)                      # pending is never skipped
    cache.mark_clean([key], flags, now)
    assert cache.is_clean(key, 10, 5, flags, 7, now + 3600)
    assert not cache.is_clean(key, 11, 5, flags, 7, now + 1)                  # size changed
    assert not cache.is_clean(key, 10, 6, flags, 7, now + 1)                  # date changed
    assert not cache.is_clean(key, 10, 5, flags, 7, now + 8 * 86400)          # too old
    assert cache.is_clean(key, 10, 5, sc.FLAG_ARCHIVES, 7, now + 1)           # a lighter scan is covered
    assert cache.is_clean(key, 10, 5, 0, 7, now + 1)
    assert not cache.is_clean(key, 10, 5, flags | sc.FLAG_PUA, 7, now + 1)    # a deeper scan is not
    assert not cache.is_clean(key, 10, 5, flags | sc.FLAG_THOROUGH, 7, now + 1)
    cache.close()


def test_the_cache_is_case_insensitive_and_remembers_across_instances(tmp_path):
    path = str(tmp_path / "c.sqlite")
    cache = sc.ScanCache(path)
    cache.mark_pending([(sc.key_of(r"C:\Data\A.TXT"), 1, 1)])
    cache.mark_clean([sc.key_of(r"c:\data\a.txt")], 0, 100.0)
    cache.close()
    again = sc.ScanCache(path)
    assert again.is_clean(sc.key_of(r"C:\DATA\a.txt"), 1, 1, 0, 7, 101.0) and again.count() == 1
    again.close()


def test_a_changed_file_loses_its_clean_status_when_planned_again(tmp_path):
    cache = sc.ScanCache(str(tmp_path / "c.sqlite"))
    key = sc.key_of(r"C:\x.txt")
    cache.mark_pending([(key, 1, 1)])
    cache.mark_clean([key], 0, 100.0)
    cache.mark_pending([(key, 2, 2)])                  # the file changed, a new scan is planned
    assert not cache.is_clean(key, 1, 1, 0, 7, 101.0) and not cache.is_clean(key, 2, 2, 0, 7, 101.0)
    cache.close()


def test_prune_and_clear(tmp_path):
    cache = sc.ScanCache(str(tmp_path / "c.sqlite"))
    old, new, pending = (sc.key_of(p) for p in (r"C:\old", r"C:\new", r"C:\pending"))
    cache.mark_pending([(old, 1, 1), (new, 1, 1), (pending, 1, 1)])
    cache.mark_clean([old], 0, 0.0)
    cache.mark_clean([new], 0, 100 * 86400.0)
    assert cache.prune(30, now=100 * 86400.0) == 2 and cache.count() == 1      # the old one and the pending one
    cache.clear()
    assert cache.count() == 0
    cache.close()


def test_a_damaged_cache_file_is_replaced(tmp_path):
    path = tmp_path / "c.sqlite"
    path.write_bytes(b"this is not a database" * 100)
    cache = sc.ScanCache(str(path))
    cache.mark_pending([(sc.key_of(r"C:\x"), 1, 1)])
    cache.close()
    assert sqlite3.connect(str(path)).execute("SELECT COUNT(*) FROM files").fetchone()[0] == 1

# endregion


# region Options and thread count

def test_scan_options_map_to_cache_flags():
    assert ps.ScanOptions().flags == sc.FLAG_ARCHIVES | sc.FLAG_HEURISTICS
    assert ps.ScanOptions(fast=True).flags == 0 and not ps.ScanOptions(fast=True).effective_archives
    assert ps.ScanOptions(archives=False).flags == sc.FLAG_HEURISTICS
    assert ps.ScanOptions(pua=True, thorough=True).flags == 15


@pytest.mark.parametrize("requested, cpus, free_gb, expected", [
    (0, 32, 100, 8), (0, 8, 100, 4), (0, 2, 100, 1), (3, 32, 100, 3), (20, 32, 100, 8),
    (0, 32, 6.5, 1), (0, 32, 9, 3), (5, 4, 100, 4), (0, 32, 1, 1)])
def test_thread_count(requested, cpus, free_gb, expected):
    assert ps.thread_count(requested, cpus, int(free_gb * 1024 ** 3)) == expected


def test_exit_codes_combine():
    assert ps.combine_codes([0, 0]) == 0 and ps.combine_codes([0, 1, 2]) == 1 and ps.combine_codes([0, 2]) == 2
    assert ps.combine_codes([]) == 0


def test_fast_mode_and_file_lists_in_the_command(tmp_path):
    fast = clamav.build_scan_command(FAKE_INSTALL, [], fast=True, file_list=str(tmp_path / "l.txt"),
                                     database=str(tmp_path), clam_folder=str(tmp_path))
    assert "--heuristic-alerts=no" in fast and "--phishing-scan-urls=no" in fast and "--scan-archive=no" in fast
    assert fast[-1] == f"--file-list={tmp_path / 'l.txt'}"
    full = clamav.build_scan_command(FAKE_INSTALL, [r"C:\x"], database=str(tmp_path), clam_folder=str(tmp_path))
    assert "--heuristic-alerts=yes" in full and "--scan-archive=no" not in full
    with pytest.raises(ValueError):
        clamav.build_scan_command(FAKE_INSTALL, [], database=str(tmp_path), clam_folder=str(tmp_path))

# endregion


# region Planning

def listed(plan):
    out = []
    for path in plan.lists:
        out += open(path, encoding="utf-8").read().splitlines()
    return out


def test_the_plan_lists_files_below_the_targets_and_ignores_the_useless(tmp_path):
    root = tmp_path / "scan"
    make_files(root / "a", 3)
    make_files(root / "b" / "deep", 2)
    (root / "empty.txt").write_bytes(b"")
    (root / "big.bin").write_bytes(b"x" * (2 * 1024 * 1024))
    single = tmp_path / "single.txt"
    single.write_bytes(b"one")
    plan = ps.make_plan([str(root), str(single), str(tmp_path / "missing")], ps.ScanOptions(max_filesize_mb=1), None,
                        str(tmp_path / "work"))
    assert plan.to_scan == 6 and plan.skipped == 0
    names = sorted(os.path.basename(p) for p in listed(plan))
    assert "empty.txt" not in names and "big.bin" not in names and "single.txt" in names and len(names) == 6


def test_our_own_folder_is_left_out(tmp_path):
    make_files(tmp_path / "mine" / "quarantine", 2)
    make_files(tmp_path / "other", 2)
    plan = ps.make_plan([str(tmp_path)], ps.ScanOptions(), None, str(tmp_path / "work"), exclude_folder=str(tmp_path / "mine"))
    assert sorted(os.path.basename(os.path.dirname(p)) for p in listed(plan)) == ["other", "other"]


def test_the_plan_does_not_cross_junctions(tmp_path):
    make_files(tmp_path / "target", 2)
    root = tmp_path / "scan"
    root.mkdir()
    done = subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "link"), str(tmp_path / "target")], capture_output=True)
    if done.returncode != 0:
        pytest.skip("cannot create a junction here")
    assert ps.make_plan([str(root)], ps.ScanOptions(), None, str(tmp_path / "work")).to_scan == 0


def test_unchanged_clean_files_are_skipped_and_changed_ones_are_not(tmp_path):
    root = tmp_path / "scan"
    make_files(root, 5)
    cache = sc.ScanCache(str(tmp_path / "c.sqlite"))
    options = ps.ScanOptions()
    first = ps.make_plan([str(root)], options, cache, str(tmp_path / "w1"))
    assert first.to_scan == 5 and first.skipped == 0
    cache.mark_clean([sc.key_of(p) for p in listed(first)], options.flags)       # clamscan said OK to all of them
    second = ps.make_plan([str(root)], options, cache, str(tmp_path / "w2"))
    assert second.to_scan == 0 and second.skipped == 5 and second.lists == []
    (root / "f00002.txt").write_bytes(b"changed content")
    third = ps.make_plan([str(root)], options, cache, str(tmp_path / "w3"))
    assert third.to_scan == 1 and third.skipped == 4 and listed(third) == [str(root / "f00002.txt")]
    # a deeper scan than the one that cleared them cannot skip anything
    deeper = ps.make_plan([str(root)], ps.ScanOptions(pua=True), cache, str(tmp_path / "w4"))
    assert deeper.to_scan == 5
    # the cache can be switched off
    cache.mark_clean([sc.key_of(p) for p in listed(third)], options.flags)
    off = ps.make_plan([str(root)], ps.ScanOptions(use_cache=False), cache, str(tmp_path / "w5"))
    assert off.to_scan == 5 and off.skipped == 0
    cache.close()


def test_a_file_that_changes_after_listing_is_not_recorded_as_clean(tmp_path):
    root = tmp_path / "scan"
    make_files(root, 1)
    cache = sc.ScanCache(str(tmp_path / "c.sqlite"))
    options = ps.ScanOptions()
    plan = ps.make_plan([str(root)], options, cache, str(tmp_path / "w1"))
    target = root / "f00000.txt"
    target.write_bytes(b"changed while the scan ran")                 # after the listing, before clamscan reported
    cache.mark_clean([sc.key_of(p) for p in listed(plan)], options.flags)
    assert ps.make_plan([str(root)], options, cache, str(tmp_path / "w2")).to_scan == 1
    cache.close()


def test_work_is_shared_between_lists_only_when_there_is_enough_of_it(tmp_path):
    make_files(tmp_path / "many", 1200)
    plan = ps.make_plan([str(tmp_path / "many")], ps.ScanOptions(), None, str(tmp_path / "w"), max_threads=4)
    assert plan.to_scan == 1200 and len(plan.lists) == 2                    # 1200 // 500 processes
    assert sorted(listed(plan)) == sorted(str(p) for p in (tmp_path / "many").iterdir())
    assert abs(len(open(plan.lists[0]).read().splitlines()) - len(open(plan.lists[1]).read().splitlines())) <= 1
    few = ps.make_plan([str(tmp_path / "many")], ps.ScanOptions(max_filesize_mb=1), None, str(tmp_path / "w2"), max_threads=1)
    assert len(few.lists) == 1
    tiny = tmp_path / "tiny"
    make_files(tiny, 10)
    small = ps.make_plan([str(tiny)], ps.ScanOptions(), None, str(tmp_path / "w3"), max_threads=8)
    assert len(small.lists) == 1 and len(listed(small)) == 10             # the other lists were merged, nothing lost


def test_accented_paths_survive_the_file_list(tmp_path):
    make_files(tmp_path / "Téléchargements é", 1)
    plan = ps.make_plan([str(tmp_path)], ps.ScanOptions(), None, str(tmp_path / "w"))
    assert listed(plan) == [str(tmp_path / "Téléchargements é" / "f00000.txt")]


def test_planning_can_be_stopped_and_reports_progress(tmp_path):
    make_files(tmp_path / "scan", 20)
    assert ps.make_plan([str(tmp_path / "scan")], ps.ScanOptions(), None, str(tmp_path / "w"), stop=lambda: True).to_scan == 0
    messages = []
    ps.PROGRESS_EVERY, old = 5, ps.PROGRESS_EVERY
    try:
        ps.make_plan([str(tmp_path / "scan")], ps.ScanOptions(), None, str(tmp_path / "w2"), progress=messages.append)
    finally:
        ps.PROGRESS_EVERY = old
    assert messages and "Listing files" in messages[0]

# endregion


# region Real clamscan processes

def run_pool(tmp_path, targets, **options):
    clam = tmp_path / "Clam Folder"
    db = clam / "database"
    db.mkdir(parents=True, exist_ok=True)
    (db / "test.hdb").write_text(f"{hashlib.md5(PAYLOAD).hexdigest()}:{len(PAYLOAD)}:Test.Harmless.DD\n")
    (clam / "quarantine").mkdir(exist_ok=True)
    pool = ClamScanPool(real_install, [str(t) for t in targets], ps.ScanOptions(**options), database=str(db),
                        clam_folder=str(clam))
    got = {"lines": [], "done": None, "planned": None, "progress": []}
    pool.lines.connect(got["lines"].extend)
    pool.done.connect(lambda code: got.__setitem__("done", code))
    pool.planned.connect(lambda *a: got.__setitem__("planned", a))
    pool.progress.connect(got["progress"].append)
    pool.run()                                                    # synchronous: QThread.run is a plain method
    got["pool"], got["clam"] = pool, clam
    return got


@needs_clamav
def test_a_real_parallel_scan_finds_the_threat_and_remembers_the_clean_files(tmp_path):
    root = tmp_path / "scan me"
    make_files(root, 1100)
    bad = root / "sample.txt"
    bad.write_bytes(PAYLOAD)
    first = run_pool(tmp_path, [root], threads=2)
    kinds = [clamav.parse_scan_line(l) for l in first["lines"]]
    assert first["done"] == 1 and first["planned"] == (1101, 0, 2), first["lines"][:5]
    assert [k[2] for k in kinds if k[0] == "found"] == ["Test.Harmless.DD.UNOFFICIAL"] or \
        [k[2].startswith("Test.Harmless.DD") for k in kinds if k[0] == "found"] == [True]
    assert any(k[0] == "moved" for k in kinds) and not bad.exists()                     # quarantined
    assert sum(1 for k in kinds if k[0] == "ok") == 1100
    assert not (first["clam"] / "work").exists()                                         # list files are cleaned up

    second = run_pool(tmp_path, [root], threads=2)
    assert second["done"] == 0 and second["planned"] == (0, 1100, 0) and second["lines"] == []

    (root / "f00007.txt").write_bytes(PAYLOAD)                                           # a changed file is scanned again
    third = run_pool(tmp_path, [root], threads=2)
    assert third["done"] == 1 and third["planned"] == (1, 1099, 1)


@needs_clamav
def test_a_scan_without_the_cache_checks_everything_again(tmp_path):
    root = tmp_path / "scan"
    make_files(root, 30)
    run_pool(tmp_path, [root])
    again = run_pool(tmp_path, [root], use_cache=False)
    assert again["planned"][:2] == (30, 0)


@needs_clamav
def test_fast_mode_clean_results_do_not_hide_files_from_a_full_scan(tmp_path):
    root = tmp_path / "scan"
    make_files(root, 30)
    run_pool(tmp_path, [root], fast=True)
    assert run_pool(tmp_path, [root], fast=True)["planned"][:2] == (0, 30)
    assert run_pool(tmp_path, [root])["planned"][:2] == (30, 0)


@needs_clamav
def test_stopping_before_the_scan_starts_kills_nothing_and_reports_it(tmp_path):
    root = tmp_path / "scan"
    make_files(root, 5)
    clam = tmp_path / "c"
    (clam / "database").mkdir(parents=True)
    pool = ClamScanPool(real_install, [str(root)], ps.ScanOptions(), database=str(clam / "database"), clam_folder=str(clam))
    codes = []
    pool.done.connect(codes.append)
    pool.stop()
    pool.run()
    assert pool.stopped and codes == [2] and not (clam / "work").exists()


@needs_clamav
def test_a_stop_during_a_scan_kills_every_process(tmp_path):
    root = tmp_path / "scan"
    make_files(root, 1200)
    clam = tmp_path / "Clam Folder"
    (clam / "database").mkdir(parents=True)
    (clam / "database" / "t.hdb").write_text(f"{hashlib.md5(PAYLOAD).hexdigest()}:{len(PAYLOAD)}:T.X\n")
    pool = ClamScanPool(real_install, [str(root)], ps.ScanOptions(threads=2), database=str(clam / "database"),
                        clam_folder=str(clam))
    codes = []
    pool.done.connect(codes.append)
    pool.planned.connect(lambda *a: pool.stop())                   # as soon as the listing is done
    pool.run()
    assert pool.stopped and len(codes) == 1 and all(p.poll() is not None for p in pool._procs)


def test_a_missing_clamscan_is_reported_not_raised(tmp_path):
    root = tmp_path / "scan"
    make_files(root, 3)
    clam = tmp_path / "c"
    (clam / "database").mkdir(parents=True)
    pool = ClamScanPool(clamav.Install("x", str(tmp_path / "nope.exe"), "x"), [str(root)], ps.ScanOptions(),
                        database=str(clam / "database"), clam_folder=str(clam))
    lines, codes = [], []
    pool.lines.connect(lines.extend)
    pool.done.connect(codes.append)
    pool.run()
    assert codes == [-1] and any("Could not start" in l for l in lines)

# endregion


# region The Scan page

def test_the_scan_page_has_the_speed_options(window):  # noqa: F811
    assert window.clam_cache_cb.isChecked() and window.clam_cache_days.value() == 7
    assert window.clam_threads_spin.value() == 0 and window.clam_threads_spin.specialValueText() == "Auto"
    assert not window.clam_fast_cb.isChecked()


def test_the_page_reports_the_plan_and_the_skipped_files(window):  # noqa: F811
    window._on_clam_planned(120, 4000, 4)
    text = window.clam_scan_summary.text()
    assert "120 file(s)" in text and "4000 unchanged" in text and "4 in parallel" in text
    window.clam_counts = {"files": 7, "found": 0, "errors": 0}
    window.clam_scan_started = time.monotonic()
    window._tick_clam_scan()
    assert "Unchanged, skipped: 4000" in window.clam_scan_stats.text()


def test_forgetting_the_scan_memory(window, dialogs, tmp_path):  # noqa: F811
    path = os.path.join(clamav.clam_dir(), sc.NAME)
    cache = sc.ScanCache(path)
    cache.mark_pending([(sc.key_of(r"C:\a"), 1, 1)])
    cache.mark_clean([sc.key_of(r"C:\a")], 0)
    assert cache.count() == 1
    cache.close()
    window._clear_scan_cache()
    cache = sc.ScanCache(path)
    assert cache.count() == 0
    cache.close()
    window.clam_scan_worker = FakeRunning()
    window._clear_scan_cache()
    assert dialogs["info"]


def test_a_scan_started_from_the_page_uses_the_pool_with_the_chosen_options(window, tmp_path, monkeypatch):  # noqa: F811
    created = []

    class Spy:
        def __init__(self, install, targets, options):
            created.append((targets, options))
            self.lines = self.done = self.progress = self.planned = type("S", (), {"connect": lambda s, f: None})()
            self.stopped = False

        def start(self):
            pass

        def isRunning(self):
            return False
    monkeypatch.setattr("ddcleaner.ui.tab_antivirus.ClamScanPool", Spy)
    monkeypatch.setattr(clamav, "find_install", lambda: (FAKE_INSTALL, ""))
    monkeypatch.setattr(clamav, "read_database_info", lambda folder=None: clamav.DatabaseInfo(ready=True))
    window.clam_fast_cb.setChecked(True)
    window.clam_cache_days.setValue(3)
    window.clam_threads_spin.setValue(2)
    window.clam_pua_cb.setChecked(True)
    assert window._start_clam_scan([str(tmp_path)]) is True
    targets, options = created[0]
    assert targets == [str(tmp_path)] and options.fast and options.cache_days == 3 and options.threads == 2
    assert options.pua and options.use_cache and options.quarantine
    window.clam_clock.stop()

# endregion
