"""ClamProcessWorker and CallWorker: run() is called directly (QThread.run is a plain method), so these run
synchronously without a real OS thread. Real short-lived subprocesses are used where it matters (pipe handling,
exit code); subprocess.Popen is stubbed only for the one race that needs precise timing control."""

import subprocess
import sys

from ddcleaner.workers import CallWorker, ClamProcessWorker

PY = sys.executable


def run_worker(command):
    """Run a ClamProcessWorker synchronously and collect everything it emits."""
    worker = ClamProcessWorker(command)
    lines, done = [], []
    worker.lines.connect(lines.extend)
    worker.done.connect(done.append)
    worker.run()
    return worker, lines, done


def test_normal_run_emits_lines_and_exit_code():
    worker, lines, done = run_worker([PY, "-c", "print('a'); print('b')"])
    assert "a" in lines and "b" in lines
    assert done == [0]
    assert not worker.stopped


def test_nonzero_exit_code_is_reported():
    _worker, _lines, done = run_worker([PY, "-c", "import sys; sys.exit(3)"])
    assert done == [3]


def test_missing_program_emits_an_error_line_and_minus_one():
    worker, lines, done = run_worker([r"C:\does\not\exist\nope.exe"])
    assert done == [-1]
    assert lines and "Could not start" in lines[0]
    assert worker._proc is None


def test_carriage_return_progress_lines_are_split():
    # freshclam draws its progress with \r only, never \n
    script = "import sys; sys.stdout.write('10%\\r20%\\r30%\\n'); sys.stdout.flush()"
    _worker, lines, _done = run_worker([PY, "-c", script])
    assert lines == ["10%", "20%", "30%"]


def test_stdout_is_closed_after_a_normal_run():
    worker, _lines, _done = run_worker([PY, "-c", "print('x')"])
    assert worker._proc.stdout.closed


def test_stop_called_before_popen_returns_kills_the_process_immediately(monkeypatch):
    """The race the review flagged: Stop is clicked while Popen() is still starting the process."""
    worker = ClamProcessWorker([PY, "-c", "import time; time.sleep(30)"])
    real_popen = subprocess.Popen

    def popen_then_stop(*a, **k):
        proc = real_popen(*a, **k)
        worker.stop()  # simulates the Stop button firing between Popen() returning and the next line running
        return proc

    monkeypatch.setattr(subprocess, "Popen", popen_then_stop)
    done = []
    worker.lines.connect(lambda _: None)
    worker.done.connect(done.append)
    worker.run()
    assert worker.stopped
    assert done and done[0] != 0          # killed, not a clean exit
    assert worker._proc.poll() is not None  # the process is actually gone, not left running


def test_a_broken_pipe_reader_stops_the_process_instead_of_hanging(monkeypatch):
    """If read1() raises mid-scan, nothing reads the pipe any more: the process must be killed, not left to
    fill the pipe buffer and block run() forever."""
    worker = ClamProcessWorker([PY, "-c", "import time; time.sleep(30)"])
    real_popen = subprocess.Popen
    captured = {}

    def popen_and_capture(*a, **k):
        proc = real_popen(*a, **k)
        captured["proc"] = proc
        real_read1 = proc.stdout.read1

        def failing_read1(n):
            failing_read1.calls += 1
            if failing_read1.calls == 1:
                return real_read1(n) or b"first chunk\n"
            raise OSError("pipe broke")
        failing_read1.calls = 0
        proc.stdout.read1 = failing_read1
        return proc

    monkeypatch.setattr(subprocess, "Popen", popen_and_capture)
    lines, done = [], []
    worker.lines.connect(lines.extend)
    worker.done.connect(done.append)
    worker.run()
    assert any("Output reading failed" in l for l in lines)
    assert worker.stopped
    assert captured["proc"].poll() is not None  # killed, not left running
    assert done  # run() returned instead of blocking on wait()


def test_call_worker_returns_the_function_result():
    worker = CallWorker(lambda: 42)
    results = []
    worker.done.connect(lambda r, e: results.append((r, e)))
    worker.run()
    assert results == [(42, "")]


def test_call_worker_reports_an_exception_instead_of_raising():
    def boom():
        raise ValueError("bad")
    worker = CallWorker(boom)
    results = []
    worker.done.connect(lambda r, e: results.append((r, e)))
    worker.run()  # must not raise out of run()
    assert results == [(None, "bad")]

