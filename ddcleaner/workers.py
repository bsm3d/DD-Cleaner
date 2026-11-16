"""QThread workers: every long operation runs here, never on the GUI thread."""

import codecs
import os
import queue
import re
import shutil
import subprocess
import logging
import threading
from datetime import datetime
from typing import List, Optional

from PySide6.QtCore import QThread, Signal

from security_audit import SecurityAuditor, HardeningEngine, HardeningProfile
from ddcleaner import clamav, driver_blocklist, firewall, health, network, parallel_scan, scan_cache
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM32, safe_environment, sys_exe


class DISMWorker(QThread):
    """Worker thread for DISM and system repair commands. The output is streamed while the tool runs."""
    progress = Signal(str)
    output = Signal(str)         # text as the tool writes it
    finished = Signal(int, str)  # exit_code, whole output

    TIMEOUT_SECONDS = 3 * 3600  # RestoreHealth can legitimately take a long time

    def __init__(self, command: List[str], encoding: Optional[str] = None):
        super().__init__()
        self.command = command
        self.encoding = encoding  # sfc.exe writes UTF-16LE when its output is redirected
        self.stopped = False      # killed by the Stop button or because the application closes
        self.timed_out = False
        self._proc: Optional[subprocess.Popen] = None

    @staticmethod
    def clean(text: str) -> str:
        """Console tools redraw their progress line with a bare CR: one line per update, no NUL."""
        return text.replace("\r\r\n", "\n").replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")

    def decode(self, data: Optional[bytes]) -> str:
        if not data:
            return ""
        return self.clean(data.decode(self.encoding or "oem", errors="replace"))  # console tools: OEM code page

    def kill(self):
        """Terminate the child process (Stop button, application closing)."""
        self.stopped = True
        proc = self._proc
        if proc and proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass

    def _on_timeout(self):
        self.timed_out = True
        self.kill()

    def run(self):
        try:
            self.progress.emit(f"Running: {' '.join(self.command)}")
            self._proc = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                shell=False,  # IMPORTANT: no shell injection
                cwd=SYSTEM32,
                env=safe_environment(),
                creationflags=SUBPROCESS_FLAGS
            )
            watchdog = threading.Timer(self.TIMEOUT_SECONDS, self._on_timeout)
            watchdog.daemon = True
            watchdog.start()
            decoder = codecs.getincrementaldecoder(self.encoding or "oem")(errors="replace")
            parts = []
            try:
                while True:
                    chunk = self._proc.stdout.read1(4096)
                    if not chunk:
                        break
                    text = self.clean(decoder.decode(chunk))
                    if text:
                        parts.append(text)
                        self.output.emit(text)
            finally:
                watchdog.cancel()
                self._proc.stdout.close()
            code = self._proc.wait()
            if self.timed_out:
                parts.append("\nTimed out: process killed.")
                self.output.emit(parts[-1])
            self.finished.emit(code, "".join(parts))
        except Exception as e:
            self.finished.emit(-1, f"Error: {str(e)}")


# the same worker runs any console tool and streams its output: the route trace uses it under a neutral name
CommandWorker = DISMWorker


class SecurityAuditWorker(QThread):
    """Worker thread for security audit."""
    progress = Signal(str)
    # domain_scores is a dict of DomainScore objects: Signal(int, dict) makes Qt try to copy-convert it to a
    # C++ type for the queued cross-thread delivery, which fails silently (Shiboken logs "Cannot copy-convert
    # ... to C++" and the slot receives nothing usable) because DomainScore isn't a Qt-convertible type.
    # Signal(object) hands the real Python object through unchanged, which is what this needs.
    finished = Signal(int, object)  # global_score, domain_scores

    def __init__(self, auditor: SecurityAuditor):
        super().__init__()
        self.auditor = auditor
        self.error = ""  # why the audit failed (the signal then carries 0 and no domain: not a real score)

    def run(self):
        try:
            self.progress.emit("Starting security audit...")
            global_score, domain_scores = self.auditor.run_full_audit()
            self.finished.emit(global_score, domain_scores)
        except Exception as e:
            logging.error(f"Security audit error: {e}")
            self.error = str(e) or type(e).__name__
            self.finished.emit(0, {})


class HardeningApplyWorker(QThread):
    """Creates a restore point then applies a hardening profile, off the GUI thread."""
    progress = Signal(str)
    done = Signal(int, int, list, bool)  # success, failures, errors, restore_point_ok

    def __init__(self, engine: HardeningEngine, profile: HardeningProfile):
        super().__init__()
        self.engine = engine
        self.profile = profile

    def run(self):
        try:
            # apply_profile saves a JSON state backup (mandatory) and creates the restore point itself
            self.progress.emit(f"Creating restore point and applying {self.profile.value} profile...")
            success, failures, errors = self.engine.apply_profile(self.profile)
            restore_ok = bool(getattr(self.engine, "last_restore_point_ok", False))
            self.done.emit(int(success), int(failures), list(errors), restore_ok)
        except Exception as e:
            logging.error(f"Hardening profile error: {e}")
            self.done.emit(0, 1, [str(e)], False)


class DriverScanWorker(QThread):
    """Lists third-party (oem*.inf) drivers via CIM/JSON: no admin needed, locale-independent."""
    done = Signal(list, str)  # drivers, error message

    PS_QUERY = (
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
        "Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.InfName -like 'oem*.inf' } | "
        "Select-Object DeviceName, DriverVersion, DriverProviderName, InfName, DeviceClass, "
        "@{n='Date';e={ if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { '' } }} | "
        "ConvertTo-Json -Compress"
    )

    def run(self):
        import json
        try:
            completed = subprocess.run(
                [sys_exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", self.PS_QUERY],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=120, cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS
            )
            if completed.returncode != 0:
                self.done.emit([], (completed.stderr or "PowerShell error").strip()[:300])
                return
            raw = json.loads(completed.stdout) if completed.stdout.strip() else []
            if isinstance(raw, dict):
                raw = [raw]
            now = datetime.now()
            drivers, seen = [], set()
            for d in raw:
                inf = d.get("InfName") or ""
                key = (inf, d.get("DriverVersion"), d.get("DeviceName"))
                if key in seen:
                    continue
                seen.add(key)
                try:
                    date = datetime.strptime(d.get("Date") or "", "%Y-%m-%d")
                except ValueError:
                    continue
                drivers.append({
                    "name": d.get("DeviceName") or inf,
                    "date": date,
                    "date_str": date.strftime("%Y-%m-%d"),
                    "version": d.get("DriverVersion") or "",
                    "provider": d.get("DriverProviderName") or "",
                    "path": inf,
                    "age_days": (now - date).days,
                    "class": d.get("DeviceClass") or "",
                })
            logging.info(f"Driver scan completed. Found {len(drivers)} third-party drivers")
            self.done.emit(drivers, "")
        except subprocess.TimeoutExpired:
            self.done.emit([], "Timed out after 120 s")
        except Exception as e:
            self.done.emit([], str(e))


class HardeningRevertWorker(QThread):
    """Reverts a hardening profile from its JSON backup (HardeningEngine format)."""
    progress = Signal(str)
    done = Signal(int, int)  # reverted, failed

    def __init__(self, engine: HardeningEngine, backup_path: str):
        super().__init__()
        self.engine = engine
        self.backup_path = backup_path

    def run(self):
        try:
            self.progress.emit(f"Reverting {os.path.basename(self.backup_path)}...")
            reverted, failed = self.engine.revert_backup(self.backup_path)
            self.done.emit(int(reverted), int(failed))
        except Exception as e:
            logging.error(f"Hardening revert error: {e}")
            self.done.emit(0, -1)


class BlocklistDownloadWorker(QThread):
    """Downloads the Microsoft vulnerable driver blocklist."""
    done = Signal(str, str)  # policy version, error message

    def run(self):
        try:
            policy = driver_blocklist.download_blocklist()
            self.done.emit(policy.version, "")
        except Exception as e:
            logging.error(f"Blocklist download failed: {e}")
            self.done.emit("", str(e))


class VulnerableDriverScanWorker(QThread):
    """Checks every driver file against the blocklist (read-only)."""
    progress = Signal(int, int, str)  # current, total, path
    done = Signal(list, str)  # DriverCheck list, error message

    def __init__(self, policy, stop_flag):
        super().__init__()
        self.policy = policy
        self.stop_flag = stop_flag

    def run(self):
        try:
            drivers = driver_blocklist.collect_driver_files()
            results = driver_blocklist.check_drivers(
                self.policy, drivers, progress=self.progress.emit, stop=self.stop_flag.is_set)
            flagged = [r for r in results if r.flagged]
            logging.info(f"Vulnerable driver check: {len(results)} files, {len(flagged)} on the blocklist")
            for r in flagged:
                logging.warning(f"Blocklisted driver: {r.driver.path} ({r.driver.state}): {'; '.join(r.reasons)}")
            self.done.emit(results, "")
        except Exception as e:
            logging.error(f"Vulnerable driver check failed: {e}")
            self.done.emit([], str(e))


class HealthCheckWorker(QThread):
    """Builds the system health report (read-only)."""
    progress = Signal(str)
    done = Signal(list, str)  # HealthItem list, error message

    def run(self):
        try:
            self.done.emit(health.run_health_check(self.progress.emit), "")
        except Exception as e:
            logging.error(f"Health check failed: {e}")
            self.done.emit([], str(e))


class NetworkAnalysisWorker(QThread):
    """Firewall analysis, then network statistics and listening port exposure (read-only)."""
    progress = Signal(str)
    done = Signal(object, object, str)  # FirewallReport, NetworkReport, error message

    def __init__(self, owners=None):
        super().__init__()
        self.owners = owners  # ipinfo.OwnerLookup, or None to keep blocked sources anonymous

    def run(self):
        try:
            fw_report = firewall.run_firewall_analysis(self.progress.emit)
            if self.owners is not None and fw_report.log is not None and fw_report.log.inbound_sources:
                self.progress.emit("Looking up who sent the blocked connections...")
                for addr, _ in fw_report.log.inbound_sources.most_common(15):
                    owner = self.owners.resolve_now(addr)
                    if owner is not None:
                        fw_report.log.source_owners[addr] = owner.label
            net_report = network.run_network_analysis(fw_report, self.progress.emit)
            self.done.emit(fw_report, net_report, "")
        except Exception as e:
            logging.error(f"Firewall/network analysis failed: {e}")
            self.done.emit(None, None, str(e))


class GeoIPDownloadWorker(QThread):
    """Downloads DB-IP City Lite (about 60 MB) with progress."""
    progress = Signal(int)   # bytes written (decompressed)
    done = Signal(dict, str)  # database info, error message

    def run(self):
        from ddcleaner import geoip
        try:
            self.done.emit(geoip.download_dbip(progress=self.progress.emit), "")
        except Exception as e:
            logging.error(f"GeoIP download failed: {e}")
            self.done.emit({}, str(e))


class TrafficSampleWorker(QThread):
    """One live traffic sample (connection tables, processes, byte counters) off the GUI thread."""
    done = Signal(object, str)  # TrafficSnapshot, error message

    def __init__(self, monitor):
        super().__init__()
        self.monitor = monitor

    def run(self):
        try:
            self.done.emit(self.monitor.sample(), "")
        except Exception as e:
            logging.error(f"Traffic sample failed: {e}")
            self.done.emit(None, str(e))


class ClamProcessWorker(QThread):
    """Runs clamscan or freshclam and streams its output. Lines arrive in batches (a scan prints one line
    per file, one signal per line would flood the GUI thread)."""
    lines = Signal(list)   # decoded output lines
    done = Signal(int)     # exit code (-1 if the program could not start)

    def __init__(self, command: List[str]):
        super().__init__()
        self.command = command
        self.stopped = False
        self._proc: Optional[subprocess.Popen] = None

    @staticmethod
    def decode(raw: bytes) -> str:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("mbcs", errors="replace")

    def stop(self):
        """Terminate the program (Stop button, application closing)."""
        self.stopped = True
        proc = self._proc
        if proc and proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass

    def run(self):
        try:
            self._proc = subprocess.Popen(
                self.command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                shell=False, cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)
        except OSError as e:
            self.lines.emit([f"Could not start {os.path.basename(self.command[0])}: {e}"])
            self.done.emit(-1)
            return
        if self.stopped:  # Stop was clicked before the process existed: stop() found nothing to kill
            self.stop()
        pending = b""
        try:
            while True:
                chunk = self._proc.stdout.read1(65536)  # freshclam draws its progress with CR only
                if not chunk:
                    break
                parts = re.split(rb"[\r\n]+", pending + chunk)
                pending = parts.pop()
                batch = [self.decode(p) for p in parts if p]
                if batch:
                    self.lines.emit(batch)
            if pending.strip():
                self.lines.emit([self.decode(pending)])
        except Exception as e:
            logging.error(f"ClamAV output reading failed: {e}")
            self.lines.emit([f"Output reading failed: {e}"])
            self.stop()  # nobody reads the pipe any more: a chatty process would block forever
        finally:
            try:
                self._proc.stdout.close()
            except OSError:
                pass
        self.done.emit(self._proc.wait())


class ClamScanPool(QThread):
    """A ClamAV scan shared between several clamscan processes.

    First the files are listed (those the scan cache knows are clean and unchanged are skipped), then each process
    scans its own list. Output lines reach the GUI in the same batches as ClamProcessWorker's, so the Antivirus tab
    handles both the same way."""
    lines = Signal(list)
    done = Signal(int)                 # one exit code for the whole scan (-1 if nothing could start)
    progress = Signal(str)             # what the listing is doing
    planned = Signal(int, int, int)    # files to scan, unchanged files skipped, processes

    def __init__(self, install, targets: List[str], options: "parallel_scan.ScanOptions",
                 database: Optional[str] = None, clam_folder: Optional[str] = None,
                 cache_path: Optional[str] = None, workdir: Optional[str] = None):
        super().__init__()
        self.install, self.targets, self.options = install, list(targets), options
        self.database = database or clamav.database_dir()
        self.clam_folder = clam_folder or clamav.clam_dir()
        self.cache_path = cache_path or os.path.join(self.clam_folder, scan_cache.NAME)
        self.workdir = workdir or os.path.join(self.clam_folder, "work")
        self.stopped = False
        self._stop_event = threading.Event()
        self._procs: List[subprocess.Popen] = []

    def stop(self):
        """Stop listing and kill every clamscan process (Stop button, application closing)."""
        self.stopped = True
        self._stop_event.set()
        for proc in list(self._procs):
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass

    def run(self):
        cache = None
        try:
            self._scan()
        except Exception as e:  # noqa: BLE001  (the GUI must always get a result)
            logging.error(f"ClamAV scan failed: {e}")
            self.lines.emit([f"Scan failed: {e}"])
            self.done.emit(-1)
        finally:
            shutil.rmtree(self.workdir, ignore_errors=True)

    def _scan(self):
        options = self.options
        cache = None
        if options.use_cache:
            try:
                cache = scan_cache.ScanCache(self.cache_path)
                cache.prune(max(options.cache_days * 4, 30))
            except OSError as e:
                logging.warning(f"Scan cache not used: {e}")
        try:
            shutil.rmtree(self.workdir, ignore_errors=True)
            threads = parallel_scan.thread_count(options.threads)
            plan = parallel_scan.make_plan(self.targets, options, cache, self.workdir, self.clam_folder, threads,
                                           self._stop_event.is_set, self.progress.emit)
            self.planned.emit(plan.to_scan, plan.skipped, len(plan.lists))
            if self.stopped:
                self.done.emit(2)
                return
            if not plan.lists:
                self.done.emit(0)  # nothing new to scan
                return
            commands = [clamav.build_scan_command(
                self.install, [], quarantine=options.quarantine, archives=options.archives,
                max_filesize_mb=options.max_filesize_mb, detect_pua=options.pua, thorough=options.thorough,
                database=self.database, clam_folder=self.clam_folder, fast=options.fast, file_list=path)
                for path in plan.lists]
            self.done.emit(self._run_processes(commands, cache))
        finally:
            if cache is not None:
                cache.close()

    def _run_processes(self, commands: List[List[str]], cache) -> int:
        messages: "queue.Queue" = queue.Queue()
        readers = []
        for command in commands:
            try:
                proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                        shell=False, cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)
            except OSError as e:
                self.lines.emit([f"Could not start {os.path.basename(command[0])}: {e}"])
                self.stop()
                return -1
            self._procs.append(proc)
            reader = threading.Thread(target=self._read, args=(proc, messages), daemon=True)
            reader.start()
            readers.append(reader)
        flags, clean_keys, open_streams = self.options.flags, [], len(readers)
        while open_streams:
            try:
                batch = messages.get(timeout=0.5)
            except queue.Empty:
                continue
            if batch is None:
                open_streams -= 1
                continue
            if cache is not None:
                clean_keys += [scan_cache.key_of(k[1]) for k in map(clamav.parse_scan_line, batch) if k[0] == "ok"]
                if len(clean_keys) >= scan_cache.BATCH:
                    cache.mark_clean(clean_keys, flags)
                    clean_keys = []
            self.lines.emit(batch)
        if cache is not None and clean_keys:
            cache.mark_clean(clean_keys, flags)
        codes = [proc.wait() for proc in self._procs]
        return parallel_scan.combine_codes(codes)

    def _read(self, proc: subprocess.Popen, messages: "queue.Queue"):
        try:
            parallel_scan.pump(proc.stdout, messages.put)
        except Exception as e:  # noqa: BLE001
            logging.error(f"ClamAV output reading failed: {e}")
            messages.put([f"Output reading failed: {e}"])
            if proc.poll() is None:
                proc.kill()  # nobody reads the pipe any more: a chatty process would block forever
        finally:
            try:
                proc.stdout.close()
            except OSError:
                pass
            messages.put(None)


class CallWorker(QThread):
    """Runs one function off the GUI thread and hands back its result (read-only queries and measurements)."""
    done = Signal(object, str)  # result, error message

    def __init__(self, function, label: str = "Background task"):
        super().__init__()
        self.function = function
        self.label = label

    def run(self):
        try:
            self.done.emit(self.function(), "")
        except Exception as e:
            logging.error(f"{self.label} failed: {e}")
            self.done.emit(None, str(e))
