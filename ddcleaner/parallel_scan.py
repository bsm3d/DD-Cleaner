"""Planning of a ClamAV scan: which files really need scanning, and how to share them between several clamscan
processes. No Qt here.

clamscan uses one core and reloads about a million signatures at every start. To use the machine, the files are
listed once (skipping those the scan cache knows are clean and unchanged), dealt out to N lists, and one clamscan
process works on each list. Each process holds the signatures in memory (about 1 GB), so N depends on the free RAM.
"""

import ctypes
import os
import re
import shutil
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from ddcleaner import scan_cache
from ddcleaner.scan_cache import ScanCache, key_of

MAX_THREADS = 8
RAM_PER_PROCESS = int(1.3 * 1024 ** 3)
RAM_RESERVE = 4 * 1024 ** 3
MIN_FILES_PER_PROCESS = 500          # fewer files than this per process is not worth another signature load
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
PROGRESS_EVERY = 5000


@dataclass
class ScanOptions:
    quarantine: bool = True
    archives: bool = True
    pua: bool = False
    thorough: bool = False
    fast: bool = False               # no archives, no heuristics: much quicker, catches less
    max_filesize_mb: int = 100
    use_cache: bool = True
    cache_days: int = 7
    threads: int = 0                 # 0 = automatic

    @property
    def effective_archives(self) -> bool:
        return self.archives and not self.fast

    @property
    def flags(self) -> int:
        """What this scan checks, as the bits stored in the cache."""
        bits = 0
        if self.effective_archives:
            bits |= scan_cache.FLAG_ARCHIVES
        if not self.fast:
            bits |= scan_cache.FLAG_HEURISTICS
        if self.pua:
            bits |= scan_cache.FLAG_PUA
        if self.thorough:
            bits |= scan_cache.FLAG_THOROUGH
        return bits


@dataclass
class Plan:
    lists: List[str] = field(default_factory=list)   # one file list per clamscan process
    to_scan: int = 0
    skipped: int = 0                                  # unchanged files the cache knows are clean
    seen: int = 0


def free_memory() -> int:
    """Free physical memory in bytes (a large default when it cannot be read)."""
    class Status(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong), ("total", ctypes.c_ulonglong),
                    ("avail", ctypes.c_ulonglong), ("page_total", ctypes.c_ulonglong),
                    ("page_avail", ctypes.c_ulonglong), ("virt_total", ctypes.c_ulonglong),
                    ("virt_avail", ctypes.c_ulonglong), ("ext", ctypes.c_ulonglong)]
    try:
        status = Status()
        status.length = ctypes.sizeof(Status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.avail)
    except (AttributeError, OSError):
        pass
    return 16 * 1024 ** 3


def thread_count(requested: int, cpus: Optional[int] = None, free_ram: Optional[int] = None) -> int:
    """How many clamscan processes to run: the request (0 = automatic) capped by cores and by free memory."""
    cpus = cpus or os.cpu_count() or 2
    free_ram = free_memory() if free_ram is None else free_ram
    by_memory = max(1, (free_ram - RAM_RESERVE) // RAM_PER_PROCESS)
    wanted = requested if requested > 0 else max(1, cpus // 2)
    return int(max(1, min(wanted, MAX_THREADS, cpus, by_memory)))


def make_plan(targets: List[str], options: ScanOptions, cache: Optional[ScanCache], workdir: str,
              exclude_folder: str = "", max_threads: int = 1, stop: Callable[[], bool] = lambda: False,
              progress: Optional[Callable[[str], None]] = None) -> Plan:
    """List the files below the targets, drop what the cache knows is clean, write the rest to file lists."""
    os.makedirs(workdir, exist_ok=True)
    max_threads = max(1, max_threads)
    names = [os.path.join(workdir, f"files_{i}.txt") for i in range(max_threads)]
    handles = [open(n, "w", encoding="utf-8", newline="\n") for n in names]  # clamscan reads UTF-8
    plan = Plan()
    max_bytes = options.max_filesize_mb * 1024 * 1024
    exclude = os.path.normcase(os.path.abspath(exclude_folder)) if exclude_folder else ""
    flags, days = options.flags, options.cache_days
    pending: list = []

    def consider(path: str, size: int, mtime_ns: int):
        plan.seen += 1
        if size == 0 or size > max_bytes:
            return  # clamscan ignores them too
        key = key_of(path)
        if cache is not None and options.use_cache and cache.is_clean(key, size, mtime_ns, flags, days):
            plan.skipped += 1
        else:
            handles[plan.to_scan % max_threads].write(path + "\n")
            plan.to_scan += 1
            if cache is not None and options.use_cache:
                pending.append((key, size, mtime_ns))
                if len(pending) >= scan_cache.BATCH:
                    cache.mark_pending(pending)
                    pending.clear()
        if progress and plan.seen % PROGRESS_EVERY == 0:
            progress(f"Listing files... {plan.seen} seen, {plan.to_scan} to scan, {plan.skipped} unchanged")

    try:
        stack = []
        for target in targets:
            try:
                info = os.stat(target)
            except OSError:
                continue
            if os.path.isdir(target):
                stack.append(target)
            else:
                consider(target, info.st_size, info.st_mtime_ns)
        while stack and not stop():
            folder = stack.pop()
            try:
                entries = list(os.scandir(folder))
            except OSError:
                continue
            for entry in entries:
                try:
                    info = entry.stat(follow_symlinks=False)
                    if info.st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        low = os.path.normcase(entry.path)
                        if not exclude or (low != exclude and not low.startswith(exclude + os.sep)):
                            stack.append(entry.path)
                    else:
                        consider(entry.path, info.st_size, info.st_mtime_ns)
                except OSError:
                    continue
        if cache is not None and pending:
            cache.mark_pending(pending)
    finally:
        for h in handles:
            h.close()

    used = max(1, min(max_threads, plan.to_scan // MIN_FILES_PER_PROCESS))
    for extra in range(used, max_threads):         # too few files for all the processes: merge the extra lists
        with open(names[extra], encoding="utf-8") as src, open(names[extra % used], "a", encoding="utf-8", newline="\n") as dst:
            shutil.copyfileobj(src, dst)
    plan.lists = [n for n in names[:used] if os.path.getsize(n) > 0]
    return plan


# region Reading a clamscan process

SPLIT = re.compile(rb"[\r\n]+")


def decode(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("mbcs", errors="replace")


def pump(stream, emit: Callable[[List[str]], None]):
    """Read a clamscan output stream and hand over its lines in batches (one signal per line would flood the GUI)."""
    pending = b""
    while True:
        chunk = stream.read1(65536)
        if not chunk:
            break
        parts = SPLIT.split(pending + chunk)
        pending = parts.pop()
        batch = [decode(p) for p in parts if p]
        if batch:
            emit(batch)
    if pending.strip():
        emit([decode(pending)])


def combine_codes(codes: List[int]) -> int:
    """One exit code for several clamscan processes: 1 if any found something, else the worst error, else 0."""
    if 1 in codes:
        return 1
    bad = [c for c in codes if c not in (0, 1)]
    return bad[0] if bad else 0

# endregion
