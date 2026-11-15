"""Garbage left on disk: wildcard search, leftovers of programs that are no longer installed, and deletion.

Searching never changes anything. Deleting only touches the exact items the caller passes, sends them to the
Recycle Bin unless told otherwise, and refuses essential folders (drive roots, Windows, the user's profile...).
"""

import ctypes
import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from ddcleaner import startup
from ddcleaner.common import SYSTEM_ROOT, app_dir, system_dll

known_folder = startup._known_folder  # folder path from the shell API (never from the environment)

KIND_FILE, KIND_FOLDER = "File", "Folder"
HIGH, MEDIUM, LOW = "High", "Medium", "Low"
CONFIDENCE_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, "": 3}

FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
DRIVE_FIXED = 3

CSIDL = {"documents": 0x05, "desktop": 0x10, "music": 0x0D, "video": 0x0E, "roaming": 0x1A, "local": 0x1C,
         "programdata": 0x23, "programfiles": 0x26, "pictures": 0x27, "profile": 0x28, "programfiles86": 0x2A}

# Search presets. A word without wildcard means "contains"; a word in double quotes is an exact name.
PRESETS = {
    "Temporary files": '*.tmp;*.temp;*.swp;*.swo;*.orig;*.rej',
    "Office and editor lock files": '~$*;.~lock.*;*.lck',
    "Incomplete downloads": '*.crdownload;*.part;*.partial;*.download;*.opdownload',
    "Backups and old copies": '*.bak;*.old;*.backup;*~',
    "Duplicate copies": '* - Copy*;* - Copie*;Copie de *;* (1).*;* (2).*',
    "Crash dumps and error reports": '*.dmp;*.mdmp;*.stackdump;hs_err_pid*;"npm-debug.log";"yarn-error.log";"pip-log.txt"',
    "Log files": '*.log;*.etl',
    "System thumbnails and junk": '"Thumbs.db";"ehthumbs.db";".DS_Store";"__MACOSX";._*;*.chk',
    "Python caches": '"__pycache__";*.pyc;*.pyo;".pytest_cache";".mypy_cache";".ruff_cache";".ipynb_checkpoints";".tox";".hypothesis";*.egg-info',
    "IDE project folders": '".vscode";".idea";".vs";".history"',
    "Browser and Electron caches": '"Cache";"Code Cache";"GPUCache";"GrShaderCache";"ShaderCache";"DawnCache"',
    "Installers and disk images": '*setup*.exe;*install*.exe;*.msi;*.iso;*.dmg',
    "AI tool leftovers": 'tmpclaude-*;"nul";.aider.tags.cache*;".aider.chat.history.md";".aider.input.history"',
}

WHERE_PROFILE, WHERE_APPDATA, WHERE_DRIVES, WHERE_CUSTOM = "profile", "appdata", "drives", "custom"
SEARCH_LIMIT = 5000
SKIPPED_FOLDERS = {"$recycle.bin", "system volume information"}
RESERVED_NAMES = {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}

# Folders of AppData / ProgramData / Program Files that belong to Windows or are shared, never reported as leftovers
KEEP_FOLDERS = {
    "microsoft", "windows", "packages", "temp", "programs", "comms", "connecteddevicesplatform", "d3dscache",
    "publishers", "history", "placeholdertilelogger", "commonfiles", "windowsapps", "windowsnt", "windowspowershell",
    "modifiablewindowsapps", "internetexplorer", "windowsdefender", "windowsmail", "windowsmediaplayer",
    "windowsphotoviewer", "windowsportabledevices", "windowssecurity", "windowssidebar", "referenceassemblies",
    "msbuild", "dotnet", "uninstallinformation", "packagecache", "ssh", "regid199106commicrosoft", "usoprivate",
    "usoshared", "softwaredistribution", "storage",
}
KEEP_PREFIXES = ("microsoft", "windows")  # Microsoft.NET, Microsoft Update Health Tools... are Windows components
OLD_FOLDER_DAYS = 90
AGE_CHOICES = (("Any age", 0), ("Older than 1 day", 1), ("Older than 7 days", 7), ("Older than 30 days", 30))


@dataclass
class GarbageItem:
    path: str
    kind: str                # File | Folder
    size: int = 0
    modified: float = 0.0    # timestamp
    reason: str = ""
    confidence: str = ""     # leftovers only: High | Medium | Low


@dataclass
class FileScan:
    items: List[GarbageItem] = field(default_factory=list)
    truncated: bool = False
    folders_seen: int = 0


@dataclass
class DeleteResult:
    deleted: List[GarbageItem] = field(default_factory=list)
    failed: List[Tuple[GarbageItem, str]] = field(default_factory=list)
    freed: int = 0


def merge_scans(first: FileScan, second: FileScan) -> FileScan:
    """Both lists in one. An item found twice keeps the version that has a confidence (the leftover scan's)."""
    merged = {os.path.normcase(i.path): i for i in first.items}
    for item in second.items:
        key = os.path.normcase(item.path)
        if key not in merged or item.confidence:
            merged[key] = item
    return FileScan(list(merged.values()), first.truncated or second.truncated, first.folders_seen + second.folders_seen)


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB"):
        if value < 1024:
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


# region Patterns

def _term_regex(term: str):
    term = term.strip()
    exact = len(term) >= 2 and term[0] == term[-1] == '"'
    if exact:
        term = term[1:-1]
    elif not any(c in term for c in "*?"):
        term = f"*{term}*"
    body = re.escape(term).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile(body, re.I | re.S), ("\\" in term or "/" in term)


def compile_patterns(text: str) -> Callable[[str, str], bool]:
    """Matcher for 'a;b;c'. A word alone means 'contains', * and ? are wildcards, "name" in quotes is an exact name.
    A term with a slash is matched against the whole path, the others against the file or folder name."""
    rules = [_term_regex(t) for t in (text or "").split(";") if t.strip()]
    if not rules:
        raise ValueError("Enter a word or a wildcard pattern, for example *.vscode")

    def match(name: str, path: str) -> bool:
        return any(rx.fullmatch(path.replace("/", "\\") if on_path else name) for rx, on_path in rules)
    return match

# endregion


# region Locations

def fixed_drives() -> List[str]:
    try:
        kernel = system_dll("kernel32")
        mask = kernel.GetLogicalDrives()
        roots = [f"{chr(65 + i)}:\\" for i in range(26) if mask & (1 << i)]
        return [r for r in roots if kernel.GetDriveTypeW(r) == DRIVE_FIXED]
    except (AttributeError, OSError):
        return []


def _outermost(folders: Iterable[str]) -> List[str]:
    kept: List[str] = []
    for folder in sorted({os.path.normpath(f) for f in folders}, key=lambda f: len(f)):
        low = os.path.normcase(folder)
        if not any(low == os.path.normcase(k) or low.startswith(os.path.normcase(k).rstrip("\\") + "\\") for k in kept):
            kept.append(folder)
    return kept


def search_roots(where: str, custom: str = "") -> List[str]:
    if where == WHERE_PROFILE:
        roots = [known_folder(CSIDL["profile"])]
    elif where == WHERE_APPDATA:
        roots = [known_folder(CSIDL["roaming"]), known_folder(CSIDL["local"]), known_folder(CSIDL["programdata"]),
                 tempfile.gettempdir()]
    elif where == WHERE_DRIVES:
        roots = fixed_drives()
    else:
        roots = [custom]
    return _outermost(r for r in roots if r and os.path.isdir(r))

# endregion


# region Walking

def _absolute(path: str) -> str:
    """Absolute path. abspath() on the whole path would turn "nul" into the device \\\\.\\nul: only the folder is resolved."""
    folder, name = os.path.split(path)
    return os.path.join(os.path.abspath(folder or os.getcwd()), name)


def _long(path: str) -> str:
    """Extended-length form: the only one that can reach files named like devices (nul, con, aux...)."""
    return path if path.startswith("\\\\") else "\\\\?\\" + _absolute(path)


def is_reserved_name(path: str) -> bool:
    return os.path.basename(path).split(".")[0].lower() in RESERVED_NAMES


def _is_link(attributes: int) -> bool:
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def folder_size(path: str, stop: Callable[[], bool] = lambda: False, max_files: int = 300_000) -> int:
    """Size of the files inside a folder (links are not followed)."""
    total, seen, stack = 0, 0, [path]
    while stack and seen < max_files and not stop():
        try:
            with os.scandir(stack.pop()) as entries:
                for entry in entries:
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if _is_link(info.st_file_attributes):
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    else:
                        total += info.st_size
                        seen += 1
        except OSError:
            continue
    return total


KEPT_FOLDER_SUFFIX = "~"


def is_kept_folder(name: str, is_dir: bool) -> bool:
    """A folder whose name ends with '~' is never garbage: Unity hides such folders from its import (Samples~,
    Documentation~, Editor Default Resources~...), they hold real package content. A file ending with '~' is an
    editor backup and stays fair game."""
    return is_dir and name.endswith(KEPT_FOLDER_SUFFIX)


def _age_cutoff(min_age_days: float, now: Optional[float]) -> float:
    """Timestamp at or before which an item is old enough (no filter: far in the future)."""
    if min_age_days <= 0:
        return float("inf")
    return (datetime.now().timestamp() if now is None else now) - min_age_days * 86400


def search_files(patterns: str, roots: List[str], stop: Callable[[], bool] = lambda: False,
                 progress: Optional[Callable[[str], None]] = None, limit: int = SEARCH_LIMIT,
                 min_age_days: float = 0, now: Optional[float] = None) -> FileScan:
    """Files and folders whose name (or path) matches. A matching folder is listed once, not its content.
    With min_age_days, only what was last modified at least that many days ago is listed."""
    match = compile_patterns(patterns)
    cutoff = _age_cutoff(min_age_days, now)
    scan = FileScan()
    windows = os.path.normcase(SYSTEM_ROOT)
    stack = list(reversed(roots))
    while stack and not stop():
        folder = stack.pop()
        scan.folders_seen += 1
        if progress and scan.folders_seen % 400 == 0:
            progress(f"Searching... {scan.folders_seen} folders looked at, {len(scan.items)} found")
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        subfolders = []
        for entry in entries:
            try:
                info = entry.stat(follow_symlinks=False)
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if _is_link(info.st_file_attributes):
                continue  # links are never listed or crossed
            if not is_kept_folder(entry.name, is_dir) and match(entry.name, entry.path):
                if info.st_mtime > cutoff:
                    continue  # too recent for the age filter
                size = folder_size(entry.path, stop) if is_dir else info.st_size
                scan.items.append(GarbageItem(entry.path, KIND_FOLDER if is_dir else KIND_FILE, size,
                                              info.st_mtime, "Matches the search"))
                if len(scan.items) >= limit:
                    scan.truncated = True
                    return scan
            elif is_dir and entry.name.lower() not in SKIPPED_FOLDERS \
                    and os.path.normcase(entry.path) != windows:
                subfolders.append(entry.path)
        stack.extend(reversed(subfolders))
    return scan

# endregion


# region Leftovers of programs that are no longer installed

def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def leftover_parents() -> List[Tuple[str, str, bool]]:
    """(label, folder, is a Program Files folder)"""
    return [("AppData\\Roaming", known_folder(CSIDL["roaming"]), False),
            ("AppData\\Local", known_folder(CSIDL["local"]), False),
            ("ProgramData", known_folder(CSIDL["programdata"]), False),
            ("Program Files", known_folder(CSIDL["programfiles"]), True),
            ("Program Files (x86)", known_folder(CSIDL["programfiles86"]), True)]


def is_covered(folder_name: str, markers: Set[str]) -> bool:
    """True when an installed program (its name, publisher or install folder) matches the folder name.
    Too short to judge also counts as covered: better to miss a leftover than to accuse a live program."""
    key = _norm(folder_name)
    if len(key) < 3 or key in KEEP_FOLDERS or key in markers:
        return True
    return any(m in key for m in markers if len(m) >= 5) or any(key in m for m in markers if len(key) >= 5)


def _has_program_files(folder: str, stop: Callable[[], bool], budget: int = 60_000) -> bool:
    """True when a program file is inside. A folder too big to look through counts as having one: a wrong
    'nothing left inside' would be the worst mistake here."""
    stack = [folder]
    while stack and not stop():
        if budget <= 0:
            return True
        try:
            with os.scandir(stack.pop()) as entries:
                for entry in entries:
                    budget -= 1
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif os.path.splitext(entry.name)[1].lower() in startup.PE_SUFFIXES:
                        return True
        except OSError:
            continue
    return False


def find_leftovers(markers: Set[str], stop: Callable[[], bool] = lambda: False,
                   progress: Optional[Callable[[str], None]] = None,
                   parents: Optional[List[Tuple[str, str, bool]]] = None, now: Optional[float] = None,
                   min_age_days: float = 0) -> FileScan:
    """Folders of AppData, ProgramData and Program Files that no installed program claims.

    High: a Program Files folder with no program file left inside. Medium: unclaimed and untouched for 90 days.
    Low: unclaimed but recently used (portable tools and manually copied programs end up here too).
    With min_age_days, folders changed more recently than that are left out."""
    parents = leftover_parents() if parents is None else parents
    now = datetime.now().timestamp() if now is None else now
    cutoff = _age_cutoff(min_age_days, now)
    scan = FileScan()
    for label, parent, is_program_files in parents:
        if not parent or not os.path.isdir(parent):
            continue
        if progress:
            progress(f"Looking at {label}...")
        try:
            entries = sorted(os.scandir(parent), key=lambda e: e.name.lower())
        except OSError:
            continue
        for entry in entries:
            if stop():
                return scan
            try:
                info = entry.stat(follow_symlinks=False)
                if not entry.is_dir(follow_symlinks=False) or info.st_file_attributes & (
                        FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_SYSTEM):
                    continue
            except OSError:
                continue
            key = _norm(entry.name)
            if len(key) < 3 or key in KEEP_FOLDERS or key.startswith(KEEP_PREFIXES) or entry.name.endswith(KEPT_FOLDER_SUFFIX):
                continue
            scan.folders_seen += 1
            if info.st_mtime > cutoff:
                continue
            covered = is_covered(entry.name, markers)
            age_days = (now - info.st_mtime) / 86400
            if is_program_files:
                if not _has_program_files(entry.path, stop):
                    confidence, reason = HIGH, f"{label}: no program file left inside"
                elif covered:
                    continue
                else:
                    confidence, reason = LOW, f"{label}: not listed in installed programs (portable or manual copy?)"
            elif covered:
                continue
            elif age_days >= OLD_FOLDER_DAYS:
                confidence = MEDIUM
                reason = f"{label}: no installed program matches, last changed {datetime.fromtimestamp(info.st_mtime):%Y-%m-%d}"
            else:
                confidence = LOW
                reason = f"{label}: no installed program matches, changed recently"
            scan.items.append(GarbageItem(entry.path, KIND_FOLDER, folder_size(entry.path, stop), info.st_mtime,
                                          reason, confidence))
    scan.items.sort(key=lambda i: (CONFIDENCE_ORDER[i.confidence], -i.size))
    return scan

# endregion


# region Sizes: categories, drives and folders

_preset_matchers: Optional[List[Tuple[str, Callable[[str, str], bool]]]] = None


def categorize(item: GarbageItem) -> str:
    """The group an item belongs to in the charts: the preset that matches its name, or the leftover class."""
    global _preset_matchers
    if item.confidence:
        return f"Leftover folders ({item.confidence.lower()} confidence)"
    if _preset_matchers is None:
        _preset_matchers = [(name, compile_patterns(patterns)) for name, patterns in PRESETS.items()]
    name = os.path.basename(item.path)
    for label, match in _preset_matchers:
        if match(name, item.path):
            return label
    return "Other matches"


def is_likely(item: GarbageItem) -> bool:
    """Counted as space that can really be freed. A low-confidence leftover may be a portable tool or a program
    in use (npm, a game launcher...), so it is shown but not counted."""
    return item.confidence != LOW


def summarize(items: List[GarbageItem]) -> List[Tuple[str, int, int]]:
    """(category, number of items, bytes), biggest first."""
    totals: Dict[str, List[int]] = {}
    for item in items:
        entry = totals.setdefault(categorize(item), [0, 0])
        entry[0] += 1
        entry[1] += item.size
    return sorted(((k, v[0], v[1]) for k, v in totals.items()), key=lambda r: -r[2])


def size_by_drive(items: List[GarbageItem]) -> Dict[str, int]:
    """Bytes of garbage per drive ('C:')."""
    totals: Dict[str, int] = {}
    for item in items:
        drive = os.path.splitdrive(item.path)[0].upper()
        if drive:
            totals[drive] = totals.get(drive, 0) + item.size
    return totals


@dataclass
class DriveUsage:
    root: str                # 'C:\\'
    total: int
    used: int
    free: int


def drive_usage(roots: Optional[List[str]] = None) -> List[DriveUsage]:
    usage = []
    for root in roots if roots is not None else fixed_drives():
        try:
            total, used, free = shutil.disk_usage(root)
        except OSError:
            continue
        usage.append(DriveUsage(root, total, used, free))
    return usage


@dataclass
class FolderUsage:
    root: str
    folders: List[Tuple[str, int]] = field(default_factory=list)   # (path, bytes), biggest first
    loose_files: int = 0                                           # bytes of the files directly in the root
    truncated: bool = False

    @property
    def total(self) -> int:
        return self.loose_files + sum(size for _p, size in self.folders)


def folder_usage(root: str, stop: Callable[[], bool] = lambda: False, progress: Optional[Callable[[str], None]] = None,
                 workers: int = 8) -> FolderUsage:
    """Size of each folder directly below root, computed in parallel (the disk is the bottleneck, threads still help)."""
    from concurrent.futures import ThreadPoolExecutor
    result = FolderUsage(root)
    children = []
    try:
        entries = list(os.scandir(root))
    except OSError:
        return result
    for entry in entries:
        try:
            info = entry.stat(follow_symlinks=False)
            if info.st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT:
                continue
            if entry.is_dir(follow_symlinks=False):
                children.append(entry.path)
            else:
                result.loose_files += info.st_size
        except OSError:
            continue
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for path, size in zip(children, pool.map(lambda p: folder_size(p, stop, max_files=2_000_000), children)):
            done += 1
            if progress:
                progress(f"Measuring folders... {done}/{len(children)}")
            result.folders.append((path, size))
    result.truncated = stop()
    result.folders.sort(key=lambda r: -r[1])
    return result

# endregion


# region Deleting

def _essential_folders() -> List[str]:
    folders = [known_folder(code) for code in CSIDL.values()] + [app_dir(), SYSTEM_ROOT, tempfile.gettempdir()]
    return [os.path.normcase(os.path.abspath(f)) for f in folders if f]


def protected_reason(path: str) -> str:
    """Why this path must never be deleted from here ('' when it is allowed)."""
    if not path or not os.path.isabs(path):
        return "Not an absolute path"
    full = os.path.normcase(_absolute(path))
    if os.path.dirname(full) == full:
        return "Drive root"
    if os.path.isdir(path) and is_kept_folder(os.path.basename(os.path.normpath(path)), True):
        return "Folder ending with ~ (a Unity package folder such as Samples~): kept"
    if full == os.path.normcase(SYSTEM_ROOT) or full.startswith(os.path.normcase(SYSTEM_ROOT) + "\\"):
        return "Inside the Windows folder"
    for essential in _essential_folders():
        if essential == full or essential.startswith(full + "\\"):
            return "Essential folder (profile, Documents, Program Files, AppData or this program)"
    try:
        if _is_link(os.lstat(_long(path) if is_reserved_name(path) else path).st_file_attributes):
            return "Link or junction"
    except OSError:
        pass
    return ""


class _ShFileOp(ctypes.Structure):
    _fields_ = [("hwnd", ctypes.c_void_p), ("func", ctypes.c_uint), ("source", ctypes.c_void_p),
                ("target", ctypes.c_void_p), ("flags", ctypes.c_ushort), ("aborted", ctypes.c_int),
                ("mappings", ctypes.c_void_p), ("title", ctypes.c_wchar_p)]


FO_DELETE, FOF_SILENT, FOF_NOCONFIRMATION, FOF_ALLOWUNDO, FOF_NOERRORUI = 3, 0x4, 0x10, 0x40, 0x400


def recycle_path(path: str) -> str:
    """Move a file or folder to the Recycle Bin. Returns '' or an error message."""
    source = ctypes.create_unicode_buffer(os.path.abspath(path) + "\0")  # the API wants a double NUL
    operation = _ShFileOp(None, FO_DELETE, ctypes.cast(source, ctypes.c_void_p).value, None,
                          FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT, 0, None, None)
    try:
        code = system_dll("shell32").SHFileOperationW(ctypes.byref(operation))
    except (AttributeError, OSError) as e:
        return str(e)
    if code or operation.aborted:
        return f"Windows could not move it to the Recycle Bin (code {code})"
    return ""


def _remove(path: str) -> str:
    """Delete for good. Returns '' or an error message."""
    target = _long(path) if is_reserved_name(path) else path

    def clear_readonly(function, failing_path, error):
        os.chmod(failing_path, 0o700)
        function(failing_path)

    try:
        if os.path.isdir(target) and not os.path.islink(target):
            shutil.rmtree(target, onexc=clear_readonly)
        else:
            try:
                os.remove(target)
            except PermissionError:
                os.chmod(target, 0o700)
                os.remove(target)
    except FileNotFoundError:
        return ""
    except OSError as e:
        return str(e)
    return ""


def delete_items(items: List[GarbageItem], permanent: bool = False, recycle: Callable[[str], str] = recycle_path,
                 stop: Callable[[], bool] = lambda: False) -> DeleteResult:
    """Delete exactly these items. Recycle Bin by default; files named like devices (nul, con...) cannot go to
    the Recycle Bin and are removed for good."""
    result = DeleteResult()
    for item in items:
        if stop():
            result.failed.append((item, "Stopped"))
            continue
        reason = protected_reason(item.path)
        if reason:
            result.failed.append((item, reason))
            continue
        probe = _long(item.path) if is_reserved_name(item.path) else item.path
        if not os.path.lexists(probe):
            result.deleted.append(item)  # already gone
            continue
        error = _remove(item.path) if permanent or is_reserved_name(item.path) else recycle(item.path)
        if error:
            result.failed.append((item, error))
            continue
        result.deleted.append(item)
        result.freed += item.size
        logging.info(f"Garbage: {'deleted' if permanent else 'recycled'} {item.path} ({human_size(item.size)})")
    return result

# endregion
