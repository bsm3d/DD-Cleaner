"""ClamAV integration: find the install, build commands, read the output, keep the quarantine list.

No Qt here, so everything can be tested without a window. The program runs as administrator, so:
  - clamscan.exe / freshclam.exe are only taken from C:\\Program Files\\ClamAV (or the x86 folder) and only if
    that folder cannot be modified without administrator rights (a planted exe or DLL would run elevated);
  - the signature database, the quarantine and the manifest live in the protected data folder
    (C:\\ProgramData\\DD Cleaner\\clamav): a database a standard program could edit could hide malware,
    and a quarantine it could read or edit could give malware back.
"""

import ctypes
import json
import logging
import os
import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

from ddcleaner import folder_security
from ddcleaner.common import data_dir

CSIDL_PROGRAM_FILES = 0x26
CSIDL_PROGRAM_FILESX86 = 0x2A
MANIFEST_NAME = "manifest.json"
DB_SUFFIXES = {".cvd", ".cld", ".cud", ".hdb", ".hsb", ".ndb", ".ldb", ".mdb", ".msb", ".fp", ".sfp", ".yar", ".yara"}
MAX_FILESIZE_MB = (1, 4000)
MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}


# region Folders

def _known_folder(csidl: int) -> Optional[str]:
    """Program Files from the API, never from %ProgramFiles% (an elevated process can inherit a fake one)."""
    try:
        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.shell32.SHGetFolderPathW(None, csidl, None, 0, buf) == 0:
            return buf.value
    except (AttributeError, OSError):
        pass
    return None


def clam_dir() -> str:
    return os.path.join(data_dir(), "clamav")


def database_dir() -> str:
    return os.path.join(clam_dir(), "database")


def quarantine_dir() -> str:
    return os.path.join(clam_dir(), "quarantine")


def manifest_path() -> str:
    return os.path.join(quarantine_dir(), MANIFEST_NAME)


def freshclam_conf_path() -> str:
    return os.path.join(clam_dir(), "freshclam.conf")


def update_log_path() -> str:
    return os.path.join(clam_dir(), "freshclam.log")

# endregion


# region Install

@dataclass
class Install:
    folder: str
    clamscan: str
    freshclam: str


def find_install() -> Tuple[Optional[Install], str]:
    """(install, "") or (None, reason). Only protected Program Files folders are accepted."""
    seen_unprotected = []
    for csidl in (CSIDL_PROGRAM_FILES, CSIDL_PROGRAM_FILESX86):
        base = _known_folder(csidl)
        if not base:
            continue
        folder = os.path.join(base, "ClamAV")
        clamscan, freshclam = (os.path.join(folder, n) for n in ("clamscan.exe", "freshclam.exe"))
        if not (os.path.isfile(clamscan) and os.path.isfile(freshclam)):
            continue
        problems = folder_security.folder_risk(folder)
        if problems:
            seen_unprotected.extend(problems)
            continue
        return Install(folder, clamscan, freshclam), ""
    if seen_unprotected:
        return None, ("ClamAV was found but its folder is not protected, so it is not used:\n"
                      + "\n".join(seen_unprotected))
    return None, "ClamAV is not installed in C:\\Program Files\\ClamAV."

# endregion


# region Signature database

@dataclass
class DatabaseInfo:
    ready: bool = False
    signatures: int = 0
    built: Optional[datetime] = None

    @property
    def age_days(self) -> Optional[int]:
        return (datetime.now() - self.built).days if self.built else None


def _parse_build_time(text: str) -> Optional[datetime]:
    """'11 Oct 2026 08-00 +0000' -> datetime (month names parsed here: strptime depends on the locale)."""
    m = re.match(r"\s*(\d{1,2}) ([A-Za-z]{3}) (\d{4}) (\d{1,2})-(\d{2})", text)
    if not m or m.group(2).title() not in MONTHS:
        return None
    try:
        return datetime(int(m.group(3)), MONTHS[m.group(2).title()], int(m.group(1)), int(m.group(4)), int(m.group(5)))
    except ValueError:
        return None


def read_database_info(folder: Optional[str] = None) -> DatabaseInfo:
    folder = folder or database_dir()
    info = DatabaseInfo()
    if not os.path.isdir(folder):
        return info
    for name in os.listdir(folder):
        path = os.path.join(folder, name)
        suffix = os.path.splitext(name)[1].lower()
        if suffix not in DB_SUFFIXES or suffix in (".yar", ".yara") or not os.path.isfile(path):
            continue  # custom YARA rules alone are not a signature database: scans stay refused until it is downloaded
        info.ready = True
        if suffix not in (".cvd", ".cld"):
            continue
        try:
            with open(path, "rb") as f:
                header = f.read(512).decode("latin-1").split(":")
        except OSError:
            continue
        if len(header) < 4 or header[0] != "ClamAV-VDB":
            continue
        if header[3].isdigit():
            info.signatures += int(header[3])
        built = _parse_build_time(header[1]) or datetime.fromtimestamp(os.path.getmtime(path))
        if info.built is None or built > info.built:
            info.built = built
    return info


def write_freshclam_conf(conf: Optional[str] = None, database: Optional[str] = None,
                         log: Optional[str] = None) -> str:
    conf, database, log = conf or freshclam_conf_path(), database or database_dir(), log or update_log_path()
    os.makedirs(database, exist_ok=True)
    with open(conf, "w", encoding="utf-8") as f:
        f.write(f"DatabaseDirectory {database}\n"
                f"UpdateLogFile {log}\n"
                "DatabaseMirror database.clamav.net\n"
                "ConnectTimeout 30\n"
                "ReceiveTimeout 120\n")
    return conf


def build_update_command(install: Install, conf: str, database: str) -> List[str]:
    return [install.freshclam, f"--config-file={conf}", f"--datadir={database}", "--stdout", "--show-progress"]

# endregion


# region Scan

def fixed_drives() -> List[str]:
    k32 = ctypes.windll.kernel32
    mask = k32.GetLogicalDrives()
    drives = []
    for i in range(26):
        root = f"{chr(65 + i)}:\\"
        if mask >> i & 1 and k32.GetDriveTypeW(root) == 3:  # DRIVE_FIXED
            drives.append(root)
    return drives


def build_scan_command(install: Install, targets: List[str], *, quarantine: bool = True, archives: bool = True,
                       max_filesize_mb: int = 100, detect_pua: bool = False, thorough: bool = False,
                       database: Optional[str] = None, clam_folder: Optional[str] = None, fast: bool = False,
                       file_list: Optional[str] = None) -> List[str]:
    """Command line for clamscan. Targets must be absolute paths (a relative one starting with '-' would be
    read as an option).

    detect_pua: also flag potentially unwanted applications (adware, bundleware, hacktools).
    thorough: turn risky-but-not-yet-known files into detections (encrypted archives and documents, OLE2
    macros, broken executables, files that hit the size/recursion limits) and raise the archive limits.
    More catches, but also more false positives, so it is off by default.
    fast: no archives, no heuristics, no phishing URL check. Several times quicker, catches less.
    file_list: scan the files named in this UTF-8 file (one path per line) instead of walking the targets."""
    if not targets and not file_list:
        raise ValueError("Nothing to scan.")
    for t in targets:
        if not os.path.isabs(t):
            raise ValueError(f"Not an absolute path: {t}")
    database = database or database_dir()
    clam_folder = clam_folder or clam_dir()
    max_mb = min(max(int(max_filesize_mb), MAX_FILESIZE_MB[0]), MAX_FILESIZE_MB[1])
    scan_mb = max(max_mb * (8 if thorough else 4), 1000 if thorough else 400)
    cmd = [install.clamscan, f"--database={database}", "--recursive",
           "--follow-dir-symlinks=0", "--follow-file-symlinks=0", "--stdout",
           f"--heuristic-alerts={'no' if fast else 'yes'}", f"--phishing-scan-urls={'no' if fast else 'yes'}",
           f"--max-filesize={max_mb}M", f"--max-scansize={scan_mb}M",
           # never scan our own database and quarantine (the quarantine holds known malware)
           f"--exclude-dir={re.escape(clam_folder)}"]
    if not archives or fast:
        cmd.append("--scan-archive=no")
    if detect_pua:
        cmd.append("--detect-pua=yes")
    if thorough:
        cmd += ["--alert-broken=yes", "--alert-broken-media=yes", "--alert-encrypted=yes",
                "--alert-macros=yes", "--alert-exceeds-max=yes", "--max-recursion=20", "--max-files=100000"]
    if quarantine:
        cmd.append(f"--move={os.path.join(clam_folder, 'quarantine')}")
    if file_list:
        cmd.append(f"--file-list={file_list}")
    cmd.extend(targets)
    return cmd


SUMMARY_KEYS = {"Known viruses": "signatures", "Engine version": "engine", "Scanned directories": "dirs",
                "Scanned files": "files", "Infected files": "infected", "Data scanned": "data", "Time": "time"}
IGNORED_STATUSES = {"Empty file", "Symbolic link", "Excluded"}


def parse_scan_line(line: str) -> tuple:
    """Classify one clamscan line: ("found", path, threat), ("moved", path, stored), ("ok", path),
    ("skip", path), ("error", line), ("summary", key, value) or ("other", line)."""
    if line.endswith(" FOUND"):
        path, _, threat = line[:-len(" FOUND")].rpartition(": ")
        return ("found", path, threat)
    moved = re.match(r"^(.*): moved to '(.*)'$", line)
    if moved:
        return ("moved", moved.group(1), moved.group(2))
    if line.endswith(": OK"):
        return ("ok", line[:-len(": OK")])
    if line.startswith("-----") or re.match(r"^(Data read|Start Date|End Date):", line):
        return ("other", "")
    path, sep, status = line.rpartition(": ")
    if sep and status in IGNORED_STATUSES:
        return ("skip", path)
    if line.endswith(" ERROR"):
        return ("error", line)
    key, sep, value = line.partition(": ")
    if sep and key in SUMMARY_KEYS:
        return ("summary", SUMMARY_KEYS[key], value.strip())
    return ("other", line)

# endregion


# region Quarantine

@dataclass
class QuarantineEntry:
    original: str
    stored: str
    threat: str
    date: str


UNKNOWN_ORIGIN = "(unknown location)"


def _inside(path: str, folder: str) -> bool:
    try:
        return os.path.commonpath([os.path.realpath(path), os.path.realpath(folder)]) == os.path.realpath(folder)
    except ValueError:
        return False  # different drives


def _read_manifest(folder: str) -> List[dict]:
    try:
        with open(os.path.join(folder, MANIFEST_NAME), encoding="utf-8") as f:
            data = json.load(f)
        return [e for e in data if isinstance(e, dict)] if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _write_manifest(folder: str, entries: List[dict]):
    """Atomic: write a temporary file then replace, so a crash never leaves half a JSON (which would be read
    as an empty list and overwritten, losing every original path)."""
    os.makedirs(folder, exist_ok=True)
    final = os.path.join(folder, MANIFEST_NAME)
    temp = final + ".tmp"
    with open(temp, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
    os.replace(temp, final)


def record_quarantine(original: str, stored: str, threat: str, folder: Optional[str] = None):
    folder = folder or quarantine_dir()
    path = os.path.join(folder, MANIFEST_NAME)
    if os.path.isfile(path) and not _read_manifest(folder) and os.path.getsize(path) > 2:
        try:  # unreadable manifest: keep it aside instead of overwriting it
            os.replace(path, path + ".corrupt")
        except OSError:
            pass
    entries = _read_manifest(folder)
    entries.append({"original": original, "stored": stored, "threat": threat,
                    "date": datetime.now().strftime("%Y-%m-%d %H:%M")})
    _write_manifest(folder, entries)


def list_quarantine(folder: Optional[str] = None) -> List[QuarantineEntry]:
    """Quarantined files: those in the manifest, plus any other file found in the folder."""
    folder = folder or quarantine_dir()
    if not os.path.isdir(folder):
        return []
    result, known = [], set()
    for e in _read_manifest(folder):
        stored = str(e.get("stored", ""))
        if os.path.isfile(stored) and _inside(stored, folder):
            result.append(QuarantineEntry(str(e.get("original", UNKNOWN_ORIGIN)), stored,
                                          str(e.get("threat", "?")), str(e.get("date", ""))))
            known.add(os.path.normcase(os.path.realpath(stored)))
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if name == MANIFEST_NAME or not os.path.isfile(path) or os.path.normcase(os.path.realpath(path)) in known:
            continue
        date = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M")
        result.append(QuarantineEntry(UNKNOWN_ORIGIN, path, "?", date))
    return result


def _forget(folder: str, stored: str):
    kept = [e for e in _read_manifest(folder) if os.path.normcase(str(e.get("stored", ""))) != os.path.normcase(stored)]
    _write_manifest(folder, kept)


def restore_quarantined(entry: QuarantineEntry, folder: Optional[str] = None) -> str:
    """Put a file back where it came from. Returns "" or an error message."""
    folder = folder or quarantine_dir()
    if not _inside(entry.stored, folder) or not os.path.isfile(entry.stored):
        return "The quarantined file is no longer in the quarantine folder."
    if entry.original == UNKNOWN_ORIGIN or not os.path.isabs(entry.original):
        return "The original location is unknown: the file cannot be restored automatically."
    if os.path.lexists(entry.original):
        return f"A file already exists at {entry.original}."
    try:
        os.makedirs(os.path.dirname(entry.original), exist_ok=True)
        shutil.move(entry.stored, entry.original)
        _forget(folder, entry.stored)
    except OSError as e:
        return str(e)
    logging.warning(f"ClamAV quarantine: restored {entry.original} ({entry.threat})")
    return ""


def delete_quarantined(entry: QuarantineEntry, folder: Optional[str] = None) -> str:
    """Delete a quarantined file for good. Returns "" or an error message."""
    folder = folder or quarantine_dir()
    if not _inside(entry.stored, folder):
        return "The file is not in the quarantine folder."
    try:
        os.remove(entry.stored)
        _forget(folder, entry.stored)
    except FileNotFoundError:
        _forget(folder, entry.stored)
    except OSError as e:
        return str(e)
    logging.info(f"ClamAV quarantine: deleted {entry.stored} ({entry.threat})")
    return ""

# endregion


def format_duration(seconds: float) -> str:
    seconds = int(seconds)
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours} h {minutes:02d} min {secs:02d} s" if hours else f"{minutes} min {secs:02d} s"


def shorten(text: str, limit: int = 100) -> str:
    if len(text) <= limit:
        return text
    keep = (limit - 3) // 2
    return text[:keep] + "..." + text[-keep:]
