"""Protection settings for the antivirus: folders watched for new files, scan schedule, and custom YARA rules.

No Qt here. The settings file and the rules live in the protected ClamAV folder: a file a standard program could edit
could switch the protection off or add a rule that whitelists nothing but still costs time. Everything runs only
while the program is open (there is no background service).
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, Iterable, List, Optional

from ddcleaner import clamav
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM32, safe_environment

PARTIAL_SUFFIXES = {".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload", ".temp"}
MAX_WATCH_FILES = 20_000
MAX_WATCH_DEPTH = 3
YARA_SUFFIXES = {".yar", ".yara"}
MAX_RULE_BYTES = 5 * 1024 * 1024
SETTINGS_NAME = "protection.json"
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


# region Settings

@dataclass
class ProtectionSettings:
    watch_enabled: bool = False
    folders: List[str] = field(default_factory=list)
    scan_hours: int = 0          # quick scan every N hours while the program is open (0 = never)
    last_quick_scan: float = 0.0


def settings_path() -> str:
    return os.path.join(clamav.clam_dir(), SETTINGS_NAME)


def load_settings(path: Optional[str] = None) -> ProtectionSettings:
    try:
        with open(path or settings_path(), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return ProtectionSettings()
    if not isinstance(data, dict):
        return ProtectionSettings()
    folders = [str(p) for p in data.get("folders", []) if isinstance(p, str) and os.path.isabs(p)] \
        if isinstance(data.get("folders"), list) else []
    try:
        hours = max(0, min(int(data.get("scan_hours", 0)), 24 * 30))
        last = float(data.get("last_quick_scan", 0.0))
    except (TypeError, ValueError):
        hours, last = 0, 0.0
    return ProtectionSettings(bool(data.get("watch_enabled", False)), folders, hours, last)


def save_settings(settings: ProtectionSettings, path: Optional[str] = None) -> str:
    """Atomic write. Returns '' or an error message."""
    path = path or settings_path()
    temp = path + ".tmp"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(temp, "w", encoding="utf-8") as f:
            json.dump(asdict(settings), f, indent=2, ensure_ascii=False)
        os.replace(temp, path)
    except OSError as e:
        logging.error(f"Protection settings not saved: {e}")
        return str(e)
    return ""


def scan_is_due(settings: ProtectionSettings, now: Optional[float] = None) -> bool:
    now = time.time() if now is None else now
    return settings.scan_hours > 0 and now - settings.last_quick_scan >= settings.scan_hours * 3600

# endregion


# region Watching folders

class FolderWatcher:
    """Reports files that appeared (or were replaced) in the watched folders and have stopped changing.

    A file is reported once its size and modification time are the same on two polls in a row: a download in
    progress keeps growing, so it is only handed over when it is complete. Files already there when watching
    starts are not reported (a full scan is a separate action)."""

    def __init__(self, folders: Iterable[str], max_depth: int = MAX_WATCH_DEPTH, max_files: int = MAX_WATCH_FILES):
        self.folders = [f for f in folders if os.path.isabs(f)]
        self.max_depth, self.max_files = max_depth, max_files
        self.known: Dict[str, tuple] = {}
        self.pending: Dict[str, tuple] = {}

    def _listing(self) -> Dict[str, tuple]:
        found: Dict[str, tuple] = {}
        stack = [(f, 0) for f in self.folders if os.path.isdir(f)]
        while stack and len(found) < self.max_files:
            folder, depth = stack.pop()
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
                        if depth < self.max_depth:
                            stack.append((entry.path, depth + 1))
                    elif os.path.splitext(entry.name)[1].lower() not in PARTIAL_SUFFIXES and not entry.name.startswith("~$"):
                        found[entry.path] = (info.st_size, info.st_mtime_ns)
                except OSError:
                    continue
        return found

    def prime(self):
        """Remember what is already there."""
        self.known = self._listing()
        self.pending = {}

    def poll(self) -> List[str]:
        current = self._listing()
        ready = []
        for path, signature in current.items():
            if self.known.get(path) == signature:
                continue
            if self.pending.get(path) == signature:
                ready.append(path)
                self.known[path] = signature
                del self.pending[path]
            else:
                self.pending[path] = signature
        self.pending = {p: s for p, s in self.pending.items() if p in current}
        self.known = {p: s for p, s in self.known.items() if p in current}
        return sorted(ready, key=str.lower)

# endregion


# region YARA rules

def rules_dir() -> str:
    return clamav.database_dir()


def list_rule_files(folder: Optional[str] = None) -> List[str]:
    folder = folder or rules_dir()
    if not os.path.isdir(folder):
        return []
    return sorted(n for n in os.listdir(folder)
                  if os.path.splitext(n)[1].lower() in YARA_SUFFIXES and os.path.isfile(os.path.join(folder, n)))


def check_rule_text(source: str) -> str:
    """'' when the file looks like a YARA rule file (size, text, a rule inside), else the reason it does not."""
    if os.path.splitext(source)[1].lower() not in YARA_SUFFIXES:
        return "A YARA rule file ends in .yar or .yara."
    try:
        size = os.path.getsize(source)
        if size == 0 or size > MAX_RULE_BYTES:
            return f"The file must be between 1 byte and {MAX_RULE_BYTES // (1024 * 1024)} MB."
        with open(source, "rb") as f:
            data = f.read()
        text = data.decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        return f"The file cannot be read as text: {e}"
    if "\x00" in text or "rule " not in text:
        return "No YARA rule found in this file."
    return ""


def check_rule_with_clamav(install: clamav.Install, source: str, run: Callable = subprocess.run) -> str:
    """Let clamscan load the rule file alone: '' if it accepts it, else its complaint."""
    work = tempfile.mkdtemp(prefix="ddc_rule_")
    try:
        shutil.copyfile(source, os.path.join(work, os.path.basename(source)))
        sample = os.path.join(work, "sample.txt")
        with open(sample, "w", encoding="utf-8") as f:
            f.write("harmless text\n")
        done = run([install.clamscan, f"--database={work}", "--stdout", sample], capture_output=True, text=True,
                   errors="replace", timeout=120, cwd=SYSTEM32, env=safe_environment(), creationflags=SUBPROCESS_FLAGS)
        output = done.stdout + done.stderr
        loaded = re.search(r"Known viruses:\s*(\d+)", output)
        # a broken rule file does not make clamscan fail: it loads nothing and says so in a warning
        if done.returncode in (0, 1) and loaded and int(loaded.group(1)) > 0 and "failed to parse" not in output:
            return ""
        lines = [l for l in output.splitlines() if "error" in l.lower() or "failed" in l.lower() or "can't" in l.lower()]
        return (lines[0] if lines else "clamscan loaded no rule from this file")[:300]
    except (subprocess.SubprocessError, OSError) as e:
        return str(e)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def add_rule_file(source: str, folder: Optional[str] = None, install: Optional[clamav.Install] = None,
                  run: Callable = subprocess.run) -> str:
    """Copy a YARA rule file into the protected rules folder. Returns '' or an error message."""
    folder = folder or rules_dir()
    problem = check_rule_text(source)
    if problem:
        return problem
    name = os.path.basename(source)
    if os.path.exists(os.path.join(folder, name)):
        return f"A rule file named {name} is already installed. Remove it first."
    if install is not None:
        problem = check_rule_with_clamav(install, source, run)
        if problem:
            return f"ClamAV cannot load this file: {problem}"
    try:
        os.makedirs(folder, exist_ok=True)
        temp = os.path.join(folder, name + ".tmp")
        shutil.copyfile(source, temp)
        os.replace(temp, os.path.join(folder, name))
    except OSError as e:
        return str(e)
    logging.info(f"YARA rule file installed: {name}")
    return ""


def remove_rule_file(name: str, folder: Optional[str] = None) -> str:
    folder = folder or rules_dir()
    if name != os.path.basename(name) or name not in list_rule_files(folder):
        return "This is not an installed rule file."
    try:
        os.remove(os.path.join(folder, name))
    except OSError as e:
        return str(e)
    logging.info(f"YARA rule file removed: {name}")
    return ""

# endregion
