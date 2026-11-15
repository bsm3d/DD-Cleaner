"""VirusTotal: look a file up by its SHA-256, and send a suspicious file for analysis after the user confirmed.

Looking up sends only the hash. Sending shares the whole file with VirusTotal and the security companies and
researchers who use it: it cannot be undone, so it is limited to programs and scripts (archives with a warning), never
documents, images or media, and the caller must have asked the user first. The API key lives in the protected
data folder (api_keys.py) and is only ever sent to www.virustotal.com over HTTPS; it is never logged.
"""

import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from ddcleaner import api_keys, file_inspect

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui/file/"
MAX_UPLOAD = 32 * 1024 * 1024        # the plain upload endpoint refuses more
REQUEST_GAP_SECONDS = 15             # the free key allows 4 requests per minute
ANALYSIS_WAIT_SECONDS = 360
SCRIPT_SUFFIXES = {".ps1", ".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd", ".hta", ".wsf", ".jar", ".dll", ".sys", ".scr",
                   ".msi", ".lnk", ".py", ".com", ".exe", ".cpl", ".ocx"}
ALLOWED_KINDS = {"executable", "script", "shortcut", "data"}
WARN_KINDS = {"archive"}

Http = Callable[[urllib.request.Request], Tuple[int, bytes]]


class VtError(Exception):
    pass


@dataclass
class VtReport:
    found: bool
    sha256: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    names: List[str] = field(default_factory=list)
    label: str = ""
    type: str = ""
    status: str = "completed"       # queued | in-progress | completed (a fresh upload takes a few minutes)

    @property
    def total(self) -> int:
        return self.malicious + self.suspicious + self.harmless + self.undetected

    @property
    def link(self) -> str:
        return GUI + self.sha256

    @property
    def verdict(self) -> str:
        if not self.found:
            return "Unknown to VirusTotal"
        if self.status != "completed":
            return "Analysis in progress"
        flagged = self.malicious + self.suspicious
        text = f"{flagged}/{self.total} engines flag it"
        return text + (f" ({self.label})" if self.label and flagged else "")

    @property
    def severity(self) -> int:
        """0 clean, 1 a few engines (often false positives), 2 several engines, -1 no verdict yet."""
        if not self.found or self.status != "completed":
            return -1
        if self.malicious >= 3:
            return 2
        return 1 if self.malicious + self.suspicious else 0


@dataclass
class VtResult:
    path: str
    sha256: str = ""
    report: Optional[VtReport] = None
    error: str = ""
    uploaded: bool = False


# region Key

def load_key() -> str:
    """The saved API key ('' when there is none). Keys are managed in File > Preferences (api_keys.py)."""
    return api_keys.get(api_keys.VIRUSTOTAL.id)

# endregion


# region HTTP

def _urlopen(request: urllib.request.Request) -> Tuple[int, bytes]:
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        raise VtError(f"Cannot reach VirusTotal: {getattr(e, 'reason', e)}")


def _call(method: str, path: str, key: str, body: Optional[bytes] = None, content_type: str = "",
          http: Http = _urlopen) -> Tuple[int, dict]:
    headers = {"x-apikey": key, "accept": "application/json"}
    if content_type:
        headers["content-type"] = content_type
    status, raw = http(urllib.request.Request(API + path, data=body, headers=headers, method=method))
    try:
        data = json.loads(raw.decode("utf-8")) if raw else {}
    except ValueError:
        data = {}
    if status == 401:
        raise VtError("VirusTotal refused the API key.")
    if status == 429:
        raise VtError("VirusTotal quota reached (the free key allows 4 requests per minute, 500 per day). Try later.")
    if status >= 500:
        raise VtError(f"VirusTotal is not available (error {status}).")
    return status, data if isinstance(data, dict) else {}


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _report(sha256: str, attributes: dict, status: str = "completed") -> VtReport:
    stats = attributes.get("last_analysis_stats") or attributes.get("stats") or {}
    classification = attributes.get("popular_threat_classification") or {}
    names = [n for n in ([attributes.get("meaningful_name")] + list(attributes.get("names") or [])) if isinstance(n, str)]
    return VtReport(True, sha256, int(stats.get("malicious", 0)), int(stats.get("suspicious", 0)),
                    int(stats.get("harmless", 0)), int(stats.get("undetected", 0)),
                    list(dict.fromkeys(names))[:5], str(classification.get("suggested_threat_label", "")),
                    str(attributes.get("type_description", "")), status)

# endregion


# region Look up and upload

def lookup(sha256: str, key: str, http: Http = _urlopen) -> VtReport:
    """What VirusTotal knows about a hash (only the hash is sent)."""
    status, data = _call("GET", f"/files/{sha256}", key, http=http)
    if status == 404:
        return VtReport(False, sha256)
    if status != 200:
        raise VtError(f"VirusTotal answered {status}: {(data.get('error') or {}).get('message', 'unexpected answer')}")
    return _report(sha256, (data.get("data") or {}).get("attributes") or {})


def upload_problem(path: str) -> str:
    """Why this file must not be sent ('' when it may be offered to the user)."""
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return f"The file cannot be read: {e}"
    if size == 0:
        return "The file is empty."
    if size > MAX_UPLOAD:
        return f"The file is larger than {MAX_UPLOAD // (1024 * 1024)} MB, the limit of a direct upload."
    inspection = file_inspect.inspect(path)
    if inspection.error:
        return f"The file cannot be read: {inspection.error}"
    if os.path.splitext(path)[1].lower() in SCRIPT_SUFFIXES or inspection.kind in ALLOWED_KINDS | WARN_KINDS:
        return ""
    return (f"This looks like a {inspection.true_type} ({inspection.kind}). Only programs, scripts and archives are "
            "sent: documents, pictures and media can hold personal data.")


def upload_warning(path: str) -> str:
    """Extra warning to show before sending, '' when none."""
    if file_inspect.inspect(path).kind in WARN_KINDS:
        return "This is an archive: make sure it holds nothing private, VirusTotal will see everything inside."
    return ""


def _multipart(path: str) -> Tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    name = "".join(c if c.isascii() and (c.isalnum() or c in "._- ") else "_" for c in os.path.basename(path)) or "file"
    with open(path, "rb") as f:
        content = f.read()
    head = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n").encode("ascii")
    return head + content + f"\r\n--{boundary}--\r\n".encode("ascii"), f"multipart/form-data; boundary={boundary}"


def upload(path: str, key: str, http: Http = _urlopen) -> str:
    """Send the file. Returns the analysis id. The caller must have the user's confirmation and have checked
    upload_problem()."""
    problem = upload_problem(path)
    if problem:
        raise VtError(problem)
    body, content_type = _multipart(path)
    status, data = _call("POST", "/files", key, body, content_type, http)
    analysis = (data.get("data") or {}).get("id")
    if status != 200 or not analysis:
        raise VtError(f"VirusTotal did not accept the file ({status}): {(data.get('error') or {}).get('message', '')}")
    logging.info(f"VirusTotal: sent {os.path.basename(path)} for analysis")
    return str(analysis)


def wait_for_analysis(analysis_id: str, sha256: str, key: str, http: Http = _urlopen,
                      stop: Callable[[], bool] = lambda: False, sleep: Callable[[float], None] = time.sleep,
                      waited: float = ANALYSIS_WAIT_SECONDS, step: float = REQUEST_GAP_SECONDS) -> VtReport:
    elapsed = 0.0
    while True:
        status, data = _call("GET", f"/analyses/{analysis_id}", key, http=http)
        attributes = (data.get("data") or {}).get("attributes") or {}
        state = str(attributes.get("status", ""))
        if status == 200 and state == "completed":
            try:
                report = lookup(sha256, key, http)  # richer than the analysis: names, label, type
                if report.found:
                    return report
            except VtError:
                pass
            return _report(sha256, attributes)  # the file report is not ready yet: the analysis has the verdict
        if elapsed >= waited or stop():
            return VtReport(True, sha256, status=state or "queued")
        sleep(step)
        elapsed += step


def check_files(paths: List[str], key: str, http: Http = _urlopen, progress: Optional[Callable[[str], None]] = None,
                stop: Callable[[], bool] = lambda: False, sleep: Callable[[float], None] = time.sleep) -> List[VtResult]:
    """Look each file up by hash, one request every REQUEST_GAP_SECONDS (free key quota). Nothing is uploaded."""
    results = []
    for index, path in enumerate(paths):
        if stop():
            break
        if index:
            sleep(REQUEST_GAP_SECONDS)
        if progress:
            progress(f"VirusTotal: looking up {os.path.basename(path)} ({index + 1}/{len(paths)})...")
        result = VtResult(path)
        try:
            result.sha256 = sha256_file(path)
            result.report = lookup(result.sha256, key, http)
        except (OSError, VtError) as e:
            result.error = str(e)
            if isinstance(e, VtError) and ("refused the API key" in result.error or "quota" in result.error):
                results.append(result)
                break  # no point trying the others
        results.append(result)
    return results


def submit_file(path: str, key: str, http: Http = _urlopen, progress: Optional[Callable[[str], None]] = None,
                stop: Callable[[], bool] = lambda: False, sleep: Callable[[float], None] = time.sleep) -> VtResult:
    """Upload one file, then wait (a few minutes at most) for the verdict."""
    result = VtResult(path, uploaded=True)
    try:
        result.sha256 = sha256_file(path)
        if progress:
            progress(f"VirusTotal: sending {os.path.basename(path)}...")
        analysis = upload(path, key, http)
        if progress:
            progress("VirusTotal: analysis running, this takes a few minutes...")
        result.report = wait_for_analysis(analysis, result.sha256, key, http, stop, sleep)
    except (OSError, VtError) as e:
        result.error = str(e)
    return result

# endregion
