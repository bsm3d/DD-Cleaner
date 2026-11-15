"""API keys of the online services the program can use (VirusTotal for now), kept in one file.

The file lives in the protected data folder (administrators only). A key is never logged, never shown in full, and
only ever sent to the service it belongs to. To add a service, add one Provider to PROVIDERS and, if it can be
tested, a branch in check_key().
"""

import json
import logging
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from ddcleaner.common import data_dir

STORE_NAME = "api_keys.json"
EMPTY_FILE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
Http = Callable[[urllib.request.Request], Tuple[int, bytes]]


@dataclass(frozen=True)
class Provider:
    id: str
    label: str
    purpose: str            # what the program does with the key, and what is sent
    get_it: str             # where to create the key
    pattern: str            # regular expression a key must match
    format_hint: str
    testable: bool = True


VIRUSTOTAL = Provider(
    "virustotal", "VirusTotal",
    "Second opinion on suspicious programs. A lookup sends only the file's SHA-256; sending a file for analysis "
    "needs your confirmation each time. The free key allows 4 requests per minute.",
    "https://www.virustotal.com/gui/my-apikey", r"[0-9a-fA-F]{64}", "64 letters and digits (hexadecimal)")
PROVIDERS: List[Provider] = [VIRUSTOTAL]


def provider(provider_id: str) -> Provider:
    for p in PROVIDERS:
        if p.id == provider_id:
            return p
    raise KeyError(provider_id)


# region Store

def store_path() -> str:
    return os.path.join(data_dir(), STORE_NAME)


def _read(path: Optional[str] = None) -> Dict[str, str]:
    try:
        with open(path or store_path(), encoding="utf-8") as f:
            keys = json.load(f).get("keys", {})
    except (OSError, ValueError, AttributeError):
        return {}
    return {k: v.strip() for k, v in keys.items() if isinstance(k, str) and isinstance(v, str)} \
        if isinstance(keys, dict) else {}


def get(provider_id: str, path: Optional[str] = None) -> str:
    return _read(path).get(provider_id, "")


def validate(provider_id: str, key: str) -> str:
    """'' when the key has the right shape for this service, else what is wrong."""
    p = provider(provider_id)
    if not re.fullmatch(p.pattern, key.strip()):
        return f"A {p.label} API key is {p.format_hint}."
    return ""


def set_key(provider_id: str, key: str, path: Optional[str] = None) -> str:
    """Save (or, with an empty key, remove) a key. Atomic write. Returns '' or an error message."""
    key = key.strip()
    if key:
        problem = validate(provider_id, key)
        if problem:
            return problem
    path = path or store_path()
    keys = _read(path)
    if key:
        keys[provider_id] = key
    else:
        keys.pop(provider_id, None)
    temp = path + ".tmp"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(temp, "w", encoding="utf-8") as f:
            json.dump({"keys": keys}, f, indent=2)
        os.replace(temp, path)
    except OSError as e:
        logging.error(f"API keys not saved: {e}")  # the message never contains a key
        return str(e)
    logging.info(f"API key for {provider_id} {'saved' if key else 'removed'}")
    return ""


def status(provider_id: str, path: Optional[str] = None) -> str:
    key = get(provider_id, path)
    return f"Saved (ends with {key[-4:]})" if key else "No key saved"

# endregion


# region Testing a key

def _urlopen(request: urllib.request.Request) -> Tuple[int, bytes]:
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        raise OSError(f"Cannot reach the service: {getattr(e, 'reason', e)}")


def check_key(provider_id: str, key: str, http: Http = _urlopen) -> str:
    """Ask the service whether it accepts this key. Returns '' when it does, else the reason. Only this call sends
    the key; it reads nothing of yours."""
    key = key.strip()
    if not key:
        return "No key to test."
    try:
        if provider_id == VIRUSTOTAL.id:
            from ddcleaner import virustotal  # imported here: virustotal itself reads its key from this module
            virustotal.lookup(EMPTY_FILE_SHA256, key, http)
            return ""
    except OSError as e:
        return str(e)
    except Exception as e:  # noqa: BLE001  (VtError and anything a service answers that we did not foresee)
        return str(e)
    return "This service cannot be tested."

# endregion
