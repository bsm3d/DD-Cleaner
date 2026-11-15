"""What the Garbage tab has freed so far: one line per deletion, kept in the protected data folder.

Only numbers are stored (date, bytes, files, registry entries), never paths or names.
"""

import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from ddcleaner.common import data_dir

NAME = "garbage_stats.json"
MAX_ENTRIES = 5000


@dataclass
class Totals:
    deletions: int = 0
    bytes: int = 0
    files: int = 0
    registry: int = 0


def stats_path() -> str:
    return os.path.join(data_dir(), NAME)


def load(path: Optional[str] = None) -> List[dict]:
    try:
        with open(path or stats_path(), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    clean = []
    for e in data if isinstance(data, list) else []:
        try:
            clean.append({"t": float(e["t"]), "bytes": max(0, int(e.get("bytes", 0))), "files": max(0, int(e.get("files", 0))),
                          "registry": max(0, int(e.get("registry", 0)))})
        except (KeyError, TypeError, ValueError):
            continue
    return clean


def record(freed_bytes: int, files: int = 0, registry: int = 0, path: Optional[str] = None,
           now: Optional[float] = None) -> str:
    """Add one deletion. Returns '' or an error message. Nothing is written when nothing was freed."""
    if freed_bytes <= 0 and files <= 0 and registry <= 0:
        return ""
    path = path or stats_path()
    entries = load(path)
    entries.append({"t": time.time() if now is None else now, "bytes": int(freed_bytes), "files": int(files),
                    "registry": int(registry)})
    temp = path + ".tmp"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(temp, "w", encoding="utf-8") as f:
            json.dump(entries[-MAX_ENTRIES:], f)
        os.replace(temp, path)
    except OSError as e:
        logging.warning(f"Garbage statistics not saved: {e}")
        return str(e)
    return ""


def totals(entries: List[dict]) -> Totals:
    return Totals(len(entries), sum(e["bytes"] for e in entries), sum(e["files"] for e in entries),
                  sum(e["registry"] for e in entries))


def per_day(entries: List[dict], days: int = 30, today: Optional[datetime] = None) -> List[tuple]:
    """(date, bytes freed) for each of the last `days` days, oldest first, zeros included."""
    today = (today or datetime.now()).date()
    buckets: Dict = {today - timedelta(days=i): 0 for i in range(days)}
    for e in entries:
        day = datetime.fromtimestamp(e["t"]).date()
        if day in buckets:
            buckets[day] += e["bytes"]
    return sorted(buckets.items())
