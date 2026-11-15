"""
Countries for the world map: outlines and label points (Natural Earth 1:110m, bundled), lookup of a country
from the code or name a registry returns, and the home country from the Windows region setting (offline).
"""

import ctypes
import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "world_countries.json")

# Spellings registries use that Natural Earth does not
ALIASES = {
    "UNITED STATES": "US", "UNITED STATES OF AMERICA": "US", "USA": "US", "UK": "GB", "UNITED KINGDOM": "GB",
    "GREAT BRITAIN": "GB", "RUSSIAN FEDERATION": "RU", "KOREA, REPUBLIC OF": "KR", "REPUBLIC OF KOREA": "KR",
    "SOUTH KOREA": "KR", "VIET NAM": "VN", "IRAN, ISLAMIC REPUBLIC OF": "IR", "TAIWAN, PROVINCE OF CHINA": "TW",
    "CZECHIA": "CZ", "THE NETHERLANDS": "NL", "HOLLAND": "NL", "EU": "", "EUROPEAN UNION": "", "AP": "", "ZZ": "",
}


@dataclass
class Country:
    code: str
    name: str
    lon: float
    lat: float
    rings: List[List[Tuple[float, float]]] = field(default_factory=list)


@lru_cache(maxsize=1)
def world() -> Tuple[List[Country], Dict[str, str]]:
    """(countries, lookup table of upper-case code / ISO3 / names -> ISO2 code)."""
    with open(DATA_FILE, encoding="utf-8") as f:
        data = json.load(f)
    countries, lookup = [], dict(ALIASES)
    for c in data["countries"]:
        country = Country(c["code"], c["name"], c["label"][0], c["label"][1],
                          [[(p[0], p[1]) for p in r] for r in c["rings"]])
        countries.append(country)
        if not c["code"]:
            continue
        for key in [c["code"], c.get("iso3") or ""] + list(c.get("names") or []):
            if key:
                lookup.setdefault(key.upper(), c["code"])
    return countries, lookup


def country_code(text: str) -> str:
    """'FR', 'FRA', 'France', 'United States' -> ISO 3166 alpha-2 code ('' when unknown)."""
    if not text:
        return ""
    return world()[1].get(text.strip().upper(), "")


def country(code: str) -> Optional[Country]:
    for c in world()[0]:
        if c.code == code:
            return c
    return None


def home_country() -> str:
    """ISO2 code of the Windows region setting (Settings > Time & language > Region)."""
    try:
        k32 = ctypes.windll.kernel32
        geo_id = k32.GetUserGeoID(16)  # GEOCLASS_NATION
        buf = ctypes.create_unicode_buffer(8)
        if k32.GetGeoInfoW(geo_id, 4, buf, len(buf), 0):  # GEO_ISO2
            return country_code(buf.value)
    except (AttributeError, OSError):
        pass
    return ""
